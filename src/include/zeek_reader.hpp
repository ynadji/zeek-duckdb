#pragma once

#include "duckdb.hpp"
#include "duckdb/common/file_system.hpp"
#include "duckdb/common/optional.hpp"
#include "duckdb/common/types/date.hpp"
#include "duckdb/common/types/timestamp.hpp"
#include "duckdb/execution/expression_executor.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/planner/table_filter.hpp"

#include <atomic>
#include <string>
#include <vector>

namespace duckdb {

//! Parsed Zeek log header metadata
struct ZeekHeader {
	//! Field separator (default: tab)
	char separator = '\t';
	//! Set/vector element separator (default: comma)
	char set_separator = ',';
	//! Marker for empty fields (default: "(empty)")
	string empty_field = "(empty)";
	//! Marker for unset/NULL fields (default: "-")
	string unset_field = "-";
	//! Log stream identifier (e.g., "conn", "dns", "known_hosts")
	string path;
	//! Opening timestamp
	string open_time;
	//! Column names
	vector<string> fields;
	//! Zeek type names for each column
	vector<string> types;
	//! Number of header lines (for skipping when re-reading)
	idx_t header_line_count = 0;
};

//! Static methods for parsing Zeek headers and converting types
class ZeekReader {
public:
	//! Parse a Zeek header from a file handle
	//! Returns the parsed header and positions the file handle at the first data line
	static ZeekHeader ParseHeader(FileHandle &file_handle);

	static LogicalType ZeekTypeToDuckDBType(const string &zeek_type, bool use_inet = true,
	                                        ClientContext *context = nullptr);

	static string ParseSeparator(const string &sep_str);

	static bool ReadLine(FileHandle &file_handle, string &line);

	static string ExtractInnerType(const string &zeek_type);

	//! Apply a single header line to a ZeekHeader. Returns true if the line was a directive
	//! (i.e. starts with '#') and was consumed; false if it was a data line. Does not modify
	//! `header` if it returns false.
	static bool ApplyHeaderLine(const char *line, idx_t len, ZeekHeader &header);
};

//! Compare two parsed headers for schema equivalence. Returns true if they describe the same
//! Zeek log schema. On mismatch, populates `mismatch_reason` with a brief human-readable
//! description of the first difference found and returns false. The fields compared are:
//! `fields`, `types`, `separator`, `set_separator`, `unset_field`, `empty_field`. The
//! `path` and `open_time` fields are intentionally ignored.
bool SameSchema(const ZeekHeader &expected, const ZeekHeader &actual, string &mismatch_reason);

//! Extract a valid date from the input file's immediate parent directory.
optional<date_t> TryExtractZeekLogDate(const string &path);

//! File coverage interval encoded as local wall-clock timestamps in its filename.
struct ZeekFileTimeRange {
	timestamp_t start;
	timestamp_t end;
};

//! Extract an explicit HH:MM:SS-HH:MM:SS range using the file's date directory.
optional<ZeekFileTimeRange> TryExtractZeekLogTimeRange(const string &path, date_t log_date);

//! Bind data for the read_zeek table function
struct ZeekScanBindData : public TableFunctionData {
	//! List of file paths (expanded from glob)
	vector<string> file_paths;
	//! Date inferred from the immediate parent directory of each file, when enabled.
	vector<optional<date_t>> file_dates;
	//! Time interval inferred from each filename when it contains an explicit time range.
	vector<optional<ZeekFileTimeRange>> file_time_ranges;
	//! Parsed header information. In strict mode this is file 0's header. In union mode the
	//! `fields` and `types` vectors contain the union of all files' fields, in the order they
	//! were first encountered (file 0's fields first, then any new fields from file 1, etc.).
	ZeekHeader header;
	//! DuckDB types for each column (size matches header.fields).
	vector<LogicalType> column_types;
	//! Virtual output column indexes. The Zeek data columns remain in column_types.
	optional<column_t> log_date_column_idx;
	optional<column_t> log_start_time_column_idx;
	optional<column_t> log_end_time_column_idx;
	optional<column_t> filename_column_idx;
	//! Whether to add a filename column
	bool filename_column = false;
	//! Whether to discover YYYY-MM-DD parent directories as a virtual log_date column.
	bool partition_discovery = false;
	//! Whether to use INET type for addr/subnet (requires inet extension)
	bool use_inet = true;
	//! Whether to union schemas across files. When true, the output schema is the union of all
	//! files' fields and missing fields become NULL. When false (default) all files must have
	//! identical schemas — any mismatch is an error.
	bool union_by_name = false;
	//! Whether to ignore corrupted or unreadable files instead of throwing an error.
	//! When true, files that cannot be opened or parsed are silently skipped.
	bool ignore_file_errors = false;
	//! When union_by_name=true: per-file inverse mapping. union_to_file_field[file_idx][union_col]
	//! gives the field index within that file for the given union column, or idx_t(-1) if the
	//! field is absent from this file. Empty when union_by_name=false.
	vector<vector<idx_t>> union_to_file_field;
};

//! Bounds extracted from filters on a temporal virtual column.
template <class T>
struct ZeekValueRange {
	optional<T> lower;
	optional<T> upper;
	bool lower_inclusive = true;
	bool upper_inclusive = true;
	bool empty = false;
};
using ZeekDateRange = ZeekValueRange<date_t>;
using ZeekTimestampRange = ZeekValueRange<timestamp_t>;

//! A view into a contiguous span of bytes (no ownership)
struct FieldSlice {
	const char *ptr;
	uint32_t len;
};

//! Global state for the read_zeek table function. Shared across all parallel scanner threads —
//! contains only read-only or atomic data.
struct ZeekScanGlobalState : public GlobalTableFunctionState {
	//! Atomic counter for the next retained file index to claim.
	std::atomic<idx_t> next_file_idx {0};
	//! Original file indexes retained after safe date partition pruning.
	vector<idx_t> scan_file_indices;
	//! Normalized range used to prune files, when one was safely extracted.
	optional<ZeekDateRange> date_range;
	optional<ZeekTimestampRange> start_time_range;
	optional<ZeekTimestampRange> end_time_range;
	//! Total number of retained files (used for MaxThreads).
	idx_t total_files = 0;

	//! Projection pushdown: for each output column index, the schema column index it maps to.
	//! Virtual column indexes are stored separately in ZeekScanBindData.
	vector<column_t> projected_schema_cols;
	//! True if no columns are projected (e.g. COUNT(*)) — skip all parsing
	bool count_only = false;

	//! Schema column index for each scanned column, in DuckDB's column_ids order. Pushed-down filter keys are
	//! positions in column_ids (not output positions), so they map back to schema columns through this list.
	//! It differs from projected_schema_cols when projection_ids drops or reorders filter-only columns.
	vector<column_t> scan_schema_cols;
	//! Pushed-down filters from DuckDB. The map key is the index into scan_schema_cols. Null if no filters
	//! were pushed down.
	optional_ptr<TableFilterSet> filters;

	//! For each output column index, true if its type isn't natively handled and needs the
	//! batched cast path (i.e. each thread should allocate a temp VARCHAR vector for it).
	vector<bool> needs_cast_buffer;

	idx_t MaxThreads() const override {
		return total_files == 0 ? 1 : total_files;
	}
};

//! Per-thread local state. One per parallel scanner thread.
struct ZeekScanLocalState : public LocalTableFunctionState {
	//! Currently-open file (or null between files).
	unique_ptr<FileHandle> file_handle;
	//! Path of the currently-open file (for filename column).
	string current_file_path;
	//! Index into bind_data.file_paths for the currently-open file.
	idx_t current_file_idx = 0;
	//! True when this thread has no more files to process.
	bool finished = false;

	//! For each schema column index (in the bound output schema), the index of that field in the
	//! currently-open file's row layout — or idx_t(-1) if the field is absent from this file
	//! (only possible in union_by_name mode). In strict mode this is always the identity mapping.
	//! Re-populated each time OpenNextFile claims a new file.
	vector<idx_t> field_lookup;

	//! Buffered I/O: raw bytes read from the file.
	vector<char> read_buffer;
	idx_t buffer_pos = 0;
	idx_t buffer_size = 0;
	bool eof_reached = false;

	//! Current line, accumulated across buffer refills if needed.
	vector<char> line_buffer;
	//! When true, line_buffer holds a line that was already read but not yet consumed by the
	//! caller (e.g., the first data line peeked at by the per-file header parser). The next
	//! call to ReadLineBuffered will return this line as-is and clear the flag.
	bool has_pending_line = false;
	//! Field slices into line_buffer (reused per row).
	vector<FieldSlice> field_slices;
	//! Element slices for LIST values (reused per LIST cell).
	vector<FieldSlice> list_element_slices;

	//! Per-thread cast temp vectors, one per output column. nullptr for native columns.
	vector<unique_ptr<Vector>> cast_temp_vecs;

	//! Per-thread filter evaluators, indexed like ZeekScanGlobalState::scan_schema_cols (null where no filter
	//! applies). Executors are not thread-safe, so each thread builds its own in ZeekScanInitLocal.
	vector<unique_ptr<ExpressionExecutor>> filter_executors;
};

//! Get the read_zeek table function
TableFunction GetZeekScanFunction();

} // namespace duckdb
