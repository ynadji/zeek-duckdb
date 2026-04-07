#pragma once

#include "duckdb.hpp"
#include "duckdb/common/file_system.hpp"
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
};

//! Bind data for the read_zeek table function
struct ZeekScanBindData : public TableFunctionData {
	//! List of file paths (expanded from glob)
	vector<string> file_paths;
	//! Parsed header information (from first file, used as schema)
	ZeekHeader header;
	//! DuckDB types for each column
	vector<LogicalType> column_types;
	//! Whether to add a filename column
	bool filename_column = false;
	//! Whether to use INET type for addr/subnet (requires inet extension)
	bool use_inet = true;
};

//! A view into a contiguous span of bytes (no ownership)
struct FieldSlice {
	const char *ptr;
	uint32_t len;
};

//! Global state for the read_zeek table function. Shared across all parallel scanner threads —
//! contains only read-only or atomic data.
struct ZeekScanGlobalState : public GlobalTableFunctionState {
	//! Atomic counter for the next file index to claim from bind_data.file_paths.
	std::atomic<idx_t> next_file_idx {0};
	//! Total number of files (cached from bind_data, used for MaxThreads).
	idx_t total_files = 0;

	//! Projection pushdown: for each output column index, the schema column index it maps to.
	//! A value of data_col_count means the filename virtual column.
	vector<column_t> projected_schema_cols;
	//! True if no columns are projected (e.g. COUNT(*)) — skip all parsing
	bool count_only = false;

	//! Pushed-down filters from DuckDB. The map key is the index into projected_schema_cols
	//! (i.e. the output column index), NOT the schema column index. Null if no filters pushed down.
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
	//! True when this thread has no more files to process.
	bool finished = false;

	//! Buffered I/O: raw bytes read from the file.
	vector<char> read_buffer;
	idx_t buffer_pos = 0;
	idx_t buffer_size = 0;
	bool eof_reached = false;

	//! Current line, accumulated across buffer refills if needed.
	vector<char> line_buffer;
	//! Field slices into line_buffer (reused per row).
	vector<FieldSlice> field_slices;
	//! Element slices for LIST values (reused per LIST cell).
	vector<FieldSlice> list_element_slices;

	//! Per-thread cast temp vectors, one per output column. nullptr for native columns.
	vector<unique_ptr<Vector>> cast_temp_vecs;
};

//! Get the read_zeek table function
TableFunction GetZeekScanFunction();

} // namespace duckdb
