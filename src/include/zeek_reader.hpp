#pragma once

#include "duckdb.hpp"
#include "duckdb/common/file_system.hpp"
#include "duckdb/function/table_function.hpp"

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

	//! Convert a Zeek type string to a DuckDB LogicalType
	static LogicalType ZeekTypeToDuckDBType(const string &zeek_type);

	//! Parse escape sequences in separator strings (e.g., \x09 -> tab)
	static string ParseSeparator(const string &sep_str);

	static bool ReadLine(FileHandle &file_handle, string &line);
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
};

//! Global state for the read_zeek table function
struct ZeekScanGlobalState : public GlobalTableFunctionState {
	//! Current file index
	idx_t current_file_idx = 0;
	//! File handle for reading
	unique_ptr<FileHandle> file_handle;
	//! Whether we've finished reading all files
	bool finished = false;
	//! Buffer for reading lines
	string line_buffer;
	//! Current file path (for filename column)
	string current_file_path;

	idx_t MaxThreads() const override {
		return 1; // Single-threaded for now
	}
};

//! Get the read_zeek table function
TableFunction GetZeekScanFunction();

} // namespace duckdb
