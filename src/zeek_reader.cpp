#include "zeek_reader.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/types.hpp"

namespace duckdb {

string ZeekReader::ParseSeparator(const string &sep_str) {
	string result;
	for (size_t i = 0; i < sep_str.size(); i++) {
		if (sep_str[i] == '\\' && i + 1 < sep_str.size()) {
			char next = sep_str[i + 1];
			if (next == 'x' && i + 3 < sep_str.size()) {
				string hex = sep_str.substr(i + 2, 2);
				char c = static_cast<char>(std::stoi(hex, nullptr, 16));
				result += c;
				i += 3;
				continue;
			} else if (next == 't') {
				result += '\t';
				i++;
				continue;
			} else if (next == 'n') {
				result += '\n';
				i++;
				continue;
			}
		}
		result += sep_str[i];
	}
	return result;
}

bool ZeekReader::ReadLine(FileHandle &file_handle, string &line) {
	line.clear();
	char c;
	while (true) {
		int64_t bytes_read = file_handle.Read(&c, 1);
		if (bytes_read == 0) {
			return !line.empty();
		}
		if (c == '\n') {
			return true;
		}
		if (c != '\r') {
			line += c;
		}
	}
}

bool ZeekReader::ApplyHeaderLine(const char *line, idx_t len, ZeekHeader &header) {
	if (len == 0 || line[0] != '#') {
		return false;
	}

	// Find the first separator (tab or space) after the directive name.
	idx_t sep_pos = 1;
	while (sep_pos < len && line[sep_pos] != '\t' && line[sep_pos] != ' ') {
		sep_pos++;
	}

	string directive(line + 1, sep_pos - 1);
	string value;
	if (sep_pos < len) {
		value.assign(line + sep_pos + 1, len - sep_pos - 1);
	}

	if (directive == "separator") {
		string parsed = ParseSeparator(value);
		if (!parsed.empty()) {
			header.separator = parsed[0];
		}
	} else if (directive == "set_separator") {
		string parsed = ParseSeparator(value);
		if (!parsed.empty()) {
			header.set_separator = parsed[0];
		}
	} else if (directive == "empty_field") {
		header.empty_field = value;
	} else if (directive == "unset_field") {
		header.unset_field = value;
	} else if (directive == "path") {
		header.path = value;
	} else if (directive == "open") {
		header.open_time = value;
	} else if (directive == "fields") {
		header.fields = StringUtil::Split(value, header.separator);
	} else if (directive == "types") {
		header.types = StringUtil::Split(value, header.separator);
	}
	return true;
}

ZeekHeader ZeekReader::ParseHeader(FileHandle &file_handle) {
	ZeekHeader header;
	string line;
	idx_t line_count = 0;

	while (ReadLine(file_handle, line)) {
		line_count++;
		if (!ApplyHeaderLine(line.data(), line.size(), header)) {
			break;
		}
	}

	header.header_line_count = line_count - 1;

	if (header.fields.empty()) {
		throw InvalidInputException("Zeek log file missing #fields directive");
	}
	if (header.types.empty()) {
		throw InvalidInputException("Zeek log file missing #types directive");
	}
	if (header.fields.size() != header.types.size()) {
		throw InvalidInputException("Zeek log file has mismatched #fields and #types count");
	}

	return header;
}

string ZeekReader::ExtractInnerType(const string &zeek_type) {
	auto bracket_start = zeek_type.find('[');
	auto bracket_end = zeek_type.rfind(']');
	if (bracket_start != string::npos && bracket_end != string::npos && bracket_end > bracket_start) {
		return zeek_type.substr(bracket_start + 1, bracket_end - bracket_start - 1);
	}
	return "string";
}

LogicalType ZeekReader::ZeekTypeToDuckDBType(const string &zeek_type, bool use_inet, ClientContext *context) {
	if (zeek_type == "time") {
		return LogicalType::TIMESTAMP_TZ;
	} else if (zeek_type == "interval") {
		return LogicalType::INTERVAL;
	} else if (zeek_type == "double") {
		return LogicalType::DOUBLE;
	} else if (zeek_type == "count") {
		return LogicalType::UBIGINT;
	} else if (zeek_type == "int") {
		return LogicalType::BIGINT;
	} else if (zeek_type == "bool") {
		return LogicalType::BOOLEAN;
	} else if (zeek_type == "port") {
		return LogicalType::USMALLINT;
	} else if (zeek_type == "addr" || zeek_type == "subnet") {
		if (use_inet && context) {
			try {
				return TransformStringToLogicalType("INET", *context);
			} catch (...) {
				throw InvalidInputException("Zeek type '%s' requires the inet extension. "
				                            "Run 'INSTALL inet; LOAD inet;' or use inet=false to read as VARCHAR.",
				                            zeek_type);
			}
		}
		return LogicalType::VARCHAR;
	} else if (zeek_type == "string" || zeek_type == "enum") {
		return LogicalType::VARCHAR;
	} else if (StringUtil::StartsWith(zeek_type, "vector[") || StringUtil::StartsWith(zeek_type, "set[")) {
		string inner_type = ExtractInnerType(zeek_type);
		LogicalType child_type = ZeekTypeToDuckDBType(inner_type, use_inet, context);
		return LogicalType::LIST(child_type);
	}
	return LogicalType::VARCHAR;
}

bool SameSchema(const ZeekHeader &expected, const ZeekHeader &actual, string &mismatch_reason) {
	if (expected.fields.size() != actual.fields.size()) {
		mismatch_reason =
		    StringUtil::Format("different field count: expected %llu fields, got %llu",
		                       (unsigned long long)expected.fields.size(), (unsigned long long)actual.fields.size());
		return false;
	}
	for (idx_t i = 0; i < expected.fields.size(); i++) {
		if (expected.fields[i] != actual.fields[i]) {
			mismatch_reason = StringUtil::Format("field %llu differs: expected '%s', got '%s'", (unsigned long long)i,
			                                     expected.fields[i], actual.fields[i]);
			return false;
		}
	}
	for (idx_t i = 0; i < expected.types.size(); i++) {
		if (expected.types[i] != actual.types[i]) {
			mismatch_reason = StringUtil::Format("type for field '%s' differs: expected '%s', got '%s'",
			                                     expected.fields[i], expected.types[i], actual.types[i]);
			return false;
		}
	}
	if (expected.separator != actual.separator) {
		mismatch_reason = "#separator differs";
		return false;
	}
	if (expected.set_separator != actual.set_separator) {
		mismatch_reason = "#set_separator differs";
		return false;
	}
	if (expected.unset_field != actual.unset_field) {
		mismatch_reason = StringUtil::Format("#unset_field differs: expected '%s', got '%s'", expected.unset_field,
		                                     actual.unset_field);
		return false;
	}
	if (expected.empty_field != actual.empty_field) {
		mismatch_reason = StringUtil::Format("#empty_field differs: expected '%s', got '%s'", expected.empty_field,
		                                     actual.empty_field);
		return false;
	}
	return true;
}

} // namespace duckdb
