#include "zeek_reader.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/enums/file_compression_type.hpp"
#include "duckdb/common/types/vector.hpp"
#include "duckdb/common/types/timestamp.hpp"

namespace duckdb {

static timestamp_tz_t EpochSecondsToTimestampTZ(double epoch_seconds) {
	int64_t micros = static_cast<int64_t>(epoch_seconds * 1000000.0);
	return timestamp_tz_t(micros);
}

static bool OpenNextFile(ClientContext &context, ZeekScanGlobalState &state, const ZeekScanBindData &bind_data) {
	auto &fs = FileSystem::GetFileSystem(context);

	while (state.current_file_idx < bind_data.file_paths.size()) {
		state.current_file_path = bind_data.file_paths[state.current_file_idx];
		state.current_file_idx++;

		state.file_handle =
		    fs.OpenFile(state.current_file_path, FileFlags::FILE_FLAGS_READ | FileCompressionType::AUTO_DETECT);

		string line;
		idx_t lines_to_skip = bind_data.header.header_line_count;
		for (idx_t i = 0; i < lines_to_skip; i++) {
			if (!ZeekReader::ReadLine(*state.file_handle, line)) {
				break;
			}
		}
		return true;
	}
	return false;
}

static void AppendListValue(Vector &vec, idx_t row_idx, const string &field_value, char set_separator,
                            const LogicalType &child_type, const string &unset_field, const string &empty_field) {
	auto &list_entry = ListVector::GetData(vec)[row_idx];
	auto current_size = ListVector::GetListSize(vec);

	if (field_value == unset_field || field_value == empty_field) {
		list_entry.offset = current_size;
		list_entry.length = 0;
		return;
	}

	vector<string> elements;
	string sep_str(1, set_separator);
	elements = StringUtil::Split(field_value, sep_str);

	list_entry.offset = current_size;
	list_entry.length = elements.size();

	auto &child_vec = ListVector::GetEntry(vec);
	ListVector::Reserve(vec, current_size + elements.size());
	ListVector::SetListSize(vec, current_size + elements.size());

	auto child_type_id = child_type.id();
	for (idx_t i = 0; i < elements.size(); i++) {
		idx_t child_idx = current_size + i;
		const string &elem = elements[i];

		if (elem == unset_field || elem == empty_field) {
			FlatVector::SetNull(child_vec, child_idx, true);
			continue;
		}

		switch (child_type_id) {
		case LogicalTypeId::DOUBLE: {
			try {
				FlatVector::GetData<double>(child_vec)[child_idx] = std::stod(elem);
			} catch (...) {
				FlatVector::SetNull(child_vec, child_idx, true);
			}
			break;
		}
		case LogicalTypeId::UBIGINT: {
			try {
				FlatVector::GetData<uint64_t>(child_vec)[child_idx] = std::stoull(elem);
			} catch (...) {
				FlatVector::SetNull(child_vec, child_idx, true);
			}
			break;
		}
		case LogicalTypeId::BIGINT: {
			try {
				FlatVector::GetData<int64_t>(child_vec)[child_idx] = std::stoll(elem);
			} catch (...) {
				FlatVector::SetNull(child_vec, child_idx, true);
			}
			break;
		}
		case LogicalTypeId::BOOLEAN: {
			FlatVector::GetData<bool>(child_vec)[child_idx] = (elem == "T" || elem == "true");
			break;
		}
		case LogicalTypeId::TIMESTAMP_TZ: {
			try {
				FlatVector::GetData<timestamp_tz_t>(child_vec)[child_idx] = EpochSecondsToTimestampTZ(std::stod(elem));
			} catch (...) {
				FlatVector::SetNull(child_vec, child_idx, true);
			}
			break;
		}
		case LogicalTypeId::VARCHAR:
		default: {
			FlatVector::GetData<string_t>(child_vec)[child_idx] = StringVector::AddString(child_vec, elem);
			break;
		}
		}
	}
}

static unique_ptr<FunctionData> ZeekScanBind(ClientContext &context, TableFunctionBindInput &input,
                                             vector<LogicalType> &return_types, vector<string> &names) {
	auto result = make_uniq<ZeekScanBindData>();
	string pattern = input.inputs[0].GetValue<string>();

	auto &fs = FileSystem::GetFileSystem(context);

	auto glob_result = fs.GlobFiles(pattern, context, FileGlobOptions::DISALLOW_EMPTY);
	for (auto &file_info : glob_result) {
		result->file_paths.push_back(file_info.path);
	}
	std::sort(result->file_paths.begin(), result->file_paths.end());

	if (result->file_paths.empty()) {
		throw IOException("No files found matching pattern: %s", pattern);
	}

	auto filename_param = input.named_parameters.find("filename");
	if (filename_param != input.named_parameters.end()) {
		result->filename_column = filename_param->second.GetValue<bool>();
	}

	auto file_handle =
	    fs.OpenFile(result->file_paths[0], FileFlags::FILE_FLAGS_READ | FileCompressionType::AUTO_DETECT);
	result->header = ZeekReader::ParseHeader(*file_handle);

	for (idx_t i = 0; i < result->header.fields.size(); i++) {
		names.push_back(result->header.fields[i]);
		LogicalType col_type = ZeekReader::ZeekTypeToDuckDBType(result->header.types[i]);
		return_types.push_back(col_type);
		result->column_types.push_back(col_type);
	}

	if (result->filename_column) {
		names.push_back("filename");
		return_types.push_back(LogicalType::VARCHAR);
	}

	return std::move(result);
}

static unique_ptr<GlobalTableFunctionState> ZeekScanInitGlobal(ClientContext &context, TableFunctionInitInput &input) {
	auto &bind_data = input.bind_data->Cast<ZeekScanBindData>();
	auto result = make_uniq<ZeekScanGlobalState>();

	if (!OpenNextFile(context, *result, bind_data)) {
		result->finished = true;
	}

	return std::move(result);
}

static void ZeekScanExecute(ClientContext &context, TableFunctionInput &data, DataChunk &output) {
	auto &bind_data = data.bind_data->Cast<ZeekScanBindData>();
	auto &state = data.global_state->Cast<ZeekScanGlobalState>();

	if (state.finished) {
		output.SetCardinality(0);
		return;
	}

	idx_t row_count = 0;
	string line;
	idx_t data_col_count = bind_data.column_types.size();

	while (row_count < STANDARD_VECTOR_SIZE) {
		if (!ZeekReader::ReadLine(*state.file_handle, line)) {
			if (!OpenNextFile(context, state, bind_data)) {
				state.finished = true;
				break;
			}
			continue;
		}

		if (line.empty() || line[0] == '#') {
			continue;
		}

		vector<string> fields = StringUtil::Split(line, bind_data.header.separator);

		for (idx_t col_idx = 0; col_idx < data_col_count; col_idx++) {
			auto &vec = output.data[col_idx];

			if (col_idx >= fields.size()) {
				FlatVector::SetNull(vec, row_count, true);
				continue;
			}

			const string &field_value = fields[col_idx];

			if (field_value == bind_data.header.unset_field || field_value == bind_data.header.empty_field) {
				FlatVector::SetNull(vec, row_count, true);
				continue;
			}

			auto type_id = bind_data.column_types[col_idx].id();
			switch (type_id) {
			case LogicalTypeId::DOUBLE: {
				try {
					FlatVector::GetData<double>(vec)[row_count] = std::stod(field_value);
				} catch (...) {
					FlatVector::SetNull(vec, row_count, true);
				}
				break;
			}
			case LogicalTypeId::UBIGINT: {
				try {
					FlatVector::GetData<uint64_t>(vec)[row_count] = std::stoull(field_value);
				} catch (...) {
					FlatVector::SetNull(vec, row_count, true);
				}
				break;
			}
			case LogicalTypeId::BIGINT: {
				try {
					FlatVector::GetData<int64_t>(vec)[row_count] = std::stoll(field_value);
				} catch (...) {
					FlatVector::SetNull(vec, row_count, true);
				}
				break;
			}
			case LogicalTypeId::BOOLEAN: {
				FlatVector::GetData<bool>(vec)[row_count] = (field_value == "T" || field_value == "true");
				break;
			}
			case LogicalTypeId::TIMESTAMP_TZ: {
				try {
					FlatVector::GetData<timestamp_tz_t>(vec)[row_count] =
					    EpochSecondsToTimestampTZ(std::stod(field_value));
				} catch (...) {
					FlatVector::SetNull(vec, row_count, true);
				}
				break;
			}
			case LogicalTypeId::LIST: {
				auto &child_type = ListType::GetChildType(bind_data.column_types[col_idx]);
				AppendListValue(vec, row_count, field_value, bind_data.header.set_separator, child_type,
				                bind_data.header.unset_field, bind_data.header.empty_field);
				break;
			}
			case LogicalTypeId::VARCHAR:
			default: {
				FlatVector::GetData<string_t>(vec)[row_count] = StringVector::AddString(vec, field_value);
				break;
			}
			}
		}

		if (bind_data.filename_column) {
			auto &filename_vec = output.data[data_col_count];
			FlatVector::GetData<string_t>(filename_vec)[row_count] =
			    StringVector::AddString(filename_vec, state.current_file_path);
		}

		row_count++;
	}

	output.SetCardinality(row_count);
}

TableFunction GetZeekScanFunction() {
	TableFunction func("read_zeek", {LogicalType::VARCHAR}, ZeekScanExecute, ZeekScanBind, ZeekScanInitGlobal);
	func.named_parameters["filename"] = LogicalType::BOOLEAN;
	return func;
}

} // namespace duckdb
