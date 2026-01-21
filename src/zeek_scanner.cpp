#include "zeek_reader.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/enums/file_compression_type.hpp"

namespace duckdb {

static unique_ptr<FunctionData> ZeekScanBind(ClientContext &context, TableFunctionBindInput &input,
                                              vector<LogicalType> &return_types, vector<string> &names) {
	auto result = make_uniq<ZeekScanBindData>();
	result->file_path = input.inputs[0].GetValue<string>();

	auto &fs = FileSystem::GetFileSystem(context);
	auto file_handle = fs.OpenFile(result->file_path, FileFlags::FILE_FLAGS_READ | FileCompressionType::AUTO_DETECT);

	result->header = ZeekReader::ParseHeader(*file_handle);

	for (idx_t i = 0; i < result->header.fields.size(); i++) {
		names.push_back(result->header.fields[i]);
		LogicalType col_type = ZeekReader::ZeekTypeToDuckDBType(result->header.types[i]);
		return_types.push_back(col_type);
		result->column_types.push_back(col_type);
	}

	return std::move(result);
}

static unique_ptr<GlobalTableFunctionState> ZeekScanInitGlobal(ClientContext &context,
                                                                TableFunctionInitInput &input) {
	auto &bind_data = input.bind_data->Cast<ZeekScanBindData>();
	auto result = make_uniq<ZeekScanGlobalState>();

	auto &fs = FileSystem::GetFileSystem(context);
	result->file_handle = fs.OpenFile(bind_data.file_path, FileFlags::FILE_FLAGS_READ | FileCompressionType::AUTO_DETECT);

	string line;
	for (idx_t i = 0; i < bind_data.header.header_line_count; i++) {
		if (!ZeekReader::ReadLine(*result->file_handle, line)) {
			result->finished = true;
			break;
		}
	}

	return std::move(result);
}

static void ZeekScanExecute(ClientContext &context, TableFunctionInput &data, DataChunk &output) {
	auto &bind_data = data.bind_data->Cast<ZeekScanBindData>();
	auto &global_state = data.global_state->Cast<ZeekScanGlobalState>();

	if (global_state.finished) {
		output.SetCardinality(0);
		return;
	}

	idx_t row_count = 0;
	string line;

	while (row_count < STANDARD_VECTOR_SIZE) {
		if (!ZeekReader::ReadLine(*global_state.file_handle, line)) {
			global_state.finished = true;
			break;
		}

		if (line.empty() || line[0] == '#') {
			continue;
		}

		vector<string> fields = StringUtil::Split(line, bind_data.header.separator);

		for (idx_t col_idx = 0; col_idx < bind_data.column_types.size(); col_idx++) {
			auto &vector = output.data[col_idx];
			
			if (col_idx >= fields.size()) {
				FlatVector::SetNull(vector, row_count, true);
				continue;
			}

			const string &field_value = fields[col_idx];

			if (field_value == bind_data.header.unset_field ||
			    field_value == bind_data.header.empty_field) {
				FlatVector::SetNull(vector, row_count, true);
				continue;
			}

			auto type_id = bind_data.column_types[col_idx].id();
			switch (type_id) {
			case LogicalTypeId::DOUBLE: {
				try {
					FlatVector::GetData<double>(vector)[row_count] = std::stod(field_value);
				} catch (...) {
					FlatVector::SetNull(vector, row_count, true);
				}
				break;
			}
			case LogicalTypeId::UBIGINT: {
				try {
					FlatVector::GetData<uint64_t>(vector)[row_count] = std::stoull(field_value);
				} catch (...) {
					FlatVector::SetNull(vector, row_count, true);
				}
				break;
			}
			case LogicalTypeId::BIGINT: {
				try {
					FlatVector::GetData<int64_t>(vector)[row_count] = std::stoll(field_value);
				} catch (...) {
					FlatVector::SetNull(vector, row_count, true);
				}
				break;
			}
			case LogicalTypeId::BOOLEAN: {
				FlatVector::GetData<bool>(vector)[row_count] = (field_value == "T" || field_value == "true");
				break;
			}
			case LogicalTypeId::VARCHAR:
			default: {
				FlatVector::GetData<string_t>(vector)[row_count] = StringVector::AddString(vector, field_value);
				break;
			}
			}
		}

		row_count++;
	}

	output.SetCardinality(row_count);
}

TableFunction GetZeekScanFunction() {
	TableFunction func("read_zeek", {LogicalType::VARCHAR}, ZeekScanExecute, ZeekScanBind, ZeekScanInitGlobal);
	return func;
}

}
