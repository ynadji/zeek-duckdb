#include "zeek_reader.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/enums/file_compression_type.hpp"
#include "duckdb/common/types/vector.hpp"
#include "duckdb/common/types/timestamp.hpp"
#include "duckdb/common/types/interval.hpp"
#include "duckdb/common/operator/cast_operators.hpp"
#include "duckdb/common/vector_operations/vector_operations.hpp"
#include "duckdb/common/operator/comparison_operators.hpp"
#include "duckdb/planner/filter/constant_filter.hpp"
#include "duckdb/planner/filter/null_filter.hpp"
#include "duckdb/planner/filter/conjunction_filter.hpp"
#include "duckdb/planner/filter/in_filter.hpp"
#include "duckdb/common/value_operations/value_operations.hpp"

#include <cstring>

namespace duckdb {

static constexpr idx_t READ_BUFFER_SIZE = 65536; // 64KB

static timestamp_tz_t EpochSecondsToTimestampTZ(double epoch_seconds) {
	int64_t micros = static_cast<int64_t>(epoch_seconds * 1000000.0);
	return timestamp_tz_t(micros);
}

static interval_t SecondsToInterval(double seconds) {
	int64_t micros = static_cast<int64_t>(seconds * 1000000.0);
	return Interval::FromMicro(micros);
}

//! Read one line from the buffered file into lstate.line_buffer.
//! Returns false on EOF (with line_buffer empty).
static bool ReadLineBuffered(ZeekScanLocalState &lstate) {
	// If a previous header parse "peeked" at the first data line and stashed it, hand it back.
	if (lstate.has_pending_line) {
		lstate.has_pending_line = false;
		return true;
	}
	lstate.line_buffer.clear();

	while (true) {
		// Refill the read buffer if exhausted.
		if (lstate.buffer_pos >= lstate.buffer_size) {
			if (lstate.eof_reached) {
				return !lstate.line_buffer.empty();
			}
			lstate.buffer_size = lstate.file_handle->Read(lstate.read_buffer.data(), lstate.read_buffer.size());
			lstate.buffer_pos = 0;
			if (lstate.buffer_size == 0) {
				lstate.eof_reached = true;
				return !lstate.line_buffer.empty();
			}
		}

		const char *start = lstate.read_buffer.data() + lstate.buffer_pos;
		idx_t remaining = lstate.buffer_size - lstate.buffer_pos;
		const char *newline = static_cast<const char *>(std::memchr(start, '\n', remaining));

		if (newline) {
			idx_t line_len = static_cast<idx_t>(newline - start);
			lstate.line_buffer.insert(lstate.line_buffer.end(), start, start + line_len);
			lstate.buffer_pos += line_len + 1;
			// Strip trailing \r if present (handles \r\n line endings even across buffer boundaries).
			if (!lstate.line_buffer.empty() && lstate.line_buffer.back() == '\r') {
				lstate.line_buffer.pop_back();
			}
			return true;
		}

		// No newline in this buffer chunk — copy what we have and refill.
		lstate.line_buffer.insert(lstate.line_buffer.end(), start, start + remaining);
		lstate.buffer_pos = lstate.buffer_size;
	}
}

//! Tokenize a span by separator into the given slices vector (reused).
static void TokenizeSpan(const char *data, uint32_t len, char separator, vector<FieldSlice> &slices) {
	slices.clear();
	uint32_t start = 0;
	for (uint32_t i = 0; i < len; i++) {
		if (data[i] == separator) {
			slices.push_back({data + start, i - start});
			start = i + 1;
		}
	}
	slices.push_back({data + start, len - start});
}

//! Compare a slice to a string for equality (used for unset/empty markers).
static inline bool SliceEquals(const FieldSlice &s, const string &str) {
	return s.len == str.size() && std::memcmp(s.ptr, str.data(), s.len) == 0;
}

//! Returns true if the given type is handled directly in the per-row switch (no batch cast needed).
static bool IsNativelyHandled(const LogicalType &type) {
	switch (type.id()) {
	case LogicalTypeId::VARCHAR:
	case LogicalTypeId::DOUBLE:
	case LogicalTypeId::UBIGINT:
	case LogicalTypeId::BIGINT:
	case LogicalTypeId::BOOLEAN:
	case LogicalTypeId::TIMESTAMP_TZ:
	case LogicalTypeId::INTERVAL:
	case LogicalTypeId::USMALLINT:
	case LogicalTypeId::LIST:
		return true;
	default:
		return false;
	}
}

//! Returns true if filter pushdown is efficient for this column type (see supports_pushdown_type).
//! We only advertise pushdown for types we can parse from a slice without going through an
//! extension cast — LIST and INET are excluded because per-row evaluation would be slower than
//! letting DuckDB filter post-scan.
static bool CanPushdownFilterOnType(const LogicalType &type) {
	switch (type.id()) {
	case LogicalTypeId::VARCHAR:
	case LogicalTypeId::DOUBLE:
	case LogicalTypeId::UBIGINT:
	case LogicalTypeId::BIGINT:
	case LogicalTypeId::BOOLEAN:
	case LogicalTypeId::TIMESTAMP_TZ:
	case LogicalTypeId::INTERVAL:
	case LogicalTypeId::USMALLINT:
		return true;
	default:
		return false;
	}
}

//! Parse a slice into a DuckDB Value of the given type. Returns a NULL Value of the target type
//! on parse failure. This is only called for filter columns and only for types where
//! CanPushdownFilterOnType returns true.
static Value SliceToValue(const FieldSlice &field, const LogicalType &type) {
	string_t s(field.ptr, field.len);
	switch (type.id()) {
	case LogicalTypeId::VARCHAR:
		return Value(string(field.ptr, field.len));
	case LogicalTypeId::DOUBLE: {
		double v;
		if (TryCast::Operation<string_t, double>(s, v)) {
			return Value::DOUBLE(v);
		}
		return Value(type);
	}
	case LogicalTypeId::UBIGINT: {
		uint64_t v;
		if (TryCast::Operation<string_t, uint64_t>(s, v)) {
			return Value::UBIGINT(v);
		}
		return Value(type);
	}
	case LogicalTypeId::BIGINT: {
		int64_t v;
		if (TryCast::Operation<string_t, int64_t>(s, v)) {
			return Value::BIGINT(v);
		}
		return Value(type);
	}
	case LogicalTypeId::BOOLEAN: {
		bool b = (field.len == 1 && field.ptr[0] == 'T') || (field.len == 4 && std::memcmp(field.ptr, "true", 4) == 0);
		return Value::BOOLEAN(b);
	}
	case LogicalTypeId::USMALLINT: {
		uint16_t v;
		if (TryCast::Operation<string_t, uint16_t>(s, v)) {
			return Value::USMALLINT(v);
		}
		return Value(type);
	}
	case LogicalTypeId::TIMESTAMP_TZ: {
		double v;
		if (TryCast::Operation<string_t, double>(s, v)) {
			return Value::TIMESTAMPTZ(EpochSecondsToTimestampTZ(v));
		}
		return Value(type);
	}
	case LogicalTypeId::INTERVAL: {
		double v;
		if (TryCast::Operation<string_t, double>(s, v)) {
			return Value::INTERVAL(SecondsToInterval(v));
		}
		return Value(type);
	}
	default:
		// Should never be reached — CanPushdownFilterOnType restricts the types we see here.
		return Value(type);
	}
}

//! Evaluate a filter against a value. `is_null` indicates whether `val` represents a SQL NULL
//! (Value is not null-tagged otherwise). Returns true if the row passes the filter.
static bool EvaluateFilter(const TableFilter &filter, const Value &val, bool is_null) {
	switch (filter.filter_type) {
	case TableFilterType::IS_NULL:
		return is_null;
	case TableFilterType::IS_NOT_NULL:
		return !is_null;
	case TableFilterType::CONSTANT_COMPARISON: {
		if (is_null) {
			// NULL compared with anything is NULL → row filtered out.
			return false;
		}
		return filter.Cast<ConstantFilter>().Compare(val);
	}
	case TableFilterType::IN_FILTER: {
		if (is_null) {
			return false;
		}
		auto &in_filter = filter.Cast<InFilter>();
		for (auto &v : in_filter.values) {
			if (!v.IsNull() && ValueOperations::Equals(v, val)) {
				return true;
			}
		}
		return false;
	}
	case TableFilterType::CONJUNCTION_AND: {
		auto &conj = filter.Cast<ConjunctionAndFilter>();
		for (auto &child : conj.child_filters) {
			if (!EvaluateFilter(*child, val, is_null)) {
				return false;
			}
		}
		return true;
	}
	case TableFilterType::CONJUNCTION_OR: {
		auto &conj = filter.Cast<ConjunctionOrFilter>();
		for (auto &child : conj.child_filters) {
			if (EvaluateFilter(*child, val, is_null)) {
				return true;
			}
		}
		return false;
	}
	default:
		// Unknown filter type — be safe: let the row through, DuckDB will re-evaluate post-scan.
		return true;
	}
}

//! Atomically claim the next file from the shared queue and open it for the calling thread.
//! Returns false if no more files remain.
static bool OpenNextFile(ClientContext &context, ZeekScanGlobalState &gstate, ZeekScanLocalState &lstate,
                         const ZeekScanBindData &bind_data) {
	auto &fs = FileSystem::GetFileSystem(context);

	while (true) {
		idx_t my_file_idx = gstate.next_file_idx.fetch_add(1, std::memory_order_relaxed);
		if (my_file_idx >= bind_data.file_paths.size()) {
			return false;
		}

		lstate.current_file_path = bind_data.file_paths[my_file_idx];
		lstate.file_handle =
		    fs.OpenFile(lstate.current_file_path, FileFlags::FILE_FLAGS_READ | FileCompressionType::AUTO_DETECT);

		// Reset buffer state for the new file.
		lstate.buffer_pos = 0;
		lstate.buffer_size = 0;
		lstate.eof_reached = false;
		lstate.has_pending_line = false;

		// Parse this file's header via the buffered reader and validate against the bound schema.
		// We read lines until we hit the first non-directive (data) line, parse each `#` line as
		// a directive, and leave the first data line in line_buffer with has_pending_line=true so
		// the hot loop can consume it without re-reading.
		ZeekHeader file_header;
		while (ReadLineBuffered(lstate)) {
			if (!ZeekReader::ApplyHeaderLine(lstate.line_buffer.data(), lstate.line_buffer.size(), file_header)) {
				// First non-directive line — this is the first data row. Stash it.
				lstate.has_pending_line = true;
				break;
			}
		}

		if (file_header.fields.empty()) {
			throw InvalidInputException("read_zeek: file '%s' is missing #fields directive", lstate.current_file_path);
		}
		if (file_header.types.empty()) {
			throw InvalidInputException("read_zeek: file '%s' is missing #types directive", lstate.current_file_path);
		}
		if (file_header.fields.size() != file_header.types.size()) {
			throw InvalidInputException("read_zeek: file '%s' has mismatched #fields and #types counts",
			                            lstate.current_file_path);
		}

		string mismatch;
		if (!SameSchema(bind_data.header, file_header, mismatch)) {
			throw InvalidInputException(
			    "read_zeek: file '%s' has a different schema than '%s' (the first file in the glob): %s",
			    lstate.current_file_path, bind_data.file_paths[0], mismatch);
		}
		return true;
	}
}

static void AppendListValue(ClientContext &context, ZeekScanLocalState &lstate, Vector &vec, idx_t row_idx,
                            const FieldSlice &field, char set_separator, const LogicalType &child_type,
                            const string &unset_field, const string &empty_field) {
	auto &list_entry = ListVector::GetData(vec)[row_idx];
	auto current_size = ListVector::GetListSize(vec);

	if (SliceEquals(field, unset_field) || SliceEquals(field, empty_field)) {
		list_entry.offset = current_size;
		list_entry.length = 0;
		return;
	}

	TokenizeSpan(field.ptr, field.len, set_separator, lstate.list_element_slices);
	auto &elements = lstate.list_element_slices;

	list_entry.offset = current_size;
	list_entry.length = elements.size();

	auto &child_vec = ListVector::GetEntry(vec);
	ListVector::Reserve(vec, current_size + elements.size());
	ListVector::SetListSize(vec, current_size + elements.size());

	auto child_type_id = child_type.id();
	for (idx_t i = 0; i < elements.size(); i++) {
		idx_t child_idx = current_size + i;
		const FieldSlice &elem = elements[i];

		if (SliceEquals(elem, unset_field) || SliceEquals(elem, empty_field)) {
			FlatVector::SetNull(child_vec, child_idx, true);
			continue;
		}

		string_t elem_str(elem.ptr, elem.len);

		switch (child_type_id) {
		case LogicalTypeId::DOUBLE: {
			double val;
			if (TryCast::Operation<string_t, double>(elem_str, val)) {
				FlatVector::GetData<double>(child_vec)[child_idx] = val;
			} else {
				FlatVector::SetNull(child_vec, child_idx, true);
			}
			break;
		}
		case LogicalTypeId::UBIGINT: {
			uint64_t val;
			if (TryCast::Operation<string_t, uint64_t>(elem_str, val)) {
				FlatVector::GetData<uint64_t>(child_vec)[child_idx] = val;
			} else {
				FlatVector::SetNull(child_vec, child_idx, true);
			}
			break;
		}
		case LogicalTypeId::BIGINT: {
			int64_t val;
			if (TryCast::Operation<string_t, int64_t>(elem_str, val)) {
				FlatVector::GetData<int64_t>(child_vec)[child_idx] = val;
			} else {
				FlatVector::SetNull(child_vec, child_idx, true);
			}
			break;
		}
		case LogicalTypeId::BOOLEAN: {
			FlatVector::GetData<bool>(child_vec)[child_idx] =
			    (elem.len == 1 && elem.ptr[0] == 'T') || (elem.len == 4 && std::memcmp(elem.ptr, "true", 4) == 0);
			break;
		}
		case LogicalTypeId::TIMESTAMP_TZ: {
			double val;
			if (TryCast::Operation<string_t, double>(elem_str, val)) {
				FlatVector::GetData<timestamp_tz_t>(child_vec)[child_idx] = EpochSecondsToTimestampTZ(val);
			} else {
				FlatVector::SetNull(child_vec, child_idx, true);
			}
			break;
		}
		case LogicalTypeId::INTERVAL: {
			double val;
			if (TryCast::Operation<string_t, double>(elem_str, val)) {
				FlatVector::GetData<interval_t>(child_vec)[child_idx] = SecondsToInterval(val);
			} else {
				FlatVector::SetNull(child_vec, child_idx, true);
			}
			break;
		}
		case LogicalTypeId::USMALLINT: {
			uint16_t val;
			if (TryCast::Operation<string_t, uint16_t>(elem_str, val)) {
				FlatVector::GetData<uint16_t>(child_vec)[child_idx] = val;
			} else {
				FlatVector::SetNull(child_vec, child_idx, true);
			}
			break;
		}
		case LogicalTypeId::VARCHAR: {
			FlatVector::GetData<string_t>(child_vec)[child_idx] =
			    StringVector::AddString(child_vec, elem.ptr, elem.len);
			break;
		}
		default: {
			child_vec.SetValue(child_idx, Value(string(elem.ptr, elem.len)).CastAs(context, child_type));
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

	auto glob_result = fs.Glob(pattern);
	if (glob_result.empty()) {
		throw IOException("No files found matching pattern: %s", pattern);
	}
	for (auto &file_info : glob_result) {
		result->file_paths.push_back(file_info.path);
	}
	std::sort(result->file_paths.begin(), result->file_paths.end());

	auto filename_param = input.named_parameters.find("filename");
	if (filename_param != input.named_parameters.end()) {
		result->filename_column = filename_param->second.GetValue<bool>();
	}

	bool replace_periods = true;
	auto replace_periods_param = input.named_parameters.find("replace_periods");
	if (replace_periods_param != input.named_parameters.end()) {
		replace_periods = replace_periods_param->second.GetValue<bool>();
	}

	auto inet_param = input.named_parameters.find("inet");
	if (inet_param != input.named_parameters.end()) {
		result->use_inet = inet_param->second.GetValue<bool>();
	}

	auto file_handle =
	    fs.OpenFile(result->file_paths[0], FileFlags::FILE_FLAGS_READ | FileCompressionType::AUTO_DETECT);
	result->header = ZeekReader::ParseHeader(*file_handle);

	for (idx_t i = 0; i < result->header.fields.size(); i++) {
		string col_name = result->header.fields[i];
		if (replace_periods) {
			std::replace(col_name.begin(), col_name.end(), '.', '_');
		}
		names.push_back(col_name);
		LogicalType col_type = ZeekReader::ZeekTypeToDuckDBType(result->header.types[i], result->use_inet, &context);
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

	result->total_files = bind_data.file_paths.size();

	// Resolve projection: which schema columns does the query actually want?
	// column_ids is provided by DuckDB when projection_pushdown = true.
	// An empty column_ids means COUNT(*) — no columns needed at all.
	if (input.column_ids.empty()) {
		result->count_only = true;
	} else {
		for (auto &col_id : input.column_ids) {
			result->projected_schema_cols.push_back(col_id);
		}
	}

	// For each projected column, decide whether it needs the batched cast path. Threads will
	// each allocate their own temp vectors based on this list.
	const idx_t data_col_count = bind_data.column_types.size();
	result->needs_cast_buffer.resize(result->projected_schema_cols.size(), false);
	for (idx_t out_idx = 0; out_idx < result->projected_schema_cols.size(); out_idx++) {
		column_t schema_col = result->projected_schema_cols[out_idx];
		if (bind_data.filename_column && schema_col == data_col_count) {
			continue;
		}
		if (schema_col >= data_col_count) {
			continue;
		}
		if (!IsNativelyHandled(bind_data.column_types[schema_col])) {
			result->needs_cast_buffer[out_idx] = true;
		}
	}

	// Capture any pushed-down filters for per-row evaluation.
	result->filters = input.filters;

	return std::move(result);
}

static unique_ptr<LocalTableFunctionState> ZeekScanInitLocal(ExecutionContext &context, TableFunctionInitInput &input,
                                                             GlobalTableFunctionState *global_state) {
	auto &gstate = global_state->Cast<ZeekScanGlobalState>();
	auto result = make_uniq<ZeekScanLocalState>();

	// Allocate this thread's read buffer.
	result->read_buffer.resize(READ_BUFFER_SIZE);

	// Allocate per-thread cast temp vectors based on global state's needs_cast_buffer.
	result->cast_temp_vecs.resize(gstate.needs_cast_buffer.size());
	for (idx_t out_idx = 0; out_idx < gstate.needs_cast_buffer.size(); out_idx++) {
		if (gstate.needs_cast_buffer[out_idx]) {
			result->cast_temp_vecs[out_idx] = make_uniq<Vector>(LogicalType::VARCHAR, STANDARD_VECTOR_SIZE);
		}
	}

	return std::move(result);
}

static void ZeekScanExecute(ClientContext &context, TableFunctionInput &data, DataChunk &output) {
	auto &bind_data = data.bind_data->Cast<ZeekScanBindData>();
	auto &gstate = data.global_state->Cast<ZeekScanGlobalState>();
	auto &lstate = data.local_state->Cast<ZeekScanLocalState>();

	if (lstate.finished) {
		output.SetCardinality(0);
		return;
	}

	idx_t row_count = 0;
	const idx_t data_col_count = bind_data.column_types.size();
	const idx_t filename_col_idx = data_col_count; // virtual column index for filename
	const string &unset_field = bind_data.header.unset_field;
	const string &empty_field = bind_data.header.empty_field;
	const char field_separator = bind_data.header.separator;

	while (row_count < STANDARD_VECTOR_SIZE) {
		// Open the first/next file if this thread doesn't currently have one.
		if (!lstate.file_handle) {
			if (!OpenNextFile(context, gstate, lstate, bind_data)) {
				lstate.finished = true;
				break;
			}
		}

		if (!ReadLineBuffered(lstate)) {
			// EOF on current file — release it and try the next.
			lstate.file_handle.reset();
			continue;
		}

		// Skip empty lines and Zeek metadata comment lines.
		if (lstate.line_buffer.empty() || lstate.line_buffer[0] == '#') {
			continue;
		}

		// COUNT(*) fast path: no columns needed, just count rows.
		if (gstate.count_only) {
			row_count++;
			continue;
		}

		// Tokenize the line into field slices (reused vector — no allocation per row in steady state).
		TokenizeSpan(lstate.line_buffer.data(), static_cast<uint32_t>(lstate.line_buffer.size()), field_separator,
		             lstate.field_slices);
		const idx_t num_fields = lstate.field_slices.size();

		// Evaluate pushed-down filters on this row. If any filter fails, skip the entire row
		// without parsing the non-filter projected columns.
		if (gstate.filters) {
			bool row_passes = true;
			for (auto &entry : gstate.filters->filters) {
				idx_t filter_out_idx = entry.first; // index into projected_schema_cols
				const TableFilter &filter = *entry.second;
				column_t schema_col = gstate.projected_schema_cols[filter_out_idx];

				// Filename virtual column filter (VARCHAR).
				if (bind_data.filename_column && schema_col == filename_col_idx) {
					Value v(lstate.current_file_path);
					if (!EvaluateFilter(filter, v, false)) {
						row_passes = false;
						break;
					}
					continue;
				}

				// Missing field → treat as NULL.
				if (schema_col >= num_fields) {
					Value null_val(bind_data.column_types[schema_col]);
					if (!EvaluateFilter(filter, null_val, true)) {
						row_passes = false;
						break;
					}
					continue;
				}

				const FieldSlice &field = lstate.field_slices[schema_col];

				// Unset/empty marker → treat as NULL.
				if (SliceEquals(field, unset_field) || SliceEquals(field, empty_field)) {
					Value null_val(bind_data.column_types[schema_col]);
					if (!EvaluateFilter(filter, null_val, true)) {
						row_passes = false;
						break;
					}
					continue;
				}

				// Parse the slice into a Value of the column's type and evaluate.
				Value row_val = SliceToValue(field, bind_data.column_types[schema_col]);
				if (!EvaluateFilter(filter, row_val, row_val.IsNull())) {
					row_passes = false;
					break;
				}
			}
			if (!row_passes) {
				continue;
			}
		}

		// Walk projected output columns and emit values for those.
		for (idx_t out_idx = 0; out_idx < gstate.projected_schema_cols.size(); out_idx++) {
			column_t schema_col = gstate.projected_schema_cols[out_idx];
			auto &vec = output.data[out_idx];

			// Filename virtual column.
			if (bind_data.filename_column && schema_col == filename_col_idx) {
				FlatVector::GetData<string_t>(vec)[row_count] = StringVector::AddString(vec, lstate.current_file_path);
				continue;
			}

			// For non-native columns (e.g. INET) we accumulate into a temp VARCHAR vector and
			// batch-cast to the real output at end of chunk. For native columns target_vec == vec.
			Vector &target_vec = lstate.cast_temp_vecs[out_idx] ? *lstate.cast_temp_vecs[out_idx] : vec;

			// Out-of-range data column → NULL.
			if (schema_col >= num_fields) {
				FlatVector::SetNull(target_vec, row_count, true);
				continue;
			}

			const FieldSlice &field = lstate.field_slices[schema_col];

			if (SliceEquals(field, unset_field) || SliceEquals(field, empty_field)) {
				FlatVector::SetNull(target_vec, row_count, true);
				continue;
			}

			string_t field_str(field.ptr, field.len);
			auto type_id = bind_data.column_types[schema_col].id();

			switch (type_id) {
			case LogicalTypeId::VARCHAR: {
				FlatVector::GetData<string_t>(vec)[row_count] = StringVector::AddString(vec, field.ptr, field.len);
				break;
			}
			case LogicalTypeId::DOUBLE: {
				double val;
				if (TryCast::Operation<string_t, double>(field_str, val)) {
					FlatVector::GetData<double>(vec)[row_count] = val;
				} else {
					FlatVector::SetNull(vec, row_count, true);
				}
				break;
			}
			case LogicalTypeId::UBIGINT: {
				uint64_t val;
				if (TryCast::Operation<string_t, uint64_t>(field_str, val)) {
					FlatVector::GetData<uint64_t>(vec)[row_count] = val;
				} else {
					FlatVector::SetNull(vec, row_count, true);
				}
				break;
			}
			case LogicalTypeId::BIGINT: {
				int64_t val;
				if (TryCast::Operation<string_t, int64_t>(field_str, val)) {
					FlatVector::GetData<int64_t>(vec)[row_count] = val;
				} else {
					FlatVector::SetNull(vec, row_count, true);
				}
				break;
			}
			case LogicalTypeId::BOOLEAN: {
				FlatVector::GetData<bool>(vec)[row_count] = (field.len == 1 && field.ptr[0] == 'T') ||
				                                            (field.len == 4 && std::memcmp(field.ptr, "true", 4) == 0);
				break;
			}
			case LogicalTypeId::TIMESTAMP_TZ: {
				double val;
				if (TryCast::Operation<string_t, double>(field_str, val)) {
					FlatVector::GetData<timestamp_tz_t>(vec)[row_count] = EpochSecondsToTimestampTZ(val);
				} else {
					FlatVector::SetNull(vec, row_count, true);
				}
				break;
			}
			case LogicalTypeId::INTERVAL: {
				double val;
				if (TryCast::Operation<string_t, double>(field_str, val)) {
					FlatVector::GetData<interval_t>(vec)[row_count] = SecondsToInterval(val);
				} else {
					FlatVector::SetNull(vec, row_count, true);
				}
				break;
			}
			case LogicalTypeId::USMALLINT: {
				uint16_t val;
				if (TryCast::Operation<string_t, uint16_t>(field_str, val)) {
					FlatVector::GetData<uint16_t>(vec)[row_count] = val;
				} else {
					FlatVector::SetNull(vec, row_count, true);
				}
				break;
			}
			case LogicalTypeId::LIST: {
				auto &child_type = ListType::GetChildType(bind_data.column_types[schema_col]);
				AppendListValue(context, lstate, vec, row_count, field, bind_data.header.set_separator, child_type,
				                unset_field, empty_field);
				break;
			}
			default: {
				// Non-native type (e.g. INET): write the slice into the temp VARCHAR vector
				// (target_vec is the temp). The batch cast at end of chunk converts to the real type.
				FlatVector::GetData<string_t>(target_vec)[row_count] =
				    StringVector::AddString(target_vec, field.ptr, field.len);
				break;
			}
			}
		}

		row_count++;
	}

	// Batch-cast each non-native column's accumulated VARCHAR slices into its real output vector.
	if (row_count > 0) {
		for (idx_t out_idx = 0; out_idx < lstate.cast_temp_vecs.size(); out_idx++) {
			if (!lstate.cast_temp_vecs[out_idx]) {
				continue;
			}
			VectorOperations::Cast(context, *lstate.cast_temp_vecs[out_idx], output.data[out_idx], row_count);
		}
	}

	output.SetCardinality(row_count);
}

//! Callback: can we push down a filter on the given (schema) column index?
//! We return true only for types we can cheaply parse from a slice per-row.
static bool ZeekSupportsPushdownType(const FunctionData &bind_data_p, idx_t col_idx) {
	auto &bind_data = bind_data_p.Cast<ZeekScanBindData>();
	// The filename virtual column is always VARCHAR; filters on it are cheap.
	if (col_idx >= bind_data.column_types.size()) {
		return true;
	}
	return CanPushdownFilterOnType(bind_data.column_types[col_idx]);
}

TableFunction GetZeekScanFunction() {
	TableFunction func("read_zeek", {LogicalType::VARCHAR}, ZeekScanExecute, ZeekScanBind, ZeekScanInitGlobal,
	                   ZeekScanInitLocal);
	func.named_parameters["filename"] = LogicalType::BOOLEAN;
	func.named_parameters["replace_periods"] = LogicalType::BOOLEAN;
	func.named_parameters["inet"] = LogicalType::BOOLEAN;
	func.projection_pushdown = true;
	func.filter_pushdown = true;
	func.supports_pushdown_type = ZeekSupportsPushdownType;
	return func;
}

} // namespace duckdb
