#include "zeek_reader.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/enums/file_compression_type.hpp"
#include "duckdb/common/types/vector.hpp"
#include "duckdb/common/vector/list_vector.hpp"
#include "duckdb/common/types/timestamp.hpp"
#include "duckdb/common/types/interval.hpp"
#include "duckdb/common/operator/cast_operators.hpp"
#include "duckdb/common/vector_operations/vector_operations.hpp"
#include "duckdb/common/operator/comparison_operators.hpp"
#include "duckdb/planner/filter/expression_filter.hpp"
#include "duckdb/planner/table_filter_set.hpp"
#include "duckdb/planner/expression/bound_between_expression.hpp"
#include "duckdb/planner/expression/bound_conjunction_expression.hpp"
#include "duckdb/planner/expression/bound_constant_expression.hpp"

#include <cstring>
#include <unordered_map>

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

//! Returns true if the type is the inet extension's INET type (a STRUCT aliased "INET").
static bool IsInetType(const LogicalType &type) {
	return type.id() == LogicalTypeId::STRUCT && type.HasAlias() && type.GetAlias() == "INET";
}

//! Returns true if filter pushdown is efficient for this column type (see supports_pushdown_type).
//! We advertise pushdown for types we can parse from a slice, plus INET. INET requires an extension
//! cast per row, but pushing it down is still preferable to letting DuckDB extract the filter into a
//! PhysicalFilter — that extraction path corrupts projection_ids on multi-column projections and
//! crashes ("Attempted to access index N within vector of size N"). LIST is still excluded.
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
		return IsInetType(type);
	}
}

//! Parse a slice into a DuckDB Value of the given type. Returns a NULL Value of the target type
//! on parse failure. This is only called for filter columns and only for types where
//! CanPushdownFilterOnType returns true. `context` is needed for the INET extension cast.
static Value SliceToValue(ClientContext &context, const FieldSlice &field, const LogicalType &type) {
	if (IsInetType(type)) {
		// The slice is the textual address; cast a VARCHAR Value to INET so the comparison runs
		// with the inet extension's semantics (normalization, IP-aware ordering).
		if (auto inet_val = Value(string(field.ptr, field.len)).TryCastAs(context, type)) {
			return *inet_val;
		}
		return Value(type);
	}
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

template <class T>
static void NormalizeValueRange(ZeekValueRange<T> &range) {
	if (!range.lower || !range.upper) {
		return;
	}
	if (*range.lower > *range.upper ||
	    (*range.lower == *range.upper && (!range.lower_inclusive || !range.upper_inclusive))) {
		range.empty = true;
	}
}

template <class T>
static void AddValueLowerBound(ZeekValueRange<T> &range, T value, bool inclusive) {
	if (!range.lower || value > *range.lower) {
		range.lower = value;
		range.lower_inclusive = inclusive;
	} else if (value == *range.lower) {
		range.lower_inclusive = range.lower_inclusive && inclusive;
	}
	NormalizeValueRange(range);
}

template <class T>
static void AddValueUpperBound(ZeekValueRange<T> &range, T value, bool inclusive) {
	if (!range.upper || value < *range.upper) {
		range.upper = value;
		range.upper_inclusive = inclusive;
	} else if (value == *range.upper) {
		range.upper_inclusive = range.upper_inclusive && inclusive;
	}
	NormalizeValueRange(range);
}

template <class T>
static void IntersectValueRanges(ZeekValueRange<T> &range, const ZeekValueRange<T> &other) {
	if (other.lower) {
		AddValueLowerBound(range, *other.lower, other.lower_inclusive);
	}
	if (other.upper) {
		AddValueUpperBound(range, *other.upper, other.upper_inclusive);
	}
	range.empty = range.empty || other.empty;
	NormalizeValueRange(range);
}

template <class T>
static bool TryGetTemporalConstant(const Expression &expression, LogicalTypeId type, T &result) {
	if (expression.GetExpressionClass() != ExpressionClass::BOUND_CONSTANT) {
		return false;
	}
	const auto &value = expression.Cast<BoundConstantExpression>().GetValue();
	if (value.IsNull() || value.type().id() != type) {
		return false;
	}
	result = value.GetValue<T>();
	return true;
}

//! Extract only direct temporal bounds. Unsupported expressions remain evaluated by the scan.
template <class T>
static bool ExtractZeekValueRange(const Expression &expression, ZeekValueRange<T> &range, LogicalTypeId type) {
	if (expression.GetExpressionClass() == ExpressionClass::BOUND_CONJUNCTION &&
	    expression.GetExpressionType() == ExpressionType::CONJUNCTION_AND) {
		auto &conjunction = expression.Cast<BoundConjunctionExpression>();
		bool found_constraint = false;
		for (auto &child : conjunction.GetChildren()) {
			ZeekValueRange<T> child_range;
			if (!ExtractZeekValueRange(*child, child_range, type)) {
				continue;
			}
			IntersectValueRanges(range, child_range);
			found_constraint = true;
		}
		return found_constraint;
	}

	if (expression.GetExpressionClass() != ExpressionClass::BOUND_FUNCTION) {
		return false;
	}
	auto &function = expression.Cast<BoundFunctionExpression>();
	if (expression.GetExpressionType() == ExpressionType::COMPARE_BETWEEN) {
		if (!BoundBetweenExpression::HasValidBindData(function) ||
		    !ExpressionFilter::IsSimpleFilterColumnRef(BoundBetweenExpression::Input(function))) {
			return false;
		}
		T lower;
		T upper;
		if (!TryGetTemporalConstant(BoundBetweenExpression::LowerBound(function), type, lower) ||
		    !TryGetTemporalConstant(BoundBetweenExpression::UpperBound(function), type, upper)) {
			return false;
		}
		AddValueLowerBound(range, lower, BoundBetweenExpression::LowerInclusive(function));
		AddValueUpperBound(range, upper, BoundBetweenExpression::UpperInclusive(function));
		return true;
	}

	if (!BoundComparisonExpression::IsComparison(expression)) {
		return false;
	}
	ExpressionType comparison_type;
	auto constant = ExpressionFilter::TryGetColumnConstantComparison(function, comparison_type);
	if (!constant) {
		return false;
	}
	T value;
	if (!TryGetTemporalConstant(*constant, type, value)) {
		return false;
	}

	switch (comparison_type) {
	case ExpressionType::COMPARE_EQUAL:
		AddValueLowerBound(range, value, true);
		AddValueUpperBound(range, value, true);
		return true;
	case ExpressionType::COMPARE_GREATERTHAN:
		AddValueLowerBound(range, value, false);
		return true;
	case ExpressionType::COMPARE_GREATERTHANOREQUALTO:
		AddValueLowerBound(range, value, true);
		return true;
	case ExpressionType::COMPARE_LESSTHAN:
		AddValueUpperBound(range, value, false);
		return true;
	case ExpressionType::COMPARE_LESSTHANOREQUALTO:
		AddValueUpperBound(range, value, true);
		return true;
	default:
		return false;
	}
}

template <class T>
static optional<ZeekValueRange<T>> ExtractZeekValueRange(const TableFilterSet &filters,
                                                         const vector<column_t> &scan_schema_cols, column_t column_idx,
                                                         LogicalTypeId type) {
	ZeekValueRange<T> range;
	bool found_constraint = false;
	for (const auto &entry : filters) {
		idx_t scan_idx = entry.GetIndex().GetIndex();
		if (scan_idx >= scan_schema_cols.size() || scan_schema_cols[scan_idx] != column_idx ||
		    entry.Filter().filter_type != TableFilterType::EXPRESSION_FILTER) {
			continue;
		}
		ZeekValueRange<T> filter_range;
		auto &expr_filter = ExpressionFilter::GetExpressionFilter(entry.Filter(), "read_zeek");
		if (!ExtractZeekValueRange(*expr_filter.expr, filter_range, type)) {
			continue;
		}
		IntersectValueRanges(range, filter_range);
		found_constraint = true;
	}
	if (!found_constraint) {
		return {};
	}
	return range;
}

template <class T>
static bool ValueMatchesRange(T value, const ZeekValueRange<T> &range) {
	if (range.empty) {
		return false;
	}
	if (range.lower && (value < *range.lower || (value == *range.lower && !range.lower_inclusive))) {
		return false;
	}
	if (range.upper && (value > *range.upper || (value == *range.upper && !range.upper_inclusive))) {
		return false;
	}
	return true;
}

//! Atomically claim the next file from the shared queue and open it for the calling thread.
//! Returns false if no more files remain.
static bool OpenNextFile(ClientContext &context, ZeekScanGlobalState &gstate, ZeekScanLocalState &lstate,
                         const ZeekScanBindData &bind_data) {
	auto &fs = FileSystem::GetFileSystem(context);

	while (true) {
		idx_t scan_file_idx = gstate.next_file_idx.fetch_add(1, std::memory_order_relaxed);
		if (scan_file_idx >= gstate.scan_file_indices.size()) {
			return false;
		}
		idx_t my_file_idx = gstate.scan_file_indices[scan_file_idx];

		lstate.current_file_idx = my_file_idx;
		lstate.current_file_path = bind_data.file_paths[my_file_idx];

		try {
			lstate.file_handle =
			    fs.OpenFile(lstate.current_file_path, FileFlags::FILE_FLAGS_READ | FileCompressionType::AUTO_DETECT);

			// Reset buffer state for the new file.
			lstate.buffer_pos = 0;
			lstate.buffer_size = 0;
			lstate.eof_reached = false;
			lstate.has_pending_line = false;

			// Parse this file's header via the buffered reader. We read lines until we hit the first
			// non-directive (data) line, parse each `#` line as a directive, and leave the first data
			// line in line_buffer with has_pending_line=true so the hot loop can consume it without
			// re-reading.
			ZeekHeader file_header;
			while (ReadLineBuffered(lstate)) {
				if (!ZeekReader::ApplyHeaderLine(lstate.line_buffer.data(), lstate.line_buffer.size(), file_header)) {
					lstate.has_pending_line = true;
					break;
				}
			}

			if (file_header.fields.empty()) {
				throw InvalidInputException("read_zeek: file '%s' is missing #fields directive",
				                            lstate.current_file_path);
			}
			if (file_header.types.empty()) {
				throw InvalidInputException("read_zeek: file '%s' is missing #types directive",
				                            lstate.current_file_path);
			}
			if (file_header.fields.size() != file_header.types.size()) {
				throw InvalidInputException("read_zeek: file '%s' has mismatched #fields and #types counts",
				                            lstate.current_file_path);
			}

			// In strict mode, the bound schema must match this file exactly.
			if (!bind_data.union_by_name) {
				string mismatch;
				if (!SameSchema(bind_data.header, file_header, mismatch)) {
					throw InvalidInputException(
					    "read_zeek: file '%s' has a different schema than '%s' (the first file in the glob): %s",
					    lstate.current_file_path, bind_data.file_paths[0], mismatch);
				}
			}

			// Build the per-file field lookup table used by the hot loop.
			// Strict mode: identity mapping (schema_col == field_idx_in_file).
			// Union mode: copy from the precomputed inverse mapping.
			const idx_t bound_col_count = bind_data.header.fields.size();
			if (bind_data.union_by_name) {
				lstate.field_lookup = bind_data.union_to_file_field[my_file_idx];
			} else {
				lstate.field_lookup.resize(bound_col_count);
				for (idx_t i = 0; i < bound_col_count; i++) {
					lstate.field_lookup[i] = i;
				}
			}
			return true;
		} catch (const std::exception &e) {
			// If ignore_file_errors is enabled, skip this file and try the next one.
			// Otherwise, re-throw the exception to fail the query.
			if (bind_data.ignore_file_errors) {
				// Close any partially-opened file handle and continue to the next file.
				lstate.file_handle.reset();
				continue;
			} else {
				throw;
			}
		}
	}
}

static void AppendListValue(ClientContext &context, ZeekScanLocalState &lstate, Vector &vec, idx_t row_idx,
                            const FieldSlice &field, char set_separator, const LogicalType &child_type,
                            const string &unset_field, const string &empty_field) {
	auto &list_entry = FlatVector::GetDataMutable<list_entry_t>(vec)[row_idx];
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

	auto &child_vec = ListVector::GetChildMutable(vec);
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
				FlatVector::GetDataMutable<double>(child_vec)[child_idx] = val;
			} else {
				FlatVector::SetNull(child_vec, child_idx, true);
			}
			break;
		}
		case LogicalTypeId::UBIGINT: {
			uint64_t val;
			if (TryCast::Operation<string_t, uint64_t>(elem_str, val)) {
				FlatVector::GetDataMutable<uint64_t>(child_vec)[child_idx] = val;
			} else {
				FlatVector::SetNull(child_vec, child_idx, true);
			}
			break;
		}
		case LogicalTypeId::BIGINT: {
			int64_t val;
			if (TryCast::Operation<string_t, int64_t>(elem_str, val)) {
				FlatVector::GetDataMutable<int64_t>(child_vec)[child_idx] = val;
			} else {
				FlatVector::SetNull(child_vec, child_idx, true);
			}
			break;
		}
		case LogicalTypeId::BOOLEAN: {
			FlatVector::GetDataMutable<bool>(child_vec)[child_idx] =
			    (elem.len == 1 && elem.ptr[0] == 'T') || (elem.len == 4 && std::memcmp(elem.ptr, "true", 4) == 0);
			break;
		}
		case LogicalTypeId::TIMESTAMP_TZ: {
			double val;
			if (TryCast::Operation<string_t, double>(elem_str, val)) {
				FlatVector::GetDataMutable<timestamp_tz_t>(child_vec)[child_idx] = EpochSecondsToTimestampTZ(val);
			} else {
				FlatVector::SetNull(child_vec, child_idx, true);
			}
			break;
		}
		case LogicalTypeId::INTERVAL: {
			double val;
			if (TryCast::Operation<string_t, double>(elem_str, val)) {
				FlatVector::GetDataMutable<interval_t>(child_vec)[child_idx] = SecondsToInterval(val);
			} else {
				FlatVector::SetNull(child_vec, child_idx, true);
			}
			break;
		}
		case LogicalTypeId::USMALLINT: {
			uint16_t val;
			if (TryCast::Operation<string_t, uint16_t>(elem_str, val)) {
				FlatVector::GetDataMutable<uint16_t>(child_vec)[child_idx] = val;
			} else {
				FlatVector::SetNull(child_vec, child_idx, true);
			}
			break;
		}
		case LogicalTypeId::VARCHAR: {
			FlatVector::GetDataMutable<string_t>(child_vec)[child_idx] =
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
                                             vector<LogicalType> &return_types, vector<Identifier> &names) {
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

	auto partition_discovery_param = input.named_parameters.find("partition_discovery");
	if (partition_discovery_param != input.named_parameters.end()) {
		result->partition_discovery = partition_discovery_param->second.GetValue<bool>();
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

	auto union_by_name_param = input.named_parameters.find("union_by_name");
	if (union_by_name_param != input.named_parameters.end()) {
		result->union_by_name = union_by_name_param->second.GetValue<bool>();
	}

	auto ignore_file_errors_param = input.named_parameters.find("ignore_file_errors");
	if (ignore_file_errors_param != input.named_parameters.end()) {
		result->ignore_file_errors = ignore_file_errors_param->second.GetValue<bool>();
	}

	if (result->partition_discovery) {
		result->file_dates.reserve(result->file_paths.size());
		result->file_time_ranges.reserve(result->file_paths.size());
		for (auto &file_path : result->file_paths) {
			auto file_date = TryExtractZeekLogDate(file_path);
			result->file_dates.push_back(file_date);
			result->file_time_ranges.push_back(file_date ? TryExtractZeekLogTimeRange(file_path, *file_date)
			                                             : optional<ZeekFileTimeRange>());
		}
	}

	if (!result->union_by_name) {
		// Strict mode: parse only the first file's header. Per-file validation happens at scan time.
		// If ignore_file_errors is enabled, try each file until we find one that works.
		bool found_valid_file = false;
		for (idx_t file_idx = 0; file_idx < result->file_paths.size(); file_idx++) {
			try {
				auto file_handle = fs.OpenFile(result->file_paths[file_idx],
				                               FileFlags::FILE_FLAGS_READ | FileCompressionType::AUTO_DETECT);
				result->header = ZeekReader::ParseHeader(*file_handle);
				found_valid_file = true;
				break;
			} catch (const std::exception &e) {
				if (!result->ignore_file_errors) {
					throw;
				}
				// Skip this file and try the next one
			}
		}
		if (!found_valid_file) {
			if (result->ignore_file_errors) {
				throw IOException("No valid Zeek log files found in pattern: %s", pattern);
			} else {
				throw IOException("No files found matching pattern: %s", pattern);
			}
		}
	} else {
		// Union mode: open every file, parse its header, build the union schema and per-file
		// inverse mappings. Same field name + different Zeek type → bind-time error.
		vector<vector<idx_t>> file_field_to_union(result->file_paths.size());
		std::unordered_map<string, idx_t> name_to_union_idx;
		bool first_file = true;

		for (idx_t file_idx = 0; file_idx < result->file_paths.size(); file_idx++) {
			ZeekHeader file_header;
			try {
				auto file_handle = fs.OpenFile(result->file_paths[file_idx],
				                               FileFlags::FILE_FLAGS_READ | FileCompressionType::AUTO_DETECT);
				file_header = ZeekReader::ParseHeader(*file_handle);
			} catch (const std::exception &e) {
				if (!result->ignore_file_errors) {
					throw;
				}
				// Skip this corrupted file - mark it as having no fields so OpenNextFile will also skip it
				file_field_to_union[file_idx].clear();
				continue;
			}

			if (first_file) {
				// Use file 0's separators / null markers as the canonical settings.
				result->header.separator = file_header.separator;
				result->header.set_separator = file_header.set_separator;
				result->header.unset_field = file_header.unset_field;
				result->header.empty_field = file_header.empty_field;
				first_file = false;
			} else {
				// All files in a union must agree on the lexical syntax (separators, null markers).
				if (file_header.separator != result->header.separator ||
				    file_header.set_separator != result->header.set_separator ||
				    file_header.unset_field != result->header.unset_field ||
				    file_header.empty_field != result->header.empty_field) {
					throw InvalidInputException("read_zeek: file '%s' has different separators or null markers than "
					                            "'%s'; cannot union files with incompatible lexical syntax",
					                            result->file_paths[file_idx], result->file_paths[0]);
				}
			}

			file_field_to_union[file_idx].resize(file_header.fields.size());
			for (idx_t f = 0; f < file_header.fields.size(); f++) {
				const string &fname = file_header.fields[f];
				const string &ftype = file_header.types[f];

				auto it = name_to_union_idx.find(fname);
				if (it == name_to_union_idx.end()) {
					idx_t new_union_idx = result->header.fields.size();
					result->header.fields.push_back(fname);
					result->header.types.push_back(ftype);
					name_to_union_idx[fname] = new_union_idx;
					file_field_to_union[file_idx][f] = new_union_idx;
				} else {
					idx_t existing = it->second;
					if (result->header.types[existing] != ftype) {
						throw InvalidInputException("read_zeek: field '%s' has type '%s' in '%s' but type '%s' in '%s'",
						                            fname, result->header.types[existing], result->file_paths[0], ftype,
						                            result->file_paths[file_idx]);
					}
					file_field_to_union[file_idx][f] = existing;
				}
			}
		}

		// Check if at least one file was successfully processed
		if (result->header.fields.empty()) {
			if (result->ignore_file_errors) {
				throw IOException("No valid Zeek log files found in pattern: %s (all files failed to parse)", pattern);
			} else {
				throw IOException("No valid Zeek log files found in pattern: %s", pattern);
			}
		}

		// Second pass: build the inverse mapping (union_col -> field_idx_in_file or idx_t(-1)).
		const idx_t union_size = result->header.fields.size();
		result->union_to_file_field.resize(result->file_paths.size());
		for (idx_t file_idx = 0; file_idx < result->file_paths.size(); file_idx++) {
			auto &inverse = result->union_to_file_field[file_idx];
			inverse.assign(union_size, idx_t(-1));
			for (idx_t f = 0; f < file_field_to_union[file_idx].size(); f++) {
				inverse[file_field_to_union[file_idx][f]] = f;
			}
		}
	}

	for (idx_t i = 0; i < result->header.fields.size(); i++) {
		string col_name = result->header.fields[i];
		if (replace_periods) {
			std::replace(col_name.begin(), col_name.end(), '.', '_');
		}
		if (result->partition_discovery &&
		    (StringUtil::CIEquals(col_name, "log_date") || StringUtil::CIEquals(col_name, "log_start_time") ||
		     StringUtil::CIEquals(col_name, "log_end_time"))) {
			throw BinderException("read_zeek: partition_discovery adds virtual date/time columns, but a log file "
			                      "already contains the name '%s'",
			                      col_name);
		}
		names.push_back(Identifier(col_name));
		LogicalType col_type = ZeekReader::ZeekTypeToDuckDBType(result->header.types[i], result->use_inet, &context);
		return_types.push_back(col_type);
		result->column_types.push_back(col_type);
	}

	if (result->partition_discovery) {
		result->log_date_column_idx = static_cast<column_t>(return_types.size());
		names.push_back(Identifier("log_date"));
		return_types.push_back(LogicalType::DATE);

		result->log_start_time_column_idx = static_cast<column_t>(return_types.size());
		names.push_back(Identifier("log_start_time"));
		return_types.push_back(LogicalType::TIMESTAMP);

		result->log_end_time_column_idx = static_cast<column_t>(return_types.size());
		names.push_back(Identifier("log_end_time"));
		return_types.push_back(LogicalType::TIMESTAMP);
	}

	if (result->filename_column) {
		result->filename_column_idx = static_cast<column_t>(return_types.size());
		names.push_back("filename");
		return_types.push_back(LogicalType::VARCHAR);
	}

	return std::move(result);
}

static unique_ptr<GlobalTableFunctionState> ZeekScanInitGlobal(ClientContext &context, TableFunctionInitInput &input) {
	auto &bind_data = input.bind_data->Cast<ZeekScanBindData>();
	auto result = make_uniq<ZeekScanGlobalState>();

	// Resolve projection: which schema columns does the query actually want?
	// column_ids is provided by DuckDB when projection_pushdown = true.
	// projection_ids maps from output DataChunk position to column_ids index.
	// When empty, the mapping is identity (output.data[i] == column_ids[i]).
	// An empty column_ids means COUNT(*) — no columns needed at all.
	if (input.column_ids.empty()) {
		result->count_only = true;
	} else if (input.projection_ids.empty()) {
		// Identity mapping: every column_ids entry is an output column.
		for (auto &col_id : input.column_ids) {
			result->projected_schema_cols.push_back(col_id);
		}
	} else {
		// Non-identity projection: only columns referenced by projection_ids go to output.
		result->projected_schema_cols.reserve(input.projection_ids.size());
		for (auto &proj_idx : input.projection_ids) {
			result->projected_schema_cols.push_back(input.column_ids[proj_idx]);
		}
	}

	// For each projected column, decide whether it needs the batched cast path. Threads will
	// each allocate their own temp vectors based on this list.
	const idx_t data_col_count = bind_data.column_types.size();
	result->needs_cast_buffer.resize(result->projected_schema_cols.size(), false);
	for (idx_t out_idx = 0; out_idx < result->projected_schema_cols.size(); out_idx++) {
		column_t schema_col = result->projected_schema_cols[out_idx];
		if (bind_data.filename_column_idx && schema_col == *bind_data.filename_column_idx) {
			continue;
		}
		if (schema_col >= data_col_count) {
			continue;
		}
		if (!IsNativelyHandled(bind_data.column_types[schema_col])) {
			result->needs_cast_buffer[out_idx] = true;
		}
	}

	// Pushed-down filter keys are positions in column_ids, so keep the scanned columns in that order.
	result->scan_schema_cols = input.column_ids;

	// Capture any pushed-down filters for per-row evaluation.
	result->filters = input.filters;

	if (bind_data.partition_discovery && input.filters) {
		if (bind_data.log_date_column_idx) {
			result->date_range = ExtractZeekValueRange<date_t>(*input.filters, result->scan_schema_cols,
			                                                   *bind_data.log_date_column_idx, LogicalTypeId::DATE);
		}
		if (bind_data.log_start_time_column_idx) {
			result->start_time_range =
			    ExtractZeekValueRange<timestamp_t>(*input.filters, result->scan_schema_cols,
			                                       *bind_data.log_start_time_column_idx, LogicalTypeId::TIMESTAMP);
		}
		if (bind_data.log_end_time_column_idx) {
			result->end_time_range = ExtractZeekValueRange<timestamp_t>(
			    *input.filters, result->scan_schema_cols, *bind_data.log_end_time_column_idx, LogicalTypeId::TIMESTAMP);
		}
	}
	result->scan_file_indices.reserve(bind_data.file_paths.size());
	for (idx_t file_idx = 0; file_idx < bind_data.file_paths.size(); file_idx++) {
		if (result->date_range && file_idx < bind_data.file_dates.size() && bind_data.file_dates[file_idx] &&
		    !ValueMatchesRange(*bind_data.file_dates[file_idx], *result->date_range)) {
			continue;
		}
		if (file_idx < bind_data.file_time_ranges.size() && bind_data.file_time_ranges[file_idx]) {
			const auto &time_range = *bind_data.file_time_ranges[file_idx];
			if ((result->start_time_range && !ValueMatchesRange(time_range.start, *result->start_time_range)) ||
			    (result->end_time_range && !ValueMatchesRange(time_range.end, *result->end_time_range))) {
				continue;
			}
		}
		result->scan_file_indices.push_back(file_idx);
	}
	result->total_files = result->scan_file_indices.size();

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

	// Build this thread's filter evaluators. Executors are not thread-safe, so each thread needs its own.
	if (gstate.filters) {
		result->filter_executors.resize(gstate.scan_schema_cols.size());
		for (auto &entry : *gstate.filters) {
			auto &expr_filter = ExpressionFilter::GetExpressionFilter(entry.Filter(), "read_zeek");
			result->filter_executors[entry.GetIndex().GetIndex()] =
			    make_uniq<ExpressionExecutor>(context.client, *expr_filter.expr);
		}
	}

	return std::move(result);
}

static void ZeekScanExecute(ClientContext &context, TableFunctionInput &data, DataChunk &output) {
	auto &bind_data = data.bind_data->Cast<ZeekScanBindData>();
	auto &gstate = data.global_state->Cast<ZeekScanGlobalState>();
	auto &lstate = data.local_state->Cast<ZeekScanLocalState>();

	if (lstate.finished) {
		output.SetChildCardinality(0);
		return;
	}

	idx_t row_count = 0;
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
			for (auto &entry : *gstate.filters) {
				// Filter keys are positions in column_ids, so they map to schema columns via scan_schema_cols.
				idx_t scan_idx = entry.GetIndex().GetIndex();
				column_t schema_col = gstate.scan_schema_cols[scan_idx];
				auto &expr_filter = ExpressionFilter::GetExpressionFilter(entry.Filter(), "read_zeek");
				auto &executor = *lstate.filter_executors[scan_idx];

				if (bind_data.log_date_column_idx && schema_col == *bind_data.log_date_column_idx) {
					const auto &file_date = bind_data.file_dates[lstate.current_file_idx];
					Value value = file_date ? Value::DATE(*file_date) : Value(LogicalType::DATE);
					if (!expr_filter.EvaluateWithConstant(executor, value)) {
						row_passes = false;
						break;
					}
					continue;
				}

				if (bind_data.log_start_time_column_idx && schema_col == *bind_data.log_start_time_column_idx) {
					const auto &file_time_range = bind_data.file_time_ranges[lstate.current_file_idx];
					Value value =
					    file_time_range ? Value::TIMESTAMP(file_time_range->start) : Value(LogicalType::TIMESTAMP);
					if (!expr_filter.EvaluateWithConstant(executor, value)) {
						row_passes = false;
						break;
					}
					continue;
				}

				if (bind_data.log_end_time_column_idx && schema_col == *bind_data.log_end_time_column_idx) {
					const auto &file_time_range = bind_data.file_time_ranges[lstate.current_file_idx];
					Value value =
					    file_time_range ? Value::TIMESTAMP(file_time_range->end) : Value(LogicalType::TIMESTAMP);
					if (!expr_filter.EvaluateWithConstant(executor, value)) {
						row_passes = false;
						break;
					}
					continue;
				}

				// Filename virtual column filter (VARCHAR).
				if (bind_data.filename_column_idx && schema_col == *bind_data.filename_column_idx) {
					Value v(lstate.current_file_path);
					if (!expr_filter.EvaluateWithConstant(executor, v)) {
						row_passes = false;
						break;
					}
					continue;
				}

				// Translate from bound schema column to this file's field position. In union
				// mode the field may be absent (idx_t(-1) wraps to a value larger than num_fields).
				idx_t file_field_idx = lstate.field_lookup[schema_col];
				if (file_field_idx >= num_fields) {
					Value null_val(bind_data.column_types[schema_col]);
					if (!expr_filter.EvaluateWithConstant(executor, null_val)) {
						row_passes = false;
						break;
					}
					continue;
				}

				const FieldSlice &field = lstate.field_slices[file_field_idx];

				// Unset/empty marker → treat as NULL.
				if (SliceEquals(field, unset_field) || SliceEquals(field, empty_field)) {
					Value null_val(bind_data.column_types[schema_col]);
					if (!expr_filter.EvaluateWithConstant(executor, null_val)) {
						row_passes = false;
						break;
					}
					continue;
				}

				// Parse the slice into a Value of the column's type and evaluate.
				Value row_val = SliceToValue(context, field, bind_data.column_types[schema_col]);
				if (!expr_filter.EvaluateWithConstant(executor, row_val)) {
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

			if (bind_data.log_date_column_idx && schema_col == *bind_data.log_date_column_idx) {
				const auto &file_date = bind_data.file_dates[lstate.current_file_idx];
				if (file_date) {
					FlatVector::GetDataMutable<date_t>(vec)[row_count] = *file_date;
				} else {
					FlatVector::SetNull(vec, row_count, true);
				}
				continue;
			}

			if (bind_data.log_start_time_column_idx && schema_col == *bind_data.log_start_time_column_idx) {
				const auto &file_time_range = bind_data.file_time_ranges[lstate.current_file_idx];
				if (file_time_range) {
					FlatVector::GetDataMutable<timestamp_t>(vec)[row_count] = file_time_range->start;
				} else {
					FlatVector::SetNull(vec, row_count, true);
				}
				continue;
			}

			if (bind_data.log_end_time_column_idx && schema_col == *bind_data.log_end_time_column_idx) {
				const auto &file_time_range = bind_data.file_time_ranges[lstate.current_file_idx];
				if (file_time_range) {
					FlatVector::GetDataMutable<timestamp_t>(vec)[row_count] = file_time_range->end;
				} else {
					FlatVector::SetNull(vec, row_count, true);
				}
				continue;
			}

			// Filename virtual column.
			if (bind_data.filename_column_idx && schema_col == *bind_data.filename_column_idx) {
				FlatVector::GetDataMutable<string_t>(vec)[row_count] =
				    StringVector::AddString(vec, lstate.current_file_path);
				continue;
			}

			// For non-native columns (e.g. INET) we accumulate into a temp VARCHAR vector and
			// batch-cast to the real output at end of chunk. For native columns target_vec == vec.
			Vector &target_vec = lstate.cast_temp_vecs[out_idx] ? *lstate.cast_temp_vecs[out_idx] : vec;

			// Translate from bound schema column to this file's field position. In union mode
			// the field may be absent (idx_t(-1) wraps to a value larger than num_fields).
			idx_t file_field_idx = lstate.field_lookup[schema_col];
			if (file_field_idx >= num_fields) {
				FlatVector::SetNull(target_vec, row_count, true);
				continue;
			}

			const FieldSlice &field = lstate.field_slices[file_field_idx];

			if (SliceEquals(field, unset_field) || SliceEquals(field, empty_field)) {
				FlatVector::SetNull(target_vec, row_count, true);
				continue;
			}

			string_t field_str(field.ptr, field.len);
			auto type_id = bind_data.column_types[schema_col].id();

			switch (type_id) {
			case LogicalTypeId::VARCHAR: {
				FlatVector::GetDataMutable<string_t>(vec)[row_count] =
				    StringVector::AddString(vec, field.ptr, field.len);
				break;
			}
			case LogicalTypeId::DOUBLE: {
				double val;
				if (TryCast::Operation<string_t, double>(field_str, val)) {
					FlatVector::GetDataMutable<double>(vec)[row_count] = val;
				} else {
					FlatVector::SetNull(vec, row_count, true);
				}
				break;
			}
			case LogicalTypeId::UBIGINT: {
				uint64_t val;
				if (TryCast::Operation<string_t, uint64_t>(field_str, val)) {
					FlatVector::GetDataMutable<uint64_t>(vec)[row_count] = val;
				} else {
					FlatVector::SetNull(vec, row_count, true);
				}
				break;
			}
			case LogicalTypeId::BIGINT: {
				int64_t val;
				if (TryCast::Operation<string_t, int64_t>(field_str, val)) {
					FlatVector::GetDataMutable<int64_t>(vec)[row_count] = val;
				} else {
					FlatVector::SetNull(vec, row_count, true);
				}
				break;
			}
			case LogicalTypeId::BOOLEAN: {
				FlatVector::GetDataMutable<bool>(vec)[row_count] =
				    (field.len == 1 && field.ptr[0] == 'T') ||
				    (field.len == 4 && std::memcmp(field.ptr, "true", 4) == 0);
				break;
			}
			case LogicalTypeId::TIMESTAMP_TZ: {
				double val;
				if (TryCast::Operation<string_t, double>(field_str, val)) {
					FlatVector::GetDataMutable<timestamp_tz_t>(vec)[row_count] = EpochSecondsToTimestampTZ(val);
				} else {
					FlatVector::SetNull(vec, row_count, true);
				}
				break;
			}
			case LogicalTypeId::INTERVAL: {
				double val;
				if (TryCast::Operation<string_t, double>(field_str, val)) {
					FlatVector::GetDataMutable<interval_t>(vec)[row_count] = SecondsToInterval(val);
				} else {
					FlatVector::SetNull(vec, row_count, true);
				}
				break;
			}
			case LogicalTypeId::USMALLINT: {
				uint16_t val;
				if (TryCast::Operation<string_t, uint16_t>(field_str, val)) {
					FlatVector::GetDataMutable<uint16_t>(vec)[row_count] = val;
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
				FlatVector::GetDataMutable<string_t>(target_vec)[row_count] =
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

	output.SetChildCardinality(row_count);
}

//! Callback: can we push down a filter on the given (schema) column index?
//! We return true only for types we can cheaply parse from a slice per-row.
static bool ZeekSupportsPushdownType(const FunctionData &bind_data_p, idx_t col_idx) {
	auto &bind_data = bind_data_p.Cast<ZeekScanBindData>();
	if ((bind_data.log_date_column_idx && col_idx == *bind_data.log_date_column_idx) ||
	    (bind_data.log_start_time_column_idx && col_idx == *bind_data.log_start_time_column_idx) ||
	    (bind_data.log_end_time_column_idx && col_idx == *bind_data.log_end_time_column_idx)) {
		return true;
	}
	// The filename virtual column is always VARCHAR; filters on it are cheap.
	if (bind_data.filename_column_idx && col_idx == *bind_data.filename_column_idx) {
		return true;
	}
	if (col_idx >= bind_data.column_types.size()) {
		return false;
	}
	return CanPushdownFilterOnType(bind_data.column_types[col_idx]);
}

TableFunction GetZeekScanFunction() {
	TableFunction func("read_zeek", {LogicalType::VARCHAR}, ZeekScanExecute, ZeekScanBind, ZeekScanInitGlobal,
	                   ZeekScanInitLocal);
	func.GetSignature().WithTypedKwargs("options", [](TypedKwargs &options) {
		options.Add("filename", LogicalType::BOOLEAN)
		    .Add("replace_periods", LogicalType::BOOLEAN)
		    .Add("inet", LogicalType::BOOLEAN)
		    .Add("union_by_name", LogicalType::BOOLEAN)
		    .Add("ignore_file_errors", LogicalType::BOOLEAN)
		    .Add("partition_discovery", LogicalType::BOOLEAN);
	});
	func.projection_pushdown = true;
	func.filter_pushdown = true;
	func.supports_pushdown_type = ZeekSupportsPushdownType;
	return func;
}

} // namespace duckdb
