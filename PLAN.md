# DuckDB Zeek Extension - Implementation Plan

## Overview

This document outlines the plan to create a DuckDB extension in C++ that implements a `read_zeek` table function for reading Zeek (formerly Bro) TSV log files. The extension will leverage DuckDB's FileSystem API for automatic compression handling and provide a native, high-performance implementation usable from any DuckDB client (Python, R, Julia, Common Lisp, etc.).

## Why C++ Extension?

- ✅ **DuckDB FileSystem Integration**: Direct access to DuckDB's FileSystem class enables automatic compression detection/handling (.gz, .zst)
- ✅ **Universal Compatibility**: Works from any language/client that uses DuckDB (Python, R, Julia, Rust, Common Lisp)
- ✅ **Native Performance**: C++ implementation with zero-copy optimizations
- ✅ **Community Distribution**: Can be published to duckdb/community-extensions for easy `INSTALL zeek FROM community;`
- ✅ **Proper Integration**: Full DuckDB optimizer support, projection pushdown, parallel scanning

## Zeek Log Format

Zeek logs are self-describing TSV files with metadata headers that define the schema.

### Sample Zeek Log Structure

```
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	known_hosts
#open	2026-01-16-00-30-32
#fields	ts	duration	kuid	host_ip	host_vlan	host_inner_vlan	conns_opened	conns_closed	conns_pending	long_conns	annotations	last_active_session	last_active_interval
#types	time	interval	string	addr	int	int	count	count	count	count	vector[string]	string	interval
1768540789.230929	323.126660	Kfoql5dpOG1K1	10.21.7.136	1	-	1	1	0	0	(empty)	KfTpFzNjZ9k9h	3895.038597
#close	2026-01-16-01-00-00
```

### Header Directives

| Directive | Description | Example |
|-----------|-------------|---------|
| `#separator` | Field separator (typically `\x09` = tab) | `\x09` |
| `#set_separator` | Separator for set/vector elements | `,` |
| `#empty_field` | Marker for empty fields | `(empty)` |
| `#unset_field` | Marker for NULL/unset fields | `-` |
| `#path` | Log stream identifier | `known_hosts` |
| `#open` | Opening timestamp | `2026-01-16-00-30-32` |
| `#fields` | Tab-separated column names | `ts	uid	id.orig_h...` |
| `#types` | Tab-separated Zeek types | `time	string	addr...` |
| `#close` | Closing timestamp (optional) | `2026-01-16-01-00-00` |

### Zeek Type Mapping to DuckDB

| Zeek Type | DuckDB Type | Notes |
|-----------|-------------|-------|
| `time` | `DOUBLE` | Unix timestamp with microsecond precision |
| `interval` | `DOUBLE` | Duration in seconds |
| `string` | `VARCHAR` | Text string |
| `addr` | `VARCHAR` | IPv4/IPv6 address |
| `subnet` | `VARCHAR` | CIDR notation |
| `port` | `VARCHAR` | Port with protocol (e.g., "80/tcp") |
| `count` | `UBIGINT` | Unsigned counter |
| `int` | `BIGINT` | Signed integer |
| `bool` | `BOOLEAN` | True/False (represented as `T`/`F`) |
| `double` | `DOUBLE` | Double-precision float |
| `enum` | `VARCHAR` | Enumeration value |
| `vector[T]` | `VARCHAR` | Comma-separated list (future: `LIST`) |
| `set[T]` | `VARCHAR` | Comma-separated set (future: `LIST`) |

### Special Value Handling

- **Unset fields** (`-`): Should be represented as SQL NULL
- **Empty fields** (`(empty)`): Should be represented as SQL NULL
- Fields can be missing from shorter rows: treat as NULL

## Project Structure

```
duckdb-zeek/
├── .github/
│   └── workflows/
│       └── MainDistributionPipeline.yml  # CI for building binaries
├── duckdb/                 # DuckDB submodule (git submodule)
├── extension-ci-tools/     # CI tools submodule
├── src/
│   ├── include/
│   │   └── zeek_reader.hpp        # Header parser and type definitions
│   ├── zeek_extension.cpp         # Extension entry point & registration
│   ├── zeek_reader.cpp            # Zeek header parsing implementation
│   └── zeek_scanner.cpp           # Table function (bind/init/execute)
├── test/
│   └── sql/
│       ├── read_zeek_basic.test   # Basic functionality tests
│       ├── read_zeek_types.test   # Type conversion tests
│       ├── read_zeek_nulls.test   # NULL handling tests
│       └── read_zeek_gz.test      # Gzip compression tests
├── CMakeLists.txt                 # Build configuration
├── extension_config.cmake         # Extension load configuration
├── Makefile                       # Convenience wrapper
├── vcpkg.json                     # Dependencies (if needed)
└── README.md                      # Documentation
```

## Implementation Plan

### Phase 1: Project Setup (30 minutes)

1. Clone DuckDB extension template:
   ```bash
   git clone --recurse-submodules https://github.com/duckdb/extension-template.git duckdb-zeek
   cd duckdb-zeek
   ```

2. Bootstrap the template:
   ```bash
   python3 scripts/bootstrap-template.py zeek
   ```

3. Verify build system works:
   ```bash
   make release
   ./build/release/duckdb -unsigned
   ```

### Phase 2: Core Data Structures (1 hour)

**File: `src/include/zeek_reader.hpp`**

Define:
- `struct ZeekHeader` - Parsed Zeek metadata
- `class ZeekReader` - Static methods for header parsing and type conversion
- `struct ZeekScanBindData` - Bind-time data (file path, header, compression)
- `struct ZeekScanGlobalState` - Global state (file handle, current position)

Key responsibilities:
- Parse all Zeek header directives
- Map Zeek types to DuckDB LogicalTypes
- Handle separator escaping (`\x09` → tab)
- Track number of header lines for skipping

### Phase 3: Header Parser (2 hours)

**File: `src/zeek_reader.cpp`**

Implement `ZeekReader::ParseHeader(FileHandle &file_handle)`:

1. Read lines until first non-`#` line
2. Parse each directive:
   - Split on first tab
   - Extract directive name and value
   - Update ZeekHeader struct
3. Validate required fields (`#fields` and `#types`)
4. Count header lines for later skipping
5. Position file handle at start of data

Implementation notes:
- Use `FileHandle::Read()` for line-by-line reading
- Handle `\x09` and `\x20` escape sequences for separators
- Use `StringUtil::Split()` for parsing field/type lists
- Reset file handle after parsing (for re-reading in init)

### Phase 4: Table Function - Bind (1 hour)

**File: `src/zeek_scanner.cpp`**

Implement `ZeekScanBind()`:

1. Extract file path from `input.inputs[0]`
2. Set compression to `FileCompressionType::AUTO_DETECT`
3. Open file using DuckDB FileSystem:
   ```cpp
   auto &fs = FileSystem::GetFileSystem(context);
   OpenFileInfo file_info(result->file_path);
   auto file_handle = fs.OpenFile(file_info, 
                                  FileFlags::FILE_FLAGS_READ | result->compression);
   ```
4. Parse Zeek header
5. Register output columns:
   ```cpp
   for (idx_t i = 0; i < header.fields.size(); i++) {
       names.push_back(header.fields[i]);
       return_types.push_back(ZeekReader::ZeekTypeToDuckDBType(header.types[i]));
   }
   ```
6. Store header and file info in `ZeekScanBindData`

**Key DuckDB APIs:**
- `FileSystem::GetFileSystem(context)` - Get filesystem instance
- `FileSystem::OpenFile(info, flags)` - Open file with compression
- `FileCompressionType::AUTO_DETECT` - Auto-detect .gz, .zst

### Phase 5: Table Function - Init (30 minutes)

Implement `ZeekScanInitGlobal()`:

1. Extract bind data
2. Re-open file for reading
3. Skip header lines (using count from bind phase)
4. Store file handle in global state

Note: File must be re-opened because bind phase closes it after schema detection.

### Phase 6: Table Function - Execute (2-3 hours)

Implement `ZeekScanExecute()`:

1. Read lines from file (up to `STANDARD_VECTOR_SIZE` rows)
2. For each line:
   - Split by separator
   - Check for NULL markers (`-`, `(empty)`)
   - Convert values based on column type
   - Write to output DataChunk
3. Handle edge cases:
   - Short rows (missing fields → NULL)
   - Comment lines after header (skip)
   - EOF (return with actual row count)

**Value conversion logic:**
```cpp
switch (type.id()) {
    case LogicalTypeId::DOUBLE:
        FlatVector::GetData<double>(vector)[row_idx] = std::stod(field_value);
        break;
    case LogicalTypeId::UBIGINT:
        FlatVector::GetData<uint64_t>(vector)[row_idx] = std::stoull(field_value);
        break;
    case LogicalTypeId::BIGINT:
        FlatVector::GetData<int64_t>(vector)[row_idx] = std::stoll(field_value);
        break;
    case LogicalTypeId::BOOLEAN:
        FlatVector::GetData<bool>(vector)[row_idx] = (field_value == "T");
        break;
    case LogicalTypeId::VARCHAR:
    default:
        FlatVector::GetData<string_t>(vector)[row_idx] = 
            StringVector::AddString(vector, field_value);
        break;
}
```

**NULL handling:**
```cpp
if (field_value == bind_data.header.unset_field ||
    field_value == bind_data.header.empty_field ||
    col_idx >= fields.size()) {
    FlatVector::SetNull(output.data[col_idx], row_count, true);
    continue;
}
```

### Phase 7: Extension Registration (30 minutes)

**File: `src/zeek_extension.cpp`**

1. Define extension entry point
2. Register `read_zeek` table function
3. Implement required extension API methods

```cpp
static void LoadInternal(DatabaseInstance &instance) {
    auto &db = instance;
    ExtensionUtil::RegisterFunction(db, GetZeekScanFunction());
}

extern "C" {
DUCKDB_EXTENSION_API void zeek_init(duckdb::DatabaseInstance &db) {
    duckdb::DuckDB db_wrapper(db);
    db_wrapper.LoadExtension<duckdb::ZeekExtension>();
}
}
```

### Phase 8: Testing (2-3 hours)

**Test files to create:**

1. `test/sql/read_zeek_basic.test` - Basic scanning
   ```sql
   LOAD 'build/release/extension/zeek/zeek.duckdb_extension';
   
   -- Test basic read
   SELECT COUNT(*) FROM read_zeek('test/data/known_hosts.log.gz');
   
   -- Test column names
   DESCRIBE SELECT * FROM read_zeek('test/data/known_hosts.log.gz');
   ```

2. `test/sql/read_zeek_types.test` - Type conversions
   ```sql
   -- Verify timestamp is DOUBLE
   SELECT typeof(ts) FROM read_zeek('test/data/conn.log.gz') LIMIT 1;
   
   -- Verify count is UBIGINT
   SELECT typeof(orig_pkts) FROM read_zeek('test/data/conn.log.gz') LIMIT 1;
   ```

3. `test/sql/read_zeek_nulls.test` - NULL handling
   ```sql
   -- Verify unset fields become NULL
   SELECT COUNT(*) FROM read_zeek('test/data/known_hosts.log.gz') 
   WHERE host_inner_vlan IS NULL;
   ```

4. `test/sql/read_zeek_gz.test` - Compression support
   ```sql
   -- Compare gzipped vs uncompressed
   SELECT COUNT(*) FROM read_zeek('test/data/conn.log.gz');
   SELECT COUNT(*) FROM read_zeek('test/data/conn.log');
   ```

**Test data:**
- Use the provided `known_hosts_20260116_00:00:00-01:00:00-0500.log.gz`
- Create additional test files with edge cases (empty logs, malformed headers, etc.)

### Phase 9: Documentation (1 hour)

**Update README.md with:**

1. Overview and features
2. Installation instructions:
   ```sql
   INSTALL zeek FROM community;
   LOAD zeek;
   ```
3. Usage examples:
   ```sql
   -- Read a single file
   SELECT * FROM read_zeek('conn.log.gz');
   
   -- Aggregate by IP
   SELECT id.orig_h, COUNT(*) as conn_count
   FROM read_zeek('conn.log.gz')
   GROUP BY id.orig_h
   ORDER BY conn_count DESC
   LIMIT 10;
   
   -- Join with other tables
   SELECT z.*, t.severity
   FROM read_zeek('conn.log.gz') z
   JOIN threats t ON z.id.resp_h = t.ip;
   ```
4. Supported Zeek types
5. Building from source
6. Contributing guidelines

### Phase 10: CI/CD Setup (1 hour)

Configure GitHub Actions for:
- Building on Linux (x64, arm64)
- Building on macOS (x64, arm64)
- Building on Windows (x64)
- Running tests on all platforms
- Creating release artifacts

The extension template includes most of this already in `.github/workflows/`.

## Key DuckDB C++ APIs

### FileSystem Operations

```cpp
// Get filesystem instance
auto &fs = FileSystem::GetFileSystem(context);

// Open file with auto-detect compression
OpenFileInfo file_info(file_path);
auto handle = fs.OpenFile(file_info, 
                          FileFlags::FILE_FLAGS_READ | FileCompressionType::AUTO_DETECT);

// Read from file
char buffer[8192];
int64_t bytes_read = handle->Read(buffer, sizeof(buffer));

// Reset file position
handle->Reset();

// Check if seekable
bool can_seek = handle->CanSeek();
```

### Table Function Lifecycle

```cpp
// 1. Bind - Define schema and validate inputs
static unique_ptr<FunctionData> Bind(
    ClientContext &context,
    TableFunctionBindInput &input,
    vector<LogicalType> &return_types,
    vector<string> &names) {
    // Parse parameters, define columns, return bind data
}

// 2. Init Global - Initialize shared state
static unique_ptr<GlobalTableFunctionState> InitGlobal(
    ClientContext &context,
    TableFunctionInitInput &input) {
    // Open resources, return global state
}

// 3. Execute - Produce rows
static void Execute(
    ClientContext &context,
    TableFunctionInput &data,
    DataChunk &output) {
    // Read data, fill output chunk
    output.SetCardinality(row_count);
}

// 4. Register
TableFunction func("read_zeek", {LogicalType::VARCHAR}, 
                  Execute, Bind, InitGlobal);
ExtensionUtil::RegisterFunction(db, func);
```

### DataChunk Operations

```cpp
// Get vector for column
auto &vector = output.data[col_idx];

// Set NULL
FlatVector::SetNull(vector, row_idx, true);

// Set typed value
FlatVector::GetData<double>(vector)[row_idx] = 42.0;
FlatVector::GetData<int64_t>(vector)[row_idx] = 123;

// Set string (copies into vector's string heap)
FlatVector::GetData<string_t>(vector)[row_idx] = 
    StringVector::AddString(vector, "hello");

// Set cardinality (row count)
output.SetCardinality(row_count);
```

### String Utilities

```cpp
// Split string
auto parts = StringUtil::Split(line, '\t');

// String comparison
if (StringUtil::StartsWith(str, "vector[")) { ... }
if (StringUtil::EndsWith(str, ".gz")) { ... }

// Case conversion
auto lower = StringUtil::Lower(str);
```

## Building and Testing

### Build Commands

```bash
# Debug build
make debug

# Release build
make release

# Clean build
make clean

# Run tests
make test

# Build with ninja (faster)
GEN=ninja make release

# Build with ccache (faster rebuilds)
USE_CCACHE=1 make release
```

### Manual Testing

```bash
# Start DuckDB with unsigned extensions allowed
./build/release/duckdb -unsigned

# In DuckDB shell:
LOAD './build/release/extension/zeek/zeek.duckdb_extension';
SELECT * FROM read_zeek('path/to/zeek.log.gz');
```

### Debugging

```bash
# Build debug version
make debug

# Run with debugger
lldb ./build/debug/duckdb
# or
gdb ./build/debug/duckdb

# Set breakpoint
(lldb) breakpoint set --name ZeekScanExecute
(lldb) run
```

## Future Enhancements

### Phase 11: Advanced Features (Optional)

1. **Parallel Scanning** - Implement `InitLocal()` for per-thread state
2. **Projection Pushdown** - Set `func.projection_pushdown = true`
3. **Filter Pushdown** - Implement filter pushdown for WHERE clauses
4. **Multi-file Support** - Use `MultiFileReader` for glob patterns
5. **Complex Types** - Parse `vector[string]` into DuckDB `LIST` types
6. **Schema Caching** - Cache parsed headers for repeated queries

### Phase 12: Community Extension (Optional)

1. Fork https://github.com/duckdb/community-extensions
2. Add `duckdb-zeek` to the repository list
3. Submit pull request
4. Once merged, users can:
   ```sql
   INSTALL zeek FROM community;
   LOAD zeek;
   SELECT * FROM read_zeek('conn.log.gz');
   ```

## Resources

### Official Documentation
- [DuckDB Extensions Overview](https://duckdb.org/docs/stable/extensions/overview)
- [Building Extensions](https://duckdb.org/docs/stable/dev/building/building_extensions)
- [Extension Template](https://github.com/duckdb/extension-template)
- [Community Extensions](https://github.com/duckdb/community-extensions)

### Reference Extensions
- [extension-template](https://github.com/duckdb/extension-template) - Starting point
- [duckdb/parquet](https://github.com/duckdb/duckdb/tree/main/extension/parquet) - Complex file scanner
- [duckdb/json](https://github.com/duckdb/duckdb/tree/main/extension/json) - JSON reading
- [duckdb-sqlite](https://github.com/duckdb/duckdb-sqlite) - External format integration

### Zeek Documentation
- [Zeek Log Formats](https://docs.zeek.org/en/current/log-formats.html)
- [Zeek Types](https://docs.zeek.org/en/master/script-reference/types.html)

## Time Estimates

| Phase | Description | Time |
|-------|-------------|------|
| 1 | Project Setup | 30 min |
| 2 | Core Data Structures | 1 hour |
| 3 | Header Parser | 2 hours |
| 4 | Table Function - Bind | 1 hour |
| 5 | Table Function - Init | 30 min |
| 6 | Table Function - Execute | 2-3 hours |
| 7 | Extension Registration | 30 min |
| 8 | Testing | 2-3 hours |
| 9 | Documentation | 1 hour |
| 10 | CI/CD Setup | 1 hour |
| **Total** | **Core Implementation** | **12-14 hours** |

## Success Criteria

The extension is complete when:

1. ✅ Can read uncompressed Zeek logs
2. ✅ Can read gzip-compressed Zeek logs (.gz)
3. ✅ Correctly parses all header directives
4. ✅ Maps Zeek types to appropriate DuckDB types
5. ✅ Handles NULL values (`-` and `(empty)`)
6. ✅ All tests pass
7. ✅ Works from Common Lisp via DuckDB CFFI bindings
8. ✅ Documentation is complete
9. ✅ Can be built on Linux/macOS/Windows

## Usage from Common Lisp

Once the extension is built, it can be loaded in DuckDB and used from Common Lisp:

```lisp
;; Load the extension
(ddb:query "LOAD './build/release/extension/zeek/zeek.duckdb_extension'" nil)

;; Query Zeek logs
(ddb:query "SELECT * FROM read_zeek('known_hosts.log.gz')" nil)

;; Aggregate queries
(ddb:query "SELECT host_ip, SUM(conns_opened) as total_conns
            FROM read_zeek('known_hosts.log.gz')
            GROUP BY host_ip
            ORDER BY total_conns DESC" nil)

;; Join with other data
(ddb:query "CREATE TABLE threats (ip VARCHAR, severity INT)" nil)
(ddb:query "INSERT INTO threats VALUES ('10.21.7.136', 9)" nil)
(ddb:query "SELECT z.*, t.severity
            FROM read_zeek('known_hosts.log.gz') z
            JOIN threats t ON z.host_ip = t.ip" nil)
```

## Next Steps

1. Create a new directory: `mkdir duckdb-zeek && cd duckdb-zeek`
2. Follow Phase 1 to set up the project
3. Implement phases 2-7 for core functionality
4. Add tests (phase 8)
5. Document usage (phase 9)
6. Set up CI/CD (phase 10)

The extension will be completely independent of the Common Lisp codebase - it's a standalone DuckDB extension that can be used from any language!
