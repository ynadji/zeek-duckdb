# DuckDB Zeek Extension

A DuckDB extension for reading [Zeek](https://zeek.org/) (formerly Bro) network security monitor log files.

## Installing

Starting with DuckDB v1.5.1, the Zeek extension can be installed from community with:

```
$ duckdb
DuckDB v1.5.1 (Variegata)
Enter ".help" for usage hints.
memory D INSTALL inet;
memory D INSTALL zeek FROM community;
memory D LOAD zeek;
memory D SELECT * FROM read_zeek('data/dns.log.gz');
┌───────────────────────────────┬────────────────────┬─────────────┬───────────┬───────────┬───────────┬─────────┬──────────┬───┬─────────┬─────────┬─────────┬─────────┬────────┬──────────────────────────┬──────────────────────┬──────────┐
│              ts               │        uid         │  id_orig_h  │ id_orig_p │ id_resp_h │ id_resp_p │  proto  │ trans_id │ … │   AA    │   TC    │   RD    │   RA    │   Z    │         answers          │         TTLs         │ rejected │
│   timestamp with time zone    │      varchar       │    inet     │  uint16   │   inet    │  uint16   │ varchar │  uint64  │ … │ boolean │ boolean │ boolean │ boolean │ uint64 │        varchar[]         │      interval[]      │ boolean  │
├───────────────────────────────┼────────────────────┼─────────────┼───────────┼───────────┼───────────┼─────────┼──────────┼───┼─────────┼─────────┼─────────┼─────────┼────────┼──────────────────────────┼──────────────────────┼──────────┤
│ 2026-01-16 00:00:02.060078-05 │ Csp4de4BFHPjq0Fyfa │ 10.20.40.41 │     51168 │ 8.8.4.4   │        53 │ udp     │    56933 │ … │ false   │ false   │ true    │ true    │      0 │ [vhost-account.vip.ican… │ ['00:45:35', '00:00… │ false    │
│ 2026-01-16 00:00:02.064667-05 │ C61GeE23uDUeX311zl │ 10.20.40.41 │     49581 │ 8.8.4.4   │        53 │ udp     │     1471 │ … │ false   │ false   │ true    │ true    │      0 │ [vhost-account.vip.ican… │ ['00:40:29', '00:00… │ false    │
└───────────────────────────────┴────────────────────┴─────────────┴───────────┴───────────┴───────────┴─────────┴──────────┴───┴─────────┴─────────┴─────────┴─────────┴────────┴──────────────────────────┴──────────────────────┴──────────┘
  2 rows                                                                                        use .last to show entire result                                                                                         24 columns (16 shown)
```

There is no community build of the Zeek extension for DuckDB v2.0.0 yet. To use it with v2.0.0, build the extension from source (see [Building](#building)) and load it from the build directory (see [Loading the Extension](#loading-the-extension)).

## Zeek Types <-> DuckDB Types

| Zeek Type | DuckDB Type |
|-----------|-------------|
| `time` | `TIMESTAMP WITH TIME ZONE` |
| `interval` | `INTERVAL` |
| `string` | `VARCHAR` |
| `addr` | `INET` (use `inet=false` for `VARCHAR`) |
| `subnet` | `INET` (use `inet=false` for `VARCHAR`) |
| `port` | `USMALLINT` |
| `count` | `UBIGINT` |
| `int` | `BIGINT` |
| `bool` | `BOOLEAN` |
| `double` | `DOUBLE` |
| `enum` | `VARCHAR` |
| `vector[T]` | `LIST[T]` |
| `set[T]` | `LIST[T]` |

## Usage

```sql
-- Read a Zeek log file (supports .gz compression)
SELECT * FROM read_zeek('conn.log.gz');

-- Also supports zstd compression
SELECT * FROM read_zeek('conn.log.zst');

-- Query with filtering
SELECT ts, id.orig_h, id.resp_h, service
FROM read_zeek('conn.log.gz')
WHERE service = 'http';

-- Aggregate by source IP
SELECT host_ip, SUM(conns_opened) as total_conns
FROM read_zeek('known_hosts.log.gz')
GROUP BY host_ip
ORDER BY total_conns DESC;
```

## `read_zeek` Options

The `read_zeek` table function takes a file path or glob pattern as its first argument, plus the following named parameters:

| Parameter | Type | Default | Description |
|---|---|---|---|
| `preserve_empty` | `BOOLEAN` | `false` | Preserve Zeek empty strings and set/vector values instead of converting them to `NULL`. Unset values remain `NULL`. |
| `inet` | `BOOLEAN` | `true` | Map Zeek `addr` and `subnet` to DuckDB `INET`. Requires the `inet` extension (`INSTALL inet; LOAD inet;`). Set to `false` to read these columns as `VARCHAR` instead. |
| `filename` | `BOOLEAN` | `false` | Add a `filename` column to the output that holds the path of the source file each row came from. Mostly useful when reading globs. |
| `replace_periods` | `BOOLEAN` | `true` | Replace `.` with `_` in column names so they can be referenced unquoted in SQL. For example, `id.orig_h` becomes `id_orig_h`. Set to `false` to keep the original names — you'll then need to quote them, e.g. `"id.orig_h"`. |
| `union_by_name` | `BOOLEAN` | `false` | When reading multiple files via a glob, build the output schema as the *union* of every file's fields. Fields absent from a file become `NULL` in that file's rows. Same field name with different Zeek types across files is a bind-time error. When `false` (the default), all files in the glob must have an identical schema — any mismatch (different field count, reordered fields, type change) raises an error rather than silently producing wrong results. |
| `ignore_file_errors` | `BOOLEAN` | `false` | Skip files that cannot be opened or parsed (e.g., corrupted gzip files, malformed headers) instead of throwing an error. When `true`, corrupted files are silently skipped and the query continues with the remaining files. |

### Examples

```sql
-- Read a glob, tagging each row with its source file
SELECT filename, COUNT(*)
FROM read_zeek('logs/conn_*.log.gz', filename=true)
GROUP BY filename;

-- Read across years of logs, even if newer files added fields
SELECT id_orig_h, service, proto
FROM read_zeek('logs/conn_*.log.gz', union_by_name=true)
WHERE proto IS NOT NULL;

-- Filter on an IP address using INET semantics
SELECT * FROM read_zeek('data/dns.log.gz')
WHERE id_orig_h <<= '10.20.40.0/24';

-- Read addresses as plain VARCHAR (no inet extension required)
SELECT host_ip FROM read_zeek('known_hosts.log.gz', inet=false);

-- Skip corrupted files instead of failing the query
SELECT COUNT(*) FROM read_zeek('logs/*/notice*', union_by_name=true, ignore_file_errors=true);
```

### Preserving empty values

Zeek TSV declares each column's original type in the `#types` header. The
extension uses that declaration to interpret the empty marker because an empty
string and an empty collection carry different meanings. DuckDB type mappings
stay the same, including the mapping of Zeek enum labels to VARCHAR.

| TSV value | Omitted or `preserve_empty=false` | `preserve_empty=true` |
|---|---|---|
| `#unset_field` marker, any type | `NULL` | `NULL` |
| `#empty_field` marker, Zeek `string` | `NULL` | `''` |
| `#empty_field` marker, Zeek `set[T]` or `vector[T]` | `NULL` | `[]` |
| `#empty_field` marker, other scalar types | `NULL` | `NULL` |

Both modes use the marker strings from the file header, including custom
markers. Ordinary values such as numeric zero and boolean false keep their
usual conversions. In string sets and vectors with multiple elements, the
option also preserves empty string elements. Unset elements become `NULL`.
This option leaves the reader's type mapping and header validation in place.

```sql
SELECT uid, service
FROM read_zeek('conn.log', inet=false, preserve_empty=true)
WHERE service = '';
```

Zeek TSV can encode an empty collection and a collection containing one empty
string with the same whole-field marker. The reader interprets that marker as
an empty list when `preserve_empty=true`.

## Building

### Prerequisites

- CMake 3.5+
- C++11 compatible compiler
- Git (for submodules)

### Build Steps

```bash
# Clone with submodules
git clone --recurse-submodules https://github.com/ynadji/zeek-duckdb.git
cd zeek-duckdb

# Build against the released DuckDB v2.0.0
DUCKDB_VERSION=v2.0.0 make release

# Run tests
make test
```

`DUCKDB_VERSION=v2.0.0` makes the build report the released version, which is what the extension targets. Without it, the build reports a dev version (for example `v2.0.0-dev1`), and `INSTALL inet` fails for that build.

### Build Artifacts

- `./build/release/duckdb` - DuckDB shell (the extension is not built in; load it as shown in [Loading the Extension](#loading-the-extension))
- `./build/release/extension/zeek/zeek.duckdb_extension` - Loadable extension

## Loading the Extension

```sql
-- From build directory (requires -unsigned flag for CLI)
LOAD './build/release/extension/zeek/zeek.duckdb_extension';

-- Or after installing
LOAD zeek;
```

## Zeek Log Format

Zeek logs are self-describing TSV files with metadata headers:

```
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	conn
#fields	ts	uid	id.orig_h	id.orig_p	...
#types	time	string	addr	port	...
1234567890.123456	CHhAvVGS1DHFjwGM9	192.168.1.1	12345	...
```

The extension automatically parses these headers to determine column names and types.

## Reporting Bugs

Please report any bugs or feature requests on this repo, rather than any of DuckDB's repos.

## License

MIT License
