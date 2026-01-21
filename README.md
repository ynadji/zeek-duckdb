# DuckDB Zeek Extension

A DuckDB extension for reading [Zeek](https://zeek.org/) (formerly Bro) network security monitor log files.

## Features

- Read Zeek TSV log files with automatic schema detection
- Automatic gzip decompression (`.gz` files)
- Proper NULL handling for unset (`-`) and empty (`(empty)`) fields
- Type-aware parsing of Zeek types to DuckDB types

## Supported Zeek Types

| Zeek Type | DuckDB Type |
|-----------|-------------|
| `time` | `DOUBLE` |
| `interval` | `DOUBLE` |
| `string` | `VARCHAR` |
| `addr` | `VARCHAR` |
| `subnet` | `VARCHAR` |
| `port` | `VARCHAR` |
| `count` | `UBIGINT` |
| `int` | `BIGINT` |
| `bool` | `BOOLEAN` |
| `double` | `DOUBLE` |
| `enum` | `VARCHAR` |
| `vector[T]` | `VARCHAR` |
| `set[T]` | `VARCHAR` |

## Usage

```sql
-- Read a Zeek log file (supports .gz compression)
SELECT * FROM read_zeek('conn.log.gz');

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

## Building

### Prerequisites

- CMake 3.5+
- C++11 compatible compiler
- Git (for submodules)

### Build Steps

```bash
# Clone with submodules
git clone --recurse-submodules https://github.com/yourusername/duckdb-zeek.git
cd duckdb-zeek

# Build
make release

# Run tests
make test
```

### Build Artifacts

- `./build/release/duckdb` - DuckDB shell with extension loaded
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

## License

MIT License
