# DuckDB Zeek Extension

A DuckDB extension for reading [Zeek](https://zeek.org/) (formerly Bro) network security monitor log files.

## Installing

Starting with DuckDB v1.5.1, the Zeek extension can be installed from community with:

```
¡ duckdb
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

## Features

- Read Zeek TSV log files with automatic schema detection
- Automatic gzip decompression (`.gz` files)
- Proper NULL handling for unset (`-`) and empty (`(empty)`) fields
- Type-aware parsing of Zeek types to DuckDB types

## Supported Zeek Types

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

## Reporting Bugs

Please report any bugs or feature requests on this repo, rather than any of DuckDB's repos.

## License

MIT License
