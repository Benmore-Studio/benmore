# Database Frontier

SQLite remains Benmore's production app database backend. Postgres/pgx support
starts with a dialect boundary and must fail closed until migrations, generated
DDL, encryption SQL functions, FTS, backups, and insert-returning semantics are
ported deliberately.

```mermaid
flowchart TD
  OpenDB[OpenDB] --> Detect[DATABASE_URL detection]
  Detect --> SQLite[sqlite3_benmore]
  Detect --> Postgres[postgres/postgresql DSN]
  Postgres --> Closed[fail closed until runtime support is complete]
  SQLite --> Runtime[existing app runtime]
  Closed --> Dialect[placeholder + introspection frontier]
```

The first slice recognizes Postgres DSNs, centralizes local SQLite DSN tuning,
and adds placeholder rewriting helpers for later `$1`/`$2` Postgres queries.
It does not enable app runtime Postgres yet.

