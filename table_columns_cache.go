//go:build !cli

package main

// Column metadata cache for the auto-CRUD list/cursor path. crudTableColumns
// ran PRAGMA table_info on every list request to build the filter/sort
// allowlist. app.Tables cannot replace it: it is the parsed schema, and the
// live table can hold more (custom fields, columns kept after a schema edit,
// columns added through `sql write:true` from the router process).
//
// Instead the cache is keyed on SQLite's schema cookie (PRAGMA
// schema_version), which every DDL statement from any connection or process
// bumps. A hit costs one single-integer pragma instead of a row per column;
// any schema change, including one made by another process, is a miss.

import (
	"database/sql"
	"sync"
)

type tableColumnsCacheKey struct {
	db    *sql.DB
	table string
}

type tableColumnsCacheEntry struct {
	schemaVersion int64
	cols          []Column
}

// tableColumnsCacheMax bounds the map: entries are per (pool, table) and a
// router or `benmore host` process can open many pools over its lifetime.
const tableColumnsCacheMax = 4096

var tableColumnsCache = struct {
	sync.Mutex
	m map[tableColumnsCacheKey]tableColumnsCacheEntry
}{m: map[tableColumnsCacheKey]tableColumnsCacheEntry{}}

func sqliteSchemaVersion(db *sql.DB) (int64, error) {
	var v int64
	err := db.QueryRow("PRAGMA schema_version").Scan(&v)
	return v, err
}

// cachedTableColumns returns GetTableColumns(db, table), served from the cache
// while the database's schema cookie is unchanged.
func cachedTableColumns(db *sql.DB, table string) ([]Column, error) {
	version, err := sqliteSchemaVersion(db)
	if err != nil {
		return GetTableColumns(db, table)
	}
	key := tableColumnsCacheKey{db: db, table: table}
	tableColumnsCache.Lock()
	entry, ok := tableColumnsCache.m[key]
	tableColumnsCache.Unlock()
	if ok && entry.schemaVersion == version {
		return append([]Column(nil), entry.cols...), nil
	}
	cols, err := GetTableColumns(db, table)
	if err != nil {
		return nil, err
	}
	tableColumnsCache.Lock()
	if len(tableColumnsCache.m) >= tableColumnsCacheMax {
		tableColumnsCache.m = map[tableColumnsCacheKey]tableColumnsCacheEntry{}
	}
	// Stored under the cookie read BEFORE the column read: if DDL landed in
	// between, the next call sees a newer cookie and refreshes.
	tableColumnsCache.m[key] = tableColumnsCacheEntry{schemaVersion: version, cols: append([]Column(nil), cols...)}
	tableColumnsCache.Unlock()
	return cols, nil
}
