//go:build !cli

package main

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
)

// Result-set scanning and column-metadata benchmarks. Run with
// `go test -tags sqlite_fts5 -run '^$' -bench 'ScanRows|TableColumns' -benchmem .`.

func benchScanDB(b *testing.B, rowsN int) *sql.DB {
	db, err := sql.Open("sqlite3", filepath.Join(b.TempDir(), "data.db"))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT, body TEXT, done BOOLEAN, amount REAL, user_id INTEGER, group_id INTEGER, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME, tag TEXT)`); err != nil {
		b.Fatal(err)
	}
	tx, _ := db.Begin()
	for i := 0; i < rowsN; i++ {
		if _, err := tx.Exec(`INSERT INTO notes (title, body, done, amount, user_id, group_id, tag) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			fmt.Sprintf("Note %d", i), "Lorem ipsum dolor sit amet", i%2, float64(i)*1.5, 42, 7, "tag"); err != nil {
			b.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		b.Fatal(err)
	}
	return db
}

func BenchmarkScanRows50(b *testing.B) {
	db := benchScanDB(b, 50)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := QueryRows(db, "SELECT * FROM notes ORDER BY id DESC LIMIT 50"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTableColumnsPragma(b *testing.B) {
	db := benchScanDB(b, 1)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := GetTableColumns(db, "notes"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTableColumnsCached(b *testing.B) {
	db := benchScanDB(b, 1)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := cachedTableColumns(db, "notes"); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkScanRows50Request is the list path as the CRUD handler runs it:
// bound to a cancellable request context plus the default deadline.
func BenchmarkScanRows50Request(b *testing.B) {
	db := benchScanDB(b, 50)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := QueryRowsContext(ctx, db, "SELECT * FROM notes ORDER BY id DESC LIMIT 50"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkScanRows500(b *testing.B) {
	db := benchScanDB(b, 500)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := QueryRows(db, "SELECT * FROM notes ORDER BY id DESC LIMIT 500"); err != nil {
			b.Fatal(err)
		}
	}
}
