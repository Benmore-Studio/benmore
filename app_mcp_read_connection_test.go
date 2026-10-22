//go:build !cli

package main

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/mattn/go-sqlite3"
)

func newAppMCPReadConnectionTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3_benmore", filepath.Join(t.TempDir(), "app.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT)`); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestOpenReadOnlyQueryConnDiscardsPooledTransaction(t *testing.T) {
	db := newAppMCPReadConnectionTestDB(t)
	if _, err := db.Exec(`BEGIN`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO notes (title) VALUES ('uncommitted')`); err != nil {
		t.Fatal(err)
	}

	rows, truncated, err := queryReadOnlyRows(context.Background(), db, `SELECT title FROM notes`, 10)
	if err == nil || len(rows) != 0 || truncated {
		t.Fatalf("dirty pooled transaction reached delegated read: rows=%v truncated=%v err=%v", rows, truncated, err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM notes`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("discarded transaction became visible: count=%d err=%v", count, err)
	}
	if _, err := db.Exec(`INSERT INTO notes (title) VALUES ('normal write')`); err != nil {
		t.Fatalf("fresh pooled connection rejected normal write: %v", err)
	}
}

func TestCloseReadOnlyQueryConnDiscardsUnexpectedTransaction(t *testing.T) {
	db := newAppMCPReadConnectionTestDB(t)
	conn, _, closeConn, err := openReadOnlyQueryConn(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Raw(func(raw any) error {
		sqlite := raw.(*sqlite3.SQLiteConn)
		restoreConnAuthorizer(sqlite)
		_, err := sqlite.Exec(`BEGIN`, nil)
		return err
	}); err != nil {
		closeConn()
		t.Fatal(err)
	}
	closeConn()

	fresh, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := fresh.Raw(func(raw any) error {
		if !raw.(*sqlite3.SQLiteConn).AutoCommit() {
			return errors.New("transactional connection was returned to the pool")
		}
		return nil
	}); err != nil {
		_ = fresh.Close()
		t.Fatal(err)
	}
	_ = fresh.Close()
	if _, err := db.Exec(`INSERT INTO notes (title) VALUES ('normal write')`); err != nil {
		t.Fatalf("fresh pooled connection rejected normal write: %v", err)
	}
}

func TestReadOnlyQueryCancellationAfterExecutionRestoresConnection(t *testing.T) {
	db := newAppMCPReadConnectionTestDB(t)
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{}, 1)
	if err := conn.Raw(func(raw any) error {
		return raw.(*sqlite3.SQLiteConn).RegisterFunc("audit_started", func() int64 {
			select {
			case started <- struct{}{}:
			default:
			}
			return 1
		}, false)
	}); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	_ = conn.Close()

	type queryResult struct {
		rows      []map[string]any
		truncated bool
		err       error
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan queryResult, 1)
	go func() {
		rows, truncated, err := queryReadOnlyRows(ctx, db,
			`WITH RECURSIVE x(n) AS (
				SELECT audit_started()
				UNION ALL SELECT n+1 FROM x WHERE n < 1000000000
			) SELECT sum(n) FROM x`, 1)
		result <- queryResult{rows: rows, truncated: truncated, err: err}
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("SQLite query did not start within one second")
	}
	cancel()
	select {
	case got := <-result:
		if !errors.Is(got.err, context.Canceled) || len(got.rows) != 0 || got.truncated {
			t.Fatalf("canceled query result: rows=%v truncated=%v err=%v", got.rows, got.truncated, got.err)
		}
	case <-time.After(time.Second):
		t.Fatal("SQLite query did not stop within one second after cancellation")
	}

	fresh, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := fresh.Raw(func(raw any) error {
		if !raw.(*sqlite3.SQLiteConn).AutoCommit() {
			return errors.New("canceled read left a transaction open")
		}
		return nil
	}); err != nil {
		_ = fresh.Close()
		t.Fatal(err)
	}
	var queryOnly bool
	if err := fresh.QueryRowContext(context.Background(), `PRAGMA query_only`).Scan(&queryOnly); err != nil {
		_ = fresh.Close()
		t.Fatal(err)
	}
	_ = fresh.Close()
	if queryOnly {
		t.Fatal("canceled read left query_only enabled")
	}
	if _, err := db.Exec(`INSERT INTO notes (title) VALUES ('normal write')`); err != nil {
		t.Fatalf("connection was not restored for normal writes: %v", err)
	}
}
