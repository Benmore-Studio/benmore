//go:build !cli

package main

// Whether a load's schema step will change the database, decided before it
// runs so the pre-migrate snapshot (a VACUUM INTO copy of the whole database)
// is taken only when there is something to undo. Every app restart took one,
// and kept ten: 31 GB across the fleet for 3.5 GB of live data, all of it
// written by restarts that changed nothing.
//
// The schema step is LoadSchema (generated Prisma migrations and adopted
// migration files, each of which snapshots before it runs, and CREATE TABLE IF
// NOT EXISTS), then Migrate (ADD COLUMN) and the deferred index/view/trigger
// DDL. The decision reads:
//
//   - the schema cookie (PRAGMA schema_version) taken when the database was
//     opened: any DDL so far in this load, LoadSchema's included, bumps it;
//   - Migrate's own plan (planMigration), the comparison Migrate applies;
//   - each deferred CREATE ... IF NOT EXISTS: it changes the schema only when
//     its object does not exist yet, and the Prisma updatedAt reconcile only
//     when a stored trigger has the legacy definition.
//
// Anything it cannot read or attribute counts as a change. The schema cookie
// is read again after the step: a change the plan missed is logged, and the
// load's integrity_check still runs (db_integrity_ledger.go). Data rewrites
// later in a start (a new runtime build, a storage-configuration change) are
// a separate snapshot reason (db_boot_state.go).

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// loadSnapshots carries, through a load's context, the first pre-migrate
// snapshot the load took: the Prisma step's (a generated or adopted migration
// snapshots before it runs), the loader's own, or the user-migration runner's.
// It holds the database as it was before the load changed anything, so the
// loader does not copy the database a second time and a failed integrity_check
// restores it.
type loadSnapshots struct{ first string }

type loadSnapshotsKey struct{}

func withLoadSnapshots(ctx context.Context, s *loadSnapshots) context.Context {
	return context.WithValue(ctx, loadSnapshotsKey{}, s)
}

// noteLoadSnapshot records a snapshot the load took (path "" is no snapshot).
// Only the first counts: it is the oldest state of this load.
func noteLoadSnapshot(ctx context.Context, path string) {
	if s, ok := ctx.Value(loadSnapshotsKey{}).(*loadSnapshots); ok && s.first == "" && path != "" {
		s.first = path
	}
}

// schemaSnapshotReason says why this load should copy the database before
// Migrate, or returns "" when the schema step will not change it.
func schemaSnapshotReason(db *sql.DB, versionAtOpen int64, versionKnown bool, tables []Table, deferred []string) string {
	if !versionKnown {
		return "the schema version could not be read at open"
	}
	now, err := sqliteSchemaVersion(db)
	if err != nil {
		return "schema version: " + err.Error()
	}
	if now != versionAtOpen {
		return "the schema changed while it was loaded"
	}
	plan, err := planMigration(db, tables, false)
	if err != nil {
		return "migration plan: " + err.Error()
	}
	if plan.changes() {
		if len(plan.missingTables) > 0 {
			return "table " + plan.missingTables[0] + " is missing"
		}
		return fmt.Sprintf("%d column(s) to add, starting with %s.%s", len(plan.adds), plan.adds[0].table, plan.adds[0].col.Name)
	}
	if stmt, err := pendingDeferredDDL(db, deferred); err != nil {
		return "deferred schema DDL: " + err.Error()
	} else if stmt != "" {
		return "deferred schema DDL to apply: " + truncate(stmt, 80)
	}
	if upgrade, err := prismaUpdatedAtTriggersNeedUpgrade(db, deferred); err != nil {
		return "Prisma updatedAt triggers: " + err.Error()
	} else if upgrade {
		return "a Prisma updatedAt trigger has a legacy definition"
	}
	return ""
}

// pendingDeferredDDL returns the first deferred statement that would create
// an object, or "" when every one names an object that already exists.
func pendingDeferredDDL(db *sql.DB, deferred []string) (string, error) {
	for _, stmt := range deferred {
		kind, name, ok := deferredDDLObject(stmt)
		if !ok {
			return stmt, nil
		}
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM main.sqlite_schema WHERE type = ? AND name = ? COLLATE NOCASE`, kind, name).Scan(&n); err != nil {
			return "", err
		}
		if n == 0 {
			return stmt, nil
		}
	}
	return "", nil
}

// deferredDDLObject reads the object type and name of a deferred
// CREATE [UNIQUE] INDEX / VIEW / TRIGGER IF NOT EXISTS statement (LoadSchema
// adds IF NOT EXISTS before deferring it). ok is false for anything else,
// including a name qualified with a schema other than main.
func deferredDDLObject(stmt string) (kind, name string, ok bool) {
	s := sqlTokenReader{src: stmt}
	if !s.keyword("CREATE") {
		return "", "", false
	}
	switch {
	case s.keyword("UNIQUE"):
		if !s.keyword("INDEX") {
			return "", "", false
		}
		kind = "index"
	case s.keyword("INDEX"):
		kind = "index"
	case s.keyword("VIEW"):
		kind = "view"
	case s.keyword("TRIGGER"):
		kind = "trigger"
	default:
		return "", "", false
	}
	if !s.keyword("IF") || !s.keyword("NOT") || !s.keyword("EXISTS") {
		return "", "", false
	}
	name, ok = s.identifier()
	if !ok {
		return "", "", false
	}
	if s.punct('.') {
		if !strings.EqualFold(name, "main") {
			return "", "", false
		}
		if name, ok = s.identifier(); !ok {
			return "", "", false
		}
	}
	return kind, name, true
}

// sqlTokenReader reads the leading keywords and identifiers of a statement.
type sqlTokenReader struct {
	src string
	pos int
}

func (r *sqlTokenReader) skipSpace() {
	for r.pos < len(r.src) && strings.ContainsRune(" \t\r\n\f", rune(r.src[r.pos])) {
		r.pos++
	}
}

func isSQLIdentByte(c byte) bool {
	return c == '_' || c == '$' || c >= 0x80 || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// keyword consumes word (case-insensitive) when it is the next whole token.
func (r *sqlTokenReader) keyword(word string) bool {
	r.skipSpace()
	end := r.pos + len(word)
	if end > len(r.src) || !strings.EqualFold(r.src[r.pos:end], word) {
		return false
	}
	if end < len(r.src) && isSQLIdentByte(r.src[end]) {
		return false
	}
	r.pos = end
	return true
}

func (r *sqlTokenReader) punct(c byte) bool {
	r.skipSpace()
	if r.pos < len(r.src) && r.src[r.pos] == c {
		r.pos++
		return true
	}
	return false
}

// identifier reads a bare, "double", `back` or [bracket] quoted identifier.
func (r *sqlTokenReader) identifier() (string, bool) {
	r.skipSpace()
	if r.pos >= len(r.src) {
		return "", false
	}
	open := r.src[r.pos]
	closer := byte(0)
	switch open {
	case '"', '`':
		closer = open
	case '[':
		closer = ']'
	}
	if closer == 0 {
		start := r.pos
		for r.pos < len(r.src) && isSQLIdentByte(r.src[r.pos]) {
			r.pos++
		}
		if r.pos == start || (r.src[start] >= '0' && r.src[start] <= '9') {
			return "", false
		}
		return r.src[start:r.pos], true
	}
	var b strings.Builder
	for i := r.pos + 1; i < len(r.src); i++ {
		if r.src[i] != closer {
			b.WriteByte(r.src[i])
			continue
		}
		// A doubled quote is a literal quote ("" and ``, not ]]).
		if closer != ']' && i+1 < len(r.src) && r.src[i+1] == closer {
			b.WriteByte(closer)
			i++
			continue
		}
		r.pos = i + 1
		if b.Len() == 0 {
			return "", false
		}
		return b.String(), true
	}
	return "", false
}
