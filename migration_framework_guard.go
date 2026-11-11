//go:build !cli

package main

// User migration files run under an engine-enforced scope.
//
// A file in migrations/ is SQL an app editor wrote, run statement by
// statement in one transaction on the app's database. The only check it had
// was by text and only while the append-only triggers existed
// (refuseAuditTableStatement), so on a `compliance: hipaa` database a file
// could set PRAGMA writable_schema, delete the six triggers from
// sqlite_master without naming an audit table, and update an audit row in its
// next statement.
//
// Each statement of a file now carries the migration marker
// (appMigrationSQL), and the driver wrapper applies
// appSQLScope.authorizeMigration to it (app_sql_guard.go): by authorizer
// action code and object name, whatever the text looks like. Only the file's
// own statements are marked. What the framework runs in the same transaction
// (its ledger row, its index drops, the schema steps of a load, the trigger
// installs) is not, so the framework's changes to its own tables are
// untouched.
//
// Whether the app is hipaa is decided before the file's first statement and
// holds for the whole file: its app.yaml says so (or the platform's record
// does), or the append-only triggers are installed. It is never read again
// from the triggers a statement of the file may have gone after.

import (
	"context"
)

type migrationHIPAAKey struct{}

// withMigrationAppDir records on ctx whether the app in dir is
// `compliance: hipaa`, for the migration files run with ctx. read is how the
// caller reads the app's files.
func withMigrationAppDir(ctx context.Context, dir string, read func(dir, name string) ([]byte, error)) context.Context {
	hipaa := hipaaStickyForAppDir != nil && hipaaStickyForAppDir(dir)
	if data, err := read(dir, "app.yaml"); err == nil && !hipaa {
		hipaa, _ = appYAMLDeclaresHIPAA(data)
	}
	return context.WithValue(ctx, migrationHIPAAKey{}, hipaa)
}

// migrationUnderHIPAA is the decision for one migration file, made once
// before its first statement.
func migrationUnderHIPAA(ctx context.Context, x auditExecer) bool {
	if hipaa, _ := ctx.Value(migrationHIPAAKey{}).(bool); hipaa {
		return true
	}
	active, err := auditAppendOnlyActive(x)
	return err != nil || active
}
