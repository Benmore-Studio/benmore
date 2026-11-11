//go:build !cli

package main

// Source-time check of a command dependency's result shape.
//
// At prepare the runtime requires every dependency query to return exactly one
// column named id (appMCPCaptureCommandDependencies). The command compiler
// checks the query's text and tables but not its result columns, so a query
// such as `SELECT id, title FROM tasks ...` used to pass `benmore mcp review`,
// `mcp check`, the push write gate and `benmore check`, and then failed every
// prepare. Here each dependency query is prepared against an empty in-memory
// database built from the app's schema source and its result columns are held
// to the same rule. The statement is never stepped (no row is read and no
// function runs) and the database holds no app data. A query the schema alone
// cannot prepare (a table or column a migration adds, a function only the live
// database registers) is left to the runtime, which then refuses the prepare
// with the named invalid_declaration error.

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// appMCPDependencyShapeBudget bounds building the scratch schema and preparing
// every dependency of one check.
const appMCPDependencyShapeBudget = 2 * time.Second

// appMCPDependencyColumnsValid is the one result-shape rule: the static check
// and appMCPCaptureCommandDependencies both use it.
func appMCPDependencyColumnsValid(columns []string) bool {
	return len(columns) == 1 && strings.EqualFold(columns[0], "id")
}

// appMCPDependencyShapeMessage is the refusal text, shared with the runtime.
func appMCPDependencyShapeMessage(name string) string {
	return fmt.Sprintf("dependency %q must return exactly one id column", name)
}

// appMCPCheckCommandDependencyShapes refuses the first dependency whose query
// prepares against the schema and returns anything but one id column. A schema
// that cannot be read or emitted is reported by the command table inventory
// itself, so it is not judged again here.
func appMCPCheckCommandDependencyShapes(readSource func(string) ([]byte, error), flows []Flow) error {
	var commands []Flow
	for _, flow := range flows {
		if flow.Command != nil && len(flow.Command.Dependencies) > 0 {
			commands = append(commands, flow)
		}
	}
	if len(commands) == 0 {
		return nil
	}
	ddl, err := appMCPSchemaDDLWithReader(readSource)
	if err != nil || strings.TrimSpace(ddl) == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), appMCPDependencyShapeBudget)
	defer cancel()
	db := appMCPDependencyShapeDB(ctx, ddl)
	if db == nil {
		return nil
	}
	defer db.Close()
	for _, flow := range commands {
		for _, dependency := range flow.Command.Dependencies {
			columns, ok := appMCPDependencyQueryColumns(ctx, db, dependency)
			if !ok || appMCPDependencyColumnsValid(columns) {
				continue
			}
			message := appMCPDependencyShapeMessage(dependency.Name)
			if flow.Source != "" {
				message = flow.Source + ": " + message
			}
			returned := "no columns"
			if len(columns) > 0 {
				returned = fmt.Sprintf("%d column(s): %s", len(columns), strings.Join(columns, ", "))
			}
			return fmt.Errorf("%s; its query returns %s. Select only the dependency table's id, for example SELECT id FROM %s WHERE ...", message, returned, dependency.Table)
		}
	}
	return nil
}

// appMCPDependencyShapeDB creates the schema's tables in a private in-memory
// database. Only CREATE TABLE statements run; one that fails leaves its table
// out, and queries naming it are then not judged.
func appMCPDependencyShapeDB(ctx context.Context, ddl string) *sql.DB {
	db, err := sql.Open(sqliteMaintenanceDriver, ":memory:")
	if err != nil {
		return nil
	}
	// One connection: every pooled :memory: connection is its own database.
	db.SetMaxOpenConns(1)
	err = splitSQLStatements(strings.NewReader(ddl), func(statement string) error {
		tokens := sqlTokenize(statement)
		if len(tokens) >= 2 && strings.EqualFold(tokens[0].text, "CREATE") && strings.EqualFold(tokens[1].text, "TABLE") {
			_, _ = db.ExecContext(ctx, statement)
		}
		return ctx.Err()
	})
	if err != nil {
		db.Close()
		return nil
	}
	return db
}

// appMCPDependencyQueryColumns prepares one dependency query with every
// binding NULL and reads its result column names. database/sql's Query binds
// and returns before the first step (this driver steps lazily unless a
// statement cache is configured, which this DSN does not), so nothing is
// evaluated. ok is false when the query does not prepare against the schema.
func appMCPDependencyQueryColumns(ctx context.Context, db *sql.DB, dependency FlowCommandDependency) (columns []string, ok bool) {
	query, runnable := sqlRunnableText(dependency.Query)
	if !runnable {
		return nil, false
	}
	args := make([]any, 0, len(dependency.Params))
	for name := range dependency.Params {
		args = append(args, sql.Named(name, nil))
	}
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, false
	}
	defer rows.Close()
	columns, err = rows.Columns()
	return columns, err == nil
}
