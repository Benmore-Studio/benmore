//go:build !cli

package main

// Data channel operations over the app's own SQL (app_data_channel.go):
//
//	query       one read-only statement, the same text gate, executor, row cap,
//	            statement timeout and credential-column masking as MCP query_db
//	            (gate "query_db") or the dashboard SQL console (gate "console")
//	exec        one guarded write statement (MCP sql write:true), audited in
//	            the statement's own transaction
//	schema      table names, optionally with columns, row counts and the tables
//	            schema.prisma declares
//	count       row counts per table
//	table_rows  one table's rows, paged and filtered by column equality, through
//	            the read-only executor
//
// Every operation validates its arguments and refuses unknown fields.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	appDataQueryMaxSQLBytes = 8 << 20
	appDataTableRowsMax     = 500
	appDataTableRowsOffset  = 1_000_000
	appDataTableFilterMax   = 16
)

func init() {
	registerAppDataOp("query", appDataOp{MinRole: "editor", Timeout: readOnlyQueryTimeout + 2*time.Second, AnswerTokens: appDataLargeAnswerTokens, Run: appDataQuery})
	registerAppDataOp("exec", appDataOp{MinRole: "editor", Mutating: true, Timeout: tenantWriteTimeout + 5*time.Second, Run: appDataExec})
	registerAppDataOp("schema", appDataOp{MinRole: "viewer", Timeout: 60 * time.Second, AnswerTokens: appDataLargeAnswerTokens, Run: appDataSchema})
	registerAppDataOp("count", appDataOp{MinRole: "viewer", Timeout: 60 * time.Second, Run: appDataCount})
	registerAppDataOp("table_rows", appDataOp{MinRole: "editor", Timeout: readOnlyQueryTimeout + 2*time.Second, AnswerTokens: appDataLargeAnswerTokens, Run: appDataTableRows})
}

// appDataQueryDBRefusal is query_db's text-gate refusal, kept word for word.
const appDataQueryDBRefusal = "only single-statement SELECT/WITH queries are allowed. For mutations, use the auto-generated CRUD endpoints (POST/PATCH/DELETE /api/<table>) via apply or write_file"

type appDataQueryArgs struct {
	SQL   string `json:"sql"`
	Limit int    `json:"limit,omitempty"`
	// Gate is the caller's text gate: "query_db" (default) or "console".
	Gate string `json:"gate,omitempty"`
	// BytesAsText returns BLOB values as text (the console's table view).
	BytesAsText bool `json:"bytes_as_text,omitempty"`
	// Reason is the owner's stated reason, required for a compliance: hipaa
	// app (hipaa_data_reads.go) and written to the audit row.
	Reason string `json:"reason,omitempty"`
}

type appDataRowsResult struct {
	Rows      []map[string]any `json:"rows"`
	Columns   []string         `json:"columns"`
	Truncated bool             `json:"truncated"`
}

func appDataQuery(ctx context.Context, c *appDataOpCall) (any, error) {
	var args appDataQueryArgs
	if err := c.decodeArgs(&args); err != nil {
		return nil, err
	}
	if strings.TrimSpace(args.SQL) == "" {
		return nil, appDataFail("bad_request", "sql is required")
	}
	if len(args.SQL) > appDataQueryMaxSQLBytes {
		return nil, appDataFail("too_large", "sql is too large")
	}
	if args.Limit < 0 || args.Limit > readOnlyQueryMaxRows {
		return nil, appDataFail("bad_request", "limit must be between 1 and %d", readOnlyQueryMaxRows)
	}
	query := args.SQL
	switch args.Gate {
	case "", "query_db":
		if !isReadOnlyQuery(query) {
			return nil, appDataFail("rejected", "%s", appDataQueryDBRefusal)
		}
	case "console":
		clean, refusal := sanitizeConsoleQuery(query)
		if refusal != "" {
			return nil, appDataFail("rejected", "%s", refusal)
		}
		query = clean
	default:
		return nil, appDataFail("bad_request", "gate must be query_db or console")
	}
	if readOnlyNamedJoinOnFrameworkTable(query) {
		return nil, appDataFail("rejected", "%s", readOnlyNamedJoinRefusal)
	}
	hipaa := c.App.hipaa()
	if hipaa {
		// The router applies the same rule (hipaa_data_reads.go); this holds it
		// for any caller of the channel.
		if c.Actor.Role != "owner" {
			return nil, appDataFail("forbidden", "this app is compliance: hipaa: reading its rows is limited to the app owner")
		}
		if r := strings.TrimSpace(args.Reason); r == "" || len(r) > 500 {
			return nil, appDataFail("bad_request", "this app is compliance: hipaa: a reason (1-500 characters) is required to read its data")
		}
	}
	rows, cols, truncated, err := queryReadOnlyAuthoredRows(ctx, c.App, query, args.Limit)
	if err != nil {
		return nil, appDataQueryError(ctx, err)
	}
	if hipaa {
		// Recorded before any row leaves; no row is answered without it. The
		// statement text is not stored (it may quote PHI), only its digest.
		sum := sha256.Sum256([]byte(args.SQL))
		if err := c.audit(c.App.DB, "data_sql_read", "", "", map[string]any{
			"gate":             args.Gate,
			"reason":           strings.TrimSpace(args.Reason),
			"statement_sha256": hex.EncodeToString(sum[:]),
			"row_count":        len(rows),
		}); err != nil {
			return nil, &appDataError{Code: "internal", Message: "audit row not written: " + err.Error()}
		}
	}
	if args.BytesAsText {
		textBytes(rows)
	}
	return appDataRowsResult{Rows: rows, Columns: cols, Truncated: truncated}, nil
}

// appDataQueryError keeps the driver's message (what callers showed before)
// and marks a statement that ran out of time.
func appDataQueryError(ctx context.Context, err error) *appDataError {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return &appDataError{Code: "timeout", Message: err.Error()}
	}
	if errors.Is(err, errReadOnlyNamedJoinView) {
		return appDataFail("rejected", "%s", err.Error())
	}
	return &appDataError{Code: "query_failed", Message: err.Error()}
}

func textBytes(rows []map[string]any) {
	for _, row := range rows {
		for k, v := range row {
			if b, ok := v.([]byte); ok {
				row[k] = string(b)
			}
		}
	}
}

type appDataExecArgs struct {
	SQL string `json:"sql"`
}

type appDataExecResult struct {
	RowsAffected int64 `json:"rows_affected"`
	LastInsertID int64 `json:"last_insert_id"`
}

// appDataExec runs one write statement (MCP sql write:true) in a transaction
// with its audit row, under the same deadline the router used, then tells
// connected clients to refetch.
func appDataExec(ctx context.Context, c *appDataOpCall) (any, error) {
	var args appDataExecArgs
	if err := c.decodeArgs(&args); err != nil {
		return nil, err
	}
	if len(args.SQL) > appDataQueryMaxSQLBytes {
		return nil, appDataFail("too_large", "sql is too large")
	}
	if err := validateTenantWriteSQL(args.SQL); err != nil {
		return nil, appDataFail("rejected", "%s", err.Error())
	}
	if c.App.hipaa() && mentionsAuditTable(args.SQL) {
		return nil, appDataFail("rejected", "the audit tables are append-only under compliance: hipaa; sql(write:true) may not name them")
	}
	ctx, cancel := context.WithTimeout(ctx, tenantWriteDeadline)
	defer cancel()
	tx, err := c.App.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, appDataExecError(c.App, err)
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, args.SQL)
	if err != nil {
		return nil, appDataExecError(c.App, err)
	}
	rows, _ := res.RowsAffected()
	// SQLite's last insert rowid belongs to the connection: after an UPDATE
	// or DELETE it still holds whatever this pooled connection inserted
	// before, so it is reported only for an insert that added rows.
	verb := sqlMainVerb(sqlTokenize(args.SQL))
	var lastID int64
	if rows > 0 && (verb == "INSERT" || verb == "REPLACE") {
		lastID, _ = res.LastInsertId()
	}
	sum := sha256.Sum256([]byte(args.SQL))
	table := extractTableFromStmt(args.SQL)
	// The statement text is not recorded: a write may carry a secret value.
	// Its hash identifies it for anyone holding the text.
	if err := c.audit(tx, "data_sql_write", table, "", map[string]any{
		"verb":             verb,
		"statement_sha256": hex.EncodeToString(sum[:]),
		"rows_affected":    rows,
	}); err != nil {
		return nil, appDataExecError(c.App, err)
	}
	if err := tx.Commit(); err != nil {
		return nil, appDataExecError(c.App, err)
	}
	broadcastSQLWrite(c.App, args.SQL)
	return appDataExecResult{RowsAffected: rows, LastInsertID: lastID}, nil
}

func appDataExecError(app *App, err error) *appDataError {
	if isStorageFullError(err) {
		return &appDataError{Code: "storage_full", Message: storageFullMessage(app)}
	}
	return &appDataError{Code: "exec_failed", Message: err.Error()}
}

type appDataSchemaArgs struct {
	// Tables picks the name list: "crud" (tables auto-CRUD would serve,
	// GetTableNames) or "all" (every table but sqlite_*, GetAllTableNames).
	Tables   string `json:"tables,omitempty"`
	Columns  bool   `json:"columns,omitempty"`
	Counts   bool   `json:"counts,omitempty"`
	Declared bool   `json:"declared,omitempty"`
}

type appDataColumn struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	NotNull bool   `json:"not_null,omitempty"`
	PK      bool   `json:"pk,omitempty"`
	Default string `json:"default,omitempty"`
}

type appDataTable struct {
	Name    string          `json:"name"`
	Columns []appDataColumn `json:"columns,omitempty"`
	Rows    *int64          `json:"rows,omitempty"`
}

type appDataSchemaResult struct {
	Tables []appDataTable `json:"tables"`
	// Declared lists the tables the app's schema file declares, when asked.
	Declared []string `json:"declared,omitempty"`
}

func appDataTableNames(c *appDataOpCall, which string) ([]string, *appDataError) {
	var (
		names []string
		err   error
	)
	switch which {
	case "", "crud":
		names, err = GetTableNames(c.App.DB)
	case "all":
		names, err = GetAllTableNames(c.App.DB)
	default:
		return nil, appDataFail("bad_request", "tables must be crud or all")
	}
	if err != nil {
		return nil, &appDataError{Code: "query_failed", Message: err.Error()}
	}
	return names, nil
}

func appDataSchema(ctx context.Context, c *appDataOpCall) (any, error) {
	var args appDataSchemaArgs
	if err := c.decodeArgs(&args); err != nil {
		return nil, err
	}
	names, derr := appDataTableNames(c, args.Tables)
	if derr != nil {
		return nil, derr
	}
	out := appDataSchemaResult{Tables: make([]appDataTable, 0, len(names))}
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return nil, appDataQueryError(ctx, err)
		}
		t := appDataTable{Name: name}
		if args.Columns {
			cols, _ := GetTableColumns(c.App.DB, name)
			t.Columns = make([]appDataColumn, 0, len(cols))
			for _, col := range cols {
				t.Columns = append(t.Columns, appDataColumn{Name: col.Name, Type: col.Type, NotNull: col.NotNull, PK: col.PK, Default: col.Default})
			}
		}
		if args.Counts {
			n := appDataRowCount(ctx, c, name)
			t.Rows = &n
		}
		out.Tables = append(out.Tables, t)
	}
	if args.Declared {
		out.Declared = appDataDeclaredTables(c.App)
	}
	return out, nil
}

// appDataRowCount counts a table's rows; an unreadable table counts 0, as the
// callers' own loops always did.
func appDataRowCount(ctx context.Context, c *appDataOpCall, table string) int64 {
	var n int64
	_ = c.App.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+quoteIdent(table)).Scan(&n)
	return n
}

// appDataDeclaredTables lists the tables the app's schema file declares: the
// loaded app's tables, or, when none are loaded, the tables of the file the
// loader reads (schema.prisma, else schema.sql).
func appDataDeclaredTables(app *App) []string {
	declared := []string{}
	for _, t := range app.Tables {
		declared = append(declared, t.Name)
	}
	if len(declared) > 0 {
		return declared
	}
	ddl, err := appMCPSchemaDDLWithReader(func(name string) ([]byte, error) {
		return os.ReadFile(filepath.Join(app.Dir, name))
	})
	if err != nil {
		return declared
	}
	for _, t := range ParseCreateTables(ddl) {
		declared = append(declared, t.Name)
	}
	return declared
}

type appDataCountArgs struct {
	Tables string `json:"tables,omitempty"`
	// Names, when set, counts only these tables (of the chosen list); a
	// name the database does not have is left out of the answer.
	Names []string `json:"names,omitempty"`
}

type appDataCountResult struct {
	Counts map[string]int64 `json:"counts"`
}

func appDataCount(ctx context.Context, c *appDataOpCall) (any, error) {
	var args appDataCountArgs
	if err := c.decodeArgs(&args); err != nil {
		return nil, err
	}
	if len(args.Names) > 256 {
		return nil, appDataFail("bad_request", "too many table names")
	}
	names, derr := appDataTableNames(c, args.Tables)
	if derr != nil {
		return nil, derr
	}
	if len(args.Names) > 0 {
		wanted := make(map[string]bool, len(args.Names))
		for _, n := range args.Names {
			wanted[n] = true
		}
		kept := names[:0]
		for _, n := range names {
			if wanted[n] {
				kept = append(kept, n)
			}
		}
		names = kept
	}
	out := appDataCountResult{Counts: make(map[string]int64, len(names))}
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return nil, appDataQueryError(ctx, err)
		}
		out.Counts[name] = appDataRowCount(ctx, c, name)
	}
	return out, nil
}

type appDataTableRowsArgs struct {
	Table   string            `json:"table"`
	Columns []string          `json:"columns,omitempty"`
	Where   map[string]string `json:"where,omitempty"`
	OrderBy string            `json:"order_by,omitempty"`
	Desc    bool              `json:"desc,omitempty"`
	Limit   int               `json:"limit,omitempty"`
	Offset  int               `json:"offset,omitempty"`
}

// appDataTableRows reads one page of a table. Every identifier is checked
// against the live schema and quoted; every value is bound. The statement
// runs on the read-only executor, so the framework credential columns read
// as NULL exactly as they do for query.
func appDataTableRows(ctx context.Context, c *appDataOpCall) (any, error) {
	var args appDataTableRowsArgs
	if err := c.decodeArgs(&args); err != nil {
		return nil, err
	}
	if c.App.hipaa() {
		// Row reads of a hipaa app go through query with an owner's reason.
		return nil, appDataFail("forbidden", "this app is compliance: hipaa: read rows with query_db (owner, with a reason)")
	}
	if args.Limit == 0 {
		args.Limit = 50
	}
	if args.Limit < 1 || args.Limit > appDataTableRowsMax {
		return nil, appDataFail("bad_request", "limit must be between 1 and %d", appDataTableRowsMax)
	}
	if args.Offset < 0 || args.Offset > appDataTableRowsOffset {
		return nil, appDataFail("bad_request", "offset must be between 0 and %d", appDataTableRowsOffset)
	}
	if len(args.Where) > appDataTableFilterMax || len(args.Columns) > 256 {
		return nil, appDataFail("bad_request", "too many columns or filters")
	}
	names, derr := appDataTableNames(c, "all")
	if derr != nil {
		return nil, derr
	}
	found := false
	for _, n := range names {
		if n == args.Table {
			found = true
			break
		}
	}
	if !found {
		return nil, appDataFail("not_found", "table %q not found", args.Table)
	}
	cols, err := GetTableColumns(c.App.DB, args.Table)
	if err != nil {
		return nil, &appDataError{Code: "query_failed", Message: err.Error()}
	}
	known := make(map[string]bool, len(cols))
	for _, col := range cols {
		known[col.Name] = true
	}
	selectList := "*"
	if len(args.Columns) > 0 {
		quoted := make([]string, 0, len(args.Columns))
		for _, name := range args.Columns {
			if !known[name] {
				return nil, appDataFail("bad_request", "unknown column %q", name)
			}
			quoted = append(quoted, quoteIdent(name))
		}
		selectList = strings.Join(quoted, ", ")
	}
	query := "SELECT " + selectList + " FROM " + quoteIdent(args.Table)
	var binds []any
	if len(args.Where) > 0 {
		keys := make([]string, 0, len(args.Where))
		for k := range args.Where {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		clauses := make([]string, 0, len(keys))
		for _, k := range keys {
			if !known[k] {
				return nil, appDataFail("bad_request", "unknown column %q", k)
			}
			clauses = append(clauses, quoteIdent(k)+" = ?")
			binds = append(binds, args.Where[k])
		}
		query += " WHERE " + strings.Join(clauses, " AND ")
	}
	if args.OrderBy != "" {
		if !known[args.OrderBy] {
			return nil, appDataFail("bad_request", "unknown column %q", args.OrderBy)
		}
		query += " ORDER BY " + quoteIdent(args.OrderBy)
		if args.Desc {
			query += " DESC"
		}
	}
	// One extra row tells the executor whether the page is truncated.
	query += " LIMIT ? OFFSET ?"
	binds = append(binds, args.Limit+1, args.Offset)
	rows, columns, truncated, err := queryReadOnlyRowsCols(ctx, c.App.DB, query, args.Limit, binds...)
	if err != nil {
		return nil, appDataQueryError(ctx, err)
	}
	return appDataRowsResult{Rows: rows, Columns: columns, Truncated: truncated}, nil
}
