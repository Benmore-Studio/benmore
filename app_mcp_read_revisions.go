//go:build !cli

package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"strconv"
)

// appMCPReadRevisionRace is a test seam that runs after the data was read and
// before the revision snapshot opens.
var appMCPReadRevisionRace func()

// appMCPRevisionPin holds one pooled connection for a single native read. The
// data is read on other pool connections, so the pin is how the revision
// sidecar proves it describes the same state: SQLite's data_version on this
// connection changes whenever any other connection commits, so an unchanged
// value across the read means no write landed between data and revisions.
type appMCPRevisionPin struct {
	conn    *sql.Conn
	version int64
	owner   *App
}

// pinAppMCPReadRevisions returns nil when revisions cannot be read safely
// (a single-connection pool would deadlock the data read; non-SQLite backends).
// A pin is held while the data read takes further pool connections, so pins
// use at most half of a bounded pool: reads that each pinned a connection and
// then waited for another would stall every query of the app until the read
// timeout. A read past the bound omits revisions (data_revision_unavailable).
// app must be the live owner, whose counter outlives policy views.
func pinAppMCPReadRevisions(ctx context.Context, app *App) *appMCPRevisionPin {
	if app == nil || app.DB == nil {
		return nil
	}
	open := app.DB.Stats().MaxOpenConnections
	if open == 1 {
		return nil
	}
	if pinned := app.mcpRevisionPins.Add(1); open > 0 && pinned > int64(open/2) {
		app.mcpRevisionPins.Add(-1)
		return nil
	}
	pin := &appMCPRevisionPin{owner: app}
	conn, err := app.DB.Conn(ctx)
	if err != nil {
		app.mcpRevisionPins.Add(-1)
		return nil
	}
	pin.conn = conn
	if conn.QueryRowContext(ctx, "PRAGMA data_version").Scan(&pin.version) != nil {
		pin.close()
		return nil
	}
	return pin
}

func (p *appMCPRevisionPin) close() {
	if p != nil && p.conn != nil {
		_ = p.conn.Close()
		p.conn = nil
		p.owner.mcpRevisionPins.Add(-1)
	}
}

// revisions returns the sidecar revisions for the rows a read returned, as
// source_revisions entries: "row:<table>/<id>" when the tool exposes ids,
// otherwise one "rows:<table>" entry holding the highest returned revision.
// ok is false when the table is not enrolled, its revision triggers are not
// intact, a returned row has no live ledger entry, or a write interleaved.
// An empty page is ok: there is no row to cite. The write path verifies the
// whole enrollment; a read only checks what it cites, in O(rows) lookups.
func (p *appMCPRevisionPin) revisions(ctx context.Context, table string, rows []map[string]any, exposeIDs bool) (found map[string]string, ok bool) {
	if p == nil {
		return nil, false
	}
	if appMCPReadRevisionRace != nil {
		appMCPReadRevisionRace()
	}
	if _, err := p.conn.ExecContext(ctx, "BEGIN"); err != nil {
		return nil, false
	}
	defer func() {
		if _, err := p.conn.ExecContext(context.WithoutCancel(ctx), "ROLLBACK"); err != nil {
			_ = p.conn.Raw(func(any) error { return driver.ErrBadConn }) // never pool an open transaction
		}
	}()
	var incarnation string
	if p.conn.QueryRowContext(ctx, "SELECT incarnation FROM main."+appMCPRevisionTablesName+" WHERE table_name=?", table).Scan(&incarnation) != nil {
		return nil, false
	}
	var version int64
	if p.conn.QueryRowContext(ctx, "PRAGMA data_version").Scan(&version) != nil || version != p.version {
		return nil, false
	}
	if !p.triggersIntact(ctx, table) {
		return nil, false
	}
	found = map[string]string{}
	var highest int64
	for _, row := range rows {
		keyType, key, valid := appMCPRevisionRowKey(row["id"])
		if !valid {
			return nil, false
		}
		var revision, deleted int64
		if p.conn.QueryRowContext(ctx, "SELECT revision,deleted FROM main."+appMCPRowRevisionsName+" WHERE table_name=? AND incarnation=? AND key_type=? AND row_key=?", table, incarnation, keyType, key).Scan(&revision, &deleted) != nil || deleted != 0 {
			return nil, false
		}
		highest = max(highest, revision)
		if exposeIDs {
			found["row:"+table+"/"+key] = strconv.FormatInt(revision, 10)
		}
	}
	if !exposeIDs && len(rows) > 0 {
		found["rows:"+table] = strconv.FormatInt(highest, 10)
	}
	return found, true
}

// triggersIntact accepts either trigger variant the enrollment can install.
func (p *appMCPRevisionPin) triggersIntact(ctx context.Context, table string) bool {
	rows, err := p.conn.QueryContext(ctx, "SELECT name,sql FROM main.sqlite_schema WHERE type='trigger' AND substr(name,1,17)='_benmore_mcp_rev_'")
	if err != nil {
		return false
	}
	actual := map[string]string{}
	for rows.Next() {
		var name, text string
		if rows.Scan(&name, &text) != nil {
			_ = rows.Close()
			return false
		}
		actual[name] = text
	}
	if rows.Close() != nil || rows.Err() != nil {
		return false
	}
	for _, variant := range [][]appMCPRevisionTrigger{appMCPRevisionTriggerSQL(table), appMCPRevisionTriggerSQLWithUniqueReconciliation(table)} {
		intact := true
		for _, want := range variant {
			matches, err := appMCPRevisionSQLMatches(actual[want.name], want.sql)
			intact = intact && err == nil && matches
		}
		if intact {
			return true
		}
	}
	return false
}

// appMCPRevisionRowKey maps a decoded JSON id to the ledger's (key_type,row_key).
func appMCPRevisionRowKey(id any) (keyType, key string, ok bool) {
	switch v := id.(type) {
	case string:
		return "text", v, true
	case interface{ String() string }: // json.Number
		if appMCPCanonicalIntegerKey(v.String()) {
			return "integer", v.String(), true
		}
	}
	return "", "", false
}
