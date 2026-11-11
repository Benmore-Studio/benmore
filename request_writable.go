//go:build !cli

package main

import "strings"

// Which columns a generic CRUD request may set.
//
// POST /api/<table> and PATCH /api/<table>/<id> drop, replace or refuse the
// columns the framework fills in or derives. The schema descriptor
// (GET /api/_schema, which the schema-driven components build forms from)
// and the OpenAPI Create<Model>/Update<Model> request schemas describe those
// requests, and used to keep their own short list of names (id, user_id,
// timestamps, role, password_hash). They listed computed columns, the tenant
// key and a workflow's state column as writable, so a form offered an input
// whose value was thrown away.
//
// requestWritable answers from the sets the write paths themselves use
// (protectedCreateFields, protectedUpdateFields, workflowProtectedFields,
// commandOwnedColumns), so a column added to one of them stops being
// described as writable without a second edit here. It describes; it is not
// a gate, and no write path calls it.

// requestWriteMode is the generic request a column is judged for.
type requestWriteMode int

const (
	requestCreate requestWriteMode = iota // POST /api/<table>
	requestUpdate                         // PATCH /api/<table>/<id>
)

// requestWritable is the answer for one table and one caller.
type requestWritable struct {
	createDrops protectedFields   // protectedCreateFields: never taken from a create
	updateDrops protectedFields   // protectedUpdateFields: never taken from an update
	state       protectedFields   // workflow state columns: only a transition moves them
	owned       map[string]string // command-owned columns: generic CRUD answers 403
	tenantKey   string
	// tenantKeyOnCreate: a create stores the tenant key it is sent. True only
	// for a platform admin who has not stepped into a tenant (handleCreate);
	// everyone else's row takes the session's tenant.
	tenantKeyOnCreate bool
}

// requestWritableFor describes what session's own requests may set on table.
func requestWritableFor(app *App, table string, session *Session) requestWritable {
	w := requestWritableAnyCaller(app, table)
	w.tenantKeyOnCreate = session.IsAdminBypass()
	return w
}

// requestWritableAnyCaller describes table for a document that is not about
// one caller (the OpenAPI request schemas): a column counts when some
// caller's request may set it, so the tenant key counts on create.
func requestWritableAnyCaller(app *App, table string) requestWritable {
	w := requestWritable{
		createDrops:       protectedCreateFields(app, table),
		updateDrops:       protectedFields(protectedUpdateFields(app, table)),
		state:             newProtectedFields(workflowProtectedFields(app, table)...),
		owned:             commandOwnedColumns(app, table),
		tenantKeyOnCreate: true,
	}
	if app.Group != nil {
		w.tenantKey = app.Group.Key
	}
	return w
}

// column reports whether a request of the given mode may set col.
func (w requestWritable) column(col Column, mode requestWriteMode) bool {
	if col.PK {
		return false
	}
	if _, owned := w.owned[sqliteIdentifierFold(col.Name)]; owned {
		return false
	}
	if mode == requestUpdate {
		return !w.updateDrops.has(col.Name)
	}
	switch {
	case identIs(col.Name, "deleted_at"):
		// The one place this is narrower than the create path, which stores a
		// deleted_at it is sent: the column belongs to delete and restore,
		// and no form or generated client should offer it.
		return false
	case identIs(col.Name, w.tenantKey):
		return w.tenantKeyOnCreate
	}
	return !w.createDrops.has(col.Name) && !w.state.has(col.Name)
}

// tenantKeyColumn reports whether col is the table's tenant key: a create
// may carry it, but only a platform admin's value is kept.
func (w requestWritable) tenantKeyColumn(col Column) bool {
	return identIs(col.Name, w.tenantKey)
}

// customFieldTableColumns returns the columns of table that were added at
// run time through POST /api/_schema/<table>/fields (customFieldColumns reads
// the tracking table). They exist in the database only (app.Tables is the
// schema source), are written by create and PATCH like any other column, and
// so belong in the request schemas. Without a database, or with no custom
// fields, it returns nil.
func customFieldTableColumns(app *App, table Table) []Column {
	if app == nil || app.DB == nil {
		return nil
	}
	tracked, err := customFieldColumns(app.DB)
	if err != nil {
		return nil
	}
	return customFieldTableColumnsFrom(app, table, tracked)
}

// customFieldTableColumnsFrom is customFieldTableColumns over a
// customFieldColumns map the caller read once (the OpenAPI document reads it
// once for every table instead of twice per table).
func customFieldTableColumnsFrom(app *App, table Table, tracked map[string]map[string]bool) []Column {
	if app == nil || app.DB == nil {
		return nil
	}
	custom := tracked[strings.ToLower(table.Name)]
	if len(custom) == 0 {
		return nil
	}
	live, err := GetTableColumns(app.DB, table.Name)
	if err != nil {
		return nil
	}
	var cols []Column
	for _, col := range live {
		// A name the schema declares since is the schema's column.
		if custom[strings.ToLower(col.Name)] && !tableHasColumn(table, col.Name) {
			cols = append(cols, col)
		}
	}
	return cols
}
