package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
)

// query.go - declarative cross-cut READ layer. POST /api/_query takes a
// JSON spec (select / where / group_by / aggregates / order_by / limit)
// and returns rows. Every identifier is validated against the table's
// real columns (no SQL injection surface) and the SAME owner/group/ACL
// scoping as auto-CRUD is applied, so a query can never read rows the
// caller couldn't read via GET /api/<table>. This is the primitive
// behind the QueryView / Report / PivotTable / SavedViews components.
//
// v1 is single-table (the 80% case: filtered views + grouped reports +
// pivots). Cross-table joins are deliberately deferred - they need
// per-joined-table scoping to stay safe, which is its own surface.

// querySpec is the request body.
type querySpec struct {
	Table      string                 `json:"table"`
	Select     []string               `json:"select"`
	Where      map[string]interface{} `json:"where"`
	GroupBy    []string               `json:"group_by"`
	Aggregates []queryAgg             `json:"aggregates"`
	OrderBy    []queryOrder           `json:"order_by"`
	Limit      int                    `json:"limit"`
}
type queryAgg struct {
	Fn  string `json:"fn"`  // count | sum | avg | min | max
	Col string `json:"col"` // empty for count(*)
	As  string `json:"as"`
}
type queryOrder struct {
	Col string `json:"col"`
	Dir string `json:"dir"` // asc | desc
}

var queryAggFns = map[string]bool{"count": true, "sum": true, "avg": true, "min": true, "max": true}
var queryOps = map[string]string{"eq": "=", "ne": "!=", "gt": ">", "gte": ">=", "lt": "<", "lte": "<=", "like": "LIKE"}

func safeAlias(s string) bool {
	if s == "" || len(s) > 40 {
		return false
	}
	for i, c := range s {
		isAlpha := c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		if i == 0 && !isAlpha {
			return false
		}
		if i > 0 && !isAlpha && !(c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

// columnSet returns the set of real column names for a table, or nil if
// the table isn't in the schema.
func columnSet(app *App, table string) map[string]bool {
	for _, t := range app.Tables {
		if t.Name == table {
			cs := make(map[string]bool, len(t.Columns))
			for _, c := range t.Columns {
				cs[c.Name] = true
			}
			return cs
		}
	}
	return nil
}

// queryScopeFilter mirrors the read-scoping in crud_read.go's list handler:
// group-key OR user_id OR ACL grant. Returns "" when the caller is admin
// or the table has no scoping column (callers gate access separately).
func queryScopeFilter(app *App, table string, session *Session) (string, []any) {
	mode := app.Access.ModeFor(table, OpRead, hasColumn(app, table, "user_id"),
		app.Group != nil && app.Group.Key != "" && hasColumn(app, table, app.Group.Key))
	if session.IsAdminBypass() || app.Access.ReadAllowsBroaderRows(mode) {
		return "", nil
	}
	pred, args, _ := rowScopeClause(app, table, session, "view")
	if sc, ok := app.Scopes[table]; ok && sc.PublicReadWhen != "" {
		if pred == "" {
			return "(" + sc.PublicReadWhen + ")", args
		}
		pred = "(" + pred + " OR (" + sc.PublicReadWhen + "))"
	}
	return pred, args
}

// RegisterQueryAPI wires POST /api/_query + the saved-views CRUD.
func RegisterQueryAPI(mux *http.ServeMux, app *App) {
	EnsureSavedViewsTable(app.DB)

	mux.HandleFunc("POST /api/_query", func(w http.ResponseWriter, r *http.Request) {
		var spec querySpec
		if err := json.NewDecoder(r.Body).Decode(&spec); err != nil {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON body"})
			return
		}
		cols := columnSet(app, spec.Table)
		if cols == nil {
			httpJSON(w, http.StatusNotFound, map[string]any{"error": "unknown table: " + spec.Table})
			return
		}
		// Read-access gate (same as auto-CRUD list).
		if !EnforceCRUDAccess(w, r, app, spec.Table, OpRead, 0) {
			return
		}
		session := getSession(app, r)
		if session != nil {
			if err := checkScope(session, spec.Table, "read"); err != nil {
				httpJSON(w, http.StatusForbidden, map[string]any{"error": err.Error()})
				return
			}
		}

		// Owner-based unmasking needs user_id even when the caller projects
		// only encrypted fields. Strip this internal projection after masking.
		hiddenOwner := len(spec.Select) > 0 && len(spec.Aggregates) == 0 && len(spec.GroupBy) == 0 && cols["user_id"] && !slices.Contains(spec.Select, "user_id")
		if hiddenOwner {
			spec.Select = append(spec.Select, "user_id")
		}

		sqlText, args, err := buildQuery(app, &spec, cols, session)
		if err != nil {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		rows, err := QueryRows(app.DB, sqlText, args...)
		if err != nil {
			httpJSON(w, http.StatusInternalServerError, map[string]any{"error": "query failed: " + err.Error()})
			return
		}
		MaskEncryptedFields(app.Encrypted, spec.Table, rows, session)
		for _, row := range rows {
			if hiddenOwner {
				delete(row, "user_id")
			}
			for col := range row {
				if queryHiddenColumn(app, spec.Table, col) {
					delete(row, col)
				}
			}
		}
		if IsReadAudited(app, spec.Table) {
			LogReadAccess(spec.Table, "", "query", session)
		}
		httpJSON(w, http.StatusOK, map[string]any{"rows": rows, "count": len(rows)})
	})

	// Saved views - persisted query specs, scoped per user.
	mux.HandleFunc("GET /api/_query/views", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil {
			httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
			return
		}
		rows, err := QueryRows(app.DB, "SELECT id, name, spec, created_at FROM _benmore_saved_views WHERE user_id = ? ORDER BY created_at DESC", session.UserID)
		if err != nil {
			httpJSON(w, http.StatusInternalServerError, map[string]any{"error": "query failed"})
			return
		}
		httpJSON(w, http.StatusOK, map[string]any{"views": rows})
	})
	mux.HandleFunc("POST /api/_query/views", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil {
			httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
			return
		}
		if !validateCSRF(r) {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid CSRF token"})
			return
		}
		var body struct {
			Name string          `json:"name"`
			Spec json.RawMessage `json:"spec"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "name and spec required"})
			return
		}
		res, err := app.DB.Exec("INSERT INTO _benmore_saved_views (user_id, name, spec) VALUES (?, ?, ?)", session.UserID, body.Name, string(body.Spec))
		if err != nil {
			httpJSON(w, http.StatusInternalServerError, map[string]any{"error": "save failed"})
			return
		}
		id, _ := res.LastInsertId()
		httpJSON(w, http.StatusOK, map[string]any{"id": id, "name": body.Name})
	})
	mux.HandleFunc("DELETE /api/_query/views/{id}", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil {
			httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
			return
		}
		if !validateCSRF(r) {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid CSRF token"})
			return
		}
		app.DB.Exec("DELETE FROM _benmore_saved_views WHERE id = ? AND user_id = ?", r.PathValue("id"), session.UserID)
		httpJSON(w, http.StatusOK, map[string]any{"status": "deleted"})
	})
}

// buildQuery turns a validated spec into parameterized SQL.
func buildQuery(app *App, spec *querySpec, cols map[string]bool, session *Session) (string, []any, error) {
	t := spec.Table
	// Filtering, sorting and aggregation can disclose protected values even
	// when the final projection is masked. Reject those uses before SQL runs.
	if err := validateQueryFieldAccess(app, spec, session); err != nil {
		return "", nil, err
	}
	var selectParts []string
	grouped := len(spec.GroupBy) > 0 || len(spec.Aggregates) > 0

	for _, g := range spec.GroupBy {
		if !cols[g] {
			return "", nil, fmt.Errorf("unknown group_by column: %s", g)
		}
		selectParts = append(selectParts, fmt.Sprintf("%s.%s", t, g))
	}
	for _, a := range spec.Aggregates {
		if !queryAggFns[a.Fn] {
			return "", nil, fmt.Errorf("unknown aggregate fn: %s", a.Fn)
		}
		alias := a.As
		if alias == "" {
			alias = a.Fn + "_" + a.Col
			if a.Col == "" {
				alias = "count"
			}
		}
		if !safeAlias(alias) {
			return "", nil, fmt.Errorf("invalid aggregate alias: %s", alias)
		}
		var expr string
		if a.Fn == "count" && a.Col == "" {
			expr = "COUNT(*)"
		} else {
			if !cols[a.Col] {
				return "", nil, fmt.Errorf("unknown aggregate column: %s", a.Col)
			}
			expr = fmt.Sprintf("%s(%s.%s)", strings.ToUpper(a.Fn), t, a.Col)
		}
		selectParts = append(selectParts, fmt.Sprintf("%s AS %s", expr, alias))
	}
	if !grouped {
		if len(spec.Select) > 0 {
			for _, c := range spec.Select {
				if !cols[c] {
					return "", nil, fmt.Errorf("unknown column: %s", c)
				}
				selectParts = append(selectParts, fmt.Sprintf("%s.%s", t, c))
			}
		} else {
			selectParts = append(selectParts, t+".*")
		}
	}

	sqlText := fmt.Sprintf("SELECT %s FROM %s", strings.Join(selectParts, ", "), t)

	// WHERE: scope + soft-delete + caller filters.
	var conds []string
	var args []any
	if scope, sa := queryScopeFilter(app, t, session); scope != "" {
		conds = append(conds, scope)
		args = append(args, sa...)
	}
	if cols["deleted_at"] {
		conds = append(conds, fmt.Sprintf("%s.deleted_at IS NULL", t))
	}
	for col, raw := range spec.Where {
		if !cols[col] {
			return "", nil, fmt.Errorf("unknown where column: %s", col)
		}
		// raw is either a scalar (eq) or {op: value}.
		if opMap, ok := raw.(map[string]interface{}); ok {
			for op, val := range opMap {
				if op == "in" {
					list, ok := val.([]interface{})
					if !ok || len(list) == 0 {
						return "", nil, fmt.Errorf("'in' on %s needs a non-empty array", col)
					}
					ph := strings.TrimSuffix(strings.Repeat("?,", len(list)), ",")
					conds = append(conds, fmt.Sprintf("%s.%s IN (%s)", t, col, ph))
					args = append(args, list...)
					continue
				}
				sqlOp, ok := queryOps[op]
				if !ok {
					return "", nil, fmt.Errorf("unknown operator: %s", op)
				}
				if op == "like" {
					conds = append(conds, fmt.Sprintf("%s.%s LIKE ?", t, col))
					args = append(args, fmt.Sprintf("%%%v%%", val))
				} else {
					conds = append(conds, fmt.Sprintf("%s.%s %s ?", t, col, sqlOp))
					args = append(args, val)
				}
			}
		} else {
			conds = append(conds, fmt.Sprintf("%s.%s = ?", t, col))
			args = append(args, raw)
		}
	}
	if len(conds) > 0 {
		sqlText += " WHERE " + strings.Join(conds, " AND ")
	}

	if len(spec.GroupBy) > 0 {
		var gb []string
		for _, g := range spec.GroupBy {
			gb = append(gb, fmt.Sprintf("%s.%s", t, g))
		}
		sqlText += " GROUP BY " + strings.Join(gb, ", ")
	}

	// ORDER BY - column must be a real column or a declared aggregate alias.
	aliases := map[string]bool{}
	for _, a := range spec.Aggregates {
		al := a.As
		if al == "" {
			al = a.Fn + "_" + a.Col
			if a.Col == "" {
				al = "count"
			}
		}
		aliases[al] = true
	}
	if len(spec.OrderBy) > 0 {
		var obs []string
		for _, o := range spec.OrderBy {
			if !cols[o.Col] && !aliases[o.Col] {
				return "", nil, fmt.Errorf("unknown order_by column: %s", o.Col)
			}
			dir := "ASC"
			if strings.ToLower(o.Dir) == "desc" {
				dir = "DESC"
			}
			ref := o.Col
			if cols[o.Col] {
				ref = t + "." + o.Col
			}
			obs = append(obs, ref+" "+dir)
		}
		sqlText += " ORDER BY " + strings.Join(obs, ", ")
	}

	limit := spec.Limit
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	sqlText += fmt.Sprintf(" LIMIT %d", limit)
	return sqlText, args, nil
}

func queryHiddenColumn(app *App, table, column string) bool {
	if strings.HasSuffix(column, blindColSuffix) {
		return true
	}
	// Explicit encryption config defines the visibility of an encrypted
	// column, including intentionally named fields such as secret_note.
	if app.Encrypted != nil {
		for _, def := range app.Encrypted.Fields[table] {
			if def.Column == column {
				return false
			}
		}
	}
	return isSensitiveUserColumn(column)
}

func validateQueryFieldAccess(app *App, spec *querySpec, session *Session) error {
	protected := func(column string) bool {
		if queryHiddenColumn(app, spec.Table, column) {
			return true
		}
		if app.Encrypted == nil {
			return false
		}
		for _, def := range app.Encrypted.Fields[spec.Table] {
			if def.Column != column || len(def.Roles) == 0 || session.IsAdmin() {
				continue
			}
			if session != nil {
				for _, role := range def.Roles {
					if role == "self" || role == "owner" {
						continue
					}
					if session.Role == role {
						return false
					}
					for _, held := range session.Roles {
						if held == role {
							return false
						}
					}
				}
			}
			return true
		}
		return false
	}
	for _, col := range spec.Select {
		if queryHiddenColumn(app, spec.Table, col) {
			return fmt.Errorf("column %s is not available", col)
		}
	}
	var uses []string
	uses = append(uses, spec.GroupBy...)
	for col := range spec.Where {
		uses = append(uses, col)
	}
	for _, order := range spec.OrderBy {
		uses = append(uses, order.Col)
	}
	for _, agg := range spec.Aggregates {
		if agg.Col != "" {
			uses = append(uses, agg.Col)
		}
	}
	for _, col := range uses {
		if protected(col) {
			return fmt.Errorf("column %s cannot be filtered, ordered or aggregated with your permissions", col)
		}
	}
	return nil
}

// EnsureSavedViewsTable creates the saved-views table.
func EnsureSavedViewsTable(db *sql.DB) {
	db.Exec(`CREATE TABLE IF NOT EXISTS _benmore_saved_views (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		name TEXT NOT NULL,
		spec TEXT NOT NULL DEFAULT '{}',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
}
