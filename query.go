package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
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
	Table      string                 `json:"table" yaml:"table"`
	Select     []string               `json:"select" yaml:"select"`
	Where      map[string]interface{} `json:"where" yaml:"where"`
	GroupBy    []string               `json:"group_by" yaml:"group_by"`
	Aggregates []queryAgg             `json:"aggregates" yaml:"aggregates"`
	OrderBy    []queryOrder           `json:"order_by" yaml:"order_by"`
	Limit      int                    `json:"limit" yaml:"limit"`
}
type queryAgg struct {
	Fn  string `json:"fn" yaml:"fn"`   // count | sum | avg | min | max
	Col string `json:"col" yaml:"col"` // empty for count(*)
	As  string `json:"as" yaml:"as"`
	// Field is not part of the spec. It is read only so that an aggregate
	// whose column was written under `field:` is refused with an error
	// naming `col`, instead of "unknown aggregate column: " with no name.
	Field string `json:"field,omitempty" yaml:"field,omitempty"`
}

// queryAggKeys are the keys an aggregate reads, as the refusal lists them.
var queryAggKeys = []string{"fn", "col", "as"}

// errQueryAggUnknownKeys names the keys of one aggregate that nothing reads.
// hint, when set, is the corrected aggregate for a column written under
// `field:` (the most common slip), so the refusal still shows the fix.
type errQueryAggUnknownKeys struct {
	keys []string
	hint string
}

func (e *errQueryAggUnknownKeys) Error() string {
	quoted := make([]string, len(e.keys))
	for i, k := range e.keys {
		quoted[i] = strconv.Quote(k)
	}
	noun := "key"
	if len(quoted) > 1 {
		noun = "keys"
	}
	return "unknown aggregate " + noun + " " + strings.Join(quoted, ", ") + ": accepted keys are " + strings.Join(queryAggKeys, ", ") + e.hint
}

// UnmarshalJSON refuses a key the aggregate does not read. Dropping it was
// worse than an error: `{fn:'count', field:'x'}` ran as COUNT(*) and answered
// a number that looked right. Keys match case-insensitively, as encoding/json
// matches the fields themselves.
func (a *queryAgg) UnmarshalJSON(data []byte) error {
	type plainQueryAgg queryAgg
	var plain plainQueryAgg
	if err := json.Unmarshal(data, &plain); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	var unknown []string
	for key := range fields {
		if !slices.ContainsFunc(queryAggKeys, func(known string) bool { return strings.EqualFold(known, key) }) {
			unknown = append(unknown, key)
		}
	}
	if len(unknown) > 0 {
		slices.Sort(unknown)
		refusal := &errQueryAggUnknownKeys{keys: unknown}
		if plain.Field != "" && plain.Col == "" {
			refusal.hint = fmt.Sprintf("; aggregates take \"col\": {fn:'%s', col:'%s'}", plain.Fn, plain.Field)
		}
		return refusal
	}
	*a = queryAgg(plain)
	return nil
}

type queryOrder struct {
	Col string `json:"col" yaml:"col"`
	Dir string `json:"dir" yaml:"dir"` // asc | desc
}

var queryAggFns = map[string]bool{"count": true, "sum": true, "avg": true, "min": true, "max": true}
var queryOps = map[string]string{"eq": "=", "ne": "!=", "gt": ">", "gte": ">=", "lt": "<", "lte": "<=", "like": "LIKE"}

// queryTextMatchOps are the where operators that match their value as
// literal text, each with the LIKE pattern it builds around the escaped
// value. `like` keeps its older meaning (the value is wrapped in %...% and
// any % or _ in it is still a wildcard), because apps rely on it; these
// operators are how a caller asks for a prefix, a suffix or a literal
// substring. Like `like`, they compare ASCII letters case-insensitively.
var queryTextMatchOps = map[string]func(escaped string) string{
	"contains":    func(s string) string { return "%" + s + "%" },
	"starts_with": func(s string) string { return s + "%" },
	"ends_with":   func(s string) string { return "%" + s },
}

// queryLikeEscaper escapes a value for `LIKE ? ESCAPE '\'` so that it
// matches only itself: the escape character and both wildcards.
var queryLikeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

func queryAggregateAlias(a queryAgg) string {
	if a.As != "" {
		return a.As
	}
	if a.Col == "" {
		return "count"
	}
	return a.Fn + "_" + a.Col
}

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
func RegisterQueryAPI(mux appRouteRegistrar, app *App) {
	EnsureSavedViewsTable(app.DB)
	registerQueryAPI(mux, app)
}

// executeAuthorizedQuery is the complete native single-table read path. All
// callers supply the original request so access, connector and token scopes
// use the real actor. Failures are written to w; success returns sanitized rows.
// ownerOnly adds a report-page restriction; it can never broaden native scope.
func executeAuthorizedQuery(w http.ResponseWriter, r *http.Request, app *App, spec querySpec, ownerOnly bool) ([]map[string]any, bool) {
	return executeAuthorizedQueryWithPolicy(w, r, app, spec, queryReadPolicy{ownerOnly: ownerOnly})
}

// Private report restrictions are never decoded from the public query request.
// They only narrow the native read policy and its bounded result contract.
type queryReadPolicy struct {
	ownerOnly      bool
	currentTenant  bool
	rejectOverflow bool
}

func executeAuthorizedQueryWithPolicy(w http.ResponseWriter, r *http.Request, app *App, spec querySpec, policy queryReadPolicy) ([]map[string]any, bool) {
	// Internal masking projections must not mutate a reusable authored spec.
	spec.Select = slices.Clone(spec.Select)
	cols := columnSet(app, spec.Table)
	if cols == nil {
		// Exactly the answer EnforceCRUDAccess gives a table the caller may
		// not read (security.md 14f); "unknown table: x" told the two apart.
		writeUnmatchedAPINotFound(w)
		return nil, false
	}
	// Read-access gate (same as auto-CRUD list).
	if !EnforceCRUDAccess(w, r, app, spec.Table, OpRead, 0) {
		return nil, false
	}
	session := getSession(app, r)
	if session != nil {
		if err := checkScope(session, spec.Table, "read"); err != nil {
			httpJSON(w, http.StatusForbidden, scopeDeniedBody(err))
			return nil, false
		}
	}
	if (policy.ownerOnly || policy.currentTenant) && session == nil {
		httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return nil, false
	}
	if policy.currentTenant {
		if err := reportTenantColumn(app, cols); err != nil {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return nil, false
		}
		if !session.EffectiveHasGroup() {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "report source requires a current tenant"})
			return nil, false
		}
	}

	// Owner-based unmasking needs user_id even when the caller projects
	// only encrypted fields. Strip this internal projection after masking.
	hiddenOwner := len(spec.Select) > 0 && len(spec.Aggregates) == 0 && len(spec.GroupBy) == 0 && cols["user_id"] && !slices.Contains(spec.Select, "user_id")
	if hiddenOwner {
		spec.Select = append(spec.Select, "user_id")
	}
	// Standard projections can carry the source tenant internally. This
	// preserves same-tenant unmask without adding fields to the response.
	tenantCol := encryptedTenantColumn(app, spec.Table)
	hiddenTenant := len(spec.Select) > 0 && len(spec.Aggregates) == 0 && len(spec.GroupBy) == 0 && tenantCol != "" && cols[tenantCol] && !slices.Contains(spec.Select, tenantCol)
	if hiddenTenant {
		spec.Select = append(spec.Select, tenantCol)
	}

	sqlText, args, err := buildQueryWithPolicy(app, &spec, cols, session, policy)
	if err != nil {
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return nil, false
	}
	sourceTable := spec.Table
	if len(spec.Aggregates) > 0 || len(spec.GroupBy) > 0 {
		sourceTable = "" // Aggregate aliases are not source columns.
	}
	rows, err := queryNativeRowsWith(app.DB, app, sourceTable, sqlText, args...)
	if err != nil {
		serverErrorJSON(w, r, app, "_query", err, "query failed")
		return nil, false
	}
	// Grouped outputs have already passed source-field authorization.
	// Their aliases are derived values, not columns of the source table.
	// Applying source masks by alias would hide or drop valid counts.
	grouped := len(spec.GroupBy) > 0 || len(spec.Aggregates) > 0
	if !grouped {
		MaskEncryptedFields(app, spec.Table, rows, session)
	}
	for _, row := range rows {
		if hiddenOwner {
			delete(row, "user_id")
		}
		if hiddenTenant {
			delete(row, tenantCol)
		}
		for col := range row {
			if !grouped && apiHiddenColumn(app, spec.Table, col) {
				delete(row, col)
			}
		}
	}
	if IsReadAudited(app, spec.Table) {
		if err := LogReadAccess(app, r, spec.Table, "", "query", session); err != nil {
			readAuditRefused(w, r, app, spec.Table, err)
			return nil, false
		}
	}
	if policy.rejectOverflow && len(rows) > queryResultLimit(spec.Limit) {
		httpJSON(w, http.StatusUnprocessableEntity, withRefusalDocs(map[string]any{"error": "report_source_limit_exceeded"}, "report_source_limit_exceeded"))
		return nil, false
	}
	return rows, true
}

func reportTenantColumn(app *App, cols map[string]bool) error {
	if app.Group == nil || !safeIdent(app.Group.Key) || !cols[app.Group.Key] {
		return fmt.Errorf("report source tenant_scope: current requires a configured physical group column on its table")
	}
	return nil
}

func registerQueryAPI(mux appRouteRegistrar, app *App) {
	mux.HandleFunc("POST /api/_query", func(w http.ResponseWriter, r *http.Request) {
		var spec querySpec
		if err := json.NewDecoder(r.Body).Decode(&spec); err != nil {
			var unknownKeys *errQueryAggUnknownKeys
			if errors.As(err, &unknownKeys) {
				httpJSON(w, http.StatusBadRequest, map[string]any{"error": unknownKeys.Error()})
				return
			}
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON body"})
			return
		}
		rows, ok := executeAuthorizedQuery(w, r, app, spec, false)
		if !ok {
			return
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
		rows, err := queryMetadataRows(app.DB, "SELECT id, name, spec, created_at FROM _benmore_saved_views WHERE user_id = ? ORDER BY created_at DESC", session.UserID)
		if err != nil {
			serverErrorJSON(w, r, app, "_query saved views", err, "query failed")
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
		// CSRF check (skip for Bearer-only requests; a session cookie keeps it).
		if !isBearerAuth(r) && !validateCSRF(r) {
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
			serverErrorJSON(w, r, app, "_query saved views", err, "save failed")
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
		// CSRF check (skip for Bearer-only requests; a session cookie keeps it).
		if !isBearerAuth(r) && !validateCSRF(r) {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid CSRF token"})
			return
		}
		app.DB.Exec("DELETE FROM _benmore_saved_views WHERE id = ? AND user_id = ?", r.PathValue("id"), session.UserID)
		httpJSON(w, http.StatusOK, map[string]any{"status": "deleted"})
	})
}

// buildQuery turns a validated spec into parameterized SQL.
func buildQuery(app *App, spec *querySpec, cols map[string]bool, session *Session) (string, []any, error) {
	return buildQueryWithOwner(app, spec, cols, session, false)
}

func buildQueryWithOwner(app *App, spec *querySpec, cols map[string]bool, session *Session, ownerOnly bool) (string, []any, error) {
	return buildQueryWithPolicy(app, spec, cols, session, queryReadPolicy{ownerOnly: ownerOnly})
}

func buildQueryWithPolicy(app *App, spec *querySpec, cols map[string]bool, session *Session, policy queryReadPolicy) (string, []any, error) {
	t := spec.Table
	if policy.ownerOnly && (session == nil || !cols["user_id"]) {
		return "", nil, fmt.Errorf("scope: owner report sources require a signed-in user and a user_id column")
	}
	if policy.currentTenant {
		if err := reportTenantColumn(app, cols); err != nil {
			return "", nil, err
		}
		if session == nil || !session.EffectiveHasGroup() {
			return "", nil, fmt.Errorf("report source requires a current tenant")
		}
	}
	// Filtering, sorting and aggregation can disclose protected values even
	// when the final projection is masked. Reject those uses before SQL runs.
	fieldScope, fieldArgs, err := queryFieldAccessScope(app, spec, session)
	if err != nil {
		return "", nil, err
	}
	var selectParts []string
	grouped := len(spec.GroupBy) > 0 || len(spec.Aggregates) > 0
	// Every column below is checked against the table's columns (cols) and
	// written qualified and quoted: a column is named by whoever created it.
	qt := quoteIdent(t)
	qcol := func(c string) string { return quoteColumn(t, c) }
	// SQL sees ciphertext, even when this caller may decrypt the response.
	// Value operations would return plausible but incorrect results (for
	// example SUM(ciphertext) = 0). Counting cells and testing NULL remain
	// meaningful and keep the field authorization applied above.
	rejectEncryptedValue := func(col string) error {
		if encryptedDefFor(app, t, col) != nil {
			return fmt.Errorf("encrypted column %s does not support query value operations; use a non-sensitive derived column or native CRUD blind-index equality filters", col)
		}
		return nil
	}
	aliases := map[string]bool{}
	outputs := map[string]bool{}

	for _, g := range spec.GroupBy {
		if !cols[g] {
			return "", nil, fmt.Errorf("unknown group_by column: %s", g)
		}
		if err := rejectEncryptedValue(g); err != nil {
			return "", nil, err
		}
		selectParts = append(selectParts, qcol(g))
		outputs[sqliteIdentifierFold(g)] = true
	}
	for _, a := range spec.Aggregates {
		if !queryAggFns[a.Fn] {
			return "", nil, fmt.Errorf("unknown aggregate fn: %s", a.Fn)
		}
		alias := queryAggregateAlias(a)
		if !safeAlias(alias) {
			return "", nil, fmt.Errorf("invalid aggregate alias: %s", alias)
		}
		// Rows become JSON objects keyed by output name. A collision would
		// discard a group key or another aggregate, and case-only aliases
		// are ambiguous to SQLite's ORDER BY resolution as well.
		if outputs[sqliteIdentifierFold(alias)] {
			return "", nil, fmt.Errorf("duplicate query output column: %s", alias)
		}
		outputs[sqliteIdentifierFold(alias)] = true
		aliases[alias] = true
		var expr string
		if a.Fn == "count" && a.Col == "" {
			expr = "COUNT(*)"
		} else {
			if a.Col == "" {
				if a.Field != "" {
					return "", nil, fmt.Errorf("aggregate %s names its column with \"field\"; aggregates take \"col\": {fn:'%s', col:'%s'}", a.Fn, a.Fn, a.Field)
				}
				return "", nil, fmt.Errorf("aggregate %s needs \"col\", the column it reads (only count may omit it, for COUNT(*))", a.Fn)
			}
			if !cols[a.Col] {
				return "", nil, fmt.Errorf("unknown aggregate column: %s", a.Col)
			}
			if a.Fn != "count" {
				if err := rejectEncryptedValue(a.Col); err != nil {
					return "", nil, err
				}
			}
			expr = fmt.Sprintf("%s(%s)", strings.ToUpper(a.Fn), qcol(a.Col))
		}
		selectParts = append(selectParts, fmt.Sprintf("%s AS %s", expr, quoteIdent(alias)))
	}
	if !grouped {
		if len(spec.Select) > 0 {
			for _, c := range spec.Select {
				if !cols[c] {
					return "", nil, fmt.Errorf("unknown column: %s", c)
				}
				selectParts = append(selectParts, qcol(c))
			}
		} else {
			selectParts = append(selectParts, qt+".*")
		}
	}

	sqlText := fmt.Sprintf("SELECT %s FROM %s", strings.Join(selectParts, ", "), qt)

	// WHERE: scope + field authorization + soft-delete + caller filters.
	var conds []string
	var args []any
	if policy.ownerOnly {
		conds = append(conds, qcol("user_id")+" = ?")
		args = append(args, session.UserID)
	}
	if policy.currentTenant {
		// This report constraint is independent of native admin bypass and
		// never replaces an authored filter, owner restriction or ACL scope.
		conds = append(conds, qcol(app.Group.Key)+" = ?")
		args = append(args, session.EffectiveGroupID())
	}
	if fieldScope != "" {
		conds = append(conds, fieldScope)
		args = append(args, fieldArgs...)
	}
	if scope, sa := queryScopeFilter(app, t, session); scope != "" {
		conds = append(conds, scope)
		args = append(args, sa...)
	}
	if cols["deleted_at"] {
		conds = append(conds, qt+".deleted_at IS NULL")
	}
	// Boolean columns store 1/0; "true"/"false" text matched nothing.
	boolCols := queryBooleanFilterColumns(app, t)
	boolValue := func(col string, v any) (any, error) {
		if kind := boolCols[col]; kind != 0 {
			return booleanQueryValue(kind, col, v)
		}
		return v, nil
	}
	// DateTime columns: a value that parses as an instant is compared as one
	// (crud_datetime_filter.go), whatever spelling each row was stored in.
	instantCols := queryInstantFilterColumns(app, t)
	for col, raw := range spec.Where {
		if !cols[col] {
			return "", nil, fmt.Errorf("unknown where column: %s", col)
		}
		// raw is either a scalar (eq) or {op: value}.
		if opMap, ok := raw.(map[string]interface{}); ok {
			for op, val := range opMap {
				if val != nil || (op != "eq" && op != "ne") {
					if err := rejectEncryptedValue(col); err != nil {
						return "", nil, err
					}
				}
				if op == "in" {
					list, ok := val.([]interface{})
					if !ok || len(list) == 0 {
						return "", nil, fmt.Errorf("'in' on %s needs a non-empty array", col)
					}
					if instantCols[col] {
						if cond, instantArgs, ok := instantQueryIn(qcol(col), list); ok {
							conds = append(conds, cond)
							args = append(args, instantArgs...)
							continue
						}
					}
					ph := strings.TrimSuffix(strings.Repeat("?,", len(list)), ",")
					conds = append(conds, fmt.Sprintf("%s IN (%s)", qcol(col), ph))
					for _, item := range list {
						v, err := boolValue(col, item)
						if err != nil {
							return "", nil, err
						}
						args = append(args, v)
					}
					continue
				}
				if pattern, ok := queryTextMatchOps[op]; ok {
					text, isText := val.(string)
					if !isText {
						return "", nil, fmt.Errorf("'%s' on %s needs a string", op, col)
					}
					conds = append(conds, qcol(col)+` LIKE ? ESCAPE '\'`)
					args = append(args, pattern(queryLikeEscaper.Replace(text)))
					continue
				}
				sqlOp, ok := queryOps[op]
				if !ok {
					return "", nil, fmt.Errorf("unknown operator: %s", op)
				}
				if val == nil && (op == "eq" || op == "ne") {
					nullOp := " IS NULL"
					if op == "ne" {
						nullOp = " IS NOT NULL"
					}
					conds = append(conds, qcol(col)+nullOp)
					continue
				}
				if op == "like" {
					// A substring match with the value's own % and _ left as
					// wildcards (see queryTextMatchOps for literal matches).
					conds = append(conds, qcol(col)+" LIKE ?")
					args = append(args, fmt.Sprintf("%%%v%%", val))
				} else if cond, instantArgs, ok := queryInstantComparison(instantCols, col, qcol(col), sqlOp, val); ok {
					conds = append(conds, cond)
					args = append(args, instantArgs...)
				} else {
					v, err := boolValue(col, val)
					if err != nil {
						return "", nil, err
					}
					conds = append(conds, fmt.Sprintf("%s %s ?", qcol(col), sqlOp))
					args = append(args, v)
				}
			}
		} else if raw == nil {
			conds = append(conds, qcol(col)+" IS NULL")
		} else {
			if err := rejectEncryptedValue(col); err != nil {
				return "", nil, err
			}
			if cond, instantArgs, ok := queryInstantComparison(instantCols, col, qcol(col), "=", raw); ok {
				conds = append(conds, cond)
				args = append(args, instantArgs...)
				continue
			}
			v, err := boolValue(col, raw)
			if err != nil {
				return "", nil, err
			}
			conds = append(conds, qcol(col)+" = ?")
			args = append(args, v)
		}
	}
	if len(conds) > 0 {
		sqlText += " WHERE " + strings.Join(conds, " AND ")
	}

	if len(spec.GroupBy) > 0 {
		var gb []string
		for _, g := range spec.GroupBy {
			gb = append(gb, qcol(g))
		}
		sqlText += " GROUP BY " + strings.Join(gb, ", ")
	}

	// ORDER BY - column must be a real column or a declared aggregate alias.
	if len(spec.OrderBy) > 0 {
		var obs []string
		for _, o := range spec.OrderBy {
			if !cols[o.Col] && !aliases[o.Col] {
				return "", nil, fmt.Errorf("unknown order_by column: %s", o.Col)
			}
			if !aliases[o.Col] {
				if err := rejectEncryptedValue(o.Col); err != nil {
					return "", nil, err
				}
			}
			dir := "ASC"
			if strings.ToLower(o.Dir) == "desc" {
				dir = "DESC"
			}
			ref := qcol(o.Col)
			if aliases[o.Col] {
				// A selected aggregate takes precedence over a physical column
				// with the same name: sum(amount) AS amount sorts by the sum.
				ref = quoteIdent(o.Col)
			} else if querySortsByInstant(app, t, o.Col, instantCols) {
				// A DateTime column a client can write sorts by instant, not
				// by stored spelling; created_at and updated_at keep the
				// plain sort.
				obs = append(obs, instantOrderBy(ref, dir))
				continue
			}
			obs = append(obs, ref+" "+dir)
		}
		sqlText += " ORDER BY " + strings.Join(obs, ", ")
	}

	limit := queryResultLimit(spec.Limit)
	if policy.rejectOverflow {
		limit++
	}
	sqlText += fmt.Sprintf(" LIMIT %d", limit)
	return sqlText, args, nil
}

// queryResultLimit is the row cap for /api/_query and report sources: 200 when
// unset, otherwise the requested limit capped at 1000. An oversized limit is
// clamped, not reset to the default, so asking for more never returns fewer
// rows. overflow: error sources never reach the clamp: authoring validation
// refuses their limits outside 1..1000.
func queryResultLimit(limit int) int {
	if limit <= 0 {
		return 200
	}
	if limit > 1000 {
		return 1000
	}
	return limit
}

func validateQueryFieldAccess(app *App, spec *querySpec, session *Session) error {
	_, _, err := queryFieldAccessScope(app, spec, session)
	return err
}

// SQL operations on encrypted columns must use the same row authorization as
// response masking. Tenant holders keep these operations inside their tenant;
// owner-only operations retain their existing refusal instead of broadening
// aggregation access. Selecting a field alone is still allowed and masked.
func queryFieldAccessScope(app *App, spec *querySpec, session *Session) (string, []any, error) {
	for _, col := range spec.Select {
		if apiHiddenColumn(app, spec.Table, col) {
			return "", nil, fmt.Errorf("column %s is not available", col)
		}
	}
	var uses []string
	uses = append(uses, spec.GroupBy...)
	for col := range spec.Where {
		uses = append(uses, col)
	}
	aggregateAliases := map[string]bool{}
	for _, agg := range spec.Aggregates {
		aggregateAliases[queryAggregateAlias(agg)] = true
	}
	for _, order := range spec.OrderBy {
		if !aggregateAliases[order.Col] {
			uses = append(uses, order.Col)
		}
	}
	for _, agg := range spec.Aggregates {
		if agg.Col != "" {
			uses = append(uses, agg.Col)
		}
	}
	var scopes []string
	var args []any
	seen := map[string]bool{}
	for _, col := range uses {
		if seen[col] {
			continue
		}
		seen[col] = true
		if apiHiddenColumn(app, spec.Table, col) {
			return "", nil, fmt.Errorf("column %s cannot be filtered, ordered or aggregated with your permissions", col)
		}
		def := encryptedDefFor(app, spec.Table, col)
		if def == nil {
			continue
		}
		access := encryptedFieldAccessFor(app, app.DB, spec.Table, *def, session)
		if access.allRows {
			continue
		}
		if access.tenantColumn == "" {
			return "", nil, fmt.Errorf("column %s cannot be filtered, ordered or aggregated with your permissions", col)
		}
		scope, sa := access.scopePredicate(spec.Table)
		scopes = append(scopes, scope)
		args = append(args, sa...)
	}
	return strings.Join(scopes, " AND "), args, nil
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
