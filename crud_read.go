//go:build !cli

package main

// Record listing, single-record reads, and SQL result shaping.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"
)

// coerceSQLValue normalises the values database/sql returns so the
// JSON-encoded response matches what a fresh GET /api/<table>/{id}
// would yield. SQLite returns []byte for TEXT in some drivers and
// time.Time for DATETIME in others - both serialize ugly without
// this nudge.
//
// v2.7.60+: a zero time.Time (the Go zero value, which the driver
// can emit when it scans a NULL DATETIME column into time.Time
// destination types) maps to nil → JSON null. Pre-v2.7.60 we
// formatted the zero value verbatim and shipped
// "0001-01-01T00:00:00Z" to API callers - a clear-as-day bug for
// any nullable DateTime column. Non-zero times still format to
// RFC3339Nano in UTC, preserving optimistic-concurrency version precision.
func coerceSQLValue(v any) any {
	switch t := v.(type) {
	case []byte:
		return string(t)
	case time.Time:
		if t.IsZero() {
			return nil
		}
		return t.UTC().Format(time.RFC3339Nano)
	case *time.Time:
		// Defensive: a *time.Time scan destination would yield
		// either nil (NULL column) or a pointer to a populated
		// value. Treat nil-pointer and zero-time identically - both
		// map to JSON null.
		if t == nil || t.IsZero() {
			return nil
		}
		return t.UTC().Format(time.RFC3339Nano)
	}
	return v
}

// crudSelectFields resolves the `?fields=` projection for a list/read
// request, but - unlike the bare selectFields helper - intersects the
// requested columns with this table's real schema AND drops any column
// apiHiddenColumn hides from every response (secrets, tokens, blind
// indexes).
//
// M-5: without this, `?fields=password_hash` projected secret columns
// directly even though the same columns are stripped from write
// responses and user-object payloads. fail closed: an unknown or
// sensitive requested column is dropped, and a projection that resolves
// to NOTHING falls back to the default ("*") rather than emitting an
// empty/invalid SELECT - "*" itself is still sanitized downstream by
// sanitizeResponseRows, so this never widens exposure.
func crudSelectFields(r *http.Request, app *App, table, defaultFields string) string {
	raw := r.URL.Query().Get("fields")
	if raw == "" {
		return defaultFields
	}

	// Real columns for this table form the allowlist. If we can't read
	// the schema, fall back to the default rather than trusting client
	// input.
	allowed := make(map[string]bool)
	cols, err := crudTableColumns(r, app, table)
	if err != nil {
		return defaultFields
	}
	for _, c := range cols {
		allowed[c.Name] = true
	}

	var safe []string
	for _, f := range strings.Split(raw, ",") {
		f = strings.TrimSpace(f)
		if f == "" || !isValidColumnName(f) {
			continue
		}
		// Must be a real column on this table (allowlist) and must not be
		// a hidden column - the same predicate every response applies.
		if !allowed[f] || apiHiddenColumn(app, table, f) {
			continue
		}
		safe = append(safe, f)
	}
	if len(safe) == 0 {
		return defaultFields
	}
	return strings.Join(safe, ", ")
}

// Retain the row identity needed by encrypted-field policy inside a controlled
// projection. These columns are removed after masking unless requested by the
// caller; a projection must not either bypass masking or hide authorized data.
func crudMaskingProjection(app *App, table, fields string) (string, []string) {
	if fields == "*" || app == nil || app.Encrypted == nil {
		return fields, nil
	}
	selected := strings.Split(fields, ", ")
	needsIdentity := false
	for _, def := range app.Encrypted.Fields[table] {
		if len(def.Roles) > 0 && slices.Contains(selected, def.Column) {
			needsIdentity = true
			break
		}
	}
	if !needsIdentity {
		return fields, nil
	}
	var hidden []string
	for _, col := range []string{encryptedTenantColumn(app, table), "user_id"} {
		if col != "" && hasColumn(app, table, col) && !slices.Contains(selected, col) {
			selected = append(selected, col)
			hidden = append(hidden, col)
		}
	}
	return strings.Join(selected, ", "), hidden
}

func stripMaskingProjection(rows []map[string]any, hidden []string) {
	for _, row := range rows {
		for _, col := range hidden {
			delete(row, col)
		}
	}
}

// listColumnAllowlist is the set of columns a list request may filter or sort
// on. Hidden columns (apiHiddenColumn) are excluded: they are stripped from
// every response, but a `?share_token__like=ab%` or `?sort=share_token` still
// answers match/no-match per row, which recovers the secret a character at a
// time. Blind-index siblings stay in the set on purpose - their probe is gated
// separately by blindFilterAccessFor.
func listColumnAllowlist(app *App, table string, cols []Column) map[string]bool {
	allow := make(map[string]bool)
	for _, c := range cols {
		if strings.HasSuffix(c.Name, blindColSuffix) || !apiHiddenColumn(app, table, c.Name) {
			allow[c.Name] = true
		}
	}
	return allow
}

// hiddenListParam returns the first hidden column a list request filters or
// sorts on, or "". The allowlist drops such a parameter, and a dropped filter
// silently widens the result (`?invite_token=X` would return every invite), so
// handleList refuses the request instead of answering with rows the caller
// did not ask for.
func hiddenListParam(r *http.Request, app *App, table string) string {
	cols, err := crudTableColumns(r, app, table)
	allow := listColumnAllowlist(app, table, cols)
	real := map[string]bool{}
	if err == nil {
		for _, c := range cols {
			real[c.Name] = true
		}
	}
	hidden := func(col string) bool { return real[col] && !allow[col] }
	q := r.URL.Query()
	keys := make([]string, 0, len(q))
	for key := range q {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if apiFilterReservedParam(key) {
			continue
		}
		if col, _ := splitAPIFilterKey(key); col != "" && hidden(col) {
			return col
		}
	}
	sortCol := q.Get("sort")
	if ob := q.Get("orderBy"); sortCol == "" && ob != "" {
		sortCol = strings.SplitN(ob, ":", 2)[0]
	}
	if sortCol != "" && hidden(sortCol) {
		return sortCol
	}
	return ""
}

func handleList(w http.ResponseWriter, r *http.Request, app *App, table string) {
	if !appMCPReadOperationAllowed(w, r, "table.list") {
		return
	}
	// Declarative access gate (v2.7.12). Decides whether the request
	// can hit this endpoint AT ALL. Also drives the per-row filter
	// below: when mode is `anon`/`everyone`, we skip the implicit
	// owner-WHERE so the list reads broadly (still respects
	// `scopes.public_read_when` if set).
	if !EnforceCRUDAccess(w, r, app, table, OpRead, 0) {
		return
	}
	hasUID := hasColumn(app, table, "user_id")
	hasGroupKey := app.Group != nil && app.Group.Key != "" && hasColumn(app, table, app.Group.Key)
	readMode := app.Access.ModeFor(table, OpRead, hasUID, hasGroupKey)
	allowBroaderRows := app.Access.ReadAllowsBroaderRows(readMode)

	session := getSession(app, r)
	if !appMCPReadSessionAvailable(w, r, session) {
		return
	}

	// Scope enforcement
	if session != nil {
		if err := checkScope(session, table, "read"); err != nil {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": err.Error()})
			return
		}
	}

	// A blind-index filter (`?ssn=<guess>`) confirms plaintexts even when
	// the column comes back masked, so callers who may not see the column
	// unmasked get a 403 (not a silently widened result they'd misread).
	if col := blindFilterRefusal(r, app, table, session); col != "" {
		writeBlindFilterRefusal(w, table, col)
		return
	}

	if col := hiddenListParam(r, app, table); col != "" {
		httpJSON(w, http.StatusBadRequest, map[string]any{
			"error": fmt.Sprintf("%s.%s is a hidden column and cannot be filtered or sorted on; the filter would be ignored and return unfiltered rows. Look the row up by another column or a flow.", table, col),
		})
		return
	}
	include, err := normalizeIncludeSpec(r.URL.Query().Get("include"))
	if err != nil {
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	// Read audit logging (batched, non-blocking)
	if IsReadAudited(app, table) {
		LogReadAccess(app, table, "", "list", session)
	}

	// Field selection: ?fields=name,email (default: all). Intersected with
	// the table schema AND the sensitive-field denylist so a projection
	// like ?fields=password_hash can't bypass the masking applied to
	// write-backs (M-5).
	fields := crudSelectFields(r, app, table, "*")
	fields, hiddenMasking := crudMaskingProjection(app, table, fields)
	baseSQL := fmt.Sprintf("SELECT %s FROM %s", fields, quoteIdent(table))

	// Soft delete filter: exclude deleted rows if table has deleted_at
	hasWhere := false
	if hasColumn(app, table, "deleted_at") {
		baseSQL += " WHERE deleted_at IS NULL"
		hasWhere = true
	}

	// Platform admins normally bypass all CRUD scoping. EXCEPTION:
	// an admin who has stepped into a tenant via /api/_auth/act_as
	// is intentionally scoped TO that tenant for the duration of the
	// step-in - IsAdminBypass returns false while ActingAsGroup is set.
	isAdmin := session.IsAdminBypass()

	// Per-table public-read override from app.yaml `scopes:`. When
	// configured, this SQL fragment names rows visible to ANY caller
	// (anonymous or authenticated, owner or not) regardless of
	// user_id ownership. Owner reads still see their private rows
	// too - the standard owner filter is OR'd in below for sessions.
	publicReadWhen := ""
	if app.Scopes != nil {
		if sc, ok := app.Scopes[table]; ok {
			publicReadWhen = sc.PublicReadWhen
		}
	}

	var scopeArgs []any // args for parameterized ACL subquery
	if !isAdmin && !allowBroaderRows {
		// Build access filter: owner/group scoping OR explicit ACL grant
		// OR (if configured) the public_read_when SQL fragment.
		// SKIPPED when readMode is `anon`/`everyone` - the developer
		// explicitly opted into broad reads via `access:` and we honor
		// that without forcing them to also write `scopes.public_read_when`.
		var accessFilter string

		if pred, pargs, bypass := rowScopeClause(app, table, session, "view"); !bypass && pred != "" {
			accessFilter = pred
			scopeArgs = append(scopeArgs, pargs...)
		}

		// Public-read-when fragment widens whatever filter we built
		// (or stands alone for anonymous callers when no other filter
		// applies). When NEITHER applies, the request returns nothing
		// - same behavior as before.
		if publicReadWhen != "" {
			if accessFilter != "" {
				accessFilter = "(" + accessFilter + " OR (" + publicReadWhen + "))"
			} else {
				accessFilter = "(" + publicReadWhen + ")"
			}
		}

		if accessFilter != "" {
			if hasWhere {
				baseSQL += " AND " + accessFilter
			} else {
				baseSQL += " WHERE " + accessFilter
				hasWhere = true
			}
		}
	}

	// Full-text search: ?q=foo. When the table has @@fulltext in
	// schema.prisma, the framework joined a SQLite FTS5 virtual table
	// at boot - route through it for BM25-ranked results. Falls
	// through to no-filter when FTS isn't configured for this table
	// (client should narrow with `where:` or use a custom search
	// flow). FTS5's MATCH syntax is parameterized so user input
	// can't break out of the query - but FTS5 has its OWN syntax for
	// the MATCH expression where `.`, `:`, `*`, `@`, etc. are special.
	// A raw `alice.garcia@cyberdyne.ai` triggers `fts5: syntax error
	// near "."` (a real app session). escapeFTS5Query wraps each
	// whitespace-separated token as a quoted phrase, which makes any
	// special chars literal while preserving multi-word AND-search.
	if q := strings.TrimSpace(r.URL.Query().Get("q")); q != "" {
		ftsTable, ftsCols := FTSTableFor(app.Tables, table)
		// A hidden column in @@fulltext would make ?q= a substring oracle
		// for a value no response returns (the round-9 filter/sort rule),
		// so search only the columns a response carries.
		searchCols := ftsSearchColumns(app, table, ftsCols)
		if ftsTable != "" && len(searchCols) == 0 {
			httpJSON(w, http.StatusBadRequest, map[string]any{
				"error": fmt.Sprintf("%s: every @@fulltext column is a hidden column, so ?q= cannot search it. Index a column responses return, or search in a flow.", table),
			})
			return
		}
		if ftsTable != "" {
			var clause string
			if ftsTrigramUsable(q) {
				// Trigram MATCH: indexed substring search (contains).
				match := escapeFTS5Query(q)
				if len(searchCols) < len(ftsCols) {
					match = "{" + strings.Join(searchCols, " ") + "} : (" + match + ")"
				}
				columns, err := crudTableColumns(r, app, table)
				if err != nil {
					serverErrorJSON(w, r, app, "search columns", err, "search failed")
					return
				}
				rowID, err := ftsSourceRowID(columns)
				if err != nil {
					serverErrorJSON(w, r, app, "search identity", err, "search failed")
					return
				}
				clause = fmt.Sprintf("%s IN (SELECT rowid FROM %s WHERE %s MATCH ?)", quoteColumn(table, rowID), quoteIdent(ftsTable), quoteIdent(ftsTable))
				scopeArgs = append(scopeArgs, match)
			} else if lc, largs := buildFTSLikeFallback(table, searchCols, q); lc != "" {
				// Sub-3-char query - trigram can't tokenize it; LIKE fallback.
				clause = lc
				scopeArgs = append(scopeArgs, largs...)
			}
			if clause != "" {
				if hasWhere {
					baseSQL += " AND " + clause
				} else {
					baseSQL += " WHERE " + clause
					hasWhere = true
				}
			}
		}
	}

	// Cursor pagination: ?cursor=X&limit=N (keyset, fast for large datasets)
	if cursor := r.URL.Query().Get("cursor"); cursor != "" {
		cols, _ := crudTableColumns(r, app, table)
		colAllowlist := listColumnAllowlist(app, table, cols)
		// Apply the same filters as offset/count before adding the keyset.
		cursorSQL, whereArgs := applyAPIWhereWithApp(baseSQL, r, table, app, session, colAllowlist)
		cursorArgs := append(append([]any{}, scopeArgs...), whereArgs...)
		hiddenID := fields != "*" && !slices.Contains(strings.Split(fields, ", "), "id")
		if hiddenID {
			cursorSQL = strings.Replace(cursorSQL, "SELECT "+fields+" FROM ", "SELECT "+fields+", id FROM ", 1)
		}
		limit := queryInt(r, "limit", 20)
		if limit > 500 {
			limit = 500
		}
		if strings.Contains(cursorSQL, " WHERE ") {
			cursorSQL += " AND id > ?"
		} else {
			cursorSQL += " WHERE id > ?"
		}
		cursorSQL += fmt.Sprintf(" ORDER BY id ASC LIMIT %d", limit)
		cursorArgs = append(cursorArgs, cursor)
		rows, err := appMCPReadRows(app, r, table, cursorSQL, cursorArgs...)
		if err != nil {
			serverError(w, r, app, table+" list", err, "list failed")
			return
		}
		// Relationship includes on cursor-paginated results
		if include != "" {
			ResolveIncludes(app, table, rows, include, session)
		}
		// Mask encrypted columns on the PRIMARY rows, same as the offset-
		// pagination path below. The keyset (cursor) branch returns early with
		// its own encode, so without this a non-unmask-role caller recovers the
		// plaintext just by paging with ?cursor= instead of ?page=.
		sanitizeResponseRows(app, table, rows, session)
		var nextCursor any
		if len(rows) == limit {
			nextCursor = rows[len(rows)-1]["id"]
		}
		if hiddenID {
			for _, row := range rows {
				delete(row, "id")
			}
		}
		stripMaskingProjection(rows, hiddenMasking)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"data":        rows,
			"next_cursor": nextCursor,
			"limit":       limit,
		})
		return
	}

	// Apply filtering, sorting, pagination from query params
	cols, _ := crudTableColumns(r, app, table)
	colAllowlist := listColumnAllowlist(app, table, cols)

	// `?count=true` (alias: `?count_only=true`) short-circuits the row
	// fetch and returns just `{count: N}` - the true total of rows that
	// would match (with WHERE filters applied) BUT ignoring the LIMIT /
	// page cap. A real app hit "50 records showing but actual count is
	// 693" three times because the auto-CRUD list defaults to a 50-row
	// page cap and the JS read `data.length`. With a dedicated count
	// endpoint, the SDK's `bm.table('x').count()` answers "how many?"
	// in one round-trip without re-deriving via a custom flow. WHERE
	// filters (`?where[col]=val`, `?col__op=val`, `?q=…`) ARE honored
	// - pass them to count a filtered subset.
	if isTruthyQuery(r, "count") || isTruthyQuery(r, "count_only") {
		whereSQL, whereArgs := applyAPIWhereWithApp(baseSQL, r, table, app, session, colAllowlist)
		countSQL := "SELECT COUNT(*) FROM (" + whereSQL + ")"
		countArgs := append(scopeArgs, whereArgs...)
		var total int64
		if err := appMCPReadCount(app, r, countSQL, countArgs, &total); err != nil {
			serverError(w, r, app, table+" count", err, "count failed")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"count": total})
		return
	}

	if msg := apiOffsetTooDeepError(r); msg != "" {
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": msg})
		return
	}
	sql, filterArgs := applyAPIFiltersWithApp(baseSQL, r, table, app, session, colAllowlist)
	allArgs := append(scopeArgs, filterArgs...)

	rows, err := appMCPReadRows(app, r, table, sql, allArgs...)
	if err != nil {
		serverError(w, r, app, table+" list", err, "list failed")
		return
	}

	// Relationship includes: ?include=contact,tasks (batched, no N+1)
	if include != "" {
		ResolveIncludes(app, table, rows, include, session)
	}

	// Mask encrypted fields for unauthorized roles (v2.7.58+: pass
	// the full session so the multi-role / join-table grants are
	// honored, not just the primary _benmore_users.role column).
	sanitizeResponseRows(app, table, rows, session)
	stripMaskingProjection(rows, hiddenMasking)

	w.Header().Set("Content-Type", "application/json")

	// Pagination metadata: if ?page= is used, wrap in {data, total, page, per_page}
	if r.URL.Query().Get("page") != "" {
		// Count total rows through the SAME where filters the rows went
		// through — applyAPIWhereWithApp is the filter half of
		// applyAPIFiltersWithApp, without LIMIT/OFFSET. Counting bare
		// baseSQL here (scope only) made `total` the whole group's row
		// count on any filtered request: `?where[project_id]=44&page=1`
		// against a project with zero documents in a group holding 38
		// answered `{data: [], total: 38}`. A paged consumer that trusts
		// total for completeness then either loops chasing phantom rows
		// or fails closed — a client app's Roadmap tab died on exactly
		// this on 2026-08-05. The `?count=true` branch above always
		// filtered correctly; the two branches now agree.
		countWhereSQL, countWhereArgs := applyAPIWhereWithApp(baseSQL, r, table, app, session, colAllowlist)
		countSQL := "SELECT COUNT(*) FROM (" + countWhereSQL + ")"
		countArgs := append(append([]any{}, scopeArgs...), countWhereArgs...)
		var total int
		if err := appMCPReadCount(app, r, countSQL, countArgs, &total); err != nil {
			serverError(w, r, app, table+" count", err, "count failed")
			return
		}
		page, perPage := apiOffsetPagination(r)
		if rows == nil {
			rows = []map[string]any{}
		}
		json.NewEncoder(w).Encode(map[string]any{
			"data":     rows,
			"total":    total,
			"page":     page,
			"per_page": perPage,
		})
	} else {
		// Always emit `[]` for empty result sets, never `null`. A nil
		// slice serializes to `null` by default, which breaks client
		// code that does `.length` or `.map(...)` on the response.
		if rows == nil {
			rows = []map[string]any{}
		}
		json.NewEncoder(w).Encode(rows)
	}
}

// readRowFilter turns rowScopeClause's result into handleList's per-row
// filter for a single-row read: none for a bypassing admin or an
// `anon`/`everyone` read mode, otherwise the scope predicate OR'd with the
// table's scopes.public_read_when.
func readRowFilter(app *App, table, pred string, args []any, bypass bool) (string, []any) {
	hasUID := hasColumn(app, table, "user_id")
	hasGroupKey := app.Group != nil && app.Group.Key != "" && hasColumn(app, table, app.Group.Key)
	if bypass || app.Access.ReadAllowsBroaderRows(app.Access.ModeFor(table, OpRead, hasUID, hasGroupKey)) {
		return "", nil
	}
	filter := pred
	if app.Scopes != nil {
		if sc, ok := app.Scopes[table]; ok && sc.PublicReadWhen != "" {
			if filter != "" {
				filter = "(" + filter + " OR (" + sc.PublicReadWhen + "))"
			} else {
				filter = "(" + sc.PublicReadWhen + ")"
			}
		}
	}
	return filter, args
}

func handleRead(w http.ResponseWriter, r *http.Request, app *App, table string) {
	if !appMCPReadOperationAllowed(w, r, "table.read") {
		return
	}
	// Coarse access gate (v2.7.12). Per-row owner/group filtering still
	// runs below - this just blocks listing modes the caller can't
	// touch at all (e.g. `read: admin` on `system_logs`).
	if !EnforceCRUDAccess(w, r, app, table, OpRead, 0) {
		return
	}
	id := extractID(r.URL.Path, table)
	if id == "" {
		httpError(w, "Missing ID", http.StatusBadRequest)
		return
	}
	if !rowIDCanonical(app, table, id) {
		http.NotFound(w, r)
		return
	}
	include, err := normalizeIncludeSpec(r.URL.Query().Get("include"))
	if err != nil {
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	// Point-in-time query: ?as_of=2026-03-01T00:00:00Z
	if asOf := r.URL.Query().Get("as_of"); asOf != "" {
		session := getSession(app, r)
		if !appMCPReadSessionAvailable(w, r, session) {
			return
		}
		if session != nil {
			if err := checkScope(session, table, "read"); err != nil {
				httpJSON(w, http.StatusForbidden, map[string]any{"error": err.Error()})
				return
			}
		}
		if session == nil || !canAccessRow(app, table, id, session) {
			httpError(w, "Not found", http.StatusNotFound)
			return
		}
		row, err := handlePointInTime(app, r, table, id, asOf, session)
		if err != nil {
			if errors.Is(err, errInvalidPointInTime) {
				httpError(w, err.Error(), http.StatusBadRequest)
				return
			}
			httpError(w, err.Error(), http.StatusNotFound)
			return
		}
		// A historical snapshot is a read of the row like any other: an
		// audited table records it (this branch returns before the live
		// read's LogReadAccess below).
		if IsReadAudited(app, table) {
			LogReadAccess(app, table, id, "as_of", session)
		}
		// Mask encrypted columns exactly as the live read path below does
		// (v2.7 parity). The point-in-time row is either a decrypted history
		// snapshot or the decrypted current row; without this a caller who can
		// READ the row but is NOT in the column's unmask_roles would get the
		// plaintext through `?as_of=` that a plain GET masks.
		sanitizeResponseRows(app, table, []map[string]any{row}, session)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(row)
		return
	}

	// SECURITY: enforce scoping on reads
	fields := "*"
	if _, private := r.Context().Value(appMCPPrivateKey{}).(*appMCPPrivateRead); private {
		fields = crudSelectFields(r, app, table, "*")
	}
	fields, hiddenMasking := crudMaskingProjection(app, table, fields)
	readSQL := fmt.Sprintf("SELECT %s FROM %s WHERE id = ?", fields, quoteIdent(table))
	readArgs := []any{id}
	// Soft delete filter
	if hasColumn(app, table, "deleted_at") {
		readSQL += " AND deleted_at IS NULL"
	}
	session := getSession(app, r)
	if !appMCPReadSessionAvailable(w, r, session) {
		return
	}
	if session != nil {
		if err := checkScope(session, table, "read"); err != nil {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": err.Error()})
			return
		}
	}
	// Read audit logging (batched, non-blocking)
	if IsReadAudited(app, table) {
		LogReadAccess(app, table, id, "read", session)
	}
	// Same row filter handleList applies, so a row the list shows can be
	// fetched by id and nothing else can: `anon`/`everyone` read modes
	// read broadly, other modes take rowScopeClause widened by
	// scopes.public_read_when.
	pred, pargs, bypass := rowScopeClause(app, table, session, "view")
	if filter, fargs := readRowFilter(app, table, pred, pargs, bypass); filter != "" {
		readSQL += " AND " + filter
		readArgs = append(readArgs, fargs...)
	}

	rows, err := appMCPReadRows(app, r, table, readSQL, readArgs...)
	if err != nil && !errors.Is(err, errAppMCPGrantDenied) {
		// A failed query is kept server-side with a request id; the answer
		// stays the 404 this route has always given.
		w.Header().Set(requestIDHeader, noteServerError(r, table+" read", err))
	}
	if err != nil || len(rows) == 0 {
		httpError(w, "Not found", http.StatusNotFound)
		return
	}

	// Relationship includes: ?include=contact,tasks
	if include != "" {
		ResolveIncludes(app, table, rows, include, session)
	}

	// Mask encrypted fields for unauthorized roles (v2.7.58+:
	// session-aware; see MaskEncryptedFields docstring).
	sanitizeResponseRows(app, table, rows, session)
	stripMaskingProjection(rows, hiddenMasking)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rows[0])
}
