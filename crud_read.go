//go:build !cli

package main

// Record listing, single-record reads, and SQL result shaping.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
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
// RFC3339 in UTC.
func coerceSQLValue(v any) any {
	switch t := v.(type) {
	case []byte:
		return string(t)
	case time.Time:
		if t.IsZero() {
			return nil
		}
		return t.UTC().Format(time.RFC3339)
	case *time.Time:
		// Defensive: a *time.Time scan destination would yield
		// either nil (NULL column) or a pointer to a populated
		// value. Treat nil-pointer and zero-time identically - both
		// map to JSON null.
		if t == nil || t.IsZero() {
			return nil
		}
		return t.UTC().Format(time.RFC3339)
	}
	return v
}

// crudSelectFields resolves the `?fields=` projection for a list/read
// request, but - unlike the bare selectFields helper - intersects the
// requested columns with this table's real schema AND drops any column
// the sensitive-field denylist (isSensitiveUserColumn) would mask on a
// write-back.
//
// M-5: without this, `?fields=password_hash` projected secret columns
// directly even though the same columns are stripped from write
// responses and user-object payloads. fail closed: an unknown or
// sensitive requested column is dropped, and a projection that resolves
// to NOTHING falls back to the default ("*") rather than emitting an
// empty/invalid SELECT - "*" itself is still masked downstream by
// MaskEncryptedFields, so this never widens exposure.
func crudSelectFields(r *http.Request, app *App, table, defaultFields string) string {
	raw := r.URL.Query().Get("fields")
	if raw == "" {
		return defaultFields
	}

	// Real columns for this table form the allowlist. If we can't read
	// the schema, fall back to the default rather than trusting client
	// input.
	allowed := make(map[string]bool)
	cols, err := GetTableColumns(app.DB, table)
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
		// a sensitive/secret column (denylist) - same denylist used to
		// mask write-backs and user payloads.
		if !allowed[f] || isSensitiveUserColumn(f) {
			continue
		}
		safe = append(safe, f)
	}
	if len(safe) == 0 {
		return defaultFields
	}
	return strings.Join(safe, ", ")
}

func handleList(w http.ResponseWriter, r *http.Request, app *App, table string) {
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

	// Scope enforcement
	if session != nil {
		if err := checkScope(session, table, "read"); err != nil {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": err.Error()})
			return
		}
	}

	// Read audit logging (batched, non-blocking)
	if IsReadAudited(app, table) {
		LogReadAccess(table, "", "list", session)
	}

	// Field selection: ?fields=name,email (default: all). Intersected with
	// the table schema AND the sensitive-field denylist so a projection
	// like ?fields=password_hash can't bypass the masking applied to
	// write-backs (M-5).
	fields := crudSelectFields(r, app, table, "*")
	baseSQL := fmt.Sprintf("SELECT %s FROM %s", fields, table)

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
		if ftsTable != "" {
			var clause string
			if ftsTrigramUsable(q) {
				// Trigram MATCH: indexed substring search (contains).
				clause = fmt.Sprintf("%s.id IN (SELECT rowid FROM %s WHERE %s MATCH ?)", table, ftsTable, ftsTable)
				scopeArgs = append(scopeArgs, escapeFTS5Query(q))
			} else if lc, largs := buildFTSLikeFallback(table, ftsCols, q); lc != "" {
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
		colAllowlist := make(map[string]bool)
		if cols, err := GetTableColumns(app.DB, table); err == nil {
			for _, col := range cols {
				colAllowlist[col.Name] = true
			}
		}
		// Apply the same filters as offset/count before adding the keyset.
		cursorSQL, whereArgs := applyAPIWhereWithApp(baseSQL, r, table, app, colAllowlist)
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
		rows, err := QueryRows(app.DB, cursorSQL, cursorArgs...)
		if err != nil {
			httpError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// Relationship includes on cursor-paginated results
		if inc := r.URL.Query().Get("include"); inc != "" {
			ResolveIncludes(app, table, rows, inc, session)
		}
		// Mask encrypted columns on the PRIMARY rows, same as the offset-
		// pagination path below. The keyset (cursor) branch returns early with
		// its own encode, so without this a non-unmask-role caller recovers the
		// plaintext just by paging with ?cursor= instead of ?page=.
		MaskEncryptedFields(app.Encrypted, table, rows, session)
		var nextCursor any
		if len(rows) == limit {
			nextCursor = rows[len(rows)-1]["id"]
		}
		if hiddenID {
			for _, row := range rows {
				delete(row, "id")
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"data":        rows,
			"next_cursor": nextCursor,
			"limit":       limit,
		})
		return
	}

	// Apply filtering, sorting, pagination from query params
	colAllowlist := make(map[string]bool)
	if cols, err := GetTableColumns(app.DB, table); err == nil {
		for _, c := range cols {
			colAllowlist[c.Name] = true
		}
	}

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
		whereSQL, whereArgs := applyAPIWhereWithApp(baseSQL, r, table, app, colAllowlist)
		countSQL := "SELECT COUNT(*) FROM (" + whereSQL + ")"
		countArgs := append(scopeArgs, whereArgs...)
		var total int64
		if err := app.DB.QueryRow(countSQL, countArgs...).Scan(&total); err != nil {
			httpError(w, "count failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"count": total})
		return
	}

	sql, filterArgs := applyAPIFiltersWithApp(baseSQL, r, table, app, colAllowlist)
	allArgs := append(scopeArgs, filterArgs...)

	rows, err := QueryRows(app.DB, sql, allArgs...)
	if err != nil {
		httpError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Relationship includes: ?include=contact,tasks (batched, no N+1)
	if inc := r.URL.Query().Get("include"); inc != "" {
		ResolveIncludes(app, table, rows, inc, session)
	}

	// Mask encrypted fields for unauthorized roles (v2.7.58+: pass
	// the full session so the multi-role / join-table grants are
	// honored, not just the primary _benmore_users.role column).
	MaskEncryptedFields(app.Encrypted, table, rows, session)

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
		countWhereSQL, countWhereArgs := applyAPIWhereWithApp(baseSQL, r, table, app, colAllowlist)
		countSQL := "SELECT COUNT(*) FROM (" + countWhereSQL + ")"
		countArgs := append(append([]any{}, scopeArgs...), countWhereArgs...)
		var total int
		app.DB.QueryRow(countSQL, countArgs...).Scan(&total)
		page := queryInt(r, "page", 1)
		perPage := queryInt(r, "per_page", 20)
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

func handleRead(w http.ResponseWriter, r *http.Request, app *App, table string) {
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

	// Point-in-time query: ?as_of=2026-03-01T00:00:00Z
	if asOf := r.URL.Query().Get("as_of"); asOf != "" {
		session := getSession(app, r)
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
		row, err := handlePointInTime(app, table, id, asOf, session)
		if err != nil {
			httpError(w, err.Error(), http.StatusNotFound)
			return
		}
		// Mask encrypted columns exactly as the live read path below does
		// (v2.7 parity). The point-in-time row is either a decrypted history
		// snapshot or the decrypted current row; without this a caller who can
		// READ the row but is NOT in the column's unmask_roles would get the
		// plaintext through `?as_of=` that a plain GET masks.
		MaskEncryptedFields(app.Encrypted, table, []map[string]any{row}, session)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(row)
		return
	}

	// SECURITY: enforce scoping on reads
	readSQL := fmt.Sprintf("SELECT * FROM %s WHERE id = ?", table)
	readArgs := []any{id}
	// Soft delete filter
	if hasColumn(app, table, "deleted_at") {
		readSQL += " AND deleted_at IS NULL"
	}
	session := getSession(app, r)
	if session != nil {
		if err := checkScope(session, table, "read"); err != nil {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": err.Error()})
			return
		}
	}
	// Read audit logging (batched, non-blocking)
	if IsReadAudited(app, table) {
		LogReadAccess(table, id, "read", session)
	}
	if pred, pargs, bypass := rowScopeClause(app, table, session, "view"); !bypass && pred != "" {
		readSQL += " AND " + pred
		readArgs = append(readArgs, pargs...)
	}

	rows, err := QueryRows(app.DB, readSQL, readArgs...)
	if err != nil || len(rows) == 0 {
		httpError(w, "Not found", http.StatusNotFound)
		return
	}

	// Relationship includes: ?include=contact,tasks
	if inc := r.URL.Query().Get("include"); inc != "" {
		ResolveIncludes(app, table, rows, inc, session)
	}

	// Mask encrypted fields for unauthorized roles (v2.7.58+:
	// session-aware; see MaskEncryptedFields docstring).
	MaskEncryptedFields(app.Encrypted, table, rows, session)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rows[0])
}
