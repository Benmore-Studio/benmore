//go:build !cli

package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ===== 404 / 500 Error Pages =====

func notFoundHandler(app *App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// An unmatched /api/* path must NEVER return HTML - not the SPA
		// index.html (GET) nor the HTML 404 page (other methods). Both make
		// a client's `await res.json()` choke on '<', and worse, a cached
		// 200-HTML for a not-yet-deployed flow path sticks in the CDN and
		// shadows the flow once it IS deployed. Emit a real JSON 404 with
		// `no-store` so the CDN won't cache it. (v2.7.139)
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":"not_found","message":"no API route matches this path"}`)
			return
		}

		// A trailing-slash variant of a registered page (`/docs/` for
		// `/docs`) is the same resource with a different URL. Send crawlers
		// and pasted links to the canonical form instead of a 404. Only
		// exact page routes qualify - never `/api/`, never unknown paths.
		if (r.Method == http.MethodGet || r.Method == http.MethodHead) && len(r.URL.Path) > 1 && strings.HasSuffix(r.URL.Path, "/") {
			trimmed := strings.TrimRight(r.URL.Path, "/")
			if _, ok := app.Pages[trimmed]; ok {
				target := trimmed
				if r.URL.RawQuery != "" {
					target += "?" + r.URL.RawQuery
				}
				http.Redirect(w, r, target, http.StatusMovedPermanently)
				return
			}
		}

		// HTML-stack apps put their frontend in `static/*.html` and
		// expect clean URLs (`/contacts` → `static/contacts.html`). Try
		// that fallback BEFORE returning 404 so vanilla-HTML apps work
		// without registering a handler per page. GET-only - POST etc.
		// always 404 because they want explicit registration (CRUD
		// endpoints, flows, auth handlers all register their own
		// methods).
		if (r.Method == http.MethodGet || r.Method == http.MethodHead) && serveStaticHTML(w, r, app) {
			return
		}

		// Headers MUST be set before WriteHeader. Once status is written,
		// Header().Set is a no-op and the browser falls back to text/plain
		// (rendering the response as raw HTML source instead of a page).
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		content := `<div class="flex flex-col items-center justify-center py-16">
			<h1 class="text-6xl font-bold tracking-tight mb-2">404</h1>
			<p class="text-muted-foreground mb-6">Page not found</p>
			<a href="/" class="inline-flex items-center justify-center rounded-md bg-primary text-primary-foreground h-9 px-4 text-sm font-medium hover:bg-primary/90 transition-colors no-underline">Go Home</a>
		</div>`
		fmt.Fprint(w, WrapLayout(content, "Not Found", app, nil))
	}
}

// Gzip compression lives in gzip_middleware.go.

// ===== CORS =====

func corsMiddleware(next http.Handler, app *App) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check for CORS_ORIGIN in env
		origin := GetEnv(app.Dir, "CORS_ORIGIN")
		if origin == "" {
			next.ServeHTTP(w, r)
			return
		}

		requestOrigin := r.Header.Get("Origin")
		if requestOrigin == "" {
			next.ServeHTTP(w, r)
			return
		}

		// Check if origin is allowed
		allowed := false
		if origin == "*" {
			allowed = true
		} else {
			for _, o := range strings.Split(origin, ",") {
				if strings.TrimSpace(o) == requestOrigin {
					allowed = true
					break
				}
			}
		}

		// The response varies by Origin whenever CORS is configured, so a
		// shared cache must not serve one origin's answer to another.
		w.Header().Add("Vary", "Origin")
		if allowed {
			w.Header().Set("Access-Control-Allow-Origin", requestOrigin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-CSRF-Token, HX-Request")
			// Per CORS spec, Access-Control-Allow-Credentials must NOT be set when origin is wildcard.
			// Only set credentials header when a specific origin is configured.
			if origin != "*" {
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}
			w.Header().Set("Access-Control-Max-Age", "86400")
		}

		// Handle preflight
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// ===== Health Check =====

// runtimeInstanceID is an opaque process nonce, not a PID, secret or app identifier.
var runtimeInstanceID = rand.Text()

func healthHandler(app *App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		status := "healthy"
		httpStatus := http.StatusOK
		checks := make(map[string]any)

		// 1. Database: actual query, not just ping - measures real latency
		dbStart := time.Now()
		var dbOK int
		err := app.DB.QueryRowContext(r.Context(), "SELECT 1").Scan(&dbOK)
		dbLatency := time.Since(dbStart)
		if err != nil {
			status = "unhealthy"
			httpStatus = http.StatusServiceUnavailable
			id := noteServerError(r, "health", err)
			w.Header().Set(requestIDHeader, id)
			checks["database"] = map[string]any{"status": "down", "error": serverErrorAnswerText(app, id, err, "database query failed")}
		} else {
			dbStatus := "ok"
			if dbLatency > 100*time.Millisecond {
				dbStatus = "slow"
			}
			checks["database"] = map[string]any{"status": dbStatus, "latency": dbLatency.String()}
		}

		// 2. Disk: check data.db size and if directory is writable
		dbPath := app.Dir + "/data.db"
		if fi, err := os.Stat(dbPath); err == nil {
			checks["disk"] = map[string]any{
				"db_size": fi.Size(),
				"status":  "ok",
			}
		}

		// 3. Job queue: check for stuck/failed jobs
		var pendingJobs, failedJobs, runningJobs int64
		app.DB.QueryRowContext(r.Context(), "SELECT COUNT(*) FROM _benmore_jobs WHERE status = 'pending'").Scan(&pendingJobs)
		app.DB.QueryRowContext(r.Context(), "SELECT COUNT(*) FROM _benmore_jobs WHERE status = 'failed'").Scan(&failedJobs)
		app.DB.QueryRowContext(r.Context(), "SELECT COUNT(*) FROM _benmore_jobs WHERE status = 'running'").Scan(&runningJobs)
		jobStatus := "ok"
		if failedJobs > 10 {
			jobStatus = "degraded"
		}
		if pendingJobs > 100 {
			jobStatus = "backlogged"
		}
		checks["jobs"] = map[string]any{
			"status":  jobStatus,
			"pending": pendingJobs,
			"running": runningJobs,
			"failed":  failedJobs,
		}

		// 4. Circuit breakers
		cbStats := CircuitBreakerStats(app)
		if len(cbStats) > 0 {
			checks["circuits"] = cbStats
		}

		// 5. Sessions: active count
		var activeSessions int64
		app.DB.QueryRowContext(r.Context(), "SELECT COUNT(*) FROM _benmore_sessions WHERE datetime(expires_at) > datetime('now')").Scan(&activeSessions)
		checks["sessions"] = map[string]any{"active": activeSessions}

		// Anonymous: basic status only. Admin: full details.
		// Prevents infrastructure reconnaissance from unauthenticated users.
		session := getSession(app, r)
		isAdmin := session != nil && session.IsAdmin()

		resp := map[string]any{
			"status":            status,
			"version":           version,
			"instance_id":       runtimeInstanceID,
			"reload_generation": app.reloadGeneration.Load(),
		}
		if isAdmin {
			resp["uptime"] = time.Since(startTime).String()
			resp["checks"] = checks
		}

		w.WriteHeader(httpStatus)
		json.NewEncoder(w).Encode(resp)
	}
}

var startTime = time.Now()

// ===== Graceful Shutdown =====

func startServerWithGracefulShutdown(server *http.Server, dev bool) error {
	// Channel to listen for interrupt signals
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// Start server in goroutine
	go func() {
		var err error
		// Prefer a systemd socket-activated listener for this port - the socket
		// is owned by systemd and stays bound across restarts, so a binary swap
		// drops zero connections (they queue in the backlog during the handoff).
		if ln := systemdListener(portFromAddr(server.Addr)); ln != nil {
			if server.TLSConfig != nil {
				err = server.ServeTLS(ln, "", "")
			} else {
				err = server.Serve(ln)
			}
		} else if server.TLSConfig != nil {
			// HTTPS with autocert - empty strings = use TLSConfig.GetCertificate
			err = server.ListenAndServeTLS("", "")
		} else {
			err = server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %s", err)
		}
	}()

	// Wait for interrupt signal
	sig := <-quit
	log.Printf("  received %s, shutting down gracefully...", sig)

	// Create deadline context for shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Printf("  forced shutdown: %s", err)
		return err
	}

	log.Printf("  server stopped")
	return nil
}

// ===== API Enhancements =====

// applyAPIFilters modifies a SQL query with pagination, sorting, and filtering.
// isValidColumnName checks that a string is safe to use as a SQL column name.
func isValidColumnName(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
			return false
		}
	}
	return true
}

// applyAPIWhere applies just the `?where[…]=val` + `?col=val` +
// `?col__op=val` filter conditions to baseSQL. ORDER / LIMIT / OFFSET
// are NOT appended - call applyAPIOrderLimit afterwards (or use
// applyAPIFilters which composes both). Used by handleList both for
// the row-fetch path AND the COUNT(*) wrap on `?count=true` - the
// count needs the same WHERE clauses as the data fetch but no ORDER
// or LIMIT.
func applyAPIWhere(baseSQL string, r *http.Request, table string, validCols ...map[string]bool) (string, []any) {
	return applyAPIWhereWithApp(baseSQL, r, table, nil, nil, validCols...)
}

// apiFilterReservedParam reports whether a query key is a pagination / sort /
// projection control rather than a column filter.
func apiFilterReservedParam(key string) bool {
	switch key {
	case "page", "per_page", "sort", "order", "fields", "limit", "offset", "include", "cursor", "q", "order_by", "orderBy", "as_of":
		return true
	}
	return false
}

// apiFilterOps maps the `__<op>` filter suffixes onto SQL operators (`__in`
// is handled separately as IN).
var apiFilterOps = map[string]string{
	"__gt":   ">",
	"__gte":  ">=",
	"__lt":   "<",
	"__lte":  "<=",
	"__ne":   "!=",
	"__like": "LIKE",
}

// splitAPIFilterKey unwraps `where[col]` → `col` and splits an operator
// suffix: `price__gte` → ("price", ">="). col is "" for an unknown operator
// (the filter is skipped). orderBy=col:dir is handled by the sort step; the
// where[] form is purely filter syntax.
func splitAPIFilterKey(key string) (col, op string) {
	if strings.HasPrefix(key, "where[") && strings.HasSuffix(key, "]") {
		key = key[len("where[") : len(key)-1]
	}
	i := strings.Index(key, "__")
	if i <= 0 {
		return key, "="
	}
	suffix := key[i:]
	if op, ok := apiFilterOps[suffix]; ok {
		return key[:i], op
	}
	if suffix == "__in" {
		return key[:i], "IN"
	}
	return "", ""
}

// applyAPIWhereWithApp is the App-aware variant. The App reference
// is used solely for blind-index lookup (v2.7.55+) - equality
// filters on encrypted columns flagged `blind_index: true` rewrite to
// `<col>_blind = HMAC(value)` so the query hits the deterministic
// sibling column instead of useless ciphertext. session decides how far a
// blind-index probe may reach (blindFilterAccessFor).
func applyAPIWhereWithApp(baseSQL string, r *http.Request, table string, app *App, session *Session, validCols ...map[string]bool) (string, []any) {
	var args []any
	query := baseSQL

	// Build column allowlist.
	//
	// M-7: the allowlist is MANDATORY and the helper fails closed. When no
	// allowlist is supplied (no validCols arg, or a nil map), we refuse to
	// apply ANY `?col=val` / `?where[...]` filter rather than permitting
	// filtering on arbitrary real columns - an empty allowlist used to be
	// treated as "allow everything", a fail-open footgun that let callers
	// filter (and, via applyAPIFilters, ORDER BY) on columns the endpoint
	// never meant to expose. invariant: no allowlist => no user-supplied
	// filter or sort columns are honored.
	hasAllowlist := len(validCols) > 0 && validCols[0] != nil
	allowed := make(map[string]bool)
	if hasAllowlist {
		for k, v := range validCols[0] {
			allowed[k] = v
		}
	}
	if !hasAllowlist {
		// fail closed: skip all filter parsing - return the base query
		// unchanged so the caller still gets rows, just no client-driven
		// WHERE narrowing on an unvalidated column set.
		return query, args
	}
	// Blind-indexed columns on this table - built once outside the loop
	// so a request with N filters does one config lookup, not N.
	blindCols := BlindIndexColumnsForTable(nil, table)
	// Encrypted columns on this table (any encrypted col, blind-indexed
	// or not). Used by the unsupported-operator guard below: a range /
	// LIKE filter on an encrypted column will silently match nothing
	// (the on-disk value is ciphertext, not the plaintext you wrote),
	// so we tag those for the loop to short-circuit with a warning
	// header rather than letting the request return an empty result
	// and look broken.
	encCols := map[string]bool{}
	if app != nil {
		blindCols = BlindIndexColumnsForTable(app.Encrypted, table)
		// Add the sibling columns to the allowlist too so a request
		// that ALREADY queries `?email_blind=hex` (explicit, for
		// debugging or for a flow that hashed the value itself) gets
		// through the validation.
		for c := range blindCols {
			allowed[c+blindColSuffix] = true
		}
		if app.Encrypted != nil {
			if defs, ok := app.Encrypted.Fields[table]; ok {
				for _, d := range defs {
					encCols[d.Column] = true
				}
			}
		}
	}

	// Filtering: ?type=lead&company=Acme  (equality, the common case)
	// Operator suffixes: ?status__in=draft,archived&price__gte=100
	//   Supported: __gt __gte __lt __lte __ne __like __in
	// `where[col]=val` and `where[col__op]=val` shapes are also
	// accepted - that's what the docs promise, what bm.js's useTable()
	// emits, and what the agent in an earlier app build naturally
	// reached for. Pre-v2.5.12 the wrapper was silently dropped (raw
	// "where[col]" failed isValidColumnName → no filter applied).
	var conditions []string
	for key, values := range r.URL.Query() {
		if len(values) == 0 {
			continue
		}
		// Skip pagination/sort params
		if apiFilterReservedParam(key) {
			continue
		}
		col, op := splitAPIFilterKey(key)
		if col == "" {
			continue // unknown operator → silently skip
		}
		// Validate column name against schema allowlist. fail closed: a
		// column not on the allowlist is dropped unconditionally (an
		// explicitly-empty allowlist therefore permits nothing).
		if !allowed[col] {
			continue
		}
		// Extra safety: only allow alphanumeric + underscore
		if !isValidColumnName(col) {
			continue
		}
		// Unsupported-operator guard for encrypted columns (v2.7.57+).
		//
		// AES-GCM ciphertext doesn't preserve order, prefix, or
		// substring relationships. A query like `?salary__gt=50000`
		// against an encrypted salary column compiles fine and
		// returns ZERO rows - SQLite text-compares "50000" against
		// "enc:v1:<random hex>" lexicographically. The caller sees
		// an empty result that LOOKS correct (no error, just no
		// matches) but is semantically nonsense.
		//
		// Better failure mode: silently drop the filter. The query
		// proceeds without the broken predicate, returning the
		// rows that pass every OTHER filter - equivalent to "this
		// operator isn't available, here's the rest of your result."
		// We also tag the response so the caller has SOMETHING to
		// debug from (a header set later in the read path, see the
		// X-Benmore-Unsupported-Filter doc in apps.md).
		//
		// Equality (`=`) and IN don't get filtered: they fall
		// through to the blind-index rewrite below, which produces
		// a meaningful result. Net effect:
		//   encrypted + equality  → blind-index rewrite (works)
		//   encrypted + range/LIKE → silently dropped (no false matches)
		//   non-encrypted any op  → unchanged
		if encCols[col] && op != "=" && op != "IN" {
			continue
		}
		// Blind-index rewrite (v2.7.55+). When the caller filters by
		// equality on an encrypted column flagged `blind_index: true`,
		// substitute the sibling `<col>_blind` and hash the value so
		// the query matches the deterministic HMAC stored there. Only
		// applies to equality (`=`) and IN - every other operator on
		// the encrypted column is unsupported (no range / prefix /
		// substring search on blind indexes) and passes through to
		// hit the ciphertext, which deliberately fails to match.
		//
		// A blind-index probe is an equality oracle, so it is honored only
		// where the caller would see the plaintext (blindFilterAccessFor):
		// refused callers are rejected up front by handleList (and dropped
		// here as defense in depth); `self`/`owner`-unmask callers have the
		// probe restricted to rows they own.
		var encryptedScope string
		var encryptedScopeArgs []any
		if base, probe := blindFilterColumn(blindCols, col, op); probe {
			if blindFilterAccessFor(app, table, base, session) == blindFilterRefused {
				continue
			}
			if def := encryptedDefFor(app, table, base); def != nil {
				access := encryptedFieldAccessFor(app, app.DB, table, *def, session)
				encryptedScope, encryptedScopeArgs = access.scopePredicate(table)
			}
		}
		if blindCols[col] {
			if op == "=" {
				h, err := blindIndexForApp(app, values[0])
				if err == nil && h != "" {
					col = col + blindColSuffix
					values[0] = h
				}
			} else if op == "IN" {
				// Hash every value in the list; preserve order so the
				// placeholder count is unchanged.
				parts := strings.Split(values[0], ",")
				hashed := make([]string, 0, len(parts))
				for _, p := range parts {
					h, err := blindIndexForApp(app, p)
					if err != nil || h == "" {
						continue
					}
					hashed = append(hashed, h)
				}
				if len(hashed) > 0 {
					col = col + blindColSuffix
					values[0] = strings.Join(hashed, ",")
				}
			}
		}
		var cond string
		if op == "IN" {
			parts := strings.Split(values[0], ",")
			placeholders := make([]string, len(parts))
			for i, p := range parts {
				placeholders[i] = "?"
				args = append(args, p)
			}
			cond = fmt.Sprintf("%s IN (%s)", col, strings.Join(placeholders, ","))
		} else {
			cond = fmt.Sprintf("%s %s ?", col, op)
			args = append(args, values[0])
		}
		if encryptedScope != "" {
			cond = "(" + cond + " AND " + encryptedScope + ")"
			args = append(args, encryptedScopeArgs...)
		}
		conditions = append(conditions, cond)
	}

	if len(conditions) > 0 {
		if strings.Contains(strings.ToUpper(query), "WHERE") {
			query += " AND " + strings.Join(conditions, " AND ")
		} else {
			query += " WHERE " + strings.Join(conditions, " AND ")
		}
	}

	return query, args
}

// applyAPIFilters wraps applyAPIWhere with ORDER BY + LIMIT/OFFSET
// composition. This is the canonical entry point for the row-fetch
// path in handleList; the COUNT(*) path uses applyAPIWhere directly
// since it neither orders nor paginates.
func applyAPIFilters(baseSQL string, r *http.Request, table string, validCols ...map[string]bool) (string, []any) {
	return applyAPIFiltersWithApp(baseSQL, r, table, nil, nil, validCols...)
}

func applyAPIFiltersWithApp(baseSQL string, r *http.Request, table string, app *App, session *Session, validCols ...map[string]bool) (string, []any) {
	query, args := applyAPIWhereWithApp(baseSQL, r, table, app, session, validCols...)

	// M-7: sorting honors the same mandatory, fail-closed allowlist as
	// filtering. Without an explicit allowlist we never emit a
	// client-controlled ORDER BY - an empty/absent allowlist permits no
	// sort column, so ?sort=<arbitrary_real_column> can't leak ordering
	// over columns the endpoint never meant to expose.
	hasAllowlist := len(validCols) > 0 && validCols[0] != nil
	allowed := map[string]bool{}
	if hasAllowlist {
		allowed = validCols[0]
	}

	// Sorting: ?sort=name&order=desc OR ?orderBy=col:desc
	// (validated against schema). Default order is by primary key
	// DESC - pre-v2.5.12 we always emitted `ORDER BY id DESC`, which
	// 500'd for tables whose PK isn't `id` (system_state has key TEXT
	// PRIMARY KEY, the agent saw the 500 with no clue why). Now we
	// look up the table's actual PK column from the allowlist and
	// fall back gracefully if there is none.
	sortField := r.URL.Query().Get("sort")
	sortOrder := r.URL.Query().Get("order")
	if orderBy := r.URL.Query().Get("orderBy"); sortField == "" && orderBy != "" {
		// orderBy=col:desc shorthand
		parts := strings.SplitN(orderBy, ":", 2)
		sortField = parts[0]
		if len(parts) == 2 {
			sortOrder = parts[1]
		}
	}
	// Sorting by a blind-index sibling orders rows by the HMAC, grouping
	// equal plaintexts - only for callers who may see the column unmasked.
	if base := strings.TrimSuffix(sortField, blindColSuffix); base != sortField && app != nil &&
		BlindIndexColumnsForTable(app.Encrypted, table)[base] && blindFilterAccessFor(app, table, base, session) != blindFilterAllRows {
		sortField = ""
	}
	if sortField != "" && isValidColumnName(sortField) && allowed[sortField] {
		if sortOrder == "" {
			sortOrder = "asc"
		}
		if strings.ToLower(sortOrder) == "desc" {
			query += fmt.Sprintf(" ORDER BY %s DESC", sortField)
		} else {
			query += fmt.Sprintf(" ORDER BY %s ASC", sortField)
		}
	} else if allowed["id"] {
		query += " ORDER BY id DESC"
	} else {
		// No `id` column - leave unordered. SQLite returns rows in
		// rowid order which is fine for tables with INTEGER PK; for
		// TEXT/UUID PK tables we'd need a per-table lookup, not
		// worth the round-trip when the caller can specify orderBy.
	}

	// Pagination: ?page=2&per_page=20. Keep this normalization shared with
	// the response envelope so its metadata describes the emitted query.
	perPage, offset := apiOffsetWindow(r)
	query += fmt.Sprintf(" LIMIT %d OFFSET %d", perPage, offset)

	return query, args
}

// maxAPIOffsetRows caps ?page= offset pagination. SQLite has no way to skip
// rows: OFFSET N reads and discards N rows, so ?page=2000000&per_page=500
// made one request walk (and with ?page= also COUNT) the whole table, and a
// loop of them pinned the tenant's pool. Keyset pagination (?cursor=) costs
// the same at any depth.
const maxAPIOffsetRows = 100000

// apiOffsetTooDeepError returns the 400 message for an offset beyond
// maxAPIOffsetRows, or "" when the request is within bounds.
func apiOffsetTooDeepError(r *http.Request) string {
	if r.URL.Query().Get("cursor") != "" {
		return ""
	}
	_, offset := apiOffsetWindow(r)
	if offset <= maxAPIOffsetRows {
		return ""
	}
	return fmt.Sprintf("offset pagination skips more than %d rows and is capped there. Use keyset pagination instead: ?cursor=<last id>&limit=N (start with ?cursor=0) returns next_cursor for the following page.", maxAPIOffsetRows)
}

// apiOffsetWindow supports the SDK's limit/offset pair without changing the
// established page/per_page contract. Explicit legacy controls win together;
// aliases otherwise keep the same default, size cap and maximum skipped rows.
func apiOffsetWindow(r *http.Request) (limit, offset int) {
	if r.URL.Query().Get("page") != "" || r.URL.Query().Get("per_page") != "" {
		page, perPage := apiOffsetPagination(r)
		return perPage, (page - 1) * perPage
	}
	limit = queryParamInt(r, "limit", 50)
	if limit > 500 {
		limit = 500
	}
	raw := r.URL.Query().Get("offset")
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		// Do not let an overflowing positive offset bypass the depth guard.
		if numErr, ok := err.(*strconv.NumError); ok && numErr.Err == strconv.ErrRange && !strings.HasPrefix(raw, "-") {
			return limit, maxAPIOffsetRows + 1
		}
		return limit, 0
	}
	if n > maxAPIOffsetRows {
		return limit, maxAPIOffsetRows + 1
	}
	if n > 0 {
		offset = int(n)
	}
	return limit, offset
}

func apiOffsetPagination(r *http.Request) (page, perPage int) {
	page = queryParamInt(r, "page", 1)
	perPage = queryParamInt(r, "per_page", 50)
	if perPage > 500 {
		perPage = 500
	}
	maxInt := int(^uint(0) >> 1)
	maxOffsetPage := maxInt / perPage
	if page-1 > maxOffsetPage {
		page = maxOffsetPage + 1
	}
	return page, perPage
}

// selectFields limits returned fields: ?fields=name,email
func selectFields(r *http.Request, defaultFields string) string {
	fields := r.URL.Query().Get("fields")
	if fields == "" {
		return defaultFields
	}
	// Validate field names (prevent injection)
	var safe []string
	for _, f := range strings.Split(fields, ",") {
		f = strings.TrimSpace(f)
		// Only allow alphanumeric and underscore
		valid := true
		for _, c := range f {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
				valid = false
				break
			}
		}
		if valid && f != "" {
			safe = append(safe, f)
		}
	}
	if len(safe) == 0 {
		return defaultFields
	}
	return strings.Join(safe, ", ")
}

func queryParamInt(r *http.Request, key string, defaultVal int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return defaultVal
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		return defaultVal
	}
	return n
}

// ===== Dynamic Route Params =====

// LoadDynamicPages handles pages with :param in filename.
// e.g., deals_[id].html → /deals/:id
func ResolveDynamicRoute(pages map[string]*Page, path string) (*Page, map[string]string) {
	// Try exact match first
	if p, ok := pages[path]; ok {
		return p, nil
	}

	// Try dynamic routes
	for route, page := range pages {
		if !strings.Contains(route, ":") {
			continue
		}
		params := matchDynamicRoute(route, path)
		if params != nil {
			return page, params
		}
	}

	return nil, nil
}

func matchDynamicRoute(pattern, path string) map[string]string {
	patternParts := strings.Split(pattern, "/")
	pathParts := strings.Split(path, "/")

	if len(patternParts) != len(pathParts) {
		return nil
	}

	params := make(map[string]string)
	for i, pp := range patternParts {
		if strings.HasPrefix(pp, ":") {
			params[strings.TrimPrefix(pp, ":")] = pathParts[i]
		} else if pp != pathParts[i] {
			return nil
		}
	}

	return params
}
