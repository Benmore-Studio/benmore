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
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ===== 404 / 500 Error Pages =====

// writeUnmatchedAPINotFound is the answer for an /api/ path with no route.
// A table the caller may not reach answers exactly the same (EnforceCRUDAccess):
// it answered Go's text/plain "404 page not found" instead, so a signed-in
// user could tell a real admin-only table from a name that matches nothing
// and list the app's tables. Because both answer these bytes, the message
// names both causes; it said only "no API route matches this path", which
// sent developers whose access rule refused the call hunting for a typo.
func writeUnmatchedAPINotFound(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNotFound)
	fmt.Fprint(w, unmatchedAPINotFoundBody)
}

// unmatchedAPINotFoundBody is the one body of writeUnmatchedAPINotFound. Its
// `docs` is where the rule is documented (refusal_docs.go).
var unmatchedAPINotFoundBody = `{"error":"not_found","message":"no API route matches this path, or the app's access rules do not let you use it","docs":"` + refusalDocsAt("not_found", "") + `"}`

func notFoundHandler(app *App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// An unmatched /api/* path must NEVER return HTML - not the SPA
		// index.html (GET) nor the HTML 404 page (other methods). Both make
		// a client's `await res.json()` choke on '<', and worse, a cached
		// 200-HTML for a not-yet-deployed flow path sticks in the CDN and
		// shadows the flow once it IS deployed. Emit a real JSON 404 with
		// `no-store` so the CDN won't cache it. (v2.7.139)
		if strings.HasPrefix(r.URL.Path, "/api/") {
			writeUnmatchedAPINotFound(w)
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

// corsExposedHeaders are the response headers an allowed cross-origin page may
// read beyond the CORS-safelisted ones.
const corsExposedHeaders = "X-Limit-Capped, " + ignoredParamsHeader + ", " + ignoredFieldsHeader + ", X-Stripped-Fields"

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
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-CSRF-Token, HX-Request, X-Benmore-Background")
			// The CRUD answers say in these headers that a list was capped or
			// that a field or parameter was not applied; without this a
			// cross-origin page could not read them.
			w.Header().Set("Access-Control-Expose-Headers", corsExposedHeaders)
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

		// ?deep=1 is the readiness check for external monitors
		// (health_probe.go): a bounded database probe and the cgroup's
		// memory pressure, answered 503 with a reason before anything below
		// can wait on a stalled database. Plain /health is unchanged.
		ctx := r.Context()
		deep := healthDeepRequested(r)
		var readiness healthReadiness
		if deep {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, healthDeepBudget)
			defer cancel()
			readiness = app.healthReadiness.read(ctx, app.DB)
			if reason := readiness.notReadyReason(); reason != "" {
				w.WriteHeader(http.StatusServiceUnavailable)
				json.NewEncoder(w).Encode(map[string]any{
					"status":            "unhealthy",
					"ready":             false,
					"reason":            reason,
					"version":           version,
					"instance_id":       runtimeInstanceID,
					"reload_generation": app.reloadGeneration.Load(),
				})
				return
			}
		}

		status := "healthy"
		httpStatus := http.StatusOK
		checks := make(map[string]any)

		// 1. Database: actual query, not just ping - measures real latency
		dbStart := time.Now()
		var dbOK int
		err := app.DB.QueryRowContext(ctx, "SELECT 1").Scan(&dbOK)
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
		app.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM _benmore_jobs WHERE status = 'pending'").Scan(&pendingJobs)
		app.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM _benmore_jobs WHERE status = 'failed'").Scan(&failedJobs)
		app.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM _benmore_jobs WHERE status = 'running'").Scan(&runningJobs)
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

		// 5. Point-in-time recovery: whether the WAL shipper is covering
		// this app (a hosted app without a WAL session, or failing uploads,
		// reports degraded; the app keeps serving either way).
		if pitr, ok := walCoverageHealth(app); ok {
			checks["pitr"] = pitr
		}

		// 6. Sessions: active count
		var activeSessions int64
		app.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM _benmore_sessions WHERE datetime(expires_at) > datetime('now')").Scan(&activeSessions)
		checks["sessions"] = map[string]any{"active": activeSessions}

		// 7. Database file: data.db is still the file this process opened
		// (db_file_watch.go; `benmore serve` only). Replaced or deleted
		// degrades the status; the app keeps serving. A hosted app also
		// names the state in a header for the router to relay
		// (router_db_file_alert.go), which strips it from what it forwards.
		if dbFile, ok := dbFileHealth(app); ok {
			checks["db_file"] = dbFile
			if dbFile.State != dbFileOK {
				if status == "healthy" {
					status = "degraded"
				}
				if hostedTenantProcess() {
					w.Header().Set(dbFileAlertHeader, dbFile.State)
				}
			}
		}

		// Anonymous: basic status only. Admin: full details.
		// Prevents infrastructure reconnaissance from unauthenticated users.
		// The detail is an admin-management report no scope names, so it
		// needs the admin's unscoped credential (IsAdminConsole): a scoped
		// token an admin minted for an integration gets the basic status.
		session := getSession(app, r)
		isAdmin := session != nil && session.IsAdminConsole()

		resp := map[string]any{
			"status":            status,
			"version":           version,
			"instance_id":       runtimeInstanceID,
			"reload_generation": app.reloadGeneration.Load(),
		}
		if deep {
			resp["ready"] = httpStatus == http.StatusOK
			if httpStatus != http.StatusOK {
				resp["reason"] = "database_error"
			}
		}
		if isAdmin {
			// 8. Readiness (health_probe.go): shown, never changing a plain
			// answer's status, which restarts and releases wait on.
			if !deep {
				readiness = app.healthReadiness.read(ctx, app.DB)
			}
			checks["db_probe"] = readiness.DB
			if readiness.Memory != nil {
				checks["memory"] = readiness.Memory
			}
			// 9. Retention: how many declared policies run, and which do
			// not (a retention.yaml keyed by table name runs none).
			if retention, ok := retentionHealth(app); ok {
				checks["retention"] = retention
			}
			if counts, err := errorHealthCounts(r.Context(), app); err == nil {
				checks["errors"] = counts
			} else {
				checks["errors"] = map[string]string{"status": "unavailable"}
			}
			resp["uptime"] = time.Since(startTime).String()
			resp["checks"] = checks
		}

		w.WriteHeader(httpStatus)
		json.NewEncoder(w).Encode(resp)
	}
}

var startTime = time.Now()

// ===== Graceful Shutdown =====

// serverShutdown is closed when graceful shutdown begins. Server.Shutdown
// closes the listener at once and then waits for in-flight requests, and an
// SSE stream never finishes on its own: with one browser tab open a restart
// waited the whole 10 s deadline while new connections were refused, and
// the router answered an error page for that window plus the boot (seen as
// ~10-30 s of 502s on a production app after `benmore restart`). Streams end
// when it closes; EventSource reconnects to the new process.
var serverShutdown = struct {
	sync.Mutex
	ch chan struct{}
}{ch: make(chan struct{})}

func serverShutdownSignal() <-chan struct{} {
	serverShutdown.Lock()
	defer serverShutdown.Unlock()
	return serverShutdown.ch
}

func beginServerShutdown() {
	serverShutdown.Lock()
	defer serverShutdown.Unlock()
	select {
	case <-serverShutdown.ch:
	default:
		close(serverShutdown.ch)
	}
}

func startServerWithGracefulShutdown(server *http.Server, dev bool) error {
	server.RegisterOnShutdown(beginServerShutdown)
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
	// Boolean columns: true/false and 1/0 bind as the stored 1/0
	// (crud_boolean_filter.go). handleList has already refused a value
	// that is no boolean on a Prisma Boolean.
	boolCols := listBooleanFilterColumns(r, app, table)
	// DateTime columns: a value that parses as an instant is compared as one
	// (crud_datetime_filter.go), whatever spelling each row was stored in.
	instantCols := listInstantFilterColumns(r, app, table)
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
		// Canonical 1/0 text before the blind-index rewrite below, which
		// hashes the same text the write path stored; bound as an integer
		// further down when the column is compared directly.
		boolBind := false
		if boolCols[col] != 0 && booleanFilterOperand(op) {
			values[0], _ = canonicalBooleanFilterText(values[0], op == "IN")
			boolBind = !blindCols[col]
		}
		bindValue := func(v string) any {
			if boolBind {
				if n, ok := parseBooleanFilterValue(v); ok {
					return n
				}
			}
			return v
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
		var instantArgs []any
		if instantCols[col] {
			cond, instantArgs, _ = instantListFilter(quoteColumn(table, col), op, values[0])
		}
		if cond != "" {
			args = append(args, instantArgs...)
		} else if op == "IN" {
			parts := strings.Split(values[0], ",")
			placeholders := make([]string, len(parts))
			for i, p := range parts {
				placeholders[i] = "?"
				args = append(args, bindValue(p))
			}
			cond = fmt.Sprintf("%s IN (%s)", quoteColumn(table, col), strings.Join(placeholders, ","))
		} else {
			// Quoted and qualified (quoteColumn): a column named like an SQL
			// keyword (`order`, `group`, a custom field) is still the column.
			cond = fmt.Sprintf("%s %s ?", quoteColumn(table, col), op)
			args = append(args, bindValue(values[0]))
		}
		if encryptedScope != "" {
			cond = "(" + cond + " AND " + encryptedScope + ")"
			args = append(args, encryptedScopeArgs...)
		}
		conditions = append(conditions, cond)
	}

	if len(conditions) > 0 {
		if sqlHasWhereKeyword(query) {
			query += " AND " + strings.Join(conditions, " AND ")
		} else {
			query += " WHERE " + strings.Join(conditions, " AND ")
		}
	}

	return query, args
}

// sqlHasWhereKeyword reports whether query holds the keyword WHERE. Only a
// bare word counts: a quoted name ("where", or a table "elsewhere") and a
// longer word (whereabouts) are names, and taking one for the keyword
// appended ` AND ...` to a query that had no WHERE.
func sqlHasWhereKeyword(query string) bool {
	for _, token := range sqlTokenize(query) {
		if token.kind == sqlTokWord && strings.EqualFold(token.text, "WHERE") {
			return true
		}
	}
	return false
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

	// Default order is by primary key DESC - pre-v2.5.12 we always
	// emitted `ORDER BY id DESC`, which 500'd for tables whose PK isn't
	// `id` (system_state has key TEXT PRIMARY KEY, the agent saw the 500
	// with no clue why). Now we look up the table's actual PK column from
	// the allowlist and fall back gracefully if there is none.
	if ls := resolveAPIListSort(r, table, app, session, allowed); ls.column != "" {
		dir := "ASC"
		if ls.desc {
			dir = "DESC"
		}
		col := quoteColumn(table, ls.column)
		if listSortsByInstant(r, app, table, ls.column) {
			// A DateTime column a client can write sorts by instant, not by
			// stored spelling; created_at and updated_at keep the plain,
			// indexable sort.
			query += " ORDER BY " + instantOrderBy(col, dir)
		} else {
			query += fmt.Sprintf(" ORDER BY %s %s", col, dir)
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

// apiListSort is the ORDER BY a list request asked for and the sort
// parameters it could not apply.
type apiListSort struct {
	column  string   // "" = the default order
	desc    bool     // direction for column
	ignored []string // query keys not applied: sort, orderBy, order, order_by
}

// resolveAPIListSort reads ?sort=col&order=asc|desc, or ?orderBy=col[:dir]
// when sort is absent (a direction there overrides order), against the
// list's column allowlist. It is the only reader of these parameters, so
// the ORDER BY and the X-Ignored-Params report cannot disagree. A sort
// column that is not on the allowlist, a direction other than asc/desc (any
// case; applied as asc, as always), an orderBy beside a sort, an order with
// no sort column to apply to and order_by (never read) are reported, not
// refused: which sorts apply is unchanged. Hidden and encrypted sort
// columns are refused with 400/403 before this runs.
func resolveAPIListSort(r *http.Request, table string, app *App, session *Session, allowed map[string]bool) apiListSort {
	q := r.URL.Query()
	var out apiListSort
	ignore := func(key string) {
		if !slices.Contains(out.ignored, key) {
			out.ignored = append(out.ignored, key)
		}
	}
	sortField, fieldKey := q.Get("sort"), "sort"
	sortOrder, orderKey := q.Get("order"), "order"
	if orderBy := q.Get("orderBy"); sortField == "" && orderBy != "" {
		// orderBy=col:desc shorthand
		parts := strings.SplitN(orderBy, ":", 2)
		sortField, fieldKey = parts[0], "orderBy"
		if len(parts) == 2 {
			if sortOrder != "" {
				ignore("order")
			}
			sortOrder, orderKey = parts[1], "orderBy"
		}
	} else if orderBy != "" {
		ignore("orderBy")
	}
	if q.Get("order_by") != "" {
		ignore("order_by")
	}
	// Sorting by a blind-index sibling orders rows by the HMAC, grouping
	// equal plaintexts - only for callers who may see the column unmasked.
	if base := strings.TrimSuffix(sortField, blindColSuffix); base != sortField && app != nil &&
		BlindIndexColumnsForTable(app.Encrypted, table)[base] && blindFilterAccessFor(app, table, base, session) != blindFilterAllRows {
		sortField = ""
	}
	if sortField != "" && isValidColumnName(sortField) && allowed[sortField] {
		out.column = sortField
	} else if q.Get(fieldKey) != "" {
		ignore(fieldKey)
	}
	switch strings.ToLower(sortOrder) {
	case "", "asc":
	case "desc":
		out.desc = true
	default:
		ignore(orderKey)
	}
	if out.column == "" && sortOrder != "" && orderKey == "order" {
		ignore("order")
	}
	return out
}

// listSortParamsPresent names the sort parameters a request carries, for a
// read that applies no sort (a cursor page is always ordered by id).
func listSortParamsPresent(r *http.Request) []string {
	var out []string
	for _, key := range []string{"order", "orderBy", "order_by", "sort"} {
		if r.URL.Query().Get(key) != "" {
			out = append(out, key)
		}
	}
	return out
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

// listPageMax is the most rows one auto-CRUD list page returns, whatever
// limit or per_page asks for.
const listPageMax = 500

// listLimitCappedHeader is set to listPageMax on a list response whose
// request asked for more rows than one page holds. The cap used to be
// silent: an export asking for limit=5000 got 500 rows of a 28k-row table and
// could not tell that page from the whole table.
const listLimitCappedHeader = "X-Limit-Capped"

// offsetListLimitCapped reports whether an offset (non-cursor) list request
// asked for more than listPageMax rows, by the same keys apiOffsetWindow reads.
func offsetListLimitCapped(r *http.Request) bool {
	if r.URL.Query().Get("page") != "" || r.URL.Query().Get("per_page") != "" {
		return queryParamInt(r, "per_page", 50) > listPageMax
	}
	return queryParamInt(r, "limit", 50) > listPageMax
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
	if limit > listPageMax {
		limit = listPageMax
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
	if perPage > listPageMax {
		perPage = listPageMax
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
