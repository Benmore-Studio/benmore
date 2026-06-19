//go:build !cli

package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// hotHandler wraps a swappable http.Handler. SIGHUP causes the per-app
// server to rebuild the mux + middleware chain and atomically swap the
// stored handler. New requests pick up the new state immediately; the
// listening socket is never closed, so there's zero downtime.
//
// Replaces the prior "systemctl restart" path for content/env reloads
// (which dropped connections, returned 502 at Cloudflare for ~1-2s, and
// re-fired cron jobs on every restart). SIGHUP keeps the socket alive.
type hotHandler struct {
	current atomic.Value // stores http.Handler
}

func (h *hotHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.current.Load().(http.Handler).ServeHTTP(w, r)
}

func (h *hotHandler) swap(next http.Handler) { h.current.Store(next) }

// hostedHotHandler is the singleton hot-swap handler for the per-app
// `benmore serve` process. SIGHUP handler reaches it through this
// package-level variable. Nil when not in per-app server mode.
var hostedHotHandler *hotHandler

// hotReloadOnce ensures we don't install duplicate signal handlers if
// StartServer is called twice in the same process (test code, host
// mode reusing the listener, etc.).
var hotReloadInstalled atomic.Bool

// installHotReloadSignal wires SIGHUP → in-process hot reload. The
// handler:
//   - re-reads YAML configs (app.yaml, hooks.yaml, flows.yaml, cron.yaml,
//     env.yaml + platform_env)
//   - stops the previous cron scheduler goroutine (via app.Stop close)
//     and starts a new one
//   - rebuilds the mux + middleware chain
//   - atomically swaps the served handler
//
// Idempotent CREATE-IF-NOT-EXISTS migrations run again on every reload,
// which is the right shape - they no-op when there's nothing to change.
// Heavy DDL (CREATE UNIQUE INDEX with prechecks) is the only case where
// a reload could surface a new error; that's still better than the old
// behavior (silent restart loop with no log signal).
func installHotReloadSignal(app *App, dev bool) {
	if !hotReloadInstalled.CompareAndSwap(false, true) {
		return
	}
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	go func() {
		for range ch {
			log.Printf("  SIGHUP - hot reloading app config + flows + cron")
			if err := hotReloadApp(app, dev); err != nil {
				log.Printf("  hot reload failed: %s (server kept serving previous config)", err)
				continue
			}
			log.Printf("  hot reload complete")
		}
	}()
}

// hotReloadApp re-runs the per-app loaders in place, stops the old cron
// scheduler, starts a new one, and swaps the served handler. Returns
// nil on success or an error if any loader failed (in which case the
// previous handler is still serving - failure is non-fatal).
//
// What's reloaded:
//   - app.yaml / Design / theme / SEO / auth / features
//   - schema.prisma (re-runs idempotent migrations)
//   - hooks.yaml / flows.yaml / workflows.yaml / cron.yaml
//   - env.yaml + platform_env
//   - the HTTP mux (route table)
//
// What's NOT reloaded (intentional):
//   - the DB connection (db.go would re-open; sessions + WAL state would churn)
//   - the SSE / WS hub (clients are mid-stream; killing them is rude)
//   - the listening socket (the whole point - no 502 window)
func hotReloadApp(app *App, dev bool) error {
	// Stop any goroutines that listen on app.Stop (cron, jobs worker,
	// retention sweeper). Then refresh the channel so a fresh round of
	// goroutines can restart with the new config.
	close(app.Stop)
	app.Stop = make(chan struct{})

	// Re-run the per-app loaders. reloadAppConfig is the in-place
	// variant of loadApp's config-reading section - it does NOT
	// re-open the DB or re-init the SSE hub.
	if err := reloadAppConfig(app); err != nil {
		return fmt.Errorf("config: %w", err)
	}

	baseURL := ""
	if app.Design != nil {
		baseURL = app.Design.SEO["url"]
	}
	if baseURL == "" {
		baseURL = fmt.Sprintf("http://localhost:%d", app.ServerPort)
	}
	mux := buildAppMux(app, dev, baseURL)
	handler := wrapMiddleware(mux, app, dev)
	hostedHotHandler.swap(handler)
	if dev || devReloadClientEnabled(app) {
		BroadcastReload("hot-reload")
	}
	return nil
}

// reloadAppConfig re-reads the per-app config files in place. Same
// content as loadApp's middle section but without DB open + first-time
// table creation (those happen exactly once at process start). Errors
// roll back nothing - caller decides whether to swap the handler.
func reloadAppConfig(app *App) error {
	// app.yaml - same loader-preference as app_loader.loadApp: prefer
	// the real YAML parser (populates Features struct), fall back to
	// the simple key-value parser for legacy app.yaml files. Treat nil
	// as "keep the previous Design" rather than an error so an in-
	// flight typo doesn't kick the server back to scaffold defaults.
	if cfg := LoadAppConfigYAML(app.Dir); cfg != nil {
		app.Design = cfg
	} else if cfg := LoadAppConfig(app.Dir); cfg != nil {
		app.Design = cfg
	}
	// schema - rerun migrations (idempotent).
	//
	// If LoadSchema reports a "disk I/O error" or "file is not a
	// database" the per-app DB handle is wedged - almost always
	// because something (a deploy, a push, manual file-level repair)
	// replaced the data.db file out from under the running process,
	// leaving us pointing at a deleted inode. No amount of SIGHUP can
	// recover this; the only fix is a fresh process with a fresh
	// open. Bail out so systemd's Restart=on-failure respawns us.
	// Pre-v2.7.5 the handler logged the error, kept serving the dead
	// handle, and every subsequent flow execution spammed the journal
	// with `[locks] cleanup error: file is not a database` while
	// returning 5xx on every write path. Agents had no escape hatch
	// because no CLI command shells out to `systemctl restart`.
	tables, deferredDDL, err := LoadSchema(app.DB, app.Dir)
	if err != nil {
		if isDBHandleWedged(err) {
			log.Fatalf(
				"FATAL: the per-app DB handle is wedged (%s) - the data.db file appears to have been replaced or corrupted under the running process. "+
					"Exiting so systemd restarts us. On restart, OpenDB will detect the corruption and auto-restore from the most recent "+
					"pre-migrate backup at .benmore/backups/pre-migrate-*.db (the original gets moved aside to data.db.corrupt-<timestamp> "+
					"for inspection). If you see this repeatedly without auto-recovery succeeding, every backup is also corrupt - check the "+
					".failed.sql files in migrations/ for the actual root cause.",
				err,
			)
		}
		return fmt.Errorf("schema: %w", err)
	}
	app.Tables = tables
	app.UUIDTables = DetectUUIDTables(tables)
	annotateFullTextFromPrisma(app.Dir, app.Tables)
	EnsureFTSTables(app.DB, app.Tables)
	if _, err := Migrate(app.DB, tables, false); err != nil {
		log.Printf("  hot reload migrate warning: %s", err)
	}
	// Indexes/views/triggers go in AFTER columns exist (see LoadSchema).
	ApplyDeferredDDL(app.DB, deferredDDL)
	// flows / hooks / workflows / cron. Same loader-preference as
	// app_loader.loadApp: prefer the real YAML parser (handles GHA shape
	// + flows/*.yaml multi-file layout), fall back to the legacy line-
	// based parser. Without this, every SIGHUP wipes GHA-shaped flows
	// because LoadFlows can't parse them - they were live after process
	// start but disappeared on the first hot reload.
	app.Flows = LoadFlowsYAML(app.Dir)
	if app.Flows == nil {
		app.Flows = LoadFlows(app.Dir)
	}
	app.Hooks = LoadHooksYAML(app.Dir)
	if app.Hooks == nil {
		app.Hooks = LoadHooks(app.Dir)
	}
	app.Workflows = LoadWorkflowsYAML(app.Dir)
	app.Cron = LoadCron(app.Dir)
	// v2.7.17: re-load the configs that hot-reload was missing.
	// Without these, every change to app.yaml's `roles:` / `access:` /
	// `aggregates:` / `groups:` was invisible until a full systemd
	// restart, and the bm.d.ts generator served stale types reflecting
	// the boot-time state. Same loader functions app_loader.loadApp uses
	// on cold start - keep them in sync if any are added.
	app.Roles = LoadRolesConfig(app.Dir)
	app.Access = LoadAccess(app.Dir)
	app.Scopes = LoadScopes(app.Dir)
	app.Group = LoadGroupConfig(app.Dir)
	app.Encrypted = LoadEncryptedFieldsConfig(app.Dir)
	// Restart cron scheduler on the new Stop channel.
	StartCronScheduler(app)
	// Re-load env.yaml. LoadEnv doesn't return an error - missing file
	// is treated as no-op there, so this is just a courtesy refresh of
	// the in-process env map. Platform env lives in the router
	// process's DB and is re-applied via writeAppEnvFile on env change.
	LoadEnv(app.Dir)
	return nil
}

// isDBHandleWedged reports whether the SQLite error indicates that the
// per-app handle is pointing at a file that no longer exists or is
// otherwise unusable. Two SQLite error messages cover the practical
// failure modes:
//
//   - "disk I/O error" / "no such file or directory" - the underlying
//     data.db file was unlinked while we held the handle.
//   - "file is not a database" - the handle is open but the bytes at
//     that path are no longer a valid SQLite database (truncated,
//     swapped to a different file, etc).
//
// Either way, the handle is irrecoverable in-process; only a fresh
// `os.Open` (i.e. a new process) restores normal operation.
func isDBHandleWedged(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "file is not a database") ||
		strings.Contains(msg, "disk I/O error") ||
		strings.Contains(msg, "database disk image is malformed")
}

// buildAppMux creates the full HTTP mux for an app with all route groups registered.
// This is the single source of truth for route registration - used by both StartServer and HostPlatform.
func buildAppMux(app *App, dev bool, baseURL string) *http.ServeMux {
	mux := http.NewServeMux()

	// Prometheus /metrics endpoint - dark unless BENMORE_METRICS_TOKEN
	// is set. Registered first so it doesn't get shadowed by clean-URL
	// fallbacks.
	RegisterMetricsRoute(mux)

	// Framework tables (auto-created)
	EnsureAuditLogTable(app.DB)
	// Audit-log shipper: tail _benmore_audit_log → POST to a configured
	// webhook destination. No-op unless BENMORE_AUDIT_WEBHOOK_URL is set.
	// Spawns one background goroutine per app, watched by app.Stop.
	StartAuditShipper(app)
	// Encryption key rotation endpoint (POST /api/_internal/encryption/rotate,
	// admin-only). Lives on the per-app mux because the rotation has to
	// run inside the per-app process - that's where appEncryptionKey + the
	// per-tenant Encrypted config are loaded; the router process has neither.
	RegisterEncryptionRotationRoute(mux, app)
	// Blind-index backfill endpoint - same architectural reason as
	// rotation (per-app process holds the derived key + the
	// `blind_index:` config). Admin-only, audit-logged.
	RegisterBlindIndexRoutes(mux, app)
	EnsureIdempotencyTable(app.DB)
	EnsureLocksTable(app.DB)
	EnsureNotificationsTable(app.DB)
	EnsureContextGraphTables(app.DB)
	EnsureRequestLogTable(app.DB)

	// Analytics - auto-enabled by default, disable with features.analytics: false
	RegisterAnalyticsRoutes(mux, app)

	// Populate the context graph from the app's current in-memory state.
	// Runs once at load; MCP write_file also triggers a rebuild so LLM
	// edits flow into the graph immediately. Extraction is O(pages) and
	// transactional, so the cost is in the tens of ms for typical apps.
	go RebuildContextGraph(app)

	// Cluster mode: SQLite-based pub/sub for horizontal scaling
	if IsClusterMode() {
		EnsureEventsTable(app.DB)
		EnsureRateLimitsTable(app.DB)
		StartEventPoller(app)
	}

	// Storage backend (local disk or S3)
	InitStorage(app.Dir)

	// Framework APIs
	RegisterAuditAPI(mux, app)
	syncAudit := app.Design != nil && app.Design.Auth["read_audit_sync"] == "true"
	InitReadAudit(app.DB, syncAudit)
	RegisterReadAuditAPI(mux, app)
	// API docs: public in dev, auth-required in production (opt-out via features.docs)
	if app.FeatureEnabled("docs") {
		RegisterAPIDocsRoutes(mux, app)
	}
	RegisterDeviceRoutes(mux, app)
	RegisterNotificationRoutes(mux, app)

	// Dynamic schema (custom fields API)
	RegisterCustomFieldRoutes(mux, app)

	// Tenant bootstrap: POST /api/_groups/create (no-op unless
	// groups.bootstrap is declared in app.yaml)
	RegisterGroupBootstrapRoute(mux, app)

	// API routes
	RegisterQueryAPI(mux, app)      // POST /api/_query - declarative cross-cut reads (scoped, column-validated)
	RegisterSchedulingAPI(mux, app) // /api/_scheduled + /api/_approvals - per-record deferred tasks + approvals
	RegisterLockRoutes(mux, app)    // must register before CRUD so /api/{table}/{id}/lock is more specific
	RegisterCRUD(mux, app)
	RegisterFileUploadRoute(mux, app)
	if NeedsAuth(app) {
		RegisterAuthRoutes(mux, app)
		RegisterMFARoutes(mux, app)
		RegisterMFALoginRoute(mux, app)
		RegisterOAuthTokensAPI(mux, app)
		RegisterRoleRoutes(mux, app)
	}
	// Edge auth consent flow + grants UI live on the parent app's
	// origin. Only relevant when the app declares auth.edge_scopes
	// in app.yaml - without that, edges remain anonymous and these
	// endpoints just refuse all consent requests.
	RegisterEdgeAuthOnApp(mux, app)
	// Auto-create user columns referenced by page require="" attributes
	EnsureRequiredUserFields(app.DB, app.Pages)
	// Auto-create user columns listed in auth.signup_fields
	if app.Design != nil {
		EnsureSignupFieldColumns(app.DB, app.Design.Auth["signup_fields"])
	}
	if len(app.Flows) > 0 {
		RegisterFlows(mux, app, app.Flows)
	}
	if app.Workflows != nil && len(app.Workflows.Workflows) > 0 {
		RegisterWorkflows(mux, app)
	}
	versionConfig := LoadVersionedConfig(app.Dir)
	if versionConfig != nil {
		RegisterVersioningAPI(mux, app, versionConfig)
	}
	if HasOAuthProviders(app.Dir) {
		EnsureRoleColumn(app.DB)
		RegisterOAuthRoutes(mux, app)
	}

	// CLI session-token mint - platform app ONLY. If a benmore.ai browser
	// session is already active, mint a CLI api_token straight from it so the
	// "Continue as <you>" button on /cli-auth finishes auth in one click - no
	// Google/password round-trip. Gated to _platform on purpose: only there is
	// the app session the real platform identity. An arbitrary app's
	// _benmore_users session is NOT a verified platform account, so exposing
	// this on any other app would let someone sign up as victim@example.com and
	// mint a platform CLI token for them (account takeover). The Google path is
	// safe by contrast because Google verifies the email. oauthMintCLIToken is
	// the same validate-port → mint → redirect helper the OAuth callback uses
	// (a no-op stub in the framework build, which then falls back to the form).
	if filepath.Base(app.Dir) == "_platform" {
		mux.HandleFunc("GET /auth/cli-session", func(w http.ResponseWriter, r *http.Request) {
			port := r.URL.Query().Get("port")
			// Validate numeric up front so it's safe to reflect into the
			// fallback redirect below (no header/redirect injection).
			if n, err := strconv.Atoi(port); err != nil || n <= 0 || n >= 65536 {
				http.Error(w, "invalid port", http.StatusBadRequest)
				return
			}
			sess := getSession(app, r)
			if sess == nil || sess.Email == "" {
				// No active session - send them to the sign-in form (port preserved).
				http.Redirect(w, r, "/cli-auth?port="+port, http.StatusSeeOther)
				return
			}
			if oauthMintCLIToken(w, r, sess.Email, port) {
				return // token minted + redirected to the localhost callback
			}
			// Framework build / mint unavailable - fall back to the form.
			http.Redirect(w, r, "/cli-auth?port="+port, http.StatusSeeOther)
		})
	}

	// Admin, billing, settings (admin panel opt-out via features.admin).
	// Auto-admin lives at /_admin (consistent with /_internal). Legacy
	// /admin path redirects to /_admin only when no user-defined page
	// claims /admin - keeps existing apps working while letting new
	// apps own the /admin URL for their own UI.
	EnsureRoleColumn(app.DB)
	if app.FeatureEnabled("admin") {
		RegisterAdminRoutes(mux, app)
		if _, userOwnsAdmin := app.Pages["/admin"]; !userOwnsAdmin {
			mux.HandleFunc("GET /admin", func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "/_admin", http.StatusTemporaryRedirect)
			})
		}
	}
	RegisterSettingsRoutes(mux, app)

	// Testing / feedback mode.
	//
	// When features.testing is enabled in app.yaml the feedback tables
	// are created so the visitor widget can write to them and so admin
	// tooling can read
	// from them. If a DEMO_PASSWORD is also set, the full demo-mode
	// gate and submission endpoints register on top via
	// RegisterDemoRoutes. If not, the tables are still present and
	// the MCP path works - the submission widget just won't accept
	// anonymous visitors without the gate.
	if app.FeatureEnabled("testing") {
		EnsureFeedbackTables(app.DB)
		demoPassword := GetAppEnv(app.Dir, "DEMO_PASSWORD")
		if demoPassword != "" {
			// Demo mode: password gate + feedback routes that accept demo tokens
			RegisterDemoRoutes(mux, app, demoPassword)
		} else {
			// No password: register feedback API with session auth only
			RegisterFeedbackAPI(mux, app)
		}
	} else if demoPassword := GetAppEnv(app.Dir, "DEMO_PASSWORD"); demoPassword != "" {
		// v2.7.164: the visitor-password gate no longer requires
		// features.testing. Previously set_demo_password returned
		// ok:true on an app without testing enabled and the app stayed
		// fully public - the gate middleware (wrapMiddleware) and this
		// login route were both behind the feature flag. The feedback
		// widget/API stays testing-only; only the gate stands alone.
		RegisterDemoLoginRoute(mux, app, demoPassword)
	}

	// Resource-level permissions (share/revoke API per table)
	RegisterPermissionRoutes(mux, app)

	// Webhook subscriptions
	RegisterWebhookRoutes(mux, app)

	// Background services
	StartJobWorker(app)
	CleanOldJobs(app)
	RegisterJobsAPI(mux, app)

	// Scheduled backups
	backupConfig := LoadBackupConfig(app.Dir)
	StartBackupWorker(app, backupConfig)
	StartLockCleanupWorker(app)
	// Per-app WAL truncation - keeps data.db-wal from bloating to 4MB
	// under continuous read traffic. Issue #1.
	StartAppWALMaintenance(app)

	// Presence - framework primitive replacing the hand-rolled
	// pagehide+heartbeat+cleanup-cron pattern that every chat / live /
	// huddle app re-derives. See presence.go and bm.presence() in
	// the SDK.
	EnsurePresenceTable(app.DB)
	RegisterPresenceRoutes(mux, app)
	StartPresenceSweeper(app)

	// Usage metering
	InitMetering(app.DB)
	RegisterUsageAPI(mux, app)

	// Data retention / TTL
	retentionPolicies := LoadRetentionConfig(app.Dir)
	StartRetentionWorker(app, retentionPolicies)

	// Materialized aggregates
	aggregateConfigs := LoadAggregateConfig(app.Dir)
	if len(aggregateConfigs) > 0 {
		StartAggregateWorker(app, aggregateConfigs)
		RegisterAggregateRoutes(mux, app)
	}

	// Real-time (opt-out via features.sse)
	if app.FeatureEnabled("sse") {
		RegisterSSERoutes(mux, app)
	}
	// WebSocket (bidirectional real-time, opt-out via features.ws)
	if app.FeatureEnabled("ws") {
		RegisterWebSocketRoutes(mux, app)
	}
	// Export and import are CLI-only - not HTTP endpoints
	RegisterFetchRoutes(mux, app)

	// Embedded libraries + PWA + dev tools
	RegisterTailwindRoute(mux)
	RegisterLibRoutes(mux)
	RegisterBMTypesRoute(mux, app)    // /_internal/types.d.ts - per-app TS defs
	RegisterUploadRoute(mux, app)     // POST /api/_upload - generic file upload (v2.7.20)
	RegisterWebRTCRoute(mux, app)     // GET /api/_webrtc/ice - STUN/TURN list (v2.7.28)
	RegisterBroadcastRoutes(mux, app) // POST /api/_broadcast/{publish,subscribe,stop} (v2.7.29)
	RegisterPWARoutes(mux, app)

	// Cron - scheduled jobs declared in cron.yaml. Background ticker
	// fires the matching schedule entries; integrates with the same
	// app.Stop channel as other workers so a graceful shutdown drains
	// in-flight jobs cleanly.
	StartCronScheduler(app)

	// Stripe billing - auto-creates _benmore_subscriptions +
	// _benmore_invoices and mounts /api/_billing/* when app.yaml
	// declares `billing_provider: stripe`. No-op otherwise.
	RegisterBillingRoutes(mux, app)

	// DSAR / GDPR data export. Auto-mounts /api/_my-data which
	// returns every row scoped to the current user.
	RegisterDSARRoute(mux, app)

	// Public status page rendered from request log + uptime stats.
	RegisterStatusRoute(mux, app)

	// Client-side error capture. Auto-mounts /api/_errors which
	// inserts into _benmore_client_errors and optionally forwards
	// to Sentry/Slack when configured.
	RegisterErrorCaptureRoute(mux, app)

	// Image transforms. /api/_images/transform?src=&w=&fmt= takes
	// any /uploads/* image and returns a resized/re-encoded copy,
	// cached to disk under uploads/_transforms/ keyed by params.
	RegisterImageTransformRoute(mux, app)
	RegisterInstallRoute(mux, app)
	RegisterInstallQRRoute(mux)
	RegisterRecordingRoutes(mux, app)

	// PDF generation (renders any page to PDF via headless Chrome)
	RegisterPDFRoutes(mux, app)

	// Health check
	mux.HandleFunc("GET /health", healthHandler(app))

	// Page routes - all registered explicitly, including dynamic routes.
	// Dynamic routes use :param in filenames (e.g., contacts-:id.html → /contacts/:id).
	// Converted to Go 1.22 {param} syntax for proper mux registration.
	for route, page := range app.Pages {
		p := page
		p.Require = ExtractPageRequire(p.RawHTML)

		// Convert :param to {param} for Go 1.22 mux
		muxPattern := route
		if strings.Contains(route, ":") {
			parts := strings.Split(route, "/")
			for i, part := range parts {
				if strings.HasPrefix(part, ":") {
					parts[i] = "{" + strings.TrimPrefix(part, ":") + "}"
				}
			}
			muxPattern = strings.Join(parts, "/")
		}

		handler := func(w http.ResponseWriter, r *http.Request) {
			// Convert Go 1.22 path values back to query params for template access
			if strings.Contains(route, ":") {
				q := r.URL.Query()
				parts := strings.Split(route, "/")
				for _, part := range parts {
					if strings.HasPrefix(part, ":") {
						paramName := strings.TrimPrefix(part, ":")
						q.Set(paramName, r.PathValue(paramName))
					}
				}
				r.URL.RawQuery = q.Encode()
			}
			servePage(w, r, app, p, dev)
		}
		if p.Require != "" {
			handler = RequireMiddleware(app, p, handler)
		}
		// role="public" means "anyone can view" - don't wrap with middleware.
		if pageRole := extractPageRole(p.RawHTML); pageRole != "" && pageRole != "public" {
			handler = RoleMiddleware(app, p, handler)
		}
		pattern := fmt.Sprintf("GET %s", muxPattern)
		if route == "/" {
			pattern = "GET /{$}"
		}
		// Recover-wrap the registration so a user page that collides
		// with a framework-reserved route (e.g. /api/_*, internal helpers)
		// doesn't crash the whole hosted process. Framework routes registered
		// earlier in buildAppMux always win on collision; the user page is
		// skipped with a clear log line for the dashboard to surface.
		// Issue #6: framework panics on route collision - this is the fix.
		func() {
			defer func() {
				if rec := recover(); rec != nil {
					log.Printf("  [%s] route conflict: page %q collides with framework route - skipped (%v)", filepath.Base(app.Dir), route, rec)
				}
			}()
			if p.Auth == "required" || p.Require != "" {
				mux.HandleFunc(pattern, AuthMiddleware(app, p, handler))
			} else {
				mux.HandleFunc(pattern, handler)
			}
		}()
	}

	// 404 handler - no catch-all. All routes registered explicitly above.
	// This handles truly unmatched paths for ALL methods (not just GET).
	notFound := notFoundHandler(app)
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		notFound(w, r)
	})
	mux.HandleFunc("POST /", func(w http.ResponseWriter, r *http.Request) {
		notFound(w, r)
	})
	mux.HandleFunc("PATCH /", func(w http.ResponseWriter, r *http.Request) {
		notFound(w, r)
	})
	mux.HandleFunc("DELETE /", func(w http.ResponseWriter, r *http.Request) {
		notFound(w, r)
	})
	mux.HandleFunc("PUT /", func(w http.ResponseWriter, r *http.Request) {
		notFound(w, r)
	})

	// Static files + uploads + favicon
	// SECURITY: all file paths sanitized to prevent directory traversal
	mux.HandleFunc("GET /static/", func(w http.ResponseWriter, r *http.Request) {
		requested := filepath.Clean(strings.TrimPrefix(r.URL.Path, "/static/"))
		// v2.7.21+: TSX-by-default. When the agent writes static/index.tsx,
		// the HTML still references /static/index.js - we look for a .tsx
		// counterpart, transpile via embedded esbuild (Go API; no Node),
		// serve the JS. Cached in-memory by file mtime.
		if serveTSXIfPresent(w, r, app, requested) {
			return
		}
		if !dev {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		fullPath := filepath.Join(app.Dir, "static", requested)
		// Verify path stays within static directory. Separator-terminated
		// prefix check (not bare HasPrefix) so a sibling like `static-old/`
		// can't be reached via `/static/../static-old/x` - same containment
		// bug class as the platform deploy extractor. ServeMux normalizes
		// `..` before routing, so this is defense-in-depth, but it must be
		// correct regardless of the front proxy.
		staticRoot := filepath.Join(app.Dir, "static")
		if fullPath != staticRoot && !strings.HasPrefix(fullPath, staticRoot+string(filepath.Separator)) {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, fullPath)
	})
	mux.HandleFunc("GET /uploads/", func(w http.ResponseWriter, r *http.Request) {
		relativePath := filepath.Clean(strings.TrimPrefix(r.URL.Path, "/uploads/"))
		fullPath := filepath.Join(app.Dir, "uploads", relativePath)
		// Verify path stays within uploads directory (separator-terminated
		// prefix - see the /static/ handler above for the rationale).
		uploadsRoot := filepath.Join(app.Dir, "uploads")
		if fullPath != uploadsRoot && !strings.HasPrefix(fullPath, uploadsRoot+string(filepath.Separator)) {
			http.NotFound(w, r)
			return
		}
		// Private files require signed URLs
		if strings.HasPrefix(relativePath, "private/") || strings.HasPrefix(relativePath, "private\\") {
			if !ValidateSignedURL(relativePath, r) {
				http.Error(w, "Forbidden - invalid or expired signed URL", http.StatusForbidden)
				return
			}
		}
		if !dev {
			w.Header().Set("Cache-Control", "public, max-age=86400")
		}
		// Force download for active-content types so a user-uploaded
		// .html / .svg / .xml can't execute JS in the app's origin.
		// Extension allowlist for inline render covers the common safe
		// media types; everything else gets attachment disposition.
		applyUploadDispositionHeaders(w, fullPath)
		http.ServeFile(w, r, fullPath)
	})
	RegisterSignedURLRoutes(mux, app)
	mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		for _, name := range []string{"static/favicon.ico", "static/favicon.png", "favicon.ico", "favicon.png"} {
			path := filepath.Join(app.Dir, name)
			if _, err := os.Stat(path); err == nil {
				http.ServeFile(w, r, path)
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	})

	// SEO feeds
	mux.HandleFunc("GET /sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Write([]byte(GenerateSitemap(app, baseURL)))
	})
	mux.HandleFunc("GET /robots.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(GenerateRobots(baseURL)))
	})
	mux.HandleFunc("GET /llms.txt", func(w http.ResponseWriter, r *http.Request) {
		// Respect features.docs visibility for LLM discoverability endpoints
		if app.Design != nil && app.Design.Features != nil && app.Design.Features.DocsRequireAuth() {
			session := getSession(app, r)
			if session == nil {
				http.Error(w, "authentication required", http.StatusUnauthorized)
				return
			}
		}
		w.Header().Set("Content-Type", "text/plain")
		// Hand-authored override: a static/llms.txt in the app is served
		// verbatim; the auto-generated public-page list is the fallback.
		if b, err := os.ReadFile(filepath.Join(app.Dir, "static", "llms.txt")); err == nil {
			w.Write(b)
			return
		}
		w.Write([]byte(GenerateLLMsTxt(app, baseURL)))
	})
	mux.HandleFunc("GET /llms-full.txt", func(w http.ResponseWriter, r *http.Request) {
		// llmstxt.org companion file - served at the root only when the app
		// ships one (static/llms-full.txt). Same visibility gate as /llms.txt.
		if app.Design != nil && app.Design.Features != nil && app.Design.Features.DocsRequireAuth() {
			session := getSession(app, r)
			if session == nil {
				http.Error(w, "authentication required", http.StatusUnauthorized)
				return
			}
		}
		b, err := os.ReadFile(filepath.Join(app.Dir, "static", "llms-full.txt"))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Write(b)
	})
	mux.HandleFunc("GET /.well-known/security.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(GenerateSecurityTxt(app, baseURL)))
	})
	mux.HandleFunc("GET /feed.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/atom+xml")
		w.Write([]byte(GenerateAtomFeed(app, baseURL)))
	})

	return mux
}

// wrapMiddleware applies the standard middleware chain to a handler.
// Order (outermost first): logger → gzip → CORS → security headers → rate limit
func wrapMiddleware(handler http.Handler, app *App, dev bool) http.Handler {
	// Per-IP/session request budget per minute for the NON-static
	// surface (static assets + /_internal libs are exempt - see
	// RateLimitMiddleware). 300 gives a data-heavy dashboard plenty of
	// headroom (a page firing 15-20 parallel /api/<table> calls can
	// still navigate ~15 pages/min). Override per-app with
	// the RATE_LIMIT_PER_MIN env var - 0 or negative disables
	// the limiter entirely.
	rateLimit := 300
	if dev {
		rateLimit = 2000
	}
	if v := strings.TrimSpace(GetAppEnv(app.Dir, "RATE_LIMIT_PER_MIN")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			rateLimit = n
		}
	}
	// rateLimit <= 0 disables HTTP rate limiting entirely (opt-out via
	// RATE_LIMIT_PER_MIN=0). Skip wrapping rather than creating a
	// zero-budget limiter that would 429 every request.
	if rateLimit > 0 {
		var limiter *RateLimiter
		if IsClusterMode() {
			limiter = NewSharedRateLimiter(app.DB, rateLimit, time.Minute)
		} else {
			limiter = NewRateLimiterStoppable(rateLimit, time.Minute, app.Stop)
		}
		handler = RateLimitMiddleware(limiter, handler)
	}
	handler = securityHeaders(handler, dev, app)
	handler = corsMiddleware(handler, app)
	if !dev {
		handler = gzipMiddleware(handler)
	}
	// Metrics middleware: counts requests + measures latency. Cheap
	// (atomic counters + a single time.Since per request). Mounted
	// inside compression so the timing doesn't include gzip work.
	handler = MetricsMiddleware(handler)
	handler = requestLogger(handler, dev)
	// _benmore_request_log persistence - powers the Runtime Logs tab
	// in the dashboard. Async insert per request; static assets skipped.
	handler = requestLogMiddleware(app, handler)
	// Outermost: recover from panics in any inner middleware/handler so a
	// single bad request doesn't take down the whole process. Issue #2.
	handler = recoverMiddleware(handler)

	// Demo mode gate: password-protect the entire app. Decoupled from
	// features.testing in v2.7.164 - DEMO_PASSWORD alone arms the gate
	// (see buildAppMux's RegisterDemoLoginRoute branch for the matching
	// login endpoint).
	if demoPassword := GetAppEnv(app.Dir, "DEMO_PASSWORD"); demoPassword != "" {
		handler = DemoGateMiddleware(demoPassword, handler)
	}

	return handler
}

// StartServer initializes and starts the HTTP server for an app.
func StartServer(app *App, port int, dev bool) error {
	app.DevMode = dev
	app.ServerPort = port

	baseURL := ""
	if app.Design != nil {
		baseURL = app.Design.SEO["url"]
	}
	if baseURL == "" {
		baseURL = fmt.Sprintf("http://localhost:%d", port)
	}

	mux := buildAppMux(app, dev, baseURL)
	handler := wrapMiddleware(mux, app, dev)

	// Install the hot-swap handler. SIGHUP rebuilds the mux + middleware
	// in place and atomic-swaps. Zero downtime - the listening socket
	// is never closed during a content/env reload.
	hh := &hotHandler{}
	hh.current.Store(handler)
	hostedHotHandler = hh
	installHotReloadSignal(app, dev)

	// Hosted per-app processes sit behind the router, which proxies to
	// 127.0.0.1:<port> (see router.go proxyTo). Binding loopback-only
	// keeps the per-app HTTP port off all external interfaces - defense
	// in depth beyond ufw. The per-app service unit sets BENMORE_BIND_LOOPBACK=1.
	// Standalone `benmore serve` (single-app self-host, local dev) keeps
	// binding all interfaces so it's directly reachable.
	addr := fmt.Sprintf(":%d", port)
	if os.Getenv("BENMORE_BIND_LOOPBACK") == "1" {
		addr = fmt.Sprintf("127.0.0.1:%d", port)
	}
	server := &http.Server{
		Addr:         addr,
		Handler:      hh,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	if dev {
		log.Printf("  benmore server running at http://localhost:%d", port)
		log.Printf("  serving app from: %s", app.Dir)
		log.Printf("  press Ctrl+C to stop")
	} else {
		log.Printf("  benmore server (production) on :%d", port)
	}

	return startServerWithGracefulShutdown(server, dev)
}

// applySecurityHeaders sets CSP, X-Frame-Options, and other security headers.
// Called directly in host mode (per-app) or via the middleware wrapper (single-app mode).
func applySecurityHeaders(w http.ResponseWriter, dev bool, app *App) {
	// Origins the Benmore Go desktop app uses for its webview. Allowed
	// to frame every deployed app so the desktop's in-app preview pane
	// can render live URLs. Tauri's `tauri://localhost` (prod) and
	// `http://localhost:1420` (vite dev) are unreachable from the open
	// web - only a Tauri process on the same machine can serve content
	// from them - so this doesn't open clickjacking surface.
	desktopFrameAncestors := "tauri://localhost https://tauri.localhost http://localhost:1420"

	// Allow the platform apex (e.g. benmore.ai) to frame apps so the hosted
	// builder's live preview pane can iframe the app. The router knows the
	// domain via platformDomain; per-app processes learn it from
	// BENMORE_PLATFORM_DOMAIN (platform.env). Plus the desktop webview origins.
	// `frame-ancestors 'none'` can't be combined with explicit origins, so we
	// list the allowed origins instead - same protection against open-web
	// framing while permitting the builder + desktop iframes.
	pd := platformDomain
	if pd == "" {
		pd = os.Getenv("BENMORE_PLATFORM_DOMAIN")
	}
	framePolicy := "frame-ancestors " + desktopFrameAncestors
	xframe := "" // X-Frame-Options can't allow specific origins; rely on CSP frame-ancestors.
	if pd != "" {
		framePolicy = fmt.Sprintf("frame-ancestors 'self' https://%s %s", pd, desktopFrameAncestors)
	}
	if dev {
		framePolicy = "frame-ancestors *"
		xframe = "SAMEORIGIN"
	}

	// 'unsafe-inline' stays for now - the framework injects inline
	// initializers (htmxInitScript, CSRF meta-reader, theme bootstrap)
	// without nonces, AND SSR (gotmpl) apps may include user-authored
	// inline scripts in their HTML. A clean nonce-based CSP requires:
	//   1. Per-request nonce threaded through every WrapLayout call
	//      site (~5 sites today) AND every inline-script emit site
	//      in layout.go / template.go / spa_runtime.go / edge_router.go.
	//   2. An app.yaml opt-in flag (security.csp_strict) so SSR apps
	//      with hand-coded inline scripts aren't broken on upgrade.
	//   3. SHA-256 hashes precomputed for the static framework inlines
	//      so the bootloader path doesn't need runtime nonce injection.
	// Scoped to a dedicated session - tracked in MEMORY.md punch list.
	//
	// 'unsafe-eval' was dropped earlier: React SPA mode compiles bundles
	// ahead of time via esbuild, so no app code needs runtime eval.
	scriptSrc := "'self' 'unsafe-inline'"
	styleSrc := "'self' 'unsafe-inline'"
	fontSrc := "'self'"
	// `'self'` is supposed to cover ws/wss to same-origin per CSP spec,
	// but several browsers (Firefox <93, Safari <14.1, some Chrome
	// edge cases) treat the scheme jump from https→wss as a CSP
	// violation and silently block the WebSocket. Add explicit
	// `wss:` (and `ws:` for local dev) so `/ws` works everywhere.
	connectSrc := "'self' wss: ws:"
	frameSrc := "'self'"
	// ESM/script CDNs agents are told they MAY import from (build.md names
	// esm.sh). Keep this list in sync with that doc - otherwise a documented
	// `import x from 'https://esm.sh/...'` gets silently CSP-blocked and the
	// whole module fails to load.
	for _, cdn := range []string{"https://unpkg.com", "https://cdn.jsdelivr.net", "https://esm.sh", "https://cdn.skypack.dev"} {
		scriptSrc += " " + cdn
		connectSrc += " " + cdn
	}
	// Cloudflare Web Analytics beacon allowance - opt-in. When serving behind
	// Cloudflare with Web Analytics enabled, the edge injects a beacon that
	// loads static.cloudflareinsights.com and calls home to
	// cloudflareinsights.com; allow both so those pages don't console-spam CSP
	// violations. Off by default (set BENMORE_CF_ANALYTICS=1 to enable) so a
	// self-hosted app never carries a Cloudflare origin in its CSP.
	if os.Getenv("BENMORE_CF_ANALYTICS") != "" {
		scriptSrc += " https://static.cloudflareinsights.com"
		connectSrc += " https://cloudflareinsights.com https://static.cloudflareinsights.com"
	}
	imgSrc := "'self' data:"
	styleSrc += " https://fonts.googleapis.com"
	fontSrc += " https://fonts.gstatic.com https://fonts.googleapis.com"
	// rsms.me hosts the Inter typeface's CSS + woff2 files and is the
	// reference distribution every agent reaches for first (the
	// official inter.style page recommends `<link rel="stylesheet"
	// href="https://rsms.me/inter/inter.css">` as the default install).
	// Several apps tried it, hit a console CSP
	// rejection, and burned a round swapping to Google Fonts. Allow it
	// here so the agent's first instinct works.
	styleSrc += " https://rsms.me"
	fontSrc += " https://rsms.me"

	// Media CDN (isolated user-content origin): allow app pages to
	// load uploaded images/video/audio from usercontent.<domain>. No-op
	// when the CDN backend isn't configured (local-disk media is same-origin).
	mediaSrc := "'self' data: blob:"
	if cfg := getPlatformMedia(); cfg != nil {
		imgSrc += " https://" + cfg.CDNDomain
		mediaSrc += " https://" + cfg.CDNDomain
	}

	// App-specific CSP overrides from seo: section in app.yaml
	// App-specific CSP allowlist extensions. Canonical form is the
	// top-level `csp:` block; values are appended to the framework
	// defaults (they widen the policy, never replace it). The legacy
	// `seo.<directive>_src` shape stays supported so older apps don't
	// regress.
	//
	//   csp:
	//     script_src: "https://maps.googleapis.com https://maps.gstatic.com"
	//     img_src:    "https://*.tile.openstreetmap.org"
	//     connect_src: "https://api.mapbox.com"
	//     frame_src:  "https://www.google.com"
	//     style_src:  "https://api.mapbox.com"
	//     font_src:   "https://fonts.gstatic.com"
	if app != nil && app.Design != nil {
		pick := func(directive string) string {
			if v := app.Design.CSP[directive]; v != "" {
				return v
			}
			return app.Design.SEO[directive]
		}
		if v := pick("frame_src"); v != "" {
			frameSrc += " " + v
		}
		if v := pick("connect_src"); v != "" {
			connectSrc += " " + v
		}
		if v := pick("script_src"); v != "" {
			scriptSrc += " " + v
		}
		if v := pick("style_src"); v != "" {
			styleSrc += " " + v
		}
		if v := pick("img_src"); v != "" {
			imgSrc += " " + v
		}
		if v := pick("font_src"); v != "" {
			fontSrc += " " + v
		}
	}

	csp := strings.Join([]string{
		"default-src 'self'",
		"script-src " + scriptSrc,
		"style-src " + styleSrc,
		"img-src " + imgSrc,
		"media-src " + mediaSrc,
		"font-src " + fontSrc,
		"connect-src " + connectSrc,
		"frame-src " + frameSrc,
		framePolicy,
	}, "; ")
	w.Header().Set("Content-Security-Policy", csp)

	if xframe != "" {
		w.Header().Set("X-Frame-Options", xframe)
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	if !dev {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	}

	// Permissions-Policy: default restrictive, but allow apps to declare needed permissions
	// Apps set permissions_policy in seo: to override (e.g., "camera=*, microphone=*")
	permPolicy := "geolocation=(), payment=()"
	if app != nil && app.Design != nil {
		if v := app.Design.SEO["permissions_policy"]; v != "" {
			permPolicy = v
		}
	}
	w.Header().Set("Permissions-Policy", permPolicy)
}

// securityHeaders wraps applySecurityHeaders as middleware for single-app mode.
func securityHeaders(next http.Handler, dev bool, app *App) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		applySecurityHeaders(w, dev, app)
		next.ServeHTTP(w, r)
	})
}

// resolveAppRole looks up the user's role from the app's group membership table.
// Returns the role string (e.g., "org", "mgmt", "site") or empty if not found.
func resolveAppRole(app *App, session *Session) string {
	if app.Group == nil || session == nil {
		return ""
	}
	// Check if the membership table has a "role" column
	if !hasColumn(app, app.Group.Table, "role") {
		return ""
	}
	var role string
	query := fmt.Sprintf("SELECT role FROM %s WHERE %s = ? LIMIT 1", app.Group.Table, app.Group.UserField)
	var lookupVal any
	if app.Group.UserField == "email" {
		lookupVal = session.Email
	} else {
		lookupVal = session.UserID
	}
	app.DB.QueryRow(query, lookupVal).Scan(&role)
	return role
}

// sensitiveGETParams are query keys that should NEVER appear in a GET
// URL. Only USER-supplied form values belong here. These are the keys a
// careless <form method="GET"> (instead of POST) on a password page
// would leak into the URL bar, browser history, server access logs,
// referer headers, and CDN logs. The framework strips them server-side.
//
// We deliberately do NOT include `token` here. Server-generated email
// tokens (password-reset, email-verify, OAuth callback) legitimately
// arrive via `?token=…` on a GET - that's how email-link flows work
// across the industry. Stripping it broke the reset flow.
var sensitiveGETParams = []string{"password", "_csrf", "csrf", "current_password", "new_password"}

func servePage(w http.ResponseWriter, r *http.Request, app *App, page *Page, dev bool) {
	// Defense in depth: any GET request that carries a sensitive query
	// param (e.g. ?password=…) means a <form> on a previous page was
	// missing method="POST" and the browser just leaked the password
	// into the URL bar, browser history, server logs, referer headers,
	// and Cloudflare logs. Strip the params and 303-redirect back to
	// the clean URL so the leaked values don't linger in this
	// response's referer/access log line either.
	if r.Method == "GET" {
		q := r.URL.Query()
		hit := false
		for _, k := range sensitiveGETParams {
			if q.Has(k) {
				q.Del(k)
				hit = true
			}
		}
		if hit {
			log.Printf("AUTH WARNING [%s] %s: form submitted via GET - sensitive params stripped. Check that the form has method=\"POST\".", app.Dir, r.URL.Path)
			clean := r.URL.Path
			if encoded := q.Encode(); encoded != "" {
				clean += "?" + encoded
			}
			http.Redirect(w, r, clean, http.StatusSeeOther)
			return
		}
	}
	// In dev mode, re-read the file on each request for hot reload
	if dev {
		data, err := os.ReadFile(filepath.Join(app.Dir, page.File))
		if err == nil {
			page.RawHTML = string(data)
			page.Auth, page.Scope, page.Title, page.Layout = ParsePageAttrs(page.RawHTML)
			page.Require = ExtractPageRequire(page.RawHTML)
			page.Redirect = ExtractPageRedirect(page.RawHTML)
		}
		app.Partials = reloadPartials(app.Dir)
	}

	session := getSession(app, r)
	if session != nil {
		Increment(meterScope(session), "page_views")
	}

	// Role-based redirect: <page redirect="admin:/admin,user:/dashboard,*:/home">
	// The `*` wildcard applies to ANYONE, including logged-out visitors - so
	// `redirect="*:/"` is the way to take a page offline (e.g. disable /docs).
	// Role-specific entries (admin:…, user:…) still only match a session.
	if page.Redirect != "" {
		role := ""
		if session != nil {
			role = session.Role
		}
		if target := matchRoleRedirect(page.Redirect, role); target != "" {
			http.Redirect(w, r, target, http.StatusSeeOther)
			return
		}
	}

	ctx := &RenderContext{
		Data:    make(map[string]any),
		User:    session,
		Request: r,
		App:     app,
		Page:    page,
	}

	ctx.Data["current_user"] = session
	if session != nil {
		ctx.Data["logged_in"] = true

		// Load ALL user columns into structured "user" object.
		// Enables {{user.email}}, {{user.plan}}, {{user.first_name}}, etc.
		userMap := LoadUserFields(app.DB, session.UserID)
		if userMap == nil {
			userMap = make(map[string]any)
		}
		// Ensure session-derived fields are always present (even if DB query fails)
		userMap["id"] = session.UserID
		userMap["email"] = session.Email
		userMap["role"] = session.Role
		if session.HasGroup() {
			userMap["org_id"] = session.GroupID
		}
		// Resolve app-level role from group membership table (e.g., "org", "mgmt", "site")
		if app.Group != nil && app.Group.Table != "" {
			appRole := resolveAppRole(app, session)
			if appRole != "" {
				userMap["app_role"] = appRole
			}
		}
		ctx.Data["user"] = userMap

		// Legacy flat keys for backwards compatibility
		ctx.Data["user_email"] = session.Email
		ctx.Data["user_id"] = session.UserID
		ctx.Data["user_role"] = session.Role
		// Multi-role: comma-separated list for the SSR `{{#role}}` block
		// and for `{{user_roles}}` lookups inside `<page require>` checks.
		ctx.Data["user_roles"] = strings.Join(session.Roles, ",")
		if session.HasGroup() {
			ctx.Data["user_group_id"] = session.GroupID
		}
		if appRole, ok := userMap["app_role"].(string); ok && appRole != "" {
			ctx.Data["user_app_role"] = appRole
		}
	}
	ctx.Data["page_title"] = page.Title
	ctx.Data["current_path"] = r.URL.Path

	for k, v := range r.URL.Query() {
		if len(v) > 0 {
			ctx.Data["param_"+k] = v[0]
		}
	}

	// Inject materialized aggregate values for {{aggregate.*}} templates
	InjectAggregateData(ctx)

	// Inject unread notification count for {{notification_count}} in templates
	InjectNotificationCount(ctx)

	content, err := RenderTemplate(app, page, ctx)
	if err != nil {
		if dev {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `<div class="benmore-error"><strong>Render Error</strong><pre>%s</pre></div>`, err.Error())
		} else {
			// Production: log full error, show generic message. ALSO
			// stash the error in the X-Benmore-Error response header
			// so the request_log middleware can record it - the
			// agent's `get_request_logs` then surfaces the real
			// failure cause via the `error` column. The header is
			// stripped from the outgoing response by the middleware
			// so it never reaches the user's browser.
			log.Printf("ERROR [%s] %s", page.File, err.Error())
			detail := err.Error()
			if len(detail) > 500 {
				detail = detail[:500] + "..."
			}
			w.Header().Set("X-Benmore-Error", fmt.Sprintf("[%s] %s", page.File, detail))
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		return
	}

	title := page.Title
	if title == "" {
		title = strings.Title(strings.TrimPrefix(page.Route, "/"))
	}

	// engine: raw - the user provided a full <!doctype html> document.
	// Skip the framework's HTML shell wrap AND the InjectCSRF walker -
	// the walker is a regex-based rewrite that finds every "<form" in
	// the response and stamps an <input> right after the opening tag.
	// In a raw page that includes inline <script type="text/babel">
	// blocks with JSX <form> elements, that means injecting an HTML
	// <input> into a JS string context, breaking the JSX parser.
	//
	// `engine: raw` was the legacy React-SPA shell - the framework no
	// longer ships a SPA runtime. Treat raw pages as opaque HTML:
	// inject CSRF + serve as-is. Anything React-specific in the
	// template (bm.mount, /_internal/bm.js, etc.) will load nothing,
	// which is the correct outcome for a stripped framework.
	if page.Engine == "raw" {
		html := injectCSRFMeta([]byte(content))
		html = injectCSRFFormFields(html, "")
		html = versionStaticAssets(html, app)
		html = versionBmInternal(html)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store, must-revalidate")
		w.Write(html)
		return
	}

	// Inject CSRF tokens into all forms (non-raw pages only)
	content = InjectCSRF(content)

	html := WrapLayoutWithPage(content, title, app, session, page)
	html = string(versionStaticAssets([]byte(html), app))
	html = string(versionBmInternal([]byte(html)))

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Every page render is dynamic (session, queries, agg vars).
	// Tell the browser explicitly not to cache so an LLM-driven edit
	// loop never produces phantom "but I just changed it" bugs.
	w.Header().Set("Cache-Control", "no-store, must-revalidate")
	w.Write([]byte(html))
}

// matchRoleRedirect checks a redirect spec like "admin:/admin,user:/dashboard,*:/home"
// against the user's role. Returns the target path if matched, empty string otherwise.
// The * wildcard matches any role. First match wins.
func matchRoleRedirect(spec, role string) string {
	for _, entry := range strings.Split(spec, ",") {
		entry = strings.TrimSpace(entry)
		parts := strings.SplitN(entry, ":", 2)
		if len(parts) != 2 {
			continue
		}
		matchRole := strings.TrimSpace(parts[0])
		target := strings.TrimSpace(parts[1])
		if matchRole == role || matchRole == "*" {
			return target
		}
	}
	return ""
}

func reloadPartials(dir string) map[string]string {
	partials := make(map[string]string)
	partialDir := filepath.Join(dir, "partials")
	entries, err := os.ReadDir(partialDir)
	if err != nil {
		return partials
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".html") {
			data, err := os.ReadFile(filepath.Join(partialDir, entry.Name()))
			if err == nil {
				partials["partials/"+entry.Name()] = string(data)
			}
		}
	}
	return partials
}

func requestLogger(next http.Handler, dev bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if dev {
			start := time.Now()
			rw := &responseWriter{ResponseWriter: w, status: 200}
			next.ServeHTTP(rw, r)
			log.Printf("  %s %s → %d (%s)", r.Method, r.URL.Path, rw.status, time.Since(start).Round(time.Millisecond))
		} else {
			next.ServeHTTP(w, r)
		}
	}
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

// Flush passes through to the underlying ResponseWriter if it supports Flusher.
// This is needed for SSE (Server-Sent Events) to work through the middleware chain.
func (rw *responseWriter) Flush() {
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap exposes the underlying ResponseWriter so http.NewResponseController
// can find the conn and call SetReadDeadline / SetWriteDeadline on it. SSE
// uses this to disable the server's 30s WriteTimeout for its long-lived
// stream - without Unwrap, Go's stdlib refuses to walk past this wrapper
// and the deadline call silently fails.
func (rw *responseWriter) Unwrap() http.ResponseWriter {
	return rw.ResponseWriter
}

// Hijack passes through to the underlying ResponseWriter if it supports
// Hijacker. Required for /ws - the WebSocket upgrade hijacks the raw
// TCP connection. Without this method on the middleware wrapper, the
// type assertion `w.(http.Hijacker)` inside wsUpgrade fails and the
// upgrade returns 400 "WebSocket upgrade required" even though the
// request was perfectly valid. Silent footgun: SSE worked because it
// uses Flusher (which we wired); WS broke because Hijacker wasn't.
func (rw *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := rw.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

func readFileFromDir(dir, name string) ([]byte, error) {
	return os.ReadFile(filepath.Join(dir, name))
}
