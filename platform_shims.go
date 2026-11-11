//go:build !cli && !platform

package main

// platform_shims.go is the open-source framework seam. It is compiled ONLY
// in the framework server build (!cli && !platform) - the build that omits
// every platform-tagged file. It provides two things the always-compiled
// framework runtime references:
//
//  1. Real implementations of small, generic helpers that happen to live in
//     platform-tagged files in the monorepo (clientIP, protoOf, …). The
//     product build (-tags platform) gets those same helpers from their
//     original files; this file is excluded there, so there is no duplicate
//     symbol. The implementations are kept byte-identical on purpose.
//
//  2. No-op / nil stubs for genuinely platform-only features (the platform
//     DB handle, dashboard user sync). Every framework
//     call site already guards on the zero value these return ("platform
//     absent"), so the framework degrades cleanly to single-app behavior.

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/http"
)

// ---- generic helpers (mirrors of the platform-build originals) ----

// clientIP returns the request's client address. No router exists in this
// edition, so its X-Benmore-App marker is never trusted; see client_ip.go.
func clientIP(r *http.Request) string {
	return resolveClientIP(r, false)
}

// protoOf returns the public-facing scheme, proxy-correct. (Mirror of router.go.)
func protoOf(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if v := r.Header.Get("X-Forwarded-Proto"); v != "" {
		return v
	}
	return "http"
}

// humanDuration formats a build duration for the "Built with Benmore" badge.
// (Mirror of build_time.go.)
func humanDuration(seconds int) string {
	if seconds < 1 {
		return "moments"
	}
	if seconds < 60 {
		return fmt.Sprintf("%ds", seconds)
	}
	if seconds < 3600 {
		mins := seconds / 60
		secs := seconds % 60
		if secs == 0 {
			if mins == 1 {
				return "1 minute"
			}
			return fmt.Sprintf("%d minutes", mins)
		}
		return fmt.Sprintf("%dm %ds", mins, secs)
	}
	hours := seconds / 3600
	mins := (seconds % 3600) / 60
	if mins == 0 {
		if hours == 1 {
			return "1 hour"
		}
		return fmt.Sprintf("%d hours", hours)
	}
	return fmt.Sprintf("%dh %dm", hours, mins)
}

// isInternalTable reports whether a table is a framework-internal table that
// should be hidden from app introspection. (Mirror of platform_dashboard.go.)
func isInternalTable(name string) bool {
	internal := map[string]bool{
		"_benmore_sessions":        true,
		"_benmore_idempotency":     true,
		"_benmore_locks":           true,
		"_benmore_jobs":            true,
		"_benmore_context_nodes":   true,
		"_benmore_context_edges":   true,
		"_benmore_request_log":     true,
		"_benmore_login_attempts":  true,
		"_benmore_password_resets": true,
		"_benmore_api_tokens":      true,
		"_benmore_custom_fields":   true,
		"_benmore_read_audit":      true,
		"_benmore_usage":           true,
		"_benmore_draft_capture":   true,
		"_benmore_events":          true,
		"_benmore_analytics":       true,
		"_benmore_visitors":        true,
		"_benmore_funnels":         true,
		"_benmore_security_scans":  true,
	}
	return internal[name]
}

// generateAPIToken mints a random opaque API token. (Mirror of platform_auth.go.)
func generateAPIToken() string {
	b := make([]byte, 24)
	rand.Read(b)
	return "bm_" + hex.EncodeToString(b)
}

// hashAPIToken returns the SHA-256 hex of a token for at-rest storage.
// (Mirror of platform_auth.go.)
func hashAPIToken(plaintext string) string {
	if plaintext == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}

// ---- platform-only feature stubs (no-op / nil = "platform absent") ----

// platformDB is the hosted control-plane database handle. It is always nil in
// the framework build; every framework call site is nil-guarded.
var platformDB *sql.DB

// platformDBConn returns the platform DB connection, or nil when absent.
func platformDBConn() *sql.DB { return nil }

// platformDomain is the hosting apex domain (e.g. apps.example.com); empty here.
var platformDomain string

// HostPlatform is the multi-tenant in-process host. It never exists in a
// single-app framework deployment; the framework only nil-checks the global
// (e.g. server.go's CSP frame-ancestors branch), never dereferences it.
type HostPlatform struct{}

var hostPlatform *HostPlatform

func platformAppEnv(dir string) (map[string]string, error) { return nil, nil }

// syncPlatformUserFromDashboard mirrors an app login into the platform users
// table. No platform → no-op.
func syncPlatformUserFromDashboard(app *App, email, passwordHash string) {}

// syncPlatformUserFromOAuth mirrors an OAuth sign-in into the platform users
// table. No platform → no-op.
func syncPlatformUserFromOAuth(app *App, email string) {}

// platformDashboardApp reports whether app is the platform dashboard app.
// Without the platform engine no app is.
func platformDashboardApp(app *App) bool { return false }

// platformEmailProved records an email proof made on the dashboard app. No
// platform → no-op.
func platformEmailProved(app *App, email string, passwordProved bool) {}

// platformPasswordChanged mirrors a dashboard password change or reset and
// revokes platform credentials. No platform → no-op.
func platformPasswordChanged(app *App, email, passwordHash string, emailProved bool) {}

// platformAccountDeleted revokes platform credentials of a deleted dashboard
// account. No platform → no-op.
func platformAccountDeleted(app *App, email string) {}

// handlePlatformAccountDeletion is the hosted dashboard's Delete account.
// Unreachable here: platformDashboardApp is false for every app.
func handlePlatformAccountDeletion(w http.ResponseWriter, r *http.Request, app *App) {
	http.NotFound(w, r)
}

// registerPlatformAccountDeletionRoutes mounts the hosted dashboard's
// account-deletion routes. No platform → nothing to mount.
func registerPlatformAccountDeletionRoutes(mux appRouteRegistrar, app *App) {}

// loadAppBuildState hydrates build-time accounting from the platform DB. No
// platform → no-op (App.BuildSeconds stays zero).
func loadAppBuildState(app *App, subdomain string) {}

// StartWALShipper is a platform durability feature. Framework/cloud builds
// keep local WAL maintenance only.
func StartWALShipper(app *App) {}

// checkStorageCap enforces a per-app storage quota. Quotas are a hosting/
// platform concern; the framework never caps a self-hosted app's storage, so
// this is a no-op (never blocked).
func checkStorageCap(app *App, projectedBytes int64) (string, bool) { return "", false }

// refuseRouterTenantData is the hosted router's tenant-data lock
// (router_tenant_data_lock.go). Framework and cloud builds have no router.
func refuseRouterTenantData(path string) error { return nil }

// storageLimitRemedy follows a storage refusal. Without plan limits the only
// way to reach one is a full disk.
func storageLimitRemedy() string { return "Delete data or free disk space, then retry." }

// oauthMintCLIToken issues a hosted-platform CLI api_token after OAuth. There
// is no platform here, so it never issues a token - OAuth just creates the
// session and falls through to the normal redirect.
func oauthMintCLIToken(w http.ResponseWriter, r *http.Request, app *App, email, cliPort string) bool {
	return false
}

// registerCLIDeviceRoutes serves CLI device login in the platform build only.
func registerCLIDeviceRoutes(mux appRouteRegistrar, app *App) {}

// dashboardIdentityFromRouter resolves the benmore.ai dashboard's caller from
// the platform router once the router owns its sign-in. No platform → the
// app resolves its own sessions.
func dashboardIdentityFromRouter(app *App, r *http.Request) (*Session, bool) { return nil, false }

// dashboardUsesRouterIdentity reports whether app is the dashboard with its
// sign-in owned by the platform router. No platform → never.
func dashboardUsesRouterIdentity(app *App) bool { return false }

// dashboardFlowWriteRefusal refuses a dashboard flow's write to credential
// tables the platform router owns. No platform → nothing is refused.
func dashboardFlowWriteRefusal(app *App, query string) error { return nil }
