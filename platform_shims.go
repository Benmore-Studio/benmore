//go:build !cli && !platform

package main

// platform_shims.go is the open-source framework seam. It is compiled ONLY
// in the framework server build (!cli && !platform) — the build that omits
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
//     DB handle, dashboard user sync, the edge-auth bridge). Every framework
//     call site already guards on the zero value these return ("platform
//     absent"), so the framework degrades cleanly to single-app behavior.

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
)

// ---- generic helpers (mirrors of the platform-build originals) ----

// clientIP extracts the originating client IP, honoring Cloudflare and the
// app proxy's forwarded headers. (Mirror of host.go.)
func clientIP(r *http.Request) string {
	if cf := r.Header.Get("CF-Connecting-IP"); cf != "" {
		return cf
	}
	if r.Header.Get("X-Benmore-App") != "" {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if i := strings.Index(xff, ","); i >= 0 {
				return strings.TrimSpace(xff[:i])
			}
			return strings.TrimSpace(xff)
		}
	}
	addr := r.RemoteAddr
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		return addr[:i]
	}
	return addr
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

// generateAPIToken mints a random opaque API token. (Mirror of platform.go.)
func generateAPIToken() string {
	b := make([]byte, 24)
	rand.Read(b)
	return "bm_" + hex.EncodeToString(b)
}

// hashAPIToken returns the SHA-256 hex of a token for at-rest storage.
// (Mirror of platform.go.)
func hashAPIToken(plaintext string) string {
	if plaintext == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}

// extractTableFromStmt returns the target table of an INSERT/UPDATE/DELETE
// statement, or "". (Mirror of mcp_tools_composers.go.)
func extractTableFromStmt(stmt string) string {
	trimmed := strings.TrimSpace(stmt)
	upper := strings.ToUpper(trimmed)
	upperNorm := strings.Join(strings.Fields(upper), " ")
	var prefix string
	switch {
	case strings.HasPrefix(upperNorm, "INSERT INTO "):
		prefix = "INSERT INTO "
	case strings.HasPrefix(upperNorm, "UPDATE "):
		prefix = "UPDATE "
	case strings.HasPrefix(upperNorm, "DELETE FROM "):
		prefix = "DELETE FROM "
	default:
		return ""
	}
	fields := strings.Fields(trimmed)
	prefixWords := len(strings.Fields(prefix))
	if len(fields) <= prefixWords {
		return ""
	}
	candidate := fields[prefixWords]
	end := 0
	for end < len(candidate) {
		c := candidate[end]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' {
			end++
			continue
		}
		break
	}
	if end == 0 {
		return ""
	}
	return candidate[:end]
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

// syncPlatformUserFromDashboard mirrors an app login into the platform users
// table. No platform → no-op.
func syncPlatformUserFromDashboard(app *App, email, passwordHash string) {}

// edgeBridgeUserID resolves a trusted edge-proxy user header. Edges are a
// platform feature, so there is never such a header here → 0 (no bridge).
func edgeBridgeUserID(r *http.Request) int64 { return 0 }

// sessionForEdgeBridge mints a session for the edge bridge. No edges → nil.
func sessionForEdgeBridge(app *App, userID int64) *Session { return nil }

// RegisterEdgeAuthOnApp mounts the edge consent routes on an app. No edges →
// nothing to mount.
func RegisterEdgeAuthOnApp(mux *http.ServeMux, app *App) {}

// loadAppBuildState hydrates build-time accounting from the platform DB. No
// platform → no-op (App.BuildSeconds stays zero).
func loadAppBuildState(app *App, subdomain string) {}

// checkStorageCap enforces a per-app storage quota. Quotas are a hosting/
// platform concern; the framework never caps a self-hosted app's storage, so
// this is a no-op (never blocked).
func checkStorageCap(app *App) (string, bool) { return "", false }

// oauthMintCLIToken issues a hosted-platform CLI api_token after OAuth. There
// is no platform here, so it never issues a token — OAuth just creates the
// session and falls through to the normal redirect.
func oauthMintCLIToken(w http.ResponseWriter, r *http.Request, email, cliPort string) bool {
	return false
}
