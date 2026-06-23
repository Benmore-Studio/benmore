//go:build !cli

package main

import (
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// cryptoRandRead is a thin shim so the lazy fallback path in
// csrfKeyBytes can fill a buffer with crypto/rand without dragging the
// rest of the file's imports around.
func cryptoRandRead(b []byte) { _, _ = cryptorand.Read(b) }

// Signed file URLs: time-limited access to private uploaded files.
// The developer marks files as private by storing them in uploads/private/.
// The runtime serves them only via signed URLs with HMAC + expiry.
//
// Generate: GET /api/_signed_url?path=private/file.pdf&expires_in=3600
// Access:   GET /uploads/private/file.pdf?expires=TIMESTAMP&sig=HMAC
//
// Uses the same HMAC key as CSRF tokens - no extra config needed.

// signedURLKey is the HMAC key for URL signing. Lazily derived from
// serverSecret on first use so callers that fire before
// RegisterSignedURLRoutes still get a secret-keyed MAC instead of the
// previous hardcoded fallback (which would let anyone with source
// access forge signed URLs and edge tokens).
var (
	signedURLKey   []byte
	signedURLKeyMu sync.Mutex
)

// oauthMaxSignedURLTTL is the hard ceiling on how long any minted signed URL
// (local-disk HMAC or CloudFront RSA-SHA1) stays valid. Signed URLs are bearer
// links with no per-request authz, so the TTL is the replay window if the link
// leaks - kept deliberately short. Tightened from the prior 24h.
const oauthMaxSignedURLTTL = 6 * time.Hour

// GenerateSignedURL creates a time-limited signed URL for a file path.
func GenerateSignedURL(host, filePath string, expiresIn time.Duration) string {
	expires := time.Now().Add(expiresIn).Unix()
	sig := computeURLSignature(filePath, expires)
	return fmt.Sprintf("/uploads/%s?expires=%d&sig=%s", filePath, expires, sig)
}

func computeURLSignature(path string, expires int64) string {
	mac := hmac.New(sha256.New, csrfKeyBytes())
	mac.Write([]byte(fmt.Sprintf("%s:%d", path, expires)))
	return hex.EncodeToString(mac.Sum(nil))
}

// csrfKeyBytes returns the HMAC key used for signed URLs AND for
// edge_auth tokens. Both must be unguessable to attackers, so we
// derive from serverSecret rather than ever returning a static literal.
func csrfKeyBytes() []byte {
	signedURLKeyMu.Lock()
	defer signedURLKeyMu.Unlock()
	if signedURLKey != nil {
		return signedURLKey
	}
	if serverSecret == "" {
		// serverSecret isn't initialized yet. Return an ephemeral key but DO
		// NOT cache it: a later call (once serverSecret is set) must derive and
		// cache the REAL key. Caching the ephemeral one (the old sync.Once bug)
		// permanently diverged signing from the real secret, breaking signed-URL
		// validation across instances and after restart. Anything signed in this
		// pre-init window won't validate later - by design (don't sign here).
		b := make([]byte, 32)
		cryptoRandRead(b)
		return b
	}
	h := hmac.New(sha256.New, []byte(serverSecret))
	h.Write([]byte("signed-url-key"))
	signedURLKey = h.Sum(nil)
	return signedURLKey
}

// ValidateSignedURL checks the HMAC signature and expiry on a file request.
func ValidateSignedURL(path string, r *http.Request) bool {
	expiresStr := r.URL.Query().Get("expires")
	sig := r.URL.Query().Get("sig")

	if expiresStr == "" || sig == "" {
		return false
	}

	expires, err := strconv.ParseInt(expiresStr, 10, 64)
	if err != nil {
		return false
	}

	// Check expiry
	if time.Now().Unix() > expires {
		return false
	}

	// Check signature
	expected := computeURLSignature(path, expires)
	return hmac.Equal([]byte(sig), []byte(expected))
}

// RegisterSignedURLRoutes adds the signed URL generation endpoint
// and protects /uploads/private/ with signature verification.
func RegisterSignedURLRoutes(mux *http.ServeMux, app *App) {
	// Derive signing key from the per-process server secret.
	// NOT from app.Dir (predictable) or a static string. csrfKeyBytes
	// also lazily derives this on first call, so we're idempotent
	// regardless of route registration order.
	h := hmac.New(sha256.New, []byte(serverSecret))
	h.Write([]byte("signed-url-key"))
	signedURLKeyMu.Lock()
	signedURLKey = h.Sum(nil)
	signedURLKeyMu.Unlock()

	// GET /api/_signed_url - generate a signed URL for a private file
	mux.HandleFunc("GET /api/_signed_url", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil {
			httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
			return
		}

		path := r.URL.Query().Get("path")
		if path == "" {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "path required"})
			return
		}

		expiresIn := 1 * time.Hour // default 1 hour
		if ei := r.URL.Query().Get("expires_in"); ei != "" {
			if seconds, err := strconv.Atoi(ei); err == nil && seconds > 0 {
				expiresIn = time.Duration(seconds) * time.Second
			}
		}

		// Clamp the lifetime to a safer ceiling. A signed URL is a BEARER
		// credential: once minted it grants access to the private object for its
		// whole TTL to anyone who holds the link (it lands in logs, referrers,
		// browser history, shared screenshots). The CloudFront variant is
		// canned-policy RSA-SHA1 (CloudFront's only supported signing alg - see
		// media_cdn.go signCloudFrontURL) and cannot be IP- or path-narrowed
		// here, so a leaked link is fully replayable until expiry. The previous
		// 24h ceiling is an unnecessarily wide replay window; 6h keeps legitimate
		// share/download flows working while shrinking exposure. Callers that
		// need shorter pass expires_in; nothing can exceed this cap.
		if expiresIn > oauthMaxSignedURLTTL {
			expiresIn = oauthMaxSignedURLTTL
		}

		// CDN-aware (v2.7.142): when the platform media CDN is configured and
		// `path` resolves to a CDN object, return a CloudFront URL directly -
		// SIGNED for private files, plain for public. Pre-fix, bm.signedUrl
		// only HMAC-signed an APP-HOST `/uploads/private/...` URL (validated by
		// SignedUploadMiddleware for LOCAL-disk files) - useless for files that
		// live on cdn.example.com after the media-CDN migration, which
		// forced apps to hand-write a serve_file flow. Now the SDK primitive
		// works for CDN-hosted private uploads too. cdnURLForServe clamps the
		// key's <vis>/<app>/ prefix to THIS app, so one app can't sign another's
		// file (the signing key is deployment-wide). Mirrors execStepServeFile.
		if cfg := getPlatformMedia(); cfg != nil {
			if cdnURL, isPrivate, ok := cdnURLForServe(app, path, cfg); ok {
				if !isPrivate {
					// Public CDN file - no signature needed, no authorization
					// beyond the session check above.
					httpJSON(w, http.StatusOK, map[string]any{"url": cdnURL, "path": cdnURL, "expires_in": 0})
					return
				}
				// PRIVATE file: minting a signed URL is an AUTHORIZATION
				// decision, and a bare session is not enough - that would let
				// any authed user sign any private file in the app. The caller
				// must name the RECORD that owns the file; we then run the FULL
				// read-authorization for that record (access mode incl.
				// role:/perm:, RBAC scope union, group + owner + ACL + tenant-
				// scoped grants, admin bypass) - identical to GET /api/<t>/<id>
				// - and confirm the record actually references this file. So a
				// signed URL is issued only to someone who could read the row
				// the file belongs to, honoring the whole RBAC model.
				rt := strings.TrimSpace(r.URL.Query().Get("record_table"))
				rid := strings.TrimSpace(r.URL.Query().Get("record_id"))
				if rt == "" || rid == "" {
					httpJSON(w, http.StatusForbidden, map[string]any{
						"error": "signing a private file requires its owning record: pass record_table + record_id (bm.signedUrl(path, {record:{table,id}})). The signature is authorized against that record's access policy - roles, perms, scopes, group/owner/ACL - not just a logged-in session.",
					})
					return
				}
				if !authorizeRecordReadForSigning(r, app, rt, rid) {
					httpJSON(w, http.StatusForbidden, map[string]any{"error": "not authorized to read the record that owns this file"})
					return
				}
				if !recordReferencesFile(app, rt, rid, path, cfg) {
					httpJSON(w, http.StatusForbidden, map[string]any{"error": "record_table/record_id does not reference this file"})
					return
				}
				expires := time.Now().Add(expiresIn).Unix()
				signed, err := signCloudFrontURL(cdnURL, expires, cfg.KeyPairID, cfg.PrivateKey)
				if err != nil {
					httpJSON(w, http.StatusInternalServerError, map[string]any{"error": "media signing unavailable"})
					return
				}
				httpJSON(w, http.StatusOK, map[string]any{"url": signed, "path": signed, "expires_in": int(expiresIn.Seconds())})
				return
			}
		}

		// Local-disk fallback: HMAC-signed app-host URL (SignedUploadMiddleware
		// validates it). Used off-platform / for files still on local disk.
		// PRIVATE local files get the SAME record-authorization as CDN ones -
		// a bare session must not be able to sign any /uploads/private/ path.
		if isPrivateUploadPath(path) {
			rt := strings.TrimSpace(r.URL.Query().Get("record_table"))
			rid := strings.TrimSpace(r.URL.Query().Get("record_id"))
			if rt == "" || rid == "" {
				httpJSON(w, http.StatusForbidden, map[string]any{
					"error": "signing a private file requires its owning record: pass record_table + record_id (bm.signedUrl(path, {record:{table,id}})). The signature is authorized against that record's access policy.",
				})
				return
			}
			if !authorizeRecordReadForSigning(r, app, rt, rid) {
				httpJSON(w, http.StatusForbidden, map[string]any{"error": "not authorized to read the record that owns this file"})
				return
			}
			if !recordReferencesLocalFile(app, rt, rid, path) {
				httpJSON(w, http.StatusForbidden, map[string]any{"error": "record_table/record_id does not reference this file"})
				return
			}
		}
		signedURL := GenerateSignedURL(r.Host, path, expiresIn)
		fullURL := fmt.Sprintf("%s://%s%s", protoOf(r), r.Host, signedURL)

		httpJSON(w, http.StatusOK, map[string]any{
			"url":        fullURL,
			"path":       signedURL,
			"expires_in": int(expiresIn.Seconds()),
		})
	})
}

// authorizeRecordReadForSigning reports whether the request's session may READ
// table/id under the FULL access model - the same decision GET /api/<table>/<id>
// makes: access mode (anon / authed / role:a,b / perm:res.act / admin / group /
// owner), RBAC scope union (checkScope), and per-row group/owner/ACL visibility
// (canAccessRow, admin bypass). No HTTP writes. Used to gate private-file
// signing so the signature inherits the owning record's access policy.
func authorizeRecordReadForSigning(r *http.Request, app *App, table, id string) bool {
	if app == nil || !safeIdent(table) || !appHasTable(app, table) {
		return false
	}
	hasUID := hasColumn(app, table, "user_id")
	hasGroupKey := app.Group != nil && app.Group.Key != "" && hasColumn(app, table, app.Group.Key)
	mode := app.Access.ModeFor(table, OpRead, hasUID, hasGroupKey)
	if mode == "off" {
		return false
	}
	session := getSession(app, r)
	if mode != "anon" && session == nil {
		return false
	}
	// Access-mode gate (role:/perm:/admin/group/owner/authed/everyone).
	if !app.Access.Allowed(mode, session, 0) {
		return false
	}
	// RBAC scope union (role → scopes, inheritance).
	if session != nil {
		if err := checkScope(session, table, "read"); err != nil {
			return false
		}
	}
	// Broadly-readable modes: the row is in scope by policy.
	if mode == "anon" || mode == "everyone" {
		return true
	}
	// Per-row: group / owner / explicit ACL grant / admin bypass.
	return canAccessRow(app, table, id, session)
}

// recordReferencesFile confirms the named row actually references `path` in one
// of its columns - so a caller can't pair a record they CAN read with another
// file's path. Compares canonical CDN forms (handles both the full CDN URL and
// the logical /uploads/... path). The read here is post-authorization, so an
// unscoped SELECT of the already-authorized row is fine.
func recordReferencesFile(app *App, table, id, path string, cfg *PlatformMediaConfig) bool {
	wantURL, _, ok := cdnURLForServe(app, path, cfg)
	if !ok {
		return false
	}
	rows, err := QueryRows(app.DB, fmt.Sprintf("SELECT * FROM %s WHERE id = ?", table), id)
	if err != nil || len(rows) == 0 {
		return false
	}
	for _, v := range rows[0] {
		s, isStr := v.(string)
		if !isStr || s == "" {
			continue
		}
		if gotURL, _, ok := cdnURLForServe(app, s, cfg); ok && gotURL == wantURL {
			return true
		}
	}
	return false
}

// recordReferencesLocalFile is recordReferencesFile for local-disk paths:
// confirms the row references `path` (modulo a leading slash) in some column.
func recordReferencesLocalFile(app *App, table, id, path string) bool {
	want := strings.TrimPrefix(path, "/")
	rows, err := QueryRows(app.DB, fmt.Sprintf("SELECT * FROM %s WHERE id = ?", table), id)
	if err != nil || len(rows) == 0 {
		return false
	}
	for _, v := range rows[0] {
		if s, ok := v.(string); ok && s != "" && strings.TrimPrefix(s, "/") == want {
			return true
		}
	}
	return false
}

func appHasTable(app *App, name string) bool {
	for _, t := range app.Tables {
		if t.Name == name {
			return true
		}
	}
	return false
}

// SignedUploadMiddleware intercepts requests to /uploads/private/ and
// requires a valid signed URL. Public uploads (not in private/) are served normally.
func SignedUploadMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only protect /uploads/private/ paths
		if len(r.URL.Path) > len("/uploads/private/") &&
			r.URL.Path[:len("/uploads/private/")] == "/uploads/private/" {

			// Extract the relative path after /uploads/
			relativePath := r.URL.Path[len("/uploads/"):]

			if !ValidateSignedURL(relativePath, r) {
				http.Error(w, "Forbidden - invalid or expired signed URL", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
