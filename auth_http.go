//go:build !cli

package main

// Authentication request decoding, response formatting, redirects, and public user fields.

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// isSafeNext returns true only if next is a same-origin relative path.
// Rejects "//evil.com" and "/\evil.com" - browsers treat both as
// protocol-relative URLs and would redirect off-site.
func isSafeNext(next string) bool {
	if len(next) < 1 || next[0] != '/' {
		return false
	}
	if len(next) >= 2 && (next[1] == '/' || next[1] == '\\') {
		return false
	}
	return true
}

// authRedirect redirects to an auth page path with an optional error message.
// Error is passed as a query param so the developer's template can show it
// via {{param_error}}. This replaces all auto-generated page rendering.
// authRedirect ends a failed auth attempt. For browser clients it
// 303s back to the auth page with ?error=…; for SPA / API clients
// that asked for JSON (Accept: application/json) it returns a JSON
// error body so they can render the message inline without a redirect
// dance - critical for React/raw apps where /login and /signup don't
// have server-rendered counterparts.
func authRedirect(w http.ResponseWriter, r *http.Request, path, errMsg string) {
	if wantsJSON(r) {
		status := http.StatusBadRequest
		if errMsg == "Invalid credentials" {
			status = http.StatusUnauthorized
		} else if strings.Contains(errMsg, "Too many") {
			status = http.StatusTooManyRequests
		}
		httpJSON(w, status, map[string]any{"ok": false, "error": errMsg})
		return
	}
	if errMsg != "" {
		sep := "?"
		if strings.Contains(path, "?") {
			sep = "&"
		}
		path += sep + "error=" + url.QueryEscape(errMsg)
	}
	http.Redirect(w, r, path, http.StatusSeeOther)
}

// mergeJSONBodyIntoForm reads a JSON request body and copies each
// top-level key into r.PostForm / r.Form, so subsequent r.FormValue
// lookups work uniformly whether the client sent
// application/x-www-form-urlencoded or application/json. Called by
// the auth handlers so bm.api.post('/signup', {...}) (which sends
// JSON) behaves identically to a native <form method="POST"> submit.
// No-ops when Content-Type isn't JSON. Body is capped at 1MB.
func mergeJSONBodyIntoForm(r *http.Request) {
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	if !strings.Contains(ct, "application/json") {
		return
	}
	if r.Body == nil {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	r.Body.Close()
	if err != nil || len(body) == 0 {
		return
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return
	}
	// ParseForm initialises r.Form from the URL query (it won't read the
	// body since the content-type isn't form-encoded). Safe to call.
	_ = r.ParseForm()
	if r.PostForm == nil {
		r.PostForm = url.Values{}
	}
	if r.Form == nil {
		r.Form = url.Values{}
	}
	for k, v := range m {
		var s string
		switch x := v.(type) {
		case nil:
			s = ""
		case string:
			s = x
		case bool:
			if x {
				s = "true"
			} else {
				s = "false"
			}
		case float64:
			s = strconv.FormatFloat(x, 'f', -1, 64)
		default:
			b, _ := json.Marshal(x)
			s = string(b)
		}
		r.PostForm.Set(k, s)
		r.Form.Set(k, s)
	}
}

// wantsJSON returns true when the client has explicitly opted into a
// JSON response, either via `Accept: application/json` or by sending
// a JSON Content-Type. Standard browser form submissions send
// `Accept: text/html,...` so they keep the redirect flow; the SPA's
// bm.useAuth flow sends `Accept: application/json` and gets clean
// JSON errors instead of being redirected to a /login URL that has
// no server-side handler.
func wantsJSON(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") {
		// Crude but adequate: prefer json only when it's listed
		// BEFORE text/html (or when html isn't mentioned at all).
		// Browsers list text/html first; explicit API clients list
		// json first.
		if !strings.Contains(accept, "text/html") {
			return true
		}
		jsonIdx := strings.Index(accept, "application/json")
		htmlIdx := strings.Index(accept, "text/html")
		if jsonIdx >= 0 && jsonIdx < htmlIdx {
			return true
		}
	}
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		return true
	}
	return false
}

// authSuccessJSON writes a successful-auth JSON response. The session
// cookie has already been set on `w` by the caller before invoking.
// Returns true when JSON was written so the caller knows to skip the
// http.Redirect.
func authSuccessJSON(w http.ResponseWriter, r *http.Request, app *App, userID int64) bool {
	if !wantsJSON(r) {
		return false
	}
	user := loadUserForJSON(app, userID)
	httpJSON(w, http.StatusOK, map[string]any{"ok": true, "user": user})
	return true
}

// isSensitiveUserColumn names columns that must never be returned over
// the wire as part of a user-object payload. The exact-match list covers
// the framework's own sensitive columns; the suffix/prefix patterns are
// a defensive net so a developer who adds e.g. `payment_token` or
// `internal_notes` doesn't accidentally leak it through loadUserForJSON
// or GET /api/_auth/profile. Defense in depth - apps that genuinely need
// to expose such a column should rename it.
func isSensitiveUserColumn(col string) bool {
	c := strings.ToLower(col)
	switch c {
	case "password_hash", "password", "totp_secret", "mfa_backup_codes",
		"backup_codes", "recovery_codes", "salt", "session_id", "csrf_token",
		// MFA bookkeeping - last TOTP submitted + timestamps. Exposing
		// them risks replay-attack analysis ("a code was used at T,
		// next codes are likely in this window"). Leaked under
		// /api/_auth/users in v2.7.11 first build; added here.
		"mfa_last_totp", "mfa_last_totp_at", "mfa_enrolled_at":
		return true
	}
	// Any column starting with mfa_ is bookkeeping - never expose.
	if strings.HasPrefix(c, "mfa_") {
		return true
	}
	for _, suf := range []string{"_hash", "_secret", "_token", "_key", "_password", "_pin"} {
		if strings.HasSuffix(c, suf) {
			return true
		}
	}
	for _, pre := range []string{"private_", "internal_", "secret_"} {
		if strings.HasPrefix(c, pre) {
			return true
		}
	}
	return false
}

// loadUserForJSON fetches the freshly-authenticated user's row for
// inclusion in the JSON response. Excludes columns flagged by
// isSensitiveUserColumn so a developer who adds a column like
// `payment_token` doesn't silently leak it.
func loadUserForJSON(app *App, userID int64) map[string]any {
	out := map[string]any{"id": userID}
	if app == nil || app.DB == nil {
		return out
	}
	rows, err := app.DB.Query("SELECT * FROM _benmore_users WHERE id = ?", userID)
	if err != nil {
		return out
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil || !rows.Next() {
		return out
	}
	vals := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	if err := rows.Scan(ptrs...); err != nil {
		return out
	}
	for i, c := range cols {
		if isSensitiveUserColumn(c) {
			continue
		}
		v := vals[i]
		if b, ok := v.([]byte); ok {
			v = string(b)
		}
		out[c] = v
	}
	return out
}

// baseURL returns the canonical base URL for email links.
// Uses the developer-configured SEO URL if available (trusted), otherwise
// falls back to r.Host (which can be spoofed via Host header).
func baseURL(app *App, r *http.Request) string {
	if app.Design != nil {
		if seoURL, ok := app.Design.SEO["url"]; ok && seoURL != "" {
			return strings.TrimRight(seoURL, "/")
		}
	}
	return fmt.Sprintf("%s://%s", protoOf(r), r.Host)
}

// securityLinkBaseURL is baseURL for links emailed as credentials (password
// reset, email verification). It must NOT be derived from the attacker-
// controllable Host / X-Forwarded-Proto headers when an operator-configured
// origin exists: a host-header-poisoning attacker could otherwise make the
// genuine reset email point the token at their domain (round-2 #5 - pre-auth
// account takeover). Preference: configured seo.url -> BENMORE_PUBLIC_URL /
// CORS_ORIGIN -> request host (logged, so operators see the unsafe fallback).
func securityLinkBaseURL(app *App, r *http.Request) string {
	if app.Design != nil {
		if seoURL, ok := app.Design.SEO["url"]; ok && seoURL != "" {
			return strings.TrimRight(seoURL, "/")
		}
	}
	if origin := uploadsCanonicalOrigin(app); origin != "" {
		return strings.TrimRight(origin, "/")
	}
	log.Printf("SECURITY: building a credential link (reset/verify) from the request Host %q - set BENMORE_PUBLIC_URL or seo.url so a host-header-poisoning attacker can't redirect the token", r.Host)
	return fmt.Sprintf("%s://%s", protoOf(r), r.Host)
}
