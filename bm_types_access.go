//go:build !cli

package main

// Access control for the generated developer artifacts under /_internal/.
//
// /_internal/types.d.ts (alias /_internal/bm.d.ts) is the app's whole data
// model: every table and column with its type, every flow path and input
// signature. It used to be served to anyone, so hiding /api/_docs hid
// nothing. It is now served only to
//
//   - an app admin on an unscoped credential (IsAdminConsole), or
//   - a request carrying X-Benmore-Types-Token: a short-lived token the
//     platform router mints for a member of the app (any collaborator role)
//     and signs with THIS instance's server secret, audience-bound to its
//     app.Dir - the same single-audience handoff shape as the import owner
//     token. `benmore push` (type refresh) and `benmore types` fetch it
//     that way.
//
// /_internal/flows.json is the registry the bm SDK needs at runtime, so it
// stays reachable, but lists only the flows the caller could call: anonymous
// callers see anonymous flows, signed-in users add auth-required flows, role
// holders add their role's flows, admins see everything. Signature-verified
// inbound webhooks are never listed for non-admins (no browser can call them).

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	typesTokenHeader = "X-Benmore-Types-Token"
	typesTokenTTL    = 5 * time.Minute
)

// mintTypesTokenWithSecret signs "types.<exp_unix>.<app.Dir>" with the target
// instance's server secret. The router is the only hosted caller: it reads the
// tenant's .benmore/server-secret, exactly like the import-token bridge.
func mintTypesTokenWithSecret(appDir string, exp time.Time, secret string) string {
	payload := fmt.Sprintf("types.%d.%s", exp.Unix(), appDir)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// verifyTypesToken checks MAC (constant time), expiry, the TTL ceiling and
// the audience - in that order, so the audience is only compared against a
// payload already proven authentic. The "types" tag keeps an import owner
// token (a different, far more powerful credential) from verifying here and
// vice versa.
func verifyTypesToken(app *App, token string) bool {
	if app == nil || serverSecret == "" {
		return false
	}
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(serverSecret))
	mac.Write(payload)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return false
	}
	// app.Dir may contain '.', so it is the last field and never split.
	fields := strings.SplitN(string(payload), ".", 3)
	if len(fields) != 3 || fields[0] != "types" {
		return false
	}
	exp, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return false
	}
	now := time.Now()
	if now.Unix() >= exp || time.Unix(exp, 0).Sub(now) > typesTokenTTL {
		return false
	}
	return fields[2] == app.Dir
}

// typesRequestAuthorized reports whether the request may read the generated
// .d.ts: a valid types token, or an admin on an unscoped credential
// (IsAdminConsole). A scoped API token an admin minted for an integration
// carries only its scopes, not the whole data model.
func typesRequestAuthorized(app *App, r *http.Request) bool {
	if tok := r.Header.Get(typesTokenHeader); tok != "" && verifyTypesToken(app, tok) {
		return true
	}
	return getSession(app, r).IsAdminConsole()
}

// flowListedFor reports whether flows.json lists an HTTP flow for session -
// the same auth/role gate executeFlow applies before running it.
func flowListedFor(f Flow, session *Session) bool {
	if len(f.Permissions) > 0 && (session == nil || !scopesWithin(session.Scopes, strings.Join(f.Permissions, " "))) {
		return false
	}
	if session.IsAdmin() {
		return true
	}
	if f.Verify != "" || f.VerifyConfig != nil {
		return false
	}
	if f.Role != "" {
		return session != nil && HasAnyRole(session, []string{f.Role})
	}
	if f.Auth == "required" {
		return session != nil
	}
	return true
}
