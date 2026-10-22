//go:build !cli

package main

// Scan marker: how an app recognizes the platform security scanner's own
// probes.
//
// The scanner (security_scan.go, router process) reaches the app through its
// public URL like any other client and sends a few hundred probe requests,
// which the request log leaves out so a scan does not bury the app's real
// traffic. The log used to recognize a probe by its User-Agent alone - a
// value any caller sets - so the same string hid anyone's requests from the
// owner's runtime log. A probe now also carries X-Benmore-Scan-Token: a
// short-lived token the router signs with THIS instance's server secret and
// binds to its app.Dir, the same single-audience shape as the types token
// (bm_types_access.go). Without the secret (self-hosted, `benmore host`) the
// scanner sends no token and its probes are logged like any request.

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
	securityScanUA  = "BenmoreSecurityScanner/1.0"
	scanTokenHeader = "X-Benmore-Scan-Token"
	// scanTokenTTL bounds a marker's life; the scanner mints one per request.
	scanTokenTTL = 2 * time.Minute
)

// mintScanTokenWithSecret signs "scan.<exp_unix>.<app.Dir>" with the target
// instance's server secret.
func mintScanTokenWithSecret(appDir string, exp time.Time, secret string) string {
	payload := fmt.Sprintf("scan.%d.%s", exp.Unix(), appDir)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// verifyScanToken checks the MAC (constant time), then the "scan" tag, the
// expiry with its TTL ceiling, and the audience.
func verifyScanToken(app *App, token string) bool {
	if app == nil || serverSecret == "" || token == "" {
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
	if len(fields) != 3 || fields[0] != "scan" {
		return false
	}
	exp, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return false
	}
	now := time.Now()
	if now.Unix() >= exp || time.Unix(exp, 0).Sub(now) > scanTokenTTL {
		return false
	}
	return fields[2] == app.Dir
}

// platformScanRequest reports whether r is a probe the platform security
// scanner sent to this instance: its User-Agent plus a valid scan marker.
func platformScanRequest(app *App, r *http.Request) bool {
	return r.UserAgent() == securityScanUA && verifyScanToken(app, r.Header.Get(scanTokenHeader))
}
