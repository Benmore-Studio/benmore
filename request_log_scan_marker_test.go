//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// The request log left out every request whose User-Agent named the
// platform's security scanner. A User-Agent is the caller's to choose, so
// anyone probing an app could send that string and stay out of the log the
// owner reads to see what happened. Only a request that also carries a
// marker the platform signed for this instance is left out.
func TestRequestLogKeepsRequestsThatOnlyClaimToBeTheScanner(t *testing.T) {
	oldSecret := serverSecret
	serverSecret = "test-instance-secret-0123456789abcdef0123"
	defer func() { serverSecret = oldSecret }()

	db := requestLogTestDB(t)
	app := &App{Dir: t.TempDir(), DB: db, Stop: make(chan struct{})}
	h := requestLogMiddleware(app, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	send := func(path, token string) {
		r := httptest.NewRequest(http.MethodPost, path, nil)
		r.Header.Set("User-Agent", securityScanUA)
		if token != "" {
			r.Header.Set(scanTokenHeader, token)
		}
		h.ServeHTTP(httptest.NewRecorder(), r)
	}
	live := time.Now().Add(time.Minute)
	send("/login/no-marker", "")
	send("/login/garbage", "not-a-token")
	send("/login/other-secret", mintScanTokenWithSecret(app.Dir, live, "another-instance-secret-0123456789abcdef"))
	send("/login/other-app", mintScanTokenWithSecret(app.Dir+"-dev", live, serverSecret))
	send("/login/expired", mintScanTokenWithSecret(app.Dir, time.Now().Add(-time.Second), serverSecret))
	send("/login/too-long-lived", mintScanTokenWithSecret(app.Dir, time.Now().Add(24*time.Hour), serverSecret))
	send("/login/genuine-scan", mintScanTokenWithSecret(app.Dir, live, serverSecret))
	close(app.Stop)
	app.workerWG.Wait()

	for _, path := range []string{"/login/no-marker", "/login/garbage", "/login/other-secret", "/login/other-app", "/login/expired", "/login/too-long-lived"} {
		var n int
		db.QueryRow(`SELECT COUNT(*) FROM _benmore_request_log WHERE path = ?`, path).Scan(&n)
		if n != 1 {
			t.Errorf("%s: logged %d times, want 1 (a scanner User-Agent alone must not hide a request)", path, n)
		}
	}
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM _benmore_request_log WHERE path = '/login/genuine-scan'`).Scan(&n)
	if n != 0 {
		t.Errorf("a probe the platform signed for this instance was logged %d times", n)
	}
}

// A types token is signed with the same secret and names the same app; it
// must not stand in for a scan marker, nor a scan marker for a types token.
func TestScanMarkerIsNotInterchangeableWithOtherInstanceTokens(t *testing.T) {
	oldSecret := serverSecret
	serverSecret = "test-instance-secret-0123456789abcdef0123"
	defer func() { serverSecret = oldSecret }()
	app := &App{Dir: t.TempDir()}
	exp := time.Now().Add(time.Minute)
	if verifyScanToken(app, mintTypesTokenWithSecret(app.Dir, exp, serverSecret)) {
		t.Error("a types token verified as a scan marker")
	}
	if verifyTypesToken(app, mintScanTokenWithSecret(app.Dir, exp, serverSecret)) {
		t.Error("a scan marker verified as a types token")
	}
	if !verifyScanToken(app, mintScanTokenWithSecret(app.Dir, exp, serverSecret)) {
		t.Error("a genuine scan marker did not verify")
	}
}
