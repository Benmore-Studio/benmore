//go:build !cli

package main

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// bm.js reports location.href with every uncaught error. On a password-reset,
// email-verification or magic-link page that is a live credential in the
// query string, and the stored row is read back through get_client_errors
// (a viewer-level MCP tool) and forwarded to Sentry/Slack. Only origin and
// path are worth keeping.
func TestErrorCaptureDropsQueryAndFragmentFromURL(t *testing.T) {
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	app := &App{Dir: t.TempDir(), DB: db, Stop: make(chan struct{})}
	t.Cleanup(func() { close(app.Stop) })
	mux := http.NewServeMux()
	RegisterErrorCaptureRoute(mux, app)

	body := `{"Message":"boom","URL":"https://app.example.com/reset-password?token=SECRETRESET&x=1#access_token=SECRETFRAG","Source":"https://app.example.com/static/app.js?v=abc&token=SECRETSRC"}`
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/_errors", strings.NewReader(body)))

	var url, source string
	if err := db.QueryRow(`SELECT url, source FROM _benmore_client_errors`).Scan(&url, &source); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{url, source} {
		if strings.Contains(v, "SECRET") || strings.ContainsAny(v, "?#") {
			t.Fatalf("stored %q, want origin and path only", v)
		}
	}
	if url != "https://app.example.com/reset-password" {
		t.Fatalf("url = %q", url)
	}
}
