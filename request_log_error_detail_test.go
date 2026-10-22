//go:build !cli

package main

import (
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A production render error was stashed in an X-Benmore-Error response header
// for the request log, which stripped it only after the headers had been
// written, so the template error (file name, up to 500 chars of detail)
// reached the client. The detail now reaches the request log server-side and
// never the response.
func TestRenderErrorDetailStaysServerSide(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	app := &App{Dir: dir, DB: db, SessionDuration: time.Hour, Stop: make(chan struct{})}
	page := &Page{Route: "/broken", File: "broken.html", RawHTML: "---\nengine: gotmpl\n---\n<p>{{ .Secret | nosuchfunc }}</p>"}
	srv := httptest.NewServer(requestLogMiddleware(app, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		servePage(w, r, app, page, false)
	})))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/broken")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500", resp.StatusCode)
	}
	if v := resp.Header.Get("X-Benmore-Error"); v != "" {
		t.Fatalf("render error detail sent to the client: X-Benmore-Error: %s", v)
	}
	if strings.Contains(string(body), "nosuchfunc") || strings.Contains(string(body), "broken.html") {
		t.Fatalf("render error detail in the response body: %s", body)
	}

	close(app.Stop)
	app.workerWG.Wait()
	var logged string
	if err := db.QueryRow(`SELECT error FROM _benmore_request_log WHERE path = '/broken'`).Scan(&logged); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logged, "broken.html") || !strings.Contains(logged, "nosuchfunc") {
		t.Fatalf("request log lost the render error: %q", logged)
	}
}
