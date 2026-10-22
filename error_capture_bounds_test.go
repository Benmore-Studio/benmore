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

// POST /api/_errors is anonymous. It used to keep every row forever at up to
// 64 KiB each, and copied the visitor's text into a Slack code fence that a
// backtick could close, so a stranger could fill the database and post
// formatted @channel messages into the developer's channel.
func TestErrorCaptureIsBoundedAndSlackSafe(t *testing.T) {
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	app := &App{Dir: t.TempDir(), DB: db, Stop: make(chan struct{})}
	t.Cleanup(func() { close(app.Stop) })
	mux := http.NewServeMux()
	RegisterErrorCaptureRoute(mux, app)

	body := `{"Message":"` + strings.Repeat("m", 40000) + `","Stack":"` + strings.Repeat("s", 15000) + `"}`
	for i := 0; i < 5400; i++ {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/_errors", strings.NewReader(body)))
	}
	var rows, maxMsg int
	if err := db.QueryRow(`SELECT COUNT(*), MAX(LENGTH(message)) FROM _benmore_client_errors`).Scan(&rows, &maxMsg); err != nil {
		t.Fatal(err)
	}
	if rows > clientErrorRowCap+200 {
		t.Fatalf("error table grew to %d rows", rows)
	}
	if maxMsg > 1000 {
		t.Fatalf("stored message of %d bytes", maxMsg)
	}

	text := slackErrorText("app", "Type", "x``` <!channel> <https://evil.example|click>", "src", 1, 2, "1.2.3.4")
	if strings.Count(text, "```") != 2 || strings.Contains(text, "<!channel>") || strings.Contains(text, "<https") {
		t.Fatalf("visitor text escaped its code fence or formatted itself: %q", text)
	}
}
