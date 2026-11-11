//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestErrorClientIntakeRawStackAndSize(t *testing.T) {
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	app := &App{Dir: t.TempDir(), DB: db, Stop: make(chan struct{})}
	defer stopReportingTest(app)
	mux := http.NewServeMux()
	RegisterErrorCaptureRoute(mux, app)
	r := httptest.NewRequest("POST", "/api/_errors", strings.NewReader(strings.Repeat("x", (64<<10)+1)))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 413 {
		t.Fatalf("oversized: %d", w.Code)
	}
	stack := "Error: boom\n at fn (https://example.com/static/app.js?v=abc:2:3)"
	data, _ := json.Marshal(map[string]any{"message": "boom", "stack": stack, "release": "ignored"})
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("POST", "/api/_errors", strings.NewReader(string(data))))
	var raw string
	if err := db.QueryRow("SELECT stack_raw FROM _benmore_client_errors").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if raw != stack {
		t.Fatalf("raw stack: %q", raw)
	}
}

func TestErrorClientExportScrubsAndHasFrames(t *testing.T) {
	app := &App{Dir: t.TempDir()}
	storeAppEnv(app.Dir, map[string]string{"UPSTREAM_KEY": "privatevalue123", "BENMORE_APP_NAME": "demo-dev", "BENMORE_PUBLISHED_AT": "2026-10-27T12:00:00Z"})
	body := clientErrorBody{Kind: "error", Message: "TypeError: privatevalue123 owner@example.com 123456789012", URL: "https://example.com/page?token=x", UserID: 42, UA: "test-agent", Frames: []errorFrame{{Filename: "/static/app.js", Line: 2, Col: 3, InApp: true, ContextLine: "const key = 'privatevalue123'"}}}
	event := clientSentryEvent(app, body)
	data, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	for _, bad := range []string{"privatevalue123", "owner@example.com", "123456789012", "token=x", "ip_address"} {
		if strings.Contains(s, bad) {
			t.Fatalf("export leaked %q", bad)
		}
	}
	for _, want := range []string{`"platform":"javascript"`, `"environment":"dev"`, `"type":"TypeError"`, `"lineno":2`, `"id":"42"`, `[email]`, `[number]`} {
		if !strings.Contains(s, want) {
			t.Fatalf("export missing %s: %s", want, s)
		}
	}
}
