//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// sduiExportApp serves an app with 1234 owner rows in ledger (half kind=in),
// 40 rows of another user, and a docs table of 700 rows with UUID text ids.
func sduiExportApp(t *testing.T) (*App, string) {
	t.Helper()
	app := newGateApp(t,
		"CREATE TABLE ledger (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, kind TEXT, note TEXT)",
		"CREATE TABLE docs (id TEXT PRIMARY KEY, user_id INTEGER, title TEXT)",
	)
	owner, sid := gateUser(t, app, "exporter@example.com")
	other, _ := gateUser(t, app, "other@example.com")
	tx, err := app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	insert := func(q string, args ...any) {
		if _, err := tx.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	for i := 0; i < 1234; i++ {
		kind := "out"
		if i%2 == 0 {
			kind = "in"
		}
		insert("INSERT INTO ledger (user_id, kind, note) VALUES (?, ?, ?)", owner, kind, fmt.Sprintf("row %d", i))
	}
	for i := 0; i < 40; i++ {
		insert("INSERT INTO ledger (user_id, kind, note) VALUES (?, 'in', 'other user')", other)
	}
	for i := 0; i < 700; i++ {
		// Spread over the whole hex range, including ids that start with 0.
		insert("INSERT INTO docs (id, user_id, title) VALUES (?, ?, ?)", fmt.Sprintf("%08x-0000-4000-8000-%012x", uint32(i)*6135607, i), owner, fmt.Sprintf("doc %d", i))
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return app, sid
}

func TestSDUIExportButtonExportsEveryRow(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; skipping component integration")
	}
	app, sid := sduiExportApp(t)
	server := httptest.NewServer(buildAppMux(app, false, "http://localhost"))
	defer server.Close()
	cmd := exec.Command(node, "embedded/sdui_export_test.mjs")
	cmd.Env = append(os.Environ(), "BM_TEST_URL="+server.URL, "BM_TEST_TOKEN="+sid)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ExportButton check failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "ExportButton exports every row passed") {
		t.Fatalf("missing success: %s", output)
	}
}

// A list page holds at most 500 rows. Asking for more used to be clamped in
// silence, so a client could not tell a short table from a capped page.
func TestListLimitCapIsVisible(t *testing.T) {
	app, sid := sduiExportApp(t)
	mux := buildAppMux(app, false, "http://localhost")
	get := func(query string) (*httptest.ResponseRecorder, int) {
		r := httptest.NewRequest(http.MethodGet, "/api/ledger?"+query, nil)
		r.Header.Set("Authorization", "Bearer "+sid)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", query, w.Code, w.Body.String())
		}
		var rows []any
		if json.Unmarshal(w.Body.Bytes(), &rows) != nil {
			var env struct{ Data []any }
			json.Unmarshal(w.Body.Bytes(), &env)
			rows = env.Data
		}
		return w, len(rows)
	}
	for _, query := range []string{"limit=5000", "page=1&per_page=900", "cursor=0&limit=5000"} {
		w, n := get(query)
		if n != 500 || w.Header().Get("X-Limit-Capped") != "500" {
			t.Fatalf("%s: %d rows, X-Limit-Capped=%q; want 500 rows and the cap named", query, n, w.Header().Get("X-Limit-Capped"))
		}
	}
	// A count ignores the page size, so it is never capped.
	for _, query := range []string{"limit=500", "limit=20", "", "cursor=0&limit=100", "page=2&per_page=50", "count=true&limit=5000"} {
		if w, _ := get(query); w.Header().Get("X-Limit-Capped") != "" {
			t.Fatalf("%s: X-Limit-Capped=%q on a request that was not capped", query, w.Header().Get("X-Limit-Capped"))
		}
	}
}
