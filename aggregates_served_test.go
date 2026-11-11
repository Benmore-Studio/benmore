//go:build !cli && !windows

package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func aggregatesAppYAML(entries ...string) string {
	if len(entries) == 0 {
		return "auth:\n  signup: false\n"
	}
	return "auth:\n  signup: false\naggregates:\n" + strings.Join(entries, "")
}

func aggregateEntry(name, query string) string {
	return "  " + name + ":\n    sql: \"" + query + "\"\n    refresh: 1m\n"
}

// aggregateServeFixture loads an app with three notes and serves it through
// the hot-reload handler a served process uses, as an admin.
func aggregateServeFixture(t *testing.T, appYAML string) (*App, *hotHandler, string) {
	t.Helper()
	dir := t.TempDir()
	writeTestFile(t, dir, "app.yaml", appYAML)
	writeTestFile(t, dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT);\n")
	app, err := loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	mustExec(t, app.DB, `INSERT INTO notes (title) VALUES ('a'), ('b'), ('c')`)
	sid := seedAdminSession(t, app)
	handler := &hotHandler{}
	handler.swap(wrapMiddleware(buildAppMux(app, false, "https://fixture.example.com"), app, false))
	previous := hostedHotHandler
	hostedHotHandler = handler
	t.Cleanup(func() { hostedHotHandler = previous })
	return app, handler, sid
}

func aggregateRequest(t *testing.T, handler http.Handler, method, sid string) *httptest.ResponseRecorder {
	t.Helper()
	path := "/api/_aggregates"
	if method == http.MethodPost {
		path += "/refresh"
	}
	req := httptest.NewRequest(method, "https://fixture.example.com"+path, nil)
	req.Header.Set("Authorization", "Bearer "+sid)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("%s %s: %d %s", method, path, rec.Code, rec.Body.String())
	}
	return rec
}

// servedAggregateList is GET /api/_aggregates by name.
func servedAggregateList(t *testing.T, handler http.Handler, sid string) map[string]map[string]any {
	t.Helper()
	rec := aggregateRequest(t, handler, http.MethodGet, sid)
	var body struct {
		Aggregates []map[string]any `json:"aggregates"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string]any{}
	for _, a := range body.Aggregates {
		out[a["name"].(string)] = a
	}
	return out
}

func templateAggregates(app *App) map[string]any {
	ctx := &RenderContext{Data: map[string]any{}, App: app}
	InjectAggregateData(ctx)
	values, _ := ctx.Data["aggregate"].(map[string]any)
	return values
}

func storedAggregateNames(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.Query(`SELECT name FROM _benmore_aggregates ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		names = append(names, name)
	}
	return names
}

// An aggregate removed from app.yaml is no longer served: not by GET
// /api/_aggregates, not as {{aggregate.<name>}}, and its stored row is
// deleted when the app reloads. It used to keep its last value forever.
func TestAggregateRemovedFromAppYAMLIsNotServed(t *testing.T) {
	app, handler, sid := aggregateServeFixture(t, aggregatesAppYAML(
		aggregateEntry("note_count", "SELECT COUNT(*) FROM notes"),
		aggregateEntry("max_id", "SELECT COALESCE(MAX(id), 0) FROM notes"),
	))
	if got := servedAggregateList(t, handler, sid); len(got) != 2 || got["max_id"]["value"] != float64(3) {
		t.Fatalf("both aggregates must be served at first: %v", got)
	}
	if got := templateAggregates(app); got["max_id"] != int64(3) || got["note_count"] != int64(3) {
		t.Fatalf("template values at first: %v", got)
	}

	writeTestFile(t, app.Dir, "app.yaml", aggregatesAppYAML(aggregateEntry("note_count", "SELECT COUNT(*) FROM notes")))
	if err := hotReloadApp(app, false); err != nil {
		t.Fatal(err)
	}
	if got := servedAggregateList(t, handler, sid); len(got) != 1 || got["note_count"] == nil {
		t.Fatalf("only note_count must be served after max_id was removed: %v", got)
	}
	if got := templateAggregates(app); len(got) != 1 || got["max_id"] != nil {
		t.Fatalf("{{aggregate.max_id}} must be gone after it was removed: %v", got)
	}
	if got := storedAggregateNames(t, app.DB); len(got) != 1 || got[0] != "note_count" {
		t.Fatalf("the removed aggregate's row must be deleted on reload: %v", got)
	}

	// A row written for it afterwards (a refresher of the previous
	// configuration that was mid-run, another process on the same database)
	// is not served either.
	mustExec(t, app.DB, `INSERT INTO _benmore_aggregates (name, value) VALUES ('max_id', '3')`)
	if got := servedAggregateList(t, handler, sid); got["max_id"] != nil {
		t.Fatalf("an unconfigured row must not be served: %v", got)
	}
	if got := templateAggregates(app); got["max_id"] != nil {
		t.Fatalf("an unconfigured row must not reach templates: %v", got)
	}

	// Removing the last aggregate stops serving it too.
	writeTestFile(t, app.Dir, "app.yaml", aggregatesAppYAML())
	if err := hotReloadApp(app, false); err != nil {
		t.Fatal(err)
	}
	if got := templateAggregates(app); len(got) != 0 {
		t.Fatalf("no aggregate may reach templates once app.yaml has none: %v", got)
	}
	if got := storedAggregateNames(t, app.DB); len(got) != 0 {
		t.Fatalf("every aggregate row must be deleted once app.yaml has none: %v", got)
	}
}

// An aggregate whose SQL fails keeps its last value, but GET
// /api/_aggregates says it is stale: stale: true, stale_since (the first
// failure since its last successful refresh) and the error; updated_at stays
// the time of the last successful refresh. One that never refreshed is
// listed with value null. It used to serve the old value as current, and an
// aggregate that had never refreshed was missing from the list.
func TestAggregateRefreshFailureServedAsStale(t *testing.T) {
	app, handler, sid := aggregateServeFixture(t, aggregatesAppYAML(
		aggregateEntry("note_count", "SELECT COUNT(*) FROM notes"),
		aggregateEntry("broken", "SELECT nope FROM notes"),
	))
	got := servedAggregateList(t, handler, sid)
	current := got["note_count"]
	if current == nil || current["value"] != float64(3) || current["stale"] != false || current["stale_since"] != nil {
		t.Fatalf("note_count must be current: %v", current)
	}
	broken := got["broken"]
	if broken == nil || broken["value"] != nil || broken["stale"] != true || broken["stale_since"] == nil || !strings.Contains(broken["error"].(string), "nope") {
		t.Fatalf("an aggregate that never refreshed must be listed as stale with value null: %v", broken)
	}
	updatedAt := current["updated_at"]

	// The SQL starts failing: the last value stays, marked stale.
	mustExec(t, app.DB, `ALTER TABLE notes RENAME TO notes_moved`)
	rec := aggregateRequest(t, handler, http.MethodPost, sid)
	if !strings.Contains(rec.Body.String(), `"failed":["broken","note_count"]`) {
		t.Fatalf("refresh must name the aggregates that failed: %s", rec.Body.String())
	}
	stale := servedAggregateList(t, handler, sid)["note_count"]
	if stale["value"] != float64(3) || stale["stale"] != true || stale["stale_since"] == nil || stale["updated_at"] != updatedAt || !strings.Contains(stale["error"].(string), "no such table") {
		t.Fatalf("a failing aggregate must keep its last value marked stale: %v", stale)
	}
	since := stale["stale_since"]
	aggregateRequest(t, handler, http.MethodPost, sid)
	if again := servedAggregateList(t, handler, sid)["note_count"]; again["stale_since"] != since {
		t.Fatalf("stale_since must stay the first failure: %v then %v", since, again["stale_since"])
	}
	if got := templateAggregates(app); got["note_count"] != int64(3) {
		t.Fatalf("{{aggregate.note_count}} keeps the last value: %v", got)
	}

	// It refreshes again: current, no error.
	mustExec(t, app.DB, `ALTER TABLE notes_moved RENAME TO notes`)
	mustExec(t, app.DB, `INSERT INTO notes (title) VALUES ('d')`)
	aggregateRequest(t, handler, http.MethodPost, sid)
	fresh := servedAggregateList(t, handler, sid)["note_count"]
	if fresh["value"] != float64(4) || fresh["stale"] != false || fresh["stale_since"] != nil || fresh["error"] != nil {
		t.Fatalf("a refreshed aggregate must be current again: %v", fresh)
	}
}
