//go:build !cli

package main

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const routeFixtureSchema = "model Note {\n  id Int @id @default(autoincrement())\n  title String\n  status String?\n  user_id Int?\n}\n"

// routeFixtureDir is an app source tree with a `notes` table that is
// versioned and carries a workflow, so every per-table framework route
// family registers for it.
func routeFixtureDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeTestFile(t, dir, "schema.prisma", routeFixtureSchema)
	writeTestFile(t, dir, "app.yaml", "name: routes\nversioned:\n  - notes\n")
	writeTestFile(t, dir, "workflows.yaml", "review:\n  table: notes\n  field: status\n  initial: draft\n")
	return dir
}

func routeFixtureFlow(method, path string) string {
	return "on:\n  request:\n    method: " + method + "\n    path: " + path + "\njobs:\n  run:\n    steps:\n      - run: respond\n        with:\n          json: {custom: true}\n"
}

// The reported failure: an app's own share endpoint at the path the
// framework registers on every table for record sharing. The write gate let
// it through (its auto-CRUD list knew only list/read/create/update/delete,
// batch and ingest) and the app then failed to load. It is now refused, with
// the colliding framework route, the built-in it duplicates, and a free path.
func TestFlowAtShareRouteRefusedAtWrite(t *testing.T) {
	dir := routeFixtureDir(t)
	msg := ValidateOnWriteIn(dir, "flows/share_note.yaml", routeFixtureFlow("POST", "/api/notes/:id/share"))
	for _, want := range []string{
		`flow "share_note" route POST /api/notes/:id/share`,
		"framework route POST /api/notes/{id}/share",
		"record sharing",
		`api(at:"permissions")`,
		"POST /api/notes/:id/share-custom",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("refusal lacks %q:\n%s", want, msg)
		}
	}
	// The suggested path is accepted.
	if msg := ValidateOnWriteIn(dir, "flows/share_note.yaml", routeFixtureFlow("POST", "/api/notes/:id/share-custom")); msg != "" {
		t.Fatalf("suggested path refused:\n%s", msg)
	}
}

// Each job of a request-triggered file becomes its own flow on the file's
// route, so a second job never registers (which one does depends on map
// order). The refusal says so instead of reporting two unrelated flows.
func TestMultiJobRequestFlowRefusedAtWrite(t *testing.T) {
	dir := routeFixtureDir(t)
	twoJobs := "on: {request: {method: POST, path: /api/ordinary}}\njobs:\n  first: {steps: [{run: respond, with: {status: 200, body: ok}}]}\n  second: {steps: [{run: respond, with: {status: 200, body: ok}}]}\n"
	msg := ValidateOnWriteIn(dir, "flows/ordinary.yaml", twoJobs)
	for _, want := range []string{`flow "second" route POST /api/ordinary collides with flow first`, "one flow per job", "Put every step in one job"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("refusal lacks %q:\n%s", want, msg)
		}
	}
	// Several jobs on a non-request trigger register no route.
	cron := "on: {schedule: [{cron: '0 * * * *'}]}\njobs:\n  first: {steps: [{run: set, with: {a: b}}]}\n  second: {steps: [{run: set, with: {a: b}}]}\n"
	if msg := ValidateOnWriteIn(dir, "flows/hourly.yaml", cron); strings.Contains(msg, "collides") {
		t.Fatalf("multi-job schedule refused as a route collision:\n%s", msg)
	}
}

// The reserved set is whatever the framework registers for this app, so each
// per-table route family and framework path is covered without a list.
func TestFlowRouteGateCoversRegisteredFrameworkRoutes(t *testing.T) {
	dir := routeFixtureDir(t)
	for _, tc := range []struct{ method, path, framework string }{
		{"GET", "/api/notes/:noteId/permissions", "GET /api/notes/{id}/permissions"},
		{"DELETE", "/api/notes/:id/share/:grant", "DELETE /api/notes/{id}/share/{permissionId}"},
		{"GET", "/api/notes/:id/versions", "GET /api/notes/{id}/versions"},
		{"POST", "/api/notes/:id/revert/:v", "POST /api/notes/{id}/revert/{version}"},
		{"POST", "/api/notes/:id/transition", "POST /api/notes/{id}/transition"},
		{"POST", "/api/notes/:id/lock", "POST /api/notes/{id}/lock"},
		{"GET", "/llms-full.txt", "GET /llms-full.txt"},
		{"GET", "/admin", "GET /admin"},
		{"POST", "/_demo/login", "POST /_demo/login"},
	} {
		msg := ValidateOnWriteIn(dir, "flows/custom.yaml", routeFixtureFlow(tc.method, tc.path))
		if !strings.Contains(msg, "framework route "+tc.framework) {
			t.Errorf("%s %s: want a refusal naming %s, got:\n%s", tc.method, tc.path, tc.framework, msg)
		}
	}
	for _, tc := range []struct{ method, path string }{
		{"POST", "/api/notes/:id/star"},     // a custom verb
		{"GET", "/api/notes/:id/summary"},   // more specific than the read subtree
		{"POST", "/api/notes/:id/restore"},  // the framework yields restore to a flow
		{"POST", "/api/share-notes/:id"},    // its own prefix
		{"GET", "/api/notes/:id/versions2"}, // a different literal
	} {
		if msg := ValidateOnWriteIn(dir, "flows/custom.yaml", routeFixtureFlow(tc.method, tc.path)); msg != "" {
			t.Errorf("%s %s refused:\n%s", tc.method, tc.path, msg)
		}
	}
}

// The auto-CRUD refusal keeps its own message and is not repeated.
func TestFlowRouteGateLeavesAutoCRUDRefusalUnchanged(t *testing.T) {
	dir := routeFixtureDir(t)
	msg := ValidateOnWriteIn(dir, "flows/list_notes.yaml", routeFixtureFlow("GET", "/api/notes"))
	if !strings.Contains(msg, "conflicts with the auto-CRUD endpoint for table \"notes\"") {
		t.Fatalf("auto-CRUD refusal changed:\n%s", msg)
	}
	if strings.Contains(msg, "framework route") {
		t.Fatalf("auto-CRUD conflict reported twice:\n%s", msg)
	}
}

// A colliding flow already on disk (deployed before the gate existed) must
// not take the app down: it is skipped with a log line naming the framework
// route, and the framework route keeps serving.
func TestDeployedCollidingFlowLoadsWithoutCrash(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "app.yaml", "name: routes\nversioned:\n  - notes\n")
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	mustExec(t, db, `CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, status TEXT)`)
	flow := func(name, method, path string) Flow {
		return Flow{Name: name, Trigger: FlowTrigger{Type: "http", Method: method, Path: path},
			Steps: []FlowStep{{Name: "r", Type: "respond", Respond: &FlowRespond{Status: 200, JSON: map[string]any{"custom": true}}}}}
	}
	app := &App{Dir: dir, DB: db, SessionDuration: time.Hour, Stop: make(chan struct{}),
		Tables:    []Table{{Name: "notes", Columns: []Column{{Name: "id"}, {Name: "title"}, {Name: "status"}}}},
		Workflows: &WorkflowConfig{Workflows: map[string]*Workflow{"review": {Name: "review", Table: "notes", Field: "status", Initial: "draft"}}},
		Flows: []Flow{
			flow("share_note", "POST", "/api/notes/:id/share"),     // permissions.go, registered after flows before
			flow("note_history", "GET", "/api/notes/:id/versions"), // versioning.go
			flow("advance", "POST", "/api/notes/:id/transition"),   // workflows.go
			flow("health", "GET", "/health"),                       // server.go
			flow("list_notes", "GET", "/api/notes"),                // auto-CRUD: the long-standing skipped case
			flow("lock_note", "POST", "/api/notes/:id/lock"),       // locks.go, registered before flows
			flow("star_note", "POST", "/api/notes/:id/star"),       // no collision
			flow("star_again", "POST", "/api/notes/:noteId/star"),  // collides with the flow above
		}}
	t.Cleanup(app.Shutdown)

	var mux *appRouteMux
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("a colliding flow crashed app load: %v", r)
			}
		}()
		mux = buildAppRouteMux(app, true, "http://localhost", true, nil)
	}()

	skipped := map[string]flowRouteCollision{}
	for _, c := range mux.flowCollisions {
		skipped[c.Flow] = c
	}
	for name, want := range map[string]string{
		"share_note":   "POST /api/notes/{id}/share",
		"note_history": "GET /api/notes/{id}/versions",
		"advance":      "POST /api/notes/{id}/transition",
		"health":       "GET /health",
		"list_notes":   "GET /api/notes",
		"lock_note":    "POST /api/notes/{id}/lock",
		"star_again":   "POST /api/notes/{id}/star",
	} {
		c, ok := skipped[name]
		if !ok || c.Conflict != want {
			t.Errorf("flow %s: collision %+v, want conflict with %s", name, c, want)
		}
	}
	if c := skipped["star_again"]; c.Source != "flow star_note" {
		t.Errorf("flow-vs-flow collision names %q", c.Source)
	}
	if c := skipped["share_note"]; !strings.HasPrefix(c.Source, "permissions.go:") {
		t.Errorf("share collision source %q", c.Source)
	}
	if _, ok := mux.flows["star_note"]; !ok || len(mux.flows) != 1 {
		t.Fatalf("registered flows = %v", mux.flows)
	}

	// The framework routes serve; the skipped flows never answer.
	for _, req := range []*http.Request{
		httptest.NewRequest("POST", "/api/notes/1/share", strings.NewReader(`{}`)),
		httptest.NewRequest("GET", "/health", nil),
		httptest.NewRequest("GET", "/api/notes", nil),
	} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if strings.Contains(w.Body.String(), `"custom"`) {
			t.Errorf("%s %s answered by the skipped flow", req.Method, req.URL.Path)
		}
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("POST", "/api/notes/1/star", nil))
	if !strings.Contains(w.Body.String(), `"custom"`) {
		t.Fatalf("non-colliding flow not served: %d %s", w.Code, w.Body.String())
	}
}

// Moving authored routes to the end changes no precedence: a flow still wins
// over a page at the same path (the page is the one skipped).
func TestFlowStillWinsOverSamePathPage(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	app := &App{Dir: dir, DB: db, SessionDuration: time.Hour, Stop: make(chan struct{}),
		Pages: map[string]*Page{"/report": {Route: "/report", File: "report.html", RawHTML: "<h1>page</h1>"}},
		Flows: []Flow{{Name: "report", Trigger: FlowTrigger{Type: "http", Method: "GET", Path: "/report"},
			Steps: []FlowStep{{Name: "r", Type: "respond", Respond: &FlowRespond{Status: 200, JSON: map[string]any{"custom": true}}}}}}}
	app.Paths = DiscoverAuthPaths(app.Pages)
	t.Cleanup(app.Shutdown)
	mux := buildAppMux(app, true, "http://localhost")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/report", nil))
	if !strings.Contains(w.Body.String(), `"custom"`) {
		t.Fatalf("page displaced the flow: %d %s", w.Code, w.Body.String())
	}
}

// `benmore check` registers every flow file together: a collision already on
// disk, one introduced later by a workflows.yaml write, and a collision
// between two flow files all surface as errors on the flow's own file.
func TestCheckReportsFlowRouteCollisions(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "schema.prisma", routeFixtureSchema)
	writeTestFile(t, dir, "app.yaml", "name: routes\n")
	writeTestFile(t, dir, "flows/a_share.yaml", routeFixtureFlow("POST", "/api/notes/:id/share"))
	writeTestFile(t, dir, "flows/b_advance.yaml", routeFixtureFlow("POST", "/api/notes/:id/transition"))
	writeTestFile(t, dir, "flows/c_star.yaml", routeFixtureFlow("POST", "/api/notes/:id/star"))
	writeTestFile(t, dir, "flows/d_star.yaml", routeFixtureFlow("POST", "/api/notes/:noteId/star"))

	routeErrors := func(report CheckReport) map[string]string {
		out := map[string]string{}
		for _, f := range report.Findings {
			if f.Source == "routes" && f.Severity == "error" {
				out[f.File] = f.Message
			}
		}
		return out
	}
	got := routeErrors(RunSourceCheck(dir, ""))
	if !strings.Contains(got["flows/a_share.yaml"], "framework route POST /api/notes/{id}/share") {
		t.Fatalf("share collision not reported: %v", got)
	}
	if !strings.Contains(got["flows/d_star.yaml"], "flow c_star") {
		t.Fatalf("cross-file flow collision not reported: %v", got)
	}
	if _, ok := got["flows/b_advance.yaml"]; ok {
		t.Fatalf("transition route reported without a workflow: %v", got)
	}

	// A workflows.yaml write registers transition routes under an existing flow.
	writeTestFile(t, dir, "workflows.yaml", "review:\n  table: notes\n  field: status\n  initial: draft\n")
	got = routeErrors(RunSourceCheck(dir, "workflows.yaml"))
	if !strings.Contains(got["flows/b_advance.yaml"], "framework route POST /api/notes/{id}/transition") {
		t.Fatalf("workflows.yaml write did not surface the transition collision: %v", got)
	}
}
