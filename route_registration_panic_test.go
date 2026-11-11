//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// A table named like a framework API path: its auto-CRUD route POST
// /api/_upload is also the framework's upload route, so ServeMux panics when
// the second one registers. The write gate accepts the schema.
const routeClashSchema = "CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT);\nCREATE TABLE _upload (id INTEGER PRIMARY KEY, title TEXT);\n"

// twoWorkflowsOnOrdersInMemory is the shape the parser refuses, built past it.
func twoWorkflowsOnOrdersInMemory() *WorkflowConfig {
	workflow := func(name, field string) *Workflow {
		return &Workflow{Name: name, Table: "orders", Field: field,
			Transitions: map[string]map[string]Transition{}, OnTransition: map[string][]Hook{}, Timeouts: map[string]WorkflowTimeout{}}
	}
	return &WorkflowConfig{Workflows: map[string]*Workflow{
		"fulfilment": workflow("fulfilment", "status"),
		"payment":    workflow("payment", "payment_status"),
	}}
}

// Whatever makes route registration panic, starting the app answers an error
// that names the route. It used to take the process down from StartServer.
func TestStartWithCollidingFrameworkRoutesIsAnErrorNotAPanic(t *testing.T) {
	cases := map[string]struct {
		prepare func(t *testing.T) *App
		route   string
	}{
		"table named like a framework route": {
			prepare: func(t *testing.T) *App {
				dir := t.TempDir()
				writeTestFile(t, dir, "app.yaml", "site_name: route clash\n")
				writeTestFile(t, dir, "schema.sql", routeClashSchema)
				app, err := loadApp(dir)
				if err != nil {
					t.Fatal(err)
				}
				return app
			},
			route: "/api/_upload",
		},
		"two workflows on one table past the parser": {
			prepare: func(t *testing.T) *App {
				app, err := loadApp(sameTableApp(t))
				if err != nil {
					t.Fatal(err)
				}
				app.Workflows = twoWorkflowsOnOrdersInMemory()
				return app
			},
			route: "/api/orders/{id}/transition",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			app := tc.prepare(t)
			defer app.Shutdown()

			mux, err := buildAppMuxChecked(app, false, "https://fixture.example.com")
			if err == nil || mux != nil {
				t.Fatalf("want an error and no mux, got mux=%v err=%v", mux != nil, err)
			}
			for _, want := range []string{"route registration failed", tc.route, "conflicts with pattern"} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("error does not mention %q: %v", want, err)
				}
			}
			if strings.Contains(err.Error(), "registered at") || strings.Contains(err.Error(), "\n") {
				t.Fatalf("error carries the build's source paths or raw line breaks: %q", err.Error())
			}
			// StartServer returns it before it listens.
			if err := StartServer(app, 0, false); err == nil || !strings.Contains(err.Error(), tc.route) {
				t.Fatalf("StartServer must return the registration error, got: %v", err)
			}
		})
	}
}

// A reload whose routes cannot register is rejected before anything is
// published or retired: the previous configuration, workers and handler stay.
// It used to panic in hotReloadApp after the new configuration was published
// and the workers were stopped, and the process died.
func TestReloadWithCollidingFrameworkRoutesKeepsThePreviousApp(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "app.yaml", "site_name: before\n")
	writeTestFile(t, dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT);\n")
	app, err := loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	handler := &hotHandler{}
	handler.swap(wrapMiddleware(buildAppMux(app, false, "https://fixture.example.com"), app, false))
	previous := hostedHotHandler
	hostedHotHandler = handler
	t.Cleanup(func() { hostedHotHandler = previous })
	health := func() int {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://fixture.example.com/health", nil))
		return rec.Code
	}
	if code := health(); code != http.StatusOK {
		t.Fatalf("before the reload: /health answered %d", code)
	}

	oldDesign, oldStop := app.Design, app.Stop
	generation := app.reloadGeneration.Load()
	writeTestFile(t, dir, "app.yaml", "site_name: after\n")
	writeTestFile(t, dir, "schema.sql", routeClashSchema)

	err = hotReloadApp(app, false)
	if err == nil || !strings.Contains(err.Error(), "route registration failed") || !strings.Contains(err.Error(), "/api/_upload") {
		t.Fatalf("the reload must be rejected with the route it could not register, got: %v", err)
	}
	if app.Design != oldDesign {
		t.Fatal("the rejected reload published its configuration")
	}
	if app.Stop != oldStop {
		t.Fatal("the rejected reload retired the worker generation")
	}
	select {
	case <-oldStop:
		t.Fatal("the rejected reload stopped the running workers")
	default:
	}
	if app.reloadGeneration.Load() != generation {
		t.Fatal("the rejected reload advanced the reload generation")
	}
	if code := health(); code != http.StatusOK {
		t.Fatalf("after the rejected reload the previous handler must still serve, /health answered %d", code)
	}
}

// `benmore check` reports a route registration that panics. The preflight
// recovered the panic and dropped it, and did not run at all for an app
// without flows, so the check was clean for an app that could not start.
func TestCheckReportsARouteRegistrationPanic(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "app.yaml", "site_name: route clash\n")
	writeTestFile(t, dir, "schema.sql", routeClashSchema)
	for _, withFlow := range []bool{false, true} {
		if withFlow {
			writeTestFile(t, dir, "flows/ping.yaml", "on:\n  request:\n    method: GET\n    path: /api/ping-custom\n    auth: none\njobs:\n  ping:\n    steps:\n      - respond:\n          json: { ok: true }\n")
		}
		var found []CheckFinding
		for _, f := range RunSourceCheck(dir, "").Findings {
			if f.Source == "routes" {
				found = append(found, f)
			}
		}
		if len(found) != 1 || found[0].Severity != "error" {
			t.Fatalf("flows=%v: want one routes error, got %+v", withFlow, found)
		}
		for _, want := range []string{"route registration failed", "/api/_upload", "cannot start"} {
			if !strings.Contains(found[0].Message, want) {
				t.Fatalf("flows=%v: finding does not mention %q: %s", withFlow, want, found[0].Message)
			}
		}
		if strings.Contains(found[0].Message, "registered at") {
			t.Fatalf("finding carries the build's source paths: %s", found[0].Message)
		}
	}

	// A source file the preflight cannot stage is its own validator's finding.
	if findings := routePreflightFindings(os.ErrNotExist); len(findings) != 0 {
		t.Fatalf("an ordinary staging error is not a route finding: %+v", findings)
	}
	// An app whose routes register reports nothing.
	writeTestFile(t, dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT);\n")
	for _, f := range RunSourceCheck(dir, "").Findings {
		if f.Source == "routes" {
			t.Fatalf("a loadable app has a routes finding: %+v", f)
		}
	}
}
