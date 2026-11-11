//go:build !cli

package main

import (
	"bytes"
	"database/sql"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Round 2026-11-04 (lifecycle finding 5h, widened): every flow validator
// starts its message with "flows.yaml", so a refusal of flows/v1ping.yaml
// named a file the app does not have. The write gate and `benmore check` now
// name the file that was written.
func TestFlowFileRefusalsNameTheWrittenFile(t *testing.T) {
	dir := routeFixtureDir(t)
	for name, c := range map[string]struct{ path, content, want string }{
		"reserved prefix": {
			path:    "flows/v1ping.yaml",
			content: routeFixtureFlow("GET", "/api/_ping"),
			want:    `flows/v1ping.yaml: path "/api/_ping" collides with the framework's reserved prefix "/api/_"`,
		},
		"unknown verifier": {
			path:    "flows/hook.yaml",
			content: "on:\n  request: {method: POST, path: /api/hooks/in, verify: nonsense}\njobs:\n  run:\n    steps:\n      - run: respond\n        with: {json: {ok: true}}\n",
			want:    `flows/hook.yaml: on.request.verify "nonsense" is not a known verifier`,
		},
		"unknown step key": {
			path:    "flows/sub/deep.yaml",
			content: "on:\n  request: {method: POST, path: /api/deep}\njobs:\n  run:\n    steps:\n      - run: respond\n        with: {json: {ok: true}}\n        bogus: 1\n",
			want:    "flows/sub/deep.yaml",
		},
	} {
		t.Run(name, func(t *testing.T) {
			msg := ValidateOnWriteIn(dir, c.path, c.content)
			if !strings.Contains(msg, c.want) {
				t.Fatalf("refusal lacks %q:\n%s", c.want, msg)
			}
			for _, line := range strings.Split(msg, "\n") {
				if strings.HasPrefix(line, "flows.yaml") {
					t.Fatalf("refusal of %s still names flows.yaml:\n%s", c.path, msg)
				}
			}
		})
	}
	// The root flows.yaml keeps its name, and advice that mentions flows.yaml
	// further on is not rewritten.
	if msg := ValidateOnWriteIn(dir, "flows.yaml", routeFixtureFlow("GET", "/api/_ping")); !strings.HasPrefix(msg, `flows.yaml: path "/api/_ping"`) {
		t.Fatalf("root flows.yaml refusal:\n%s", msg)
	}
	if got := flowFileLabel(dir, filepath.Join(dir, "flows", "a.yaml")); got != "flows/a.yaml" {
		t.Fatalf("flowFileLabel = %q", got)
	}
	if got := nameFlowFile("flows.yaml: x\nwrite a flow in flows.yaml\nflows.yaml route GET /a", "flows/a.yaml"); got != "flows/a.yaml: x\nwrite a flow in flows.yaml\nflows/a.yaml route GET /a" {
		t.Fatalf("nameFlowFile = %q", got)
	}
}

// Round 2026-11-04 (lifecycle finding 5h): a flow skipped at load because
// another flow holds its route was logged with "Move the flow to a path the
// framework does not register". The log now names the other flow.
func TestFlowCollisionLogNamesTheOtherFlow(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	flow := func(name, file, method, path string) Flow {
		return Flow{Name: name, Source: file, Trigger: FlowTrigger{Type: "http", Method: method, Path: path},
			Steps: []FlowStep{{Name: "r", Type: "respond", Respond: &FlowRespond{Status: 200, JSON: map[string]any{"custom": true}}}}}
	}
	app := &App{Dir: dir, DB: db, SessionDuration: time.Hour, Stop: make(chan struct{}),
		Flows: []Flow{
			flow("ping", "flows/ping.yaml", "POST", "/api/ping/:id"),
			flow("ping_again", "flows/ping_again.yaml", "POST", "/api/ping/:pingId"),
			flow("health", "flows/health.yaml", "GET", "/health"),
		}}
	t.Cleanup(app.Shutdown)

	var logged bytes.Buffer
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	buildAppRouteMux(app, true, "http://localhost", true, nil)
	log.SetOutput(os.Stderr)

	var flowLine, frameworkLine string
	for _, line := range strings.Split(logged.String(), "\n") {
		switch {
		case strings.Contains(line, `flow "ping_again" route`):
			flowLine = line
		case strings.Contains(line, `flow "health" route`):
			frameworkLine = line
		}
	}
	if !strings.Contains(flowLine, "give this flow (flows/ping_again.yaml) or flow ping a different method or path") ||
		strings.Contains(flowLine, "framework does not register") {
		t.Fatalf("flow-vs-flow collision log:\n%s", logged.String())
	}
	if !strings.Contains(frameworkLine, "Move the flow (flows/health.yaml) to a path the framework does not register") {
		t.Fatalf("framework collision log:\n%s", logged.String())
	}
}
