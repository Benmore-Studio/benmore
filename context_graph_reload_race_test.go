//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The context-graph rebuild is a tracked worker: it runs beside requests and
// beside a reload that publishes new configuration. It must read that
// configuration the way every other reader does, so a reload during a rebuild
// is neither a data race nor a graph mixed from two configurations.

// contextGraphGeneration is one configuration whose every graph node carries
// name, so a graph built from two configurations is visible in its refs.
type contextGraphGeneration struct {
	pages      map[string]*Page
	partials   map[string]string
	hooks      *HookConfig
	flows      []Flow
	workflows  *WorkflowConfig
	computed   *ComputedFieldConfig
	encrypted  *EncryptedFieldConfig
	validators *ValidatorConfig
	roles      *RolesConfig
	group      *GroupConfig
}

func newContextGraphGeneration(name string) contextGraphGeneration {
	return contextGraphGeneration{
		pages:      map[string]*Page{"/" + name: {Route: "/" + name, File: name + ".html", Layout: "none", RawHTML: "<page layout=\"none\">" + name + "</page>"}},
		partials:   map[string]string{name: "<nav>" + name + "</nav>"},
		hooks:      &HookConfig{OnInsert: map[string][]Hook{name: {{SQL: "SELECT 1"}}}},
		flows:      []Flow{{Name: name, Trigger: FlowTrigger{Type: "http", Method: "POST", Path: "/api/" + name}}},
		workflows:  &WorkflowConfig{Workflows: map[string]*Workflow{name: {Name: name, Table: "notes", Field: "status"}}},
		computed:   &ComputedFieldConfig{Fields: map[string]map[string]*ComputedField{name: {"total": {Table: name, Column: "total", Expr: "1"}}}},
		encrypted:  &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{name: {{Column: "secret"}}}},
		validators: &ValidatorConfig{Rules: map[string][]ValidatorRule{name: {{Rule: "1 = 1", Error: name}}}},
		roles:      &RolesConfig{Roles: map[string]RoleDef{name: {Scopes: "notes:read"}}},
		group:      &GroupConfig{Table: "members", Key: name, UserField: "user_id"},
	}
}

// publish installs g the way a reload publishes configuration: every field
// under app.mu, each object replaced whole.
func (g contextGraphGeneration) publish(app *App) {
	app.mu.Lock()
	defer app.mu.Unlock()
	app.Pages, app.Partials = g.pages, g.partials
	app.Hooks, app.Flows, app.Workflows = g.hooks, g.flows, g.workflows
	app.Computed, app.Encrypted, app.Validators = g.computed, g.encrypted, g.validators
	app.Roles, app.Group = g.roles, g.group
}

// A publication between two of the rebuild's reads must not show: each graph
// holds the eleven configuration nodes of exactly one generation.
func TestContextGraphRebuildReadsOnePublishedConfiguration(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	app := &App{Dir: dir, DB: db}
	t.Cleanup(app.Shutdown)
	mustExec(t, db, "CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT, status TEXT)")
	generations := []contextGraphGeneration{newContextGraphGeneration("alpha"), newContextGraphGeneration("beta")}
	generations[0].publish(app)

	stop, published := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(published)
		for i := 1; ; i++ {
			select {
			case <-stop:
				return
			default:
				generations[i%2].publish(app)
				time.Sleep(20 * time.Microsecond)
			}
		}
	}()
	defer func() {
		close(stop)
		<-published
	}()

	for rebuild := 0; rebuild < 40; rebuild++ {
		RebuildContextGraph(app)
		rows, err := db.Query("SELECT node_type, ref FROM _benmore_context_nodes WHERE node_type != 'table' ORDER BY node_type, ref")
		if err != nil {
			t.Fatal(err)
		}
		var refs []string
		seen := map[string]int{}
		for rows.Next() {
			var nodeType, ref string
			if err := rows.Scan(&nodeType, &ref); err != nil {
				t.Fatal(err)
			}
			refs = append(refs, ref)
			for _, name := range []string{"alpha", "beta"} {
				if strings.Contains(ref, name) {
					seen[name]++
				}
			}
		}
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
		// page, partial, hook, flow, api_endpoint, workflow, computed_field,
		// encrypted_field, validator, role, group
		if len(refs) != 11 || (seen["alpha"] != 11 && seen["beta"] != 11) {
			t.Fatalf("rebuild %d: graph is not one whole configuration (alpha %d, beta %d of %d nodes): %v", rebuild, seen["alpha"], seen["beta"], len(refs), refs)
		}
	}
}

func contextGraphReloadFixture(t *testing.T) *App {
	t.Helper()
	dir := t.TempDir()
	writeTestFile(t, dir, "app.yaml", "name: graph\nroles:\n  auditor:\n    scopes: notes:read\n")
	writeTestFile(t, dir, "schema.sql", "CREATE TABLE notes (\n id INTEGER PRIMARY KEY,\n title TEXT,\n status TEXT\n);\n")
	writeTestFile(t, dir, "report.html", contextGraphReloadPage(0))
	writeTestFile(t, dir, "partials/nav.html", "<nav>navigation</nav>")
	writeTestFile(t, dir, "hooks.yaml", "on_insert:\n  notes:\n    - sql: \"UPDATE notes SET status = 'new' WHERE status IS NULL\"\n")
	writeTestFile(t, dir, "flows.yaml", "on:\n  request: {method: POST, path: /api/summary}\njobs:\n  first:\n    steps:\n      - run: respond\n        with: {json: {ok: true}}\n")
	writeTestFile(t, dir, "workflows.yaml", "notes:\n  table: notes\n  field: status\n  initial: new\n  transitions:\n    new:\n      done: {role: admin}\n")
	app, err := loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	return app
}

func contextGraphReloadPage(version int) string {
	return fmt.Sprintf("<page title=\"Report %d\" auth=\"none\" layout=\"none\">\n<include src=\"partials/nav.html\">\n<query sql=\"SELECT title FROM notes\" as=\"rows\">{{#rows}}<p>{{title}}</p>{{/rows}}</query>\n</page>", version)
}

// Real reloads of a loaded app while rebuilds run: every reload succeeds and
// the graph ends as the last configuration. The race detector seldom sees the
// unlocked reads through this path (a reload's last step before it publishes
// is a write transaction, the rebuild reads inside one, and every statement of
// both passes through the driver's callback lock, which orders them for the
// detector); TestContextGraphRebuildReadsOnePublishedConfiguration is the test
// that fails without the snapshot.
func TestContextGraphRebuildDuringReload(t *testing.T) {
	app := contextGraphReloadFixture(t)
	const reloads = 12
	reloadErr := make(chan error, 1)
	go func() {
		defer close(reloadErr)
		for version := 1; version <= reloads; version++ {
			if err := os.WriteFile(filepath.Join(app.Dir, "report.html"), []byte(contextGraphReloadPage(version)), 0o644); err != nil {
				reloadErr <- err
				return
			}
			if err := reloadAppConfig(app); err != nil {
				reloadErr <- fmt.Errorf("reload %d: %w", version, err)
				return
			}
		}
	}()
	for reloading := true; reloading; {
		select {
		case err, failed := <-reloadErr:
			if failed {
				t.Fatal(err)
			}
			reloading = false
		default:
			// A rebuild holds the write lock; back off for as long as it ran so
			// the reload's own migrations are not starved by this loop.
			began := time.Now()
			RebuildContextGraph(app)
			time.Sleep(time.Since(began) + 2*time.Millisecond)
		}
	}

	// The graph of the last published configuration, whole.
	RebuildContextGraph(app)
	count := func(nodeType string) (n int) {
		t.Helper()
		if err := app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_context_nodes WHERE node_type = ?", nodeType).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	for _, nodeType := range []string{"table", "page", "partial", "hook", "flow", "api_endpoint", "workflow", "role"} {
		if count(nodeType) == 0 {
			t.Errorf("rebuilt graph has no %s node", nodeType)
		}
	}
	var raw string
	if err := app.DB.QueryRow("SELECT metadata FROM _benmore_context_nodes WHERE node_type = 'page' AND ref = 'page:/report'").Scan(&raw); err != nil {
		t.Fatalf("page node: %v", err)
	}
	var meta map[string]any
	if err := json.Unmarshal([]byte(raw), &meta); err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprintf("Report %d", reloads); meta["title"] != want {
		t.Errorf("page node title = %v, want %q (the last reload's page)", meta["title"], want)
	}
	var edges int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM _benmore_context_edges e
		JOIN _benmore_context_nodes f ON f.id = e.from_node JOIN _benmore_context_nodes t ON t.id = e.to_node
		WHERE f.ref = 'page:/report' AND t.ref = 'table:notes' AND e.edge_type = 'queries'`).Scan(&edges); err != nil || edges != 1 {
		t.Errorf("page → table queries edges = %d (err %v), want 1", edges, err)
	}
}
