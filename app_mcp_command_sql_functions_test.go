//go:build !cli && !windows

package main

import (
	"database/sql"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/mattn/go-sqlite3"
)

// Command SQL that calls a function the command authorizer refuses used to pass
// review, mcp check, the write gate and benmore check, be prepared and
// approved, and then fail at _commit as a retryable unavailable_provider. The
// source gates now refuse it, naming the tool, the function and the allowed
// list, and the runtime reports the refusal as the final invalid_declaration.

const (
	functionFixtureApply      = "completed_at = datetime('now') WHERE id = :id"
	functionFixturePrepare    = "query: SELECT id, status FROM tasks WHERE id = :id AND project_id = :project_id AND org_id = :tenant AND status <> 'done'"
	functionFixtureDependency = "query: SELECT id FROM tasks WHERE id = :id AND project_id = :project_id AND org_id = :tenant AND status <> 'done'\n      params:"
	functionFixtureReadback   = "query: SELECT t.id,t.status,t.completed_by"
)

func functionFlow(t *testing.T, from, to string) string {
	t.Helper()
	flow := strings.Replace(commandTaskFlowFixture, from, to, 1)
	if flow == commandTaskFlowFixture {
		t.Fatalf("command fixture text changed: %q not found", from)
	}
	return flow
}

// functionSourceGates runs every source gate on a copy of the app's reviewed
// source and returns what each said ("" when it accepted the source).
func functionSourceGates(t *testing.T, appDir, flow string) map[string]string {
	t.Helper()
	dir := copyAppSources(t, appDir, "schema.sql", "app.yaml", "env.yaml", "flows/complete_item.yaml", "mcp.yaml")
	before, err := os.ReadFile(filepath.Join(dir, "mcp.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	said := map[string]string{}
	text := func(err error) string {
		if err == nil {
			return ""
		}
		return err.Error()
	}
	_, reviewErr := reviewAppMCPSource(dir)
	said["mcp review"] = text(reviewErr)
	if after, _ := os.ReadFile(filepath.Join(dir, "mcp.yaml")); reviewErr != nil && string(after) != string(before) {
		t.Fatal("a refused review rewrote mcp.yaml")
	}
	writeTestFile(t, dir, "mcp.yaml", string(before)) // check the manifest as it was reviewed before
	said["mcp check"] = text(runAppMCPCLI([]string{"check", dir}, io.Discard))
	_, inspectErr := inspectAppMCPSource(dir)
	said["mcp inspect"] = text(inspectErr)
	said["write gate (flow file)"] = ValidateOnWriteIn(dir, "flows/complete_item.yaml", flow)
	said["write gate (mcp.yaml)"] = ValidateOnWriteIn(dir, "mcp.yaml", string(before))
	for _, finding := range RunSourceCheck(dir, "").Findings {
		if finding.Severity == "error" && strings.Contains(finding.Message, "which approved commands cannot run") {
			said["benmore check"] = finding.Message
		}
	}
	return said
}

func TestAppMCPCommandSQLFunctionRefusedAtReviewAndFinalAtCommit(t *testing.T) {
	allowed := append([]string(nil), commandAllowedSQLFunctions...)
	sort.Strings(allowed)
	list := "Command SQL may call only: " + strings.Join(allowed, ", ") + "."
	for _, tc := range []struct {
		name, from, to   string
		function, where  string
		failsAtPrepare   bool
		wantRuntimeWhere string
	}{
		{name: "apply randomblob", from: functionFixtureApply, to: "completed_at = hex(randomblob(8)) WHERE id = :id",
			function: "randomblob", where: `apply SQL (step "complete_task")`, wantRuntimeWhere: "apply SQL"},
		{name: "apply trigger-only function by name", from: functionFixtureApply, to: "completed_at = benmore_encrypt('x') WHERE id = :id",
			function: "benmore_encrypt", where: `apply SQL (step "complete_task")`, wantRuntimeWhere: "SQL"},
		{name: "prepare random", from: functionFixturePrepare, to: functionFixturePrepare + " AND abs(random()) >= 0",
			function: "random", where: `prepare SQL (step "selected_task")`, failsAtPrepare: true, wantRuntimeWhere: "prepare SQL"},
		{name: "dependency random", from: functionFixtureDependency, to: strings.Replace(functionFixtureDependency, "\n      params:", " AND abs(random()) >= 0\n      params:", 1),
			function: "random", where: `dependency "selected_task" query`, failsAtPrepare: true, wantRuntimeWhere: "dependency query"},
		{name: "readback iif", from: functionFixtureReadback, to: "query: SELECT t.id,iif(t.status = 'done', 'done', 'open') AS status,t.completed_by",
			function: "iif", where: `readback SQL (step "completed_task")`, wantRuntimeWhere: "readback SQL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			flow := functionFlow(t, tc.from, tc.to)
			// The fixture seals the manifest without the review gates, as a
			// manifest reviewed before this check existed: the served load keeps it.
			h := newExposureHarnessWithFlow(t, flow, "")
			wantText := "calls the SQL function \"" + tc.function + "\", which approved commands cannot run"
			assertFinal := func(step, code, text string) {
				t.Helper()
				if code != appMCPInvalidDeclarationCode || !strings.Contains(text, "The command's "+tc.wantRuntimeWhere+" "+wantText) || !strings.Contains(text, "retrying cannot succeed") {
					t.Fatalf("%s: code=%q text=%q, want %s naming %s", step, code, text, appMCPInvalidDeclarationCode, tc.function)
				}
				for _, leak := range []string{"SELECT", "UPDATE", "tasks", "not authorized"} {
					if strings.Contains(text, leak) {
						t.Fatalf("%s: client text discloses %q: %s", step, leak, text)
					}
				}
			}
			if tc.failsAtPrepare {
				code, text := exposureCallText(h, "complete_item", map[string]any{"arguments": map[string]any{"id": 1, "project_id": 7}})
				assertFinal("prepare", code, text)
				if h.operationRows() != 0 {
					t.Fatal("a refused prepare stored an operation")
				}
			} else {
				id := h.prepare()
				h.approveOK(id)
				code, text := exposureCallText(h, appMCPCommitTool, map[string]any{"operation_id": id})
				assertFinal("commit", code, text)
				state := h.status(id)
				attempt, _ := state["attempt"].(map[string]any)
				if state["state"] != "failed" || state["business"] != "not_committed" || state["receipt"] != nil || state["retryable"] != false || attempt["error_class"] != appMCPInvalidDeclarationCode {
					t.Fatalf("status after a refused function: %#v", state)
				}
				code, text = exposureCallText(h, appMCPCommitTool, map[string]any{"operation_id": id})
				if code != appMCPInvalidDeclarationCode || !strings.Contains(text, "committing it again cannot succeed") {
					t.Fatalf("second commit: code=%q text=%q", code, text)
				}
				if again := h.status(id); again["retryable"] != false || again["attempt"].(map[string]any)["attempt_id"] != attempt["attempt_id"] {
					t.Fatalf("second commit claimed another attempt: %#v", again)
				}
			}
			if h.taskDone() || h.count("SELECT count(*) FROM activities WHERE task_id=1") != 0 {
				t.Fatal("a refused function left business rows")
			}

			said := functionSourceGates(t, h.app.Dir, flow)
			for _, gate := range []string{"mcp review", "mcp check", "mcp inspect", "write gate (flow file)", "write gate (mcp.yaml)", "benmore check"} {
				message := said[gate]
				for _, want := range []string{tc.where, `calls function "` + tc.function + `"`, "which approved commands cannot run", list} {
					if !strings.Contains(message, want) {
						t.Errorf("%s: %q does not contain %q", gate, message, want)
					}
				}
			}
			// The gates that see the manifest name the tool bound to the command
			// and its flow file; the flow file's own gate names the command.
			for _, gate := range []string{"mcp review", "mcp check", "mcp inspect", "write gate (mcp.yaml)"} {
				if !strings.Contains(said[gate], `mcp.yaml: tool "complete_item": flows/complete_item.yaml: `+tc.where) {
					t.Errorf("%s does not name the tool and its flow file: %q", gate, said[gate])
				}
			}
			if !strings.Contains(said["write gate (flow file)"], `command declaration: command "complete_item": `+tc.where) {
				t.Errorf("flow file gate does not name the command: %q", said["write gate (flow file)"])
			}
		})
	}
}

// The unchanged fixture, and SQL that calls only allowed functions, pass every
// gate and still commit.
func TestAppMCPCommandSQLFunctionCheckAcceptsAllowedFunctions(t *testing.T) {
	flow := functionFlow(t, functionFixtureApply, "completed_at = coalesce(strftime('%Y-%m-%d', 'now'), lower(hex(zeroblob(2))), json_extract('{\"a\":1}', '$.a')) WHERE id = :id")
	// CURRENT_TIMESTAMP is what the framework's own triggers read: the apply
	// authorizer admits it, so review does too.
	flow = strings.Replace(flow, "'completed' FROM tasks AS t", "CASE WHEN CURRENT_TIMESTAMP IS NULL THEN 'none' ELSE 'completed' END FROM tasks AS t", 1)
	if !strings.Contains(flow, "CURRENT_TIMESTAMP") {
		t.Fatal("command fixture text changed")
	}
	h := newExposureHarnessWithFlow(t, flow, "")
	for gate, message := range functionSourceGates(t, h.app.Dir, flow) {
		if message != "" {
			t.Errorf("%s refused allowed functions: %s", gate, message)
		}
	}
	id := h.prepare()
	h.approveOK(id)
	if code, text := exposureCallText(h, appMCPCommitTool, map[string]any{"operation_id": id}); code != "" {
		t.Fatalf("commit of allowed functions: code=%q text=%q", code, text)
	}
	if !h.taskDone() {
		t.Fatal("the command did not apply")
	}
}

// One list: the commit-time authorizer and the review check give the same
// answer for every function SQLite has registered, in every phase.
func TestCommandSQLFunctionAllowlistIsSharedByAuthorizerAndReview(t *testing.T) {
	db, err := sql.Open(sqliteMaintenanceDriver, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	rows, err := db.Query("SELECT DISTINCT name FROM pragma_function_list")
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{"current_timestamp": true, "current_date": true, "current_time": true, "raise": true}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		names[name] = true
	}
	if err := rows.Close(); err != nil || len(names) < 100 {
		t.Fatalf("function list: %d names, %v", len(names), err)
	}
	seen := map[string]bool{}
	for _, name := range commandAllowedSQLFunctions {
		if name != strings.ToLower(name) || seen[name] {
			t.Errorf("allowlist entry %q is not lowercase or is listed twice", name)
		}
		seen[name] = true
		if !names[name] {
			// Admitted by the authorizer, but this SQLite build does not have
			// it: a call fails with "no such function" before the authorizer
			// is asked, so the list (and the reference that prints it) would
			// offer a function no command can call.
			t.Errorf("allowlisted function %q is not registered on a framework connection", name)
		}
	}
	allowedSomewhere := 0
	for name := range names {
		for _, phase := range []string{"prepare", "apply", "readback"} {
			guard := &appMCPCommandExecution{phase: phase}
			authorized := guard.authorize(sqlite3.SQLITE_FUNCTION, "", name, "") == sqlite3.SQLITE_OK
			if authorized != commandPhaseSQLFunctionAllowed(phase, name) {
				t.Errorf("%s in %s: authorizer=%t, review rule=%t", name, phase, authorized, commandPhaseSQLFunctionAllowed(phase, name))
			}
			if authorized {
				allowedSomewhere++
			} else if guard.takeRefusedFunction() != name {
				t.Errorf("%s in %s: the authorizer did not note the function it refused", name, phase)
			}
			// Outside a command phase's own statement nothing is noted.
			internal := &appMCPCommandExecution{phase: phase, internal: true}
			if internal.authorize(sqlite3.SQLITE_FUNCTION, "", name, ""); internal.takeRefusedFunction() != "" {
				t.Errorf("%s in %s: a framework-internal statement was noted", name, phase)
			}
		}
	}
	if allowedSomewhere < 3*len(commandAllowedSQLFunctions) {
		t.Fatalf("only %d function/phase pairs allowed", allowedSomewhere)
	}

	// The review check decides by compiling the statement: its verdict follows
	// the same rule, phase by phase, and it never judges what it cannot compile.
	read := func(name string) ([]byte, error) {
		if name == "schema.sql" {
			return []byte("CREATE TABLE tasks (id INTEGER PRIMARY KEY, title TEXT, token TEXT);"), nil
		}
		return nil, os.ErrNotExist
	}
	check := func(phase, query string) error {
		command := &FlowCommand{}
		step := []FlowStep{{Name: "s", Type: "if", Steps: []FlowStep{{Name: "inner", Type: "sql", SQL: query}}}}
		switch phase {
		case "prepare":
			command.Prepare.Steps = step
		case "apply":
			command.Apply.Steps = step
		case "readback":
			command.Readback.Steps = step
		case "dependency":
			command.Dependencies = []FlowCommandDependency{{Name: "d", Table: "tasks", Query: query, MaxRows: 1}}
		}
		return appMCPCheckCommandSQLFunctions(read, []Flow{{Name: "f", Source: "flows/f.yaml", Command: command}}, nil)
	}
	for _, tc := range []struct {
		phase, query, refused string
	}{
		{"apply", "UPDATE tasks SET token = hex(randomblob(8)) WHERE id = :id", "randomblob"},
		{"apply", "UPDATE tasks SET token = hex(zeroblob(8)) WHERE id = :id", ""},
		{"apply", "UPDATE tasks SET title = CURRENT_TIMESTAMP WHERE id = :id", ""},
		{"prepare", "SELECT id FROM tasks WHERE title = CURRENT_TIMESTAMP", "current_timestamp"},
		{"readback", "SELECT id FROM tasks WHERE title = CURRENT_TIMESTAMP", "current_timestamp"},
		{"readback", "SELECT id, group_concat(title) AS titles FROM tasks", "group_concat"},
		{"readback", "SELECT id, count(*) AS n, max(title) AS last FROM tasks", ""},
		{"dependency", "SELECT id FROM tasks WHERE id = :id AND random() > 0", "random"},
		{"prepare", "SELECT id FROM tasks WHERE title LIKE 'a%' AND title GLOB 'a*' AND id IN (1, 2)", ""},
		{"apply", "INSERT INTO tasks(title, token) VALUES (:title, lower(:token)) ON CONFLICT(id) DO UPDATE SET title = excluded.title", ""},
		{"apply", "UPDATE tasks SET title = raise(ABORT, 'x') WHERE id = :id", "raise"},
		// A column only a migration adds: the schema files cannot compile it.
		{"apply", "UPDATE tasks SET archived_at = datetime('now') WHERE id = :id", ""},
		// The function name in a string or a comment is not a call.
		{"apply", "UPDATE tasks SET title = 'randomblob(8)' /* random() */ WHERE id = :id", ""},
	} {
		err := check(tc.phase, tc.query)
		switch {
		case tc.refused == "" && err != nil:
			t.Errorf("%s %q refused: %v", tc.phase, tc.query, err)
		case tc.refused != "" && (err == nil || !strings.Contains(err.Error(), `calls function "`+tc.refused+`"`) || !strings.HasPrefix(err.Error(), "flows/f.yaml: ")):
			t.Errorf("%s %q: %v, want a refusal of %s", tc.phase, tc.query, err, tc.refused)
		}
	}
	// No command, no schema: nothing to judge.
	if err := appMCPCheckCommandSQLFunctions(read, []Flow{{Name: "plain"}}, nil); err != nil {
		t.Fatal(err)
	}
	if err := appMCPCheckCommandSQLFunctions(func(string) ([]byte, error) { return nil, os.ErrNotExist }, []Flow{{Name: "f", Command: &FlowCommand{Apply: FlowCommandPhase{Steps: []FlowStep{{Type: "sql", SQL: "UPDATE tasks SET token = hex(randomblob(8))"}}}}}}, nil); err != nil {
		t.Fatalf("without schema files nothing can be compiled: %v", err)
	}
}
