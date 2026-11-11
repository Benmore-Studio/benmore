//go:build !cli && !windows

package main

import (
	"strings"
	"testing"
)

// Command SQL that names a function or a column the database does not have
// fails the same way on every attempt: SQLite cannot compile the statement.
// It used to pass review and then fail at _commit as a retryable
// unavailable_provider. An unknown function is refused by the source gates
// (no schema can make it exist); a column is not, because the schema files
// do not show the columns a migration or the framework adds, so that one is
// reported by the run, as the final invalid_declaration.

const unresolvedFixtureInsert = "INSERT INTO activities(task_id,actor_user_id,actor_email,event)"

func TestAppMCPCommandUnknownFunctionOrColumnIsFinal(t *testing.T) {
	const (
		callsUnknown = `calls the SQL function "%s", which approved commands cannot run`
		namesColumn  = "names a column the app's database does not have"
	)
	for _, tc := range []struct {
		name, from, to string
		function       string // "" for a column
		where          string // the statement, as the source gates name it
		runtimeWhere   string
		failsAtPrepare bool
		hidden         string // must not reach the client
	}{
		{name: "apply calls a misspelled function", from: functionFixtureApply, to: "completed_at = datetim('now') WHERE id = :id",
			function: "datetim", where: `apply SQL (step "complete_task")`, runtimeWhere: "apply SQL"},
		{name: "dependency calls a misspelled function", from: functionFixtureDependency, to: strings.Replace(functionFixtureDependency, "\n      params:", " AND lenght(status) > 0\n      params:", 1),
			function: "lenght", where: `dependency "selected_task" query`, runtimeWhere: "dependency query", failsAtPrepare: true},
		{name: "readback calls a misspelled function", from: functionFixtureReadback, to: "query: SELECT t.id,lowr(t.status) AS status,t.completed_by",
			function: "lowr", where: `readback SQL (step "completed_task")`, runtimeWhere: "readback SQL"},
		{name: "apply sets a missing column", from: functionFixtureApply, to: "completed_att = datetime('now') WHERE id = :id",
			runtimeWhere: "apply SQL", hidden: "completed_att"},
		{name: "apply inserts into a missing column", from: unresolvedFixtureInsert, to: "INSERT INTO activities(task_id,actor_user_id,actor_email,evnt)",
			runtimeWhere: "apply SQL", hidden: "evnt"},
		{name: "prepare selects a missing column", from: functionFixturePrepare, to: strings.Replace(functionFixturePrepare, "SELECT id, status FROM", "SELECT id, statuss AS status FROM", 1),
			runtimeWhere: "prepare SQL", failsAtPrepare: true, hidden: "statuss"},
		{name: "readback selects a missing column", from: functionFixtureReadback, to: "query: SELECT t.id,t.status,t.completed_bye AS completed_by",
			runtimeWhere: "readback SQL", hidden: "completed_bye"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			flow := functionFlow(t, tc.from, tc.to)
			// The fixture seals the manifest without the review gates, as a
			// manifest reviewed before these checks existed: the served load keeps it.
			h := newExposureHarnessWithFlow(t, flow, "")
			wantText := "The command's " + tc.runtimeWhere + " " + namesColumn
			if tc.function != "" {
				wantText = "The command's " + tc.runtimeWhere + " " + strings.Replace(callsUnknown, "%s", tc.function, 1)
			}
			assertFinal := func(step, code, text string) {
				t.Helper()
				if code != appMCPInvalidDeclarationCode || !strings.Contains(text, wantText) || !strings.Contains(text, "retrying cannot succeed") {
					t.Fatalf("%s: code=%q text=%q, want %s saying %q", step, code, text, appMCPInvalidDeclarationCode, wantText)
				}
				for _, leak := range []string{"SELECT", "UPDATE", "INSERT", "tasks", "activities", "no such", "has no column"} {
					if strings.Contains(text, leak) {
						t.Fatalf("%s: client text discloses %q: %s", step, leak, text)
					}
				}
				if tc.hidden != "" && strings.Contains(text, tc.hidden) {
					t.Fatalf("%s: client text names the column %q: %s", step, tc.hidden, text)
				}
			}
			if tc.failsAtPrepare {
				code, text := exposureCallText(h, "complete_item", map[string]any{"arguments": map[string]any{"id": 1, "project_id": 7}})
				assertFinal("prepare", code, text)
				if h.operationRows() != 0 {
					t.Fatal("a prepare that cannot compile stored an operation")
				}
			} else {
				id := h.prepare()
				h.approveOK(id)
				code, text := exposureCallText(h, appMCPCommitTool, map[string]any{"operation_id": id})
				assertFinal("commit", code, text)
				state := h.status(id)
				attempt, _ := state["attempt"].(map[string]any)
				if state["state"] != "failed" || state["business"] != "not_committed" || state["receipt"] != nil || state["retryable"] != false || attempt["error_class"] != appMCPInvalidDeclarationCode {
					t.Fatalf("status after a statement that cannot compile: %#v", state)
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
				t.Fatal("a statement that cannot compile left business rows")
			}

			said := functionSourceGates(t, h.app.Dir, flow)
			gates := []string{"mcp review", "mcp check", "mcp inspect", "write gate (flow file)", "write gate (mcp.yaml)", "benmore check"}
			if tc.function == "" {
				// A column: the schema files do not list what a migration or
				// the framework adds, so the source gates do not judge it.
				for _, gate := range gates {
					if said[gate] != "" {
						t.Errorf("%s refused a column the schema files alone cannot judge: %s", gate, said[gate])
					}
				}
				return
			}
			for _, gate := range gates {
				for _, want := range []string{tc.where, `calls function "` + tc.function + `"`, "which approved commands cannot run", "Command SQL may call only: "} {
					if !strings.Contains(said[gate], want) {
						t.Errorf("%s: %q does not contain %q", gate, said[gate], want)
					}
				}
			}
		})
	}
}

// soundex was on the list of functions command SQL may call, and in the
// reference, but the bundled SQLite is built without it: a command that
// called it passed every source gate and could never run.
func TestAppMCPCommandSQLCannotCallSoundex(t *testing.T) {
	flow := functionFlow(t, functionFixtureApply, "completed_at = soundex('done') WHERE id = :id")
	h := newExposureHarnessWithFlow(t, flow, "")
	id := h.prepare()
	h.approveOK(id)
	code, text := exposureCallText(h, appMCPCommitTool, map[string]any{"operation_id": id})
	if code != appMCPInvalidDeclarationCode || !strings.Contains(text, `calls the SQL function "soundex", which approved commands cannot run`) {
		t.Fatalf("commit of a command that calls soundex: code=%q text=%q", code, text)
	}
	if state := h.status(id); state["retryable"] != false || state["business"] != "not_committed" {
		t.Fatalf("status: %#v", state)
	}
	said := functionSourceGates(t, h.app.Dir, flow)
	for _, gate := range []string{"mcp review", "mcp check", "mcp inspect", "write gate (flow file)", "write gate (mcp.yaml)", "benmore check"} {
		message := said[gate]
		if !strings.Contains(message, `calls function "soundex", which approved commands cannot run`) {
			t.Errorf("%s accepted a call to soundex: %q", gate, message)
		}
		if _, list, _ := strings.Cut(message, "Command SQL may call only: "); strings.Contains(list, "soundex") {
			t.Errorf("%s lists soundex among the functions command SQL may call: %q", gate, message)
		}
	}
	if commandPhaseSQLFunctionAllowed("apply", "soundex") {
		t.Error("the command authorizer still admits soundex")
	}
}
