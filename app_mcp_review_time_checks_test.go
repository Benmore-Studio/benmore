//go:build !cli && !windows

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"go.yaml.in/yaml/v3"
)

// ---- dependency result shape -------------------------------------------------

const shapeFixtureDependency = "query: SELECT id FROM tasks WHERE id = :id AND project_id = :project_id AND org_id = :tenant AND status <> 'done'\n      params:"

func shapeFlow(t *testing.T, selectList string) string {
	t.Helper()
	flow := strings.Replace(commandTaskFlowFixture, shapeFixtureDependency, "query: SELECT "+selectList+" FROM tasks WHERE id = :id AND project_id = :project_id AND org_id = :tenant AND status <> 'done'\n      params:", 1)
	if flow == commandTaskFlowFixture && selectList != "id" {
		t.Fatal("dependency fixture text changed")
	}
	return flow
}

// exposureCallText calls a connector tool and returns the error code and the
// text the client sees ("" when the call succeeded).
func exposureCallText(h *exposureHarness, name string, args map[string]any) (code, text string) {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	result, err := h.client.CallTool(ctx, &sdk.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		h.t.Fatalf("call %s: %v", name, err)
	}
	if !result.IsError {
		return "", ""
	}
	code, _ = result.Meta["error_code"].(string)
	for _, content := range result.Content {
		if text, ok := content.(*sdk.TextContent); ok {
			return code, text.Text
		}
	}
	return code, ""
}

// copyAppSources copies the reviewed source files of a fixture app into a fresh
// directory, as they were when the fixture sealed its manifest.
func copyAppSources(t *testing.T, from string, files ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, file := range files {
		data, err := os.ReadFile(filepath.Join(from, file))
		if err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, dir, file, string(data))
	}
	return dir
}

// A dependency query that does not return exactly one id column used to pass
// review, mcp check, the write gate and benmore check, then fail every prepare
// as an opaque unavailable_provider. Every source gate now refuses it with the
// runtime's own message, and the runtime names it as a final error.
func TestAppMCPDependencyShapeRefusedAtSourceTimeAndNamedAtRuntime(t *testing.T) {
	const want = `dependency "selected_task" must return exactly one id column`
	for name, selectList := range map[string]string{
		"extra column": "id, status",
		"other column": "project_id",
		"star":         "*",
	} {
		t.Run(name, func(t *testing.T) {
			flow := shapeFlow(t, selectList)
			h := newExposureHarnessWithFlow(t, flow, "")
			code, text := exposureCallText(h, "complete_item", map[string]any{"arguments": map[string]any{"id": 1, "project_id": 7}})
			if code != appMCPInvalidDeclarationCode || !strings.Contains(text, want) || !strings.Contains(text, "retrying cannot succeed") {
				t.Fatalf("runtime prepare: code=%q text=%q, want %s naming the dependency", code, text, appMCPInvalidDeclarationCode)
			}
			if strings.Contains(text, "SELECT") || strings.Contains(text, "tasks") {
				t.Fatalf("runtime error disclosed SQL: %q", text)
			}

			dir := copyAppSources(t, h.app.Dir, "schema.sql", "app.yaml", "env.yaml", "flows/complete_item.yaml", "mcp.yaml")
			manifestBefore, err := os.ReadFile(filepath.Join(dir, "mcp.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := reviewAppMCPSource(dir); err == nil || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "flows/complete_item.yaml") {
				t.Fatalf("review: %v", err)
			}
			if after, _ := os.ReadFile(filepath.Join(dir, "mcp.yaml")); string(after) != string(manifestBefore) {
				t.Fatal("refused review rewrote mcp.yaml")
			}
			if err := runAppMCPCLI([]string{"check", dir}, io.Discard); err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("mcp check: %v", err)
			}
			if issue := ValidateOnWriteIn(dir, "flows/complete_item.yaml", flow); !strings.Contains(issue, want) {
				t.Fatalf("write gate: %q", issue)
			}
			found := false
			for _, finding := range RunSourceCheck(dir, "").Findings {
				if finding.Severity == "error" && strings.Contains(finding.Message, want) {
					found = true
				}
			}
			if !found {
				t.Fatal("benmore check did not report the dependency shape")
			}
			// The same file with an accepted shape passes the gate.
			for _, ok := range []string{"id", "tasks.id", "id AS ID"} {
				if issue := ValidateOnWriteIn(dir, "flows/complete_item.yaml", shapeFlow(t, ok)); strings.Contains(issue, "exactly one id column") {
					t.Fatalf("valid select list %q refused: %s", ok, issue)
				}
			}
		})
	}
}

// What the schema files alone cannot prepare (a column a migration adds) is
// left to the runtime check rather than refused on a guess.
func TestAppMCPDependencyShapeLeavesUnpreparableQueriesToRuntime(t *testing.T) {
	read := func(name string) ([]byte, error) {
		if name == "schema.sql" {
			return []byte("CREATE TABLE tasks (id INTEGER PRIMARY KEY, title TEXT);"), nil
		}
		return nil, os.ErrNotExist
	}
	flow := func(query string) []Flow {
		return []Flow{{Name: "f", Source: "flows/f.yaml", Command: &FlowCommand{Dependencies: []FlowCommandDependency{{Name: "d", Table: "tasks", Query: query, Params: map[string]FlowCommandParamRef{"id": {Kind: "intent_path", Path: "id"}}, MaxRows: 1}}}}}
	}
	if err := appMCPCheckCommandDependencyShapes(read, flow("SELECT id, archived_at FROM tasks WHERE id = :id")); err != nil {
		t.Fatalf("a query the schema cannot prepare was refused: %v", err)
	}
	if err := appMCPCheckCommandDependencyShapes(read, flow("SELECT id, title FROM tasks WHERE id = :id")); err == nil || !strings.Contains(err.Error(), "flows/f.yaml: dependency \"d\" must return exactly one id column") || !strings.Contains(err.Error(), "2 column(s): id, title") {
		t.Fatalf("two-column dependency: %v", err)
	}
}

// ---- deterministic constraint failures ---------------------------------------

func TestAppMCPCommandConstraintFailureClassification(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	for _, statement := range []string{
		"PRAGMA foreign_keys=ON",
		"CREATE TABLE parents (id INTEGER PRIMARY KEY, code TEXT UNIQUE, name TEXT NOT NULL, qty INTEGER CHECK (qty >= 0))",
		"CREATE TABLE children (id INTEGER PRIMARY KEY, parent_id INTEGER NOT NULL REFERENCES parents(id))",
		"CREATE TABLE _benmore_ledger (id INTEGER PRIMARY KEY, entry TEXT UNIQUE)",
		"CREATE TABLE guarded (id INTEGER PRIMARY KEY)",
		"CREATE TRIGGER guarded_raise BEFORE INSERT ON guarded BEGIN SELECT RAISE(ABORT, 'revision ledger row missing'); END",
		"INSERT INTO parents VALUES (1, 'a', 'secret-name', 1)",
		"INSERT INTO children VALUES (1, 1)",
		"INSERT INTO _benmore_ledger VALUES (1, 'k')",
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
	fail := func(query string) error {
		t.Helper()
		_, err := db.Exec(query)
		if err == nil {
			t.Fatalf("%s did not fail", query)
		}
		return err
	}
	for name, tc := range map[string]struct{ query, reason string }{
		"foreign key delete": {"DELETE FROM parents WHERE id = 1", "a foreign key constraint failed"},
		"foreign key insert": {"INSERT INTO children VALUES (2, 99)", "a foreign key constraint failed"},
		"unique":             {"INSERT INTO parents VALUES (2, 'a', 'B', 1)", "a uniqueness constraint failed"},
		"primary key":        {"INSERT INTO parents VALUES (1, 'b', 'B', 1)", "a uniqueness constraint failed"},
		"not null":           {"UPDATE parents SET name = NULL WHERE id = 1", "a NOT NULL constraint failed"},
		"check":              {"UPDATE parents SET qty = -1 WHERE id = 1", "a CHECK constraint failed"},
	} {
		err := appMCPCommandConstraintFailure(fail(tc.query))
		var final *appMCPCommandFinalError
		if !errors.As(err, &final) || final.Code != appMCPConstraintFailedCode || !strings.Contains(final.Message, tc.reason) || !strings.Contains(final.Message, "rolled back") {
			t.Errorf("%s: %#v", name, err)
			continue
		}
		for _, leak := range []string{"parents", "children", "secret-name", "DELETE", "INSERT", "UPDATE", "qty"} {
			if strings.Contains(final.Message, leak) {
				t.Errorf("%s: client message discloses %q: %s", name, leak, final.Message)
			}
		}
		if class := appMCPCommandErrorClass(fmt.Errorf("apply step: %w", err)); class != appMCPConstraintFailedCode {
			t.Errorf("%s: class %q", name, class)
		}
		if state, class := appMCPAttemptOutcomeFor(err); state != appMCPAttemptFailed || class != appMCPConstraintFailedCode {
			t.Errorf("%s: attempt outcome %s/%s, want a known failed attempt", name, state, class)
		}
	}
	// Outages, the framework's trigger guards and framework tables keep their class.
	for name, query := range map[string]string{
		"trigger raise":    "INSERT INTO guarded VALUES (1)",
		"framework table":  "INSERT INTO _benmore_ledger VALUES (2, 'k')",
		"not a constraint": "SELECT json('{')",
	} {
		if class := appMCPCommandErrorClass(appMCPCommandConstraintFailure(fail(query))); class != "unavailable_provider" {
			t.Errorf("%s: class %q, want unavailable_provider", name, class)
		}
	}
	hook := newAppMCPCommandHookError("parents", "update", fail("UPDATE parents SET name = NULL WHERE id = 1"), false)
	if class := appMCPCommandErrorClass(appMCPCommandConstraintFailure(hook)); class != "hook_refused" {
		t.Errorf("hook error reclassified: %q", class)
	}

	now := time.Now()
	failed := func(class string) *appMCPAttempt {
		return &appMCPAttempt{appMCPAttemptRecord: appMCPAttemptRecord{State: appMCPAttemptFailed, ErrorClass: class, StartedAt: now.Unix(), FinishedAt: now.Unix()}}
	}
	if appMCPAttemptRetryable(appMCPAttemptFailed, failed(appMCPConstraintFailedCode), 1, now) || appMCPAttemptRetryable(appMCPAttemptFailed, failed(appMCPInvalidDeclarationCode), 1, now) {
		t.Error("a deterministic failure was reported retryable")
	}
	if !appMCPAttemptRetryable(appMCPAttemptFailed, failed("unavailable_provider"), 1, now) {
		t.Error("an outage stopped being retryable")
	}
}

// End to end through _commit and _status: the failure is a known, rolled-back
// failed attempt with its own code, retryable false, and a second _commit adds
// no attempt.
func TestAppMCPExposureConstraintFailureIsFinal(t *testing.T) {
	const set = "UPDATE tasks SET status = 'done', completed_by"
	returningSQL := "query: UPDATE tasks SET status = 'done', completed_by = :actor, completed_at = datetime('now') WHERE id = :id AND project_id = :project_id AND org_id = :tenant AND status <> 'done'"
	for _, tc := range []struct {
		name      string
		hooks     string
		returning bool
	}{
		{name: "ordinary write"},
		{name: "hooked write", hooks: hookFiredOnUpdate},
		{name: "returning write", returning: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			flow := commandTaskFlowFixture
			if tc.returning {
				flow = strings.Replace(flow, returningSQL, returningSQL+" RETURNING id", 1)
			}
			flow = strings.Replace(flow, set, "UPDATE tasks SET status = NULL, completed_by", 1)
			if !strings.Contains(flow, "SET status = NULL") {
				t.Fatal("fixture text changed")
			}
			h := newExposureHarnessWithFlow(t, flow, tc.hooks)
			id := h.prepare()
			h.approveOK(id)
			code, text := exposureCallText(h, appMCPCommitTool, map[string]any{"operation_id": id})
			if code != appMCPConstraintFailedCode || !strings.Contains(text, "a NOT NULL constraint failed") || !strings.Contains(text, "rolled back") {
				t.Fatalf("commit: code=%q text=%q", code, text)
			}
			if strings.Contains(text, "tasks.") || strings.Contains(text, "UPDATE") {
				t.Fatalf("commit text discloses SQL: %q", text)
			}
			state := h.status(id)
			attempt, _ := state["attempt"].(map[string]any)
			if state["state"] != "failed" || state["business"] != "not_committed" || state["receipt"] != nil || state["retryable"] != false || attempt["error_class"] != appMCPConstraintFailedCode {
				t.Fatalf("status after a constraint failure: %#v", state)
			}
			code, text = exposureCallText(h, appMCPCommitTool, map[string]any{"operation_id": id})
			if code != appMCPConstraintFailedCode || !strings.Contains(text, "Prepare a new operation") {
				t.Fatalf("second commit: code=%q text=%q", code, text)
			}
			again := h.status(id)
			if againAttempt, _ := again["attempt"].(map[string]any); againAttempt["attempt_id"] != attempt["attempt_id"] || again["retryable"] != false {
				t.Fatalf("second commit claimed another attempt: %#v", again)
			}
			if h.taskDone() || h.count("SELECT count(*) FROM activities WHERE task_id=1") != 0 {
				t.Fatal("constraint failure left business or activity rows")
			}
		})
	}
}

// The reported case: deleting a row other rows still reference.
func TestAppMCPCommandForeignKeyDeleteIsConstraintFailed(t *testing.T) {
	from := "query: UPDATE tasks SET status = 'done', completed_by = :actor, completed_at = datetime('now') WHERE id = :id AND project_id = :project_id AND org_id = :tenant AND status <> 'done'\n          params: {id: '${{ params.id }}', project_id: '${{ params.project_id }}', actor: '${{ user.id }}', tenant: '${{ user.group_id }}'}"
	to := "query: DELETE FROM tasks WHERE id = :id AND project_id = :project_id AND org_id = :tenant AND status <> 'done'\n          params: {id: '${{ params.id }}', project_id: '${{ params.project_id }}', tenant: '${{ user.group_id }}'}"
	flow := strings.Replace(commandTaskFlowFixture, from, to, 1)
	if flow == commandTaskFlowFixture {
		t.Fatal("fixture text changed")
	}
	schema := strings.Replace(commandFKScanSchema, "task_id INTEGER NOT NULL,", "task_id INTEGER NOT NULL REFERENCES tasks(id),", 1)
	app, sessionID, userID := newUnenrolledCommandProviderTaskFixtureWithManifest(t, flow, "", func(_ *AppMCPManifest, dir string) {
		writeTestFile(t, dir, "schema.sql", schema)
	})
	if _, err := updateAppMCPEpoch(app.Dir, true, false, true); err != nil {
		t.Fatal(err)
	}
	generation := snapshotAppMCPGeneration(app)
	if _, err := initializeAppMCPRevisionEnrollment(context.Background(), app, generation); err != nil {
		t.Fatal(err)
	}
	if _, err := enableAppMCPRevisionEnrolledWrites(context.Background(), app, generation); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec(`INSERT INTO activities(id,task_id,actor_user_id,actor_email,event) VALUES(50,1,?,'seed@example.com','seed')`, userID); err != nil {
		t.Fatal(err)
	}
	origin := appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}
	prepared, err := prepareCommandTask(t, app, origin)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	_, err = applyCommandTask(t, app, origin, prepared)
	var final *appMCPCommandFinalError
	if appMCPCommandErrorClass(err) != appMCPConstraintFailedCode || !errors.As(err, &final) || !strings.Contains(final.Message, "a foreign key constraint failed") {
		t.Fatalf("foreign key delete: class %q err %v", appMCPCommandErrorClass(err), err)
	}
	var tasks, activities int
	if err := app.DB.QueryRow(`SELECT (SELECT count(*) FROM tasks WHERE id=1), (SELECT count(*) FROM activities WHERE task_id=1)`).Scan(&tasks, &activities); err != nil || tasks != 1 || activities != 1 {
		t.Fatalf("rolled-back delete changed rows: tasks=%d activities=%d %v", tasks, activities, err)
	}
}

// ---- review keeps the authored text ------------------------------------------

const reviewFormatManifest = `# Notes connector. Reviewed by hand before each release.
version: 1
connector:
  id: notes
  name: Notes
  version: '1'
resources: []
connections: []
tools:
  - name: list_notes
    description: Read notes with bounded pagination
    handler: {kind: native, operation: table.list, table: notes}
    input_schema:
      type: object
      additionalProperties: false
      properties:
        page: {type: integer, minimum: 1}
        per_page: {type: integer, minimum: 1, maximum: 500}
    output_schema:
      type: object
      additionalProperties: false
      properties:
        id: {type: integer, minimum: 1, maximum: 9007199254740991}
        title: {type: string}
        views: {type: integer, minimum: 0, maximum: 100000000} # counted per visit
    permissions: [notes:read]
    effect: read
    approval: none
    idempotency: none
    reconciliation: none
    output: {include: [id, title, views]}
    component: none
`

const reviewFormatAddedTool = `  - name: read_note
    description: Read one note
    handler: {kind: native, operation: table.read, table: notes}
    input_schema:
      type: object
      additionalProperties: false
      required: [id]
      properties:
        id: {type: integer, minimum: 1, maximum: 9007199254740991}
    output_schema:
      type: object
      additionalProperties: false
      properties:
        id: {type: integer}
        title: {type: string}
    permissions: [notes:read]
    effect: read
    approval: none
    idempotency: none
    reconciliation: none
    output: {include: [id, title]}
    component: none
`

func withoutReviewKeys(text string) string {
	var kept []string
	for _, line := range strings.SplitAfter(text, "\n") {
		if !strings.HasPrefix(line, "contract_digest:") && !strings.HasPrefix(line, "execution_digest:") && !strings.HasPrefix(line, "execution_sources:") {
			kept = append(kept, line)
		}
	}
	return strings.Join(kept, "")
}

func TestAppMCPReviewKeepsIntegersIndentationAndComments(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT, views INTEGER);")
	writeTestFile(t, dir, "mcp.yaml", reviewFormatManifest)
	authored, err := parseAppMCPManifestForReview([]byte(reviewFormatManifest))
	if err != nil {
		t.Fatal(err)
	}
	authored.ExecutionSources = appMCPExecutionSourcesRuntime
	wantContract, err := appMCPContractDigest(authored)
	if err != nil {
		t.Fatal(err)
	}
	report, err := reviewAppMCPSource(dir)
	if err != nil {
		t.Fatalf("review: %v", err)
	}
	reviewed, err := os.ReadFile(filepath.Join(dir, "mcp.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(reviewed)
	if withoutReviewKeys(text) != reviewFormatManifest {
		t.Fatalf("review changed authored text beyond its own keys:\n%s", text)
	}
	if strings.Contains(text, "e+") || !strings.Contains(text, "maximum: 100000000} # counted per visit") || !strings.Contains(text, "maximum: 9007199254740991}") {
		t.Fatalf("integer bounds were rewritten:\n%s", text)
	}
	if !strings.Contains(text, "\nexecution_sources: runtime\n") || !strings.Contains(text, "\ncontract_digest: "+report.ContractDigest+"\n") || report.ContractDigest != wantContract {
		t.Fatalf("review keys: report %s want %s\n%s", report.ContractDigest, wantContract, text)
	}

	// A tool added later in the documented two-space style parses and reviews.
	writeTestFile(t, dir, "mcp.yaml", text+reviewFormatAddedTool)
	second, err := reviewAppMCPSource(dir)
	if err != nil {
		t.Fatalf("review after a two-space edit: %v", err)
	}
	config, err := loadRuntimeConfig(dir)
	if err != nil || config.mcp == nil || len(config.mcp.Tools) != 2 || config.mcp.ContractDigest != second.ContractDigest {
		t.Fatalf("reviewed two-tool manifest: %v", err)
	}
	if max := config.mcp.Tools[1].InputSchema.Properties["id"].Maximum; max == nil || *max != 9007199254740991 {
		t.Fatalf("bound decoded as %v", max)
	}
}

// A manifest written by the earlier review (re-encoded, four-space, floats)
// still verifies, and reviewing it again keeps its bytes and digests.
func TestAppMCPReviewKeepsEarlierReviewOutputAndDigests(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT, views INTEGER);")
	writeTestFile(t, dir, "mcp.yaml", reviewFormatManifest)
	first, err := reviewAppMCPSource(dir)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "mcp.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := parseAppMCPManifest(data)
	if err != nil {
		t.Fatal(err)
	}
	earlier, err := yaml.Marshal(manifest) // the previous review's output form
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(earlier), "1e+08") || !strings.Contains(string(earlier), "\n    - name: list_notes") {
		t.Fatalf("fixture is not the earlier output form:\n%s", earlier)
	}
	writeTestFile(t, dir, "mcp.yaml", string(earlier))
	config, err := loadRuntimeConfig(dir)
	if err != nil || config.mcp == nil || config.mcp.ContractDigest != first.ContractDigest || config.mcp.ExecutionDigest != first.ExecutionDigest {
		t.Fatalf("earlier review output no longer verifies: %v", err)
	}
	again, err := reviewAppMCPSource(dir)
	if err != nil {
		t.Fatal(err)
	}
	resealed, _ := os.ReadFile(filepath.Join(dir, "mcp.yaml"))
	if string(resealed) != string(earlier) || again.ContractDigest != first.ContractDigest || again.ExecutionDigest != first.ExecutionDigest {
		t.Fatalf("re-review changed an unchanged manifest:\n%s", resealed)
	}

	// A flow-style document cannot be edited line by line; it is re-encoded
	// from its nodes and still binds the same declarations.
	flowStyle := "{version: 1, connector: {id: notes, name: Notes, version: '1'}, tools: [], resources: [], connections: []}\n"
	writeTestFile(t, dir, "mcp.yaml", flowStyle)
	if _, err := reviewAppMCPSource(dir); err != nil {
		t.Fatalf("flow-style review: %v", err)
	}
	if _, err := loadRuntimeConfig(dir); err != nil {
		t.Fatalf("flow-style reviewed manifest: %v", err)
	}
}

// The starter mcp.yaml of a new app is written in the documented two-space
// style too, so the first added tool can follow it.
func TestAppMCPStarterIsTwoSpaceAndSealed(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteHTMLScaffoldFiles(dir, "Notes fixture"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "mcp.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "\ntools:\n  - name: list_notes\n") || !strings.Contains(string(data), "maximum: 500}") || !strings.Contains(string(data), "\nexecution_sources: runtime\n") {
		t.Fatalf("starter manifest:\n%s", data)
	}
	if config, err := loadRuntimeConfig(dir); err != nil || config.mcp == nil {
		t.Fatalf("starter manifest does not verify: %v", err)
	}
}

// ---- OAuth dynamic client registration -----------------------------------------

// The connector registration answer names the grants the token endpoint
// actually honours (RFC 7591 3.2.1), the same set its metadata advertises, and
// the registered client really is issued and can use a refresh token.
func TestAppMCPOAuthRegisterAnswersRefreshGrant(t *testing.T) {
	f := newAppMCPOAuthHTTPFixture(t)
	w := f.request(t, http.MethodGet, "/.well-known/oauth-authorization-server", nil, "", "")
	var metadata struct {
		Grants []string `json:"grant_types_supported"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &metadata); err != nil || w.Code != http.StatusOK {
		t.Fatalf("metadata: %d %v", w.Code, err)
	}
	register := func(body map[string]any) (string, []string) {
		t.Helper()
		payload, _ := json.Marshal(body)
		r := httptest.NewRequest(http.MethodPost, appMCPOAuthHTTPOrigin+"/oauth/register", strings.NewReader(string(payload)))
		r.Host = "fixture.example"
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		f.mux.ServeHTTP(w, r)
		var registered struct {
			ClientID string   `json:"client_id"`
			Grants   []string `json:"grant_types"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &registered); err != nil || w.Code != http.StatusCreated {
			t.Fatalf("register: %d %s", w.Code, w.Body.String())
		}
		return registered.ClientID, registered.Grants
	}
	want := []string{"authorization_code", "refresh_token"}
	clientID, grants := register(map[string]any{"client_name": "Loopback test", "redirect_uris": []string{mcpOAuthFixtureRedirect},
		"grant_types": want, "response_types": []string{"code"}, "token_endpoint_auth_method": "none"})
	if !reflect.DeepEqual(grants, want) || !reflect.DeepEqual(metadata.Grants, want) {
		t.Fatalf("registered grants %v, metadata %v, want %v", grants, metadata.Grants, want)
	}
	if _, defaulted := register(map[string]any{"client_name": "No grant types", "redirect_uris": []string{mcpOAuthFixtureRedirect}}); !reflect.DeepEqual(defaulted, want) {
		t.Fatalf("registration without grant_types answered %v; the token endpoint refreshes for every client", defaulted)
	}

	f.values.Set("client_id", clientID)
	form := appMCPOAuthHTTPConsent(t, f)
	form.Set("decision", "approve")
	w = f.request(t, http.MethodPost, "/oauth/authorize", form, appMCPOAuthHTTPOrigin, "")
	callback, err := url.Parse(w.Header().Get("Location"))
	if w.Code != http.StatusFound || err != nil || callback.Query().Get("code") == "" {
		t.Fatalf("approve for the registered client: %d %s", w.Code, w.Body.String())
	}
	exchange := url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID}, "resource": f.values["resource"], "code": {callback.Query().Get("code")}, "redirect_uri": f.values["redirect_uri"], "code_verifier": {strings.Repeat("v", 43)}}
	w = f.request(t, http.MethodPost, "/oauth/token", exchange, "", "")
	var pair struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &pair); err != nil || w.Code != http.StatusOK || pair.RefreshToken == "" {
		t.Fatalf("code exchange: %d %s", w.Code, w.Body.String())
	}
	refresh := url.Values{"grant_type": {"refresh_token"}, "client_id": {clientID}, "resource": f.values["resource"], "refresh_token": {pair.RefreshToken}}
	if w = f.request(t, http.MethodPost, "/oauth/token", refresh, "", ""); w.Code != http.StatusOK {
		t.Fatalf("refresh by the registered client: %d %s", w.Code, w.Body.String())
	}

	// The non-connector app endpoint issues no refresh tokens and says so.
	app, cleanup := newOAuthTestApp(t)
	defer cleanup()
	rec := httptest.NewRecorder()
	appOAuthRegister(rec, httptest.NewRequest(http.MethodPost, "https://myapp.example.com/oauth/register", strings.NewReader(`{"client_name":"Legacy","redirect_uris":["https://client.example/cb"]}`)), app)
	var legacy struct {
		Grants []string `json:"grant_types"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &legacy); err != nil || !reflect.DeepEqual(legacy.Grants, []string{"authorization_code"}) {
		t.Fatalf("legacy registration grants: %s", rec.Body.String())
	}
}
