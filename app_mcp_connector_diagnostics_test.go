//go:build !cli && !windows

package main

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

// `benmore mcp inspect --json` left out the review text and artifact layout,
// though both are contract-digest content a reviewer approves.
func TestAppMCPInspectShowsReviewedTextAndArtifact(t *testing.T) {
	app, _, _ := newUnenrolledCommandProviderTaskFixtureWithManifest(t, reviewFieldsFlow, "", func(m *AppMCPManifest, _ string) { reviewFieldsManifest(m) })
	report, err := inspectAppMCPSource(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	tool := report.ReviewedTools[0]
	if tool["title"] != "Complete a task" || tool["review_summary"] != "Marks the task done and records who did it." || tool["labels"] == nil || tool["review_changes"] == nil {
		t.Fatalf("inspect omits the reviewed text: %#v", tool)
	}

	e := newReadArtifactEnv(t, readArtifactYAML())
	report, err = inspectAppMCPSource(e.app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, tool := range report.ReviewedTools {
		if artifact, ok := tool["artifact"].(map[string]any); ok && len(artifact["sheets"].([]map[string]any)) > 0 {
			found = true
		}
		if _, ok := tool["title"]; ok && tool["name"] != "complete_item" {
			t.Fatalf("an undeclared title was reported: %#v", tool)
		}
	}
	if !found {
		t.Fatalf("inspect omits the artifact layout: %#v", report.ReviewedTools)
	}
}

// The consent page offered auto-approval of "complete_item" instead of the
// reviewed title the approval page shows.
func TestAppMCPConsentNamesAutoApproveToolsByTitle(t *testing.T) {
	app, _, _ := newUnenrolledCommandProviderTaskFixtureWithManifest(t, commandTaskFlowFixture, "", func(m *AppMCPManifest, _ string) {
		m.Tools[0].Approval = "grant"
		m.Tools[0].Title = "Complete a task"
	})
	if err := appMCPConnectorApply(context.Background(), app, appMCPConnectorRequest{Action: "enable", Writes: true, AutoApprove: true}); err != nil {
		t.Fatal(err)
	}
	appOAuthEnsureTables(app)
	if _, err := app.DB.Exec("INSERT INTO _benmore_oauth_clients(client_id,name,redirect_uris,scopes) VALUES ('client-fixture','Reviewed client',?,'tasks:write')", `["`+mcpOAuthFixtureRedirect+`"]`); err != nil {
		t.Fatal(err)
	}
	var userID int64
	if err := app.DB.QueryRow("SELECT id FROM _benmore_users WHERE email='task-actor@example.com'").Scan(&userID); err != nil {
		t.Fatal(err)
	}
	session := GetSessionFromDB(app.DB, CreateSession(app.DB, userID, "task-actor@example.com", "17", time.Hour))
	values := url.Values{"response_type": {"code"}, "client_id": {"client-fixture"}, "redirect_uri": {mcpOAuthFixtureRedirect}, "state": {"s"}, "scope": {"tasks:write"},
		"code_challenge": {oauthPKCEChallenge(strings.Repeat("v", 43))}, "code_challenge_method": {"S256"}, "resource": {grantFixtureResource}}
	consent, err := prepareAppMCPOAuthConsentFor(context.Background(), app, session, values, grantFixtureResource, "17", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(consent.AutoApprove, []string{"Complete a task"}) {
		t.Fatalf("consent offers %v, want the reviewed title", consent.AutoApprove)
	}
}

// "tool "approve_expense": strings require a finite maxLength" left the
// builder to search the whole schema for the unbounded string.
func TestAppMCPBoundErrorsNameThePropertyPath(t *testing.T) {
	m := commandManifest()
	m.Tools[0].InputSchema.Properties["arguments"].Properties["note"] = &AppMCPSchema{Type: "string"}
	data, err := yaml.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	_, err = parseAppMCPManifest(data)
	if err == nil || !strings.Contains(err.Error(), "input_schema.properties.arguments.properties.note: strings require a finite maxLength") {
		t.Fatalf("bound error does not name the property: %v", err)
	}
}

// enable --writes failed with "revision enrollment universe changed; explicit
// repair is required" while status said revision_enrollment: active, and no
// command offered a repair; only a full disable, enable, enable --writes
// worked. Status now says changed, and enable --writes re-enrolls.
func TestAppMCPEnableWritesReenrollsAChangedRevisionUniverse(t *testing.T) {
	installCanonicalHotHandler(t)
	app := enabledWritesFixture(t)
	flowPath := filepath.Join(app.Dir, "flows/complete_item.yaml")
	flow, err := os.ReadFile(flowPath)
	if err != nil {
		t.Fatal(err)
	}
	// The reviewed prepare step now also reads projects.
	const from = "query: SELECT id, status FROM tasks WHERE id = :id AND project_id = :project_id AND org_id = :tenant AND status <> 'done'"
	const to = "query: SELECT t.id, t.status FROM tasks AS t JOIN projects AS p ON p.id = t.project_id WHERE t.id = :id AND t.project_id = :project_id AND t.org_id = :tenant AND t.status <> 'done'"
	if !strings.Contains(string(flow), from) {
		t.Fatal("fixture prepare query moved")
	}
	writeTestFile(t, app.Dir, "flows/complete_item.yaml", strings.Replace(string(flow), from, to, 1))
	reviewAppMCPFixture(t, app.Dir)
	if err := hotReloadApp(app, false); err != nil {
		t.Fatal(err)
	}
	if st := connectorStatus(t, app); st.Enrollment != "changed" || st.ApprovedWrites {
		t.Fatalf("status after a reviewed universe change: %+v", st)
	}
	if err := connectorApply(t, app, "enable", true); err != nil {
		t.Fatalf("enable --writes after a reviewed universe change: %v", err)
	}
	if st := connectorStatus(t, app); st.Enrollment != "active" || !st.ApprovedWrites {
		t.Fatalf("status after re-enrollment: %+v", st)
	}
}
