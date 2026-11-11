//go:build !cli && !windows

package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// The reported case (r1104 finding 3): the approver signed out after
// approving. _status and _commit say denied/approval_lapsed; the review page
// said "Approved. Your assistant can now apply this change." It must say what
// they say, and the batch page must explain it too.
func TestAppMCPReviewPageAgreesWithStatusOnLapsedApproval(t *testing.T) {
	h := newExposureHarness(t)
	id := h.prepare()
	h.approveOK(id)
	if _, body, _ := h.review(h.cookie, id); !strings.Contains(body, "Approved. Your assistant can now apply this change.") {
		t.Fatalf("live approval page: %s", body)
	}
	// Sign out (the approving session ends), then sign back in.
	if _, err := h.app.DB.Exec("DELETE FROM _benmore_sessions WHERE user_id=?", h.actorID); err != nil {
		t.Fatal(err)
	}
	if state := h.status(id); state["state"] != "denied" || state["reason"] != appMCPBlockApprovalLapsed {
		t.Fatalf("status: %#v", state)
	}
	h.cookie = CreateSession(h.app.DB, h.actorID, "task-actor@example.com", "17", time.Hour)

	status, body, token := h.review(h.cookie, id)
	if status != http.StatusOK || strings.Contains(body, "can now apply") || token != "" {
		t.Fatalf("lapsed approval page claims it applies or offers approval: %d token=%q\n%s", status, token, body)
	}
	for _, want := range []string{`class="note bad"`, "The approval no longer holds", "can&#39;t apply this change", "prepare it again"} {
		if !strings.Contains(body, want) {
			t.Errorf("lapsed approval page lacks %q:\n%s", want, body)
		}
	}

	resp, batch := h.do("GET", appMCPBatchRoute+"?grant="+url.QueryEscape(h.pair.GrantID), h.cookie, nil, nil)
	if resp.StatusCode != http.StatusOK || strings.Contains(batch, `name="op" value="`+id+`"`) {
		t.Fatalf("batch page offers the lapsed operation: %d\n%s", resp.StatusCode, batch)
	}
	for _, want := range []string{"<h2>Can't be applied</h2>", "The approval no longer holds", "Nothing from this connection is waiting for your approval."} {
		if !strings.Contains(batch, want) {
			t.Errorf("batch page lacks %q:\n%s", want, batch)
		}
	}
	assertMCPPageHeaders(t, resp, batch)
	if h.taskDone() {
		t.Fatal("business row changed")
	}
}

// A role change the command reads (${{ user.role }}) blocks the operation in
// _status and _commit (actor_changed). The review page used to refuse to show
// it at all ("can't be shown"); it now shows the operation with the reason and
// still refuses to approve it. The block follows the live role.
func TestAppMCPReviewPageAgreesWithStatusOnChangedRole(t *testing.T) {
	app, sessions := newCommandCapabilityFixture(t)
	ensureCommandAuditFixture(t, app)
	EnsureJobsTable(app.DB)
	generation := snapshotAppMCPGeneration(app)
	var uid int64
	var role string
	if err := app.DB.QueryRow(`SELECT u.id, u.role FROM _benmore_sessions s JOIN _benmore_users u ON u.id=s.user_id WHERE s.id=?`, sessions["editor"]).Scan(&uid, &role); err != nil {
		t.Fatal(err)
	}
	pair, err := createAppMCPNativeGrantFor(context.Background(), app, uid, "17", "editor-client", grantFixtureResource, "complete_item", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	grant, err := readAppMCPGrant(app.DB, pair.GrantID)
	if err != nil {
		t.Fatal(err)
	}
	origin, err := appMCPConnectorOrigin(app, generation, grant, &generation.manifest.Tools[0], pair.AccessToken, grantFixtureResource)
	if err != nil {
		t.Fatal(err)
	}
	request := appMCPCommandRequest{app: app, generation: generation, toolName: "complete_item", origin: origin, now: time.Now().UTC()}
	review := request
	review.origin = appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessions["editor"]}
	prepared, err := appMCPPrepareOperation(context.Background(), request, map[string]any{"arguments": map[string]any{"id": 1, "project_id": 7}})
	if err != nil {
		t.Fatal(err)
	}
	setRole := func(r string) {
		t.Helper()
		if _, err := app.DB.Exec(`UPDATE _benmore_users SET role=? WHERE id=?`, r, uid); err != nil {
			t.Fatal(err)
		}
	}

	setRole("admin")
	shown, err := appMCPReviewOperation(context.Background(), review, prepared.ID, "")
	if err != nil {
		t.Fatalf("review after role change: %v (the page would say it can't be shown)", err)
	}
	if shown.State != "denied" || shown.Reason != appMCPBlockActorChanged {
		t.Fatalf("review state %q reason %q, want denied/%s", shown.State, shown.Reason, appMCPBlockActorChanged)
	}
	view := newAppMCPReviewView(shown, prepared.ID, time.Now())
	if view.StateKind != "bad" || !strings.Contains(view.StateText, "Your role in this app changed") {
		t.Fatalf("state note: %q %q", view.StateKind, view.StateText)
	}
	_, err = appMCPReviewOperation(context.Background(), review, prepared.ID, "fixture-approved")
	var blocked *appMCPOperationBlockedError
	if !errors.As(err, &blocked) || blocked.Reason != appMCPBlockActorChanged {
		t.Fatalf("approve while blocked: %v", err)
	}

	setRole(role)
	if shown, err = appMCPReviewOperation(context.Background(), review, prepared.ID, ""); err != nil || shown.State != "prepared" || shown.Reason != "" {
		t.Fatalf("review with the role back: %+v %v", shown, err)
	}
	if _, err := appMCPReviewOperation(context.Background(), review, prepared.ID, "fixture-approved"); err != nil {
		t.Fatalf("approve with the role back: %v", err)
	}
	if out, err := appMCPCommitOperation(context.Background(), request, prepared.ID); err != nil || out.Outcome != "applied" {
		t.Fatalf("commit: %+v %v", out, err)
	}
}

// The page reads attempts as _status does: an approved operation whose apply
// failed shows that failure, not "Approved".
func TestAppMCPReviewPageShowsTheLatestAttempt(t *testing.T) {
	h := newExposureHarness(t)
	id := h.prepare()
	h.approveOK(id)
	attempt := h.insertAttempt(id, appMCPClock().Unix())
	h.forceAttemptState(attempt, appMCPAttemptFailed, "unavailable_provider")
	if state := h.status(id); state["state"] != appMCPAttemptFailed {
		t.Fatalf("status: %#v", state)
	}
	_, body, _ := h.review(h.cookie, id)
	if strings.Contains(body, "can now apply") || !strings.Contains(body, "This change could not be applied.") {
		t.Fatalf("failed attempt page: %s", body)
	}
}

// A standing-consent (approval: grant) approval is judged against the
// connection's own credential, which a browser session does not hold. The page
// must not call a live consent lapsed, nor promise more than it can check.
func TestAppMCPReviewPageGrantApprovalIsNotCalledLapsed(t *testing.T) {
	h := newGrantExposureHarness(t, "grant", "complete_item")
	req, err := h.connectorRequest()
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := appMCPPrepareOperation(context.Background(), req, map[string]any{"arguments": map[string]any{"id": 1, "project_id": 7}})
	if err != nil || !prepared.AutoApproved {
		t.Fatalf("prepare: %+v %v", prepared, err)
	}
	review := h.reviewOf(prepared.ID)
	if review.State != "approved" || review.Reason != "" || !review.ByConsent {
		t.Fatalf("grant approval on the page: state %q reason %q consent %t", review.State, review.Reason, review.ByConsent)
	}
	view := newAppMCPReviewView(review, prepared.ID, time.Now())
	if strings.Contains(view.StateText, "can now apply") || !strings.Contains(view.StateText, "permission you gave this connection") {
		t.Fatalf("consent note: %q", view.StateText)
	}
}

// Every reason _status can report has its own sentence on the page.
func TestAppMCPReviewStateNoteNamesEveryBlock(t *testing.T) {
	seen := map[string]bool{}
	for _, reason := range []string{appMCPBlockSourceChanged, appMCPBlockActorChanged, appMCPBlockApprovalLapsed} {
		kind, text := appMCPReviewStateNote(&appMCPReview{State: "denied", Reason: reason})
		if kind != "bad" || text == "" || seen[text] || strings.Contains(text, "can now apply") {
			t.Errorf("%s: %q %q", reason, kind, text)
		}
		seen[text] = true
	}
}

// r1104 finding 9: the "Exact data" block showed & < > as \u0026 \u003c
// \u003e. Only hidden characters are escaped; the page still HTML-escapes the
// text when it renders it.
func TestAppMCPReviewExactDataKeepsAmpersandAndAngleBrackets(t *testing.T) {
	text, err := appMCPReviewPreviewText(map[string]any{"note": "Tom & Jerry <script>x</script>", "hidden": "a\u200bb"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, `"note": "Tom & Jerry <script>x</script>"`) || strings.Contains(text, `\u0026`) || strings.Contains(text, `\u003c`) {
		t.Fatalf("preview text: %s", text)
	}
	if !strings.Contains(text, `"hidden": "a\u200bb"`) {
		t.Fatalf("hidden character not escaped: %s", text)
	}
	h := newExposureHarness(t)
	review := &appMCPReview{Tool: "complete_item", Preview: text, State: "prepared", ExpiresAt: time.Now().Add(10 * time.Minute).Unix()}
	rec := httptest.NewRecorder()
	writeAppMCPPage(rec, h.app, 200, appMCPReviewPage, appMCPReviewPageOpts, newAppMCPReviewView(review, strings.Repeat("a", 32), time.Now()))
	body := rec.Body.String()
	if strings.Contains(body, "<script>x") || !strings.Contains(body, "Tom &amp; Jerry &lt;script&gt;x&lt;/script&gt;") {
		t.Fatalf("rendered exact data is not HTML-escaped once: %s", body)
	}
}

// The text content of a connector result is the JSON a model reads; it carries
// & < > as written.
func TestAppMCPToolTextContentKeepsAmpersandAndAngleBrackets(t *testing.T) {
	result := appMCPCommandResult(map[string]any{"note": "R&D <draft>"})
	text := result.Content[0].(*sdk.TextContent).Text
	if text != `{"note":"R&D <draft>"}` {
		t.Fatalf("command text content: %s", text)
	}
	encoded, err := appMCPJSONText(appMCPReadResult{Data: map[string]any{"title": "A & B"}, ObservedAt: "now"})
	if err != nil || !strings.Contains(string(encoded), `"title":"A & B"`) || strings.HasSuffix(string(encoded), "\n") {
		t.Fatalf("read text content: %q %v", encoded, err)
	}
}

// r1104 finding 12: an input-schema violation names the JSON path and rule,
// never the rejected value.
func TestAppMCPCommandInvalidInputNamesThePath(t *testing.T) {
	h := newExposureHarness(t)
	for _, tc := range []struct {
		name      string
		arguments map[string]any
		want      []string
	}{
		{"wrong type", map[string]any{"id": "secret-value-123", "project_id": 7}, []string{"arguments.id", "expected finite number"}},
		{"out of bounds", map[string]any{"id": 0, "project_id": 7}, []string{"arguments.id", "outside schema bounds"}},
		{"missing", map[string]any{"project_id": 7}, []string{"arguments.id", "required property is missing"}},
		{"undeclared", map[string]any{"id": 1, "project_id": 7, "note": "secret-value-123"}, []string{"arguments", `"note"`, "not allowed"}},
	} {
		code, text, isError := h.callMessage("complete_item", map[string]any{"arguments": tc.arguments})
		if !isError || code != "invalid_input" || strings.Contains(text, "secret-value-123") {
			t.Errorf("%s: code %q text %q", tc.name, code, text)
			continue
		}
		for _, want := range tc.want {
			if !strings.Contains(text, want) {
				t.Errorf("%s: %q lacks %q", tc.name, text, want)
			}
		}
	}
	if h.operationRows() != 0 {
		t.Fatal("an invalid input prepared an operation")
	}
}

func TestAppMCPSchemaValueErrorNamesNestedPathWithoutTheValue(t *testing.T) {
	no := false
	schema := &AppMCPSchema{Type: "object", AdditionalProperties: &no, Properties: map[string]*AppMCPSchema{
		"items": {Type: "array", Items: &AppMCPSchema{Type: "object", AdditionalProperties: &no, Properties: map[string]*AppMCPSchema{
			"status": {Type: "string", Enum: []any{"open", "done"}},
		}}},
	}}
	value := map[string]any{"items": []any{map[string]any{"status": "open"}, map[string]any{"status": "s3cr3t"}}}
	err := validateAppMCPSchemaValue(schema, value)
	var named *appMCPSchemaValueError
	if !errors.As(err, &named) || named.Path != "items[1].status" || strings.Contains(err.Error(), "s3cr3t") || !strings.Contains(err.Error(), "items[1].status: value is not in enum") {
		t.Fatalf("enum error: %v", err)
	}
	// An undeclared key is named only when it is a plain identifier.
	err = validateAppMCPSchemaValue(schema, map[string]any{"items": []any{}, "pass word=hunter2": 1})
	if err == nil || strings.Contains(err.Error(), "hunter2") || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("undeclared odd key: %v", err)
	}
	failure := appMCPInvalidInputFailure(err)
	var result *appMCPResultError
	if !errors.As(failure, &result) || result.Code != "invalid_input" || strings.Contains(result.Message, "hunter2") {
		t.Fatalf("failure: %#v", failure)
	}
}

// r1104 finding 10: artifact.export returns the download_url artifact.create
// returns, on the same retrieval route with the same session rules.
func TestAppMCPArtifactExportReturnsDownloadURL(t *testing.T) {
	h := newExposureHarness(t)
	operationID := h.prepare()
	h.approveOK(operationID)
	if result, code := h.call(h.client, appMCPCommitTool, map[string]any{"operation_id": operationID}); code != "" || result["outcome"] != "applied" {
		t.Fatalf("command commit: code=%q result=%#v", code, result)
	}
	exported, code := h.call(h.client, mcpArtifactExportTool, map[string]any{"operation_id": operationID, "format": "html"})
	if code != "" {
		t.Fatalf("html export: %s", code)
	}
	artifactID, _ := exported["artifact_id"].(string)
	link, _ := exported["download_url"].(string)
	if artifactID == "" || link != h.server.URL+"/api/_mcp/artifacts/"+artifactID {
		t.Fatalf("export result: %#v", exported)
	}
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	status, data := mcpArtifactGet(t, h.app, strings.TrimPrefix(u.Path, "/api/_mcp/artifacts/"), h.cookie)
	if status != http.StatusOK || !strings.Contains(string(data), "<html") {
		t.Fatalf("download with the session: %d", status)
	}
	// A bearer credential (the assistant's) still cannot fetch it.
	if status, _ := mcpArtifactGet(t, h.app, artifactID, ""); status != http.StatusUnauthorized {
		t.Fatalf("download without a session: %d", status)
	}
}
