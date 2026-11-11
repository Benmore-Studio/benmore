//go:build !cli && !windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"go.yaml.in/yaml/v3"
)

// editReviewedToolDescription re-reviews mcp.yaml with an edited tool
// description and hot-reloads it. The epochs do not move, so an operation
// prepared before it stays unexpired under a source it was not prepared for.
func editReviewedToolDescription(t *testing.T, h *exposureHarness) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(h.app.Dir, "mcp.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := parseAppMCPManifest(data)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Tools[0].Description += " Edited after the operation was prepared."
	if data, err = yaml.Marshal(manifest); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, h.app.Dir, "mcp.yaml", string(data))
	reviewAppMCPFixture(t, h.app.Dir)
	if err := hotReloadApp(h.app, false); err != nil {
		t.Fatalf("valid reload refused: %v", err)
	}
}

// commitFailure calls _commit and returns the failed result's code, reason and
// text; a successful commit fails the test.
func commitFailure(t *testing.T, session *sdk.ClientSession, id string) (code, reason, text string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	result, err := session.CallTool(ctx, &sdk.CallToolParams{Name: appMCPCommitTool, Arguments: map[string]any{"operation_id": id}})
	if err != nil {
		t.Fatalf("call _commit: %v", err)
	}
	if !result.IsError {
		t.Fatalf("_commit applied: %#v", result.StructuredContent)
	}
	code, _ = result.Meta["error_code"].(string)
	reason, _ = result.Meta["reason"].(string)
	if len(result.Content) > 0 {
		if content, ok := result.Content[0].(*sdk.TextContent); ok {
			text = content.Text
		}
	}
	return code, reason, text
}

// A hot reload ends approved writes and rotates the write epoch, so a changed
// source reaches a connector only behind that rotation (expired, below) or a
// new disclosure version. The check itself is pinned here.
func TestAppMCPBindSourceNamesWhatChanged(t *testing.T) {
	stored := &appMCPStoredOperation{}
	stored.Prepared.DisclosureVersion = appMCPDisclosureVersion
	stored.Prepared.ContractDigest, stored.Prepared.ExecutionDigest = "contract", "execution"
	stored.Prepared.Origin.ActorRole = "editor"
	capability := func(contract string, role string) *appMCPCommandCapability {
		return &appMCPCommandCapability{
			generation: &appMCPRuntimeGeneration{manifest: &AppMCPManifest{ContractDigest: contract, ExecutionDigest: "execution"}},
			actor:      Session{Role: role},
		}
	}
	if err := appMCPBindSource(capability("contract", "editor"), stored); err != nil {
		t.Fatalf("unchanged: %v", err)
	}
	for _, tc := range []struct {
		name, contract, role, want string
	}{
		{"source changed", "other", "editor", appMCPBlockSourceChanged},
		{"role changed", "contract", "admin", appMCPBlockActorChanged},
	} {
		err := appMCPBindSource(capability(tc.contract, tc.role), stored)
		var blocked *appMCPOperationBlockedError
		if !errors.As(err, &blocked) || blocked.Reason != tc.want || !errors.Is(err, errAppMCPOperationDenied) {
			t.Errorf("%s: %v, want a denied block with reason %s", tc.name, err, tc.want)
		}
	}
}

// A live operation is unaffected: no reason, and it commits.
func TestAppMCPCommitAndStatusLiveOperationHasNoReason(t *testing.T) {
	h := newExposureHarness(t)
	id := h.prepare()
	if state := h.status(id); state["state"] != "prepared" || state["reason"] != nil {
		t.Fatalf("prepared status: %#v", state)
	}
	if code, reason, _ := commitFailure(t, h.client, id); code != "approval_required" || reason != "" {
		t.Fatalf("unapproved _commit = code %q reason %q", code, reason)
	}
	h.approveOK(id)
	if state := h.status(id); state["state"] != "approved" || state["reason"] != nil {
		t.Fatalf("approved status: %#v", state)
	}
	out, code := h.call(h.client, appMCPCommitTool, map[string]any{"operation_id": id})
	if code != "" || out["outcome"] != "applied" {
		t.Fatalf("_commit = %#v %q", out, code)
	}
	if state := h.status(id); state["state"] != "succeeded" || state["reason"] != nil {
		t.Fatalf("committed status: %#v", state)
	}
}

// The reason is said only to the caller the operation is bound to.
func TestAppMCPCommitAndStatusStayOpaqueToOtherCallers(t *testing.T) {
	h := newExposureHarness(t)
	id := h.prepare()
	h.approveOK(id)
	if _, err := h.app.DB.Exec("DELETE FROM _benmore_sessions WHERE user_id=?", h.actorID); err != nil {
		t.Fatal(err)
	}
	other, err := createAppMCPNativeGrantFor(t.Context(), h.app, h.actorID, "17", "client-other", h.resource, "complete_item", appMCPClock())
	if err != nil {
		t.Fatal(err)
	}
	client := appMCPClient(t, h.server, other.AccessToken, nil)
	if code, reason, text := commitFailure(t, client, id); code != "denied" || reason != "" || strings.Contains(text, appMCPBlockApprovalLapsed) {
		t.Fatalf("another connection's _commit = code %q reason %q text %q", code, reason, text)
	}
	if _, code := h.call(client, appMCPStatusTool, map[string]any{"operation_id": id}); code != "denied" {
		t.Fatalf("another connection's _status = %q, want denied", code)
	}
}

// Expiry comes first in both answers, whatever else changed: here the owner
// changed the reviewed source and switched the connector off and on.
func TestAppMCPCommitAndStatusAgreeOnExpiryOverSource(t *testing.T) {
	installCanonicalHotHandler(t)
	h := newExposureHarness(t)
	id := h.prepare()
	h.approveOK(id)
	if err := connectorApply(t, h.app, "disable", true); err != nil {
		t.Fatal(err)
	}
	editReviewedToolDescription(t, h)
	if err := connectorApply(t, h.app, "enable", true); err != nil {
		t.Fatal(err)
	}
	h.client = appMCPClient(t, h.server, h.pair.AccessToken, nil)
	if state := h.status(id); state["state"] != "expired" || state["reason"] != nil {
		t.Fatalf("status: %#v", state)
	}
	if code, _, _ := commitFailure(t, h.client, id); code != "expired_intent" {
		t.Fatalf("_commit = %q, want expired_intent", code)
	}
}

// The approval's own checks agree too: the approving session ended.
func TestAppMCPCommitAndStatusAgreeOnLapsedApproval(t *testing.T) {
	h := newExposureHarness(t)
	id := h.prepare()
	h.approveOK(id)
	if _, err := h.app.DB.Exec("DELETE FROM _benmore_sessions WHERE user_id=?", h.actorID); err != nil {
		t.Fatal(err)
	}
	state := h.status(id)
	if state["state"] != "denied" || state["reason"] != appMCPBlockApprovalLapsed || state["retryable"] != false {
		t.Fatalf("status: %#v", state)
	}
	if code, reason, _ := commitFailure(t, h.client, id); code != "denied" || reason != appMCPBlockApprovalLapsed {
		t.Fatalf("_commit = code %q reason %q", code, reason)
	}
	if h.taskDone() {
		t.Fatal("business row changed")
	}
}

// A grant-domain approval: live, it reads approved and commits; after the owner
// turns auto-approve off, status and commit agree it has lapsed.
func TestAppMCPCommitAndStatusAgreeOnGrantApproval(t *testing.T) {
	input, _ := appMCPDecodeToolArguments(json.RawMessage(`{"arguments":{"id":1,"project_id":7}}`))
	statusOf := func(t *testing.T, h *exposureHarness, id string) *appMCPStatusView {
		t.Helper()
		generation := snapshotAppMCPGeneration(h.app)
		grant, err := readAppMCPGrant(h.app.DB, h.pair.GrantID)
		if err != nil {
			t.Fatal(err)
		}
		tool, _, err := appMCPFindCommandDeclaration(generation, "complete_item")
		if err != nil {
			t.Fatal(err)
		}
		origin, err := appMCPConnectorStatusOrigin(h.app, generation, grant, tool, h.pair.AccessToken, h.resource)
		if err != nil {
			t.Fatal(err)
		}
		view, err := appMCPStatusOperation(context.Background(), appMCPCommandRequest{app: h.app, generation: generation, toolName: "complete_item", origin: origin, readOnlyStatus: true}, id)
		if err != nil {
			t.Fatalf("status: %v", err)
		}
		return view
	}
	prepare := func(t *testing.T, h *exposureHarness) string {
		t.Helper()
		req, err := h.connectorRequest()
		if err != nil {
			t.Fatal(err)
		}
		view, err := appMCPPrepareOperation(context.Background(), req, input)
		if err != nil || !view.AutoApproved {
			t.Fatalf("prepare: %+v %v", view, err)
		}
		return view.ID
	}

	t.Run("live", func(t *testing.T) {
		h := newGrantExposureHarness(t, "grant", "complete_item")
		id := prepare(t, h)
		if view := statusOf(t, h, id); view.State != "approved" || view.Reason != "" {
			t.Fatalf("status: %+v", view)
		}
		req, err := h.connectorRequest()
		if err != nil {
			t.Fatal(err)
		}
		if out, err := appMCPCommitOperation(context.Background(), req, id); err != nil || out.Outcome != "applied" {
			t.Fatalf("commit: %+v %v", out, err)
		}
	})
	t.Run("auto-approve turned off", func(t *testing.T) {
		h := newGrantExposureHarness(t, "grant", "complete_item")
		id := prepare(t, h)
		if err := appMCPConnectorApply(context.Background(), h.app, appMCPConnectorRequest{Action: "disable", AutoApprove: true}); err != nil {
			t.Fatal(err)
		}
		if view := statusOf(t, h, id); view.State != "denied" || view.Reason != appMCPBlockApprovalLapsed || view.Retryable {
			t.Fatalf("status: %+v", view)
		}
		req, err := h.connectorRequest()
		if err != nil {
			t.Fatal(err)
		}
		_, err = appMCPCommitOperation(context.Background(), req, id)
		result := appMCPCommandFailure("_commit", id, err)
		if result.Meta["error_code"] != "denied" || result.Meta["reason"] != appMCPBlockApprovalLapsed {
			t.Fatalf("commit failure meta: %#v (%v)", result.Meta, err)
		}
		if h.taskDone() {
			t.Fatal("business row changed")
		}
	})
}

// The reported case: a command that reads ${{ user.role }} seals the role at
// prepare. The block follows the live role: it clears when the role returns.
func TestAppMCPCommitAndStatusAgreeOnChangedRole(t *testing.T) {
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
	tool := &generation.manifest.Tools[0]
	origin, err := appMCPConnectorOrigin(app, generation, grant, tool, pair.AccessToken, grantFixtureResource)
	if err != nil {
		t.Fatal(err)
	}
	statusOrigin, err := appMCPConnectorStatusOrigin(app, generation, grant, tool, pair.AccessToken, grantFixtureResource)
	if err != nil {
		t.Fatal(err)
	}
	request := appMCPCommandRequest{app: app, generation: generation, toolName: "complete_item", origin: origin, now: time.Now().UTC()}
	statusRequest := appMCPCommandRequest{app: app, generation: generation, toolName: "complete_item", origin: statusOrigin, readOnlyStatus: true}
	approve := request
	approve.origin = appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessions["editor"]}
	prepared, err := appMCPPrepareOperation(context.Background(), request, map[string]any{"arguments": map[string]any{"id": 1, "project_id": 7}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := appMCPReviewOperation(context.Background(), approve, prepared.ID, "fixture-approved"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if _, err := app.DB.Exec(`UPDATE _benmore_users SET role='admin' WHERE id=?`, uid); err != nil {
		t.Fatal(err)
	}
	view, err := appMCPStatusOperation(context.Background(), statusRequest, prepared.ID)
	if err != nil || view.State != "denied" || view.Reason != appMCPBlockActorChanged || view.Business != "not_committed" {
		t.Fatalf("status after role change: %+v %v", view, err)
	}
	_, err = appMCPCommitOperation(context.Background(), request, prepared.ID)
	result := appMCPCommandFailure("_commit", prepared.ID, err)
	if result.Meta["error_code"] != "denied" || result.Meta["reason"] != appMCPBlockActorChanged {
		t.Fatalf("commit failure meta: %#v (%v)", result.Meta, err)
	}
	if _, err := app.DB.Exec(`UPDATE _benmore_users SET role=? WHERE id=?`, role, uid); err != nil {
		t.Fatal(err)
	}
	if view, err = appMCPStatusOperation(context.Background(), statusRequest, prepared.ID); err != nil || view.State != "approved" || view.Reason != "" {
		t.Fatalf("status with the role back: %+v %v", view, err)
	}
	if out, err := appMCPCommitOperation(context.Background(), request, prepared.ID); err != nil || out.Outcome != "applied" {
		t.Fatalf("commit with the role back: %+v %v", out, err)
	}
}

// An attempt whose outcome is unknown stays undetermined in the status: the
// block stops another commit, it does not settle the earlier one.
func TestAppMCPStatusKeepsBusinessUndeterminedWhenBlocked(t *testing.T) {
	h := newExposureHarness(t)
	id := h.prepare()
	h.approveOK(id)
	attempt := h.insertAttempt(id, appMCPClock().Unix())
	h.forceAttemptState(attempt, appMCPAttemptUnknown, "commit_unknown")
	if _, err := h.app.DB.Exec("DELETE FROM _benmore_sessions WHERE user_id=?", h.actorID); err != nil {
		t.Fatal(err)
	}
	state := h.status(id)
	if state["state"] != "denied" || state["reason"] != appMCPBlockApprovalLapsed || state["business"] != "undetermined" || state["attempt"] == nil || state["retryable"] != false {
		t.Fatalf("status: %#v", state)
	}
}
