//go:build !cli && !windows

package main

import (
	"bytes"
	"context"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func TestAppMCPExposureInfrastructureFailureIsLoggedNotDenied(t *testing.T) {
	h := newExposureHarness(t)
	id := h.prepare()
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	// An authorization refusal stays "denied" and is not logged as a failure.
	second, err := createAppMCPNativeGrantFor(context.Background(), h.app, h.actorID, "17", "client-denied", h.resource, "complete_item", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, code := h.call(appMCPClient(t, h.server, second.AccessToken, nil), appMCPStatusTool, map[string]any{"operation_id": id}); code != "denied" {
		t.Fatalf("authorization refusal: %q", code)
	}
	if strings.Contains(logs.String(), "mcp-command: tool=") {
		t.Fatalf("an authorization refusal was logged as a failure: %s", logs.String())
	}

	// A broken approval store is an infrastructure failure: logged, 503, unavailable_provider.
	if _, err := h.app.DB.Exec("ALTER TABLE _benmore_mcp_command_approvals RENAME TO _benmore_mcp_command_approvals_gone"); err != nil {
		t.Fatal(err)
	}
	if _, code := h.call(h.client, appMCPStatusTool, map[string]any{"operation_id": id}); code != "unavailable_provider" {
		t.Fatalf("infrastructure failure code: %q", code)
	}
	for _, want := range []string{"mcp-command: tool=complete_item", "op=" + id[:8], "class=unavailable_provider"} {
		if !strings.Contains(logs.String(), want) {
			t.Fatalf("log is missing %q: %s", want, logs.String())
		}
	}
	if resp, _ := h.do("GET", appMCPOperationRoute+id, h.cookie, nil, nil); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("review page during infrastructure failure: %d", resp.StatusCode)
	}
}

func TestAppMCPExposureOperationCapAndSweep(t *testing.T) {
	h := newExposureHarness(t)
	for i := 0; i < appMCPOperationActorLimit; i++ {
		h.prepare()
	}
	if _, code := h.call(h.client, "complete_item", map[string]any{"arguments": map[string]any{"id": 1, "project_id": 7}}); code != "operation_limit" {
		t.Fatalf("operation past the cap: %q", code)
	}
	ops := func() int { return h.count("SELECT count(*) FROM _benmore_mcp_operations") }
	if ops() != appMCPOperationActorLimit {
		t.Fatalf("operations = %d", ops())
	}
	// Once they are all past expiry plus grace, the next prepare sweeps them and has room again.
	setExposureClock(t, time.Now().UTC().Add(3*time.Hour))
	fresh := h.prepare()
	if ops() != 1 || h.status(fresh)["state"] != "prepared" {
		t.Fatalf("operations after the sweep = %d", ops())
	}
}

func TestAppMCPExposureSweepRemovesExpiredUnfinishedOperations(t *testing.T) {
	h := newExposureHarness(t)
	h.addTask(2)
	finished := h.prepare()
	h.approveOK(finished)
	if _, code := h.call(h.client, appMCPCommitTool, map[string]any{"operation_id": finished}); code != "" {
		t.Fatalf("commit: %q", code)
	}
	var stale []string
	for i := 0; i < 3; i++ {
		stale = append(stale, h.prepareTask(2))
	}
	h.approveOK(stale[0]) // an unfinished approved operation, with an approval row
	if h.count("SELECT count(*) FROM _benmore_mcp_operations") != 4 || h.count("SELECT count(*) FROM _benmore_mcp_command_approvals") != 2 {
		t.Fatal("fixture rows")
	}
	// Not yet past expiry plus grace: a prepare sweeps nothing.
	h.addTask(3)
	h.prepareTask(3)
	if h.count("SELECT count(*) FROM _benmore_mcp_operations") != 5 {
		t.Fatal("a live operation was swept")
	}
	setExposureClock(t, time.Now().UTC().Add(3*time.Hour))
	h.addTask(4)
	fresh := h.prepareTask(4)
	// Receipt-bearing operation and the new one remain; the four unfinished ones and the approval are gone.
	if got := h.count("SELECT count(*) FROM _benmore_mcp_operations"); got != 2 {
		t.Fatalf("operations after sweep = %d, want the receipt and the new operation", got)
	}
	if got := h.count("SELECT count(*) FROM _benmore_mcp_command_approvals"); got != 1 {
		t.Fatalf("approvals after sweep = %d, want only the finished operation's", got)
	}
	if state := h.status(finished); state["state"] != "succeeded" || state["receipt"] == nil {
		t.Fatalf("receipt did not survive the sweep: %#v", state)
	}
	if state := h.status(fresh); state["state"] != "prepared" {
		t.Fatalf("fresh operation: %#v", state)
	}
}

// Receipts are kept forever, so the open-operation scan every prepare runs
// under the write lock must not read finished operations at all.
func TestAppMCPExposurePrepareScanSkipsFinishedOperations(t *testing.T) {
	h := newExposureHarness(t)
	h.addTask(2)
	finished := h.prepare()
	h.approveOK(finished)
	if _, code := h.call(h.client, appMCPCommitTool, map[string]any{"operation_id": finished}); code != "" {
		t.Fatalf("commit: %q", code)
	}
	// Make the finished row unreadable: a scan that still opened it would log it.
	if _, err := h.app.DB.Exec("UPDATE _benmore_mcp_operations SET prepared_ciphertext=substr(prepared_ciphertext,1,length(prepared_ciphertext)-4)||'AAAA' WHERE operation_id=?", finished); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	open := h.prepareTask(2)
	if strings.Contains(logs.String(), "unreadable_operation") {
		t.Fatalf("prepare read a finished operation: %s", logs.String())
	}
	if h.status(open)["state"] != "prepared" {
		t.Fatal("open operation")
	}
	// Unfinished operations are still counted against the cap.
	for i := 1; i < appMCPOperationActorLimit; i++ {
		h.prepareTask(2)
	}
	if _, code := h.call(h.client, "complete_item", map[string]any{"arguments": map[string]any{"id": 2, "project_id": 7}}); code != "operation_limit" {
		t.Fatalf("operation past the cap: %q", code)
	}
}

func TestAppMCPExposureApprovalTokenIsBoundToTheOperation(t *testing.T) {
	h := newExposureHarness(t)
	h.addTask(2)
	a, b := h.prepare(), h.prepareTask(2)
	_, _, tokenA := h.review(h.cookie, a)
	if got := h.approve(h.cookie, b, tokenA, nil); got == http.StatusSeeOther || h.count("SELECT count(*) FROM _benmore_mcp_command_approvals") != 0 {
		t.Fatalf("a token for one operation approved another: %d", got)
	}
	// The older session-only binding is refused as well.
	if got := h.approve(h.cookie, b, authMintCSRFToken(h.cookie), nil); got == http.StatusSeeOther {
		t.Fatal("a session-only token approved")
	}
	if got := h.approve(h.cookie, a, tokenA, nil); got != http.StatusSeeOther {
		t.Fatalf("own token: %d", got)
	}
	// Repeating it is reported as already approved, not as a session denial.
	if got := h.approve(h.cookie, a, tokenA, nil); got != http.StatusConflict {
		t.Fatalf("double approve status %d, want 409", got)
	}
}

func TestAppMCPExposureCommitNeedsTheApprovingSessionAlive(t *testing.T) {
	h := newExposureHarness(t)
	h.addTask(2)
	id := h.prepare()
	h.approveOK(id)
	key := sessionStorageKey(h.cookie)
	// The approving session loses its direct, unscoped nature: the approval is dead.
	if _, err := h.app.DB.Exec("UPDATE _benmore_sessions SET scopes='tasks:write' WHERE id=?", key); err != nil {
		t.Fatal(err)
	}
	if _, code := h.call(h.client, appMCPCommitTool, map[string]any{"operation_id": id}); code != "denied" || h.taskDone() {
		t.Fatalf("commit with a scoped approver session: %q", code)
	}
	if _, err := h.app.DB.Exec("UPDATE _benmore_sessions SET scopes='' WHERE id=?", key); err != nil {
		t.Fatal(err)
	}
	// Revocation (logout) kills it for good.
	if _, err := h.app.DB.Exec("DELETE FROM _benmore_sessions WHERE id=?", key); err != nil {
		t.Fatal(err)
	}
	if _, code := h.call(h.client, appMCPCommitTool, map[string]any{"operation_id": id}); code != "denied" || h.taskDone() {
		t.Fatalf("commit with a revoked approver session: %q", code)
	}
	if state := h.status(id); state["state"] != "approved" {
		t.Fatalf("status: %#v", state)
	}
	// An expired session is as dead as a deleted one.
	other := h.prepareTask(2)
	fresh := CreateSession(h.app.DB, h.actorID, "task-actor@example.com", "17", time.Hour)
	h.cookie = fresh
	h.approveOK(other)
	if _, err := h.app.DB.Exec("UPDATE _benmore_sessions SET expires_at=datetime('now','-1 minute') WHERE id=?", sessionStorageKey(fresh)); err != nil {
		t.Fatal(err)
	}
	if _, code := h.call(h.client, appMCPCommitTool, map[string]any{"operation_id": other}); code != "denied" {
		t.Fatalf("commit with an expired approver session: %q", code)
	}
}

func TestAppMCPExposureLoggedOutReviewRedirectsToLogin(t *testing.T) {
	h := newExposureHarness(t)
	id := h.prepare()
	resp, _ := h.do("GET", appMCPOperationRoute+id, "", nil, nil)
	want := "/login?next=" + url.QueryEscape(appMCPOperationRoute+id)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != want {
		t.Fatalf("logged-out review: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp, _ := h.do("GET", appMCPOperationRoute+id, "", nil, map[string]string{"Authorization": "Bearer " + h.pair.AccessToken}); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("connector credential on the review page: %d", resp.StatusCode)
	}
}

func TestAppMCPExposureAuditsPrepareApproveAndCommitWithTheDigest(t *testing.T) {
	h := newExposureHarness(t)
	id := h.prepare()
	h.approveOK(id)
	if _, code := h.call(h.client, appMCPCommitTool, map[string]any{"operation_id": id}); code != "" {
		t.Fatalf("commit: %q", code)
	}
	for _, action := range []string{"mcp_command_prepare", "mcp_command_approve", "mcp_command_commit"} {
		var details string
		if err := h.app.DB.QueryRow("SELECT new_values FROM _benmore_audit_log WHERE action=? AND row_id=?", action, id).Scan(&details); err != nil {
			t.Fatalf("%s audit row: %v", action, err)
		}
		if !strings.Contains(details, `"prepared_digest":"`) {
			t.Fatalf("%s audit details lack the prepared digest: %s", action, details)
		}
	}
}

// Replay and status describe a finished operation: they must not depend on the
// reviewed source still matching, so a redeploy cannot hide a receipt.
func TestAppMCPExposureBindingSplitsIdentityFromSource(t *testing.T) {
	h := newExposureHarness(t)
	generation := snapshotAppMCPGeneration(h.app)
	tool, _, err := appMCPFindCommandDeclaration(generation, "complete_item")
	if err != nil {
		t.Fatal(err)
	}
	cap := &appMCPCommandCapability{tool: tool, generation: generation, actor: Session{UserID: 5}, actorCreated: "created", tenant: "17",
		origin: appMCPCommandConnectorOrigin, originPin: &appMCPWriteAuthorityPin{GrantID: "grant", Client: "client"}}
	stored := &appMCPStoredOperation{Prepared: appMCPPreparedOperationRecord{Command: "complete_item", DisclosureVersion: appMCPDisclosureVersion,
		ContractDigest: strings.Repeat("a", 64), ExecutionDigest: strings.Repeat("b", 64),
		Origin: appMCPOperationOriginRecord{Kind: "connector", ActorID: 5, ActorCreated: "created", Tenant: "17", GrantID: "grant", Client: "client"}}}
	if err := appMCPBindOperation(cap, stored); err != nil {
		t.Fatalf("identity binding: %v", err)
	}
	if err := appMCPBindSource(cap, stored); err == nil {
		t.Fatal("an operation from another reviewed source was bound")
	}
	stored.Prepared.ContractDigest, stored.Prepared.ExecutionDigest = generation.manifest.ContractDigest, generation.manifest.ExecutionDigest
	if err := appMCPBindSource(cap, stored); err != nil {
		t.Fatalf("same source: %v", err)
	}
	for name, mutate := range map[string]func(){
		"actor":       func() { stored.Prepared.Origin.ActorID = 6 },
		"incarnation": func() { stored.Prepared.Origin.ActorCreated = "reborn" },
		"tenant":      func() { stored.Prepared.Origin.Tenant = "29" },
		"grant":       func() { stored.Prepared.Origin.GrantID = "other" },
	} {
		before := stored.Prepared
		mutate()
		if err := appMCPBindOperation(cap, stored); err == nil {
			t.Fatalf("%s mismatch was bound", name)
		}
		stored.Prepared = before
	}
}
