//go:build !cli && !windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mattn/go-sqlite3"
)

var attemptTestActor = Session{UserID: 1, Email: "task-actor@example.com"}

func (h *exposureHarness) attempts(id string) []appMCPAttempt {
	h.t.Helper()
	tx, err := h.app.DB.Begin()
	if err != nil {
		h.t.Fatal(err)
	}
	defer tx.Rollback()
	appID, key, err := appMCPReadyOperationStorage(context.Background(), tx, h.app)
	if err != nil {
		h.t.Fatal(err)
	}
	attempts, err := appMCPReadAttemptsWithKey(context.Background(), tx, appID, key, id)
	if err != nil {
		h.t.Fatal(err)
	}
	return attempts
}

// insertAttempt writes a running attempt the way the claim phase does, started at the given time.
func (h *exposureHarness) insertAttempt(id string, startedAt int64) appMCPAttempt {
	h.t.Helper()
	tx, err := h.app.DB.Begin()
	if err != nil {
		h.t.Fatal(err)
	}
	appID, key, err := appMCPReadyOperationStorage(context.Background(), tx, h.app)
	if err != nil {
		_ = tx.Rollback()
		h.t.Fatal(err)
	}
	attemptID, err := appMCPRandomHex(32)
	if err != nil {
		h.t.Fatal(err)
	}
	record := appMCPAttemptRecord{Version: 1, Domain: appMCPAttemptDomain, AttemptID: attemptID, OperationID: id, AppID: appID, StartedAt: startedAt, State: appMCPAttemptRunning}
	if err := insertAppMCPAttemptWithKey(context.Background(), tx, appID, key, record); err != nil {
		_ = tx.Rollback()
		h.t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		h.t.Fatal(err)
	}
	for _, attempt := range h.attempts(id) {
		if attempt.AttemptID == attemptID {
			return attempt
		}
	}
	h.t.Fatal("inserted attempt not found")
	return appMCPAttempt{}
}

// forceAttemptState rewrites an attempt's sealed state directly (test only).
func (h *exposureHarness) forceAttemptState(attempt appMCPAttempt, state, class string) {
	h.t.Helper()
	tx, err := h.app.DB.Begin()
	if err != nil {
		h.t.Fatal(err)
	}
	appID, key, err := appMCPReadyOperationStorage(context.Background(), tx, h.app)
	if err != nil {
		_ = tx.Rollback()
		h.t.Fatal(err)
	}
	next := attempt.appMCPAttemptRecord
	next.State, next.ErrorClass, next.FinishedAt = state, class, next.StartedAt
	_, sealed, err := appMCPSealAttempt(key, next, appID)
	if err != nil {
		_ = tx.Rollback()
		h.t.Fatal(err)
	}
	if err := appMCPSwapAttemptCiphertext(context.Background(), tx, attempt, sealed); err != nil {
		_ = tx.Rollback()
		h.t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		h.t.Fatal(err)
	}
}

func (h *exposureHarness) commit(id string) (map[string]any, string) {
	h.t.Helper()
	return h.call(h.client, appMCPCommitTool, map[string]any{"operation_id": id})
}

func attemptStatus(t *testing.T, status map[string]any) map[string]any {
	t.Helper()
	attempt, _ := status["attempt"].(map[string]any)
	if attempt == nil {
		t.Fatalf("status has no attempt: %#v", status)
	}
	return attempt
}

func TestAppMCPAttemptHappyPathLeavesOneSucceededAttempt(t *testing.T) {
	h := newExposureHarness(t)
	id := h.prepare()
	h.approveOK(id)
	if out, code := h.commit(id); code != "" || out["outcome"] != "applied" {
		t.Fatalf("commit: %q %#v", code, out)
	}
	attempts := h.attempts("")
	if len(attempts) != 1 || attempts[0].State != appMCPAttemptSucceeded || attempts[0].ErrorClass != "" || attempts[0].OperationID != id || attempts[0].FinishedAt < attempts[0].StartedAt {
		t.Fatalf("attempts after a clean commit: %#v", attempts)
	}
	status := h.status(id)
	receipt := status["receipt"].(map[string]any)
	if status["retryable"] != false {
		t.Fatalf("a succeeded operation is not retryable: %#v", status)
	}
	if status["state"] != "succeeded" || receipt["attempt_id"] != attempts[0].AttemptID || attemptStatus(t, status)["state"] != "succeeded" {
		t.Fatalf("status: %#v", status)
	}
	// Replay claims nothing new.
	if out, code := h.commit(id); code != "" || out["outcome"] != "already_applied" || len(h.attempts("")) != 1 {
		t.Fatalf("replay: %q %#v attempts=%d", code, out, len(h.attempts("")))
	}
	if h.count("SELECT count(*) FROM _benmore_audit_log WHERE action LIKE 'mcp_command_attempt_%'") != 0 {
		t.Fatal("a successful attempt wrote a failure audit row")
	}
	// Sealed at rest: no plaintext state, actor or operation content in the row.
	var raw string
	if err := h.app.DB.QueryRow("SELECT state_ciphertext FROM _benmore_mcp_command_attempts").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(raw, encPrefixV2) || strings.Contains(raw, "task-actor") || strings.Contains(raw, "succeeded") || !appMCPAttemptAAD(raw) {
		t.Fatalf("attempt row is not sealed: %q", raw)
	}
}

func TestAppMCPAttemptApplyFailureIsRecordedOutsideTheRollback(t *testing.T) {
	h := newExposureHarnessWithHooks(t, `before_update:
  tasks:
    - sql: SELECT 'blocked by policy' AS error WHERE '{{status}}' = 'done'
`+hookFiredOnUpdate)
	id := h.prepare()
	h.approveOK(id)
	if _, code := h.commit(id); code != "hook_refused" {
		t.Fatalf("commit: %q", code)
	}
	attempts := h.attempts(id)
	if len(attempts) != 1 || attempts[0].State != appMCPAttemptFailed || attempts[0].ErrorClass != "hook_refused" {
		t.Fatalf("attempts after a refused commit: %#v", attempts)
	}
	if h.taskDone() || h.count("SELECT count(*) FROM activities") != 0 || h.count("SELECT count(*) FROM _benmore_mcp_operations WHERE receipt_digest IS NOT NULL") != 0 {
		t.Fatal("a failed attempt left business rows or a receipt")
	}
	var details string
	if err := h.app.DB.QueryRow("SELECT new_values FROM _benmore_audit_log WHERE action='mcp_command_attempt_failed' AND row_id=?", id).Scan(&details); err != nil {
		t.Fatalf("failure audit row: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(details), &decoded); err != nil || len(decoded) != 2 || decoded["attempt_id"] != attempts[0].AttemptID || decoded["error_class"] != "hook_refused" {
		t.Fatalf("audit details carry more than the attempt id and class: %q", details)
	}
	status := h.status(id)
	if status["state"] != "failed" || status["retryable"] != true || status["business"] != "not_committed" || attemptStatus(t, status)["error_class"] != "hook_refused" {
		t.Fatalf("status: %#v", status)
	}
	// Failed attempts may be retried, but only a bounded number of times.
	for i := 1; i < appMCPOperationAttemptLimit; i++ {
		if _, code := h.commit(id); code != "hook_refused" {
			t.Fatalf("retry %d: %q", i, code)
		}
	}
	if _, code := h.commit(id); code != "operation_limit" || len(h.attempts(id)) != appMCPOperationAttemptLimit {
		t.Fatalf("attempt cap: %q attempts=%d", code, len(h.attempts(id)))
	}
}

func TestAppMCPAttemptRetryAfterFailedSucceeds(t *testing.T) {
	h := newExposureHarness(t)
	id := h.prepare()
	h.approveOK(id)
	// The third clock read of a commit (after the apply, before the receipt) lands past
	// expiry: the apply rolls back as failed, with the attempt already recorded.
	real := time.Now().UTC()
	var reads atomic.Int32
	previous := appMCPClock
	appMCPClock = func() time.Time {
		if reads.Add(1) == 3 {
			return real.Add(16 * time.Minute)
		}
		return real
	}
	t.Cleanup(func() { appMCPClock = previous })
	if _, code := h.commit(id); code != "expired_intent" {
		t.Fatalf("first commit: %q", code)
	}
	if attempts := h.attempts(id); len(attempts) != 1 || attempts[0].State != appMCPAttemptFailed || attempts[0].ErrorClass != "expired_intent" || h.taskDone() {
		t.Fatalf("after the failed attempt: %#v done=%v", attempts, h.taskDone())
	}
	if state := h.status(id); state["state"] != "failed" {
		t.Fatalf("failed status: %#v", state)
	}
	if out, code := h.commit(id); code != "" || out["outcome"] != "applied" {
		t.Fatalf("retry: %q %#v", code, out)
	}
	attempts := h.attempts(id)
	if len(attempts) != 2 || attempts[0].State != appMCPAttemptFailed || attempts[1].State != appMCPAttemptSucceeded || !h.taskDone() || h.status(id)["state"] != "succeeded" {
		t.Fatalf("after the retry: %#v", attempts)
	}
	if h.count("SELECT count(*) FROM activities WHERE task_id=1") != 1 {
		t.Fatal("business rows were not written exactly once")
	}
}

func TestAppMCPAttemptDependencyChangeLeavesConflict(t *testing.T) {
	h := newExposureHarness(t)
	id := h.prepare()
	h.approveOK(id)
	if _, err := h.app.DB.Exec("UPDATE tasks SET title='changed after approval' WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if _, code := h.commit(id); code != "conflict" {
		t.Fatalf("commit after a dependency change: %q", code)
	}
	attempts := h.attempts(id)
	if len(attempts) != 1 || attempts[0].State != appMCPAttemptConflict || attempts[0].ErrorClass != "conflict" {
		t.Fatalf("attempts: %#v", attempts)
	}
	if h.taskDone() || h.count("SELECT count(*) FROM _benmore_audit_log WHERE action='mcp_command_attempt_conflict' AND row_id=?", id) != 1 {
		t.Fatal("conflict wrote business rows or no audit row")
	}
	if state := h.status(id); state["state"] != "conflict" || state["retryable"] != true || state["business"] != "not_committed" {
		t.Fatalf("status: %#v", state)
	}
	// Retrying is allowed while unexpired; the changed dependency still conflicts.
	if _, code := h.commit(id); code != "conflict" || len(h.attempts(id)) != 2 {
		t.Fatalf("retry: %q", code)
	}
}

func TestAppMCPAttemptCommitUnknownIsNeverReplayed(t *testing.T) {
	h := newExposureHarness(t)
	h.app.DB.SetMaxIdleConns(1)
	id := h.prepare()
	h.approveOK(id)
	// Reject the COMMIT containing the task business write. This stays tied to
	// the operation under test if bookkeeping adds transactions around it.
	var businessWrite atomic.Bool
	conn, err := h.app.DB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Raw(func(raw any) error {
		sqlConn := raw.(*sqlite3.SQLiteConn)
		sqlConn.RegisterUpdateHook(func(_ int, db, table string, _ int64) {
			if db == "main" && table == "tasks" {
				businessWrite.Store(true)
			}
		})
		sqlConn.RegisterCommitHook(func() int {
			if businessWrite.CompareAndSwap(true, false) {
				return 1
			}
			return 0
		})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if _, code := h.commit(id); code != "unknown_execution" {
		t.Fatalf("commit: %q (business write observed %v)", code, businessWrite.Load())
	}
	attempts := h.attempts(id)
	if len(attempts) != 1 || attempts[0].State != appMCPAttemptUnknown || attempts[0].ErrorClass != "unknown_execution" {
		t.Fatalf("attempts: %#v (business write observed %v)", attempts, businessWrite.Load())
	}
	if h.taskDone() || h.count("SELECT count(*) FROM _benmore_audit_log WHERE action='mcp_command_attempt_unknown' AND row_id=?", id) != 1 {
		t.Fatal("unknown attempt changed business rows or has no audit row")
	}
	// No receipt: stays unknown, and _commit refuses to run it again.
	if state := h.status(id); state["state"] != "unknown" || state["retryable"] != false || state["business"] != "undetermined" || state["receipt"] != nil {
		t.Fatalf("status: %#v", state)
	}
	if _, code := h.commit(id); code != "unknown_execution" || len(h.attempts(id)) != 1 || h.taskDone() {
		t.Fatalf("commit on an unknown operation: %q attempts=%d", code, len(h.attempts(id)))
	}
}

func TestAppMCPAttemptUnknownReconcilesFromTheReceipt(t *testing.T) {
	h := newExposureHarness(t)
	id := h.prepare()
	h.approveOK(id)
	if _, code := h.commit(id); code != "" {
		t.Fatalf("commit: %q", code)
	}
	// An attempt that claims unknown while the receipt exists is succeeded: the
	// record step reconciles it, and a stored unknown never overrides the receipt.
	running := h.insertAttempt(id, time.Now().Unix())
	appMCPRecordAttemptOutcome(context.Background(), h.app, attemptTestActor, id, running.AttemptID, appMCPAttemptUnknown, "unknown_execution")
	var reconciled *appMCPAttempt
	for _, attempt := range h.attempts(id) {
		if attempt.AttemptID == running.AttemptID {
			reconciled = &attempt
		}
	}
	if reconciled == nil || reconciled.State != appMCPAttemptSucceeded || reconciled.ErrorClass != "" {
		t.Fatalf("receipt did not reconcile the unknown attempt: %#v", reconciled)
	}
	stale := h.insertAttempt(id, time.Now().Unix())
	h.forceAttemptState(stale, appMCPAttemptUnknown, "unknown_execution")
	if state := h.status(id); state["state"] != "succeeded" || state["business"] != "committed" || state["receipt"] == nil {
		t.Fatalf("the receipt must win over an unknown attempt: %#v", state)
	}
}

func TestAppMCPAttemptStaleRunningIsSupersededAndAppliesOnce(t *testing.T) {
	h := newExposureHarness(t)
	h.addTask(2)
	crashed, live := h.prepare(), h.prepareTask(2)
	h.approveOK(crashed)
	h.approveOK(live)
	// A crash between the claim and the business transaction leaves this row behind.
	stale := h.insertAttempt(crashed, time.Now().Unix()-int64(appMCPAttemptStaleAfter/time.Second)-5)
	if state := h.status(crashed); state["state"] != "unknown" || state["retryable"] != true || state["business"] != "undetermined" || attemptStatus(t, state)["state"] != "unknown" {
		t.Fatalf("stale running status: %#v", state)
	}
	// With no receipt the stale claim never committed and cannot any more: a new
	// _commit marks it unknown (audited) and applies under a fresh claim, once.
	if out, code := h.commit(crashed); code != "" || out["outcome"] != "applied" {
		t.Fatalf("commit over a stale claim: %q %#v", code, out)
	}
	attempts := h.attempts(crashed)
	if len(attempts) != 2 || attempts[0].AttemptID != stale.AttemptID || attempts[0].State != appMCPAttemptUnknown || attempts[0].ErrorClass != "stale_claim" || attempts[1].State != appMCPAttemptSucceeded {
		t.Fatalf("attempts after superseding: %#v", attempts)
	}
	if !h.taskDone() || h.count("SELECT count(*) FROM activities WHERE task_id=1") != 1 ||
		h.count("SELECT count(*) FROM _benmore_audit_log WHERE action='mcp_command_attempt_unknown' AND row_id=?", crashed) != 1 {
		t.Fatal("superseding did not apply exactly once with an audit row")
	}
	if again, code := h.commit(crashed); code != "" || again["outcome"] != "already_applied" || len(h.attempts(crashed)) != 2 {
		t.Fatalf("replay after superseding: %q %#v", code, again)
	}
	// A recent running attempt is in progress: reported running, and not claimed again.
	h.insertAttempt(live, time.Now().Unix())
	if state := h.status(live); state["state"] != "running" || state["retryable"] != false || state["business"] != "undetermined" {
		t.Fatalf("running status: %#v", state)
	}
	if _, code := h.commit(live); code != "in_progress" || len(h.attempts(live)) != 1 {
		t.Fatalf("concurrent claim: %q", code)
	}
}

// attemptClock reads a controllable clock; the nth read (n>0) may be overridden.
func attemptClock(t *testing.T, base time.Time) (offset *atomic.Int64, override func(n int32, at time.Time), reads *atomic.Int32) {
	t.Helper()
	offset = new(atomic.Int64)
	reads = new(atomic.Int32)
	var mu sync.Mutex
	overrides := map[int32]time.Time{}
	previous := appMCPClock
	appMCPClock = func() time.Time {
		n := reads.Add(1)
		mu.Lock()
		at, ok := overrides[n]
		mu.Unlock()
		if ok {
			return at
		}
		return base.Add(time.Duration(offset.Load()) * time.Second)
	}
	t.Cleanup(func() { appMCPClock = previous })
	return offset, func(n int32, at time.Time) {
		mu.Lock()
		overrides[n] = at
		mu.Unlock()
	}, reads
}

func TestAppMCPAttemptApplyRefusesOnceItsOwnClaimIsStale(t *testing.T) {
	h := newExposureHarness(t)
	id := h.prepare()
	h.approveOK(id)
	base := time.Now().UTC()
	// Clock reads of a commit: 1 claim, 2 apply. The apply starts after the stale bound.
	_, override, _ := attemptClock(t, base)
	override(2, base.Add(appMCPAttemptStaleAfter+time.Second))
	if _, code := h.commit(id); code != "denied" {
		t.Fatalf("apply with a stale claim: %q", code)
	}
	if attempts := h.attempts(id); len(attempts) != 1 || attempts[0].State != appMCPAttemptFailed || attempts[0].ErrorClass != "denied" {
		t.Fatalf("attempts: %#v", attempts)
	}
	if h.taskDone() || h.count("SELECT count(*) FROM activities") != 0 {
		t.Fatal("a stale claim applied business rows")
	}
	if out, code := h.commit(id); code != "" || out["outcome"] != "applied" || len(h.attempts(id)) != 2 {
		t.Fatalf("retry: %q %#v", code, out)
	}
}

func TestAppMCPAttemptApplyDoesNoWorkPastTheCommitDeadline(t *testing.T) {
	h := newExposureHarness(t)
	id := h.prepare()
	h.approveOK(id)
	base := time.Now().UTC()
	// The claim is stamped 31 s ago: not yet stale (35 s), but past the 30 s the
	// business transaction may commit within, so the apply step refuses up front.
	_, override, _ := attemptClock(t, base)
	override(1, base.Add(-(appMCPCommandTimeout + time.Second)))
	if _, code := h.commit(id); code != "denied" {
		t.Fatalf("commit past the commit deadline: %q", code)
	}
	if h.taskDone() || h.count("SELECT count(*) FROM activities") != 0 || h.count("SELECT count(*) FROM _benmore_mcp_operations WHERE receipt_digest IS NOT NULL") != 0 {
		t.Fatal("apply work ran past the commit deadline")
	}
	if attempts := h.attempts(id); len(attempts) != 1 || attempts[0].State != appMCPAttemptFailed || attempts[0].ErrorClass != "denied" {
		t.Fatalf("attempts: %#v", attempts)
	}
}

func TestAppMCPAttemptClockSteppedBackDoesNotWedgeTheOperation(t *testing.T) {
	h := newExposureHarness(t)
	base := time.Now().UTC()
	offset, override, reads := attemptClock(t, base)
	// Prepare and approve earlier than the failure, so a later step back still
	// precedes neither the approval nor the receipt time.
	offset.Store(-200)
	id := h.prepare()
	h.approveOK(id)
	offset.Store(0)
	override(reads.Load()+3, base.Add(16*time.Minute)) // third read of the commit: the apply rolls back
	if _, code := h.commit(id); code != "expired_intent" {
		t.Fatalf("first commit: %q", code)
	}
	failed := h.attempts(id)
	if len(failed) != 1 || failed[0].State != appMCPAttemptFailed {
		t.Fatalf("first attempt: %#v", failed)
	}
	// The clock steps back 100 s: the new claim must still sort after the failed one.
	offset.Store(-100)
	if out, code := h.commit(id); code != "" || out["outcome"] != "applied" {
		t.Fatalf("commit after the clock stepped back: %q %#v", code, out)
	}
	attempts := h.attempts(id)
	if len(attempts) != 2 || attempts[1].StartedAt <= attempts[0].StartedAt || attempts[1].State != appMCPAttemptSucceeded || !h.taskDone() {
		t.Fatalf("attempts: %#v", attempts)
	}
}

func TestAppMCPAttemptRecordStepRetriesAndStaleClaimIsSuperseded(t *testing.T) {
	failing := func(t *testing.T, limit int32) *atomic.Int32 {
		t.Helper()
		tries := new(atomic.Int32)
		previous := appMCPAttemptFinisher
		appMCPAttemptFinisher = func(ctx context.Context, app *App, actor Session, op, attempt, state, class string) (string, error) {
			if limit < 0 || tries.Add(1) <= limit {
				return "", errors.New("injected record failure")
			}
			return previous(ctx, app, actor, op, attempt, state, class)
		}
		t.Cleanup(func() { appMCPAttemptFinisher = previous })
		return tries
	}
	t.Run("a transient record failure is retried", func(t *testing.T) {
		h := newExposureHarness(t)
		id := h.prepare()
		h.approveOK(id)
		tries := failing(t, 2)
		if out, code := h.commit(id); code != "" || out["outcome"] != "applied" {
			t.Fatalf("commit: %q %#v", code, out)
		}
		if attempts := h.attempts(id); tries.Load() != 3 || len(attempts) != 1 || attempts[0].State != appMCPAttemptSucceeded {
			t.Fatalf("tries=%d attempts=%#v", tries.Load(), attempts)
		}
	})
	t.Run("every record try fails, then the stale claim is superseded and applies once", func(t *testing.T) {
		h := newExposureHarness(t)
		id := h.prepare()
		h.approveOK(id)
		base := time.Now().UTC()
		offset, override, _ := attemptClock(t, base)
		// Clock reads of a commit: 1 claim, 2 apply, 3 receipt time (past expiry: the apply rolls back).
		override(3, base.Add(16*time.Minute))
		failing(t, -1)
		if _, code := h.commit(id); code != "expired_intent" {
			t.Fatalf("first commit: %q", code)
		}
		if attempts := h.attempts(id); len(attempts) != 1 || attempts[0].State != appMCPAttemptRunning {
			t.Fatalf("the unrecorded attempt must stay running: %#v", attempts)
		}
		if state := h.status(id); state["state"] != "running" || state["business"] != "undetermined" {
			t.Fatalf("status before the stale bound: %#v", state)
		}
		if _, code := h.commit(id); code != "in_progress" {
			t.Fatalf("commit inside the stale window: %q", code)
		}
		// Past the stale bound, with no receipt: superseded, then applied exactly once.
		offset.Store(int64(appMCPAttemptStaleAfter/time.Second) + 5)
		if state := h.status(id); state["state"] != "unknown" {
			t.Fatalf("status after the stale bound: %#v", state)
		}
		appMCPAttemptFinisher = appMCPAttemptFinisherOriginal
		if out, code := h.commit(id); code != "" || out["outcome"] != "applied" {
			t.Fatalf("commit after the stale bound: %q %#v", code, out)
		}
		attempts := h.attempts(id)
		if len(attempts) != 2 || attempts[0].State != appMCPAttemptUnknown || attempts[0].ErrorClass != "stale_claim" || attempts[1].State != appMCPAttemptSucceeded {
			t.Fatalf("attempts: %#v", attempts)
		}
		if h.count("SELECT count(*) FROM activities WHERE task_id=1") != 1 || !h.taskDone() {
			t.Fatal("not applied exactly once")
		}
	})
}

var appMCPAttemptFinisherOriginal = appMCPAttemptFinisher

func TestAppMCPAttemptSettleReconcilesAnUnknownCommitFromTheReceipt(t *testing.T) {
	h := newExposureHarness(t)
	h.addTask(2)
	committed, uncommitted := h.prepare(), h.prepareTask(2)
	h.approveOK(committed)
	h.approveOK(uncommitted)
	if _, code := h.commit(committed); code != "" {
		t.Fatalf("commit: %q", code)
	}
	request := appMCPCommandRequest{app: h.app}
	unknown := &appMCPCommandOutcomeUnknownError{}
	// The receipt exists: the unknown outcome is a success and returns the applied view.
	running := h.insertAttempt(committed, time.Now().Unix())
	view := &appMCPCommitView{OperationID: committed, Outcome: "applied"}
	if got, err := appMCPSettleCommit(context.Background(), request, attemptTestActor, committed, running.AttemptID, unknown, view, nil); err != nil || got != view {
		t.Fatalf("unknown commit with a receipt: %v %v", got, err)
	}
	// No receipt: it stays an unknown error and the attempt is recorded unknown.
	pending := h.insertAttempt(uncommitted, time.Now().Unix())
	if got, err := appMCPSettleCommit(context.Background(), request, attemptTestActor, uncommitted, pending.AttemptID, unknown, &appMCPCommitView{}, nil); err == nil || got != nil || appMCPCommandErrorClass(err) != "unknown_execution" {
		t.Fatalf("unknown commit without a receipt: %v %v", got, err)
	}
	if got := h.attempts(uncommitted); len(got) != 1 || got[0].State != appMCPAttemptUnknown {
		t.Fatalf("attempts: %#v", got)
	}
}

func TestAppMCPAttemptRecordStepRunsUnderTheWritePolicyLock(t *testing.T) {
	h := newExposureHarness(t)
	id := h.prepare()
	h.approveOK(id)
	running := h.insertAttempt(id, time.Now().Unix())
	previousWait, previousBudget := appMCPAttemptLockWait, appMCPAttemptRecordBudget
	t.Cleanup(func() { appMCPAttemptLockWait, appMCPAttemptRecordBudget = previousWait, previousBudget })
	appMCPAttemptLockWait = 300 * time.Millisecond
	_, release, _, err := acquireAppMCPWritePolicy(context.Background(), h.app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := appMCPFinishAttempt(context.Background(), h.app, attemptTestActor, id, running.AttemptID, appMCPAttemptFailed, "denied"); err == nil {
		t.Fatal("the record step ran while the write-policy lock was held (rotation would interleave)")
	}
	// The lock wait has its own budget: a lock held longer than the record budget
	// does not starve the outcome record.
	appMCPAttemptLockWait, appMCPAttemptRecordBudget = 5*time.Second, 400*time.Millisecond
	go func() {
		time.Sleep(900 * time.Millisecond)
		release()
	}()
	if recorded := appMCPRecordAttemptOutcome(context.Background(), h.app, attemptTestActor, id, running.AttemptID, appMCPAttemptFailed, "denied"); recorded != appMCPAttemptFailed {
		t.Fatalf("record after a long lock wait: %q", recorded)
	}
	// Idempotent: a repeated try reports the recorded state.
	if state, err := appMCPFinishAttempt(context.Background(), h.app, attemptTestActor, id, running.AttemptID, appMCPAttemptFailed, "denied"); err != nil || state != appMCPAttemptFailed {
		t.Fatalf("repeated record step: %q %v", state, err)
	}
}

func TestAppMCPAttemptLatestIsOrderedByStartedAtThenInsertion(t *testing.T) {
	at := func(started int64, id string) appMCPAttempt {
		return appMCPAttempt{appMCPAttemptRecord: appMCPAttemptRecord{AttemptID: id, StartedAt: started, State: appMCPAttemptFailed}}
	}
	if got := appMCPLatestAttempt([]appMCPAttempt{at(200, "late"), at(100, "early")}); got.AttemptID != "late" {
		t.Fatalf("latest by StartedAt: %s", got.AttemptID)
	}
	if got := appMCPLatestAttempt([]appMCPAttempt{at(100, "first"), at(100, "second")}); got.AttemptID != "second" {
		t.Fatalf("tie goes to the later row: %s", got.AttemptID)
	}
	if appMCPLatestAttempt(nil) != nil {
		t.Fatal("no attempts, no latest")
	}
	running := at(100, "x")
	running.State = appMCPAttemptRunning
	view := appMCPAttemptView(&running, time.Unix(100, 0), true)
	if view["state"] != appMCPAttemptSucceeded || view["error_class"] != "" {
		t.Fatalf("a receipt makes the latest attempt succeeded: %#v", view)
	}
	if view := appMCPAttemptView(&running, time.Unix(100, 0), false); view["state"] != appMCPAttemptRunning {
		t.Fatalf("without a receipt: %#v", view)
	}
}

func TestAppMCPAttemptPurgeToleratesAMissingAttemptsTable(t *testing.T) {
	h := newExposureHarness(t)
	id := h.prepare()
	h.approveOK(id)
	if _, err := h.app.DB.Exec("DROP TABLE _benmore_mcp_command_attempts"); err != nil {
		t.Fatal(err)
	}
	tx, err := h.app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	n, err := purgeAppMCPOperations(context.Background(), h.app, tx, h.actorID)
	if err != nil {
		_ = tx.Rollback()
		t.Fatalf("purge without an attempts table: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if n != 2 || h.count("SELECT count(*) FROM _benmore_mcp_operations") != 0 {
		t.Fatalf("purge deleted %d rows", n)
	}
}

func TestAppMCPAttemptRotationRoundTripsAttemptRows(t *testing.T) {
	h := newExposureHarness(t)
	oldGlobal, oldEphemeral, oldBlind := appEncryptionKey, appEncryptionKeyEphemeral, appBlindIndexKey.Load()
	t.Cleanup(func() {
		appEncryptionKey, appEncryptionKeyEphemeral = oldGlobal, oldEphemeral
		appBlindIndexKey.Store(oldBlind)
	})
	committed := h.prepare()
	h.approveOK(committed)
	if _, code := h.commit(committed); code != "" {
		t.Fatalf("commit: %q", code)
	}
	h.addTask(2)
	pending := h.prepareTask(2)
	h.approveOK(pending)
	h.insertAttempt(pending, time.Now().Unix())
	oldKey := cryptoKeyForQuerier(h.app.DB)
	newSource := strings.Repeat("k", 64)
	if _, err := RotateEncryptionKey(h.app, newSource, false); err != nil {
		t.Fatal(err)
	}
	newKey, _ := cryptoDeriveAppKey(newSource)
	appID, _ := appMCPOperationOwnerID(h.app.Dir)
	read := func(key []byte) (int, error) {
		tx, err := h.app.DB.Begin()
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		attempts, err := appMCPReadAttemptsWithKey(context.Background(), tx, appID, key, "")
		return len(attempts), err
	}
	if _, err := read(oldKey); err == nil {
		t.Fatal("attempt rows still authenticate under the old key")
	}
	if n, err := read(newKey); err != nil || n != 2 {
		t.Fatalf("attempts under the new key: %d %v", n, err)
	}
	if state := h.status(committed); state["state"] != "succeeded" || attemptStatus(t, state)["state"] != "succeeded" {
		t.Fatalf("status after rotation: %#v", state)
	}
	if state := h.status(pending); state["state"] != "running" {
		t.Fatalf("running attempt after rotation: %#v", state)
	}
}

func TestAppMCPAttemptPurgeRemovesTheUsersAttempts(t *testing.T) {
	h := newExposureHarness(t)
	id := h.prepare()
	h.approveOK(id)
	if _, code := h.commit(id); code != "" {
		t.Fatalf("commit: %q", code)
	}
	tx, err := h.app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	n, err := purgeAppMCPOperations(context.Background(), h.app, tx, h.actorID)
	if err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if n != 3 || h.count("SELECT count(*) FROM _benmore_mcp_command_attempts") != 0 || h.count("SELECT count(*) FROM _benmore_mcp_operations") != 0 {
		t.Fatalf("purge deleted %d rows and left attempts", n)
	}
}

func TestAppMCPAttemptSweepRemovesAttemptsWithTheirOperation(t *testing.T) {
	h := newExposureHarness(t)
	h.addTask(2)
	finished := h.prepare()
	h.approveOK(finished)
	if _, code := h.commit(finished); code != "" {
		t.Fatalf("commit: %q", code)
	}
	abandoned := h.prepareTask(2)
	h.approveOK(abandoned)
	h.forceAttemptState(h.insertAttempt(abandoned, time.Now().Unix()), appMCPAttemptFailed, "denied")
	if h.count("SELECT count(*) FROM _benmore_mcp_command_attempts") != 2 {
		t.Fatal("fixture attempts")
	}
	setExposureClock(t, time.Now().UTC().Add(3*time.Hour))
	h.addTask(3)
	h.prepareTask(3)
	if len(h.attempts(abandoned)) != 0 || h.count("SELECT count(*) FROM _benmore_mcp_operations WHERE operation_id=?", abandoned) != 0 {
		t.Fatal("the sweep left an unfinished operation or its attempts")
	}
	if got := h.attempts(finished); len(got) != 1 || got[0].State != appMCPAttemptSucceeded {
		t.Fatalf("the finished operation's attempt must survive: %#v", got)
	}
}

func TestAppMCPAttemptStorageProvisionedWithoutAttemptsBootsAndGainsTheTable(t *testing.T) {
	h := newExposureHarness(t)
	id := h.prepare()
	h.approveOK(id)
	// Command storage as provisioned before attempt history existed.
	if _, err := h.app.DB.Exec("DROP TABLE _benmore_mcp_command_attempts"); err != nil {
		t.Fatal(err)
	}
	reloaded, err := loadApp(h.app.Dir)
	if err != nil {
		t.Fatalf("an app provisioned without the attempts table must still load: %v", err)
	}
	defer reloaded.Shutdown()
	tx, err := h.app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	verifyErr := verifyAppMCPCommandAttemptStorage(context.Background(), tx)
	_ = tx.Rollback() // release the connection before the next query
	if verifyErr != nil {
		t.Fatalf("attempts table after load: %v", verifyErr)
	}
	if n := h.count("SELECT count(*) FROM _benmore_mcp_command_attempts"); n != 0 {
		t.Fatalf("the added table must be empty, has %d rows", n)
	}
	// Existing operations and approvals are untouched.
	if h.count("SELECT count(*) FROM _benmore_mcp_operations") != 1 || h.count("SELECT count(*) FROM _benmore_mcp_command_approvals") != 1 {
		t.Fatal("the upgrade changed existing command storage")
	}
}
