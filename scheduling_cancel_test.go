//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// scheduledCancelTask stores one task for userID in the given status and
// returns its id.
func scheduledCancelTask(t *testing.T, app *App, userID int64, kind, status string) int64 {
	t.Helper()
	res, err := app.DB.Exec(
		"INSERT INTO _benmore_scheduled_tasks (user_id, kind, title, flow, run_at, status) VALUES (?, ?, 'Call back', ?, '2999-01-01T00:00:00Z', ?)",
		userID, kind, map[string]string{"flow": "nightly"}[kind], status)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	return id
}

func scheduledCancelStatus(t *testing.T, app *App, id int64) string {
	t.Helper()
	var status string
	if err := app.DB.QueryRow("SELECT status FROM _benmore_scheduled_tasks WHERE id = ?", id).Scan(&status); err != nil {
		t.Fatalf("task %d: %v", id, err)
	}
	return status
}

func scheduledCancelCall(t *testing.T, mux *http.ServeMux, token, id string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	rec := crudScopeRequest(t, mux, http.MethodDelete, "/api/_scheduled/"+id, token, nil)
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("DELETE /api/_scheduled/%s: %d %q is not JSON", id, rec.Code, rec.Body.String())
	}
	return rec, body
}

// DELETE /api/_scheduled/{id} threw away the result and the error of its
// guarded UPDATE and always answered 200 {"status":"cancelled"}: for a task
// that had already fired, was running, belonged to another user or did not
// exist (round 2026-11-09 state F5, docs F5). It answers what is stored.
func TestScheduledCancelAnswersWhatIsStored(t *testing.T) {
	app, mux := auditApp(t)
	alice := createCrudScopeSession(t, app, "alice@example.com", "user", "", "")
	bob := createCrudScopeSession(t, app, "bob@example.com", "user", "", "")
	aliceID := GetSessionFromDB(app.DB, alice).UserID
	bobID := GetSessionFromDB(app.DB, bob).UserID

	// A pending or blocked task of the caller is cancelled.
	for _, tc := range []struct{ kind, status string }{{"reminder", "pending"}, {"flow", "blocked"}} {
		id := scheduledCancelTask(t, app, aliceID, tc.kind, tc.status)
		rec, body := scheduledCancelCall(t, mux, alice, fmt.Sprint(id))
		if rec.Code != http.StatusOK || body["status"] != "cancelled" {
			t.Errorf("cancel of a %s task: %d %s, want 200 cancelled", tc.status, rec.Code, rec.Body.String())
		}
		if got := scheduledCancelStatus(t, app, id); got != "cancelled" {
			t.Errorf("a %s task is stored %q after its cancel", tc.status, got)
		}
	}

	// A task that is running, has finished or was already cancelled is not
	// changed, and the answer names its stored status.
	for _, stored := range []string{"running", "done", "failed", "cancelled"} {
		id := scheduledCancelTask(t, app, aliceID, "flow", stored)
		rec, body := scheduledCancelCall(t, mux, alice, fmt.Sprint(id))
		if rec.Code != http.StatusConflict || body["status"] != stored {
			t.Errorf("cancel of a %s task: %d %s, want 409 with status %q", stored, rec.Code, rec.Body.String(), stored)
		}
		if message, _ := body["error"].(string); !strings.Contains(message, stored) {
			t.Errorf("cancel of a %s task: error %q does not name the stored status", stored, message)
		}
		if got := scheduledCancelStatus(t, app, id); got != stored {
			t.Errorf("a %s task is stored %q after a refused cancel", stored, got)
		}
	}

	// Another user's task and an id that does not exist get one answer, so
	// an id cannot be probed; the other user's task is untouched.
	theirs := scheduledCancelTask(t, app, bobID, "reminder", "pending")
	otherRec, _ := scheduledCancelCall(t, mux, alice, fmt.Sprint(theirs))
	missingRec, _ := scheduledCancelCall(t, mux, alice, "424242")
	wordRec, _ := scheduledCancelCall(t, mux, alice, "not-a-number")
	for name, rec := range map[string]*httptest.ResponseRecorder{"another user's task": otherRec, "a missing id": missingRec, "a non-numeric id": wordRec} {
		if rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "cancelled") {
			t.Errorf("cancel of %s: %d %s, want 404", name, rec.Code, rec.Body.String())
		}
	}
	if otherRec.Body.String() != missingRec.Body.String() {
		t.Errorf("another user's task and a missing id answer differently:\n%s\n%s", otherRec.Body.String(), missingRec.Body.String())
	}
	if got := scheduledCancelStatus(t, app, theirs); got != "pending" {
		t.Errorf("another user's task is stored %q after the caller's cancel", got)
	}
	// Its owner can still cancel it.
	if rec, body := scheduledCancelCall(t, mux, bob, fmt.Sprint(theirs)); rec.Code != http.StatusOK || body["status"] != "cancelled" {
		t.Errorf("owner's cancel after another user's refused one: %d %s", rec.Code, rec.Body.String())
	}

	// Of several cancels of one task, exactly one did the cancelling: 200
	// means this request cancelled it.
	shared := scheduledCancelTask(t, app, aliceID, "reminder", "pending")
	codes := make([]int, 8)
	var wg sync.WaitGroup
	for i := range codes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes[i] = crudScopeRequest(t, mux, http.MethodDelete, fmt.Sprintf("/api/_scheduled/%d", shared), alice, nil).Code
		}()
	}
	wg.Wait()
	count := map[int]int{}
	for _, code := range codes {
		count[code]++
	}
	if count[http.StatusOK] != 1 || count[http.StatusConflict] != len(codes)-1 {
		t.Errorf("%d concurrent cancels of one task answered %v, want one 200 and the rest 409", len(codes), count)
	}
}

// A cancel whose UPDATE failed answered 200 {"status":"cancelled"} too, and
// the task then fired. A database error is a 500 and says nothing was
// cancelled.
func TestScheduledCancelReportsDatabaseError(t *testing.T) {
	app, mux := auditApp(t)
	alice := createCrudScopeSession(t, app, "alice@example.com", "user", "", "")
	id := scheduledCancelTask(t, app, GetSessionFromDB(app.DB, alice).UserID, "reminder", "pending")
	// Every UPDATE of the table fails, as a full disk or a lock timeout would make it.
	mustExec(t, app.DB, `CREATE TRIGGER scheduled_cancel_write_fails BEFORE UPDATE ON _benmore_scheduled_tasks BEGIN SELECT RAISE(ABORT, 'write failed'); END`)

	rec, body := scheduledCancelCall(t, mux, alice, fmt.Sprint(id))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("cancel whose write failed: %d %s, want 500", rec.Code, rec.Body.String())
	}
	if body["status"] != nil {
		t.Errorf("cancel whose write failed reports status %v", body["status"])
	}
	if got := scheduledCancelStatus(t, app, id); got != "pending" {
		t.Fatalf("fixture: the failed write left the task %q", got)
	}
}
