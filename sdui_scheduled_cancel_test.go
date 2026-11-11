//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// The Reminder and ScheduleAction components cancel through
// DELETE /api/_scheduled/{id}, which now answers 404 or 409 with the stored
// status when it cancelled nothing. The components show that answer and
// re-read the list, so a reminder that fired while it was on screen stops
// offering Cancel; a second cancel of a cancelled task is not an error.
// Real server, real SDK, real components (embedded/sdui_scheduled_cancel_test.mjs).
func TestSDUIScheduledCancelShowsStoredStatus(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; skipping component integration")
	}
	app := newGateApp(t)
	owner, sid := gateUser(t, app, "planner@example.com")
	mux := http.NewServeMux()
	mux.Handle("/", buildAppMux(app, false, "http://localhost"))
	// Fixture routes: the script moves a task on the server while a component
	// still lists it as pending.
	mux.HandleFunc("POST /__fixture/sweep", func(w http.ResponseWriter, r *http.Request) {
		sweepScheduledTasks(app)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /__fixture/tasks/{id}/{state}", func(w http.ResponseWriter, r *http.Request) {
		var err error
		if state := r.PathValue("state"); state == "gone" {
			_, err = app.DB.Exec("DELETE FROM _benmore_scheduled_tasks WHERE id = ?", r.PathValue("id"))
		} else {
			_, err = app.DB.Exec("UPDATE _benmore_scheduled_tasks SET status = ? WHERE id = ?", state, r.PathValue("id"))
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	for _, task := range []struct{ kind, title, flow, runAt string }{
		{"reminder", "Call Dana", "", "2000-01-01T00:00:00Z"}, // due: one sweep fires it
		{"reminder", "Send invoice", "", "2999-01-01T00:00:00Z"},
		{"reminder", "Renew licence", "", "2999-01-01T00:00:00Z"},
		{"flow", "Nightly sync", "nightly_sync", "2999-01-01T00:00:00Z"},
		{"flow", "Close books", "nightly_sync", "2999-01-01T00:00:00Z"},
		{"flow", "Export ledger", "nightly_sync", "2999-01-01T00:00:00Z"},
	} {
		if _, err := app.DB.Exec("INSERT INTO _benmore_scheduled_tasks (user_id, kind, title, flow, run_at) VALUES (?, ?, ?, ?, ?)", owner, task.kind, task.title, task.flow, task.runAt); err != nil {
			t.Fatal(err)
		}
	}
	server := httptest.NewServer(mux)
	defer server.Close()

	cmd := exec.Command(node, "embedded/sdui_scheduled_cancel_test.mjs")
	cmd.Env = append(os.Environ(), "BM_TEST_URL="+server.URL, "BM_TEST_TOKEN="+sid)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("scheduled cancel component check failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "scheduled cancel components passed") {
		t.Fatalf("missing success: %s", output)
	}

	// What the components showed is what is stored.
	var stored string
	if err := app.DB.QueryRow("SELECT group_concat(title || '=' || status, ', ') FROM (SELECT title, status FROM _benmore_scheduled_tasks ORDER BY id)").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if want := "Call Dana=done, Send invoice=cancelled, Nightly sync=running, Close books=cancelled, Export ledger=cancelled"; stored != want {
		t.Fatalf("stored tasks:\n got %s\nwant %s", stored, want)
	}
}
