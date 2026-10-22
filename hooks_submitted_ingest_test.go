//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// NDJSON ingest fires before_insert hooks per row, so it must hand them the
// same {{_submitted}} list single, batch and transaction creates do. Without
// it the placeholder rendered as its own literal text, instr() found nothing,
// and a guard written the documented way ("refuse when this field is
// submitted") let every ingested row through.
func TestIngestBeforeHooksSeeSubmittedFields(t *testing.T) {
	app, mux := auditApp(t)
	mustExec(t, app.DB, "ALTER TABLE notes ADD COLUMN body TEXT")
	sid := createCrudScopeSession(t, app, "writer@example.com", "user", "", "")
	tok := auditToken(t, app, sid, "*")
	// The shared 5-per-minute ingest limiter would otherwise make this test
	// depend on how many ingests other tests in the process made.
	saved := ingestLimiter
	ingestLimiter = NewRateLimiter(1000, time.Minute)
	t.Cleanup(func() { ingestLimiter = saved })

	ingest := func(body string) string {
		t.Helper()
		req := httptest.NewRequest("POST", "/api/notes/ingest", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-ndjson")
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		// 200 when a row landed, 400 "no rows ingested" when every row was
		// refused; anything else is a gate this test did not mean to hit.
		if rec.Code != http.StatusOK && rec.Code != http.StatusBadRequest {
			t.Fatalf("ingest: %d %s", rec.Code, rec.Body.String())
		}
		return rec.Body.String()
	}

	app.Hooks = &HookConfig{BeforeInsert: map[string][]Hook{"notes": {{
		SQL: "SELECT CASE WHEN instr('{{_submitted}}', ',title,') > 0 THEN RAISE(ABORT, 'title is locked') END",
	}}}}
	if got := ingest("{\"title\":\"x\"}\n"); !strings.Contains(got, `"ingested":0`) || !strings.Contains(got, `"errors":1`) {
		t.Fatalf("an ingested row that submitted a locked field was accepted: %s", got)
	}
	if got := ingest("{\"body\":\"b\",\"user_id\":5}\n"); !strings.Contains(got, `"ingested":1`) {
		t.Fatalf("control: a row without the locked field was refused: %s", got)
	}

	// The list names only the columns the row writes: not user_id (the
	// framework fills it in) and not keys the write drops.
	app.Hooks = &HookConfig{BeforeInsert: map[string][]Hook{"notes": {{
		SQL: "SELECT CASE WHEN '{{_submitted}}' != ',body,title,' THEN RAISE(ABORT, 'unexpected submitted list') END",
	}}}}
	if got := ingest("{\"title\":\"x\",\"body\":\"b\",\"user_id\":5,\"created_at\":\"2020-01-01\"}\n"); !strings.Contains(got, `"ingested":1`) {
		t.Fatalf("ingest {{_submitted}} did not list exactly the written columns: %s", got)
	}
}
