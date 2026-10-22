//go:build !cli

package main

import (
	"net/http"
	"testing"
	"time"
)

// GET /api/_usage is open to every signed-in user and returned total_rows
// (COUNT(*) over every app table, all owners and tenants) and the database
// size. Polled, it shows when any other user writes.
func TestUsageGaugesAreAdminOnly(t *testing.T) {
	app, mux, admin, cleanup := adminPanelApp(t)
	defer cleanup()
	for i := 0; i < 3; i++ {
		mustExec(t, app.DB, `INSERT INTO docs (user_id, file_url) VALUES (99, 'other-owner')`)
	}
	res, err := app.DB.Exec("INSERT INTO _benmore_users (username, email, role, verified) VALUES ('member', 'member@example.com', 'user', 1)")
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := res.LastInsertId()
	member := CreateSession(app.DB, uid, "member@example.com", "", time.Hour)

	var body struct {
		Metrics map[string]any `json:"metrics"`
	}
	rec := crudScopeRequest(t, mux, http.MethodGet, "/api/_usage", member, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("/api/_usage: %d %s", rec.Code, rec.Body.String())
	}
	mustDecodeBody(t, rec, &body)
	for _, k := range []string{"total_rows", "storage_bytes"} {
		if _, ok := body.Metrics[k]; ok {
			t.Errorf("member sees app-wide gauge %s: %v", k, body.Metrics)
		}
	}
	rec = crudScopeRequest(t, mux, http.MethodGet, "/api/_usage", admin, nil)
	body.Metrics = nil
	mustDecodeBody(t, rec, &body)
	if got, _ := body.Metrics["total_rows"].(float64); got < 4 {
		t.Errorf("admin lost total_rows: %v", body.Metrics)
	}
}
