//go:build !cli

package main

import (
	"net/http"
	"testing"
)

func TestGenerateRestoreTestsOnlyNativeSoftDeleteRoutes(t *testing.T) {
	app, mux, sid, _ := restoreFixture(t)
	mustExec(t, app.DB, `CREATE TABLE string_keys(id TEXT PRIMARY KEY,deleted_at TEXT)`)
	mustExec(t, app.DB, `INSERT INTO string_keys VALUES('01','2026-10-14'),('not-a-canonical-row-id','2026-10-14')`)
	refreshTableColumns(t, app, "string_keys")
	file := generateRestoreTests(app)
	if len(file.Tests) != 1 {
		t.Fatalf("restore cases: %#v", file.Tests)
	}
	tc, ok := file.Tests["restore_invalid_id_notes"]
	if !ok || len(tc.Steps) != 1 || tc.Steps[0].Expect.Status != http.StatusNotFound {
		t.Fatalf("restore case: %#v", tc)
	}
	w := crudScopeRequest(t, mux, http.MethodPost, "/api/notes/01/restore", sid, nil)
	if w.Code != http.StatusNotFound || gateScalar(t, app, `SELECT deleted_at IS NOT NULL FROM notes WHERE id=1`) != "1" {
		t.Fatalf("generated invalid-ID probe changed data: %d %s", w.Code, w.Body.String())
	}
	if gateScalar(t, app, `SELECT count(*) FROM string_keys WHERE deleted_at IS NOT NULL`) != "2" {
		t.Fatal("generator mutated string-key rows")
	}
	app.Flows = []Flow{{Trigger: FlowTrigger{Type: "http", Method: "POST", Path: "/api/notes/:id/restore"}}}
	if got := generateRestoreTests(app); len(got.Tests) != 0 {
		t.Fatalf("generated tests impose native behavior on authored route: %#v", got)
	}
}
