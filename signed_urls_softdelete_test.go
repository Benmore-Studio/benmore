//go:build !cli

package main

import (
	"net/http"
	"testing"
)

// On a broadly readable table the per-row check is skipped, but a
// soft-deleted record is still gone: GET /api/<table>/<id> and every list
// hide it, so it can no longer authorize signing the private files it
// referenced. Scoped tables already refuse it through canAccessRow.
func TestSignedURL_SoftDeletedRecordCannotAuthorize(t *testing.T) {
	app, mux, cleanup := signedURLApp(t)
	defer cleanup()
	mustExec(t, app.DB, "ALTER TABLE docs ADD COLUMN deleted_at DATETIME")
	app.Tables = []Table{{Name: "docs", Columns: []Column{{Name: "id"}, {Name: "user_id"}, {Name: "file_url"}, {Name: "deleted_at"}}}}
	app.Access = &AccessConfig{rules: map[string]map[AccessOp]string{"docs": {OpRead: "everyone"}}}

	tok := createCrudScopeSession(t, app, "reader@example.com", "user", "", "")
	if code, _ := mintSignedURL(t, mux, tok, "path=private/secret.pdf&record_table=docs&record_id=1"); code != http.StatusOK {
		t.Fatalf("live public record should authorize signing: %d", code)
	}
	mustExec(t, app.DB, "UPDATE docs SET deleted_at = datetime('now') WHERE id = 1")
	if code, _ := mintSignedURL(t, mux, tok, "path=private/secret.pdf&record_table=docs&record_id=1"); code != http.StatusForbidden {
		t.Fatalf("soft-deleted record authorized signing its private file: %d", code)
	}
	// A record id that does not exist authorizes nothing either.
	if code, _ := mintSignedURL(t, mux, tok, "path=private/secret.pdf&record_table=docs&record_id=999"); code != http.StatusForbidden {
		t.Fatalf("missing record authorized signing: %d", code)
	}
}
