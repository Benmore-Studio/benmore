//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func callCleanupDelete(app *App, route, sid string) *httptest.ResponseRecorder {
	switch route {
	case "single":
		return gateCall(app, handleDelete, "notes", http.MethodDelete, "/api/notes/2", "application/json", "", sid)
	case "batch":
		return gateCall(app, handleBatchDelete, "notes", http.MethodDelete, "/api/notes/batch", "application/json", `{"ids":[1,2]}`, sid)
	default:
		r := httptest.NewRequest(http.MethodPost, "https://app.example.com/api/_transaction", strings.NewReader(`{"operations":[{"table":"notes","action":"delete","id":1},{"table":"notes","action":"delete","id":2}]}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+sid)
		w := httptest.NewRecorder()
		handleTransaction(w, r, app)
		return w
	}
}

// Row-keyed shares and locks must be removed in the same successful transaction
// as a hard delete. If cleanup fails, keeping the deleted id available for reuse
// would transfer the surviving state to an unrelated new row.
func TestHardDeleteRollsBackWhenRowStateCleanupFails(t *testing.T) {
	for _, route := range []string{"single", "batch", "transaction"} {
		for _, ledger := range []string{"_benmore_permissions", "_benmore_locks"} {
			t.Run(route+"/"+ledger, func(t *testing.T) {
				app := newGateApp(t, `CREATE TABLE notes (id INTEGER PRIMARY KEY, user_id INTEGER, body TEXT)`)
				uid, sid := gateUser(t, app, "owner@example.com")
				for _, id := range []string{"1", "2"} {
					if _, err := app.DB.Exec(`INSERT INTO notes (id, user_id, body) VALUES (?, ?, 'original')`, id, uid); err != nil {
						t.Fatal(err)
					}
					if _, err := app.DB.Exec(`INSERT INTO _benmore_permissions (resource_type, resource_id, grant_type, grantee_id, permission) VALUES ('notes', ?, 'user', 'reader@example.com', 'edit')`, id); err != nil {
						t.Fatal(err)
					}
					if _, err := app.DB.Exec(`INSERT INTO _benmore_locks (table_name, row_id, user_id, user_email, expires_at) VALUES ('notes', ?, ?, 'owner@example.com', datetime('now', '+1 hour'))`, id, uid); err != nil {
						t.Fatal(err)
					}
				}
				rowKey := "resource_id"
				if ledger == "_benmore_locks" {
					rowKey = "row_id"
				}
				mustExec(t, app.DB, `CREATE TRIGGER reject_cleanup BEFORE DELETE ON `+quoteIdent(ledger)+` WHEN OLD.`+rowKey+` = '2' BEGIN SELECT RAISE(ABORT, 'fixture cleanup failed'); END`)

				w := callCleanupDelete(app, route, sid)
				if w.Code < 400 {
					t.Errorf("delete must fail when cleanup fails: %d %s", w.Code, w.Body.String())
				}
				for _, table := range []string{"notes", "_benmore_permissions", "_benmore_locks"} {
					if got := gateScalar(t, app, `SELECT COUNT(*) FROM `+quoteIdent(table)); got != "2" {
						t.Errorf("cleanup failure must roll back all rows and state: %s has %s rows, want 2", table, got)
					}
				}
				if got := gateScalar(t, app, `SELECT COUNT(*) FROM _benmore_audit_log WHERE action = 'delete'`); got != "0" {
					t.Errorf("failed delete wrote %s committed audit entries", got)
				}
			})
		}
	}
}

func TestHardDeleteAllowsAbsentRowStateTables(t *testing.T) {
	for _, route := range []string{"single", "batch", "transaction"} {
		t.Run(route, func(t *testing.T) {
			// An unscoped table does not need a permissions ledger for its
			// authorization query either.
			app := newGateApp(t, `CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)`)
			app.Access = &AccessConfig{rules: map[string]map[AccessOp]string{"notes": {"all": "everyone"}}}
			_, sid := gateUser(t, app, "owner@example.com")
			mustExec(t, app.DB, `INSERT INTO notes (id, body) VALUES (1, 'first'), (2, 'second')`)
			mustExec(t, app.DB, `DROP TABLE _benmore_permissions`)
			mustExec(t, app.DB, `DROP TABLE _benmore_locks`)
			w := callCleanupDelete(app, route, sid)
			if w.Code != http.StatusOK {
				t.Fatalf("unused row state ledgers must not prevent delete: %d %s", w.Code, w.Body.String())
			}
			if got := gateScalar(t, app, `SELECT COUNT(*) FROM notes WHERE id = 2`); got != "0" {
				t.Fatalf("delete left %s matching rows", got)
			}
		})
	}
}
