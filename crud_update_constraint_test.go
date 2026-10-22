//go:build !cli

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mattn/go-sqlite3"
)

const updateConstraintTable = "private_catalog"

func updateConstraintFixture(t *testing.T, dev bool) (*App, *http.ServeMux, string) {
	t.Helper()
	app, sid, uid := canonicalUpdateFixture(t)
	app.DevMode = dev
	mustExec(t, app.DB, `CREATE TABLE private_catalog (id INTEGER PRIMARY KEY, user_id INTEGER, secret_code TEXT NOT NULL UNIQUE, quantity INTEGER NOT NULL CHECK(quantity>=0), updated_at TEXT)`)
	if _, err := app.DB.Exec(`INSERT INTO private_catalog VALUES (1,?,'first-private-value',1,'2026-10-16 00:00:00'),(2,?,'second-private-value',2,'2026-10-16 00:00:00'),(3,?,'foreign-private-value',3,'2026-10-16 00:00:00')`, uid, uid, uid+100); err != nil {
		t.Fatal(err)
	}
	refreshTableColumns(t, app, updateConstraintTable)
	app.Access.rules[updateConstraintTable] = map[AccessOp]string{"all": "self"}
	mux := http.NewServeMux()
	RegisterCRUD(mux, app)
	return app, mux, sid
}

func updateConstraintCall(mux *http.ServeMux, sid, method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://app.example.com"+path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+sid)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

func updateConstraintState(t *testing.T, app *App) string {
	t.Helper()
	rows, err := queryRowsWith(app.DB, `SELECT * FROM private_catalog ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	audit, err := queryRowsWith(app.DB, `SELECT * FROM _benmore_audit_log WHERE table_name='private_catalog' ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	state, err := json.Marshal(map[string]any{"rows": rows, "audit": audit})
	if err != nil {
		t.Fatal(err)
	}
	return string(state)
}

func updateConstraintRequest(route string) (string, string, string) {
	switch route {
	case "single":
		return "PATCH", "/api/private_catalog/1", `{"secret_code":"second-private-value"}`
	case "batch":
		return "PATCH", "/api/private_catalog/batch", `{"ids":[1,3,2],"fields":{"secret_code":"fresh-collision-value"}}`
	default:
		return "POST", "/api/_transaction", `{"operations":[{"table":"private_catalog","action":"update","id":1,"data":{"quantity":42}},{"table":"private_catalog","action":"update","id":2,"data":{"secret_code":"first-private-value"}}]}`
	}
}

// Real UNIQUE errors at SQLite's UPDATE boundary are caller refusals, as on
// CREATE. A later applicable-row failure must also undo earlier batch/transaction
// updates and their audits; the foreign row must never become an error oracle.
func TestUpdateConstraintResponsesPreserveRowsAndAudit(t *testing.T) {
	for _, dev := range []bool{false, true} {
		for _, route := range []string{"single", "batch", "transaction"} {
			t.Run(fmt.Sprintf("%s/dev=%t", route, dev), func(t *testing.T) {
				app, mux, sid := updateConstraintFixture(t, dev)
				positive := updateConstraintCall(mux, sid, "PATCH", "/api/private_catalog/1", `{"secret_code":"positive-private-value"}`)
				if positive.Code != 200 {
					t.Fatalf("normal indexed update: %d %s", positive.Code, positive.Body.String())
				}
				restore := updateConstraintCall(mux, sid, "PATCH", "/api/private_catalog/1", `{"secret_code":"first-private-value"}`)
				if restore.Code != 200 {
					t.Fatalf("normal indexed restore: %d %s", restore.Code, restore.Body.String())
				}
				before := updateConstraintState(t, app)
				method, path, body := updateConstraintRequest(route)
				w := updateConstraintCall(mux, sid, method, path, body)
				if w.Code != http.StatusBadRequest {
					t.Errorf("duplicate value: got %d, want400: %s", w.Code, w.Body.String())
				}
				if got := updateConstraintState(t, app); got != before {
					t.Errorf("refusal changed rows or audit\nbefore=%s\nafter=%s", before, got)
				}
				if dev {
					if !strings.Contains(w.Body.String(), "UNIQUE constraint failed: private_catalog.secret_code") {
						t.Errorf("dev diagnostic missing: %s", w.Body.String())
					}
				} else {
					if !strings.Contains(w.Body.String(), "a record with the same unique value already exists") {
						t.Errorf("safe constraint explanation missing: %s", w.Body.String())
					}
					for _, secret := range []string{"private_catalog", "secret_code", "first-private-value", "second-private-value", "fresh-collision-value", "foreign-private-value"} {
						if strings.Contains(w.Body.String(), secret) {
							t.Errorf("production response disclosed %q: %s", secret, w.Body.String())
						}
					}
				}
			})
		}
	}
}

// A genuine SQL execution fault stays 5xx even if its text resembles a UNIQUE
// error. Register a failing SQLite function, rather than injecting a fabricated
// handler error, so both the driver code and transaction rollback are exercised.
func TestUpdateInternalDatabaseFaultRemainsServerError(t *testing.T) {
	for _, route := range []string{"single", "batch", "transaction"} {
		t.Run(route, func(t *testing.T) {
			app, mux, sid := updateConstraintFixture(t, false)
			app.DB.SetMaxOpenConns(1)
			conn, err := app.DB.Conn(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			err = conn.Raw(func(raw any) error {
				return raw.(*sqlite3.SQLiteConn).RegisterFunc("broken_catalog_storage", func() (int, error) { return 0, errors.New("UNIQUE constraint failed: private_internal_failure") }, false)
			})
			if closeErr := conn.Close(); err != nil || closeErr != nil {
				t.Fatalf("register fault: %v close:%v", err, closeErr)
			}
			badID := 2
			if route == "single" {
				badID = 1
			}
			mustExec(t, app.DB, fmt.Sprintf(`CREATE TRIGGER private_storage_fault BEFORE UPDATE ON private_catalog WHEN NEW.id=%d BEGIN SELECT broken_catalog_storage(); END`, badID))
			before := updateConstraintState(t, app)
			method, path, body := updateConstraintRequest(route)
			// Avoid a competing UNIQUE violation: the failing SQL function is the cause.
			body = strings.ReplaceAll(body, "second-private-value", "new-private-value")
			body = strings.ReplaceAll(body, "first-private-value", "new-private-value")
			w := updateConstraintCall(mux, sid, method, path, body)
			if w.Code != http.StatusInternalServerError {
				t.Errorf("real database fault: got%d want500: %s", w.Code, w.Body.String())
			}
			if !requestIDPattern.MatchString(w.Header().Get(requestIDHeader)) {
				t.Errorf("server error missing request id: %s", w.Body.String())
			}
			for _, secret := range []string{"private_internal_failure", "UNIQUE constraint", "broken_catalog_storage"} {
				if strings.Contains(w.Body.String(), secret) {
					t.Errorf("internal detail leaked: %s", w.Body.String())
				}
			}
			if updateConstraintState(t, app) != before {
				t.Error("database fault changed rows or audits")
			}
		})
	}
}

func TestUpdateOtherDatabaseConstraintsAreClientErrors(t *testing.T) {
	for _, tc := range []struct{ name, body, message string }{
		{"not null", `{"secret_code":null}`, "a required field is missing"},
		{"check", `{"quantity":-1}`, "a field value is not allowed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, mux, sid := updateConstraintFixture(t, false)
			before := updateConstraintState(t, app)
			w := updateConstraintCall(mux, sid, "PATCH", "/api/private_catalog/1", tc.body)
			if w.Code != 400 || !strings.Contains(w.Body.String(), tc.message) {
				t.Errorf("constraint refusal: %d %s", w.Code, w.Body.String())
			}
			for _, detail := range []string{"private_catalog", "secret_code", "quantity"} {
				if strings.Contains(w.Body.String(), detail) {
					t.Errorf("constraint detail disclosed: %s", w.Body.String())
				}
			}
			if updateConstraintState(t, app) != before {
				t.Error("constraint refusal changed row/audit state")
			}
		})
	}
}
