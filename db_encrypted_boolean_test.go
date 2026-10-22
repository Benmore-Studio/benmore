//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

// The dispatch-check app received encrypted false as the truthy string "0"
// from POST and GET, so both its immediate and reloaded UI showed "Ready to dispatch".
func TestEncryptedBooleansKeepDeclaredType(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, dir, "schema.prisma", `model Clearance {
 id Int @id @default(autoincrement())
 user_id Int
 label String
 cleared Boolean @default(false)
 optional_flag Boolean?
 public_flag Boolean @default(false)
 numeric_text String
 restricted_flag Boolean
 @@map("clearances")
}`)
	writeTestFile(t, dir, "app.yaml", `auth: {identifier: email}
access: {clearances: self}
versioned: [clearances]
encrypted:
 clearances:
  - {column: cleared, roles: [owner]}
  - {column: optional_flag, roles: [owner]}
  - {column: numeric_text, roles: [owner]}
  - {column: restricted_flag, roles: [reviewer]}
`)
	app, err := loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	mux := buildAppMux(app, true, "https://clearance.example.invalid")
	token := createCrudScopeSession(t, app, "owner@example.test", "user", "", "")
	foreign := createCrudScopeSession(t, app, "foreign@example.test", "user", "", "")
	for _, value := range []any{false, true, nil} {
		t.Run(fmt.Sprint(value), func(t *testing.T) {
			cleared := value == true
			body := map[string]any{"label": fmt.Sprint(value), "cleared": cleared, "optional_flag": value, "public_flag": cleared, "numeric_text": "0", "restricted_flag": false}
			created := crudScopeRequest(t, mux, http.MethodPost, "/api/clearances", token, body)
			if created.Code != http.StatusOK {
				t.Fatalf("create: %d %s", created.Code, created.Body.String())
			}
			var row map[string]any
			if err := json.Unmarshal(created.Body.Bytes(), &row); err != nil {
				t.Fatal(err)
			}
			id := fmt.Sprint(row["id"])
			assertRow := func(route string, row map[string]any) {
				t.Helper()
				if row["cleared"] != cleared || row["optional_flag"] != value || row["public_flag"] != cleared {
					t.Errorf("%s Boolean types: cleared=%#v optional=%#v public=%#v; want %v/%v/%v", route, row["cleared"], row["optional_flag"], row["public_flag"], cleared, value, cleared)
				}
				if row["numeric_text"] != "0" {
					t.Errorf("%s changed encrypted TEXT: %#v", route, row["numeric_text"])
				}
				if _, ok := row["restricted_flag"].(bool); ok || row["restricted_flag"] == "0" {
					t.Errorf("%s unmasked restricted Boolean: %#v", route, row["restricted_flag"])
				}
			}
			assertRow("create", row)
			read := crudScopeRequest(t, mux, http.MethodGet, "/api/clearances/"+id, token, nil)
			if read.Code != http.StatusOK {
				t.Fatalf("read: %d %s", read.Code, read.Body.String())
			}
			if err := json.Unmarshal(read.Body.Bytes(), &row); err != nil {
				t.Fatal(err)
			}
			assertRow("get", row)
			projected := crudScopeRequest(t, mux, http.MethodPost, "/api/_query", token, map[string]any{
				"table": "clearances", "select": []string{"cleared", "optional_flag", "public_flag", "numeric_text", "restricted_flag"}, "where": map[string]any{"id": row["id"]},
			})
			var projection struct {
				Rows []map[string]any `json:"rows"`
			}
			if projected.Code != http.StatusOK {
				t.Fatalf("projected query: %d %s", projected.Code, projected.Body.String())
			}
			if err := json.Unmarshal(projected.Body.Bytes(), &projection); err != nil || len(projection.Rows) != 1 {
				t.Fatalf("projected rows: %s %v", projected.Body.String(), err)
			}
			assertRow("query projection", projection.Rows[0])

			list := crudScopeRequest(t, mux, http.MethodGet, "/api/clearances", token, nil)
			var rows []map[string]any
			if list.Code != http.StatusOK {
				t.Fatalf("list: %d %s", list.Code, list.Body.String())
			}
			if err := json.Unmarshal(list.Body.Bytes(), &rows); err != nil {
				t.Fatal(err)
			}
			found := false
			for _, r := range rows {
				if fmt.Sprint(r["id"]) == id {
					assertRow("list", r)
					found = true
				}
			}
			if !found {
				t.Fatal("created row missing from list")
			}
			var stored string
			if err := app.DB.QueryRow("SELECT cleared FROM clearances WHERE id=?", id).Scan(&stored); err != nil || !strings.HasPrefix(stored, "enc:") {
				t.Fatalf("not ciphertext: %q %v", stored, err)
			}
			denied := crudScopeRequest(t, mux, http.MethodGet, "/api/clearances/"+id, foreign, nil)
			if denied.Code != http.StatusNotFound {
				t.Fatalf("foreign read: %d %s", denied.Code, denied.Body.String())
			}
			// Updating the encrypted flag must retain the same type on the next read.
			updated := crudScopeRequest(t, mux, http.MethodPatch, "/api/clearances/"+id, token, map[string]any{"cleared": !cleared})
			if updated.Code != http.StatusOK {
				t.Fatalf("update: %d %s", updated.Code, updated.Body.String())
			}
			read = crudScopeRequest(t, mux, http.MethodGet, "/api/clearances/"+id, token, nil)
			if err := json.Unmarshal(read.Body.Bytes(), &row); err != nil {
				t.Fatal(err)
			}
			if row["cleared"] != !cleared {
				t.Errorf("updated Boolean = %#v, want %v", row["cleared"], !cleared)
			}
			var version int64
			if err := app.DB.QueryRow("SELECT _version FROM clearances_history WHERE id=? ORDER BY _version LIMIT 1", id).Scan(&version); err != nil {
				t.Fatal(err)
			}
			history := crudScopeRequest(t, mux, http.MethodGet, fmt.Sprintf("/api/clearances/%s/versions/%d", id, version), token, nil)
			if history.Code != http.StatusOK {
				t.Fatalf("history: %d %s", history.Code, history.Body.String())
			}
			if err := json.Unmarshal(history.Body.Bytes(), &row); err != nil {
				t.Fatal(err)
			}
			assertRow("history", row)

		})
	}
	// A wrong-key read must retain the decryption-failure mask instead of
	// interpreting it as false. Literal encrypted TEXT "0" also stays text.
	rows, err := app.DB.Query("SELECT cleared, optional_flag, numeric_text FROM clearances ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	masked, err := scanRows(rows, []byte(strings.Repeat("x", 32)))
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range masked {
		if row["cleared"] != decryptFailMask || row["numeric_text"] != decryptFailMask {
			t.Errorf("wrong-key read did not retain masks: %#v", row)
		}
	}
	// Direct SQL can contain invalid BOOLEAN text. Preserve it for diagnosis;
	// it is not permission to silently turn an unknown value into false.
	if _, err := app.DB.Exec("UPDATE clearances SET cleared='not-a-boolean' WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	rows, err = app.DB.Query("SELECT cleared FROM clearances WHERE id=1")
	if err != nil {
		t.Fatal(err)
	}
	invalid, err := scanRows(rows, cryptoKeyForQuerier(app.DB))
	if err != nil || len(invalid) != 1 || invalid[0]["cleared"] != "not-a-boolean" {
		t.Fatalf("invalid Boolean plaintext changed: %#v %v", invalid, err)
	}

}
