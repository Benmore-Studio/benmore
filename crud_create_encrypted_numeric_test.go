//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The Casework app's native create response returned encrypted INTEGER money
// as a string, although GET returned a number. A client using the returned row
// could concatenate the amount instead of adding it until the next refresh.
func TestCreateEncryptedNumbersMatchCanonicalRead(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, dir, "schema.prisma", `model Evidence {
 id Int @id @default(autoincrement())
 user_id Int
 title String
 budget_cents Int
 ratio Float
 reserve_cents Int?
 restricted_cents Int
 numeric_text String
 approved Boolean @default(false)
 optional_flag Boolean?
 acquired_at DateTime?
 status String?
 api_secret String
 @@map("evidence")
}`)
	writeTestFile(t, dir, "app.yaml", `auth: {identifier: email}
access: {evidence: self}
encrypted:
  evidence:
    - {column: budget_cents, roles: [owner]}
    - {column: ratio, roles: [owner]}
    - {column: reserve_cents, roles: [owner]}
    - {column: restricted_cents, roles: [finance]}
    - {column: numeric_text, roles: [owner]}
    - api_secret
`)
	app, err := loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	mux := buildAppMux(app, true, "https://numeric.example.invalid")
	token := createCrudScopeSession(t, app, "creator@example.test", "user", "", "")
	decode := func(body string) map[string]any {
		t.Helper()
		var row map[string]any
		decoder := json.NewDecoder(strings.NewReader(body))
		decoder.UseNumber()
		if err := decoder.Decode(&row); err != nil {
			t.Fatalf("decode row: %v: %s", err, body)
		}
		return row
	}
	for _, tc := range []struct {
		name, budget, ratio string
		approved            bool
		reserve             any
	}{
		{"positive", "50000", "12.5", true, json.Number("1200")},
		{"zero_and_null", "0", "0", false, nil},
		{"negative_exact_integer", "-9007199254740993", "-0.125", false, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := map[string]any{
				"title": tc.name, "budget_cents": json.Number(tc.budget), "ratio": json.Number(tc.ratio),
				"reserve_cents": tc.reserve, "restricted_cents": 321, "numeric_text": "00120",
				"approved": tc.approved, "optional_flag": nil, "acquired_at": nil, "status": nil,
				"api_secret": "synthetic-hidden-value",
			}
			created := crudScopeRequest(t, mux, http.MethodPost, "/api/evidence", token, body)
			if created.Code != http.StatusOK {
				t.Fatalf("create: %d %s", created.Code, created.Body.String())
			}
			row := decode(created.Body.String())
			id, ok := row["id"].(json.Number)
			if !ok {
				t.Fatalf("created id: %#v", row["id"])
			}
			read := crudScopeRequest(t, mux, http.MethodGet, "/api/evidence/"+id.String(), token, nil)
			if read.Code != http.StatusOK {
				t.Fatalf("read: %d %s", read.Code, read.Body.String())
			}
			canonical := decode(read.Body.String())
			if got := row["budget_cents"]; got != json.Number(tc.budget) {
				t.Errorf("create budget = %#v (%T), want JSON number %s", got, got, tc.budget)
			}
			if _, ok := row["ratio"].(json.Number); !ok {
				t.Errorf("create ratio = %#v (%T), want JSON number", row["ratio"], row["ratio"])
			}
			if !reflect.DeepEqual(row, canonical) {
				t.Errorf("created row differs from canonical read:\ncreated: %s\nread: %s", created.Body.String(), read.Body.String())
			}
			if row["approved"] != tc.approved || row["optional_flag"] != nil || row["acquired_at"] != nil || row["status"] != nil || row["numeric_text"] != "00120" {
				t.Errorf("ordinary Boolean, null, status or encrypted text changed: %v", row)
			}
			if _, present := row["api_secret"]; present || strings.Contains(created.Body.String(), "synthetic-hidden-value") {
				t.Error("create exposed hidden encrypted field")
			}
			if row["restricted_cents"] == json.Number("321") || row["restricted_cents"] == "321" {
				t.Error("create bypassed encrypted field's unmask role")
			}
			var stored string
			if err := app.DB.QueryRow("SELECT budget_cents FROM evidence WHERE id=?", id.String()).Scan(&stored); err != nil || !strings.HasPrefix(stored, "enc:") {
				t.Fatalf("fixture is not encrypted at rest: %q %v", stored, err)
			}
		})
	}
}
