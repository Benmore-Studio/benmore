//go:build !cli

package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"testing"
)

// Execute the generated create/read journey against the real CRUD handlers.
// A domain status (or NULL) must not make a valid UUID app fail fleet checks;
// the legacy operation-marker assertion still belongs to tables without it.
func TestGeneratedUUIDCreateUsesActualStatusContract(t *testing.T) {
	for _, tc := range []struct {
		name        string
		statusField string
		nullStatus  bool
	}{
		{"legacy marker", "", false},
		{"domain status", `status String @default("draft")`, false},
		{"nullable status", "status String?", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, _ := auditApp(t)
			models, err := ParsePrismaSchema(fmt.Sprintf(`model UUIDRecord {
  id String @id @default(uuid())
  title String
  userId Int @map("user_id")
  %s
  @@map("uuid_records")
}
`, tc.statusField))
			if err != nil {
				t.Fatal(err)
			}
			mustExec(t, app.DB, EmitSQL(models))
			refreshTableColumns(t, app, "uuid_records")
			app.UUIDTables = DetectUUIDTables(app.Tables)
			app.Access.rules["uuid_records"] = map[AccessOp]string{"all": "self"}
			mux := http.NewServeMux()
			RegisterCRUD(mux, app)
			server := httptest.NewServer(mux)
			defer server.Close()

			generated := generateUUIDTests(app)
			journey, ok := generated.Tests["uuid_create_uuid_records"]
			if !ok || len(journey.Steps) != 2 {
				t.Fatalf("missing generated create/read journey: %#v", journey)
			}
			contains := expectContains(journey.Steps[0].Expect.Contains)
			if slices.Contains(contains, `"status":"created"`) != (tc.statusField == "") {
				t.Errorf("legacy marker assertion does not match the actual columns: %v", contains)
			}
			if !slices.Contains(contains, `"id":"`) || journey.Steps[0].Expect.Status != http.StatusOK {
				t.Fatalf("UUID success/id assertions were removed: %+v", journey.Steps[0].Expect)
			}
			if tc.nullStatus {
				// Omit a nullable value to exercise a real SQL NULL, not an empty string.
				delete(journey.Steps[0].Data, "status")
			}
			result := runSingleTest(app, server.URL, generated.Name, "uuid_create_uuid_records", journey)
			if !result.Pass {
				t.Errorf("generated UUID journey rejected the real create response: %+v", result)
			}
			var id string
			if err := app.DB.QueryRow("SELECT id FROM uuid_records").Scan(&id); err != nil {
				t.Fatal(err)
			}
			if !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`).MatchString(id) {
				t.Fatalf("created id is not a canonical UUID: %q", id)
			}
		})
	}
}
