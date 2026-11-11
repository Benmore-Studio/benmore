//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func generatedScalarFixture(t *testing.T, schema string) (*App, *httptest.Server) {
	t.Helper()
	app, _ := auditApp(t)
	app.Group = nil
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "schema.prisma"), []byte(schema), 0600); err != nil {
		t.Fatal(err)
	}
	tables, deferred, err := LoadSchema(app.DB, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = ApplyDeferredDDL(app.DB, deferred); err != nil {
		t.Fatal(err)
	}
	app.Tables = tables
	app.JoinMap = BuildJoinMap(app.DB)
	app.UUIDTables = DetectUUIDTables(tables)
	for _, table := range tables {
		app.Access.rules[table.Name] = map[AccessOp]string{"all": "self"}
	}
	mux := http.NewServeMux()
	RegisterCRUD(mux, app)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return app, server
}

func TestGeneratedRequiredScalarIDFields(t *testing.T) {
	app, server := generatedScalarFixture(t, `model Record {
 id Int @id @default(autoincrement())
 userId Int
 externalId String @map("external_id")
 quantityId Int @map("quantity_id")
 optionalId Int? @map("optional_id")
 defaultId Int @default(7) @map("default_id")
 title String
 @@map("scalar_records")
}`)
	generated := generateCRUDTests(app)
	journey := generated.Tests["create_scalar_records"]
	if journey.Steps[0].Expect.Status != http.StatusOK {
		t.Fatal("success assertion weakened")
	}
	result := runSingleTest(app, server.URL, generated.Name, "create_scalar_records", journey)
	if !result.Pass {
		t.Fatalf("required ordinary scalar *_id omitted: %+v", result)
	}
	var external string
	var quantity, defaultID int
	var optional any
	if err := app.DB.QueryRow("SELECT external_id, quantity_id, optional_id, default_id FROM scalar_records").Scan(&external, &quantity, &optional, &defaultID); err != nil {
		t.Fatal(err)
	}
	if external == "" || quantity != 1 || optional != nil || defaultID != 7 {
		t.Fatalf("unexpected values: %q %d %#v %d", external, quantity, optional, defaultID)
	}
}

func TestGeneratedUUIDLifecycleUsesDeclaredType(t *testing.T) {
	for _, scalar := range []string{"Int", "Float", "Boolean", "DateTime"} {
		t.Run(scalar, func(t *testing.T) {
			app, server := generatedScalarFixture(t, `model Record {
 id String @id @default(uuid())
 userId Int
 metric `+scalar+`
 @@map("typed_records")
}`)
			generated := generateUUIDTests(app)
			journey, ok := generated.Tests["uuid_lifecycle_typed_records"]
			if !ok {
				t.Fatal("typed lifecycle omitted")
			}
			if len(journey.Steps) != 3 || journey.Steps[1].Expect.Status != http.StatusOK {
				t.Fatal("lifecycle success assertion weakened")
			}
			// Check the stored updated value before the generated delete, rather
			// than treating a successful PATCH receipt as proof of the change.
			want := map[string]string{"Int": "2", "Float": "2.0", "Boolean": "1", "DateTime": "2026-01-02"}[scalar]
			journey.Steps = append(journey.Steps[:2],
				AppTestStep{SQL: "SELECT id FROM typed_records WHERE CAST(metric AS TEXT) = '" + want + "'", Expect: AppTestExpect{Rows: expectRows(1)}},
				journey.Steps[2])
			result := runSingleTest(app, server.URL, generated.Name, "uuid_lifecycle_typed_records", journey)
			if !result.Pass {
				t.Fatalf("typed lifecycle failed: %+v", result)
			}
			var count int
			if err := app.DB.QueryRow("SELECT count(*) FROM typed_records").Scan(&count); err != nil || count != 0 {
				t.Fatalf("delete did not persist: count=%d err=%v", count, err)
			}
		})
	}
}

// A suffix alone is not a relationship, and no existing parent's ID is
// guessed: a required foreign key references a parent the test creates first.
func TestGeneratedRequiredIDDoesNotGuessForeignKey(t *testing.T) {
	app, server := generatedScalarFixture(t, `model Parent {
 id Int @id @default(autoincrement())
 userId Int
 label String
 @@map("fixture_parents")
}

model Child {
 id Int @id @default(autoincrement())
 userId Int
 parentId Int @map("parent_id")
 parent Parent @relation(fields:[parentId], references:[id])
 externalId String @map("external_id")
 title String
 @@map("fixture_children")
}`)
	mustExec(t, app.DB, "INSERT INTO fixture_parents(id,user_id,label) VALUES (1,99999,'unrelated synthetic row')")
	generated := generateCRUDTests(app)
	journey := generated.Tests["create_fixture_children"]
	if len(journey.Steps) != 2 || journey.Steps[0].API != "POST /api/fixture_parents" {
		t.Fatalf("the required parent is not created first: %+v", journey.Steps)
	}
	if ref, _ := journey.Steps[1].Data["parent_id"].(string); !strings.HasPrefix(ref, "{{") {
		t.Fatalf("generator invented a foreign parent ID: %#v", journey.Steps[1].Data["parent_id"])
	}
	if journey.Steps[1].Expect.Status != http.StatusOK {
		t.Fatal("the child create's success assertion was loosened")
	}
	app.JoinMap = nil
	if _, ok := smartFormData(app, "fixture_children", tableColumns(app, "fixture_children"))["parent_id"]; ok {
		t.Fatal("generator ignored the physical FK when cached metadata was absent")
	}
	if planned := planGeneratedRow(app, "fixture_children", "metadata", plainGeneratedSession(app)); len(planned.Steps) != 1 {
		t.Fatalf("the physical FK must still be planned without cached metadata: %+v", planned)
	}
	result := runSingleTest(app, server.URL, generated.Name, "create_fixture_children", journey)
	if !result.Pass {
		t.Fatalf("child create with its own parent failed: %+v", result)
	}
	var parentOwner int64
	if err := app.DB.QueryRow("SELECT p.user_id FROM fixture_children c JOIN fixture_parents p ON p.id = c.parent_id").Scan(&parentOwner); err != nil || parentOwner == 99999 {
		t.Fatalf("child references the unrelated parent: owner=%d err=%v", parentOwner, err)
	}
}

func TestGeneratedFixtureMetadataFailureDoesNotInventReferences(t *testing.T) {
	app, _ := generatedScalarFixture(t, `model Parent {
 id Int @id @default(autoincrement())
 title String
 @@map("metadata_parents")
}
model Child {
 id Int @id @default(autoincrement())
 parentKey Int @map("parent_key")
 parent Parent @relation(fields:[parentKey], references:[id])
 title String
 @@map("metadata_children")
}`)
	cols := tableColumns(app, "metadata_children")
	if len(cols) == 0 {
		t.Fatal("fixture columns not loaded")
	}
	app.JoinMap = nil
	if err := app.DB.Close(); err != nil {
		t.Fatal(err)
	}
	if data := smartFormData(app, "metadata_children", cols); len(data) != 0 {
		t.Fatalf("uncertain metadata produced guessed fixture values: %#v", data)
	}
}
