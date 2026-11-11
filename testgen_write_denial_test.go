//go:build !cli

package main

import (
	"net/http"
	"testing"
)

// Round 2 B15: a create the access rules refuse on a table the caller may
// read answers 403 forbidden (writeCRUDOpDenied), not the unmatched-route 404.
// The generated framework tests must predict that, and still pass on a
// correct app, or every app with a read-everyone/write-by-role table would
// fail `benmore test --framework`.
func TestGeneratedTestsExpect403ForAWriteRefusedOnAReadableTable(t *testing.T) {
	app := loadGeneratedFixtureApp(t, map[string]string{
		"app.yaml": `access:
  services: { read: everyone, write: "role:staff", update: "role:staff", delete: "role:staff" }
  secrets: { all: "role:staff" }
`,
		"schema.prisma": `model Service {
  id   Int    @id @default(autoincrement())
  name String
  @@map("services")
}
model Secret {
  id   Int    @id @default(autoincrement())
  name String
  @@map("secrets")
}
`,
	})
	run := runGeneratedFixture(t, app)
	expectStep(t, "create_services", run.testCase(t, "_framework_crud", "create_services").Steps[0], http.StatusForbidden, "access rules do not let you")
	expectStep(t, "list_services", run.testCase(t, "_framework_crud", "list_services").Steps[0], http.StatusOK, "")
	// A table the plain user cannot read keeps the unmatched-route answer.
	expectStep(t, "create_secrets", run.testCase(t, "_framework_crud", "create_secrets").Steps[0], http.StatusNotFound, "no API route matches")
	for _, name := range []string{"create_services", "create_secrets"} {
		if r := run.result(t, "_framework_crud", name); !r.Pass {
			t.Errorf("%s failed on a correct app: %s", name, r.Message)
		}
	}
}

// A restore is an update: handleRestore refuses it on access before it looks
// at the ID, so on a table the plain user may read but not change the
// invalid-ID probe answers 403, and on one it cannot read at all the
// unmatched-route 404 (the 2.7.311 fleet check found the old blanket 404
// failing on every such table).
func TestGeneratedRestoreProbeFollowsTheTableGate(t *testing.T) {
	app := loadGeneratedFixtureApp(t, map[string]string{
		"app.yaml": `access:
  services: { read: everyone, write: "role:staff", update: "role:staff", delete: "role:staff" }
  secrets: { all: "role:staff" }
`,
		"schema.prisma": `model Note {
  id         Int       @id @default(autoincrement())
  title      String
  user_id    Int
  deleted_at DateTime?
  @@map("notes")
}
model Service {
  id         Int       @id @default(autoincrement())
  name       String
  deleted_at DateTime?
  @@map("services")
}
model Secret {
  id         Int       @id @default(autoincrement())
  name       String
  deleted_at DateTime?
  @@map("secrets")
}
`,
	})
	run := runGeneratedFixture(t, app)
	expectStep(t, "restore_invalid_id_services", run.testCase(t, "_framework_restore", "restore_invalid_id_services").Steps[0], http.StatusForbidden, "access rules do not let you")
	expectStep(t, "restore_invalid_id_secrets", run.testCase(t, "_framework_restore", "restore_invalid_id_secrets").Steps[0], http.StatusNotFound, "no API route matches")
	expectStep(t, "restore_invalid_id_notes", run.testCase(t, "_framework_restore", "restore_invalid_id_notes").Steps[0], http.StatusNotFound, "")
	for _, name := range []string{"restore_invalid_id_services", "restore_invalid_id_secrets", "restore_invalid_id_notes"} {
		if r := run.result(t, "_framework_restore", name); !r.Pass {
			t.Errorf("%s failed on a correct app: %s", name, r.Message)
		}
	}
}
