//go:build !cli

package main

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// role:<X> and perm: on a table that has user_id (and no groups: key) decide
// who may call, and rowScopeClause still falls through to the owner filter:
// a manager reaches only their own rows, so `delete: role:manager` 404s on a
// staff member's row while `update: owner_or_role:manager` reaches it. That
// runtime behaviour is unchanged (changing it would widen access in live
// apps); it is documented, describe adds a hint and benmore check warns.
func TestRoleModeOnOwnedTableStaysOwnerScoped(t *testing.T) {
	app, mux := undeclaredAdminApp(t, undeclaredAdminRoles)
	mgr := authzUser(t, app, "mgr@example.com", "manager")
	staff := authzUser(t, app, "staff@example.com", "user")
	mustExec(t, app.DB, fmt.Sprintf(`INSERT INTO shifts (id, user_id, title) VALUES (1, %d, 'staff shift'), (2, %d, 'manager shift')`, staff, mgr))
	mgrSID := authzSession(t, app, mgr, "mgr@example.com")

	// owner_or_role:manager (update) reaches another user's row.
	if w := undeclaredAdminCall(t, mux, "PATCH", "/api/shifts/1", mgrSID, "", `{"title":"edited by manager"}`); w.Code != http.StatusOK {
		t.Fatalf("owner_or_role update of staff's shift: %d %s", w.Code, w.Body.String())
	}
	// role:manager (delete) on the same table does not: the row answers 404
	// and stays; the manager's own row deletes.
	if w := undeclaredAdminCall(t, mux, "DELETE", "/api/shifts/1", mgrSID, "", ""); w.Code != http.StatusNotFound {
		t.Fatalf("role:manager delete of staff's shift: %d %s, want 404 (owner-scoped)", w.Code, w.Body.String())
	}
	var title string
	if err := app.DB.QueryRow("SELECT title FROM shifts WHERE id = 1").Scan(&title); err != nil || title != "edited by manager" {
		t.Fatalf("staff's shift after refused delete: %q %v", title, err)
	}
	if w := undeclaredAdminCall(t, mux, "DELETE", "/api/shifts/2", mgrSID, "", ""); w.Code != http.StatusOK && w.Code != http.StatusNoContent {
		t.Fatalf("role:manager delete of own shift: %d %s", w.Code, w.Body.String())
	}

	// describe says so, and points at owner_or_role for the delete op only.
	access := describeTableAccess(app, "shifts")
	del := access["delete"]
	if del["rows"] != "owner" || !strings.Contains(fmt.Sprint(del["effect"]), "only decides who may call") ||
		!strings.Contains(fmt.Sprint(del["hint"]), "owner_or_role:manager") {
		t.Fatalf("describe delete = %v", del)
	}
	if _, ok := access["update"]["hint"]; ok || access["update"]["rows"] != "owner_or_role" {
		t.Fatalf("describe update = %v", access["update"])
	}
	// perm: on an owned table gets the hint too, naming the roles granting it.
	// The realtime dispatcher reads the app's access rules under app.mu
	// while it delivers the writes above, so the swap takes the lock.
	permAccess := accessFromYAML(t, undeclaredAdminRoles+"access:\n  notes: {update: perm:reports.read}\n")
	app.mu.Lock()
	app.Access = permAccess
	app.mu.Unlock()
	notes := describeTableAccess(app, "notes")["update"]
	if notes["rows"] != "owner" || !strings.Contains(fmt.Sprint(notes["hint"]), "owner_or_role:manager") {
		t.Fatalf("describe perm: update = %v", notes)
	}
}

const roleModeRowsSchema = `model Shift {
  id Int @id @default(autoincrement())
  title String
  user_id Int?
  @@map("shifts")
}
model TimeOff {
  id Int @id @default(autoincrement())
  day String
  user_id Int?
  @@map("time_off")
}
model TeamNote {
  id Int @id @default(autoincrement())
  body String
  user_id Int?
  @@map("team_notes")
}
model PayRate {
  id Int @id @default(autoincrement())
  amount Int
  @@map("pay_rates")
}
model Org {
  id Int @id @default(autoincrement())
  name String
  user_id Int?
  @@map("orgs")
}
model OrgMember {
  id Int @id @default(autoincrement())
  org_id Int
  email String
  @@map("org_members")
}
model OrgDoc {
  id Int @id @default(autoincrement())
  org_id Int
  user_id Int?
  @@map("org_docs")
}
model Diary {
  id Int @id @default(autoincrement())
  entry String
  user_id Int?
  @@map("diaries")
}
model Booking {
  id Int @id @default(autoincrement())
  slot String
  user_id Int?
  @@map("bookings")
}
`

const roleModeRowsAppYAML = `roles:
  user: {scopes: "*"}
  manager: {scopes: "*"}
  auditor: {scopes: "time_off:approve"}
groups:
  table: org_members
  key: org_id
  user_field: email
  bootstrap: {org_table: orgs}
access:
  shifts: {read: "owner_or_role:manager", update: "owner_or_role:manager", delete: "role:manager"}
  time_off: {update: "perm:time_off.approve"}
  team_notes: {all: "role:manager"}
  pay_rates: {all: "role:manager"}
  orgs: {all: "role:manager"}
  org_docs: {all: "role:manager"}
  diaries: {all: self}
  bookings: {update: "role:admin", delete: "role:admin"}
`

func TestRoleModeOwnerRowsWarnings(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "schema.prisma", roleModeRowsSchema)
	writeTestFile(t, dir, "app.yaml", roleModeRowsAppYAML)

	var got []string
	for _, f := range authzWarnings(dir) {
		if strings.Contains(f.Message, "on a table with user_id and no tenant key") {
			if f.Severity != "warning" || f.File != "app.yaml" {
				t.Errorf("finding %+v: want a warning on app.yaml", f)
			}
			got = append(got, f.Message)
		}
	}
	want := []string{
		"access.shifts: delete uses `role:manager`",
		"access.team_notes: read/update/delete uses `role:manager`",
		"access.time_off: update uses `perm:time_off.approve`",
	}
	if len(got) != len(want) {
		t.Fatalf("warnings = %q, want one each for %q", got, want)
	}
	for i, w := range want {
		if !strings.HasPrefix(got[i], w) {
			t.Errorf("warning %d = %q, want prefix %q", i, got[i], w)
		}
	}
	// The suggestion names the roles: role: lists its own, perm: the roles
	// granting the permission. Group-keyed tables, the tenant root, tables
	// without user_id, owner_or_role, self and role:admin (only a global
	// admin passes it there, and admins bypass rows) are not flagged.
	if !strings.Contains(got[0], "use `owner_or_role:manager`") || !strings.Contains(got[2], "use `owner_or_role:auditor,manager,user`") {
		t.Errorf("suggestions: %q", got)
	}
	for _, msg := range got {
		for _, table := range []string{"pay_rates", "orgs", "org_docs", "diaries", "bookings"} {
			if strings.HasPrefix(msg, "access."+table+":") {
				t.Errorf("flagged %s: %q", table, msg)
			}
		}
	}

	// The write gate reports it too (same check layer as benmore check),
	// without refusing the write.
	report := RunSourceCheck(dir, "app.yaml")
	found := false
	for _, f := range report.Findings {
		if f.Severity == "error" {
			t.Errorf("write gate error: %+v", f)
		}
		if strings.HasPrefix(f.Message, "access.shifts: delete uses `role:manager`") {
			found = true
		}
	}
	if !found {
		t.Fatalf("write gate findings lack the role-mode warning: %+v", report.Findings)
	}
}
