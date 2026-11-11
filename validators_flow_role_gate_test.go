//go:build !cli

package main

import (
	"bytes"
	"log"
	"os"
	"strings"
	"testing"
)

const roleGateSchema = "model Note {\n  id   Int    @id @default(autoincrement())\n  body String\n\n  @@map(\"notes\")\n}\n"

// roleGateFlow is a request flow whose `role:` line is written as given.
func roleGateFlow(roleLine string) string {
	return "on:\n  request:\n    method: POST\n    path: /api/receive-stock\n    " + roleLine + "\njobs:\n  receive:\n    steps:\n      - run: respond\n        with: { status: 200, json: { ok: true } }\n"
}

// roleGateWarnings are the role-gate findings of a report, each checked to be
// a `flows` warning on the flow file whose address is the role key.
func roleGateWarnings(t *testing.T, report CheckReport, file string) []string {
	t.Helper()
	var out []string
	for _, f := range report.Findings {
		if !strings.Contains(f.Message, "on.request.role") {
			continue
		}
		if f.Severity != "warning" || f.Source != "flows" || f.File != file {
			t.Errorf("finding is not a flows warning on %s: %+v", file, f)
		}
		if got := checkFindingDocs(f); got != "flows.role_gate" {
			t.Errorf("the finding is documented at %q, want flows.role_gate: %s", got, f.Message)
		}
		out = append(out, f.Message)
	}
	return out
}

// A flow's role gate is one role name. A comma or space separated list is
// read as one name nobody holds, so the flow answers 403 to everyone but a
// global admin; deployed files carry such gates, so the write is accepted and
// the post-write check, `benmore check` and the load log say what it means.
func TestFlowRoleListIsWarnedAbout(t *testing.T) {
	for name, tc := range map[string]struct {
		roleLine string
		warned   bool
	}{
		"comma list":           {`role: "warehouse,manager"`, true},
		"comma list, unquoted": {`role: finance,admin`, true},
		"comma and space":      {`role: "warehouse, manager"`, true},
		"space separated":      {`role: warehouse manager`, true},
		"one role":             {`role: warehouse`, false},
		"one role, padded":     {`role: " warehouse "`, false},
		"admin":                {`role: admin`, false},
		"no role":              {`auth: required`, false},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeTestFile(t, dir, "app.yaml", "site_name: roles\n")
			writeTestFile(t, dir, "schema.prisma", roleGateSchema)
			flow := roleGateFlow(tc.roleLine)
			if msg := ValidateOnWriteIn(dir, "flows/receive-stock.yaml", flow); msg != "" {
				t.Fatalf("the write gate refuses a flow shape deployed apps carry: %s", msg)
			}
			writeTestFile(t, dir, "flows/receive-stock.yaml", flow)
			for where, report := range map[string]CheckReport{
				"the post-write check of the flow file": RunSourceCheck(dir, "flows/receive-stock.yaml"),
				"benmore check":                         RunSourceCheck(dir, ""),
			} {
				got := roleGateWarnings(t, report, "flows/receive-stock.yaml")
				if !tc.warned {
					if len(got) != 0 {
						t.Errorf("%s warns about a single role: %q", where, got)
					}
					continue
				}
				if len(got) != 1 {
					t.Fatalf("%s: %d role warnings, want 1: %q", where, len(got), got)
				}
				for _, want := range []string{"flows/receive-stock.yaml: ", "exactly one role", "everyone but a global admin", "`auth: required`", "status: 403"} {
					if !strings.Contains(got[0], want) {
						t.Errorf("%s: the warning lacks %q: %s", where, want, got[0])
					}
				}
				if report.Errors != 0 {
					t.Errorf("%s reports %d error(s): %+v", where, report.Errors, report.Findings)
				}
			}
			if got := roleGateWarnings(t, RunSourceCheck(dir, "schema.prisma"), "flows/receive-stock.yaml"); len(got) != 0 {
				t.Errorf("a write of another file repeats the warning: %q", got)
			}
		})
	}
}

// A YAML list (or map) under `role:` was refused with the YAML decoder's own
// words and the address of a key that never mentions `role`. It is refused
// with what the gate takes and the key that says so.
func TestFlowRoleYAMLListIsRefusedInWords(t *testing.T) {
	for name, roleLine := range map[string]string{
		"flow list":  `role: [warehouse, manager]`,
		"block list": "role:\n      - warehouse\n      - manager",
		"map":        `role: { any: [warehouse, manager] }`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeTestFile(t, dir, "app.yaml", "site_name: roles\n")
			writeTestFile(t, dir, "schema.prisma", roleGateSchema)
			msg := ValidateOnWriteIn(dir, "flows/receive-stock.yaml", roleGateFlow(roleLine))
			if msg == "" {
				t.Fatal("a role list is accepted: the flow parser cannot read it")
			}
			if strings.Contains(msg, "unmarshal") || strings.Contains(msg, "!!") {
				t.Errorf("the refusal quotes the YAML decoder: %s", msg)
			}
			for _, want := range []string{"on.request.role", "exactly one role", "`auth: required`", `docs: api(at:"flows.role_gate")`} {
				if !strings.Contains(msg, want) {
					t.Errorf("the refusal lacks %q: %s", want, msg)
				}
			}
		})
	}
}

// With roles: declared, a gate naming a role no part of the app names is held
// by nobody (a typo): warned about. Names the app does name, and the built-in
// admin and user, are not.
func TestFlowRoleNotDeclaredIsWarnedAbout(t *testing.T) {
	const roles = "roles:\n  warehouse: [notes:read, notes:write]\n  manager: [notes:read, notes:write]\n  user: [notes:read]\n"
	for name, tc := range map[string]struct {
		app, role string
		warned    bool
		note      string
	}{
		"typo with roles declared":      {"site_name: r\n" + roles, "wharehouse", true, ""},
		"declared role":                 {"site_name: r\n" + roles, "warehouse", false, ""},
		"built-in admin":                {"site_name: r\n" + roles, "admin", false, ""},
		"built-in user":                 {"site_name: r\n" + roles, "user", false, ""},
		"no roles block":                {"site_name: r\n", "wharehouse", false, ""},
		"named by an access rule":       {"site_name: r\n" + roles + "access:\n  notes:\n    update: role:auditor\n", "auditor", false, ""},
		"the founding tenant role":      {"site_name: r\n" + roles + "groups:\n  table: org_members\n  key: org_id\n  user_field: user_id\n  role_field: member_role\n  bootstrap:\n    org_table: organizations\n    founding_role: org_admin\n", "org_admin", false, ""},
		"a tenant role that is data":    {"site_name: r\n" + roles + "groups:\n  table: org_members\n  key: org_id\n  user_field: user_id\n  role_field: member_role\n", "finance", true, "org_members.member_role"},
		"letter case is not a declared": {"site_name: r\n" + roles, "Warehouse", true, ""},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeTestFile(t, dir, "app.yaml", tc.app)
			writeTestFile(t, dir, "schema.prisma", roleGateSchema)
			writeTestFile(t, dir, "flows/receive-stock.yaml", roleGateFlow("role: "+tc.role))
			for where, report := range map[string]CheckReport{
				"the post-write check of the flow file": RunSourceCheck(dir, "flows/receive-stock.yaml"),
				"the post-write check of app.yaml":      RunSourceCheck(dir, "app.yaml"),
				"benmore check":                         RunSourceCheck(dir, ""),
			} {
				got := roleGateWarnings(t, report, "flows/receive-stock.yaml")
				if !tc.warned {
					if len(got) != 0 {
						t.Errorf("%s warns about a role the app names: %q", where, got)
					}
					continue
				}
				if len(got) != 1 {
					t.Fatalf("%s: %d role warnings, want 1: %q", where, len(got), got)
				}
				for _, want := range []string{`"` + tc.role + `"`, "roles:", "matched exactly", "everyone but a global admin"} {
					if !strings.Contains(got[0], want) {
						t.Errorf("%s: the warning lacks %q: %s", where, want, got[0])
					}
				}
				if (tc.note != "") != strings.Contains(got[0], "ignore this warning") || !strings.Contains(got[0], tc.note) {
					t.Errorf("%s: tenant-role note (want %q): %s", where, tc.note, got[0])
				}
			}
		})
	}
}

// `role: admin` on a flow admits only a global admin. In an app whose tenant
// members can hold a role named admin, the builder is told that those members
// do not pass, and what to write when they should.
func TestFlowRoleAdminInATenantAdminAppIsWarnedAbout(t *testing.T) {
	groups := func(founding string) string {
		return "groups:\n  table: org_members\n  key: org_id\n  user_field: user_id\n  role_field: member_role\n  bootstrap:\n    org_table: organizations\n    founding_role: " + founding + "\n"
	}
	const tenantSchema = roleGateSchema + "model Organization {\n  id   Int    @id @default(autoincrement())\n  name String\n\n  @@map(\"organizations\")\n}\n"
	member := func(def string) string {
		return "model OrgMember {\n  id         Int    @id @default(autoincrement())\n  orgId      Int    @map(\"org_id\")\n  userId     Int    @map(\"user_id\")\n  memberRole String @default(\"" + def + "\") @map(\"member_role\")\n\n  @@map(\"org_members\")\n}\n"
	}
	for name, tc := range map[string]struct {
		app, schema, role string
		warned            bool
		because           string
	}{
		"founding role admin":             {"site_name: r\n" + groups("admin"), tenantSchema + member("member"), "admin", true, "groups.bootstrap.founding_role"},
		"founding role Admin, gate ADMIN": {"site_name: r\n" + groups("Admin"), tenantSchema + member("member"), "ADMIN", true, "groups.bootstrap.founding_role"},
		"membership default admin":        {"site_name: r\n" + groups("owner"), tenantSchema + member("admin"), "admin", true, "the default of org_members.member_role"},
		"roles: declares admin":           {"site_name: r\nroles:\n  admin: [notes:read, notes:write]\n  user: [notes:read]\n" + groups("owner"), tenantSchema + member("member"), "admin", true, "roles:"},
		"tenant role with its own name":   {"site_name: r\n" + groups("org_admin"), tenantSchema + member("member"), "admin", false, ""},
		"another gate":                    {"site_name: r\n" + groups("admin"), tenantSchema + member("member"), "finance", false, ""},
		"no tenant roles":                 {"site_name: r\nroles:\n  admin: [notes:read, notes:write]\n  user: [notes:read]\n", roleGateSchema, "admin", false, ""},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeTestFile(t, dir, "app.yaml", tc.app)
			writeTestFile(t, dir, "schema.prisma", tc.schema)
			writeTestFile(t, dir, "flows/receive-stock.yaml", roleGateFlow("role: "+tc.role))
			for where, report := range map[string]CheckReport{
				"the post-write check of the flow file": RunSourceCheck(dir, "flows/receive-stock.yaml"),
				"the post-write check of app.yaml":      RunSourceCheck(dir, "app.yaml"),
				"benmore check":                         RunSourceCheck(dir, ""),
			} {
				got := roleGateWarnings(t, report, "flows/receive-stock.yaml")
				if !tc.warned {
					if len(got) != 0 {
						t.Errorf("%s warns: %q", where, got)
					}
					continue
				}
				if len(got) != 1 {
					t.Fatalf("%s: %d role warnings, want 1: %q", where, len(got), got)
				}
				for _, want := range []string{tc.because, "only a global admin", "org_members", "member_role = 'admin'", "${{ user.group_id || 0 }}", "a name of its own"} {
					if !strings.Contains(got[0], want) {
						t.Errorf("%s: the warning lacks %q: %s", where, want, got[0])
					}
				}
			}
		})
	}
}

// The app logs the same lines when it loads a deployed flow file, which no
// write gate sees again.
func TestFlowRoleGateProblemsAreLoggedAtLoad(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "app.yaml", "site_name: r\nroles:\n  warehouse: [notes:read]\n  user: [notes:read]\ngroups:\n  table: org_members\n  key: org_id\n  user_field: user_id\n  role_field: member_role\n  bootstrap:\n    org_table: organizations\n    founding_role: admin\n")
	writeTestFile(t, dir, "schema.prisma", roleGateSchema)
	writeTestFile(t, dir, "flows/a-list.yaml", strings.Replace(roleGateFlow(`role: "warehouse,manager"`), "/api/receive-stock", "/api/a", 1))
	writeTestFile(t, dir, "flows/b-typo.yaml", strings.Replace(roleGateFlow(`role: wharehouse`), "/api/receive-stock", "/api/b", 1))
	writeTestFile(t, dir, "flows/c-admin.yaml", strings.Replace(roleGateFlow(`role: admin`), "/api/receive-stock", "/api/c", 1))
	writeTestFile(t, dir, "flows/d-fine.yaml", strings.Replace(roleGateFlow(`role: warehouse`), "/api/receive-stock", "/api/d", 1))

	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	flows, err := loadFlowsChecked(dir, true)
	log.SetOutput(os.Stderr)
	if err != nil || len(flows) != 4 {
		t.Fatalf("loaded %d flows, err %v: a warned-about gate must not stop a deployed file from loading", len(flows), err)
	}
	logged := buf.String()
	for file, want := range map[string]string{
		"flows/a-list.yaml":  "exactly one role",
		"flows/b-typo.yaml":  "matched exactly",
		"flows/c-admin.yaml": "only a global admin",
	} {
		found := false
		for _, line := range strings.Split(logged, "\n") {
			if strings.Contains(line, "WARNING: "+file+": ") && strings.Contains(line, "on.request.role") && strings.Contains(line, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("the load log has no role-gate WARNING for %s (%q):\n%s", file, want, logged)
		}
	}
	if strings.Contains(logged, "flows/d-fine.yaml") {
		t.Errorf("the load log names a flow with a sound gate:\n%s", logged)
	}
}

// The two fixture apps behind api(at:"flows.role_gate"), as the write gate
// and their own tests judge them.
//
// flow-role-gate-forms: what a comma list does at run time, and the forms the
// key gives for several roles (an `if:` on the account's role, a SQL step
// that counts grants, a synchronous gate in front of queued work).
//
// flow-role-admin-gate: a tenant app whose founder holds the tenant role
// admin. Its `role: admin` worker flow is warned about (tenant admins do not
// pass), and its flows that read the membership row are the forms the warning
// and the key give, one role and several.
func TestFlowRoleGateFixtures(t *testing.T) {
	for name, tc := range map[string]struct {
		file, warning, shows string
		tests                int
	}{
		"flow-role-gate-forms": {"flows/receive-stock.yaml", "exactly one role", "user.role != 'warehouse' && user.role != 'manager' && user.role != 'admin'", 13},
		"flow-role-admin-gate": {"flows/log-activity.yaml", "only a global admin", "SELECT id FROM org_members WHERE org_id = :org AND user_id = :user_id AND member_role = 'admin'", 7},
	} {
		t.Run(name, func(t *testing.T) {
			dir := configGapFixtureDir(t, name)
			warned := 0
			for _, f := range RunSourceCheck(dir, "").Findings {
				switch {
				case f.Severity == "warning" && f.Source == "flows":
					warned++
					if f.File != tc.file || !strings.Contains(f.Message, tc.warning) || !strings.Contains(f.Message, tc.shows) {
						t.Errorf("unexpected flows warning on %s: %s", f.File, f.Message)
					}
				case f.Severity == "warning" && f.Source == "security" && f.File == "app.yaml" && name == "flow-role-admin-gate":
					// The tenant role named admin itself, which the fixture is about.
				case f.Severity == "error" || f.Severity == "warning":
					t.Errorf("%s (%s, %s): %s", f.File, f.Severity, f.Source, f.Message)
				}
			}
			if warned != 1 {
				t.Errorf("%d role-gate warnings, want 1 on %s", warned, tc.file)
			}
			app, err := loadApp(dir)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(app.Shutdown)
			ran := 0
			for _, r := range RunAppTests(app) {
				if r.File == "SUMMARY" {
					continue
				}
				ran++
				if !r.Pass {
					t.Errorf("%s/%s: %s %+v", r.File, r.Test, r.Message, r.Steps)
				}
			}
			if ran < tc.tests {
				t.Fatalf("the fixture ran %d tests, want at least %d", ran, tc.tests)
			}
			t.Logf("%s: %d tests pass", name, ran)
		})
	}
}
