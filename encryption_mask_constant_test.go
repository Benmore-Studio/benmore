//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// maskedValueFixture adds encrypted INTEGER, REAL and TEXT columns to the
// tenant encryption fixture's projects. Project 2 (globex) holds the values
// the field-mask report leaked: a 5-digit number, a multibyte string, an
// empty string and a NULL. A gotmpl page selects the same columns.
func maskedValueFixture(t *testing.T) (*App, *http.ServeMux) {
	t.Helper()
	app, mux := legacyQueryFixture(t, map[string]string{
		"masked.html": legacyQueryPage("", "SELECT id, budget, ratio, motto, empty_note, null_note, private_note FROM projects ORDER BY id"),
	})
	for _, col := range []string{"budget INTEGER", "ratio REAL", "motto TEXT", "empty_note TEXT", "null_note TEXT"} {
		crudScopeMustExec(t, app.DB, "ALTER TABLE projects ADD COLUMN "+col)
		app.Encrypted.Fields["projects"] = append(app.Encrypted.Fields["projects"],
			EncryptedFieldDef{Column: strings.Fields(col)[0], Roles: []string{"company_admin"}})
	}
	InstallEncryptionTriggers(app.DB, app.Encrypted)
	crudScopeMustExec(t, app.DB, "UPDATE projects SET budget = 50000, ratio = 98765.5, motto = 'ключ-日本', empty_note = '' WHERE id = 2")
	var stored string
	if err := app.DB.QueryRow("SELECT budget FROM projects WHERE id = 2").Scan(&stored); err != nil || !cryptoIsEncrypted(stored) {
		t.Fatalf("budget not encrypted at rest: %q %v", stored, err)
	}
	for i := range app.Tables {
		if app.Tables[i].Name == "projects" {
			cols, err := GetTableColumns(app.DB, "projects")
			if err != nil {
				t.Fatal(err)
			}
			app.Tables[i].Columns = cols
		}
	}
	return app, mux
}

// assertConstantMask checks one masked globex row: every non-NULL encrypted
// value is exactly the constant mask (a string even for the numeric columns),
// and the NULL stays a present null.
func assertConstantMask(t *testing.T, where string, row map[string]any) {
	t.Helper()
	for _, col := range []string{"budget", "ratio", "motto", "empty_note", "private_note"} {
		if got, ok := row[col]; !ok || got != encryptedFieldMask {
			t.Errorf("%s: %s = %#v, want %q", where, col, got, encryptedFieldMask)
		}
	}
	if got, ok := row["null_note"]; !ok || got != nil {
		t.Errorf("%s: null_note = %#v (present %t), want a present null", where, got, ok)
	}
}

// assertNoPlaintextTrace fails when a response carries any piece of the
// masked plaintext: the digits the old last-4 mask kept, the tail of the
// text, a fragment of the multibyte value or invalid UTF-8.
func assertNoPlaintextTrace(t *testing.T, where, body string) {
	t.Helper()
	for _, trace := range []string{"0000", "8765", "765.5", "日本", "ключ", "�", "*****", "globex-private-note"} {
		if strings.Contains(body, trace) {
			t.Errorf("%s leaked %q: %s", where, trace, body)
		}
	}
}

func TestMaskedEncryptedFieldsRevealNothingOnAutoCRUD(t *testing.T) {
	app, mux := maskedValueFixture(t)
	viewer, _ := tenantMember(t, app, "viewer@example.com", "user", 1, "viewer")

	w := crudScopeRequest(t, mux, http.MethodGet, "/api/projects/2", viewer, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("read: %d %s", w.Code, w.Body.String())
	}
	assertNoPlaintextTrace(t, "single read", w.Body.String())
	var row map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &row); err != nil {
		t.Fatal(err)
	}
	assertConstantMask(t, "single read", row)

	w = crudScopeRequest(t, mux, http.MethodGet, "/api/projects?id=2", viewer, nil)
	assertNoPlaintextTrace(t, "list", w.Body.String())
	var rows []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil || len(rows) != 1 {
		t.Fatalf("list: %d %s", w.Code, w.Body.String())
	}
	assertConstantMask(t, "list", rows[0])

	spec := map[string]any{"table": "projects", "select": []string{"company_id", "budget", "ratio", "motto", "empty_note", "null_note", "private_note"}, "where": map[string]any{"id": 2}}
	w = crudScopeRequest(t, mux, http.MethodPost, "/api/_query", viewer, spec)
	assertNoPlaintextTrace(t, "/api/_query", w.Body.String())
	var queried struct {
		Rows []map[string]any `json:"rows"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &queried); err != nil || len(queried.Rows) != 1 {
		t.Fatalf("/api/_query: %d %s", w.Code, w.Body.String())
	}
	assertConstantMask(t, "/api/_query", queried.Rows[0])

	// A viewer entitled to the field still reads the typed plaintext.
	admin := createCrudScopeSession(t, app, "root@example.com", "admin", "", "")
	w = crudScopeRequest(t, mux, http.MethodGet, "/api/projects/2", admin, nil)
	row = nil
	if err := json.Unmarshal(w.Body.Bytes(), &row); err != nil {
		t.Fatal(err)
	}
	if row["budget"] != float64(50000) || row["ratio"] != 98765.5 || row["motto"] != "ключ-日本" || row["empty_note"] != "" || row["null_note"] != nil {
		t.Fatalf("entitled read lost the plaintext or its type: %s", w.Body.String())
	}
}

func TestMaskedEncryptedFieldsRevealNothingOnGotmplPage(t *testing.T) {
	app, mux := maskedValueFixture(t)
	viewer, _ := tenantMember(t, app, "viewer@example.com", "user", 1, "viewer")

	rows := reportFixtureRows(t, ssrGet(mux, "/masked", viewer))
	rendered, _ := json.Marshal(rows)
	assertNoPlaintextTrace(t, "gotmpl page", string(rendered))
	if len(rows) != 2 || rows[1]["id"] != float64(2) {
		t.Fatalf("page rows: %v", rows)
	}
	assertConstantMask(t, "gotmpl page", rows[1])

	admin := createCrudScopeSession(t, app, "root@example.com", "admin", "", "")
	rows = reportFixtureRows(t, ssrGet(mux, "/masked", admin))
	if rows[1]["budget"] != float64(50000) || rows[1]["motto"] != "ключ-日本" || rows[1]["empty_note"] != "" {
		t.Fatalf("entitled page read lost the plaintext: %v", rows[1])
	}
}

// `owner` (and `self`) in unmask_roles always mean the row's owner, never a
// role. An app that also names a role "owner" - commonly the tenant founding
// role - gets a warning, because that role's holders never unmask the field.
func TestUnmaskOwnerAliasWarnsWhenARoleSharesTheName(t *testing.T) {
	const schema = `model Company {
  id   Int    @id @default(autoincrement())
  name String
}
model CompanyMember {
  id         Int    @id @default(autoincrement())
  companyId  Int
  userId     Int
  memberRole String @default("member")
}
model Project {
  id        Int    @id @default(autoincrement())
  companyId Int
  userId    Int
  budget    Int
}
`
	const groups = `groups:
  table: company_members
  key: company_id
  user_field: user_id
  role_field: member_role
  bootstrap:
    org_table: companies
    founding_role: %s
`
	cases := []struct {
		name      string
		appYAML   string
		encrypted string
		schema    string
		file      string // where the warning is filed; "" = no warning
		mentions  []string
	}{
		{
			name:      "founding role owner",
			appYAML:   strings.Replace(groups, "%s", "owner", 1),
			encrypted: "tables:\n  projects:\n    fields: [budget]\n    unmask_roles: [owner, admin]\n",
			file:      "encrypted.yaml",
			mentions:  []string{"projects", "owner", "self", "groups.bootstrap.founding_role"},
		},
		{
			name:      "global role owner",
			appYAML:   "roles:\n  owner:\n    scopes: \"*\"\n",
			encrypted: "tables:\n  projects:\n    fields: [budget]\n    unmask_roles: [owner]\n",
			file:      "encrypted.yaml",
			mentions:  []string{"roles:"},
		},
		{
			name:      "tenant role default owner",
			appYAML:   strings.Replace(groups, "%s", "org_admin", 1),
			encrypted: "tables:\n  projects:\n    fields: [budget]\n    unmask_roles: [owner]\n",
			schema:    strings.Replace(schema, `@default("member")`, `@default("owner")`, 1),
			file:      "encrypted.yaml",
			mentions:  []string{"company_members.member_role"},
		},
		{
			name:      "access gate names role owner",
			appYAML:   strings.Replace(groups, "%s", "org_admin", 1) + "access:\n  projects:\n    write: role:owner,org_admin\n",
			encrypted: "tables:\n  projects:\n    fields: [budget]\n    unmask_roles: [owner]\n",
			file:      "encrypted.yaml",
			mentions:  []string{"access.projects"},
		},
		{
			name:      "role named self",
			appYAML:   "roles:\n  self:\n    scopes: \"*\"\n",
			encrypted: "tables:\n  projects:\n    fields: [budget]\n    unmask_roles: [self]\n",
			file:      "encrypted.yaml",
			mentions:  []string{"self"},
		},
		{
			name:     "legacy app.yaml encrypted section",
			appYAML:  strings.Replace(groups, "%s", "owner", 1) + "encrypted:\n  projects:\n    - column: budget\n      roles: [owner]\n",
			file:     "app.yaml",
			mentions: []string{"encrypted.projects"},
		},
		{
			name:      "owner alias with no role named owner",
			appYAML:   strings.Replace(groups, "%s", "org_admin", 1),
			encrypted: "tables:\n  projects:\n    fields: [budget]\n    unmask_roles: [owner, org_admin]\n",
		},
		{
			name:      "role owner but unmask lists only self",
			appYAML:   strings.Replace(groups, "%s", "owner", 1),
			encrypted: "tables:\n  projects:\n    fields: [budget]\n    unmask_roles: [self, admin]\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			write := func(name, content string) {
				if content == "" {
					return
				}
				if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			s := tc.schema
			if s == "" {
				s = schema
			}
			write("schema.prisma", s)
			write("app.yaml", tc.appYAML)
			write("encrypted.yaml", tc.encrypted)

			var alias []CheckFinding
			for _, f := range unmaskOwnerAliasWarnings(dir) {
				alias = append(alias, f)
			}
			if tc.file == "" {
				if len(alias) != 0 {
					t.Fatalf("unexpected warning: %+v", alias)
				}
				return
			}
			if len(alias) != 1 || alias[0].Severity != "warning" || alias[0].File != tc.file {
				t.Fatalf("want one warning filed under %s, got %+v", tc.file, alias)
			}
			for _, want := range tc.mentions {
				if !strings.Contains(alias[0].Message, want) {
					t.Errorf("warning does not mention %q: %s", want, alias[0].Message)
				}
			}

			// The same warning reaches the write gate for the file that
			// declares the unmask roles and for app.yaml, and benmore check.
			for _, written := range []string{tc.file, "app.yaml", ""} {
				found := false
				for _, f := range RunSourceCheck(dir, written).Findings {
					if f.Severity == "warning" && f.Message == alias[0].Message {
						found = true
					}
				}
				if !found {
					t.Errorf("check after writing %q did not report the alias warning", written)
				}
			}
		})
	}
}
