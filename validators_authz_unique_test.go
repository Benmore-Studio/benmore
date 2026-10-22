//go:build !cli

package main

import (
	"database/sql"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// A unique constraint that leaves out the tenant key is enforced across every
// tenant, so a create that collides with ANOTHER tenant's row is refused -
// which tells the caller the value exists somewhere. The schema is the
// author's; `benmore check` and the post-write check warn about it.
func TestGlobalUniqueOnTenantTableWarns(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("app.yaml", "groups:\n  table: members\n  key: org_id\n  user_field: email\n")
	write("schema.prisma", `model Customer {
  id     Int    @id @default(autoincrement())
  orgId  String
  email  String @unique
  code   String
  ref    String

  @@unique([code, ref])
}

model Project {
  id     Int    @id @default(autoincrement())
  orgId  String
  slug   String

  @@unique([orgId, slug])
}

model Catalog {
  id   Int    @id @default(autoincrement())
  sku  String @unique
}
`)
	var msgs []string
	for _, f := range authzWarnings(dir) {
		if f.Severity != "warning" {
			t.Fatalf("a global unique constraint must be a warning, not %q", f.Severity)
		}
		msgs = append(msgs, f.Message)
	}
	all := strings.Join(msgs, "\n")
	for _, want := range []string{"customers", "(email)", "(code, ref)", "@@unique([orgId, "} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q in warnings:\n%s", want, all)
		}
	}
	for _, not := range []string{"projects", "catalogs"} {
		if strings.Contains(all, not) {
			t.Errorf("%s must not be flagged:\n%s", not, all)
		}
	}
	// The write gate does not refuse the schema.
	if report := RunSourceCheck(dir, "schema.prisma"); !report.Clean() {
		t.Fatalf("a global unique constraint must not block the write: %+v", report.Findings)
	}
}

// The runtime refusal says the same thing whether the row that already holds
// the value is in the caller's tenant or another one.
func TestUniqueConflictAnswerDoesNotDependOnTenant(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := EnsureUsersTable(db); err != nil {
		t.Fatal(err)
	}
	if err := EnsureUserRolesTable(db); err != nil {
		t.Fatal(err)
	}
	EnsureSessionsTable(db)
	for _, stmt := range []string{
		`CREATE TABLE members (id INTEGER PRIMARY KEY AUTOINCREMENT, org_id TEXT, email TEXT)`,
		`CREATE TABLE customers (id INTEGER PRIMARY KEY AUTOINCREMENT, org_id TEXT, email TEXT UNIQUE, name TEXT)`,
		`INSERT INTO members (org_id, email) VALUES ('tenant-a', 'a@example.com')`,
		`INSERT INTO customers (id, org_id, email, name) VALUES (1, 'tenant-a', 'mine@example.com', 'mine'), (2, 'tenant-b', 'theirs@example.com', 'theirs'), (3, 'tenant-a', 'other@example.com', 'other')`,
	} {
		crudScopeMustExec(t, db, stmt)
	}
	app := &App{Dir: dir, DB: db, SessionDuration: time.Hour, Stop: make(chan struct{}),
		Group: &GroupConfig{Table: "members", Key: "org_id", UserField: "email"}}
	for _, name := range []string{"members", "customers"} {
		cols, err := GetTableColumns(db, name)
		if err != nil {
			t.Fatal(err)
		}
		app.Tables = append(app.Tables, Table{Name: name, Columns: cols})
	}
	t.Cleanup(app.Shutdown)
	mux := buildAppMux(app, true, "http://localhost")
	sid := createCrudScopeSession(t, app, "a@example.com", "user", "tenant-a", "")

	// A server error's request id is a fresh random value per request
	// (server_error.go); it says nothing about the tenant, so it is masked
	// before the answers are compared.
	requestID := regexp.MustCompile(`"request_id":"[0-9a-f]{16}"`)
	answer := func(method, path string, body any) string {
		t.Helper()
		rec := crudScopeRequest(t, mux, method, path, sid, body)
		return strings.TrimSpace(strings.Join([]string{http.StatusText(rec.Code), requestID.ReplaceAllString(rec.Body.String(), `"request_id":"<id>"`)}, " "))
	}
	for name, probe := range map[string]func(email string) string{
		"create": func(email string) string {
			return answer(http.MethodPost, "/api/customers", map[string]any{"email": email, "name": "x"})
		},
		"batch": func(email string) string {
			return answer(http.MethodPost, "/api/customers/batch", []any{map[string]any{"email": email, "name": "x"}})
		},
		"transaction": func(email string) string {
			return answer(http.MethodPost, "/api/_transaction", map[string]any{"operations": []any{map[string]any{"table": "customers", "action": "insert", "data": map[string]any{"email": email, "name": "x"}}}})
		},
		"update": func(email string) string {
			return answer(http.MethodPatch, "/api/customers/3", map[string]any{"email": email})
		},
	} {
		own, foreign := probe("mine@example.com"), probe("theirs@example.com")
		if own != foreign {
			t.Errorf("%s: a unique conflict answers differently inside and outside the caller's tenant:\n own tenant:   %s\n other tenant: %s", name, own, foreign)
		}
		if strings.Contains(foreign, "customers.email") || strings.Contains(foreign, "UNIQUE constraint") {
			t.Errorf("%s: the refusal names the constraint: %s", name, foreign)
		}
	}
}
