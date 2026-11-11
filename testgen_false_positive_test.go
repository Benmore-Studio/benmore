//go:build !cli

package main

import (
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// These fixtures reproduce the generator false positives a fleet run of
// `benmore test --framework` found on live apps: each is a small app loaded
// the way the command loads one, with every generated test run against it.
// A fixture passes only when no generated test fails AND the assertions that
// prove the declared behavior are still there.

func loadGeneratedFixtureApp(t *testing.T, files map[string]string) *App {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	app, err := loadAppForServerTests(dir)
	if err != nil {
		t.Fatalf("load fixture app: %v", err)
	}
	t.Cleanup(app.Shutdown)
	return app
}

type generatedRun struct {
	files   map[string]AppTestFile
	results map[string]AppTestResult
}

func (g generatedRun) testCase(t *testing.T, file, name string) AppTestCase {
	t.Helper()
	tc, ok := g.files[file].Tests[name]
	if !ok {
		t.Fatalf("generated test %s/%s missing; have %v", file, name, g.names(file))
	}
	return tc
}

func (g generatedRun) has(file, name string) bool {
	_, ok := g.files[file].Tests[name]
	return ok
}

func (g generatedRun) names(file string) []string {
	var out []string
	for name := range g.files[file].Tests {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func (g generatedRun) result(t *testing.T, file, name string) AppTestResult {
	t.Helper()
	r, ok := g.results[file+"/"+name]
	if !ok {
		t.Fatalf("no result for %s/%s", file, name)
	}
	return r
}

// runGeneratedFixture generates the framework tests for app, runs them all the
// way `benmore test --framework` does, and fails on any failing test.
func runGeneratedFixture(t *testing.T, app *App) generatedRun {
	t.Helper()
	generated := GenerateFrameworkTests(app)
	run := generatedRun{files: map[string]AppTestFile{}, results: map[string]AppTestResult{}}
	for _, f := range generated {
		run.files[f.Name] = f
	}
	var failures []string
	for _, r := range RunAllTests(app, generated, false) {
		if r.File == "SUMMARY" {
			continue
		}
		run.results[r.File+"/"+r.Test] = r
		if !r.Pass {
			failures = append(failures, r.File+"/"+r.Test+": "+r.Message)
		}
	}
	sort.Strings(failures)
	if len(failures) > 0 {
		t.Errorf("generated framework tests failed on a correct app:\n  %s", strings.Join(failures, "\n  "))
	}
	return run
}

func expectStep(t *testing.T, label string, step AppTestStep, status int, contains string) {
	t.Helper()
	if step.Expect.Status != status || len(step.Expect.StatusIn) != 0 {
		t.Errorf("%s: expected exact status %d, got status=%d status_in=%v", label, status, step.Expect.Status, step.Expect.StatusIn)
	}
	if contains == "" {
		return
	}
	for _, c := range expectContains(step.Expect.Contains) {
		if strings.Contains(c, contains) {
			return
		}
	}
	t.Errorf("%s: expectation does not assert %q (contains=%v)", label, contains, step.Expect.Contains)
}

// Cause 1 + 2: tables an access rule closes, and tables the plain user's role
// scopes do not name. The generated tests must assert the declared refusal,
// never expect the route to work.
func TestGeneratedTestsFollowAccessOffAndRoleScopes(t *testing.T) {
	app := loadGeneratedFixtureApp(t, map[string]string{
		"app.yaml": `auth:
  identifier: email
roles:
  user:
    scopes: ["notes:read", "notes:write", "notes:delete", "ledgers:read", "lines:read", "lines:write", "submissions:write"]
  admin:
    scopes: "*"
access:
  notes: { all: self }
  lines: off
  ledgers: { read: self, write: off, update: off, delete: off }
  contacts: { all: self }
  submissions: { read: off, write: anon, update: off, delete: off }
`,
		"schema.prisma": `model Note {
  id        String    @id @default(uuid())
  userId    Int       @map("user_id")
  title     String
  deletedAt DateTime? @map("deleted_at")
  @@map("notes")
}
model Line {
  id     String @id @default(uuid())
  userId Int    @map("user_id")
  label  String
  @@map("lines")
}
model Ledger {
  id        String    @id @default(uuid())
  userId    Int       @map("user_id")
  memo      String
  deletedAt DateTime? @map("deleted_at")
  @@map("ledgers")
}
model Contact {
  id        Int       @id @default(autoincrement())
  userId    Int       @map("user_id")
  name      String
  deletedAt DateTime? @map("deleted_at")
  @@map("contacts")
}
model Submission {
  id    String @id @default(uuid())
  name  String
  email String
  @@map("submissions")
}
`,
	})
	run := runGeneratedFixture(t, app)

	// access: off answers like a route that does not exist.
	expectStep(t, "create_lines", run.testCase(t, "_framework_crud", "create_lines").Steps[0], http.StatusNotFound, "no API route matches")
	expectStep(t, "list_lines", run.testCase(t, "_framework_crud", "list_lines").Steps[0], http.StatusNotFound, "")
	expectStep(t, "create_ledgers", run.testCase(t, "_framework_crud", "create_ledgers").Steps[0], http.StatusNotFound, "no API route matches")
	expectStep(t, "list_ledgers", run.testCase(t, "_framework_crud", "list_ledgers").Steps[0], http.StatusOK, "")
	// A role whose scopes name no contacts permission is refused by the scope gate.
	for _, name := range []string{"list_contacts", "paginate_contacts", "cursor_contacts"} {
		expectStep(t, name, run.testCase(t, "_framework_crud", name).Steps[0], http.StatusForbidden, "scope denied")
	}
	expectStep(t, "create_contacts", run.testCase(t, "_framework_crud", "create_contacts").Steps[0], http.StatusForbidden, "scope denied")
	// Success journeys are not generated for tables the plain user cannot write.
	for _, name := range []string{"uuid_create_lines", "uuid_lifecycle_lines", "uuid_create_ledgers", "uuid_lifecycle_ledgers"} {
		if run.has("_framework_uuid", name) {
			t.Errorf("%s generated although writes are off", name)
		}
	}
	if run.has("_framework_lifecycle", "lifecycle_contacts") {
		t.Error("lifecycle_contacts generated although the role holds no contacts scope")
	}
	// The writable table keeps its strict success journeys and they pass.
	create := run.testCase(t, "_framework_uuid", "uuid_create_notes")
	expectStep(t, "uuid_create_notes", create.Steps[len(create.Steps)-2], http.StatusOK, `"id":"`)
	if !run.result(t, "_framework_uuid", "uuid_lifecycle_notes").Pass || !run.result(t, "_framework_lifecycle", "lifecycle_notes").Pass {
		t.Error("success journeys on the writable table must still run and pass")
	}
	batch := run.testCase(t, "_framework_batch", "batch_create_notes")
	expectStep(t, "batch_create_notes", batch.Steps[len(batch.Steps)-1], http.StatusOK, `"count":2`)
	// A contact form (write: anon, read/update/delete off): the journey creates
	// the row and then asserts each declared refusal.
	life := run.testCase(t, "_framework_uuid", "uuid_lifecycle_submissions")
	n := len(life.Steps)
	expectStep(t, "uuid_lifecycle_submissions create", life.Steps[n-3], http.StatusOK, "")
	expectStep(t, "uuid_lifecycle_submissions update", life.Steps[n-2], http.StatusNotFound, "no API route matches")
	expectStep(t, "uuid_lifecycle_submissions delete", life.Steps[n-1], http.StatusNotFound, "no API route matches")
	readBack := run.testCase(t, "_framework_uuid", "uuid_create_submissions")
	expectStep(t, "uuid_create_submissions read", readBack.Steps[len(readBack.Steps)-1], http.StatusNotFound, "no API route matches")
	var rows int
	if err := app.DB.QueryRow(`SELECT count(*) FROM submissions`).Scan(&rows); err != nil || rows < 2 {
		t.Fatalf("anon-writable table journeys did not write: rows=%d err=%v", rows, err)
	}
}

// Cause 3: generated values must not collide with unique constraints, within a
// batch, across tests on the same table, or on a one-row-per-user table.
func TestGeneratedTestsUseUniqueValues(t *testing.T) {
	app := loadGeneratedFixtureApp(t, map[string]string{
		"app.yaml": `auth:
  identifier: email
access:
  items: { all: self }
  prefs: { all: self }
  settings: { all: everyone }
`,
		"schema.prisma": `model Item {
  id        Int       @id @default(autoincrement())
  userId    Int       @map("user_id")
  sku       String    @unique
  email     String    @unique
  name      String
  deletedAt DateTime? @map("deleted_at")
  @@map("items")
}
model Pref {
  id     String @id @default(uuid())
  userId Int    @unique @map("user_id")
  theme  String
  @@map("prefs")
}
model Setting {
  id    String @id @default("settings")
  theme String
  @@map("settings")
}
`,
	})
	run := runGeneratedFixture(t, app)
	// A primary key with a constant default allows one row in all: the
	// journeys that would create more are skipped with the reason.
	for _, c := range []struct{ file, name string }{
		{"_framework_crud", "create_settings"},
		{"_framework_uuid", "uuid_create_settings"},
		{"_framework_uuid", "uuid_lifecycle_settings"},
	} {
		if tc := run.testCase(t, c.file, c.name); !strings.Contains(tc.Skip, "defaults to the constant") {
			t.Errorf("%s: want a skip naming the constant primary key, got %q", c.name, tc.Skip)
		}
	}
	if run.has("_framework_uuid", "uuid_batch_settings") {
		t.Error("uuid_batch_settings generated for a one-row table")
	}
	if a, b := run.testCase(t, "_framework_uuid", "uuid_create_prefs").AsUser, run.testCase(t, "_framework_uuid", "uuid_lifecycle_prefs").AsUser; a == b || a == frameworkTestUser {
		t.Errorf("one-row-per-account journeys must sign in as identities of their own: %q, %q", a, b)
	}
	for _, name := range []string{"batch_create_items"} {
		step := run.testCase(t, "_framework_batch", name).Steps[0]
		expectStep(t, name, step, http.StatusOK, `"count":2`)
	}
	expectStep(t, "audit_trail_logged", run.testCase(t, "_framework_audit", "audit_trail_logged").Steps[0], http.StatusOK, "")
	expectStep(t, "bearer_skips_csrf", run.testCase(t, "_framework_security", "bearer_skips_csrf").Steps[0], http.StatusOK, "")
	for _, name := range []string{"uuid_create_prefs", "uuid_lifecycle_prefs"} {
		if !run.result(t, "_framework_uuid", name).Pass {
			t.Errorf("%s did not pass", name)
		}
	}
	var items, distinct int
	if err := app.DB.QueryRow(`SELECT count(*), count(DISTINCT sku) FROM items`).Scan(&items, &distinct); err != nil || items < 5 || distinct != items {
		t.Fatalf("unique values were not distinct per row: rows=%d distinct=%d err=%v", items, distinct, err)
	}
}

// Cause 4: a required foreign key needs its parent row first. The generator
// creates the parent through the API (never guessing an existing id) when the
// plain user can, and visibly skips the journey when it cannot.
func TestGeneratedTestsCreateRequiredParentsFirst(t *testing.T) {
	app := loadGeneratedFixtureApp(t, map[string]string{
		"app.yaml": `auth:
  identifier: email
access:
  shelves: { all: self }
  books: { all: self }
  zones:
    read: member-of:zone_members(zone_id, user_id)
    write: self
    update: self
    delete: self
  zone_members: admin
  tasks:
    read: member-of:zone_members(zone_id, user_id)
    write: member-of:zone_members(zone_id, user_id)
    update: self
    delete: self
  vaults: { all: admin }
  coins: { all: self }
  seats: { all: self }
`,
		"schema.prisma": `model Shelf {
  id     Int    @id @default(autoincrement())
  userId Int    @map("user_id")
  label  String
  books  Book[]
  @@map("shelves")
}
model Book {
  id        Int       @id @default(autoincrement())
  userId    Int       @map("user_id")
  shelfId   Int       @map("shelf_id")
  shelf     Shelf     @relation(fields: [shelfId], references: [id])
  title     String
  status    String    @default("draft")
  deletedAt DateTime? @map("deleted_at")
  @@map("books")
}
model Zone {
  id      Int          @id @default(autoincrement())
  userId  Int          @map("user_id")
  name    String
  members ZoneMember[]
  tasks   Task[]
  @@map("zones")
}
model ZoneMember {
  id     Int  @id @default(autoincrement())
  zoneId Int  @map("zone_id")
  zone   Zone @relation(fields: [zoneId], references: [id])
  userId Int  @map("user_id")
  @@map("zone_members")
}
model Task {
  id        Int       @id @default(autoincrement())
  userId    Int       @map("user_id")
  zoneId    Int?      @map("zone_id")
  zone      Zone?     @relation(fields: [zoneId], references: [id])
  title     String
  deletedAt DateTime? @map("deleted_at")
  @@map("tasks")
}
model Vault {
  id    Int    @id @default(autoincrement())
  label String
  coins Coin[]
  @@map("vaults")
}
model Coin {
  id        Int       @id @default(autoincrement())
  userId    Int       @map("user_id")
  vaultId   Int       @map("vault_id")
  vault     Vault     @relation(fields: [vaultId], references: [id])
  title     String
  deletedAt DateTime? @map("deleted_at")
  @@map("coins")
}
model Seat {
  id        Int       @id @default(autoincrement())
  userId    Int       @map("user_id")
  role      String
  deletedAt DateTime? @map("deleted_at")
  @@map("seats")
}
`,
		"workflows.yaml": `book_flow:
  table: books
  field: status
  initial: draft
  transitions:
    draft:
      published: {}
`,
	})
	run := runGeneratedFixture(t, app)
	create := run.testCase(t, "_framework_crud", "create_books")
	if len(create.Steps) != 2 || !strings.HasPrefix(create.Steps[0].API, "POST /api/shelves") {
		t.Fatalf("create_books does not create its shelf first: %+v", create.Steps)
	}
	ref, _ := create.Steps[1].Data["shelf_id"].(string)
	if !strings.HasPrefix(ref, "{{") {
		t.Fatalf("shelf_id must reference the parent created by the test, got %#v", create.Steps[1].Data["shelf_id"])
	}
	expectStep(t, "create_books", create.Steps[1], http.StatusOK, "")
	for _, name := range []string{"lifecycle_books", "lifecycle_tasks"} {
		if !run.result(t, "_framework_lifecycle", name).Pass {
			t.Errorf("%s did not pass", name)
		}
	}
	for _, name := range []string{"wf_book_flow_valid_transition", "wf_book_flow_invalid_transition", "wf_book_flow_available_transitions"} {
		if name == "wf_book_flow_invalid_transition" && !run.has("_framework_workflows", name) {
			continue
		}
		if !run.result(t, "_framework_workflows", name).Pass {
			t.Errorf("%s did not pass", name)
		}
	}
	// Every book references a shelf the test user created, never a guessed id.
	var orphan int
	if err := app.DB.QueryRow(`SELECT count(*) FROM books b LEFT JOIN shelves s ON s.id = b.shelf_id AND s.user_id = b.user_id WHERE s.id IS NULL`).Scan(&orphan); err != nil || orphan != 0 {
		t.Fatalf("books reference shelves the test user did not create: %d err=%v", orphan, err)
	}
	var tasks int
	if err := app.DB.QueryRow(`SELECT count(*) FROM tasks t JOIN zone_members m ON m.zone_id = t.zone_id AND m.user_id = t.user_id`).Scan(&tasks); err != nil || tasks == 0 {
		t.Fatalf("membership-scoped task was not created in the test user's own zone: %d err=%v", tasks, err)
	}

	// A row that cannot be built is skipped with the reason, never run to fail
	// and never loosened to pass.
	for _, c := range []struct{ file, name, reason string }{
		{"_framework_crud", "create_coins", "coins.vault_id references vaults"},
		{"_framework_lifecycle", "lifecycle_coins", "coins.vault_id references vaults"},
		{"_framework_crud", "create_seats", "seats.role has no default"},
	} {
		tc := run.testCase(t, c.file, c.name)
		if !strings.Contains(tc.Skip, c.reason) || len(tc.Steps) != 0 {
			t.Errorf("%s: want a skipped case naming %q, got skip=%q steps=%d", c.name, c.reason, tc.Skip, len(tc.Steps))
		}
		r := run.result(t, c.file, c.name)
		if !r.Skipped || !r.Pass || !strings.HasPrefix(r.Message, "skipped: ") {
			t.Errorf("%s: result not reported as skipped: %+v", c.name, r)
		}
	}
	var coins int
	if err := app.DB.QueryRow(`SELECT count(*) FROM coins`).Scan(&coins); err != nil || coins != 0 {
		t.Fatalf("a skipped journey wrote rows: %d err=%v", coins, err)
	}
	results := make([]AppTestResult, 0, len(run.results))
	for _, r := range run.results {
		results = append(results, r)
	}
	total, passed := testResultCounts(results)
	if skipped := testResultSkipped(results); skipped < 3 || total+skipped != len(results) || passed != total {
		t.Fatalf("skipped cases must be counted apart from run ones: total=%d passed=%d skipped=%d of %d", total, passed, skipped, len(results))
	}
}

// Cause 5: social-only sign-in and email-domain rules refuse the password
// token exchange for the generated identity; that refusal is the declared
// behavior. A domain rule is honored with an identity inside the domain.
func TestGeneratedTokenTestFollowsSocialOnlyAndEmailRules(t *testing.T) {
	cases := []struct {
		name, auth string
		status     int
		contains   string
	}{
		{"oauth_only", "  oauth_only: true\n", http.StatusForbidden, "password auth is disabled"},
		{"domain", "  domain: example.org\n", http.StatusOK, `"token"`},
		{"allowlist", "  allow_emails: owner@example.org\n", http.StatusForbidden, "Access is restricted to approved accounts."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app := loadGeneratedFixtureApp(t, map[string]string{
				"app.yaml": "auth:\n  identifier: email\n" + tc.auth + "access:\n  notes: { all: self }\n",
				"schema.prisma": `model Note {
  id     Int    @id @default(autoincrement())
  userId Int    @map("user_id")
  title  String
  @@map("notes")
}
`,
			})
			run := runGeneratedFixture(t, app)
			expectStep(t, "token_endpoint", run.testCase(t, "_framework_auth", "token_endpoint").Steps[0], tc.status, tc.contains)
			if tc.name == "domain" {
				gate := run.testCase(t, "_framework_auth", "token_endpoint_email_gate")
				expectStep(t, "token_endpoint_email_gate", gate.Steps[0], http.StatusForbidden, "Only @example.org emails are allowed")
			}
		})
	}
}

// Cause 6: with the admin panel and the framework docs switched off, an HTML
// app's own page answers /_admin and /docs. That is the app's route, not the
// framework's, and the test must not expect a 404.
func TestGeneratedTestsTreatAppOwnedPageRoutesAsExpected(t *testing.T) {
	app := loadGeneratedFixtureApp(t, map[string]string{
		"app.yaml": `auth:
  identifier: email
features:
  admin: false
  docs: false
access:
  notes: { all: self }
`,
		"schema.prisma": `model Note {
  id     Int    @id @default(autoincrement())
  userId Int    @map("user_id")
  title  String
  @@map("notes")
}
`,
		"static/index.html": "<!doctype html><html><head><title>Shell</title></head><body><div id=\"app\">fixture shell</div></body></html>\n",
	})
	run := runGeneratedFixture(t, app)
	// The admin panel would redirect an anonymous visitor to sign in; the
	// app's page answering 200 proves the panel's route is gone.
	expectStep(t, "admin_requires_auth", run.testCase(t, "_framework_security", "admin_requires_auth").Steps[0], http.StatusOK, "")
	for name, marker := range map[string]string{"api_docs_html": "Copy for LLM", "api_docs_markdown": "## Platform features"} {
		step := run.testCase(t, "_framework_docs", name).Steps[0]
		expectStep(t, name, step, http.StatusOK, "")
		if got := expectContains(step.Expect.NotContains); len(got) != 1 || got[0] != marker {
			t.Errorf("%s must assert the framework docs are not served (not_contains %q), got %v", name, marker, got)
		}
	}
	// The JSON docs route has no page fallback and stays a 404.
	expectStep(t, "api_docs_json", run.testCase(t, "_framework_docs", "api_docs_json").Steps[0], http.StatusNotFound, "")

	// Without an app page there, the switched-off routes are the router's 404.
	bare := loadGeneratedFixtureApp(t, map[string]string{
		"app.yaml": "auth:\n  identifier: email\nfeatures:\n  admin: false\n  docs: false\naccess:\n  notes: { all: self }\n",
		"schema.prisma": `model Note {
  id     Int    @id @default(autoincrement())
  userId Int    @map("user_id")
  title  String
  @@map("notes")
}
`,
	})
	bareRun := runGeneratedFixture(t, bare)
	expectStep(t, "bare admin_requires_auth", bareRun.testCase(t, "_framework_security", "admin_requires_auth").Steps[0], http.StatusNotFound, "")
	expectStep(t, "bare api_docs_html", bareRun.testCase(t, "_framework_docs", "api_docs_html").Steps[0], http.StatusNotFound, "")
}

// An anonymous create is refused by whichever gate the table declares: auth,
// an access rule that removes the route, or the CSRF check of an anon table.
func TestGeneratedAnonymousCreateFollowsTheTablesGate(t *testing.T) {
	cases := []struct {
		name, access string
		status       int
		contains     string
	}{
		{"anon_write", "  forms: { read: anon, write: anon, update: off, delete: off }\n", http.StatusForbidden, "Invalid CSRF token"},
		{"write_off", "  forms: { read: everyone, write: off, update: off, delete: off }\n", http.StatusNotFound, "no API route matches"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app := loadGeneratedFixtureApp(t, map[string]string{
				"app.yaml": "access:\n" + tc.access,
				"schema.prisma": `model Form {
  id    Int    @id @default(autoincrement())
  title String
  @@map("forms")
}
`,
			})
			run := runGeneratedFixture(t, app)
			expectStep(t, "csrf_auth_rejection", run.testCase(t, "_framework_security", "csrf_auth_rejection").Steps[0], tc.status, tc.contains)
		})
	}
}
