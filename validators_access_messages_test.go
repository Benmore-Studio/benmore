//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// An access: rule on a table that a migrations/ file creates is in force: the
// runtime looks rules up by table name (AccessConfig.ModeFor) and serves
// auto-CRUD for every table in the database. The check used to warn that such
// a rule "applies to nothing" because the table is not a schema.prisma model.
func TestAccessRuleOnAMigrationTableIsInForceAndNotWarnedAbout(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "widgetsapp")
	writeTestFile(t, dir, "schema.prisma", "model Note {\n  id Int @id @default(autoincrement())\n  title String\n  userId Int @map(\"user_id\")\n}\n")
	writeTestFile(t, dir, "migrations/001_widgets.sql", "CREATE TABLE IF NOT EXISTS widgets (\n  id INTEGER PRIMARY KEY AUTOINCREMENT,\n  name TEXT NOT NULL DEFAULT ''\n);\nINSERT INTO widgets (name) VALUES ('from-migration');\n")
	// widgets: created by the migration. gadgets: created by nothing.
	writeTestFile(t, dir, "app.yaml", "site_name: Widgets\nauth: {identifier: email}\naccess:\n  widgets:\n    read: anon\n  gadgets:\n    read: anon\n")

	// What the runtime does with the rule.
	app, err := loadAppForServerTests(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Shutdown()
	mux := buildAppMux(app, false, "https://widgets.example.com")
	anon := func(path string) (int, string) {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "https://widgets.example.com"+path, nil))
		return w.Code, w.Body.String()
	}
	if code, body := anon("/api/widgets"); code != http.StatusOK || !strings.Contains(body, "from-migration") {
		t.Fatalf("anonymous GET /api/widgets = %d %.200s; this test assumes `read: anon` on a migration-created table is honored", code, body)
	}
	if code, _ := anon("/api/notes"); code != http.StatusUnauthorized {
		t.Fatalf("anonymous GET /api/notes = %d, want 401 (no rule: the owner default)", code)
	}

	// What the check says: `benmore check` and the write gate share it.
	for name, messages := range map[string][]string{
		"cross-file warnings": CrossFileWarnings(dir, ""),
		"source check":        checkMessagesFrom(RunSourceCheck(dir, ""), "cross_file"),
		"app.yaml write":      checkMessagesFrom(RunSourceCheck(dir, "app.yaml"), "cross_file"),
	} {
		joined := strings.Join(messages, "\n")
		if strings.Contains(joined, "access.widgets") {
			t.Errorf("%s: warns about a rule the runtime applies:\n%s", name, joined)
		}
		if strings.Contains(joined, "applies to nothing") {
			t.Errorf("%s: still says a rule applies to nothing:\n%s", name, joined)
		}
		for _, want := range []string{"access.gadgets names a table", "migrations/", "known tables: notes"} {
			if !strings.Contains(joined, want) {
				t.Errorf("%s: the warning for a table nothing creates lacks %q:\n%s", name, want, joined)
			}
		}
	}
}

func checkMessagesFrom(report CheckReport, source string) []string {
	var out []string
	for _, f := range report.Findings {
		if f.Source == source {
			out = append(out, f.Message)
		}
	}
	return out
}

// The messages that list the access modes name every mode the runtime
// honors. `owner_or_role:` was accepted by the validator and by the runtime
// (AccessConfig.Allowed, rowScopeClause) but missing from both lists.
func TestAccessModeMessagesListEveryModeTheRuntimeHonors(t *testing.T) {
	access := &AccessConfig{rolesDeclared: true}
	member := &Session{UserID: 7, Role: "user", Roles: []string{"user"}}
	if !access.Allowed("owner_or_role:manager", member, 0) {
		t.Fatal("the runtime no longer honors owner_or_role:; this test assumes it does")
	}
	if msg := validateAccessMode("notes", "read", "owner_or_role:manager"); msg != "" {
		t.Fatalf("the validator refuses owner_or_role:manager: %s", msg)
	}
	// Every exact mode and every prefix form validateAccessMode accepts.
	modes := []string{"role:", "owner_or_role:", "perm:", "member-of:"}
	for mode := range knownAccessModes {
		modes = append(modes, mode)
	}
	for _, bad := range []string{"", "everybody"} {
		msg := validateAccessMode("notes", "read", bad)
		if msg == "" {
			t.Fatalf("mode %q is accepted", bad)
		}
		for _, mode := range modes {
			if !strings.Contains(msg, mode) {
				t.Errorf("the message for mode %q does not list %q:\n%s", bad, mode, msg)
			}
		}
	}

	// Both entry points carry the corrected list: the write gate and check.
	dir := t.TempDir()
	writeTestFile(t, dir, "schema.prisma", "model Note {\n  id Int @id @default(autoincrement())\n  title String\n  userId Int @map(\"user_id\")\n}\n")
	conf := "site_name: Modes\naccess:\n  notes:\n    read: everybody\n"
	writeTestFile(t, dir, "app.yaml", conf)
	if refusal := ValidateOnWriteIn(dir, "app.yaml", conf); !strings.Contains(refusal, "owner_or_role:") {
		t.Errorf("the write gate's refusal does not list owner_or_role:\n%s", refusal)
	}
	checked := strings.Join(checkMessagesFrom(RunSourceCheck(dir, ""), "syntax"), "\n")
	if !strings.Contains(checked, "not a known access mode") || !strings.Contains(checked, "owner_or_role:") {
		t.Errorf("benmore check's finding does not list owner_or_role:\n%s", checked)
	}
}
