//go:build !cli

package main

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"
)

// auth.session_duration values that are not an accepted form, with the
// lifetime the runtime has always given sessions for them (which a load must
// keep) and how a message prints it.
var unreadableSessionDurations = []struct {
	yaml    string // as written after `session_duration: `
	value   string // as the runtime sees it
	applied time.Duration
	text    string
}{
	{`"1w"`, "1w", 30 * 24 * time.Hour, "30 days"},
	{`"12"`, "12", 30 * 24 * time.Hour, "30 days"},
	{`12`, "12", 30 * 24 * time.Hour, "30 days"},
	{`"0"`, "0", 30 * 24 * time.Hour, "30 days"},
	{`0`, "0", 30 * 24 * time.Hour, "30 days"},
	{`"8 hours"`, "8 hours", 30 * 24 * time.Hour, "30 days"},
	{`"1.5d"`, "1.5d", 30 * 24 * time.Hour, "30 days"},
	{`"-1h"`, "-1h", 30 * 24 * time.Hour, "30 days"},
	{`"0d"`, "0d", 30 * 24 * time.Hour, "30 days"},
	{`"24h "`, "24h ", 30 * 24 * time.Hour, "30 days"},
	// Below minSessionDuration: a typo every session would expire on. A
	// running app keeps what it had (the reader's 1s); a write refuses it.
	{`"1s"`, "1s", time.Second, "1s"},
	// The reader takes this loose spelling as 7 days; a load keeps doing so.
	{`"7days"`, "7days", 7 * 24 * time.Hour, "7 days"},
}

var acceptedSessionDurations = map[string]time.Duration{
	`"30d"`:   30 * 24 * time.Hour,
	`"7d"`:    7 * 24 * time.Hour,
	`"1d"`:    24 * time.Hour,
	`"12h"`:   12 * time.Hour,
	`"90m"`:   90 * time.Minute,
	`"1h30m"`: 90 * time.Minute,
	`"5m"`:    5 * time.Minute,
}

const configValuesNoteSchema = "model Note {\n  id Int @id @default(autoincrement())\n  title String\n}\n"

func sessionDurationApp(t *testing.T, authLines string) (dir, appYAML string) {
	t.Helper()
	dir = t.TempDir()
	appYAML = "site_name: session duration\nauth:\n  identifier: email\n" + authLines
	writeTestFile(t, dir, "app.yaml", appYAML)
	writeTestFile(t, dir, "schema.prisma", configValuesNoteSchema)
	return dir, appYAML
}

func checkErrorsFor(report CheckReport, file string) []string {
	var messages []string
	for _, f := range report.Findings {
		if f.Severity == "error" && f.File == file {
			messages = append(messages, f.Message)
		}
	}
	return messages
}

// loadAndRegister loads the app and registers its routes as a start does, and
// returns what the load logged.
func loadAndRegister(t *testing.T, dir string) (*App, string) {
	t.Helper()
	var logs bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(previous)
	app, err := loadApp(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	t.Cleanup(app.Shutdown)
	buildAppMux(app, false, "https://fixture.example.com")
	return app, logs.String()
}

// A session_duration that is not an accepted form is refused when app.yaml is
// written and is an error in `benmore check`, with the accepted forms. Both
// used to accept it, and sessions then lasted 30 days whatever it said.
func TestSessionDurationNotAnAcceptedFormIsRefusedByWriteGateAndCheck(t *testing.T) {
	for _, tc := range unreadableSessionDurations {
		t.Run(tc.yaml, func(t *testing.T) {
			dir, appYAML := sessionDurationApp(t, "  session_duration: "+tc.yaml+"\n")
			wants := []string{"auth.session_duration", fmt.Sprintf("%q", tc.value), tc.text, `"12h"`, `"7d"`}

			gate := validateOnWriteIn(dir, "app.yaml", appYAML, true)
			for _, want := range wants {
				if !strings.Contains(gate, want) {
					t.Fatalf("write gate refusal does not mention %s: %q", want, gate)
				}
			}
			errors := checkErrorsFor(runCheck(dir, "", false), "app.yaml")
			if len(errors) != 1 {
				t.Fatalf("benmore check: want one app.yaml error, got %q", errors)
			}
			for _, want := range wants {
				if !strings.Contains(errors[0], want) {
					t.Fatalf("benmore check error does not mention %s: %q", want, errors[0])
				}
			}
		})
	}
}

// Accepted forms, an absent key and an empty string pass both, and get the
// lifetime they name (30 days when nothing is named).
func TestSessionDurationAcceptedFormsPassAndApply(t *testing.T) {
	cases := map[string]time.Duration{"": 30 * 24 * time.Hour, "  session_duration: \"\"\n": 30 * 24 * time.Hour}
	for yaml, want := range acceptedSessionDurations {
		cases["  session_duration: "+yaml+"\n"] = want
	}
	for authLines, want := range cases {
		t.Run(strings.TrimSpace(authLines), func(t *testing.T) {
			dir, appYAML := sessionDurationApp(t, authLines)
			if gate := validateOnWriteIn(dir, "app.yaml", appYAML, true); gate != "" {
				t.Fatalf("write gate refused an accepted value: %s", gate)
			}
			if errors := checkErrorsFor(runCheck(dir, "", false), "app.yaml"); len(errors) != 0 {
				t.Fatalf("benmore check refused an accepted value: %q", errors)
			}
			app, logs := loadAndRegister(t, dir)
			if app.SessionDuration != want {
				t.Fatalf("applied %v, want %v", app.SessionDuration, want)
			}
			if strings.Contains(logs, "session_duration") {
				t.Fatalf("the load logged about an accepted value: %s", logs)
			}
		})
	}
}

// An app that already carries such a value keeps loading and keeps the
// lifetime it has had; the load says so. It used to say nothing, and for "0"
// or a negative value the app's own duration was 0 or negative (the cookie
// restored after ending a support session then had no lifetime).
func TestSessionDurationNotAnAcceptedFormLoadsWithAWarningAndTheLifetimeItHad(t *testing.T) {
	for _, tc := range unreadableSessionDurations {
		t.Run(tc.yaml, func(t *testing.T) {
			dir, _ := sessionDurationApp(t, "  session_duration: "+tc.yaml+"\n")
			app, logs := loadAndRegister(t, dir)

			var warning string
			for _, line := range strings.Split(logs, "\n") {
				if strings.Contains(line, "auth.session_duration") {
					warning = line
				}
			}
			for _, want := range []string{"WARNING", "app.yaml", fmt.Sprintf("%q", tc.value), tc.text} {
				if !strings.Contains(warning, want) {
					t.Fatalf("load warning does not mention %s: %q", want, warning)
				}
			}
			if app.SessionDuration != tc.applied {
				t.Fatalf("the app's session duration is %v, want %v", app.SessionDuration, tc.applied)
			}
			token := CreateSession(app.DB, 1, "member@example.com", "", app.SessionDuration)
			var seconds float64
			if err := app.DB.QueryRow("SELECT (julianday(expires_at) - julianday(created_at)) * 86400 FROM _benmore_sessions WHERE id = ?", sessionStorageKey(token)).Scan(&seconds); err != nil {
				t.Fatal(err)
			}
			if lasted := time.Duration(seconds * float64(time.Second)); lasted < tc.applied-time.Minute || lasted > tc.applied+time.Minute {
				t.Fatalf("a session lasts %v, want %v", lasted, tc.applied)
			}
			if maxAge := sessionCookie(token, false, app.SessionDuration).MaxAge; maxAge != int(tc.applied.Seconds()) {
				t.Fatalf("session cookie Max-Age %d, want %d", maxAge, int(tc.applied.Seconds()))
			}
		})
	}
}

// The fixture app (CI runs it through scripts/check-fixture-apps.py): the
// source check refuses its app.yaml and nothing else fails, and its own test
// proves the deployed app still runs with 30-day sessions.
func TestSessionDurationFixtureIsRefusedAtWriteAndStillRuns(t *testing.T) {
	fixture := filepath.Join("testdata", "session-duration-refused")
	listed, err := os.ReadFile(filepath.Join(fixture, "tests", "expected-failures.txt"))
	if err != nil {
		t.Fatal(err)
	}
	expected := map[string]bool{}
	for _, line := range strings.Split(string(listed), "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			expected[line] = true
		}
	}
	results, runErr := runServerTestsOnCopy(fixture, "app")
	if runErr != nil {
		t.Fatalf("the fixture must still load and run: %v", runErr)
	}
	failed := map[string]bool{}
	passed := 0
	for _, r := range results {
		switch {
		case r.File == "SUMMARY" || r.Skipped:
		case r.Pass:
			passed++
		case !expected[r.File]:
			t.Fatalf("unexpected failure %s / %s: %s %+v", r.File, r.Test, r.Message, r.Steps)
		case !strings.Contains(r.Message, "auth.session_duration"):
			t.Fatalf("%s failed for another reason: %s", r.File, r.Message)
		default:
			failed[r.File] = true
		}
	}
	for file := range expected {
		if !failed[file] {
			t.Fatalf("expected %s to fail its source check, results: %+v", file, results)
		}
	}
	if passed == 0 {
		t.Fatalf("no fixture test ran and passed: %+v", results)
	}
}

func prismaSchemaWithTable(table string) string {
	return configValuesNoteSchema + "\nmodel Thing {\n  id Int @id @default(autoincrement())\n  title String\n  @@map(\"" + table + "\")\n}\n"
}

// registerRoutes registers the loaded app's routes as a start of the app does
// and returns the panic that stopped it, if any.
func registerRoutes(app *App) (mux *http.ServeMux, panicked string) {
	defer func() {
		if recovered := recover(); recovered != nil {
			mux, panicked = nil, fmt.Sprint(recovered)
		}
	}()
	previous := log.Writer()
	log.SetOutput(&bytes.Buffer{})
	defer log.SetOutput(previous)
	return buildAppMux(app, false, "https://fixture.example.com"), ""
}

// A table named like a framework route cannot register its auto-CRUD routes,
// so the app does not load. The write gate and `benmore check` used to accept
// the schema; they refuse it, naming the table, the route and `@@map`.
func TestTableNamedLikeAFrameworkRouteIsRefusedByWriteGateAndCheck(t *testing.T) {
	for _, table := range []string{"_upload", "_schema", "_query", "_jobs", "_notifications", "_auth", "_transaction", "_broadcast"} {
		t.Run(table, func(t *testing.T) {
			dir := t.TempDir()
			schema := prismaSchemaWithTable(table)
			writeTestFile(t, dir, "app.yaml", "site_name: route clash\n")
			writeTestFile(t, dir, "schema.prisma", schema)

			// The premise: this app cannot register its routes.
			app, err := loadApp(dir)
			if err != nil {
				t.Fatal(err)
			}
			_, panicked := registerRoutes(app)
			app.Shutdown()
			if !strings.Contains(panicked, "/api/"+table) || !strings.Contains(panicked, "conflicts with pattern") {
				t.Fatalf("expected the table's route to collide at registration, got %q", panicked)
			}

			wants := []string{"schema.prisma", "model Thing", `"` + table + `"`, "/api/" + table, "@@map(", "would not load"}
			gate := validateOnWriteIn(dir, "schema.prisma", schema, true)
			for _, want := range wants {
				if !strings.Contains(gate, want) {
					t.Fatalf("write gate refusal does not mention %s: %q", want, gate)
				}
			}
			errors := checkErrorsFor(runCheck(dir, "", false), "schema.prisma")
			if len(errors) != 1 {
				t.Fatalf("benmore check: want one schema.prisma error, got %q", errors)
			}
			for _, want := range wants {
				if !strings.Contains(errors[0], want) {
					t.Fatalf("benmore check error does not mention %s: %q", want, errors[0])
				}
			}
		})
	}
}

// The suggested name is one the app can register, and writing it passes.
func TestTableRouteRefusalSuggestsANameThatRegisters(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "app.yaml", "site_name: route clash\n")
	writeTestFile(t, dir, "schema.prisma", configValuesNoteSchema)
	gate := validateOnWriteIn(dir, "schema.prisma", prismaSchemaWithTable("_upload"), true)
	if !strings.Contains(gate, `@@map("upload")`) {
		t.Fatalf("refusal does not suggest @@map(\"upload\"): %q", gate)
	}
	fixed := prismaSchemaWithTable("upload")
	if gate := validateOnWriteIn(dir, "schema.prisma", fixed, true); gate != "" {
		t.Fatalf("the suggested name is refused: %s", gate)
	}
	// A taken name is not suggested.
	taken := prismaSchemaWithTable("_upload") + "\nmodel Upload {\n  id Int @id @default(autoincrement())\n  @@map(\"upload\")\n}\n"
	if gate := validateOnWriteIn(dir, "schema.prisma", taken, true); !strings.Contains(gate, `@@map("app_upload")`) {
		t.Fatalf("refusal must suggest a free name when \"upload\" is taken: %q", gate)
	}
}

// schema.sql is checked when it is the schema the app loads, without the
// Prisma advice.
func TestSchemaSQLTableNamedLikeAFrameworkRouteIsRefused(t *testing.T) {
	const sqlSchema = "CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT);\nCREATE TABLE _upload (id INTEGER PRIMARY KEY, title TEXT);\n"
	dir := t.TempDir()
	writeTestFile(t, dir, "app.yaml", "site_name: route clash\n")
	writeTestFile(t, dir, "schema.sql", sqlSchema)
	gate := validateOnWriteIn(dir, "schema.sql", sqlSchema, true)
	for _, want := range []string{"schema.sql", `table "_upload"`, "POST /api/_upload", `for example "upload"`} {
		if !strings.Contains(gate, want) {
			t.Fatalf("write gate refusal does not mention %s: %q", want, gate)
		}
	}
	if strings.Contains(gate, "@@map") {
		t.Fatalf("a schema.sql refusal gives Prisma advice: %q", gate)
	}
	if errors := checkErrorsFor(runCheck(dir, "", false), "schema.sql"); len(errors) != 1 || !strings.Contains(errors[0], "/api/_upload") {
		t.Fatalf("benmore check: want one schema.sql error naming the route, got %q", errors)
	}
	// With a schema.prisma the app loads that one; schema.sql is not its tables.
	writeTestFile(t, dir, "schema.prisma", configValuesNoteSchema)
	if gate := validateOnWriteIn(dir, "schema.sql", sqlSchema, true); gate != "" {
		t.Fatalf("schema.sql refused although schema.prisma is the loaded schema: %s", gate)
	}
}

// Names that register are not refused: a leading underscore alone is served
// at /api/_<name> today, and tables that get no auto-CRUD routes never
// collide. Each such app loads, registers and serves the table.
func TestTableNamesThatRegisterAreNotRefused(t *testing.T) {
	for _, table := range []string{"_foo", "_private_notes", "uploads", "jobs", "notifications", "query", "auth", "_benmore_custom"} {
		t.Run(table, func(t *testing.T) {
			dir := t.TempDir()
			schema := prismaSchemaWithTable(table)
			writeTestFile(t, dir, "app.yaml", "site_name: no clash\n")
			writeTestFile(t, dir, "schema.prisma", schema)
			if gate := validateOnWriteIn(dir, "schema.prisma", schema, true); strings.Contains(gate, "/api/"+table) {
				t.Fatalf("write gate refused a table that registers: %s", gate)
			}
			for _, message := range checkErrorsFor(runCheck(dir, "", false), "schema.prisma") {
				if strings.Contains(message, "/api/"+table) {
					t.Fatalf("benmore check refused a table that registers: %s", message)
				}
			}
			app, err := loadApp(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer app.Shutdown()
			mux, panicked := registerRoutes(app)
			if panicked != "" {
				t.Fatalf("the app does not register its routes: %s", panicked)
			}
			if table == "_benmore_custom" {
				return // a framework-prefixed name gets no auto-CRUD routes
			}
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://fixture.example.com/api/"+table, nil))
			if rec.Code == http.StatusNotFound {
				t.Fatalf("GET /api/%s answered 404: the table is not served", table)
			}
		})
	}
}

// The refusal follows the routes this app registers, not a fixed list:
// GET /api/_csrf exists only for an app with auth, so a table `_csrf` loads
// without auth and cannot load with it.
func TestTableRouteRefusalFollowsTheAppsOwnRoutes(t *testing.T) {
	schema := prismaSchemaWithTable("_csrf")
	for appYAML, refused := range map[string]bool{
		"site_name: no auth\n":                               false,
		"site_name: with auth\nauth:\n  identifier: email\n": true,
	} {
		dir := t.TempDir()
		writeTestFile(t, dir, "app.yaml", appYAML)
		writeTestFile(t, dir, "schema.prisma", schema)
		app, err := loadApp(dir)
		if err != nil {
			t.Fatal(err)
		}
		_, message := registerRoutes(app)
		panicked := message != ""
		app.Shutdown()
		if panicked != refused {
			t.Fatalf("%q: premise: registration panics = %v, want %v", appYAML, panicked, refused)
		}
		gate := validateOnWriteIn(dir, "schema.prisma", schema, true)
		if got := strings.Contains(gate, "/api/_csrf"); got != refused {
			t.Fatalf("%q: write gate refused = %v, want %v: %q", appYAML, got, refused, gate)
		}
		if got := len(checkErrorsFor(runCheck(dir, "", false), "schema.prisma")) > 0; got != refused {
			t.Fatalf("%q: benmore check refused = %v, want %v", appYAML, got, refused)
		}
		// The check that follows an app.yaml write re-reads the schema, so
		// switching auth on over such a table is reported with that write.
		if got := len(checkErrorsFor(runCheck(dir, "app.yaml", false), "schema.prisma")) > 0; got != refused {
			t.Fatalf("%q: the check after an app.yaml write refused = %v, want %v", appYAML, got, refused)
		}
	}
}

// A route that overlaps a framework route without being the same one is
// described as a collision, with both routes.
func TestTableRouteRefusalNamesBothRoutesOfAnOverlap(t *testing.T) {
	dir := t.TempDir()
	schema := prismaSchemaWithTable("_broadcast")
	writeTestFile(t, dir, "app.yaml", "site_name: route clash\n")
	writeTestFile(t, dir, "schema.prisma", schema)
	gate := validateOnWriteIn(dir, "schema.prisma", schema, true)
	for _, want := range []string{"collides with the framework route", "/api/_broadcast/{id}/", "/api/_broadcast/stats/{slug}"} {
		if !strings.Contains(gate, want) {
			t.Fatalf("write gate refusal does not mention %s: %q", want, gate)
		}
	}
}

// appRegistersRoutes loads the app at dir and registers its routes in one
// mode, as a start does.
func appRegistersRoutes(t *testing.T, dir string, dev bool) bool {
	t.Helper()
	previous := log.Writer()
	log.SetOutput(&bytes.Buffer{})
	defer log.SetOutput(previous)
	app, err := loadApp(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	defer app.Shutdown()
	registered := false
	func() {
		defer func() { registered = recover() == nil }()
		buildAppMux(app, dev, "https://fixture.example.com")
	}()
	return registered
}

// The reserved names are derived, not listed: for every path segment the
// framework registers under /api/ (for an app without and with auth), a table
// of that name is refused exactly when the real app cannot register its
// routes with it. A framework route added later is covered without a change
// here, and a name that still loads is never refused.
func TestTableRefusalMatchesRegistrationForEveryFrameworkAPIPath(t *testing.T) {
	var refusedNames []string
	for _, appYAML := range []string{"site_name: bare\n", "site_name: with auth\nauth:\n  identifier: email\n"} {
		base := t.TempDir()
		writeTestFile(t, base, "app.yaml", appYAML)
		writeTestFile(t, base, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT);\n")
		candidate, _, err := routeCandidateApp(base)
		if err != nil {
			t.Fatal(err)
		}
		segments := map[string]bool{}
		for _, dev := range []bool{false, true} {
			candidate.DevMode = dev
			mux := buildAppRouteMux(candidate, dev, "", false, nil)
			for _, pattern := range mux.patterns[:mux.authoredFrom] {
				_, path, _ := strings.Cut(pattern, " ")
				if rest, ok := strings.CutPrefix(path, "/api/"); ok {
					segment, _, _ := strings.Cut(rest, "/")
					if membershipIdentRe.MatchString(segment) && !crudInternalName.MatchString(sqliteIdentifierFold(segment)) {
						segments[segment] = true
					}
				}
			}
		}
		if len(segments) < 15 {
			t.Fatalf("found only %d framework /api/ segments: %v", len(segments), segments)
		}
		for segment := range segments {
			dir := t.TempDir()
			schema := "CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT);\nCREATE TABLE " + segment + " (id INTEGER PRIMARY KEY, title TEXT);\n"
			writeTestFile(t, dir, "app.yaml", appYAML)
			writeTestFile(t, dir, "schema.sql", schema)
			refused := strings.Contains(validateOnWriteIn(dir, "schema.sql", schema, true), "/api/"+segment)
			loads := appRegistersRoutes(t, dir, false) && appRegistersRoutes(t, dir, true)
			if refused == loads {
				t.Errorf("%q table %s: refused=%v but the app registers its routes=%v", appYAML, segment, refused, loads)
			}
			if refused {
				refusedNames = append(refusedNames, segment)
			}
		}
	}
	sort.Strings(refusedNames)
	refusedNames = slices.Compact(refusedNames)
	t.Logf("table names refused for these two apps: %s", strings.Join(refusedNames, ", "))
	for _, name := range []string{"_upload", "_schema", "_query", "_jobs", "_notifications"} {
		if !slices.Contains(refusedNames, name) {
			t.Errorf("%s is not refused", name)
		}
	}
}

// readSessionDuration accepts only forms the runtime's reader gives the same
// lifetime, so a value that passes the write gate is never applied differently.
func TestReadSessionDurationAgreesWithTheRuntimeReader(t *testing.T) {
	accepted := map[string]time.Duration{"30d": 720 * time.Hour, "7d": 168 * time.Hour, "1d": 24 * time.Hour, "365d": 8760 * time.Hour,
		"12h": 12 * time.Hour, "90m": 90 * time.Minute, "1h30m": 90 * time.Minute, "1.5h": 90 * time.Minute, "5m": 5 * time.Minute}
	for value, want := range accepted {
		got, ok := readSessionDuration(value)
		if !ok || got != want {
			t.Errorf("readSessionDuration(%q) = %v, %v; want %v", value, got, ok, want)
		}
		if runtime := ParseSessionDuration(value); runtime != want {
			t.Errorf("the runtime reads %q as %v, want %v", value, runtime, want)
		}
		if applied, problem := sessionDurationSetting(value); applied != want || problem != "" {
			t.Errorf("sessionDurationSetting(%q) = %v, %q", value, applied, problem)
		}
	}
	for _, value := range []string{"1w", "12", "0", "0s", "0d", "-1h", "-7d", "8 hours", "1.5d", "7days", "7d ", " 7d", "24h ", "07d", "+7d", "d", "1y", "1mo", "forever", "never", "[1 2]", "99999999999d", "45s", "1s", "1ns", "4m59s"} {
		if got, ok := readSessionDuration(value); ok {
			t.Errorf("readSessionDuration(%q) accepted it as %v", value, got)
		}
		applied, problem := sessionDurationSetting(value)
		if problem == "" || applied <= 0 {
			t.Errorf("sessionDurationSetting(%q) = %v, %q: want a problem and a positive lifetime", value, applied, problem)
		}
	}
	if applied, problem := sessionDurationSetting(""); applied != defaultSessionDuration || problem != "" {
		t.Errorf("an unset value: %v, %q", applied, problem)
	}
}
