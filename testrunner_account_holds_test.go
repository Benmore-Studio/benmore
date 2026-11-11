//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// accountHoldTestApp loads a throwaway app for a `benmore test` run.
func accountHoldTestApp(t *testing.T, appYAML string) *App {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, dir, "schema.prisma", `model Note {
  id Int @id @default(autoincrement())
  title String
  user_id Int?
  @@map("notes")
}
`)
	writeTestFile(t, dir, "app.yaml", appYAML)
	app, err := loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	return app
}

// runAccountHoldTests runs one YAML test file through the runner and returns
// its results by test name.
func runAccountHoldTests(t *testing.T, app *App, file AppTestFile) map[string]AppTestResult {
	t.Helper()
	out := map[string]AppTestResult{}
	for _, r := range RunAllTests(app, []AppTestFile{file}, false) {
		if r.File != "SUMMARY" {
			out[r.Test] = r
		}
	}
	if len(out) != len(file.Tests) {
		t.Fatalf("ran %d tests, want %d: %+v", len(out), len(file.Tests), out)
	}
	return out
}

// A YAML test sees what the server answers an account that is held: 403
// mfa_enrollment_required (page navigation: a redirect to the setup page) for
// one that must enroll MFA, 403 password_change_required (a redirect to the
// change page) for one on a temporary password. The runner served the bare mux,
// so both got 401 from the API and the page itself, and a test could only
// record the harness's answer.
func TestRunnerAnswersHeldAccountsAsTheServerDoes(t *testing.T) {
	app := accountHoldTestApp(t, "auth:\n  identifier: email\n  require_mfa_for_roles: \"*\"\n")
	results := runAccountHoldTests(t, app, AppTestFile{Name: "holds", Tests: map[string]AppTestCase{
		"enrolled_account_keeps_its_session": {AsUser: "enrolled@example.com", Steps: []AppTestStep{
			{Get: "/api/notes", Expect: AppTestExpect{Status: 200}},
		}},
		"account_without_a_factor": {AsUser: "nofactor@example.com", Steps: []AppTestStep{
			{SQL: "UPDATE _benmore_users SET totp_secret = NULL WHERE email = 'nofactor@example.com'"},
			{Get: "/api/notes", Expect: AppTestExpect{Status: 403, Contains: mfaEnrollmentRequiredError, JSONField: map[string]any{"error": mfaEnrollmentRequiredError, "redirect": "/mfa-setup"}}},
			{Get: "/api/notes", Bearer: true, Expect: AppTestExpect{Status: 403, Contains: mfaEnrollmentRequiredError}},
			{Get: "/", Expect: AppTestExpect{Status: 303, Headers: map[string]string{"Location": "/mfa-setup"}}},
			// What a held account may still reach stays reachable.
			{Get: "/api/_csrf", Expect: AppTestExpect{Status: 200}},
		}},
		"account_on_a_temporary_password": {AsUser: "temporary@example.com", Steps: []AppTestStep{
			{SQL: "UPDATE _benmore_users SET password_change_required = 1 WHERE email = 'temporary@example.com'"},
			{Get: "/api/notes", Expect: AppTestExpect{Status: 403, JSONField: map[string]any{"error": "password_change_required", "redirect": passwordChangePagePath}}},
			{Get: "/", Expect: AppTestExpect{Status: 303, Headers: map[string]string{"Location": passwordChangePagePath}}},
			{Get: passwordChangePagePath, Expect: AppTestExpect{Status: 200}},
		}},
		// No credential, no hold: the gates answer only an account they hold.
		"anonymous_is_not_held": {Anon: true, Steps: []AppTestStep{
			{Get: "/api/notes", Expect: AppTestExpect{Status: 401}},
		}},
	}})
	for name, r := range results {
		if !r.Pass {
			t.Errorf("%s: %s", name, r.Message)
		}
	}
}

// A test step that changes an audit table of a compliance: hipaa app is
// refused by the append-only triggers; the failure says where such SQL goes.
// It said only "<table> is append-only".
func TestRunnerStepSQLOnAuditTablePointsToSetup(t *testing.T) {
	app := accountHoldTestApp(t, "compliance: hipaa\nauth:\n  identifier: email\n")
	results := runAccountHoldTests(t, app, AppTestFile{Name: "audit", Tests: map[string]AppTestCase{
		"step_sql": {AsUser: "audit@example.com", Steps: []AppTestStep{
			{API: "POST /api/notes", JSON: map[string]any{"title": "one"}, Expect: AppTestExpect{Status: 200}},
			{SQL: "DELETE FROM _benmore_audit_log"},
		}},
		"setup_sql": {AsUser: "audit@example.com", Setup: []AppTestSetup{{SQL: "DELETE FROM _benmore_audit_log"}}, Steps: []AppTestStep{
			{Get: "/api/notes", Expect: AppTestExpect{Status: 200}},
		}},
		// Any other SQL error is reported as it was.
		"other_sql_error": {AsUser: "audit@example.com", Steps: []AppTestStep{
			{SQL: "SELECT * FROM no_such_table"},
		}},
	}})
	step := results["step_sql"]
	if step.Pass || !strings.Contains(step.Message, "_benmore_audit_log is append-only") {
		t.Fatalf("step SQL on an audit table was not refused: %+v", step)
	}
	if !strings.Contains(step.Message, "setup:") || !strings.Contains(step.Message, "compliance: hipaa") {
		t.Errorf("the refusal does not say where the statement goes: %q", step.Message)
	}
	if r := results["setup_sql"]; !r.Pass {
		t.Errorf("setup SQL on an audit table failed: %s", r.Message)
	}
	if r := results["other_sql_error"]; r.Pass || strings.Contains(r.Message, "setup:") {
		t.Errorf("an unrelated SQL error got the audit hint: %+v", r)
	}
}

// An auth.idle_timeout that is not a duration says so under compliance: hipaa
// too. `15` got "between 2m0s and 15m0s ... got 15", which reads as in range.
func TestComplianceIdleTimeoutMessagesNameTheFormat(t *testing.T) {
	hipaa := func(v string) string {
		return complianceAppYAMLProblem(map[string]any{"compliance": "hipaa", "auth": map[string]any{"idle_timeout": v}})
	}
	for _, v := range []string{"15", "900", "15M", "true", "soon"} {
		msg := hipaa(v)
		if !strings.Contains(msg, "is not a duration") || !strings.Contains(msg, `"10m"`) || !strings.Contains(msg, "= "+v+" ") {
			t.Errorf("idle_timeout %q: the refusal does not name the format: %q", v, msg)
		}
		if !strings.Contains(msg, "2m and 15m") {
			t.Errorf("idle_timeout %q: the refusal does not give the range: %q", v, msg)
		}
	}
	// A duration outside the range keeps the range message, with the value.
	for _, v := range []string{"1h", "16m", "1d", "0", "90s"} {
		msg := hipaa(v)
		if strings.Contains(msg, "is not a duration") || !strings.Contains(msg, "between 2m and 15m") || !strings.Contains(msg, "got "+v) {
			t.Errorf("idle_timeout %q: want the range refusal, got %q", v, msg)
		}
	}
	for _, v := range []string{"2m", "10m", "15m", "900s"} {
		if msg := hipaa(v); msg != "" {
			t.Errorf("idle_timeout %q refused: %q", v, msg)
		}
	}
	// Durations read as a config value is written, in both checks.
	plain := idleTimeoutAppYAMLProblem(map[string]any{"auth": map[string]any{"idle_timeout": "15"}})
	for _, msg := range []string{hipaa("15"), hipaa("1h"), plain} {
		if strings.Contains(msg, "m0s") {
			t.Errorf("a duration is printed as Go formats it: %q", msg)
		}
	}
	if !strings.Contains(plain, "at least 2m.") {
		t.Errorf("the every-app check lost its minimum: %q", plain)
	}
}

// The missing-setup-page warning names where the requirement comes from: under
// compliance: hipaa the builder never wrote auth.require_mfa_for_roles.
func TestMFASetupPageWarningNamesTheHIPAADefault(t *testing.T) {
	dir := t.TempDir()
	byDefault := mfaSetupPageWarning(dir, []byte("compliance: hipaa\nauth:\n  identifier: email\n"))
	if !strings.Contains(byDefault, "compliance: hipaa") || !strings.Contains(byDefault, "default") || !strings.Contains(byDefault, "/mfa-setup") {
		t.Errorf("the warning does not say compliance: hipaa set the requirement: %q", byDefault)
	}
	// Written out, it is the builder's own key, hipaa or not.
	for _, doc := range []string{
		"compliance: hipaa\nauth:\n  require_mfa_for_roles: \"*\"\n",
		"auth:\n  require_mfa_for_roles: admin\n",
	} {
		msg := mfaSetupPageWarning(dir, []byte(doc))
		if !strings.Contains(msg, "auth.require_mfa_for_roles (") || strings.Contains(msg, "defaults to") {
			t.Errorf("an explicit list was reported as a default: %q", msg)
		}
	}
	os.MkdirAll(filepath.Join(dir, "static"), 0o755)
	os.WriteFile(filepath.Join(dir, "static", "mfa-setup.html"), []byte("<html></html>"), 0o644)
	if msg := mfaSetupPageWarning(dir, []byte("compliance: hipaa\nauth:\n  identifier: email\n")); msg != "" {
		t.Errorf("warned although the page exists: %q", msg)
	}
}

// The framework binary prints the contract its refusals cite: `benmore docs
// compliance` (and mfa, audit, which the compliance contract points to) used
// to answer "Unknown topic".
func TestAgentDocsCoverTheComplianceTopics(t *testing.T) {
	build := AgentDocs("build")
	const section = "`compliance: hipaa` - stricter defaults for apps holding PHI"
	if !strings.Contains(build, "\n## "+section+"\n") {
		t.Fatalf("the build guide has no %q section", section)
	}
	body := build[strings.Index(build, "\n## "+section+"\n"):]
	if next := strings.Index(body[4:], "\n## "); next >= 0 {
		body = body[:next+4]
	}
	for _, want := range []string{"auth.idle_timeout", "auth.require_mfa_for_roles", "/mfa-setup", "_benmore_audit_log", "GitHub", "refresh_dev", "recording.enabled", `api(at:"compliance")`} {
		if !strings.Contains(body, want) {
			t.Errorf("the compliance section does not mention %s", want)
		}
	}
	for _, topic := range []string{"compliance", "mfa", "audit"} {
		if AgentDocs(topic) != build {
			t.Errorf("benmore docs %s does not print the build guide", topic)
		}
		if pointer := AgentDocsPointer(topic); !strings.Contains(pointer, section) {
			t.Errorf("benmore docs %s does not name the section: %q", topic, pointer)
		}
	}
	// The unknown-value refusal names the command that prints it.
	if msg := complianceAppYAMLProblem(map[string]any{"compliance": "HIPAA"}); !strings.Contains(msg, "benmore docs compliance") || !strings.Contains(msg, `api(at:"compliance")`) {
		t.Errorf("the refusal does not say where the contract is: %q", msg)
	}
}
