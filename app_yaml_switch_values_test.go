//go:build !cli && !windows

package main

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

// app.yaml switches written in a spelling of true or false other than the
// literal words (app_yaml_switch_values.go).
//
// yaml.v3 hands `no`, `off`, `yes` and `on` over as text and `0`/`1` as
// numbers; only `true`/`false` in any case arrive as booleans. A loader that
// compares to the text "false" therefore leaves `enabled: no` switched ON.
// Every test loads real app.yaml text through the runtime's loader, so it
// holds what the parser really hands over.

func loadSwitchApp(t *testing.T, appYAML string, devMode bool) *App {
	t.Helper()
	dir := t.TempDir()
	writeTestFile(t, dir, "app.yaml", appYAML)
	design := LoadAppConfigYAML(dir)
	if design == nil {
		t.Fatalf("app.yaml did not load:\n%s", appYAML)
	}
	return &App{Dir: dir, DevMode: devMode, Design: design}
}

// recorderServed reports what a visitor meets: whether pages carry the
// recorder script, and the status of the beacon the script posts to.
func recorderServed(app *App) (script string, beacon int) {
	mux := http.NewServeMux()
	RegisterRecordingRoutes(mux, app)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/_internal/recording", strings.NewReader(`{"id":"s1","events":[]}`)))
	return RecorderScript(app, app.DevMode), rec.Code
}

var (
	switchOffSpellings = []string{"false", "False", "FALSE", "no", "No", "NO", "off", "Off", "0", `"false"`, `"no"`, `"off"`, `"0"`, `" no "`}
	switchOnSpellings  = []string{"true", "True", "yes", "Yes", "on", "ON", "1", `"true"`, `"yes"`, `"on"`, `"1"`}
)

// `recording.enabled` written as any spelling of "no" turns the recorder off:
// pages carry no recorder script and the beacon route does not exist. A
// builder who writes `enabled: no` believes visitors are not recorded.
func TestRecordingEnabledReadsEverySpellingOfNo(t *testing.T) {
	for _, v := range switchOffSpellings {
		// Dev mode records by default, and production has opted in: only
		// `enabled` stands between a visitor and the recorder.
		for _, devMode := range []bool{true, false} {
			app := loadSwitchApp(t, "site_name: x\nrecording:\n  enabled: "+v+"\n  production: true\n", devMode)
			script, beacon := recorderServed(app)
			if script != "" || beacon != http.StatusNotFound {
				t.Errorf("recording.enabled: %s (dev mode %v): the recorder is on (script %d bytes, beacon %d)", v, devMode, len(script), beacon)
			}
		}
	}
	for _, v := range append(slices.Clone(switchOnSpellings), `""`, "") {
		app := loadSwitchApp(t, "site_name: x\nrecording:\n  enabled: "+v+"\n", true)
		script, beacon := recorderServed(app)
		if !strings.Contains(script, "sendBeacon") || beacon != http.StatusNoContent {
			t.Errorf("recording.enabled: %s in dev mode: the recorder is off (script %d bytes, beacon %d)", v, len(script), beacon)
		}
	}
	// No recording: section at all keeps the default: on in dev mode, off in production.
	if script, _ := recorderServed(loadSwitchApp(t, "site_name: x\n", true)); script == "" {
		t.Error("the dev-mode default changed: no recorder without a recording: section")
	}
	if script, beacon := recorderServed(loadSwitchApp(t, "site_name: x\n", false)); script != "" || beacon != http.StatusNotFound {
		t.Error("the production default changed: the recorder is on without a recording: section")
	}
}

// `recording.production` is the production opt-in: every spelling of "yes"
// gives it, every spelling of "no" (and leaving it out) withholds it.
func TestRecordingProductionReadsEverySpelling(t *testing.T) {
	for _, v := range switchOnSpellings {
		app := loadSwitchApp(t, "site_name: x\nrecording:\n  production: "+v+"\n", false)
		if script, beacon := recorderServed(app); !strings.Contains(script, "sendBeacon") || beacon != http.StatusNoContent {
			t.Errorf("recording.production: %s: production is not recorded (script %d bytes, beacon %d)", v, len(script), beacon)
		}
	}
	for _, v := range append(slices.Clone(switchOffSpellings), `""`, "", "sometimes") {
		app := loadSwitchApp(t, "site_name: x\nrecording:\n  enabled: true\n  production: "+v+"\n", false)
		if script, beacon := recorderServed(app); script != "" || beacon != http.StatusNotFound {
			t.Errorf("recording.production: %s: production is recorded (script %d bytes, beacon %d)", v, len(script), beacon)
		}
	}
}

// `recording.mask_inputs` turns the input-name masking rule off only when it
// says no; every other value keeps typed values masked.
func TestRecordingMaskInputsReadsEverySpelling(t *testing.T) {
	masks := func(v string) string {
		script, _ := recorderServed(loadSwitchApp(t, "site_name: x\nrecording:\n  mask_inputs: "+v+"\n", true))
		_, rest, _ := strings.Cut(script, "var maskInputs = ")
		value, _, _ := strings.Cut(rest, ";")
		return value
	}
	for _, v := range switchOffSpellings {
		if got := masks(v); got != "false" {
			t.Errorf("recording.mask_inputs: %s: maskInputs = %q, want false", v, got)
		}
	}
	for _, v := range append(slices.Clone(switchOnSpellings), `""`, "", "sometimes") {
		if got := masks(v); got != "true" {
			t.Errorf("recording.mask_inputs: %s: maskInputs = %q, want true", v, got)
		}
	}
}

// A features: switch written as a mapping is read by its `enabled:` value,
// in every spelling. `uploads: {enabled: no}` used to leave uploads on and
// `ws_anonymous: {enabled: no}` opened /ws and /sse/events to anonymous
// clients: any mapping counted as "on".
func TestFeatureSwitchWrittenAsAMappingReadsEnabled(t *testing.T) {
	switches := []string{"admin", "uploads", "exports", "sse", "ws", "docs", "testing", "feedback", "analytics", "account_settings", "sharing"}
	features := func(value string) *App {
		var b strings.Builder
		b.WriteString("site_name: x\nfeatures:\n")
		for _, name := range append(slices.Clone(switches), "ws_anonymous") {
			b.WriteString("  " + name + ": " + value + "\n")
		}
		return loadSwitchApp(t, b.String(), true)
	}
	for _, v := range switchOffSpellings {
		app := features("{enabled: " + v + "}")
		for _, name := range switches {
			if app.Design.Features.IsEnabled(name) {
				t.Errorf("features.%s: {enabled: %s} left the feature on", name, v)
			}
		}
		if broadcastAllowAnon(app) {
			t.Errorf("features.ws_anonymous: {enabled: %s} opened the anonymous gate", v)
		}
	}
	for _, v := range switchOnSpellings {
		app := features("{enabled: " + v + "}")
		for _, name := range switches {
			if !app.Design.Features.IsEnabled(name) {
				t.Errorf("features.%s: {enabled: %s} left the feature off", name, v)
			}
		}
		if !broadcastAllowAnon(app) {
			t.Errorf("features.ws_anonymous: {enabled: %s} left the anonymous gate closed", v)
		}
	}
	// A mapping that does not say: every switch counts as on, as it always
	// has, except the one that opens a gate, which needs a value that says so.
	for _, v := range []string{"{}", "{limit: 5}", "{enabled: sometimes}", "{enabled: }"} {
		app := features(v)
		for _, name := range switches {
			if !app.Design.Features.IsEnabled(name) {
				t.Errorf("features.%s: %s turned the feature off", name, v)
			}
		}
		if broadcastAllowAnon(app) {
			t.Errorf("features.ws_anonymous: %s opened the anonymous gate", v)
		}
	}
}

// A switch value that is not read the way it is written is accepted by the
// write gate (apps may carry one) and warned about by the post-write check
// of app.yaml and by `benmore check`, with what it leaves the app with.
func TestAppYAMLSwitchValuesNotReadAsWrittenWarn(t *testing.T) {
	for _, c := range []struct {
		name, yaml string
		want       []string
	}{
		{"recording switches that are neither true nor false", unreadBaseYAML + "recording:\n  enabled: disabled\n  production: sometimes\n  mask_inputs: [password]\n",
			[]string{
				"app.yaml: `recording.enabled` takes true or false (yes/no, on/off and 1/0 mean the same), and `disabled` is neither, so the recorder is not turned off.",
				"app.yaml: `recording.mask_inputs` takes true or false (yes/no, on/off and 1/0 mean the same), and the list written here is neither, so typed values stay masked.",
				"app.yaml: `recording.production` takes true or false (yes/no, on/off and 1/0 mean the same), and `sometimes` is neither, so production is not recorded.",
			}},
		{"features switches written as mappings", unreadBaseYAML + "features:\n  admin: false\n  uploads: {enabled: no, max_mb: 5}\n  testing: {banner: amber}\n  ws_anonymous: {rooms: lobby}\n",
			[]string{
				"app.yaml: `features.testing` takes true or false (yes/no and on/off mean the same), and of the mapping written here only `enabled:` is read, so the switch is on and its other keys have no effect. Write `testing: true` or `testing: false`.",
				"app.yaml: `features.uploads` takes true or false (yes/no and on/off mean the same), and of the mapping written here only `enabled:` is read, so the switch is off and its other keys have no effect. Write `uploads: true` or `uploads: false`.",
				"app.yaml: `features.ws_anonymous` takes true or false (yes/no and on/off mean the same), and of the mapping written here only `enabled:` is read, so the switch is off and its other keys have no effect. Write `ws_anonymous: true` or `ws_anonymous: false`.",
			}},
	} {
		t.Run(c.name, func(t *testing.T) {
			afterWrite, check := unreadWarningsOf(t, c.yaml)
			if !slices.Equal(afterWrite, c.want) {
				t.Errorf("the post-write check of app.yaml:\n got %q\nwant %q", afterWrite, c.want)
			}
			if !slices.Equal(check, c.want) {
				t.Errorf("benmore check:\n got %q\nwant %q", check, c.want)
			}
		})
	}
}

// What each warning says is what the loaders do: the value named in a
// warning leaves the app in the state the warning states.
func TestAppYAMLSwitchWarningsStateWhatTheLoaderDoes(t *testing.T) {
	app := loadSwitchApp(t, "site_name: x\nrecording:\n  enabled: disabled\n  mask_inputs: [password]\n"+
		"features:\n  uploads: {enabled: no, max_mb: 5}\n  testing: {banner: amber}\n  ws_anonymous: {rooms: lobby}\n", true)
	if script, _ := recorderServed(app); !strings.Contains(script, "var maskInputs = true;") {
		t.Error("recording.enabled: disabled with mask_inputs: [password]: the warnings say the recorder stays on with typed values masked")
	}
	features := app.Design.Features
	if features.IsEnabled("uploads") || !features.IsEnabled("testing") || broadcastAllowAnon(app) {
		t.Errorf("the warnings say uploads off, testing on, ws_anonymous off; got uploads %v, testing %v, ws_anonymous %v",
			features.IsEnabled("uploads"), features.IsEnabled("testing"), broadcastAllowAnon(app))
	}
}

// Every spelling a switch reads, and every value that means what it says, is
// quiet.
func TestAppYAMLSwitchValuesReadAsWrittenAreNotReported(t *testing.T) {
	spellings := append(append(slices.Clone(switchOffSpellings), switchOnSpellings...), `""`, "")
	for _, v := range spellings {
		yaml := "recording:\n  enabled: " + v + "\n  production: " + v + "\n  mask_inputs: " + v + "\n"
		if got := appYAMLUnreadWarnings(yaml); len(got) != 0 {
			t.Errorf("recording switches written %s are reported: %q", v, got)
		}
	}
	for _, clean := range []string{
		"auth:\n  identifier: email\n", "auth:\n  identifier: username\n", "auth:\n  identifier: phone\n", "auth:\n  identifier: \"\"\n", "auth:\n  identifier:\n", "auth:\n  otp: true\n",
		"auth:\n  identifier: Username\n", "auth:\n  identifier: \" PHONE \"\n",
		"features:\n  admin: false\n  uploads: no\n  docs: auth\n  testing: \"on\"\n  ws_anonymous: yes\n",
		"oauth:\n  custom:\n    trust_email: true\n  other:\n    trust_email: \"True\"\n  third:\n    trust_email: no\n  fourth:\n    trust_email: \"false\"\n  fifth:\n    trust_email:\n  sixth: {}\n  seventh:\n    trust_email: yes\n  eighth:\n    trust_email: 1\n  ninth:\n    trust_email: \"On\"\n",
	} {
		if got := appYAMLUnreadWarnings(clean); len(got) != 0 {
			t.Errorf("%q is reported: %q", clean, got)
		}
	}
}

// Each warning carries the address of the key that documents the switch.
func TestAppYAMLSwitchWarningsCarryTheirDocs(t *testing.T) {
	dir := noEffectDir(t, "site_name: \"Unread\"\nrecording:\n  enabled: disabled\nfeatures:\n  uploads: {enabled: no}\n")
	got := map[string]string{}
	for _, f := range RunSourceCheck(dir, "app.yaml").Findings {
		if f.Source == "config" {
			got[strings.SplitN(strings.TrimPrefix(f.Message, "app.yaml: "), " ", 2)[0]] = f.Docs
		}
	}
	want := map[string]string{"`recording.enabled`": "frontend.ssr_session_recording", "`features.uploads`": "recovery.configuration_loading"}
	for subject, at := range want {
		if got[subject] != at {
			t.Errorf("%s: docs %q, want %q (all: %v)", subject, got[subject], at, got)
		}
	}
}

// `auth.identifier` is read whatever its letter case and surrounding space.
// `identifier: Username` used to mean email sign-in, because the value was
// compared to the lower-case words; the write gate accepts every spelling it
// reads, and nothing warns about one.
func TestAuthIdentifierReadsEveryLetterCase(t *testing.T) {
	for written, want := range map[string]string{
		"email": "email", "Email": "email", "EMAIL": "email", `" email"`: "email",
		"username": "username", "Username": "username", "USERNAME": "username", `" username "`: "username", `"UserName"`: "username",
		"phone": "phone", "Phone": "phone", "PHONE": "phone", `"Phone "`: "phone",
		`""`: "email", `"  "`: "email",
	} {
		yaml := "site_name: x\nauth:\n  identifier: " + written + "\n"
		app := loadSwitchApp(t, yaml, false)
		if got := authIdentifier(app); got != want {
			t.Errorf("auth.identifier: %s signs in by %s, want %s", written, got, want)
		}
		// Code that reads the loaded value itself sees the same word.
		if got := app.Design.Auth["identifier"]; strings.TrimSpace(got) != "" && got != want {
			t.Errorf("auth.identifier: %s is loaded as %q, want %q", written, got, want)
		}
		if msg := ValidateOnWrite("app.yaml", yaml); msg != "" {
			t.Errorf("auth.identifier: %s is refused at write time: %s", written, msg)
		}
		if got := appYAMLUnreadWarnings(yaml); len(got) != 0 {
			t.Errorf("auth.identifier: %s is warned about: %q", written, got)
		}
	}
	if got := authIdentifier(loadSwitchApp(t, "site_name: x\n", false)); got != "email" {
		t.Errorf("the default changed: no auth section signs in by %s", got)
	}
}

// An app that writes `identifier: Username` signs its accounts in by
// username: the name is accepted and the address is not a sign-in name.
func TestSignInByUsernameWhenIdentifierIsCapitalised(t *testing.T) {
	app, _, call := tokenAuthFixture(t, "ada@example.com", fixturePassword, "198.51.100.71")
	writeTestFile(t, app.Dir, "app.yaml", "site_name: x\nauth:\n  identifier: Username\n")
	app.Design = LoadAppConfigYAML(app.Dir)
	if app.Design == nil {
		t.Fatal("app.yaml did not load")
	}
	if w := call(map[string]string{"email": "ada", "password": fixturePassword}); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"token"`) {
		t.Fatalf("sign-in by username: %d %s", w.Code, w.Body.String())
	}
	if w := call(map[string]string{"email": "ada@example.com", "password": fixturePassword}); w.Code != http.StatusUnauthorized {
		t.Fatalf("sign-in by address on a username app: %d %s", w.Code, w.Body.String())
	}
}

// appYAMLRefusal is what the write gate and `benmore check` answer for an
// app.yaml: the gate's message, and the error finding with its docs address.
func appYAMLRefusal(t *testing.T, appYAML string) (gate string, finding CheckFinding) {
	t.Helper()
	dir := noEffectDir(t, appYAML)
	for _, f := range RunSourceCheck(dir, "").Findings {
		if f.Severity == "error" && f.File == "app.yaml" {
			finding = f
			break
		}
	}
	return ValidateOnWriteIn(dir, "app.yaml", appYAML), finding
}

// A value that is no identifier cannot mean what is written: the write gate
// and `benmore check` refuse it and name the three it takes, and an app that
// carries one keeps signing in by email. (A list or a mapping there is no
// scalar: the load of app.yaml refuses the file.)
func TestUnknownAuthIdentifierIsRefusedAtWriteTime(t *testing.T) {
	for written, hint := range map[string]string{
		"mobile": "", "usernme": " Did you mean `username`?", "user_name": " Did you mean `username`?",
		"7": "", "true": "", `"phone number"`: " Did you mean `phone`?",
	} {
		yaml := "site_name: \"Unread\"\nauth:\n  identifier: " + written + "\n"
		gate, finding := appYAMLRefusal(t, yaml)
		for _, want := range []string{"app.yaml: auth.identifier", "is not a sign-in identifier", "email (the default), username or phone", "accounts sign in by email"} {
			if !strings.Contains(gate, want) {
				t.Errorf("auth.identifier: %s: the write gate says %q, without %q", written, gate, want)
			}
		}
		if strings.Contains(gate, "Did you mean") != (hint != "") || !strings.Contains(gate, hint) {
			t.Errorf("auth.identifier: %s: the write gate says %q, want the hint %q", written, gate, hint)
		}
		if !strings.Contains(finding.Message, "is not a sign-in identifier") || finding.Docs != "auth.app_yaml_flags" {
			t.Errorf("auth.identifier: %s: benmore check reports %+v", written, finding)
		}
		if got := authIdentifier(loadSwitchApp(t, yaml, false)); got != "email" {
			t.Errorf("auth.identifier: %s signs in by %s; the refusal says email", written, got)
		}
	}
}

const trustEmailProvider = "site_name: \"Unread\"\noauth:\n  custom:\n    auth_url: https://identity.example.com/authorize\n    token_url: https://identity.example.com/token\n    userinfo_url: https://identity.example.com/userinfo\n"

// trustedWithoutClaim reports whether a sign-in through the app's custom
// provider counts an address as proven when the provider sends no
// email_verified claim: what `trust_email` decides.
func trustedWithoutClaim(t *testing.T, appYAML string) bool {
	t.Helper()
	dir := t.TempDir()
	writeTestFile(t, dir, "app.yaml", appYAML)
	provider, loaded := oauthProvidersForApp(dir)["custom"]
	if !loaded {
		t.Fatalf("the custom provider did not load:\n%s", appYAML)
	}
	return oauthEmailVerified(&provider, "custom", map[string]any{"email": "someone@example.com"})
}

// `oauth.<name>.trust_email` is read like every other switch: each spelling
// of yes gives the trust, each spelling of no (and leaving it out) withholds
// it. `trust_email: yes` used to be read as false.
func TestTrustEmailReadsEverySpelling(t *testing.T) {
	for _, v := range switchOnSpellings {
		yaml := trustEmailProvider + "    trust_email: " + v + "\n"
		if !trustedWithoutClaim(t, yaml) {
			t.Errorf("trust_email: %s: the provider's addresses are not trusted", v)
		}
		if msg := ValidateOnWrite("app.yaml", yaml); msg != "" {
			t.Errorf("trust_email: %s is refused at write time: %s", v, msg)
		}
	}
	for _, v := range append(slices.Clone(switchOffSpellings), `""`, "", "~", "null") {
		yaml := trustEmailProvider + "    trust_email: " + v + "\n"
		if trustedWithoutClaim(t, yaml) {
			t.Errorf("trust_email: %s: the provider's addresses are trusted", v)
		}
		if msg := ValidateOnWrite("app.yaml", yaml); msg != "" {
			t.Errorf("trust_email: %s is refused at write time: %s", v, msg)
		}
	}
	if trustedWithoutClaim(t, trustEmailProvider) {
		t.Error("the default changed: a provider without trust_email is trusted")
	}
}

// A value that is no spelling of true or false gives no trust, and the write
// gate and `benmore check` refuse it: trust is never read out of a value
// that does not say so.
func TestUnknownTrustEmailFailsClosedAndIsRefusedAtWriteTime(t *testing.T) {
	for _, v := range []string{"sometimes", "verified", "truthy", "[true]", "{enabled: true}", "2", "1.0", "-1", `"true dat"`} {
		yaml := trustEmailProvider + "    trust_email: " + v + "\n"
		if trustedWithoutClaim(t, yaml) {
			t.Errorf("trust_email: %s: the provider's addresses are trusted", v)
		}
		gate, finding := appYAMLRefusal(t, yaml)
		for _, want := range []string{"app.yaml: oauth.custom.trust_email", "is not a boolean", "yes/no, on/off and 1/0", "addresses are not trusted"} {
			if !strings.Contains(gate, want) {
				t.Errorf("trust_email: %s: the write gate says %q, without %q", v, gate, want)
			}
		}
		if !strings.Contains(finding.Message, "oauth.custom.trust_email") || finding.Docs != "oauth.configuration_notes" {
			t.Errorf("trust_email: %s: benmore check reports %+v", v, finding)
		}
	}
	// One unreadable value among several providers is named by its own provider.
	two := trustEmailProvider + "    trust_email: yes\n  other:\n    auth_url: https://other.example.com/authorize\n    trust_email: maybe\n"
	if gate, _ := appYAMLRefusal(t, two); !strings.Contains(gate, "app.yaml: oauth.other.trust_email") {
		t.Errorf("the write gate says %q, want it to name oauth.other.trust_email", gate)
	}
}
