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
	switches := []string{"admin", "uploads", "exports", "sse", "ws", "docs", "testing", "feedback", "analytics", "account_settings"}
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
	const provider = "oauth:\n  custom:\n    auth_url: https://identity.example.com/authorize\n    token_url: https://identity.example.com/token\n    userinfo_url: https://identity.example.com/userinfo\n"
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
		{"an identifier in another case", "site_name: \"Unread\"\nauth:\n  identifier: Username\n",
			[]string{"app.yaml: `auth.identifier` takes email, username or phone, and `Username` is none of them, so accounts sign in by email. Did you mean `username`?"}},
		{"an identifier that is none", "site_name: \"Unread\"\nauth:\n  identifier: mobile\n",
			[]string{"app.yaml: `auth.identifier` takes email, username or phone, and `mobile` is none of them, so accounts sign in by email."}},
		{"trust_email written yes", unreadBaseYAML + provider + "    trust_email: yes\n",
			[]string{"app.yaml: `oauth.custom.trust_email` takes true or false, and `yes` is read as false, so the provider's addresses are not trusted. Write `true` when the provider verifies every address it returns."}},
		{"trust_email written 1", unreadBaseYAML + provider + "    trust_email: 1\n",
			[]string{"app.yaml: `oauth.custom.trust_email` takes true or false, and `1` is read as false, so the provider's addresses are not trusted. Write `true` when the provider verifies every address it returns."}},
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
	app := loadSwitchApp(t, "site_name: x\nauth:\n  identifier: Username\nrecording:\n  enabled: disabled\n  mask_inputs: [password]\n"+
		"features:\n  uploads: {enabled: no, max_mb: 5}\n  testing: {banner: amber}\n  ws_anonymous: {rooms: lobby}\n"+
		"oauth:\n  custom:\n    auth_url: https://identity.example.com/authorize\n    token_url: https://identity.example.com/token\n    userinfo_url: https://identity.example.com/userinfo\n    trust_email: yes\n", true)
	if got := authIdentifier(app); got != "email" {
		t.Errorf("auth.identifier: Username signs in by %s; the warning says email", got)
	}
	if script, _ := recorderServed(app); !strings.Contains(script, "var maskInputs = true;") {
		t.Error("recording.enabled: disabled with mask_inputs: [password]: the warnings say the recorder stays on with typed values masked")
	}
	features := app.Design.Features
	if features.IsEnabled("uploads") || !features.IsEnabled("testing") || broadcastAllowAnon(app) {
		t.Errorf("the warnings say uploads off, testing on, ws_anonymous off; got uploads %v, testing %v, ws_anonymous %v",
			features.IsEnabled("uploads"), features.IsEnabled("testing"), broadcastAllowAnon(app))
	}
	if provider, loaded := oauthProvidersForApp(app.Dir)["custom"]; !loaded || provider.TrustEmail {
		t.Errorf("oauth.custom.trust_email: yes: the warning says the addresses are not trusted; provider %+v", provider)
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
		"features:\n  admin: false\n  uploads: no\n  docs: auth\n  testing: \"on\"\n  ws_anonymous: yes\n",
		"oauth:\n  custom:\n    trust_email: true\n  other:\n    trust_email: \"True\"\n  third:\n    trust_email: no\n  fourth:\n    trust_email: \"false\"\n  fifth:\n    trust_email:\n  sixth: {}\n",
	} {
		if got := appYAMLUnreadWarnings(clean); len(got) != 0 {
			t.Errorf("%q is reported: %q", clean, got)
		}
	}
}

// Each warning carries the address of the key that documents the switch.
func TestAppYAMLSwitchWarningsCarryTheirDocs(t *testing.T) {
	dir := noEffectDir(t, "site_name: \"Unread\"\nauth:\n  identifier: Username\nrecording:\n  enabled: disabled\nfeatures:\n  uploads: {enabled: no}\noauth:\n  custom:\n    trust_email: yes\n")
	got := map[string]string{}
	for _, f := range RunSourceCheck(dir, "app.yaml").Findings {
		if f.Source == "config" {
			got[strings.SplitN(strings.TrimPrefix(f.Message, "app.yaml: "), " ", 2)[0]] = f.Docs
		}
	}
	want := map[string]string{"`auth.identifier`": "auth.app_yaml_flags", "`recording.enabled`": "frontend.ssr_session_recording",
		"`features.uploads`": "recovery.configuration_loading", "`oauth.custom.trust_email`": "oauth.configuration_notes"}
	for subject, at := range want {
		if got[subject] != at {
			t.Errorf("%s: docs %q, want %q (all: %v)", subject, got[subject], at, got)
		}
	}
}
