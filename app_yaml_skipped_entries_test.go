//go:build !cli && !windows

package main

import (
	"strings"
	"testing"
)

// app.yaml entries and values the loader skips or reads as something else
// without a word (app_yaml_skipped_entries.go). Each test reads real app.yaml
// text through the loader first, so the reading it warns about is the one the
// runtime has.

// An `oauth:` entry named after a built-in provider is skipped whole: the
// provider keeps its built-in endpoints, scopes and fields whatever the entry
// says. The check says so, names the keys written, and does not also list
// each of them as an unknown key.
func TestOAuthEntryNamedAfterABuiltInProviderIsWarned(t *testing.T) {
	const appYAML = `site_name: x
oauth:
  google:
    auth_url: https://login.example.test/authorize
    scopes: "openid email calendar"
    prompt: consent
  discord:
    auth_url: https://discord.example.test/authorize
    token_url: https://discord.example.test/token
    userinfo_url: https://discord.example.test/me
`
	dir := t.TempDir()
	writeTestFile(t, dir, "app.yaml", appYAML)
	providers := oauthProvidersForApp(dir)
	if got := providers["google"]; got.AuthURL != oauthProviders["google"].AuthURL || strings.Join(got.Scopes, " ") != "email profile" {
		t.Fatalf("the entry changed the built-in provider (%+v): the warning below would be false", got)
	}
	if providers["discord"].AuthURL == "" {
		t.Fatal("a custom provider did not load")
	}
	if msg := validateAppYAML(appYAML); msg != "" {
		t.Fatalf("the write gate refuses the file (apps may carry such an entry): %s", msg)
	}
	var about []string
	for _, w := range appYAMLUnreadWarnings(appYAML) {
		if strings.Contains(w, "oauth.google") {
			about = append(about, w)
		}
		if strings.Contains(w, "oauth.discord") {
			t.Errorf("a custom provider is warned about: %s", w)
		}
	}
	if len(about) != 1 {
		t.Fatalf("%d warnings about oauth.google, want 1: %v", len(about), about)
	}
	for _, want := range []string{"built-in provider", "none of its keys", "auth_url, prompt, scopes", "GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET"} {
		if !strings.Contains(about[0], want) {
			t.Errorf("the warning lacks %q: %s", want, about[0])
		}
	}
	// It carries the address of the provider rules.
	found := false
	for _, f := range RunSourceCheck(dir, "app.yaml").Findings {
		if strings.Contains(f.Message, "oauth.google") {
			found = true
			if f.Severity != "warning" || f.Docs != "oauth.configuration_notes" {
				t.Errorf("finding is %s with docs %q, want a warning at oauth.configuration_notes", f.Severity, f.Docs)
			}
		}
	}
	if !found {
		t.Error("`benmore check` does not report the skipped entry")
	}
}

// An `auto_memberships:` entry that is not a mapping is skipped: no hook is
// made and nobody is enrolled. The write gate refuses it, an empty entry
// included, and names the form that takes every default.
func TestAutoMembershipEntryThatIsNotAMappingIsRefused(t *testing.T) {
	for _, entry := range []string{"channel_members", "true", "[channel_members]", "", "~"} {
		appYAML := "site_name: x\nauto_memberships:\n  channels: " + entry + "\n"
		dir := t.TempDir()
		writeTestFile(t, dir, "app.yaml", appYAML)
		design := LoadAppConfigYAML(dir)
		if design == nil {
			t.Fatalf("%q: app.yaml did not load", entry)
		}
		if len(design.AutoMemberships) != 0 {
			t.Fatalf("%q: the loader read the entry (%v): the refusal below would be false", entry, design.AutoMemberships)
		}
		msg := validateAppYAML(appYAML)
		for _, want := range []string{"auto_memberships.channels", "skipped", "channels: {}"} {
			if !strings.Contains(msg, want) {
				t.Errorf("%q: the refusal lacks %q: %q", entry, want, msg)
			}
		}
	}
	for _, entry := range []string{"{}", "{table: channel_members}", "\n    table: channel_members\n    parent: channel_id"} {
		appYAML := "site_name: x\nauto_memberships:\n  channels: " + entry + "\n"
		if msg := validateAppYAML(appYAML); msg != "" {
			t.Errorf("%q is refused: %s", entry, msg)
		}
		dir := t.TempDir()
		writeTestFile(t, dir, "app.yaml", appYAML)
		if design := LoadAppConfigYAML(dir); design == nil || len(design.AutoMemberships) != 1 {
			t.Errorf("%q: the entry did not load", entry)
		}
	}
}

// `nav.theme` is the colour preset while top-level `theme:` is absent, and a
// name that is no preset selects none. The write gate refuses it with the
// presets the stylesheet has.
func TestUnknownNavThemeIsRefusedAtWriteTime(t *testing.T) {
	for _, value := range []string{"chartreuse", "Blue", "[blue]", "7"} {
		appYAML := "site_name: x\nnav:\n  theme: " + value + "\n"
		dir := t.TempDir()
		writeTestFile(t, dir, "app.yaml", appYAML)
		app := &App{Dir: dir, Design: LoadAppConfigYAML(dir)}
		if app.Design == nil || app.Design.Nav["theme"] == "" {
			t.Fatalf("nav.theme: %s did not load as the theme", value)
		}
		// The stylesheet looks the preset up by this exact name.
		if primaryVars[app.Design.Nav["theme"]+"-light"] != "" {
			t.Fatalf("nav.theme: %s selects a preset: the refusal below would be false", value)
		}
		msg := validateAppYAML(appYAML)
		for _, want := range []string{"nav.theme", "not a colour preset", "blue", "zinc"} {
			if !strings.Contains(msg, want) {
				t.Errorf("nav.theme: %s: the refusal lacks %q: %q", value, want, msg)
			}
		}
	}
	if msg := validateAppYAML("site_name: x\nnav:\n  theme: chartreus\n"); !strings.Contains(msg, "nav.theme") {
		t.Errorf("an unknown preset is accepted: %q", msg)
	}
	if msg := validateAppYAML("site_name: x\nnav:\n  theme: ble\n"); !strings.Contains(msg, "Did you mean `blue`?") {
		t.Errorf("the refusal does not offer the nearest preset: %q", msg)
	}
	for _, name := range themeNames() {
		if msg := validateAppYAML("site_name: x\nnav:\n  theme: " + name + "\n"); msg != "" {
			t.Errorf("nav.theme: %s (a preset) is refused: %s", name, msg)
		}
	}
	for _, appYAML := range []string{"site_name: x\nnav:\n  brand: \"#112233\"\n", "site_name: x\nnav:\n  theme: \"\"\n", "site_name: x\nnav: {}\n"} {
		if msg := validateAppYAML(appYAML); msg != "" {
			t.Errorf("a nav: section without a theme is refused: %s\n%s", msg, appYAML)
		}
	}
}

// A features: switch written as the number 0 or 1 is read like every other
// switch. A bare number used to leave the feature at its default: `admin: 0`
// kept the admin panel on. The write gate accepts 0 and 1 and refuses any
// other number, a list and a mapping whose `enabled:` is no switch value.
func TestFeatureSwitchWrittenAsANumberIsRead(t *testing.T) {
	onByDefault := []string{"admin", "uploads", "exports", "sse", "ws", "docs", "analytics", "account_settings", "sharing"}
	offByDefault := []string{"testing", "feedback"}
	features := func(value string) *App {
		var b strings.Builder
		b.WriteString("site_name: x\nfeatures:\n")
		for _, name := range append(append([]string{"ws_anonymous"}, onByDefault...), offByDefault...) {
			b.WriteString("  " + name + ": " + value + "\n")
		}
		if msg := validateAppYAML(b.String()); msg != "" {
			t.Errorf("the write gate refuses a features: switch written as %s: %s", value, msg)
		}
		return loadSwitchApp(t, b.String(), true)
	}
	off := features("0")
	for _, name := range append(onByDefault, offByDefault...) {
		if off.Design.Features.IsEnabled(name) {
			t.Errorf("features.%s: 0 left the feature on", name)
		}
	}
	if broadcastAllowAnon(off) {
		t.Error("features.ws_anonymous: 0 opened the anonymous gate")
	}
	on := features("1")
	for _, name := range append(onByDefault, offByDefault...) {
		if !on.Design.Features.IsEnabled(name) {
			t.Errorf("features.%s: 1 left the feature off", name)
		}
	}
	if !broadcastAllowAnon(on) {
		t.Error("features.ws_anonymous: 1 left the anonymous gate closed")
	}

	// Shapes that are no switch: refused at write time, and the load keeps
	// the feature at its default.
	for _, value := range []string{"2", "-1", "1.5", "[true]", "{enabled: sometimes}", "{enabled: [yes]}", "{enabled: 2}"} {
		appYAML := "site_name: x\nfeatures:\n  admin: " + value + "\n"
		if msg := validateAppYAML(appYAML); !strings.Contains(msg, "features.admin") {
			t.Errorf("features.admin: %s is accepted: %q", value, msg)
		}
		if app := loadSwitchApp(t, appYAML, true); !app.Design.Features.IsEnabled("admin") {
			t.Errorf("features.admin: %s turned the admin panel off", value)
		}
		if app := loadSwitchApp(t, "site_name: x\nfeatures:\n  ws_anonymous: "+value+"\n", true); broadcastAllowAnon(app) {
			t.Errorf("features.ws_anonymous: %s opened the anonymous gate", value)
		}
	}
	// A mapping that says is still accepted (and warned about, see
	// TestAppYAMLSwitchValuesNotReadAsWrittenWarn), as is one with no
	// `enabled:` at all.
	for _, value := range []string{"{enabled: no}", "{enabled: 1}", "{enabled: true}", "{limit: 5}", "{}"} {
		if msg := validateAppYAML("site_name: x\nfeatures:\n  uploads: " + value + "\n"); msg != "" {
			t.Errorf("features.uploads: %s is refused: %s", value, msg)
		}
	}
}
