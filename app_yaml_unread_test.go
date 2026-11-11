//go:build !cli && !windows

package main

import (
	"maps"
	"os"
	"slices"
	"strings"
	"testing"
)

// app.yaml keys and values the loader accepts and does not read
// (app_yaml_unread.go).
//
// Three things are held here:
//
//  1. each such key or value is accepted by the write gate and warned about,
//     by the post-write check of app.yaml and by `benmore check`, with the
//     nearest key that is read;
//  2. nothing that is read is warned about: every key of every set, the
//     scaffold's app.yaml and the legacy spellings load without a warning;
//  3. the sets are the loaders': a key the source reads from one of these
//     sections is in its set, and every key of a set is read.

const unreadBaseYAML = "site_name: \"Unread\"\nauth:\n  identifier: email\n"

func unreadWarningsOf(t *testing.T, appYAML string) (afterWrite, check []string) {
	t.Helper()
	dir := noEffectDir(t, unreadBaseYAML)
	if msg := ValidateOnWriteIn(dir, "app.yaml", appYAML); msg != "" {
		t.Fatalf("the write gate refuses content apps carry: %s", msg)
	}
	writeTestFile(t, dir, "app.yaml", appYAML)
	written, full := RunSourceCheck(dir, "app.yaml"), RunSourceCheck(dir, "")
	for name, report := range map[string]CheckReport{"the post-write check": written, "benmore check": full} {
		if report.Errors != 0 {
			t.Errorf("%s reports %d error(s): %+v", name, report.Errors, report.Findings)
		}
	}
	writeTestFile(t, dir, "tests/smoke.yaml", "smoke:\n  steps:\n    - get: \"/health\"\n      expect:\n        status: 200\n")
	if got := noEffectWarningsIn(RunSourceCheck(dir, "tests/smoke.yaml")); len(got) != 0 {
		t.Errorf("a write of another file repeats the warning: %q", got)
	}
	return noEffectWarningsIn(written), noEffectWarningsIn(full)
}

// One case per section and per value: the write gate accepts the content and
// both checks answer with exactly these warnings.
func TestAppYAMLKeysAndValuesNothingReadsWarn(t *testing.T) {
	const (
		seoKeys = "Keys under `seo:`: author, cookie_notice, description, favicon, footer, image, lang, logo, org, permissions_policy, privacy_url, search_url, security_contact, site_name, url."
		pwaKeys = "Keys under `pwa:`: background_color, display, icon, name, offline, offline_page, service_worker, short_name, start_url, theme_color."
		themes  = "Values of `theme`: blue, gray, green, neutral, orange, red, rose, slate, stone, violet, yellow, zinc."
	)
	for _, c := range []struct {
		name, yaml string
		want       []string
	}{
		{"a misspelled seo key", "seo:\n  descripton: \"typo key\"\n  description: \"read\"\n",
			[]string{"app.yaml: `seo.descripton` is not a key the framework reads, so it has no effect. Did you mean `seo.description`? " + seoKeys}},
		{"an seo key with no near match", "seo:\n  keywords: \"a, b\"\n",
			[]string{"app.yaml: `seo.keywords` is not a key the framework reads, so it has no effect. " + seoKeys}},
		{"a misspelled pwa key", "pwa:\n  nmae: Tracker\n  short_name: T\n",
			[]string{"app.yaml: `pwa.nmae` is not a key the framework reads, so it has no effect. Did you mean `pwa.name`? " + pwaKeys}},
		{"a recording key", "recording:\n  enabled: \"true\"\n  mask: \"false\"\n",
			[]string{"app.yaml: `recording.mask` is not a key the framework reads, so it has no effect. Did you mean `recording.mask_inputs`? Keys under `recording:`: enabled, mask_inputs, production."}},
		{"a role's scope for scopes", "roles:\n  manager:\n    scope: [\"notes:read\"]\n  viewer: \"notes:read\"\n  editor: [\"notes:read\", \"notes:write\"]\n",
			[]string{"app.yaml: `roles.manager.scope` is not a key the framework reads, so it has no effect. Did you mean `roles.manager.scopes`? Keys of each `roles:` entry: inherits, scopes."}},
		{"an auto_memberships key", "auto_memberships:\n  notes:\n    table: note_members\n    member: all_users\n",
			[]string{"app.yaml: `auto_memberships.notes.member` is not a key the framework reads, so it has no effect. Did you mean `auto_memberships.notes.members`? Keys of each `auto_memberships:` entry: members, parent, table, user_field."}},
		{"a scopes key", "scopes:\n  notes:\n    public_read: \"title != ''\"\n",
			[]string{"app.yaml: `scopes.notes.public_read` is not a key the framework reads, so it has no effect. Did you mean `scopes.notes.public_read_when`? Keys of each `scopes:` entry: public_read_when."}},
		{"a custom OAuth provider key", "oauth:\n  custom:\n    auth_url: https://identity.example.com/authorize\n    token_url: https://identity.example.com/token\n    user_info_url: https://identity.example.com/userinfo\n",
			[]string{"app.yaml: `oauth.custom.user_info_url` is not a key the framework reads, so it has no effect. Did you mean `oauth.custom.userinfo_url`? Keys of each `oauth:` entry: auth_url, email_endpoint, email_field, name_field, scopes, token_url, trust_email, userinfo_url."}},
		{"a theme that is not one", "theme: chartreuse\n",
			[]string{"app.yaml: `theme: chartreuse` is not a value the framework knows, so no colour preset is selected. " + themes}},
		{"a theme in another case", "theme: Zinc\n",
			[]string{"app.yaml: `theme: Zinc` is not a value the framework knows, so no colour preset is selected. Did you mean `zinc`? " + themes}},
		{"a list of themes", "theme: [zinc, blue]\n",
			[]string{"app.yaml: `theme:` takes text, and the list written here is not read, so it has no effect. Write one value, in quotes when it is a number."}},
		{"a misspelled mode", "mode: drak\n",
			[]string{"app.yaml: `mode: drak` is not a value the framework knows, so neither mode is selected. Did you mean `dark`? Values of `mode`: dark, light."}},
		{"a misspelled css", "css: themd\n",
			[]string{"app.yaml: `css: themd` is not a value the framework knows, so pages load what `tailwind` loads. Did you mean `themed`? Values of `css`: none, tailwind, themed."}},
		{"a brand that YAML reads as a number", "brand: 336699\n",
			[]string{"app.yaml: `brand:` takes text, and the bare number or true/false written here is not read, so it has no effect. Write one value, in quotes when it is a number."}},
	} {
		t.Run(c.name, func(t *testing.T) {
			afterWrite, check := unreadWarningsOf(t, unreadBaseYAML+c.yaml)
			if !slices.Equal(afterWrite, c.want) {
				t.Errorf("the post-write check of app.yaml:\n got %q\nwant %q", afterWrite, c.want)
			}
			if !slices.Equal(check, c.want) {
				t.Errorf("benmore check:\n got %q\nwant %q", check, c.want)
			}
		})
	}
}

// The app.yaml a builder reported: every key and value in it that does
// nothing is named, each once, and the file still pushes.
func TestAppYAMLReportedMistakesAreAllNamed(t *testing.T) {
	const reported = `site_name: "Tracker"
theme: chartreuse
mode: drak
auth: {identifier: email, session_duration: "30d", signup_fields: "first_name", public_api: notes}
features: {testing: true}
seo: {descripton: "typo key"}
pwa: {nmae: Tracker}
roles: {manager: {scope: ["notes:read"]}}
access: {ghosts: {read: everyone}}
`
	afterWrite, check := unreadWarningsOf(t, reported)
	if !slices.Equal(afterWrite, check) {
		t.Errorf("the two checks differ:\n write %q\n check %q", afterWrite, check)
	}
	for _, named := range []string{"`auth.public_api` has no effect", "`theme: chartreuse` is not a value", "`mode: drak` is not a value", "`seo.descripton` is not a key", "`pwa.nmae` is not a key", "`roles.manager.scope` is not a key"} {
		n := 0
		for _, msg := range afterWrite {
			if strings.Contains(msg, named) {
				n++
			}
		}
		if n != 1 {
			t.Errorf("%q is named %d times, want once, in %q", named, n, afterWrite)
		}
	}
	if len(afterWrite) != 6 {
		t.Errorf("%d warnings, want 6: %q", len(afterWrite), afterWrite)
	}
}

// Every warning carries the address of the key that documents it.
func TestAppYAMLUnreadWarningsCarryTheirDocs(t *testing.T) {
	dir := noEffectDir(t, unreadBaseYAML+"theme: chartreuse\nbrand: 336699\nseo:\n  descripton: x\n")
	got := map[string]string{}
	for _, f := range RunSourceCheck(dir, "app.yaml").Findings {
		if f.Source == "config" {
			got[strings.SplitN(strings.TrimPrefix(f.Message, "app.yaml: "), " ", 2)[0]] = f.Docs
		}
	}
	want := map[string]string{"`theme:": "ssr.appearance", "`brand:`": "recovery.configuration_loading", "`seo.descripton`": "recovery.configuration_loading"}
	if !maps.Equal(got, want) {
		t.Errorf("docs:\n got %v\nwant %v", got, want)
	}
}

// Nothing that is read is warned about: every key of every set and every
// known value, the legacy spellings, the shapes without keys, and what the
// scaffold writes.
func TestAppYAMLReadKeysAndValuesAreNotReported(t *testing.T) {
	var b strings.Builder
	b.WriteString("site_name: \"Everything\"\nfont: Inter\nbrand: \"#336699\"\n")
	for _, section := range appYAMLKeyedSections {
		b.WriteString(section.Section + ":\n")
		indent := "  "
		if section.Entries {
			b.WriteString("  entry:\n")
			indent = "    "
		}
		for _, key := range slices.Sorted(maps.Keys(section.Keys)) {
			value := "\"x\""
			if section.Section == "recording" || key == "trust_email" {
				value = "true" // a switch: a value that is neither true nor false has its own warning
			}
			b.WriteString(indent + key + ": " + value + "\n")
		}
		for _, key := range slices.Sorted(maps.Keys(section.Legacy)) {
			b.WriteString(indent + key + ": \"x\"\n")
		}
		if section.Section == "roles" {
			b.WriteString("  as_text: \"notes:read\"\n  as_list: [\"notes:read\"]\n")
		}
	}
	if got := appYAMLUnreadWarnings(b.String()); len(got) != 0 {
		t.Errorf("keys that are read are reported: %q\n%s", got, b.String())
	}
	for _, enum := range appYAMLEnumKeys {
		for _, value := range append(enum.Values(), enum.Legacy...) {
			if got := appYAMLUnreadWarnings(enum.Key + ": " + value + "\n"); len(got) != 0 {
				t.Errorf("%s: %s is reported: %q", enum.Key, value, got)
			}
		}
		if len(enum.Values()) < 2 {
			t.Errorf("%s has the values %v", enum.Key, enum.Values())
		}
	}
	for _, clean := range []string{"", "site_name: x\n", "theme: \"\"\nmode:\n", "site_name: [\n", "seo: {}\nroles: {}\n"} {
		if got := appYAMLUnreadWarnings(clean); len(got) != 0 {
			t.Errorf("%q is reported: %q", clean, got)
		}
	}
	dir := t.TempDir()
	if err := WriteHTMLScaffoldFiles(dir, "Scaffold"); err != nil {
		t.Fatal(err)
	}
	scaffold, err := os.ReadFile(dir + "/app.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if got := appYAMLUnreadWarnings(string(scaffold)); len(got) != 0 {
		t.Errorf("the scaffold's app.yaml is reported: %q", got)
	}
}

// An unknown `css:` value really is `tailwind`: the app serves the same pages.
func TestUnknownCSSValueServesWhatTailwindServes(t *testing.T) {
	base := "site_name: \"No effect\"\ntheme: zinc\nauth:\n  identifier: email\n"
	unknown, tailwind, themed := noEffectServed(t, base+"css: themd\n"), noEffectServed(t, base+"css: tailwind\n"), noEffectServed(t, base+"css: themed\n")
	for path, body := range tailwind {
		if unknown[path] != body {
			t.Errorf("%s differs between css: themd and css: tailwind", path)
		}
	}
	if maps.Equal(tailwind, themed) {
		t.Fatal("css: themed serves what css: tailwind serves, so this test shows nothing")
	}
}

// The key sets are the loaders'. Each section's keys are read by name in the
// places listed here; a key read there that the set does not hold would be
// warned about while it works, and a key of the set that nothing reads would
// be offered as a fix.
func TestAppYAMLKeyedSectionsMatchTheLoaders(t *testing.T) {
	index := runtimeSourceIndex(t)
	// Where a section's keys are indexed by name: `<base> ` for a field of
	// the loaded configuration, `<base> <file>:<func>` for a local variable.
	indexed := map[string][]string{
		"seo":              {"SEO "},
		"pwa":              {"PWA "},
		"recording":        {"Recording ", "rec recorder.go:IsRecordingEnabled"},
		"roles":            {"val config.go:parseRolesConfig"},
		"auto_memberships": {"entry config.go:parseAutoMembershipConfig"},
		"oauth":            {"cfg oauth.go:oauthProvidersForApp"},
	}
	// Keys read through a name passed to a helper, with the file that passes it.
	passed := map[string]map[string]string{
		"seo": {"script_src": "server.go", "style_src": "server.go", "img_src": "server.go", "font_src": "server.go",
			"connect_src": "server.go", "frame_src": "server.go", "frame_ancestors": "server.go"},
		"pwa": {"offline_page": "pwa.go", "service_worker": "pwa.go"},
	}
	for _, section := range appYAMLKeyedSections {
		if section.Section == "scopes" {
			continue // its keys are the yaml tags of the struct the loader decodes into
		}
		read := map[string]bool{}
		for probe, places := range index.refs {
			key, ok := strings.CutPrefix(probe, "idx ")
			if !ok {
				continue
			}
			for where := range places {
				for _, prefix := range indexed[section.Section] {
					if strings.HasPrefix(where, prefix) {
						read[key] = true
					}
				}
			}
		}
		if len(read) == 0 {
			t.Errorf("%s: the source indexes no key at %v; the loader moved, so name its new place", section.Section, indexed[section.Section])
		}
		for key, file := range passed[section.Section] {
			found := false
			for where := range index.refs["lit "+key] {
				found = found || strings.HasPrefix(where, file+":")
			}
			if !found {
				t.Errorf("%s.%s: %s no longer passes it by name", section.Section, key, file)
				continue
			}
			read[key] = true
		}
		known := maps.Clone(section.Keys)
		maps.Copy(known, section.Legacy)
		for _, key := range slices.Sorted(maps.Keys(read)) {
			if !known[key] {
				t.Errorf("the source reads %s.%s and the set does not hold it: a working key would be warned about. Add it to appYAMLKeyedSections.", section.Section, key)
			}
		}
		for _, key := range slices.Sorted(maps.Keys(known)) {
			if !read[key] {
				t.Errorf("the set holds %s.%s and nothing reads it: remove it from appYAMLKeyedSections.", section.Section, key)
			}
		}
	}
	// A theme is a preset with colours for both modes; the modes are the ones
	// the shared variables exist for.
	if themes := themeNames(); !slices.Contains(themes, "zinc") || !slices.Contains(themes, "blue") || len(themes)*2 != len(primaryVars) {
		t.Errorf("themes %v for %d preset tables", themes, len(primaryVars))
	}
}

// A dry run of a write reports the warnings the content alone decides, with
// their docs, and nothing for a file that has none.
func TestWriteContentWarnings(t *testing.T) {
	report := writeContentWarnings("./app.yaml", unreadBaseYAML+"description: x\nmode: drak\n")
	var got []string
	for _, f := range report.Findings {
		subject, _, _ := strings.Cut(strings.TrimPrefix(f.Message, "app.yaml: "), "` ")
		got = append(got, f.Severity+" "+f.Source+" "+f.File+" "+f.Docs+" "+subject+"`")
	}
	want := []string{
		"warning config app.yaml frontend.site_identity `description:`",
		"warning config app.yaml ssr.appearance `mode: drak`",
	}
	if !slices.Equal(got, want) || report.Warnings != 2 || report.Errors != 0 {
		t.Errorf("app.yaml: %d warning(s), %d error(s)\n got %q\nwant %q", report.Warnings, report.Errors, got, want)
	}
	tests := writeContentWarnings("tests/smoke.yaml", "smoke:\n  step:\n    - get: \"/health\"\n")
	if len(tests.Findings) != 1 || tests.Findings[0].Source != "tests" || tests.Findings[0].Docs != "verification.test_file_load" || tests.Findings[0].File != "tests/smoke.yaml" {
		t.Errorf("a tests file the runner cannot load: %+v", tests.Findings)
	}
	for path, content := range map[string]string{
		"app.yaml":         unreadBaseYAML,
		"flows/a.yaml":     "theme: chartreuse\n",
		"tests/smoke.yaml": "smoke:\n  steps:\n    - get: \"/health\"\n      expect:\n        status: 200\n",
	} {
		if r := writeContentWarnings(path, content); len(r.Findings) != 0 || r.Warnings != 0 {
			t.Errorf("%s: %+v", path, r.Findings)
		}
	}
}
