//go:build !cli

package main

// app.yaml keys and values the loader accepts and never reads.
//
// The write gate refuses an unknown top-level key and an unknown key under
// auth:, csp:, groups:, features:, backup: and access.<table>:. The sections
// below are read the same way (each loader looks up a fixed set of names) and
// were not checked at all: `seo.descripton`, `pwa.nmae` or a role's `scope:`
// loaded without a word and did nothing, and `theme: chartreuse` or
// `mode: drak` picked no preset. Deployed apps carry such keys, so they stay
// accepted: the post-write check of app.yaml, `benmore check` and a dry run
// of the write warn, with the nearest key that is read.
//
// The key sets are the loaders': app_yaml_unread_test.go fails when the
// source reads a key of one of these sections that its set does not hold
// (the warning would be false), or holds a key nothing reads.

import (
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"
)

// appYAMLKeyedSection is one app.yaml section whose loader reads a fixed set
// of keys.
type appYAMLKeyedSection struct {
	// Section is the top-level key.
	Section string
	// Entries is true when the section maps names to entries (roles, custom
	// OAuth providers) and the keys are those of each entry.
	Entries bool
	// Keys are the keys the loader reads and a warning offers.
	Keys map[string]bool
	// Legacy are keys the loader also reads that a warning does not offer:
	// older spellings another section has replaced.
	Legacy map[string]bool
}

func keySet(names string) map[string]bool {
	set := map[string]bool{}
	for _, name := range strings.Fields(names) {
		set[name] = true
	}
	return set
}

var appYAMLKeyedSections = []appYAMLKeyedSection{
	{Section: "seo",
		Keys: keySet("site_name description url image favicon logo lang author org footer search_url security_contact privacy_url cookie_notice permissions_policy"),
		// CSP sources moved to csp:, billing settings to auth:, and
		// external_id is a top-level key.
		Legacy: keySet("script_src style_src img_src font_src connect_src frame_src frame_ancestors billing_publishable_key_env billing_api_key_env billing_provider billing_webhook_secret_env external_id")},
	{Section: "pwa",
		Keys: keySet("name short_name icon theme_color background_color start_url display offline offline_page service_worker")},
	{Section: "recording",
		Keys: keySet("enabled production mask_inputs")},
	{Section: "roles", Entries: true,
		Keys: keySet("scopes inherits")},
	{Section: "auto_memberships", Entries: true,
		Keys: keySet("table parent user_field members")},
	{Section: "scopes", Entries: true,
		Keys: yamlStructKeys(ScopeConfig{})},
	{Section: "oauth", Entries: true,
		Keys: keySet("auth_url token_url userinfo_url email_field name_field email_endpoint scopes trust_email")},
}

// appYAMLEnumKey is one top-level key that takes a value from a fixed set.
type appYAMLEnumKey struct {
	Key string
	// Values are the values the runtime knows and a warning offers.
	Values func() []string
	// Legacy are older values still read as one of Values.
	Legacy []string
	// Effect says what an unknown value leaves the app with.
	Effect string
}

var appYAMLEnumKeys = []appYAMLEnumKey{
	{Key: "theme", Values: themeNames, Effect: "no colour preset is selected"},
	{Key: "mode", Values: func() []string { return slices.Sorted(maps.Keys(extraVars)) }, Effect: "neither mode is selected"},
	{Key: "css", Values: func() []string { return []string{"none", "tailwind", "themed"} }, Legacy: []string{"default", "both"},
		Effect: "pages load what `tailwind` loads"},
}

// appYAMLStringKeys are the top-level keys the loader reads only as a string:
// a list, a map or a number there is dropped.
var appYAMLStringKeys = []string{"site_name", "theme", "mode", "font", "brand", "css"}

// themeNames lists the presets `theme:` selects: the ones with colours for
// both modes.
func themeNames() []string {
	var names []string
	for key := range primaryVars {
		if name, ok := strings.CutSuffix(key, "-light"); ok && primaryVars[name+"-dark"] != "" {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

// appYAMLUnreadWarnings lists one warning for each key or value of app.yaml
// content that the loader accepts and does not read. Nothing for a file that
// cannot be read as app.yaml (its own validator reports that).
func appYAMLUnreadWarnings(content string) []string {
	var doc map[string]any
	if decodeConfigYAML([]byte(content), &doc) != nil {
		return nil
	}
	var out []string
	for _, key := range appYAMLStringKeys {
		written := ""
		switch doc[key].(type) {
		case nil, string:
			continue
		case []any:
			written = "list"
		case map[string]any:
			written = "mapping"
		default:
			written = "bare number or true/false"
		}
		out = append(out, fmt.Sprintf("app.yaml: `%s:` takes text, and the %s written here is not read, so it has no effect. Write one value, in quotes when it is a number.", key, written))
	}
	for _, enum := range appYAMLEnumKeys {
		value, _ := doc[enum.Key].(string)
		values := enum.Values()
		if strings.TrimSpace(value) == "" || slices.Contains(values, value) || slices.Contains(enum.Legacy, value) {
			continue
		}
		known := map[string]bool{}
		for _, v := range values {
			known[v] = true
		}
		out = append(out, fmt.Sprintf("app.yaml: `%s: %s` is not a value the framework knows, so %s.%s Values of `%s`: %s.",
			enum.Key, value, enum.Effect, didYouMean(nearestKnownKey(value, known)), enum.Key, strings.Join(values, ", ")))
	}
	for _, section := range appYAMLKeyedSections {
		body, _ := doc[section.Section].(map[string]any)
		if !section.Entries {
			out = append(out, section.unreadKeys(section.Section, body)...)
			continue
		}
		for _, name := range slices.Sorted(maps.Keys(body)) {
			// An entry written as a string or a list (a role's scopes) has
			// no keys.
			entry, _ := body[name].(map[string]any)
			out = append(out, section.unreadKeys(section.Section+"."+name, entry)...)
		}
	}
	return append(out, appYAMLSwitchWarnings(doc)...)
}

// unreadKeys warns about each key of body, the mapping at path, that the
// section's loader does not read.
func (s appYAMLKeyedSection) unreadKeys(path string, body map[string]any) []string {
	var out []string
	for _, key := range slices.Sorted(maps.Keys(body)) {
		if s.Keys[key] || s.Legacy[key] {
			continue
		}
		suggestion := ""
		if nearest := nearestKnownKey(key, s.Keys); nearest != "" {
			suggestion = didYouMean(path + "." + nearest)
		}
		keys := "Keys under `" + s.Section + ":`"
		if s.Entries {
			keys = "Keys of each `" + s.Section + ":` entry"
		}
		out = append(out, fmt.Sprintf("app.yaml: `%s.%s` is not a key the framework reads, so it has no effect.%s %s: %s.",
			path, key, suggestion, keys, sortedKeyList(s.Keys)))
	}
	return out
}

func didYouMean(name string) string {
	if name == "" {
		return ""
	}
	return " Did you mean `" + name + "`?"
}

// appYAMLUnreadFindings is the `benmore check` and post-write finding for the
// keys and values above: warnings, never errors, so a push or a deploy of an
// app that carries one is not refused. A write of another file does not
// repeat them.
func appYAMLUnreadFindings(dir, writtenPath string, liveDB bool) []CheckFinding {
	if !liveDB && writtenPath != "" && filepath.ToSlash(filepath.Clean(writtenPath)) != "app.yaml" {
		return nil
	}
	data, err := readFileInRoot(dir, "app.yaml")
	if err != nil {
		return nil
	}
	var findings []CheckFinding
	for _, msg := range appYAMLUnreadWarnings(string(data)) {
		findings = append(findings, CheckFinding{Severity: "warning", Source: "config", File: "app.yaml", Message: msg})
	}
	return findings
}

// writeContentWarnings is what a dry run of a write (write_file with dry_run,
// `benmore validate-write`) reports beside the write gate's verdict: the
// warnings the saved write would report that the content alone decides. The
// warnings that compare the file with the rest of the app need the file on
// disk and come with the write itself and `benmore check`.
func writeContentWarnings(path, content string) CheckReport {
	path = cleanWritePath(path)
	var findings []CheckFinding
	if path == "app.yaml" {
		for _, msg := range append(appYAMLNoEffectWarnings(content), appYAMLUnreadWarnings(content)...) {
			findings = append(findings, CheckFinding{Severity: "warning", Source: "config", File: "app.yaml", Message: msg})
		}
	}
	if msg := appTestFileWarning(path, content); msg != "" {
		findings = append(findings, CheckFinding{Severity: "warning", Source: "tests", File: path, Message: msg})
	}
	findings = withFindingDocs(findings)
	return CheckReport{Findings: findings, Warnings: len(findings)}
}
