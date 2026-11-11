//go:build !cli

package main

// app.yaml keys the write gate accepts and the runtime does nothing with.
//
// The write gate's unknown-key errors print the accepted keys as "the real
// keys", so an author (usually an agent) who writes `description:` or
// `auth.public_api:` is told the file is fine and believes a meta description
// or a public table now exists. Apps carry these keys (the scaffold wrote
// `frontend.stack: html` into nearly every app), so they stay accepted: the
// write gate's post-write check and `benmore check` warn instead, and say what
// to write where something takes the key's place. `frontend` itself is listed
// without a warning (Quiet): the scaffold wrote it, no author did.
//
// One table drives the warning. app_yaml_no_effect_test.go holds, per key,
// where the loader puts the value and every place the source touches that
// place, and fails when one gains a reader (the warning must not outlive the
// fact); it also fails when the write gate accepts a top-level or auth key
// that nothing reads and that is not listed here.

import (
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"
)

// appYAMLNoEffectKey is one accepted key that changes nothing.
type appYAMLNoEffectKey struct {
	// Key is the dotted path: a top-level key ("description"), a key of a
	// section ("auth.public_api"), or a section ("nav").
	Key string
	// Replacement is what to write instead, "" when nothing takes its place:
	// another key, or a file of the app.
	Replacement string
	// Reason says, in one or two sentences, what the key does not do.
	Reason string
	// Reads lists the sub-keys of a section that are read. The section
	// warns only for its other sub-keys (or when it holds none at all).
	Reads []string
	// Quiet keeps the key in the table (accepted, documented as having no
	// effect, held to the same "nothing reads it" test) without a warning.
	// For a key an earlier scaffold wrote: nobody chose it, and a warning
	// that 269 of 289 deployed instances would show (2026-11-10) teaches
	// authors to skip the warnings that matter.
	Quiet bool
}

var appYAMLNoEffectKeys = []appYAMLNoEffectKey{
	{Key: "description", Replacement: "seo.description",
		Reason: "Pages and the web app manifest take their description from `seo.description`; a top-level `description:` is not read."},
	{Key: "database",
		Reason: "An app has one database, and nothing in this section changes how it is stored."},
	{Key: "frontend", Quiet: true,
		Reason: "Which stack serves a path follows the files, not this label: a file under static/ is served as written (TSX compiled) and a root *.html file is a server-rendered page."},
	{Key: "head", Replacement: "head.html",
		Reason: "Tags for the <head> of every server-rendered page go in a head.html file at the app root; a page under static/ writes its own <head>."},
	{Key: "radius", Replacement: "theme.css",
		Reason: "Server-rendered pages take their corner radius from the CSS variable --radius, which theme.css at the app root can set (`:root { --radius: 0.75rem; }`)."},
	{Key: "shadow",
		Reason: "No stylesheet reads it; write shadows in your own CSS or utility classes."},
	{Key: "nav", Reads: []string{"theme", "brand", "font"},
		Reason: "`nav:` draws no navigation: write the navigation in a layout or a partial."},
	{Key: "nav.theme", Replacement: "theme",
		Reason: "It is read only while top-level `theme:` is absent."},
	{Key: "auth.billing_publishable_key_env",
		Reason: "The Stripe routes use the secret key and the webhook secret only, and nothing sends a publishable key to the browser; the page that loads Stripe.js holds its own `pk_` key."},
	{Key: "auth.public_api", Replacement: "access.<table>.read: anon",
		Reason: "It does not make a table public: an anonymous request to a listed table still gets 401."},
}

// appYAMLNoEffectEntry returns the table's entry for key.
func appYAMLNoEffectEntry(key string) (appYAMLNoEffectKey, bool) {
	for _, entry := range appYAMLNoEffectKeys {
		if entry.Key == key {
			return entry, true
		}
	}
	return appYAMLNoEffectKey{}, false
}

// appYAMLNoEffectWarnings lists, in table order, one warning for each key of
// app.yaml content that has no effect. Nothing for a file that cannot be read
// as app.yaml (its own validator reports that).
func appYAMLNoEffectWarnings(content string) []string {
	var doc map[string]any
	if decodeConfigYAML([]byte(content), &doc) != nil {
		return nil
	}
	var out []string
	for _, entry := range appYAMLNoEffectKeys {
		if entry.Quiet {
			continue
		}
		section, key, nested := strings.Cut(entry.Key, ".")
		value, present := doc[section]
		if nested {
			inner, _ := value.(map[string]any)
			if _, present = inner[key]; !present {
				continue
			}
			subject := "`" + entry.Key + "` has"
			if entry.Key == "nav.theme" {
				// With `theme:` set the key is dead and the fix is to remove
				// it. Without one it is the theme, so the warning says when
				// it stops counting and to write `theme:` instead.
				if _, set := doc["theme"].(string); set {
					entry.Replacement = ""
				} else {
					subject = "once `theme:` is set, " + subject
				}
			}
			out = append(out, noEffectMessage(subject, "it", entry))
			continue
		}
		if !present {
			continue
		}
		if entry.Reads == nil {
			out = append(out, noEffectMessage("`"+entry.Key+":` has", "it", entry))
			continue
		}
		// A section with some read sub-keys: name the others.
		inner, _ := value.(map[string]any)
		var unread []string
		for _, sub := range slices.Sorted(maps.Keys(inner)) {
			if !slices.Contains(entry.Reads, sub) {
				unread = append(unread, "`"+entry.Key+"."+sub+"`")
			}
		}
		switch {
		case len(inner) == 0:
			out = append(out, noEffectMessage("`"+entry.Key+":` has", "it", entry))
		case len(unread) == 1:
			out = append(out, noEffectMessage(unread[0]+" has", "it", entry))
		case len(unread) > 1:
			out = append(out, noEffectMessage(strings.Join(unread[:len(unread)-1], ", ")+" and "+unread[len(unread)-1]+" have", "them", entry))
		}
	}
	return out
}

// noEffectMessage is one warning: what has no effect, why, and what to do.
func noEffectMessage(subject, pronoun string, entry appYAMLNoEffectKey) string {
	fix := "Remove " + pronoun + "."
	if entry.Replacement != "" {
		fix = "Use `" + entry.Replacement + "` instead."
	}
	return fmt.Sprintf("app.yaml: %s no effect. %s %s", subject, entry.Reason, fix)
}

// appYAMLNoEffectFindings is the `benmore check` and post-write finding for
// app.yaml keys that have no effect: warnings, never errors, so a push or a
// deploy of an app that carries one is not refused. A write of another file
// does not repeat them.
func appYAMLNoEffectFindings(dir, writtenPath string, liveDB bool) []CheckFinding {
	if !liveDB && writtenPath != "" && filepath.ToSlash(filepath.Clean(writtenPath)) != "app.yaml" {
		return nil
	}
	data, err := readFileInRoot(dir, "app.yaml")
	if err != nil {
		return nil
	}
	var findings []CheckFinding
	for _, msg := range appYAMLNoEffectWarnings(string(data)) {
		findings = append(findings, CheckFinding{Severity: "warning", Source: "config", File: "app.yaml", Message: msg})
	}
	return findings
}
