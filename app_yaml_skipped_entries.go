//go:build !cli

package main

// app.yaml entries the loader skips whole, and one value it reads as a name
// that selects nothing.
//
//   - An `oauth:` entry named after a built-in provider (google, github,
//     microsoft). The loader adds new names only, so nothing in the entry is
//     read. Accepted, with a warning that says so and names the keys written.
//   - An `auto_memberships:` entry that is not a mapping (`channels: true`,
//     an empty `channels:`). No hook is made for it and nobody is enrolled.
//     Refused by the write gate and `benmore check`.
//   - `nav.theme` set to a name that is no colour preset. Refused by the
//     write gate and `benmore check`; top-level `theme:` keeps its warning
//     (app_yaml_unread.go).
//
// None of the three changes what a loaded app does.

import (
	"fmt"
	"maps"
	"slices"
	"strings"
)

// oauthBuiltInEntryWarning is the warning for the `oauth:` entry called name
// when a built-in provider has that name ("" otherwise).
func oauthBuiltInEntryWarning(name string, entry any) string {
	builtIn, ok := oauthProviders[name]
	if !ok {
		return ""
	}
	written := "nothing in it is read"
	if body, _ := entry.(map[string]any); len(body) > 0 {
		written = "none of its keys (" + strings.Join(slices.Sorted(maps.Keys(body)), ", ") + ") is read"
	}
	env := strings.ToUpper(name)
	return fmt.Sprintf("app.yaml: `oauth.%s` is named after a built-in provider, so the entry is skipped: %s, and %s sign-in keeps its built-in endpoints, scopes and fields. %s_CLIENT_ID and %s_CLIENT_SECRET in the app's environment are what configure it. Remove the entry, or give it another name to add a provider of your own.",
		name, written, builtIn.Name, env, env)
}

// autoMembershipEntryProblem is the write gate's and `benmore check`'s
// refusal of an auto_memberships: entry that is not a mapping. The loader
// skips such an entry.
func autoMembershipEntryProblem(doc map[string]any) string {
	entries, _ := doc["auto_memberships"].(map[string]any)
	for _, parent := range slices.Sorted(maps.Keys(entries)) {
		if _, ok := entries[parent].(map[string]any); ok {
			continue
		}
		written := "is empty"
		if entries[parent] != nil {
			written = "is " + writtenValue(entries[parent])
		}
		return fmt.Sprintf("app.yaml: auto_memberships.%s %s, and an entry that is not a mapping is skipped: nobody is enrolled when a %s row is created. Write `%s: {}` to take every default, or a mapping with any of the keys %s.",
			parent, written, parent, parent, sortedKeyList(keySet("table parent user_field members")))
	}
	return ""
}

// navThemeAppYAMLProblem is the write gate's and `benmore check`'s refusal of
// a nav.theme that names no colour preset. The stylesheet looks the preset up
// by that exact name (themeNames lists the ones it has).
func navThemeAppYAMLProblem(doc map[string]any) string {
	nav, _ := doc["nav"].(map[string]any)
	v, set := nav["theme"]
	if !set || strings.TrimSpace(anyToString(v)) == "" {
		return ""
	}
	names := themeNames()
	text, isText := v.(string)
	if isText && slices.Contains(names, text) {
		return ""
	}
	known := map[string]bool{}
	for _, name := range names {
		known[name] = true
	}
	return fmt.Sprintf("app.yaml: nav.theme = %s is not a colour preset, so it selects none.%s Presets: %s. Write the preset as top-level `theme:`; `nav.theme` is read only while `theme:` is absent.",
		writtenValue(v), didYouMean(nearestKnownKey(text, known)), strings.Join(names, ", "))
}
