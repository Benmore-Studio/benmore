//go:build !cli

package main

// app.yaml switches: one reading of true and false.
//
// yaml.v3 hands `no`, `off`, `yes` and `on` over as text and a bare `0`/`1`
// as a number; only true/false arrive as booleans. A loader that compares a
// switch to the text "false" therefore leaves `enabled: no` switched ON, and
// the author believes it is off. Every switch below is read through
// canonicalAuthFlag, the reading the auth: flags have.
//
// A value that is no spelling of either keeps the meaning it had, and the
// post-write check of app.yaml, `benmore check` and a dry run of the write
// warn about it (appYAMLSwitchWarnings), with what the value leaves the app
// with.
//
// Two values decide who signs in and are stricter: `auth.identifier` is read
// in any letter case (canonicalAuthIdentifier) and a custom provider's
// `trust_email` in every spelling of true and false (trustEmailSetting). A
// value that is neither is refused by the write gate and `benmore check`
// (authIdentifierAppYAMLProblem, trustEmailAppYAMLProblem), and an app that
// carries one signs in by email and gives the provider no trust.

import (
	"fmt"
	"maps"
	"slices"
	"strings"
)

// recordingSwitchKeys are the recording: keys the recorder compares to
// "true"/"false", each with what a value that is neither leaves in place.
var recordingSwitchKeys = map[string]string{
	"enabled":     "the recorder is not turned off",
	"production":  "production is not recorded",
	"mask_inputs": "typed values stay masked",
}

// authIdentifierValues are the sign-in identifiers; any other value means email.
var authIdentifierValues = map[string]bool{"email": true, "username": true, "phone": true}

// canonicalAuthIdentifier maps a written auth.identifier onto email, username
// or phone, whatever its letter case and surrounding space: `Username` used
// to be compared to the lower-case word and meant email. ok is false for a
// value that is none of the three; one left empty is not set.
func canonicalAuthIdentifier(v string) (string, bool) {
	id := strings.ToLower(strings.TrimSpace(v))
	if authIdentifierValues[id] {
		return id, true
	}
	return v, id == ""
}

// authIdentifierAppYAMLProblem is the write gate's and `benmore check`'s
// refusal of an auth.identifier that is no identifier. The load keeps
// reading such a value as email.
func authIdentifierAppYAMLProblem(doc map[string]any) string {
	auth, _ := doc["auth"].(map[string]any)
	v := auth["identifier"]
	text, isText := v.(string)
	if v == nil {
		return ""
	}
	if isText {
		if _, ok := canonicalAuthIdentifier(text); ok {
			return ""
		}
	}
	return fmt.Sprintf("app.yaml: auth.identifier = %s is not a sign-in identifier. Use email (the default), username or phone, in any letter case. With any other value accounts sign in by email.%s",
		writtenValue(v), didYouMean(nearestKnownKey(text, authIdentifierValues)))
}

// trustEmailSetting reads a custom provider's trust_email. Every spelling of
// true gives the trust: `yes`, `on` and `1` used to be read as false, because
// YAML hands them over as text and a number. known is false for a value that
// is no spelling of true or false, which gives no trust.
func trustEmailSetting(v any) (trusted, known bool) {
	switch value := v.(type) {
	case nil:
		return false, true
	case bool:
		return value, true
	case string, int, int64, uint64:
		canon, ok := canonicalAuthFlag(anyToString(value))
		return ok && canon == "true", ok
	}
	return false, false
}

// trustEmailAppYAMLProblem is the write gate's and `benmore check`'s refusal
// of a trust_email that is no spelling of true or false.
func trustEmailAppYAMLProblem(doc map[string]any) string {
	providers, _ := doc["oauth"].(map[string]any)
	for _, name := range slices.Sorted(maps.Keys(providers)) {
		entry, _ := providers[name].(map[string]any)
		v := entry["trust_email"]
		if _, known := trustEmailSetting(v); known {
			continue
		}
		return fmt.Sprintf("app.yaml: oauth.%s.trust_email = %s is not a boolean. Use `true` or `false` (yes/no, on/off and 1/0 are read the same way). With any other value the provider's addresses are not trusted. Write `true` only when the provider verifies every address it returns.",
			name, writtenValue(v))
	}
	return ""
}

// canonicalSwitchValues rewrites the switches of a loaded section onto
// "true"/"false". A key left empty is not set and keeps its default.
func canonicalSwitchValues(section, keys map[string]string) {
	for key := range keys {
		value := section[key]
		if strings.TrimSpace(value) == "" {
			continue
		}
		if canon, ok := canonicalAuthFlag(value); ok {
			section[key] = canon
		}
	}
}

// featureSwitchValue reads one features: switch; nil (the feature's default)
// for a value that is no switch at all, which the write gate refuses.
//
// Text that is no spelling of true or false ("auth", "public") counts as on,
// and so does a mapping without an `enabled:` that says, as both always
// have. ws_anonymous is the exception: it opens a gate, so it needs a value
// that says so. A mapping used to count as on whatever it held, which read
// `uploads: {enabled: no}` as on and `ws_anonymous: {enabled: no}` as open.
func featureSwitchValue(key string, v any) *bool {
	said := func(text string) *bool {
		canon, known := canonicalAuthFlag(text)
		if strings.TrimSpace(text) == "" {
			known = false
		}
		on := canon == "true" || (!known && key != "ws_anonymous")
		return &on
	}
	switch value := v.(type) {
	case bool:
		return &value
	case string:
		return said(value)
	case map[string]any:
		return said(anyToString(value["enabled"]))
	}
	return nil
}

// writtenValue names a value in a warning: by its shape when it is not a scalar.
func writtenValue(v any) string {
	switch v.(type) {
	case map[string]any:
		return "the mapping written here"
	case []any:
		return "the list written here"
	}
	return "`" + strings.TrimSpace(anyToString(v)) + "`"
}

// appYAMLSwitchWarnings lists one warning for each switch of a parsed
// app.yaml whose value is not read the way it is written.
func appYAMLSwitchWarnings(doc map[string]any) []string {
	var out []string
	features, _ := doc["features"].(map[string]any)
	for _, key := range slices.Sorted(maps.Keys(features)) {
		if _, isMapping := features[key].(map[string]any); !isMapping || !featureKeys[key] {
			continue
		}
		state := "off"
		if on := featureSwitchValue(key, features[key]); on != nil && *on {
			state = "on"
		}
		out = append(out, fmt.Sprintf("app.yaml: `features.%s` takes true or false (yes/no and on/off mean the same), and of the mapping written here only `enabled:` is read, so the switch is %s and its other keys have no effect. Write `%s: true` or `%s: false`.",
			key, state, key, key))
	}
	recording, _ := doc["recording"].(map[string]any)
	for _, key := range slices.Sorted(maps.Keys(recordingSwitchKeys)) {
		v, set := recording[key]
		if !set || strings.TrimSpace(anyToString(v)) == "" {
			continue
		}
		if _, ok := canonicalAuthFlag(anyToString(v)); !ok {
			out = append(out, fmt.Sprintf("app.yaml: `recording.%s` takes true or false (yes/no, on/off and 1/0 mean the same), and %s is neither, so %s.",
				key, writtenValue(v), recordingSwitchKeys[key]))
		}
	}
	return out
}
