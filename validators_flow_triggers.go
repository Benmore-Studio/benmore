//go:build !cli

package main

// Trigger-shape checks for GHA flow files that the loader applies
// leniently. Each of these parsed clean and then behaved differently from
// what the file said: an on.schedule cron the scheduler can't evaluate
// never fired and a second trigger in the same `on:` was dropped. (An
// unknown on.request auth/mode or on.event op/table is checked by
// flowTriggerValueViolation; an unknown auth reads as required.) The write gate and
// `benmore check` refuse them (validateFlowsYAML); a deployed file still
// loads and parseGHAFlowFile logs the problem.

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// flowTriggerProblems lists what a GHA flow file's `on:` block declares that
// the runtime would ignore or read differently.
func flowTriggerProblems(file FlowFileGHA) []string {
	var problems []string
	on := file.On
	declared := []string{}
	if on.Request != nil {
		declared = append(declared, "request")
		if _, err := parseFlowOpenAPIContract(on.Request); err != nil {
			problems = append(problems, err.Error())
		}
		if _, err := flowStrictJSONFlag(on.Request.StrictJSON); err != nil {
			problems = append(problems, "flows.yaml: on.request.strict_json must be a YAML boolean (`true` or `false`).")
		}
		if name, ok := on.Request.Verify.(string); ok {
			if msg := flowVerifyNameProblem(name); msg != "" {
				problems = append(problems, msg)
			}
		}
		if msg := flowVerifySecretProblem(on.Request); msg != "" {
			problems = append(problems, msg)
		}
	}
	if on.Schedule != nil {
		declared = append(declared, "schedule")
	}
	if on.Event != nil {
		declared = append(declared, "event")
	}
	if len(declared) > 1 {
		problems = append(problems, fmt.Sprintf("flows.yaml: `on:` declares %s, but a flow file has one trigger; only `%s` would be used. Put each trigger in its own file under flows/ (they can share steps through a named flow or cron `flow:`).",
			strings.Join(declared, " and "), declared[0]))
	}
	if on.Schedule != nil {
		expr := strings.TrimSpace(on.Schedule.Cron)
		if expr == "" {
			problems = append(problems, "flows.yaml: on.schedule needs `cron:` (e.g. `cron: \"0 9 * * 1\"` or `cron: \"every 15m\"`); without it the flow never runs.")
		} else if err := validateCronSchedule(expr); err != nil {
			problems = append(problems, fmt.Sprintf("flows.yaml: on.schedule cron %q: %s. The scheduler can't evaluate it, so the flow would never run. Use five cron fields (minute hour day month weekday, weekday 0-6), @hourly/@daily/@weekly/@monthly/@yearly, or `every <Go duration>` such as every 15m or every 24h.", expr, err))
		}
	}
	return problems
}

// verifyHeaderNameRe is the header-name form of `verify:`: hyphen-joined
// tokens such as X-Webhook-Signature. Requiring the hyphen is what tells a
// header apart from a misspelled provider (`strpe`, `githb`).
var verifyHeaderNameRe = regexp.MustCompile(`^[A-Za-z0-9]+(-[A-Za-z0-9]+)+$`)

// verifyProviderOwnHeaders are provider signature headers the header form
// can't check (a timestamped or base64 signature, not a hex body HMAC):
// written as `verify:`, every real request would get 401.
var verifyProviderOwnHeaders = map[string]string{
	"stripe-signature":      "stripe",
	"x-slack-signature":     "slack",
	"x-shopify-hmac-sha256": "shopify",
}

// flowVerifyNameProblem explains why a string `verify:` value names neither
// a provider (verifyProviderNames) nor a header the runtime can check. Such
// a value used to run a lenient generic verifier (flows_verify.go); it now
// checks one header, so a typo fails every request instead of passing
// headers the author never named. The loader still loads the file and logs
// this; the write gate and `benmore check` refuse it.
func flowVerifyNameProblem(name string) string {
	if name == "" {
		return ""
	}
	lower := strings.ToLower(name)
	if slices.Contains(verifyProviderNames, lower) {
		return ""
	}
	const forms = " Use a provider (`verify: stripe`, `github`, `github_sha256`, `shopify`, `slack`, or `benmore` for another Benmore app's webhook subscription), a header name containing a hyphen (`verify: X-Webhook-Signature`: that header must carry hex(HMAC-SHA256(secret, raw body)) and is the only one read), or the map form `verify: { recipe: hmac_sha256_body, header: ..., secret: ... }` (api(at:\"verify\"))."
	if provider, ok := verifyProviderOwnHeaders[lower]; ok {
		return fmt.Sprintf("flows.yaml: on.request.verify %q is %s's own signature header, which the header form can't check (it compares a hex HMAC of the body), so every real request would get 401. Did you mean `verify: %s`?", name, provider, provider)
	}
	if verifyHeaderNameRe.MatchString(name) {
		return ""
	}
	recipes := []string{"hmac_sha256_body", "hmac_timestamp_dot_body", "hmac_sha1_body", "hmac_sha256_path_bearer"}
	for _, recipe := range recipes {
		if levenshtein(lower, recipe) <= 2 {
			return fmt.Sprintf("flows.yaml: on.request.verify %q looks like the recipe `%s`, which takes the map form: `verify: { recipe: %s, header: ..., secret: ... }` (api(at:\"verify\") lists each recipe's keys).", name, recipe, recipe)
		}
	}
	hint := ""
	best := 3
	for _, provider := range verifyProviderNames {
		if d := levenshtein(lower, provider); d < best {
			best, hint = d, provider
		}
	}
	if hint != "" {
		return fmt.Sprintf("flows.yaml: on.request.verify %q is not a known verifier. Did you mean `verify: %s`?%s", name, hint, forms)
	}
	return fmt.Sprintf("flows.yaml: on.request.verify %q is not a known verifier.%s", name, forms)
}

// flowVerifySecretProblem explains an on.request whose `secret:` and
// `verify:` don't go together. The loader reads them as written, so each of
// these loaded clean and behaved differently from what the file says:
//
//   - `secret:` with no `verify:` checks nothing: the route answers unsigned
//     requests although the file reads as a verified receiver;
//   - a string `verify:` (a provider or a header name) takes its secret
//     from on.request.secret, and without one every request gets 401 (the
//     map form already refused a missing secret);
//   - with the map form, on.request.secret is not read: the map's own
//     `secret:` is the one used.
//
// Write gate and `benmore check` only; a deployed file still loads, and
// parseGHAFlowFile logs the problem.
func flowVerifySecretProblem(req *FlowRequestTrigger) string {
	if req == nil {
		return ""
	}
	secret := strings.TrimSpace(req.Secret) != ""
	switch verify := req.Verify.(type) {
	case nil:
		if secret {
			return "flows.yaml: on.request.secret is set but the flow has no `verify:`, so nothing checks a signature and the route accepts unsigned requests. Add the verifier the sender signs with (`verify: stripe`, `github`, `shopify`, `slack`, `benmore`, a header name, or the map form `verify: { recipe: ... }`; api(at:\"verify\")), or remove `secret:`."
		}
	case string:
		if strings.TrimSpace(verify) == "" {
			if secret {
				return "flows.yaml: on.request.secret is set but `verify:` is empty, so nothing checks a signature and the route accepts unsigned requests. Name the verifier the sender signs with (`verify: stripe`, `github`, `shopify`, `slack`, `benmore` or a header name; api(at:\"verify\")), or remove `secret:`."
			}
			return ""
		}
		if !secret {
			return fmt.Sprintf("flows.yaml: on.request.verify %q needs `secret:` beside it on on.request (`secret: \"${{ env.WEBHOOK_SECRET }}\"`, with the value set by `benmore env`); without one every request is refused with 401.", verify)
		}
	case map[string]any:
		if secret {
			return "flows.yaml: on.request.secret is not read when `verify:` is a map; the map's own `secret:` is the one used. Remove on.request.secret (put the secret inside `verify:`)."
		}
	}
	return ""
}
