//go:build !cli

package main

// Step values the runtime cannot honor as written.
//
// flowStepKeyProblems decides which keys a step type reads; this decides
// whether the values of five of them can be sent: a webhook's JSON body
// (`payload:`, or `body:` as a map or list), a respond step's `status`,
// `content_type` and `headers`, an api step's `body:` written as a map or
// list, and an email's `unsubscribe_url`. The write gate and `benmore check`
// refuse each problem; the loader logs the same line for a deployed file,
// which keeps loading and drops what it cannot send (a refused header, a
// second body) or fails the step when it runs (a status that is not one, an
// unsubscribe URL that is not https).

import (
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

// flowStepValueProblems lists the step values of a flow file that would not
// be sent as written, jobs in name order and steps in file order at every
// nesting depth.
func flowStepValueProblems(file FlowFileGHA) []string {
	signedIn := flowRequestSignedIn(file.On.Request)
	var problems []string
	var walk func(job, path string, steps []FlowStepGHA)
	walk = func(job, path string, steps []FlowStepGHA) {
		for i, s := range steps {
			here := fmt.Sprintf("%s[%d]", path, i)
			where := fmt.Sprintf("flows.yaml: job %q step %s", job, here)
			if s.ID != "" {
				where += fmt.Sprintf(" (%q)", s.ID)
			}
			for _, problem := range flowStepValueProblemsOf(ghaStepRunType(s), s.With, signedIn) {
				problems = append(problems, where+": "+problem)
			}
			walk(job, here+".steps", s.Steps)
			walk(job, here+".else", s.Else)
			walk(job, here+".on_error", s.OnError)
		}
	}
	for _, job := range slices.Sorted(maps.Keys(file.Jobs)) {
		walk(job, "steps", file.Jobs[job].Steps)
	}
	return problems
}

// flowRequestSignedIn reports a request flow only signed-in callers reach.
func flowRequestSignedIn(req *FlowRequestTrigger) bool {
	if req == nil {
		return false
	}
	auth, _ := canonicalAuthValue(req.Auth)
	return auth == "required" || strings.TrimSpace(req.Role) != "" || len(req.Permissions) > 0
}

// flowStepValueProblemsOf checks one step's `with:` values.
func flowStepValueProblemsOf(runType string, with map[string]any, signedIn bool) []string {
	switch runType {
	case "enqueue":
		return enqueueValueProblems(with)
	case "webhook":
		return webhookValueProblems(with)
	case "api":
		return apiBodyValueProblems(with)
	case "respond":
		return respondValueProblems(with, signedIn)
	case "email":
		return emailValueProblems(with)
	}
	return nil
}

// isJSONBodyShape reports a value written as a JSON body: a map or a list.
func isJSONBodyShape(v any) bool {
	switch v.(type) {
	case map[string]any, []any:
		return true
	}
	return false
}

func webhookValueProblems(with map[string]any) []string {
	var problems []string
	body, hasBody := with["body"]
	payload, hasPayload := with["payload"]
	if hasBody && hasPayload {
		problems = append(problems, "`with.body` and `with.payload` are both set, and the step sends one body: only `body` is sent. Keep one (`payload:` for a JSON map or list, `body:` for text).")
	}
	if hasPayload && !isJSONBodyShape(payload) {
		problems = append(problems, "`with.payload` is the JSON body and must be a map or a list; it is not sent. For a text body use `with.body`.")
	}
	if _, text := body.(string); hasBody && !text && !isJSONBodyShape(body) {
		problems = append(problems, "`with.body` must be text, a map or a list; it is not sent.")
	}
	return problems
}

func apiBodyValueProblems(with map[string]any) []string {
	if !isJSONBodyShape(with["body"]) {
		return nil
	}
	for _, other := range []string{"json", "form"} {
		if _, set := with[other]; set {
			return []string{fmt.Sprintf("`with.body` written as a map or list is a JSON body, and the step also sets `with.%s`; it sends one body, the `%s` one. Keep one.", other, other)}
		}
	}
	return nil
}

func respondValueProblems(with map[string]any, signedIn bool) []string {
	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }

	if status, set := with["status"]; set && status != nil {
		if n, template := respondStatusFromWith(status); n == 0 && template != "" && !strings.Contains(template, "{{") {
			add("`with.status` is %q, which is not an HTTP status: write an integer 200-599 (or a `${{ }}` that renders one). The step fails when it runs.", template)
		}
	}

	declared := ""
	if raw, set := with["content_type"]; set {
		ct, isText := raw.(string)
		if problem := respondContentTypeProblem(strings.TrimSpace(ct)); !isText || problem != "" {
			if !isText {
				problem = "must be text"
			}
			add("`with.content_type` %s; it is not sent.", problem)
		} else {
			declared = strings.TrimSpace(ct)
		}
	}

	if raw, set := with["headers"]; set {
		headers, isMap := raw.(map[string]any)
		if !isMap {
			add("`with.headers` must be a map of header names to values; it is not sent.")
		}
		seen := map[string]string{}
		for _, written := range slices.Sorted(maps.Keys(headers)) {
			name := http.CanonicalHeaderKey(strings.TrimSpace(written))
			label := fmt.Sprintf("`with.headers` %q", written)
			if refusal := respondHeaderRefusal(name); refusal != "" {
				add("%s %s; it is not sent.", label, refusal)
				continue
			}
			if first, twice := seen[name]; twice {
				add("%s names the same header as %q; only one is sent. Keep one.", label, first)
				continue
			}
			seen[name] = written
			value, scalar := respondHeaderScalar(headers[written])
			if !scalar {
				add("%s must have one text value; it is not sent.", label)
				continue
			}
			value = strings.TrimSpace(normalizeGHARefs(value))
			literal := !strings.Contains(value, "{{")
			switch {
			case name == "Content-Type" && declared != "":
				add("%s and `with.content_type` both set the content type; only `content_type` is sent. Keep one.", label)
				continue
			case name == "Content-Type":
				if problem := respondContentTypeProblem(value); problem != "" {
					add("%s %s; it is not sent.", label, problem)
					continue
				}
				declared = value
				continue
			case name == "Cache-Control" && !literal:
				add("%s must be literal text, not a template; it is not sent.", label)
				continue
			case name == "Cache-Control" && signedIn && respondCacheControlShared(value):
				add("%s lets a shared cache (a CDN or proxy) store the response (`public`, `s-maxage`, or `max-age` without unqualified `private`/`no-store`), on a flow only signed-in callers reach: one caller's data could be served to another. Use `private`; it is not sent.", label)
				continue
			}
			if literal {
				if problem := respondHeaderValueProblem(name, value); problem != "" {
					add("%s %s; it is not sent.", label, problem)
				}
			}
		}
	}

	if declared != "" && !respondContentTypeIsJSON(declared) {
		for _, key := range []string{"body", "json"} {
			if isJSONBodyShape(with[key]) {
				add("the content type is %q, but `with.%s` is a map or list, which is sent as JSON (application/json); the declared type is not sent. Declare a JSON type, or write the body as text.", declared, key)
				break
			}
		}
	}
	return problems
}

func emailValueProblems(with map[string]any) []string {
	for _, key := range []string{"cc", "bcc"} {
		if raw, ok := with[key]; ok {
			if _, ok := raw.(string); !ok {
				return []string{"`with." + key + "` must be recipient-list text."}
			}
		}
	}
	if raw, ok := with["unsubscribe_one_click"]; ok {
		switch v := raw.(type) {
		case bool:
		case string:
			v = strings.TrimSpace(normalizeGHARefs(v))
			if v != "true" && v != "false" && !strings.Contains(v, "{{") {
				return []string{"`with.unsubscribe_one_click` must be true, false or a template resolving to one of them."}
			}
		default:
			return []string{"`with.unsubscribe_one_click` must be a boolean or template."}
		}
		if strings.TrimSpace(fmt.Sprint(raw)) == "true" && (with["unsubscribe_url"] == nil || strings.TrimSpace(fmt.Sprint(with["unsubscribe_url"])) == "") {
			return []string{"one-click unsubscribe requires an https unsubscribe_url."}
		}
		if strings.TrimSpace(fmt.Sprint(raw)) == "true" {
			count := 0
			for _, key := range []string{"to", "cc", "bcc"} {
				value, _ := with[key].(string)
				if strings.Contains(normalizeGHARefs(value), "{{") {
					continue
				}
				addresses, err := parseEmailAddressList(value)
				if err != nil {
					continue
				}
				count += len(addresses)
			}
			if count > 1 {
				return []string{"one-click unsubscribe requires exactly one recipient across to, cc and bcc."}
			}
		}
	}

	raw, set := with["unsubscribe_url"]
	if !set || raw == nil {
		return nil
	}
	text, isText := raw.(string)
	if !isText {
		return []string{"`with.unsubscribe_url` must be text (an https URL); the step fails when it runs."}
	}
	text = strings.TrimSpace(normalizeGHARefs(text))
	prefix, _, templated := strings.Cut(text, "{{")
	switch {
	case !templated:
		if strings.TrimSpace(fmt.Sprint(with["unsubscribe_one_click"])) == "true" {
			if problem := emailOneClickURLProblem(text); problem != "" {
				return []string{"one-click unsubscribe_url " + problem}
			}
		}
		if text == "" {
			return nil
		}
		if problem := emailUnsubscribeURLProblem(text); problem != "" {
			return []string{fmt.Sprintf("`with.unsubscribe_url` %s; the step fails when it runs.", problem)}
		}
	case strings.Contains(prefix, ":") && !strings.HasPrefix(strings.ToLower(prefix), "https://"):
		// The scheme is written out and it is not https.
		return []string{"`with.unsubscribe_url` must be an https:// URL; the step fails when it runs."}
	}
	return nil
}

// emailUnsubscribeURLProblem checks a List-Unsubscribe target as it will be
// sent; "" when it may be. It must be an absolute https URL that fits inside
// the header's angle brackets: no whitespace, control character, `<` or `>`
// (which would end the URL and start another target).
func emailUnsubscribeURLProblem(v string) string {
	if len(v) > 2048 {
		return "is longer than 2048 bytes"
	}
	if strings.ContainsAny(v, "<> \t") {
		return "holds a space, `<` or `>`"
	}
	for i := 0; i < len(v); i++ {
		if v[i] < 0x20 || v[i] == 0x7f {
			return "holds a line break or another control character"
		}
	}
	u, err := url.Parse(v)
	if err != nil || !strings.EqualFold(u.Scheme, "https") || u.Host == "" {
		return "must be an https:// URL"
	}
	return ""
}

// Enqueue payloads are explicit text bindings; JSON values can be serialized with the json filter.
func enqueueValueProblems(with map[string]any) []string {
	var problems []string
	flow, ok := with["flow"].(string)
	if !ok || strings.TrimSpace(flow) == "" {
		problems = append(problems, "`with.flow` must be a non-empty flow name string.")
	}
	for _, key := range []string{"run_at", "unique_key"} {
		if raw, present := with[key]; present {
			if _, ok := raw.(string); !ok {
				problems = append(problems, "`with."+key+"` must be a string.")
			}
		}
	}
	if raw, present := with["with"]; present {
		payload, ok := raw.(map[string]any)
		if !ok {
			problems = append(problems, "`with.with` must be a map of text bindings.")
		} else {
			for _, key := range slices.Sorted(maps.Keys(payload)) {
				if _, ok := payload[key].(string); !ok {
					problems = append(problems, "`with.with."+key+"` must be text; quote scalars or use the json filter.")
				}
			}
		}
	}
	return problems
}

// Mail clients POST the URL without a user session. Fragments never reach that
// endpoint, and userinfo must not become credentials in an automatic request.
func emailOneClickURLProblem(v string) string {
	if problem := emailUnsubscribeURLProblem(v); problem != "" {
		return problem
	}
	u, _ := url.Parse(v)
	if u.Hostname() == "" {
		return "must have a host"
	}
	if u.User != nil {
		return "must not contain userinfo"
	}
	if strings.Contains(v, "#") {
		return "must not contain a fragment"
	}
	return ""
}
