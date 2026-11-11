//go:build !cli

package main

// Step values the runtime cannot honor as written.
//
// flowStepKeyProblems decides which keys a step type reads; this decides
// whether the values of some of them can be sent: a webhook's JSON body
// (`payload:`, or `body:` as a map or list), a respond step's `status`,
// `content_type` and `headers`, an api step's `json:` (a map, a list or one
// `${{ }}` reference) and `body:` written as a map or list, an email's
// `unsubscribe_url`, and the `source` a parse step reads. The write gate and
// `benmore check` refuse each problem; the loader logs the same line for a
// deployed file, which keeps loading and drops what it cannot send (a
// refused header, a second body) or fails the step when it runs (a status
// that is not one, an unsubscribe URL that is not https); a parse step with
// such a source produces no outputs. A send inside a `transaction: true` flow
// is the exception: deployed files carry it, so it is a warning
// (flowTransactionalSendProblems). The values the runtime used to ignore
// without a word (a negative `retry`, a `retry_delay` it cannot read, a
// `paginate` block, a reserved loop variable, a malformed `attachments`) are
// checked from here too: validators_flow_ignored_values.go.

import (
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
)

// flowStepValueProblems lists the step values of a flow file that would not
// be sent as written, jobs in name order and steps in file order at every
// nesting depth. The write gate and `benmore check` refuse each.
func flowStepValueProblems(file FlowFileGHA) []string {
	problems, _ := flowStepValueFindings(file)
	return problems
}

// flowTransactionalSendProblems lists the fire-and-forget sends inside a
// `transaction: true` flow (transactionalSendProblem), in the same order.
// Deployed flow files carry them (six files in four apps on 2026-11-10), so
// the write gate and `benmore check` warn (flowTransactionalSendWarnings)
// and the loader logs each; nothing is refused until no deployed file has one.
func flowTransactionalSendProblems(file FlowFileGHA) []string {
	_, sends := flowStepValueFindings(file)
	return sends
}

// flowTransactionalSendWarnings reports flowTransactionalSendProblems for the
// flow file just written, or for every flow file on a full check.
func flowTransactionalSendWarnings(dir, writtenPath string) []CheckFinding {
	var findings []CheckFinding
	for _, rel := range flowFilesFor(dir, writtenPath) {
		data, err := readFileInRoot(dir, rel)
		if err != nil {
			continue
		}
		var file FlowFileGHA
		if decodeConfigYAML(data, &file) != nil || file.Jobs == nil {
			continue
		}
		name := filepath.ToSlash(rel)
		for _, problem := range flowTransactionalSendProblems(file) {
			findings = append(findings, CheckFinding{Severity: "warning", Source: "flows", File: name,
				Message: strings.Replace(problem, "flows.yaml: ", name+": ", 1)})
		}
	}
	return findings
}

// flowStepValueFindings walks a flow file once. problems are refused when the
// file is written; sends are the transactional sends, which are warned about.
func flowStepValueFindings(file FlowFileGHA) (problems, sends []string) {
	signedIn := flowRequestSignedIn(file.On.Request)
	inTx := (file.On.Request != nil && file.On.Request.Transaction) || (file.On.Schedule != nil && file.On.Schedule.Transaction)
	background := flowRunsInBackground(file.On)
	var walk func(job, path string, steps []FlowStepGHA, transactional bool)
	walk = func(job, path string, steps []FlowStepGHA, transactional bool) {
		for i, s := range steps {
			here := fmt.Sprintf("%s[%d]", path, i)
			where := fmt.Sprintf("flows.yaml: job %q step %s", job, here)
			if s.ID != "" {
				where += fmt.Sprintf(" (%q)", s.ID)
			}
			for _, problem := range flowStepValueProblemsOf(ghaStepRunType(s), s.With, signedIn) {
				problems = append(problems, where+": "+problem)
			}
			// Values the runtime would ignore or read as something else
			// (validators_flow_ignored_values.go).
			for _, problem := range flowStepRetryProblems(s) {
				problems = append(problems, where+": "+problem)
			}
			if ghaStepRunType(s) == "for_each" {
				if problem := flowLoopNameProblem(s.As); problem != "" {
					problems = append(problems, where+": "+problem)
				}
			}
			if transactional {
				if problem := transactionalSendProblem(ghaStepRunType(s)); problem != "" {
					sends = append(sends, where+": "+problem)
				}
			}
			if file.On.Request != nil && !background && ghaStepRunType(s) == "extract_text" {
				problems = append(problems, where+": "+syncExtractTextProblem)
			}
			if transactional && ghaStepRunType(s) == "extract_text" {
				problems = append(problems, where+": "+extractTextTransactionMessage)
			}
			if background && ghaStepRunType(s) == "parse" && s.With["source"] == "headers" {
				problems = append(problems, where+": "+backgroundParseHeadersProblem)
			}
			if file.On.Request != nil && ghaStepRunType(s) == "api" {
				if problem := apiRequestHostProblem(s.With); problem != "" {
					problems = append(problems, where+": "+problem)
				}
			}
			// A signed-in caller's profile values are request input
			// (flows_user_taint.go); the runtime refuses them in
			// sql_dynamic text. A deployed file still loads (the loader
			// logs this) and the step fails when it runs.
			if file.On.Request != nil && ghaStepRunType(s) == "sql_dynamic" {
				withQuery, _ := s.With["query"].(string)
				for _, query := range []string{s.Query, withQuery} {
					if problem := sqlDynamicUserProfileProblem(query); problem != "" {
						problems = append(problems, where+": "+problem)
						break
					}
				}
			}
			if ghaStepRunType(s) == "sql" {
				query := s.Query
				if q, ok := s.With["query"].(string); ok {
					query = q
				}
				if problem := sqlQuotedRefProblem(query); problem != "" {
					problems = append(problems, where+": "+problem)
				}
			}
			// DDL on a framework object, which the runtime refuses when the
			// step runs (app_sql_guard.go). A deployed file still loads.
			if rt := ghaStepRunType(s); rt == "sql" || rt == "sql_dynamic" {
				withQuery, _ := s.With["query"].(string)
				for _, query := range []string{s.Query, withQuery} {
					if problem := appSQLFrameworkDDLProblem(query); problem != "" {
						problems = append(problems, where+": "+problem)
						break
					}
				}
			}
			walk(job, here+".steps", s.Steps, transactional)
			walk(job, here+".else", s.Else, transactional)
			// The handler runs after the transaction was rolled back
			// (flows_steps.go), so a send there is outside it.
			walk(job, here+".on_error", s.OnError, false)
		}
	}
	for _, job := range slices.Sorted(maps.Keys(file.Jobs)) {
		walk(job, "steps", file.Jobs[job].Steps, inTx)
	}
	return problems, sends
}

// transactionalSendProblem names a fire-and-forget send inside a
// `transaction: true` flow. It runs at once, so a later failing step rolls the
// rows back after the email, SMS or webhook has already gone. The step is
// not refused and still runs, and the text says so (it used to read "can't
// run", which a builder took for a refusal). `run: api` is
// left alone: later steps read its outputs (live flows POST to a payment API
// and store the result), which `run: enqueue` cannot give them. It is a
// warning when the file is written and in `benmore check`, and a log line
// when the file loads (flowTransactionalSendProblems).
func transactionalSendProblem(runType string) string {
	sent := map[string]string{"email": "email", "sms": "text message", "webhook": "request"}[runType]
	switch runType {
	case "email", "sms", "webhook":
		return fmt.Sprintf("`run: %s` in a `transaction: true` flow sends at once and is not undone by a rollback: when a later step fails, the rows are rolled back after the "+sent+" has already gone. Queue it with `run: enqueue` (`with: { flow: <flow that sends>, with: { ... } }`): the job is written inside the transaction and runs only after COMMIT. Or send from a separate flow.", runType)
	}
	return ""
}

// flowRunsInBackground reports a flow that runs in the job worker or the
// scheduler rather than inside the HTTP request: `mode: async`, a schedule or
// a data event.
func flowRunsInBackground(on FlowTriggerGHA) bool {
	if on.Request != nil {
		return strings.EqualFold(strings.TrimSpace(on.Request.Mode), "async")
	}
	return on.Schedule != nil || on.Event != nil
}

// backgroundParseHeadersProblem refuses `run: parse` with `source: headers`
// in a background flow. There is no request when it runs, so the headers
// would have to travel in the job, and request headers carry credentials
// (Authorization, Cookie, signature and API-key headers) that would then sit
// in `_benmore_jobs.payload`. The step reads nothing today, so refusing it
// also stops it passing as a check that never fires.
const backgroundParseHeadersProblem = "`run: parse` with `source: headers` can't run in an async, scheduled or data-event flow. The flow runs in the background with no request, and carrying request headers into it would write credentials (Authorization, Cookie, API keys) into job payloads. Read the header in an inline flow and queue only the value you need: `run: enqueue` with `with: { flow: <background flow>, with: { name: \"${{ steps.<parse id>.outputs.<Header> | json }}\" } }` (a header is a list of values; the queued flow reads it as `${{ params.name }}`)."

// flowRequestSignedIn reports a request flow only signed-in callers reach.
func flowRequestSignedIn(req *FlowRequestTrigger) bool {
	if req == nil {
		return false
	}
	// An optional flow answers signed-in callers too, so a shared cache
	// must not store its responses either.
	auth := normalizeFlowAuth(req.Auth, "")
	return auth == "required" || auth == "optional" || strings.TrimSpace(req.Role) != "" || len(req.Permissions) > 0
}

// flowStepValueProblemsOf checks one step's `with:` values.
func flowStepValueProblemsOf(runType string, with map[string]any, signedIn bool) []string {
	switch runType {
	case "enqueue":
		return enqueueValueProblems(with)
	case "webhook":
		return webhookValueProblems(with)
	case "api":
		return append(apiBodyValueProblems(with), paginateValueProblems(with)...)
	case "respond":
		return respondValueProblems(with, signedIn)
	case "email":
		return append(emailValueProblems(with), emailAttachmentProblems(with)...)
	case "serve_file":
		return append(serveFileValueProblems(with), uploadRecordValueProblems(with)...)
	case "delete_upload":
		return uploadRecordValueProblems(with)
	case "extract_text":
		return append(extractTextValueProblems(with), uploadRecordValueProblems(with)...)
	case "parse":
		return parseSourceValueProblems(with)
	}
	return nil
}

// syncExtractTextProblem refuses `run: extract_text` in a synchronous request
// flow: extraction can take minutes, a synchronous flow is cut off at 30 s.
const syncExtractTextProblem = "`run: extract_text` can take minutes and cannot run in a synchronous request flow (30 s limit). Add `mode: async` under `on: request:`, or put the step in an async or scheduled flow and `run: enqueue` that flow (api(at:\"pdf\") -> extract_text)."

// extractTextValueProblems refuses the values `run: extract_text` cannot honor.
func extractTextValueProblems(with map[string]any) []string {
	var problems []string
	if p, ok := with["source_path"].(string); !ok || strings.TrimSpace(p) == "" {
		problems = append(problems, "`run: extract_text` needs `with.source_path`: the private upload reference, taken from a row.")
	}
	// Without a record the uploader rule is only advisory (flows_upload_owner.go),
	// so a schedule reading user-editable reference columns would extract
	// files their row owners never uploaded.
	if _, ok := with["record"]; !ok {
		problems = append(problems, "`run: extract_text` needs `with.record: { table: <table>, id: \"${{ steps.<id>.outputs.first.id }}\" }` naming the row that stores `source_path`: the file must have been uploaded by that row's owner or tenant.")
	}
	if ocr, set := with["ocr"]; set {
		if _, ok := ocr.(bool); !ok {
			problems = append(problems, fmt.Sprintf("`with.ocr: %v` must be true or false (default true).", ocr))
		}
	}
	return problems
}

// parseSourceValueProblems refuses a `run: parse` source the step cannot
// read. execStepParse reads `body` and `headers` only, so any other text (an
// unsupported source such as `query`, a `${{ }}` reference to another step's
// output) made the step a silent no-op with no outputs, and a value that is
// not text was read as `body`.
func parseSourceValueProblems(with map[string]any) []string {
	raw, set := with["source"]
	if !set {
		return nil
	}
	if source, ok := raw.(string); ok && (source == "body" || source == "headers") {
		return nil
	}
	return []string{fmt.Sprintf("`with.source: %v` is not a source `run: parse` reads, so the step would produce no outputs. It reads `body` (the default) or `headers`; query parameters already bind as `:name` / `${{ params.<key> }}`, and another step's output needs no parse step.", raw)}
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
	if raw, set := with["json"]; set && !isJSONBodyShape(raw) {
		text, isText := raw.(string)
		if _, sole := soleFlowExpr(normalizeGHARefs(text)); !isText || !sole {
			return []string{"`with.json` must be a map, a list, or one `${{ }}` reference to the value to send (for example `json: ${{ steps.build.outputs }}`); it is not sent. For a text body use `with.body`."}
		}
		if _, text := with["body"].(string); text {
			return []string{"`with.json` and `with.body` are both set, and the step sends one body: only the `json` one is sent. Keep one."}
		}
	}
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
				// The queued flow would read the key as who it runs for; the
				// step never queues it (execStepEnqueue).
				if flowJobIdentityKey(key) {
					problems = append(problems, flowJobIdentityKeyProblem("with.with."+key))
					continue
				}
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

// sqlQuotedRefProblem refuses a `${{ }}` reference inside a larger quoted SQL
// string ('n=${{ x }}'). References bind as parameters, and SQLite does not
// read a parameter inside a string literal, so the step failed only when it
// ran ("not enough args"), in an event flow as nothing but a log line. A
// literal that is exactly one reference ('${{ x }}') is inlined as an escaped
// string and stays accepted.
func sqlQuotedRefProblem(query string) string {
	if !strings.Contains(query, "{{") {
		return ""
	}
	for _, tok := range sqlTokenize(normalizeGHARefs(query)) {
		if tok.kind != sqlTokLiteral || !strings.Contains(tok.text, "{{") {
			continue
		}
		if _, sole := soleFlowExpr(tok.text); sole && strings.TrimSpace(tok.text) == tok.text {
			continue
		}
		return fmt.Sprintf("the query has a `${{ }}` reference inside the quoted string '%s'. A reference is bound as a parameter, and a parameter inside a SQL string is not read, so the step fails when it runs. Bind the value outside the quotes and concatenate ('n=' || :n), or make the whole string one reference ('${{ x }}').", truncate(tok.text, 80))
	}
	return ""
}
