//go:build !cli

package main

// Contract-key gates for the app author's config files.
//
// yaml.v3 decodes into structs by silently DROPPING every key the struct
// does not declare. For config that means a typo'd or invented key parses
// clean, loads clean, and does nothing - which for some keys means a
// security control is off while the file reads as if it were on:
//
//	on.request.roles: admin       → no role gate, and with no auth: the flow is public
//	access.orders.create: admin   → create falls back to the table default
//	workflows.yaml `workflows:`   → a workflow on no table; the state field is freely PATCHable
//
// The gates here derive the accepted key set from the loader's own struct
// tags (the only thing that decides which keys survive), so they cannot
// drift behind the parser. They run at write time and in `benmore check`
// (both through ValidateOnWriteIn), never in the loader: a file that loads
// today keeps loading; the author hears about the dead key on the next write
// or check.

import (
	"fmt"
	"maps"
	"reflect"
	"regexp"
	"slices"
	"strings"
)

// yamlStructKeys returns the YAML keys a struct binds, from its tags.
func yamlStructKeys(v any) map[string]bool {
	keys := map[string]bool{}
	t := reflect.TypeOf(v)
	for i := range t.NumField() {
		tag := t.Field(i).Tag.Get("yaml")
		if tag == "" || tag == "-" {
			continue
		}
		keys[strings.Split(tag, ",")[0]] = true
	}
	return keys
}

func sortedKeyList(m map[string]bool) string {
	return strings.Join(slices.Sorted(maps.Keys(m)), ", ")
}

var (
	flowFileKeys     = yamlStructKeys(FlowFileGHA{})
	flowOnKeys       = yamlStructKeys(FlowTriggerGHA{})
	flowRequestKeys  = yamlStructKeys(FlowRequestTrigger{})
	flowScheduleKeys = yamlStructKeys(FlowScheduleTrigger{})
	flowEventKeys    = yamlStructKeys(FlowEventTrigger{})
	flowJobKeys      = yamlStructKeys(FlowJobGHA{})
	flowStepKeys     = yamlStructKeys(FlowStepGHA{})
	flowInputKeys    = yamlStructKeys(FlowInput{})
)

// flowKeyHints names the key an author most likely meant. Only hints -
// the refusal itself comes from the struct-derived key sets above.
var flowKeyHints = map[string]string{
	"roles":          "use `role:` with one role name (admins always pass)",
	"require_role":   "use `role:`",
	"required_role":  "use `role:`",
	"rate-limit":     "use `rate_limit:` (underscore)",
	"ratelimit":      "use `rate_limit:`",
	"rate_limits":    "use `rate_limit:`",
	"throttle":       "use `rate_limit:` (e.g. `rate_limit: \"5/hour per ip\"`)",
	"auth_required":  "use `auth: required`",
	"require_auth":   "use `auth: required`",
	"requires_auth":  "use `auth: required`",
	"authenticated":  "use `auth: required`",
	"login_required": "use `auth: required`",
	"async":          "use `mode: async`",
	"transactional":  "use `transaction: true`",
	"expect_row":     "use `expect_rows:`",
	"expected_rows":  "use `expect_rows:`",
	"expects_rows":   "use `expect_rows:`",
	"expect":         "use `expect_rows:` (e.g. `expect_rows: \">0\"`)",
	"name":           "a step is named by `id:` (reference it as `${{ steps.<id>.outputs... }}`); a flow is named by its file (flows/<name>.yaml) or its job key",
	"uses":           "Benmore steps take `run: <type>` + `with:`, not GitHub `uses:` actions",
	"runs-on":        "Benmore jobs take only `steps:`",
	"needs":          "jobs run in series; there is no `needs:`",
	"env":            "reference environment values inline as `${{ env.NAME }}`; there is no `env:` block",
	"then":           "put the guarded steps under `steps:` next to `if:`",
	"retries":        "use `retry:`",
	"on_failure":     "use `on_error:`",
	"catch":          "use `on_error:`",
}

// flowVerifyKeyHints are the hints for `on.request.verify` map keys
// (flowVerifyKeys).
var flowVerifyKeyHints = map[string]string{
	"skew":             "use `skew_seconds:`",
	"tolerance":        "use `skew_seconds:`",
	"max_age":          "use `skew_seconds:`",
	"algorithm":        "the scheme is the `recipe:` (hmac_sha256_body, hmac_timestamp_dot_body, hmac_sha1_body, hmac_sha256_path_bearer)",
	"type":             "use `recipe:`",
	"provider":         "use `recipe:`, or the string form `verify: <provider>`",
	"signature_header": "use `header:`",
	"timestamp-header": "use `timestamp_header:`",
	"secret_env":       "use `secret: \"${{ env.NAME }}\"`",
}

// flowUnknownKeyViolation walks a GHA flow file and refuses any key its
// structs don't bind: file level, on:, on.request (auth/role/rate_limit
// live here, so a typo there fails OPEN), inputs, jobs and every step
// (nested steps/else/on_error included). Which of those step keys, and which
// `with:` keys, a given step type reads is flowStepKeyProblems'.
func flowUnknownKeyViolation(content string) string {
	var raw map[string]any
	if err := yamlUnmarshal([]byte(content), &raw); err != nil || raw == nil {
		return ""
	}
	if msg := unknownKeyIn(raw, flowFileKeys, "the top level of the file"); msg != "" {
		return msg
	}
	if on, ok := raw["on"].(map[string]any); ok {
		if msg := unknownKeyIn(on, flowOnKeys, "`on:`"); msg != "" {
			return msg
		}
		if req, ok := on["request"].(map[string]any); ok {
			if msg := unknownKeyIn(req, flowRequestKeys, "`on.request`"); msg != "" {
				return msg
			}
			// A verify map is read key by key (parseVerifyMap): a misspelled
			// skew_seconds or an invented algorithm: would do nothing.
			if verify, ok := req["verify"].(map[string]any); ok {
				if msg := unknownKeyInHints(verify, flowVerifyKeys, "`on.request.verify`", flowVerifyKeyHints); msg != "" {
					return msg
				}
			}
			if inputs, ok := req["inputs"].(map[string]any); ok {
				for _, name := range slices.Sorted(maps.Keys(inputs)) {
					if in, ok := inputs[name].(map[string]any); ok {
						if msg := unknownKeyIn(in, flowInputKeys, fmt.Sprintf("`on.request.inputs.%s`", name)); msg != "" {
							return msg
						}
					}
				}
			}
		}
		if sched, ok := on["schedule"].(map[string]any); ok {
			if msg := unknownKeyIn(sched, flowScheduleKeys, "`on.schedule`"); msg != "" {
				return msg
			}
		}
		if ev, ok := on["event"].(map[string]any); ok {
			if msg := unknownKeyIn(ev, flowEventKeys, "`on.event`"); msg != "" {
				return msg
			}
		}
	}
	jobs, _ := raw["jobs"].(map[string]any)
	for _, jobName := range slices.Sorted(maps.Keys(jobs)) {
		job, ok := jobs[jobName].(map[string]any)
		if !ok {
			continue
		}
		where := fmt.Sprintf("`jobs.%s`", jobName)
		if msg := unknownKeyIn(job, flowJobKeys, where); msg != "" {
			return msg
		}
		if msg := unknownStepKeys(job["steps"], "jobs."+jobName+".steps"); msg != "" {
			return msg
		}
	}
	return ""
}

func unknownStepKeys(v any, path string) string {
	steps, _ := v.([]any)
	for i, s := range steps {
		step, ok := s.(map[string]any)
		if !ok {
			continue
		}
		here := fmt.Sprintf("%s[%d]", path, i)
		if msg := unknownKeyIn(step, flowStepKeys, "`"+here+"`"); msg != "" {
			return msg
		}
		for _, nested := range []string{"steps", "else", "on_error"} {
			if msg := unknownStepKeys(step[nested], here+"."+nested); msg != "" {
				return msg
			}
		}
	}
	return ""
}

func unknownKeyIn(m map[string]any, known map[string]bool, where string) string {
	return unknownKeyInHints(m, known, where, flowKeyHints)
}

func unknownKeyInHints(m map[string]any, known map[string]bool, where string, hints map[string]string) string {
	for _, k := range slices.Sorted(maps.Keys(m)) {
		if known[k] {
			continue
		}
		hint := ""
		if h, ok := hints[strings.ToLower(k)]; ok {
			hint = " Did you mean: " + h + "."
		}
		return fmt.Sprintf(
			"flows.yaml: unknown key %q in %s.%s\n\n"+
				"Valid keys there: %s.\n"+
				"The flow parser silently drops keys it does not read, so this setting would never apply - for an `on.request` key that can mean the endpoint runs with no sign-in, role gate or rate limit while the file reads as if it had one. Remove or rename it.",
			k, where, hint, sortedKeyList(known))
	}
	return ""
}

// flowTriggerValueViolation refuses on.request / on.event values the
// runtime cannot honor as written.
func flowTriggerValueViolation(file FlowFileGHA) string {
	if req := file.On.Request; req != nil {
		if _, known := canonicalAuthValue(req.Auth); !known {
			return fmt.Sprintf(
				"flows.yaml: on.request.auth %q is not a recognized value.\n\n"+
					"Use `auth: required` (a signed-in session is required; `${{ user.* }}` binds from it) or `auth: none` (public; omitting auth: is the same). `true`/`yes`/`on` mean required and `false`/`no`/`off`/`public` mean none. An unrecognized value is treated as `required` at runtime, so say which one you mean.",
				req.Auth)
		}
		switch strings.ToLower(strings.TrimSpace(req.Mode)) {
		case "", "sync", "async":
		default:
			return fmt.Sprintf("flows.yaml: on.request.mode %q is not a recognized value. Use `mode: async` (enqueue and return {job_id, status_url}) or omit it (runs inline). Any other value runs inline.", req.Mode)
		}
	}
	if ev := file.On.Event; ev != nil {
		switch strings.ToLower(strings.TrimSpace(ev.Op)) {
		case "insert", "update", "delete":
		default:
			return fmt.Sprintf("flows.yaml: on.event.op %q is not one of insert, update, delete. The runtime falls back to insert for any other value, so the flow would fire on the wrong event.", ev.Op)
		}
		if strings.TrimSpace(ev.Table) == "" {
			return "flows.yaml: on.event needs a `table:` - an event flow with no table never fires."
		}
	}
	for _, jobName := range slices.Sorted(maps.Keys(file.Jobs)) {
		if msg := expectRowsViolation(jobName, file.Jobs[jobName].Steps); msg != "" {
			return msg
		}
	}
	return ""
}

// expectRowsViolation refuses an `expect_rows` that would not be the
// assertion its author wrote: a value the runtime can't parse, one written in
// both positions with different values, one with no value, one on a step that
// has no row count, and one on a statement that has none. Every one of these
// used to parse clean and then assert nothing (or the wrong number), which is
// the silent pass the key exists to prevent. Steps at every nesting depth are
// checked, both positions (step root and `with:`).
func expectRowsViolation(jobName string, steps []FlowStepGHA) string {
	for _, s := range steps {
		if msg := stepExpectRowsViolation(jobName, s); msg != "" {
			return msg
		}
		for _, nested := range [][]FlowStepGHA{s.Steps, s.Else, s.OnError} {
			if msg := expectRowsViolation(jobName, nested); msg != "" {
				return msg
			}
		}
	}
	return ""
}

func stepExpectRowsViolation(jobName string, s FlowStepGHA) string {
	root := strings.TrimSpace(s.ExpectRows)
	under, underPresent := ghaWithExpectRows(s.With)
	if root == "" && !underPresent {
		return ""
	}
	where := fmt.Sprintf("flows.yaml: job %q", jobName)
	if s.ID != "" {
		where += fmt.Sprintf(" step %q", s.ID)
	}
	const counts = "It compares the rows a SELECT (or a write with RETURNING) returns, or the rows any other INSERT/UPDATE/DELETE affects."
	runType := ghaStepRunType(s)
	if !flowRunTypeCountsRows(runType) {
		kind := "a `run: " + runType + "` step"
		switch runType {
		case "":
			kind = "a step with no SQL"
		case "if":
			kind = "an `if:` block"
		case "for_each":
			kind = "a `for_each:` loop"
		}
		if root != "" {
			hint := ""
			if runType == "for_each" {
				hint = " To require that a loop has something to iterate, put it on the query that feeds the loop."
			}
			return fmt.Sprintf("%s: `expect_rows` is on %s, which has no row count, so it would never be checked. Move it onto the `run: sql` step whose rows you mean. %s%s", where, kind, counts, hint)
		}
		// On `run: set` every `with:` key is a variable, so this one is a
		// variable named expect_rows: a working program, not a dropped guard.
		if runType == "set" {
			return ""
		}
		return fmt.Sprintf("%s: `with.expect_rows` is on %s. Only a `run: sql` step reads it, so it would never be checked. Move it onto the `run: sql` step whose rows you mean. %s", where, kind, counts)
	}
	if underPresent && under == "" {
		return where + ": `with.expect_rows` has no value, so nothing would be asserted." + expectRowsEmptyAdvice
	}
	for _, position := range []struct{ name, value string }{{"expect_rows", root}, {"with.expect_rows", under}} {
		if position.value == "" {
			continue
		}
		if _, err := evalExpectRows(position.value, 0); err != nil {
			return fmt.Sprintf("flows.yaml: job %q: %s %q is not a row-count comparison. Use one of \">0\", \">=1\", \"=1\", \"!=0\" (or a bare number meaning =N).", jobName, position.name, position.value)
		}
	}
	if _, conflict := ghaStepExpectRows(s); conflict != "" {
		return fmt.Sprintf("%s: %s. Keep one; the step-root key is the canonical position. The runtime refuses to run a step with two different guards.", where, conflict)
	}
	// A `run: sql` statement is fixed at write time (references are bound as
	// parameters), so a statement with no row count can be refused here. A
	// `run: sql_dynamic` statement is only known when it is rendered; the
	// runtime makes the same check then (routeAssertedFlowSQL).
	if runType == "sql" {
		query := s.Query
		if query == "" {
			query, _ = s.With["query"].(string)
		}
		if why := classifyFlowSQL(flowSQLStaticText(query)).uncheckable(); why != "" {
			return fmt.Sprintf("%s: `expect_rows` cannot be checked on this step: %s. %s. The runtime refuses to run a step whose assertion it cannot check.", where, why, expectRowsUncheckableAdvice)
		}
	}
	return ""
}

const expectRowsEmptyAdvice = " Write a quoted comparison, e.g. `expect_rows: \"!=0\"`: unquoted, YAML reads a leading `!` as a tag and the value is empty. Remove the key if no assertion is meant."

// flowTemplateRefRe matches one `{{ ... }}` reference in a normalized flow
// template.
var flowTemplateRefRe = regexp.MustCompile(`(?s)\{\{.*?\}\}`)

// flowSQLStaticText is a `run: sql` template as the runtime will run it, as
// far as its statement shape goes: every `${{ }}` / `{{ }}` reference is a
// bound `?` parameter (interpolateCtxSafe), so no reference can add a
// keyword, a statement or a RETURNING clause.
func flowSQLStaticText(query string) string {
	return flowTemplateRefRe.ReplaceAllString(normalizeGHARefs(query), "?")
}

// expectRowsEmptyViolation refuses a step-root `expect_rows:` that is present
// with no value. The typed step cannot tell that from an absent key (both
// decode to ""), so this reads the raw document. The usual cause is an
// unquoted `expect_rows: !=0`.
func expectRowsEmptyViolation(content string) string {
	var raw map[string]any
	if err := yamlUnmarshal([]byte(content), &raw); err != nil || raw == nil {
		return ""
	}
	jobs, _ := raw["jobs"].(map[string]any)
	for _, jobName := range slices.Sorted(maps.Keys(jobs)) {
		job, _ := jobs[jobName].(map[string]any)
		if msg := emptyExpectRowsStep(jobName, job["steps"]); msg != "" {
			return msg
		}
	}
	return ""
}

func emptyExpectRowsStep(jobName string, v any) string {
	steps, _ := v.([]any)
	for _, item := range steps {
		step, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if value, present := step["expect_rows"]; present {
			if text, isString := value.(string); value == nil || isString && strings.TrimSpace(text) == "" {
				where := fmt.Sprintf("flows.yaml: job %q", jobName)
				if id, _ := step["id"].(string); id != "" {
					where += fmt.Sprintf(" step %q", id)
				}
				return where + ": `expect_rows` has no value, so nothing would be asserted." + expectRowsEmptyAdvice
			}
		}
		for _, nested := range []string{"steps", "else", "on_error"} {
			if msg := emptyExpectRowsStep(jobName, step[nested]); msg != "" {
				return msg
			}
		}
	}
	return ""
}

// flowExpectRowsProblems lists what the write gate refuses about a file's
// `expect_rows` keys (the first problem of each job), for the loader's log:
// a deployed file keeps loading.
func flowExpectRowsProblems(content string, file FlowFileGHA) []string {
	var problems []string
	if msg := expectRowsEmptyViolation(content); msg != "" {
		problems = append(problems, msg)
	}
	for _, jobName := range slices.Sorted(maps.Keys(file.Jobs)) {
		if msg := expectRowsViolation(jobName, file.Jobs[jobName].Steps); msg != "" {
			problems = append(problems, msg)
		}
	}
	return problems
}

// hookEntrySubKeys maps each nested hook action (email:, sms:, ws:) to the
// keys its struct binds, derived from HookEntryYAML.
var hookEntrySubKeys = func() map[string]map[string]bool {
	out := map[string]map[string]bool{}
	t := reflect.TypeOf(HookEntryYAML{})
	for i := range t.NumField() {
		f := t.Field(i)
		ft := f.Type
		if ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		if ft.Kind() != reflect.Struct {
			continue
		}
		name := strings.Split(f.Tag.Get("yaml"), ",")[0]
		out[name] = yamlStructKeys(reflect.New(ft).Elem().Interface())
	}
	return out
}()

// hookEntrySubKeyViolation reports a key inside email:/sms:/ws: that the
// hook struct drops (`email: { body: ... }` - the body lives in the
// template - or `sms: { message: ... }`), so the hook sends without it.
func hookEntrySubKeyViolation(entry map[string]any, where string) string {
	for _, action := range slices.Sorted(maps.Keys(hookEntrySubKeys)) {
		sub, ok := entry[action].(map[string]any)
		if !ok {
			continue
		}
		known := hookEntrySubKeys[action]
		for _, k := range slices.Sorted(maps.Keys(sub)) {
			if !known[k] {
				return fmt.Sprintf("%s: unknown key %q under `%s:`. Valid keys: %s. The hook parser drops it, so the %s goes out without it.", where, k, action, sortedKeyList(known), action)
			}
		}
	}
	return ""
}

func hooksSubKeyViolation(content string) string {
	var shaped map[string]map[string][]map[string]any
	if err := yamlUnmarshal([]byte(content), &shaped); err != nil {
		return ""
	}
	for _, section := range slices.Sorted(maps.Keys(shaped)) {
		for _, table := range slices.Sorted(maps.Keys(shaped[section])) {
			for i, e := range shaped[section][table] {
				if msg := hookEntrySubKeyViolation(e, fmt.Sprintf("hooks.yaml: %s.%s[%d]", section, table, i)); msg != "" {
					return msg
				}
			}
		}
	}
	return ""
}

// contractCrossFileWarnings names access: rules and encryption declarations
// whose table (or encrypted column) is not in the schema. Such a declaration
// binds nothing: the real table keeps its implicit access default, and a
// misspelled encrypted column fails its trigger (logged only) while the real
// column is stored in plaintext. Warnings, not errors: the schema may be
// written after the config, and a table can come from migrations/.
func contractCrossFileWarnings(appDir string, tables map[string]bool) []string {
	var out []string
	known := func(t string) bool { return tables[t] || frameworkTables[t] }
	if data := readAppFileOrNil(appDir, "app.yaml"); data != nil {
		var raw map[string]any
		if yamlUnmarshal(data, &raw) == nil {
			access, _ := raw["access"].(map[string]any)
			for _, table := range slices.Sorted(maps.Keys(access)) {
				t := strings.ToLower(strings.TrimSpace(table))
				if t == "default" || known(t) {
					continue
				}
				out = append(out, fmt.Sprintf("app.yaml: access.%s names a table that is not in schema.prisma, so the rule applies to nothing (known tables: %s). A misspelled table keeps its implicit default (self/group/admin).", table, crossFileSortedKeys(tables)))
			}
		}
	}
	enc := LoadEncryptedFieldsConfig(appDir)
	if enc == nil {
		return out
	}
	columns := loadSchemaColumns(appDir)
	for _, table := range slices.Sorted(maps.Keys(enc.Fields)) {
		if !known(table) {
			out = append(out, fmt.Sprintf("encryption: table %q is not in schema.prisma, so nothing is encrypted for it (known tables: %s).", table, crossFileSortedKeys(tables)))
			continue
		}
		cols := columns[table]
		if cols == nil {
			continue
		}
		for _, def := range enc.Fields[table] {
			if !cols[def.Column] {
				out = append(out, fmt.Sprintf("encryption: %s.%s is not a column of %s, so its encryption trigger fails and nothing is encrypted under that name - check the spelling; a misspelled entry leaves the real column in plaintext.", table, def.Column, table))
			}
		}
	}
	return out
}

// loadSchemaColumns maps each schema.prisma table to its column names, or
// nil when there is no parseable schema.prisma.
func loadSchemaColumns(appDir string) map[string]map[string]bool {
	data := readAppFileOrNil(appDir, "schema.prisma")
	if data == nil {
		return nil
	}
	models, err := ParsePrismaSchema(string(data))
	if err != nil {
		return nil
	}
	out := map[string]map[string]bool{}
	for _, m := range models {
		cols := map[string]bool{}
		for _, f := range m.Fields {
			cols[f.Column] = true
		}
		out[m.Table] = cols
	}
	return out
}

// accessOps are the op keys the access loader reads (access.go
// DeclaredModeFor): read, write (create: POST, batch create, ingest,
// import), update, delete, and the `all` fallback. Anything else is kept in
// the parsed map but never looked up.
var accessOps = map[string]bool{"read": true, "write": true, "update": true, "delete": true, "all": true}

func accessOpKeyViolation(table, op string) string {
	if accessOps[strings.ToLower(strings.TrimSpace(op))] {
		return ""
	}
	return fmt.Sprintf(
		"app.yaml: access.%s.%s is not an access operation - the rule is never read, so that operation silently keeps the table's broader fallback (`all:`, then `default:`, then the implicit self/group/admin default).\n\n"+
			"Operations: read, write (creates: POST /api/<table>, batch create, ingest, import), update, delete, all (fallback for any op not listed). "+
			"Note that update and delete do NOT inherit from write - declare each, or use `all:`.\n"+
			"Common fabrications: `create:`/`insert:` (use write), `list:`/`get:` (use read), `edit:`/`patch:` (use update), `remove:` (use delete).",
		table, op)
}

// canonicalAuthFlag maps a boolean app.yaml value onto "true"/"false".
// YAML 1.2 (yaml.v3) reads yes/no/on/off as STRINGS, and the runtime
// compared auth flags against "true" only, so `require_verified: yes`
// stayed off. ok is false for a value that is neither.
func canonicalAuthFlag(v string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "yes", "on", "1":
		return "true", true
	case "false", "no", "off", "0", "":
		return "false", true
	}
	return v, false
}

var (
	groupKeys          = map[string]bool{"table": true, "key": true, "user_field": true, "role_field": true, "active_field": true, "bootstrap": true, "shared": true, "label": true}
	groupBootstrapKeys = map[string]bool{"org_table": true, "founding_role": true}
	groupLabelKeys     = map[string]bool{"table": true, "key": true, "field": true}
	featureKeys        = yamlStructKeys(FeaturesConfig{})
)

// appYAMLSectionKeyViolation refuses keys that the groups:/features:
// loaders never read and feature values they would misread.
func appYAMLSectionKeyViolation(doc map[string]any) string {
	if g, ok := doc["groups"].(map[string]any); ok {
		for _, k := range slices.Sorted(maps.Keys(g)) {
			if !groupKeys[k] {
				return fmt.Sprintf("app.yaml: groups.%s is not read by the tenant loader, so it has no effect. groups keys: %s.", k, sortedKeyList(groupKeys))
			}
		}
		if l, ok := g["label"].(map[string]any); ok {
			for _, k := range slices.Sorted(maps.Keys(l)) {
				if !groupLabelKeys[k] {
					return fmt.Sprintf("app.yaml: groups.label.%s is not read, so it has no effect. groups.label keys: %s.", k, sortedKeyList(groupLabelKeys))
				}
			}
		}
		if b, ok := g["bootstrap"].(map[string]any); ok {
			for _, k := range slices.Sorted(maps.Keys(b)) {
				if !groupBootstrapKeys[k] {
					return fmt.Sprintf("app.yaml: groups.bootstrap.%s is not read, so it has no effect. groups.bootstrap keys: %s.", k, sortedKeyList(groupBootstrapKeys))
				}
			}
		}
	}
	if f, ok := doc["features"].(map[string]any); ok {
		for _, k := range slices.Sorted(maps.Keys(f)) {
			if !featureKeys[k] {
				return fmt.Sprintf("app.yaml: features.%s is not a feature switch, so it has no effect. Switches: %s.", k, sortedKeyList(featureKeys))
			}
			switch v := f[k].(type) {
			case bool, map[string]any:
			case string:
				if _, ok := canonicalAuthFlag(v); ok {
					continue
				}
				if k == "docs" && (v == "auth" || v == "public") {
					continue
				}
				extra := ""
				if k == "docs" {
					extra = "; docs also takes `auth` (sign-in required) or `public`"
				}
				return fmt.Sprintf("app.yaml: features.%s = %q is not a switch value. Use true or false (yes/no and on/off are read the same way)%s.", k, v, extra)
			default:
				return fmt.Sprintf("app.yaml: features.%s must be true or false, got %v.", k, v)
			}
		}
	}
	// The inline encrypted: section is checked by parseAppConfigDocument
	// (appEncryptedSectionError), which validateAppYAML runs first.
	return ""
}

// appEncryptedSectionError checks the legacy inline `encrypted:` section of
// app.yaml against the shape encryption.go actually decodes: a map of table
// → LIST of columns, each a column name or {column, roles}. The encrypted.yaml
// tree (`tables:` / `fields:` / `unmask_roles:`) does not decode here: the
// whole section was dropped (every column stored in plaintext), and an
// `unmask_roles:` inside an item was ignored, so every reader saw plaintext.
// The loader (parseAppConfigDocument) refuses the same shapes, as it does a
// malformed encrypted.yaml.
func appEncryptedSectionError(v any) error {
	if v == nil {
		return nil
	}
	sec, ok := v.(map[string]any)
	if !ok {
		return fmt.Errorf("app.yaml: encrypted must be a mapping")
	}
	shape := "app.yaml's inline form maps each table to a LIST of columns:\n\n  encrypted:\n    contacts: [notes]\n    patients:\n      - column: ssn\n        roles: [admin]\n\n(`roles`, not unmask_roles; no blind_index). For the `tables:`/`fields:`/`unmask_roles:`/`blind_index:` tree, use encrypted.yaml (preferred)."
	for _, table := range slices.Sorted(maps.Keys(sec)) {
		if _, tree := sec[table].(map[string]any); tree && table == "tables" {
			return fmt.Errorf("app.yaml: encrypted.tables is the encrypted.yaml shape; inside app.yaml it encrypts nothing. %s", shape)
		}
		items, ok := sec[table].([]any)
		if !ok {
			return fmt.Errorf("app.yaml: encrypted.%s must be a list of columns. %s", table, shape)
		}
		// The table name and each column go into the encryption trigger SQL;
		// both must be plain identifiers.
		if !membershipIdentRe.MatchString(table) {
			return fmt.Errorf("app.yaml: encrypted table name %q is not a plain identifier", table)
		}
		for i, item := range items {
			switch it := item.(type) {
			case string:
				if strings.TrimSpace(it) == "" {
					return fmt.Errorf("app.yaml: encrypted.%s[%d] is an empty column name", table, i)
				}
				if !membershipIdentRe.MatchString(strings.TrimSpace(it)) {
					return fmt.Errorf("app.yaml: encrypted.%s[%d] (%q) is not a plain column name", table, i, it)
				}
			case map[string]any:
				for _, k := range slices.Sorted(maps.Keys(it)) {
					if k != "column" && k != "roles" {
						return fmt.Errorf("app.yaml: encrypted.%s[%d].%s is not read (keys: column, roles). %s", table, i, k, shape)
					}
				}
				c, _ := it["column"].(string)
				if strings.TrimSpace(c) == "" {
					return fmt.Errorf("app.yaml: encrypted.%s[%d] needs a `column:` name", table, i)
				}
				if !membershipIdentRe.MatchString(strings.TrimSpace(c)) {
					return fmt.Errorf("app.yaml: encrypted.%s[%d].column (%q) is not a plain column name", table, i, c)
				}
				if r, present := it["roles"]; present {
					list, ok := r.([]any)
					if !ok {
						return fmt.Errorf("app.yaml: encrypted.%s[%d].roles must be a list of role names", table, i)
					}
					for _, role := range list {
						if _, ok := role.(string); !ok {
							return fmt.Errorf("app.yaml: encrypted.%s[%d].roles must be a list of role names", table, i)
						}
					}
				}
			default:
				return fmt.Errorf("app.yaml: encrypted.%s[%d] must be a column name or {column, roles}. %s", table, i, shape)
			}
		}
	}
	return nil
}
