//go:build !cli

package main

// Step-key gate for GHA flow files.
//
// A step decodes into FlowStepGHA and a free-form `with:` map, and
// convertGHASteps then picks out the keys its step type uses. Every other key
// is dropped without a word: `retry` written under `with:`, a `timeout` on a
// SQL step, `with.sql` for `with.query`. Each passed the write gate and did
// nothing at run time, and the last one ran an empty statement and reported
// success.
//
// flowStepKeyTable lists, per step type, the keys the loader reads and the
// executor acts on. The write gate and `benmore check` refuse a key outside it
// (flowStepKeyProblems); the loader logs the same message for a deployed file,
// which keeps loading. The TestFlowStepKeyTableMatchesLoader tests probe
// convertGHASteps with every key at both positions, so the table cannot drift
// from the loader.

import (
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
)

// flowStepTypeKeys is what one step type reads besides the keys every step
// has (flowStepRootKeysEvery, flowStepRootKeysAction).
type flowStepTypeKeys struct {
	// block: an `if:` block, a `for_each:` loop or `run: parallel`. Its
	// `steps:` are the work, and it takes no `retry`: a retried block runs its
	// steps again from the top, those that succeeded included, and still
	// reports the first failure (executeSteps never clears ctx.Error).
	block bool
	// root: step-root keys only this type reads.
	root []string
	// with: the keys read under `with:`.
	with []string
	// anyWith: every `with:` key is data (the variables of `run: set`).
	anyWith bool
}

var (
	// Read at the root of every step: its name, its type, its gate with the
	// gate's other branch, and its error handler. `else` is read only next to
	// an `if:`.
	flowStepRootKeysEvery = []string{"id", "run", "if", "else", "on_error"}
	// Read at the root of every step that is one action, not a block.
	flowStepRootKeysAction = []string{"retry", "retry_delay"}
)

// flowStepKeyTable is the SINGLE SOURCE OF TRUTH for the keys each step type
// takes. When convertGHASteps starts or stops reading a key, change the row
// here too: the TestFlowStepKeyTableMatchesLoader tests fail until both agree.
// The reference at api(at:"flows") → step_keys is rendered from it
// (flowStepKeysReference).
//
// `timeout` is a root key of three types only. The loader maps a step-root
// `timeout:` onto every FlowStep because the command runtime bounds each of
// its steps with it, but an ordinary flow can cut off only an outbound call,
// a compute function and a transcription.
var flowStepKeyTable = map[string]flowStepTypeKeys{
	"enqueue":     {with: []string{"flow", "with", "run_at", "unique_key"}},
	"sql":         {root: []string{"query", "params", "expect_rows"}, with: []string{"query", "params", "expect_rows"}},
	"sql_dynamic": {root: []string{"query", "expect_rows"}, with: []string{"query", "expect_rows"}},
	"api": {root: []string{"timeout"}, with: []string{
		"method", "url", "auth", "headers", "query", "json", "form", "body",
		"sign", "handled_statuses", "paginate", "success_when", "timeout",
	}},
	"compute":    {root: []string{"timeout"}, with: []string{"module", "function", "args", "timeout"}},
	"transcribe": {root: []string{"timeout"}, with: []string{"file", "model", "language", "timeout"}},
	"email": {with: []string{
		"to", "subject", "template", "html", "body", "text", "data", "vars",
		"from", "reply_to", "attachments", "unsubscribe_url", "cc", "bcc", "unsubscribe_one_click",
	}},
	"sms":                    {with: []string{"to", "body", "text"}},
	"webhook":                {with: []string{"url", "body", "payload"}},
	"redirect":               {with: []string{"to", "allow_hosts"}},
	"respond":                {with: []string{"status", "body", "json", "content_type", "headers"}},
	"serve_file":             {with: []string{"path", "disposition", "filename"}},
	"delete_upload":          {with: []string{"path"}},
	"inspect_private_upload": {with: []string{"source_path", "kind"}},
	"render_pdf_signatures":  {with: []string{"source_path", "source_sha256", "placements_json"}},
	"purge_current_user":     {with: []string{"confirm"}},
	"revoke_user_sessions":   {with: []string{"user_id"}},
	"broadcast":              {with: []string{"room", "payload"}},
	"parse":                  {with: []string{"source"}},
	"set":                    {anyWith: true},
	"if":                     {block: true, root: []string{"steps"}},
	"for_each":               {block: true, root: []string{"for_each", "as", "steps"}},
	"parallel":               {block: true, root: []string{"steps"}},
}

// readsRoot reports whether a step of this type reads key at its root.
func (k flowStepTypeKeys) readsRoot(key string) bool {
	switch {
	case slices.Contains(flowStepRootKeysEvery, key), slices.Contains(k.root, key):
		return true
	case key == "with":
		return k.anyWith || len(k.with) > 0
	}
	return !k.block && slices.Contains(flowStepRootKeysAction, key)
}

// readsWith reports whether a step of this type reads key under `with:`.
func (k flowStepTypeKeys) readsWith(key string) bool {
	return k.anyWith || slices.Contains(k.with, key)
}

// flowStepLiveIgnoredKey is a key the loader does not read but deployed apps
// carry. Refusing it would block those apps' next push and honoring it would
// change what they do, so until each app has been looked at the write gate
// keeps accepting it and the loader names it in its log. Moving a row into
// flowStepKeyTable (with the loader change) or deleting it (the gate then
// refuses the key) is the decision.
type flowStepLiveIgnoredKey struct {
	runType string
	with    bool // under `with:`; false: at the step root
	key     string
	effect  string // what the step does without it
}

var flowStepLiveIgnoredKeys = []flowStepLiveIgnoredKey{
	{"parse", true, "from", "the step parses the request body whatever this says (`with.source: body` is the key it reads)"},
	{"parse", false, "as", "the parsed body is stored under the step's `id:`, or as `body` (JSON) / `form` without one"},
	{"for_each", true, "items", "the loop iterates the step-root `for_each:`; without that it never runs"},
	{"for_each", true, "as", "the loop variable is the step-root `as:` (default `item`)"},
}

// flowStepLiveIgnored finds the row for a key, if deployed apps carry it.
func flowStepLiveIgnored(runType string, with bool, key string) (flowStepLiveIgnoredKey, bool) {
	for _, row := range flowStepLiveIgnoredKeys {
		if row.runType == runType && row.with == with && row.key == key {
			return row, true
		}
	}
	return flowStepLiveIgnoredKey{}, false
}

// flowStepTimeoutTypes names the step types with a `timeout`, for messages.
const flowStepTimeoutTypes = "Only `run: api`, `run: compute` and `run: transcribe` steps can be cut off"

// ghaStepSQLText is a SQL step's statement as the loader takes it: the
// step-root `query:` when set, else `with.query` when that is text.
func ghaStepSQLText(s FlowStepGHA) string {
	if s.Query != "" {
		return s.Query
	}
	query, _ := s.With["query"].(string)
	return query
}

// flowStepKeyProblems lists the step keys of a flow file that the runtime
// would ignore, at every nesting depth, jobs in name order and steps in file
// order. refused is what the write gate and `benmore check` refuse; ignored is
// what deployed apps carry and only the loader's log names
// (flowStepLiveIgnoredKeys, and two shapes not known to be absent from them:
// modifiers on a parallel child, `params` at both positions).
// `expect_rows` and `when:` have their own gates (expectRowsViolation,
// ghaWhenViolation), and a key FlowStepGHA does not declare is
// flowUnknownKeyViolation's.
func flowStepKeyProblems(content string, file FlowFileGHA) (refused, ignored []string) {
	var raw map[string]any
	_ = yamlUnmarshal([]byte(content), &raw)
	rawJobs, _ := raw["jobs"].(map[string]any)
	walk := &flowStepKeyWalk{}
	for _, job := range slices.Sorted(maps.Keys(file.Jobs)) {
		rawJob, _ := rawJobs[job].(map[string]any)
		walk.steps(job, "steps", file.Jobs[job].Steps, rawJob["steps"], false)
	}
	return walk.refused, walk.ignored
}

type flowStepKeyWalk struct {
	refused, ignored []string
}

// steps visits a step list. raw is the same list as decoded YAML maps: the
// typed step cannot tell an absent root key from one with a zero value.
func (w *flowStepKeyWalk) steps(job, path string, steps []FlowStepGHA, raw any, inParallel bool) {
	rawSteps, _ := raw.([]any)
	for i, s := range steps {
		var m map[string]any
		if i < len(rawSteps) {
			m, _ = rawSteps[i].(map[string]any)
		}
		here := fmt.Sprintf("%s[%d]", path, i)
		w.step(job, here, s, m, inParallel)
		w.steps(job, here+".steps", s.Steps, m["steps"], ghaStepRunType(s) == "parallel")
		w.steps(job, here+".else", s.Else, m["else"], false)
		w.steps(job, here+".on_error", s.OnError, m["on_error"], false)
	}
}

func (w *flowStepKeyWalk) step(job, path string, s FlowStepGHA, raw map[string]any, parallelChild bool) {
	runType := ghaStepRunType(s)
	keys, known := flowStepKeyTable[runType]
	if !known {
		return // no action, or a `run:` the gate refuses by name
	}
	where := fmt.Sprintf("flows.yaml: job %q step %s", job, path)
	if s.ID != "" {
		where += fmt.Sprintf(" (%q)", s.ID)
	}
	kind := flowStepKindName(runType)
	refuse := func(format string, args ...any) {
		w.refused = append(w.refused, where+": "+fmt.Sprintf(format, args...))
	}
	note := func(format string, args ...any) {
		w.ignored = append(w.ignored, where+": "+fmt.Sprintf(format, args...))
	}

	for _, key := range slices.Sorted(maps.Keys(raw)) {
		if !flowStepKeys[key] || key == "when" || key == "expect_rows" {
			continue
		}
		live, isLive := flowStepLiveIgnored(runType, false, key)
		switch {
		case key == "else" && strings.TrimSpace(s.If) == "":
			if runType != "if" { // `run: if` without a condition is reported below
				refuse("`else` has no `if:` next to it, so its steps would never run. `else:` is the other branch of the step's own `if:`.")
			}
		case keys.readsRoot(key):
		case key == "with" && flowStepHasLiveIgnoredWith(runType):
			// Judged key by key below.
		case isLive:
			note("`%s` is ignored on %s: %s.", key, kind, live.effect)
		default:
			refuse("%s", flowStepRootKeyRefusal(key, "`"+key+"`", runType, kind))
		}
	}
	if runType == "if" && strings.TrimSpace(s.If) == "" {
		refuse("`run: if` has no `if:` condition, so its steps would never run. Write the condition as `if: ${{ ... }}` next to `steps:` (`run: if` is not needed).")
	}
	// With `with.items` it is the shape deployed apps carry, noted below.
	if _, items := s.With["items"]; runType == "for_each" && strings.TrimSpace(s.ForEach) == "" && !items {
		refuse("`run: for_each` has no `for_each:` list, so its steps would never run. Write the list as `for_each: ${{ ... }}` next to `steps:` (`run: for_each` is not needed).")
	}

	noStatement := ""
	if flowRunTypeCountsRows(runType) {
		noStatement = flowStepNoStatement(s, runType)
	}
	if !keys.anyWith && (len(keys.with) > 0 || flowStepHasLiveIgnoredWith(runType)) {
		for _, key := range slices.Sorted(maps.Keys(s.With)) {
			live, isLive := flowStepLiveIgnored(runType, true, key)
			switch {
			case key == "expect_rows" || keys.readsWith(key):
			case key == "sql" && noStatement != "":
				// The missing statement below says where it goes.
			case isLive:
				note("`with.%s` is ignored on %s: %s.", key, kind, live.effect)
			case keys.readsRoot(key) && key != "with":
				refuse("`with.%s` is not read: `%s` is a step-level key. Write it next to `run:`, not under `with:`.", key, key)
			case flowStepKeys[key] && key != "with":
				refuse("%s", flowStepRootKeyRefusal(key, "`with."+key+"`", runType, kind))
			case len(keys.with) == 0:
				refuse("`with.%s` is not read on %s, which reads nothing under `with:`, so it would be ignored.", key, kind)
			default:
				refuse("`with.%s` is not read on %s, so it would be ignored. Under `with:` it reads: %s.", key, kind, strings.Join(slices.Sorted(slices.Values(keys.with)), ", "))
			}
		}
	}

	if noStatement != "" {
		refuse("the step has no SQL statement: %s. At run time it fails with `no SQL statement` (it used to run nothing and report success).", noStatement)
	}
	if flowRunTypeCountsRows(runType) {
		// The loader takes the step-root `query:` and never looks at
		// `with.query` then; `with.params` likewise wins over a step-root
		// `params:` outright.
		under, _ := s.With["query"].(string)
		if s.Query != "" && strings.TrimSpace(under) != "" && strings.TrimSpace(under) != strings.TrimSpace(s.Query) {
			refuse("`query` is written twice with different statements, at the step root and under `with:`. Only the step-root one runs. Keep one.")
		}
		rootParams, _ := s.RawParams.(map[string]any)
		underParams, _ := s.With["params"].(map[string]any)
		if runType == "sql" && len(rootParams) > 0 && len(underParams) > 0 && !reflect.DeepEqual(rootParams, underParams) {
			note("`params` is written twice with different values, at the step root and under `with:`. Only `with.params` is bound; the step-root `params` is ignored. Keep one map.")
		}
	}

	// execStepParallel runs each child once and returns the first error to
	// the block. A child gated by its own `if:` is wrapped and runs through
	// executeSteps, which retries it and runs its handler; any other child's
	// own modifiers are never looked at.
	if parallelChild && (strings.TrimSpace(s.If) == "" || runType == "if") {
		for _, key := range []string{"on_error", "retry", "retry_delay"} {
			if _, present := raw[key]; present && keys.readsRoot(key) {
				note("`%s` is ignored on a direct child of `run: parallel`: the block runs each child once and fails with the first error (only a child gated by its own `if:` is retried and runs its handler). Put `on_error:` on the parallel block.", key)
			}
		}
	}
}

// flowStepHasLiveIgnoredWith reports whether deployed apps write `with:` keys
// on this step type that the loader does not read.
func flowStepHasLiveIgnoredWith(runType string) bool {
	for _, row := range flowStepLiveIgnoredKeys {
		if row.runType == runType && row.with {
			return true
		}
	}
	return false
}

// flowStepKindName names a step type in a message.
func flowStepKindName(runType string) string {
	switch runType {
	case "if":
		return "an `if:` block"
	case "for_each":
		return "a `for_each:` loop"
	case "parallel":
		return "a `run: parallel` block"
	}
	return "a `run: " + runType + "` step"
}

// flowStepRootKeyRefusal words the refusal of a step-level key on a step type
// that does not read it. written is the key as the author wrote it (`timeout`
// or `with.timeout`).
func flowStepRootKeyRefusal(key, written, runType, kind string) string {
	block := flowStepKeyTable[runType].block
	switch key {
	case "timeout":
		if block {
			return fmt.Sprintf("%s is not read on %s, so it would limit nothing. %s; put it on that step.", written, kind, flowStepTimeoutTypes)
		}
		return fmt.Sprintf("%s is not read on %s, so the step would run with no time limit of its own. %s; remove it.", written, kind, flowStepTimeoutTypes)
	case "query":
		return fmt.Sprintf("%s is not read on %s: only a `run: sql` or `run: sql_dynamic` step runs a statement. Give the statement its own step.", written, kind)
	case "params":
		if runType == "sql_dynamic" {
			return fmt.Sprintf("%s is not read on %s, which binds nothing: it substitutes `${{ }}` references into the SQL as text. To bind values, use `run: sql` with `:name` placeholders.", written, kind)
		}
		return fmt.Sprintf("%s is not read on %s: only a `run: sql` step binds `params` to the `:name` placeholders of its query.", written, kind)
	case "steps":
		return fmt.Sprintf("%s is not read on %s, so the nested steps would never run. `steps:` belongs to an `if:` block (an `if:` with no `run:` next to it), a `for_each:` loop or `run: parallel`.", written, kind)
	case "for_each":
		return fmt.Sprintf("%s is not read on %s: the step would run once, not once per item. Make the loop its own step (`for_each:`, `as:`, `steps:`) and put this step under its `steps:`.", written, kind)
	case "as":
		return fmt.Sprintf("%s is not read on %s: it names the loop variable of a `for_each:` step.", written, kind)
	case "with":
		return fmt.Sprintf("%s is not read on %s, which has no options of its own. Put `with:` on the step that needs it, under `steps:`.", written, kind)
	case "retry", "retry_delay":
		return fmt.Sprintf("%s is on %s. A retried block runs its steps again from the top, those that already succeeded included, and still fails with the first error. Put `retry:` on the step that should be retried.", written, kind)
	}
	return fmt.Sprintf("%s is not read on %s, so it would be ignored.", written, kind)
}

// flowStepNoStatement says why a SQL step has no statement to run, as far as
// that is knowable from the file; "" when it has one or when the text is only
// known once rendered (a `run: sql_dynamic` template with references).
func flowStepNoStatement(s FlowStepGHA, runType string) string {
	text := ghaStepSQLText(s)
	if strings.TrimSpace(text) == "" {
		under, present := s.With["query"]
		if _, isText := under.(string); present && under != nil && !isText {
			return fmt.Sprintf("`with.query` must be text, not %T", under)
		}
		if _, sql := s.With["sql"]; sql {
			return "`with.sql` is not read. Write the statement as `with.query` (or `query:` at the step root)"
		}
		if s.Query != "" || present {
			return "its query is empty"
		}
		return "neither `query:` nor `with.query` is set"
	}
	static := normalizeGHARefs(text)
	if runType == "sql" {
		// References are bound parameters: they cannot supply the statement.
		static = flowSQLStaticText(text)
	} else if strings.Contains(static, "{{") {
		return ""
	}
	if _, ok := sqlRunnableText(static); !ok {
		return "its query holds only a comment or whitespace"
	}
	return ""
}

// flowStepKeysReference renders flowStepKeyTable for api(at:"flows") →
// step_keys, so the reference lists exactly the keys the write gate accepts.
func flowStepKeysReference() map[string]any {
	byType := make([]string, 0, len(flowStepKeyTable))
	for _, runType := range slices.Sorted(maps.Keys(flowStepKeyTable)) {
		row := flowStepKeyTable[runType]
		var parts []string
		if len(row.root) > 0 {
			parts = append(parts, "step root: "+strings.Join(row.root, ", "))
		}
		switch {
		case row.anyWith:
			parts = append(parts, "with: any key (each is a variable)")
		case len(row.with) > 0:
			parts = append(parts, "with: "+strings.Join(row.with, ", "))
		}
		name := runType
		if runType == "if" {
			name = "if (an `if:` with no `run:` next to it)"
		}
		byType = append(byType, name+" - "+strings.Join(parts, "; "))
	}
	ignored := make([]string, 0, len(flowStepLiveIgnoredKeys)+2)
	for _, row := range flowStepLiveIgnoredKeys {
		key := "`" + row.key + "` at the step root"
		if row.with {
			key = "`with." + row.key + "`"
		}
		ignored = append(ignored, fmt.Sprintf("%s on %s: %s.", key, flowStepKindName(row.runType), row.effect))
	}
	ignored = append(ignored,
		"`retry`, `retry_delay` and `on_error` on a direct child of `run: parallel` that has no `if:` of its own: the block runs each child once and fails with the first error. Put `on_error:` on the parallel block.",
		"`params` written both at the step root and under `with:` with different values: only `with.params` is bound.",
	)
	return map[string]any{
		"rule":       "Each step type reads a fixed set of keys (by_type, plus the step-level keys in every_step). A key outside that set is refused when the file is written (unreleased): the write gate and `benmore check` name the step and the key, and a deployed app logs the same line as a `WARNING` each time it loads its flows. Before, such a key was accepted and did nothing at run time. On `run: set` every `with:` key is a variable and may have any name.",
		"every_step": "Step-level keys go next to `run:`, never under `with:`: `id`, `if`, `else` (the steps to run when the step's `if:` is false, on an `if:` block and on a gated `if:` + `run:` step alike), `on_error`, and on a step that is one action `retry` and `retry_delay`. An `if:` block, a `for_each:` loop and `run: parallel` take no `retry` (a retried block would run its finished steps again; put `retry:` on the step to retry), no `with:` and no `timeout`. `steps:` belongs to those three only, `for_each:` and `as:` to the loop only: next to a `run:` they would be dropped and the step would run once.",
		"by_type":    byType,
		"timeout":    "`timeout` caps a `run: api`, `run: compute` or `run: transcribe` step. Write it under `with:` or at the step root; when both are set the step root wins. No other step type can be cut off, and `timeout` is refused on it at either position.",
		"sql":        "A SQL step's statement is `query:` at the step root or `with.query` (not `with.sql`); written in both places with different text it is refused. `params` binds at either position on `run: sql`; `run: sql_dynamic` binds nothing and refuses `params`. A SQL step with no statement (no query, an empty one, one that is only a comment) is refused, and at run time it fails the flow with `no SQL statement` where it used to run nothing and report success; a `run: sql_dynamic` template that renders nothing fails the same way.",
		"accepted_but_ignored": append([]string{
			"These are still accepted and still ignored, because deployed apps carry them. The loader names each in a `WARNING`; do not rely on them, and expect a later release to either honor or refuse each:",
		}, ignored...),
	}
}
