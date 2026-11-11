//go:build !cli

package main

// Flow values the runtime would not honor as written.
//
// Each of these passed the write gate and then did nothing, or the wrong
// thing, while the flow answered success:
//
//   - `retry: -2` skipped its step (the attempt loop ran zero times);
//   - `retry_delay: 5` (no unit) was read as the 2 s default;
//   - `with.paginate` written as anything but the map withToPaginate reads
//     (a boolean, quoted numbers, keys it does not know, `page_start: 0`, a
//     cursor strategy with no `cursor_field`) made one request, or read the
//     default number of pages from page 1, and reported success;
//   - SQL steps in a `run: parallel` block of a `transaction: true` flow: the
//     app does not register such a flow, so its route answered 404;
//   - `on.event.table` naming no table of the app never started the flow;
//   - `for_each` with `as: user` replaced the signed-in caller's values with
//     the loop's element, inside the loop and after it;
//   - a malformed email `attachments:` sent the message without the file;
//   - `min`/`max` on a declared input that is not a number were not checked.
//
// The write gate and `benmore check` refuse each one (validateFlowsYAML and
// the flows case of validateOnWriteInPending), except `min`/`max` on a
// non-number input, which deployed apps carry: that one is a warning
// (flowInputBoundsWarnings). A deployed file keeps loading and the loader logs
// the same message (parseGHAFlowFile, RegisterFlows for the event table).
// What the runtime does with such a value is in each message.
//
// Two more shapes are warned about (ghaMissingRequestValueWarnings, at the
// end of this file): an optional request field with no fallback on the
// right-hand side of an `if:`, where it has no value and equals nothing
// (flows_condition_unresolved.go), and in a redirect target, where the
// redirect is sent with the reference's own text.

import (
	"encoding/base64"
	"fmt"
	"log"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// flowRetryDelayDefault is the wait between a step's attempts when it sets no
// `retry_delay` (executeSteps).
const flowRetryDelayDefault = 2 * time.Second

// parseFlowRetryDelay reads a step's `retry_delay`: a Go duration (`500ms`,
// `5s`) or a whole number of seconds (`5`), the two forms the step-level
// `timeout` beside it takes (parseFlexDuration). It must be greater than
// zero: the executor cannot tell a zero wait from an unset one, and waits the
// default then. "" is unset.
func parseFlowRetryDelay(v string) (time.Duration, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		n, convErr := strconv.Atoi(v)
		if convErr != nil {
			return 0, fmt.Errorf("is not a duration")
		}
		d = time.Duration(n) * time.Second
	}
	if d <= 0 {
		return 0, fmt.Errorf("is not greater than zero")
	}
	return d, nil
}

// flowStepRetryProblems checks the `retry` and `retry_delay` of a step that is
// one action. A block takes neither (flowStepKeyProblems refuses them there).
func flowStepRetryProblems(s FlowStepGHA) []string {
	if flowStepKeyTable[ghaStepRunType(s)].block {
		return nil
	}
	var problems []string
	if s.Retry < 0 {
		problems = append(problems, fmt.Sprintf("`retry: %d` is not a number of attempts. `retry` is how many times the step may run in all: write a whole number of 1 or more (`retry: 3` runs it at most 3 times), or remove the key to run it once. The step runs once.", s.Retry))
	}
	if _, err := parseFlowRetryDelay(s.RetryDelay); err != nil {
		problems = append(problems, fmt.Sprintf("`retry_delay: %s` %s. Write a Go duration (`500ms`, `5s`, `1m`) or a whole number of seconds (`5`), greater than zero, as for `timeout`. The step waits the default %s between attempts.", strings.TrimSpace(s.RetryDelay), err, flowRetryDelayDefault))
	}
	return problems
}

// flowPaginateKey is one key of `with.paginate`.
type flowPaginateKey struct {
	name string
	// number: a whole number written without quotes; otherwise literal text.
	number bool
	// strategy the key belongs to; "" for either.
	strategy string
}

// flowPaginateKeys is the SINGLE SOURCE OF TRUTH for the keys of
// `with.paginate`: what withToPaginate reads and execStepAPIPaginated acts on.
// When withToPaginate starts or stops reading a key, change the row here too:
// TestFlowPaginateKeysMatchLoader fails until both agree.
var flowPaginateKeys = []flowPaginateKey{
	{name: "strategy"},
	{name: "items_field"},
	{name: "max_pages", number: true},
	{name: "cursor_field", strategy: "cursor"},
	{name: "cursor_param", strategy: "cursor"},
	{name: "page_param", strategy: "page"},
	{name: "page_start", number: true, strategy: "page"},
}

// Bounds the paginator applies (execStepAPIPaginated).
const (
	flowPaginateDefaultPages = 50
	flowPaginateMaxPages     = 500
)

func flowPaginateKeyNames() string {
	names := make([]string, len(flowPaginateKeys))
	for i, k := range flowPaginateKeys {
		names[i] = k.name
	}
	slices.Sort(names)
	return strings.Join(names, ", ")
}

// paginateWholeNumber reads a `with.paginate` number as withToPaginate does:
// a YAML integer. Quoted text, a decimal and a boolean are not one.
func paginateWholeNumber(v any) (int, bool) {
	n, ok := v.(int)
	return n, ok
}

// paginateValueProblems checks an api step's `with.paginate` against what the
// paginator reads. Every problem here used to be dropped without a word.
func paginateValueProblems(with map[string]any) []string {
	raw, set := with["paginate"]
	if !set {
		return nil
	}
	block, isMap := raw.(map[string]any)
	if !isMap {
		return []string{fmt.Sprintf("`with.paginate` must be a map such as `paginate: { strategy: page, items_field: $.data }`, not %s. It is not read: the step makes one request and does not paginate. Its keys: %s.", yamlValueKind(raw), flowPaginateKeyNames())}
	}
	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }

	known := map[string]flowPaginateKey{}
	for _, k := range flowPaginateKeys {
		known[k.name] = k
	}
	for _, name := range slices.Sorted(maps.Keys(block)) {
		if _, ok := known[name]; !ok {
			add("`with.paginate.%s` is not read, so it would be ignored. `paginate` reads: %s.", name, flowPaginateKeyNames())
		}
	}

	// The strategy as the paginator takes it: lowercased, cursor when unset.
	strategy := "cursor"
	strategyKnown := true
	if v, present := block["strategy"]; present {
		text, isText := v.(string)
		text = strings.ToLower(strings.TrimSpace(text))
		switch {
		case isText && (text == "cursor" || text == "page"):
			strategy = text
		default:
			strategyKnown = false
			add("`with.paginate.strategy: %v` is not a strategy. Use `cursor` (follow the next-cursor value each answer carries; the default) or `page` (count pages up). The step fails when it runs.", v)
		}
	}

	for _, key := range flowPaginateKeys {
		v, present := block[key.name]
		if !present || key.name == "strategy" {
			continue
		}
		where := "`with.paginate." + key.name + "`"
		if strategyKnown && key.strategy != "" && key.strategy != strategy {
			add("%s is read only with `strategy: %s`; with `strategy: %s` it would be ignored. Remove it, or set the strategy it belongs to.", where, key.strategy, strategy)
			continue
		}
		if key.number {
			n, whole := paginateWholeNumber(v)
			switch {
			case !whole:
				add("%s must be a whole number written without quotes (`%s: %s`), not %s. It is not read: %s.", where, key.name, paginateNumberExample(key.name), yamlValueKind(v), paginateNumberFallback(key.name))
			case key.name == "max_pages" && (n < 1 || n > flowPaginateMaxPages):
				add("`with.paginate.max_pages: %d` is outside 1 to %d. The step reads %s.", n, flowPaginateMaxPages, paginateMaxPagesFallback(n))
			case key.name == "page_start" && n < 0:
				add("`with.paginate.page_start: %d` is not a page number: write 0 or more (the first page an upstream numbers from 0 is `page_start: 0`). The step starts at page 1.", n)
			}
			continue
		}
		text, isText := v.(string)
		switch {
		case !isText || strings.TrimSpace(text) == "":
			add("%s must be text, not %s. It is not read: %s.", where, yamlValueKind(v), paginateTextFallback(key.name))
		case strings.Contains(text, "{{"):
			add("%s is literal text: a `${{ }}` reference there is not filled in, so the step would use the text as written.", where)
		case strings.HasSuffix(key.name, "_field") && strings.ContainsAny(text, "[]*"):
			add("%s `%s` is a dotted path into each JSON answer (`$.data`, `$.result.rows`, or `$` for the answer itself). Indexing (`[0]`) and wildcards are not read, so it would find nothing.", where, text)
		}
	}

	// A cursor strategy with nowhere to read the next cursor read one page and
	// reported success.
	if field, _ := block["cursor_field"].(string); strategyKnown && strategy == "cursor" && strings.TrimSpace(field) == "" {
		if _, written := block["cursor_field"]; !written {
			uses := "`strategy: cursor`"
			if _, set := block["strategy"]; !set {
				uses = "the cursor strategy (the default)"
			}
			add("`with.paginate` uses %s but has no `cursor_field`, the dotted path of the next cursor in each answer (`cursor_field: $.next_cursor`). Without it the step cannot ask for a second page; it fails when it runs. For numbered pages set `strategy: page`.", uses)
		}
	}
	return problems
}

func paginateNumberExample(key string) string {
	if key == "page_start" {
		return "0"
	}
	return "25"
}

func paginateNumberFallback(key string) string {
	if key == "page_start" {
		return "the step starts at page 1"
	}
	return fmt.Sprintf("the step reads up to the default %d pages", flowPaginateDefaultPages)
}

func paginateMaxPagesFallback(n int) string {
	if n > flowPaginateMaxPages {
		return fmt.Sprintf("at most %d pages", flowPaginateMaxPages)
	}
	return fmt.Sprintf("up to the default %d pages", flowPaginateDefaultPages)
}

func paginateTextFallback(key string) string {
	switch key {
	case "items_field":
		return "the step looks for the list at the default `$.items`"
	case "cursor_param":
		return "the cursor is sent as the default `cursor` query parameter"
	case "page_param":
		return "the page number is sent as the default `page` query parameter"
	}
	return "the step fails when it runs"
}

// yamlValueKind names a decoded YAML value's kind for a message.
func yamlValueKind(v any) string {
	switch t := v.(type) {
	case nil:
		return "an empty value"
	case string:
		if strings.TrimSpace(t) == "" {
			return "empty text"
		}
		return fmt.Sprintf("the text %q", truncate(t, 60))
	case bool:
		return fmt.Sprintf("the boolean `%v`", t)
	case int, int64, uint64:
		return fmt.Sprintf("the number %v", t)
	case float64:
		return fmt.Sprintf("the decimal %v", t)
	case map[string]any:
		return "a map"
	case []any:
		return "a list"
	}
	return fmt.Sprintf("a %T", v)
}

// flowLoopNameRe is a loop variable every reference can read: in a value
// (`${{ name.column }}`), in a SQL bind and in an `if:` condition. With any
// other character (a space, `:`, `$`, a bracket, a letter outside ASCII) a
// value still reads it, but a condition on it is silently false or the step
// fails.
var flowLoopNameRe = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// flowRuntimePrivatePrefix starts the names the flow runtime keeps for itself
// (flowStepNamedParamsKey, flowRequestBodyPayloadField).
const flowRuntimePrivatePrefix = "__benmore_"

// flowLoopNameReplacesIdentity reports a loop variable name the runtime owns
// for the caller's identity or the app's environment: flowIdentityKeys, any
// `user.` or `env.` path, and the runtime's private names. These are exactly
// the names a request may never supply (stripRequestIdentityKeys); a loop's
// elements can come from the request, so a loop may not write them either.
// execStepForEach fails such a loop before it writes anything.
func flowLoopNameReplacesIdentity(name string) bool {
	return slices.Contains(flowIdentityKeys, name) || strings.HasPrefix(name, "user.") ||
		name == "env" || strings.HasPrefix(name, "env.") || strings.HasPrefix(name, flowRuntimePrivatePrefix)
}

// flowLoopNameProblem explains why a `for_each` step's `as:` cannot be its
// loop variable; "" when it can. An empty `as:` is the default `item`.
func flowLoopNameProblem(as string) string {
	if strings.TrimSpace(as) == "" {
		return ""
	}
	const rename = " Give the loop variable a name of its own (for example `as: row`, read as `${{ row.column }}`)."
	switch {
	case slices.Contains(flowIdentityKeys, as) || strings.HasPrefix(as, "user."):
		return fmt.Sprintf("`as: %s` names the signed-in caller's identity (`${{ user.* }}`, `:user_id` and the other identity values are set from the session only). The loop's element would stand in for it inside the loop and after it, so the loop is not run: it fails the flow.%s", as, rename)
	case as == "env" || strings.HasPrefix(as, "env."):
		return fmt.Sprintf("`as: %s` names the app's environment: `${{ env.NAME }}` always reads an environment value, so the loop variable could never be read, and the loop is not run: it fails the flow.%s", as, rename)
	case strings.HasPrefix(as, flowRuntimePrivatePrefix):
		return fmt.Sprintf("`as: %s` starts with `%s`, which the runtime keeps for its own values, so the loop is not run: it fails the flow.%s", as, flowRuntimePrivatePrefix, rename)
	case as == "params" || strings.HasPrefix(as, "params."):
		return fmt.Sprintf("`as: %s` collides with `${{ params.<name> }}`, which always reads the request field `<name>`: the fields of the loop's element could not be read.%s", as, rename)
	case as == "steps" || strings.HasPrefix(as, "steps."):
		return fmt.Sprintf("`as: %s` collides with `${{ steps.<id>.outputs.<name> }}`, which always reads a step's output: the fields of the loop's element could not be read.%s", as, rename)
	case as == "error":
		return "`as: error` is the name of the failed step's error inside an `on_error:` handler, which would replace the loop's element there." + rename
	case !flowLoopNameRe.MatchString(as):
		return fmt.Sprintf("`as: %s` is not a name every reference can read: an `if:` condition on it would be false without a word. Use letters, digits, `_`, `-` and `.` only.%s", as, rename)
	}
	return ""
}

// flowEmailAttachmentKeys are the keys of one `attachments:` entry
// (withToEmail).
var flowEmailAttachmentKeys = []string{"content", "content_type", "filename"}

// emailAttachmentUnresolvable explains an `attachments:` value, or one entry
// of it, that names no file to attach: the message would have gone out without
// it. "" when every entry has content. Shared by the write gate and the
// loader, which hands the reason to the step (FlowEmail.AttachmentsError) so
// the send fails before anything leaves.
func emailAttachmentUnresolvable(raw any) string {
	const shape = "a list of `{ filename, content, content_type }` entries, `content` being the file's bytes as base64"
	list, isList := raw.([]any)
	if !isList {
		return fmt.Sprintf("`with.attachments` must be %s, not %s", shape, yamlValueKind(raw))
	}
	for i, item := range list {
		entry, isMap := item.(map[string]any)
		if !isMap {
			return fmt.Sprintf("`with.attachments[%d]` must be a map `{ filename, content, content_type }`, not %s", i, yamlValueKind(item))
		}
		if text, ok := entry["content"].(string); !ok || strings.TrimSpace(text) == "" {
			hint := ""
			if _, path := entry["path"]; path {
				hint = " (there is no `path:` key: a stored file is not attached by its reference)"
			}
			return fmt.Sprintf("`with.attachments[%d]` has no `content`: the file's bytes as base64 text, or a `${{ }}` value such as `${{ steps.csv.outputs.text | base64 }}`%s", i, hint)
		}
	}
	return ""
}

// emailAttachmentProblems checks an email step's `with.attachments` as far as
// it is literal: its shape, the keys of each entry, a missing filename, a
// literal `content` that is not base64 and a `content_type` that is not
// literal text.
func emailAttachmentProblems(with map[string]any) []string {
	raw, set := with["attachments"]
	if !set {
		return nil
	}
	const unsent = " The step fails when it runs and nothing is sent."
	if problem := emailAttachmentUnresolvable(raw); problem != "" {
		return []string{problem + "." + unsent}
	}
	var problems []string
	for i, item := range raw.([]any) {
		entry := item.(map[string]any)
		for _, key := range slices.Sorted(maps.Keys(entry)) {
			if !slices.Contains(flowEmailAttachmentKeys, key) {
				problems = append(problems, fmt.Sprintf("`with.attachments[%d].%s` is not read, so it would be ignored. An attachment takes: %s.", i, key, strings.Join(flowEmailAttachmentKeys, ", ")))
			}
		}
		if text, ok := entry["filename"].(string); !ok || strings.TrimSpace(text) == "" {
			problems = append(problems, fmt.Sprintf("`with.attachments[%d]` has no `filename` (text such as `report.csv`; it may be a `${{ }}` value). The file would be attached without a name.", i))
		}
		content := strings.TrimSpace(entry["content"].(string))
		if !strings.Contains(content, "{{") {
			if _, err := base64.StdEncoding.DecodeString(content); err != nil {
				problems = append(problems, fmt.Sprintf("`with.attachments[%d].content` is not base64. Write the file's bytes as standard base64, or encode text a step produced with `${{ steps.<id>.outputs.<name> | base64 }}`.%s", i, unsent))
			}
		}
		if rawType, present := entry["content_type"]; present {
			text, isText := rawType.(string)
			switch {
			case !isText || strings.TrimSpace(text) == "":
				problems = append(problems, fmt.Sprintf("`with.attachments[%d].content_type` must be text such as `text/csv`, not %s. It is not read: the type follows the filename's extension.", i, yamlValueKind(rawType)))
			case strings.Contains(text, "{{"):
				problems = append(problems, fmt.Sprintf("`with.attachments[%d].content_type` is literal text: a `${{ }}` reference there is not filled in and would be sent as written. Leave it out to let the type follow the filename's extension.", i))
			}
		}
	}
	return problems
}

// flowParallelSQLInTransactionProblems refuses SQL steps in a `run: parallel`
// block of a `transaction: true` flow (request or schedule). The loader's
// reason is flowValidateParallelTx's: the block's steps run at the same time
// and one transaction cannot be shared between them, so RegisterFlows skips
// the whole flow and its route answers 404. The gate used to accept the file.
func flowParallelSQLInTransactionProblems(file FlowFileGHA) []string {
	transactional := (file.On.Request != nil && file.On.Request.Transaction) || (file.On.Schedule != nil && file.On.Schedule.Transaction)
	if !transactional {
		return nil
	}
	var problems []string
	for _, job := range slices.Sorted(maps.Keys(file.Jobs)) {
		flow := &Flow{Name: job, Transaction: true, Steps: convertGHASteps(file.Jobs[job].Steps)}
		if flowValidateParallelTx(flow) == nil {
			continue
		}
		outcome := "its route would answer 404"
		if file.On.Schedule != nil && file.On.Request == nil {
			outcome = "it would never run"
		}
		problems = append(problems, fmt.Sprintf("flows.yaml: job %q has SQL steps inside a `run: parallel` block, and the flow is `transaction: true`. The steps of a parallel block run at the same time and one transaction cannot be shared between them, so the app does not register this flow: %s. Move the SQL steps out of the parallel block (before or after it), or remove `transaction: true`.", job, outcome))
	}
	return problems
}

// flowInputBoundsProblems lists declared inputs that set `min` or `max` on a
// type other than number. validateFlowInputValues compares the bounds only on
// a number, so on text they limit nothing (not its length either). Deployed
// apps carry these, so this is a warning and a loader log line, not a refusal.
func flowInputBoundsProblems(inputs map[string]FlowInput) []string {
	var problems []string
	for _, name := range slices.Sorted(maps.Keys(inputs)) {
		in := inputs[name]
		if in.Type == "number" || in.Type == "" || (in.Min == nil && in.Max == nil) {
			continue
		}
		var set []string
		if in.Min != nil {
			set = append(set, "`min`")
		}
		if in.Max != nil {
			set = append(set, "`max`")
		}
		problems = append(problems, fmt.Sprintf("on.request.inputs.%s sets %s, but its type is %q: `min` and `max` bound a `type: number` input only. On any other type they are not checked (they do not limit a text's length), so every value passes. Remove them, or check the value in a step (`if: ${{ ... }}` with a respond).", name, strings.Join(set, " and "), in.Type))
	}
	return problems
}

// flowInputBoundsWarnings reports flowInputBoundsProblems for the flow file
// just written, or for every flow file on a full check.
func flowInputBoundsWarnings(dir, writtenPath string) []CheckFinding {
	var findings []CheckFinding
	for _, rel := range flowFilesFor(dir, writtenPath) {
		data, err := readFileInRoot(dir, rel)
		if err != nil {
			continue
		}
		var file FlowFileGHA
		if decodeConfigYAML(data, &file) != nil || file.On.Request == nil {
			continue
		}
		for _, msg := range flowInputBoundsProblems(file.On.Request.Inputs) {
			findings = append(findings, CheckFinding{Severity: "warning", Source: "flows", File: filepath.ToSlash(rel), Message: filepath.ToSlash(rel) + ": " + msg})
		}
	}
	return findings
}

// flowEventTables is what an `on.event.table` is judged against.
type flowEventTables struct {
	// tables are the names an event can carry, spelled as stored: an event
	// matches its flow's table exactly (FireFlowsForEvent).
	tables []string
	// models maps a schema.prisma model name to its table.
	models map[string]string
	// migrated holds the tables the app's own migrations create or rename
	// into place, as each migration spells them.
	migrated map[string]bool
}

// readFlowEventTables reads the tables of an app's sources, the way the write
// gate reads them for its other checks: schema.prisma (else schema.sql) and
// the tables the app's own migrations create (as readLoadRefSchema finds
// them). nil when there is no readable schema to judge against.
func readFlowEventTables(appDir string) *flowEventTables {
	if appDir == "" {
		return nil
	}
	// Through the app's root, regular files only: the check also runs in
	// the router, on a tenant's directory.
	read := func(name string) []byte {
		data, err := readFileInRoot(appDir, name)
		if err != nil {
			return nil
		}
		return data
	}
	out := &flowEventTables{models: map[string]string{}, migrated: map[string]bool{}}
	if data := read("schema.prisma"); data != nil {
		models, err := ParsePrismaSchema(string(data))
		if err != nil {
			return nil
		}
		for _, m := range models {
			out.tables = append(out.tables, m.Table)
			out.models[m.Name] = m.Table
		}
	} else if data := read("schema.sql"); data != nil {
		for _, m := range schemaSQLCreateTableRe.FindAllStringSubmatch(string(data), -1) {
			if !strings.HasPrefix(sqliteIdentifierFold(m[1]), "_benmore_") {
				out.tables = append(out.tables, m[1])
			}
		}
	}
	if len(out.tables) == 0 {
		return nil
	}
	entries, _ := os.ReadDir(filepath.Join(appDir, "migrations"))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".sql") {
			continue
		}
		body := string(read("migrations/" + entry.Name()))
		// A migration the Prisma step generated replays the schema's history
		// and says nothing about what exists now.
		if generatedPrismaMigration(entry.Name(), body) {
			continue
		}
		for _, re := range []*regexp.Regexp{migrationCreateTableRe, migrationRenameTableRe} {
			for _, m := range re.FindAllStringSubmatch(body, -1) {
				out.migrated[m[1]] = true
			}
		}
	}
	slices.Sort(out.tables)
	return out
}

// flowEventTableProblem explains an `on.event.table` that starts no flow.
// refuse: the name is not a table of the app. warn: a migration creates a
// table of that name under another spelling, and which one is stored cannot
// be checked here. Both are "" when the name is a table as written.
func flowEventTableProblem(name string, known *flowEventTables) (refuse, warn string) {
	// The name as written: an event matches it exactly, spaces included. An
	// empty one is flowTriggerValueViolation's.
	if strings.TrimSpace(name) == "" || known == nil {
		return "", ""
	}
	const exact = "An event flow starts when a row of its table is written through the API, and the table name is matched exactly, as in `/api/<table>`."
	if strings.HasPrefix(sqliteIdentifierFold(name), "_benmore_") {
		return fmt.Sprintf("flows.yaml: on.event.table %q is a framework table. Its rows are not written through the app's API, so no event flow ever starts on it. For sign-ups and profile changes use a hooks.yaml hook on `_benmore_users` (api(at:\"hooks\")).", name), ""
	}
	if slices.Contains(known.tables, name) {
		return "", ""
	}
	if tableName, isModel := known.models[name]; isModel {
		return fmt.Sprintf("flows.yaml: on.event.table %q is the schema's model name; its table is %q. %s Write `table: %s`, or the flow never runs.", name, tableName, exact, tableName), ""
	}
	for _, t := range known.tables {
		if strings.EqualFold(t, name) {
			return fmt.Sprintf("flows.yaml: on.event.table %q differs from the table %q only in letter case. %s Write `table: %s`, or the flow never runs.", name, t, exact, t), ""
		}
	}
	// A table only a migration creates can exist: never refused. Spelled as
	// the migration spells it, it is that table.
	if known.migrated[name] {
		return "", ""
	}
	for spelled := range known.migrated {
		if strings.EqualFold(spelled, name) {
			return "", fmt.Sprintf("flows.yaml: on.event.table %q is not a table of the schema; a migration creates it, spelled %q. %s Check that the table is stored under exactly this name: with another spelling the flow never runs.", name, spelled, exact)
		}
	}
	nearest, best := "", 3
	for _, t := range known.tables {
		if d := levenshtein(strings.ToLower(name), strings.ToLower(t)); d < best {
			nearest, best = t, d
		}
	}
	hint := ""
	if nearest != "" {
		hint = fmt.Sprintf(" Did you mean `table: %s`?", nearest)
	}
	return fmt.Sprintf("flows.yaml: on.event.table %q is not a table of this app, so the flow would never run.%s %s Tables: %s.", name, hint, exact, strings.Join(known.tables, ", ")), ""
}

// flowEventTableViolation is the write gate's check of a flow file's
// `on.event.table` against the app's tables. A write that defers its reload
// to a schema or migration file of the same batch is left to the check that
// follows that file's write, which re-reads every flow file.
func flowEventTableViolation(appDir, content string, pending map[string]bool) string {
	for file := range pending {
		if file == "schema.prisma" || file == "schema.sql" || strings.HasPrefix(file, "migrations/") {
			return ""
		}
	}
	var file FlowFileGHA
	if yamlUnmarshal([]byte(content), &file) != nil || file.On.Event == nil || file.Jobs == nil {
		return ""
	}
	refuse, _ := flowEventTableProblem(file.On.Event.Table, readFlowEventTables(appDir))
	return refuse
}

// flowEventTableWarnings reports the event tables a migration creates under
// another spelling, for the flow file just written or for every flow file on
// a full check.
func flowEventTableWarnings(dir, writtenPath string) []CheckFinding {
	files := flowFilesFor(dir, writtenPath)
	if len(files) == 0 {
		return nil
	}
	var known *flowEventTables
	var findings []CheckFinding
	for _, rel := range files {
		data, err := readFileInRoot(dir, rel)
		if err != nil {
			continue
		}
		var file FlowFileGHA
		if decodeConfigYAML(data, &file) != nil || file.On.Event == nil {
			continue
		}
		if known == nil {
			if known = readFlowEventTables(dir); known == nil {
				return nil
			}
		}
		if _, warn := flowEventTableProblem(file.On.Event.Table, known); warn != "" {
			msg := strings.Replace(warn, "flows.yaml: ", filepath.ToSlash(rel)+": ", 1)
			findings = append(findings, CheckFinding{Severity: "warning", Source: "flows", File: filepath.ToSlash(rel), Message: msg})
		}
	}
	return findings
}

// warnFlowEventTables logs, when an app's flows are registered, each event
// flow whose table the app does not serve: such a flow never starts. It reads
// the tables the app loaded, so it is exact for a table only a migration
// creates. The write gate refuses the same names (flowEventTableViolation).
func warnFlowEventTables(app *App, flows []Flow) {
	if app == nil || len(app.Tables) == 0 {
		return
	}
	known := &flowEventTables{}
	for _, t := range app.Tables {
		known.tables = append(known.tables, t.Name)
	}
	slices.Sort(known.tables)
	for _, f := range flows {
		if !strings.HasPrefix(f.Trigger.Type, "on_") {
			continue
		}
		if refuse, _ := flowEventTableProblem(f.Trigger.Table, known); refuse != "" {
			where := f.Source
			if where == "" {
				where = "flow " + strconv.Quote(f.Name)
			}
			log.Printf("WARNING: %s: %s", where, strings.TrimPrefix(refuse, "flows.yaml: "))
		}
	}
}

// A request field read with no fallback where a missing value is not empty.
//
// On the right-hand side of a single `if:` comparison a `${{ params.<name> }}`
// the caller left out has no value: it equals nothing and only `!=` holds
// (flows_condition_unresolved.go), while a missing left side compares as
// empty. In a `run: redirect` target it is sent as the text
// `{{params.<name>}}`: the step answers before its unresolved-reference
// check, and changing that changes what deployed flows answer. The write gate
// warns about both: ghaMissingRequestValueWarnings, an advisory like
// ghaRedirectWarnings.

// flowDefaultPipeRe matches the `| default:` pipe of a reference.
var flowDefaultPipeRe = regexp.MustCompile(`\|\s*default\s*:`)

// flowRequestFieldsAlwaysSent names the request fields a flow always has a
// value for: its path parameters, and declared inputs that are required
// (a request without one is answered 422 before any step) or have a default.
func flowRequestFieldsAlwaysSent(req *FlowRequestTrigger) map[string]bool {
	always := map[string]bool{}
	if req == nil {
		return always
	}
	for name, in := range req.Inputs {
		if in.Required || in.Default != nil {
			always[name] = true
		}
	}
	for _, part := range strings.Split(req.Path, "/") {
		if name, isParam := strings.CutPrefix(part, ":"); isParam && name != "" {
			always[name] = true
		}
	}
	return always
}

// flowOptionalRequestRef reads one normalized reference (the inside of a
// `{{ }}`): the request field it names when it is `params.<name>` with no
// `||` or `| default:` fallback and the request may leave <name> out.
func flowOptionalRequestRef(inner string, always map[string]bool) (field string, ok bool) {
	if strings.Contains(inner, "||") || flowDefaultPipeRe.MatchString(inner) {
		return "", false
	}
	rest, isParam := strings.CutPrefix(ghaRefBase(inner), "params.")
	if !isParam {
		return "", false
	}
	if i := strings.IndexAny(rest, ".["); i >= 0 {
		rest = rest[:i]
	}
	if rest == "" || always[rest] || slices.Contains(flowIdentityKeys, rest) {
		return "", false
	}
	return rest, true
}

// ghaMissingRequestValueWarnings lists, for a request flow, each `if:` whose
// right-hand side is an optional request field with no fallback, and each
// `run: redirect` whose `to:` holds one. Advisory: the file is accepted.
// Shared by the write path and `benmore check` (redirectWarnings).
func ghaMissingRequestValueWarnings(content string) []string {
	var file FlowFileGHA
	if err := yamlUnmarshal([]byte(content), &file); err != nil || file.Jobs == nil || file.On.Request == nil {
		return nil
	}
	always := flowRequestFieldsAlwaysSent(file.On.Request)
	const fix = "Give it a fallback, `${{ params.%[1]s || '' }}` (or `| default:''`), or declare `%[1]s` under `on.request.inputs` with `required: true`."
	var out []string
	var walk func(job, path string, steps []FlowStepGHA)
	walk = func(job, path string, steps []FlowStepGHA) {
		for i, s := range steps {
			here := fmt.Sprintf("%s[%d]", path, i)
			where := fmt.Sprintf("job %q step %s", job, here)
			if s.ID != "" {
				where += fmt.Sprintf(" (%q)", s.ID)
			}
			if strings.TrimSpace(s.If) != "" {
				// As the evaluator reads it: one comparison, the operator found
				// in the author's text, the right side one reference.
				cond := ghaIfToFlowCondition(s.If)
				if !conditionUsesExpressionSyntax(cond) {
					if lhs, _, rhs, ok := splitConditionOperator(cond); ok && lhs != "" {
						if inner, sole := soleFlowExpr(rhs); sole {
							if field, optional := flowOptionalRequestRef(inner, always); optional {
								out = append(out, fmt.Sprintf("%s: `if: %s` has the request field `%s` on its right-hand side with no fallback. When a request leaves `%s` out, that side has no value and equals nothing: `!=` holds and `==` does not, whatever the left side is. ",
									where, truncate(strings.TrimSpace(s.If), 160), field, field)+fmt.Sprintf(fix, field))
							}
						}
					}
				}
			}
			if ghaStepRunType(s) == "redirect" {
				to, _ := s.With["to"].(string)
				var fields []string
				for _, ref := range flowTemplateRefRe.FindAllString(normalizeGHARefs(to), -1) {
					inner, sole := soleFlowExpr(ref)
					if !sole {
						continue
					}
					field, optional := flowOptionalRequestRef(inner, always)
					if !optional || slices.Contains(fields, field) {
						continue
					}
					fields = append(fields, field)
					out = append(out, fmt.Sprintf("%s: `to: %s` reads the request field `%s` with no fallback. When a request leaves `%s` out, the redirect is still sent, with the text `{{%s}}` in its target. ",
						where, truncate(strings.TrimSpace(to), 160), field, field, inner)+fmt.Sprintf(fix, field))
				}
			}
			walk(job, here+".steps", s.Steps)
			walk(job, here+".else", s.Else)
			walk(job, here+".on_error", s.OnError)
		}
	}
	for _, job := range slices.Sorted(maps.Keys(file.Jobs)) {
		walk(job, "steps", file.Jobs[job].Steps)
	}
	return out
}

// flowCheckedValuesReference is api(at:"flows") → checked_values: the values
// this file checks, for app builders. The key lists are rendered from
// flowPaginateKeys, flowEmailAttachmentKeys and flowIdentityKeys, so the
// reference names exactly what the gate accepts and refuses.
func flowCheckedValuesReference() map[string]any {
	quoted := func(names []string) string {
		out := make([]string, len(names))
		for i, name := range names {
			out[i] = "`" + name + "`"
		}
		return strings.Join(out, ", ")
	}
	var cursorKeys, pageKeys []string
	for _, key := range flowPaginateKeys {
		switch key.strategy {
		case "cursor":
			cursorKeys = append(cursorKeys, key.name)
		case "page":
			pageKeys = append(pageKeys, key.name)
		}
	}
	return map[string]any{
		"rule":                    "A flow value the runtime would not honor as written is refused when the file is written: the write gate and `benmore check` name the step, the key, the value and what is accepted. An app that already carries such a value keeps loading, and its log names the value in a `WARNING` each time the flows load.",
		"retry":                   "`retry` and `retry_delay` are described in step_retry. Refused: a negative `retry`; a `retry_delay` that is not a Go duration or a whole number of seconds, or is not greater than zero. In an app that already has one, the step runs once and waits the default " + flowRetryDelayDefault.String() + ".",
		"paginate":                fmt.Sprintf("`with.paginate` on a `run: api` step is described in api_paginate. Refused: a value that is not a map; a key other than %s; a `strategy` other than `cursor` or `page`; a key of the other strategy (%s belong to cursor, %s to page); `max_pages` outside 1 to %d, a negative `page_start`, or either of them quoted; a path with `[0]` indexing or a `${{ }}`; a cursor strategy with no `cursor_field`. In an app that already has one the value keeps the reading it had (the default %d pages, page 1, one unpaginated request for a block that is not a map), except an unknown strategy and a cursor strategy with no `cursor_field`, which fail the step when it runs.", quoted(strings.Split(flowPaginateKeyNames(), ", ")), quoted(cursorKeys), quoted(pageKeys), flowPaginateMaxPages, flowPaginateDefaultPages),
		"loop_variable":           "A `for_each` loop's `as:` is a name made of letters, digits, `_`, `-` and `.` (default `item`); with any other character an `if:` condition could not read it, so it is refused. These names are refused too: " + quoted(flowIdentityKeys) + " and any `user.<field>` (the signed-in caller's identity, set from the session only), `env`, `params`, `steps` and `error`. A loop whose variable names the caller's identity or `env` never runs: the loop step fails the flow, so an element of the list can never stand in for `${{ user.* }}`.",
		"attachments":             "`with.attachments` on a `run: email` step is described in email_attachments. Refused: a value that is not a list; an entry that is not a map; a key other than " + quoted(flowEmailAttachmentKeys) + "; an entry with no `content` or no `filename`; literal `content` that is not base64; a `content_type` that is not literal text. When the step runs, an attachment it cannot build fails the step before anything is sent.",
		"parallel_sql":            "SQL steps inside a `run: parallel` block of a `transaction: true` flow (request or schedule) are refused, at any depth: the block's steps run at the same time and cannot share the flow's one transaction (parallel → not_inside). An app that already has such a flow does not register it. Move the SQL steps before or after the block, or drop `transaction: true`.",
		"event_table":             "An `on.event.table` that is no table of the app is refused, with the table to write named: see trigger_event → declare. A table that only one of the app's migrations creates is accepted.",
		"input_bounds":            "`min` and `max` on a declared input that is not `type: number` are accepted and not checked; the write gate and `benmore check` warn. See inputs → declare.",
		"optional_request_values": "A request field read as `${{ params.<name> }}` with no fallback has no value when the request leaves it out. The write gate and `benmore check` warn about it in two places: on the right-hand side of an `if:` comparison, where it then equals nothing (`!=` holds and `==` does not, whatever the left side is: missing_values), and in a `run: redirect` target, where the redirect is sent with the text `{{params.<name>}}` in it. Write `${{ params.<name> || '' }}` (or `| default:''`), or declare the field under `on.request.inputs` with `required: true`; a path parameter and an input with a `default` always have a value.",
	}
}
