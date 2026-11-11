//go:build !cli

package main

// The write gate refuses flow values the runtime would not honor as written,
// each with a message naming the key, the value and what is accepted, and it
// still accepts the neighbouring values that work.

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// ignoredValueFlow is a request flow around one step.
func ignoredValueFlow(step string) string {
	return "on:\n  request:\n    method: POST\n    path: /api/probe\njobs:\n  j:\n    steps:\n" + step +
		"      - run: respond\n        with: { status: 200, json: { ok: true } }\n"
}

type ignoredValueCase struct {
	name string
	flow string
	// want is text the refusal must contain; empty means the gate accepts.
	want []string
}

func runIgnoredValueCases(t *testing.T, cases []ignoredValueCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			msg := validateFlowsYAML(c.flow)
			if len(c.want) == 0 {
				if msg != "" {
					t.Fatalf("the gate refuses a value the runtime honors:\n%s", msg)
				}
				return
			}
			if msg == "" {
				t.Fatalf("the gate accepts it; want a refusal naming %q", c.want)
			}
			for _, part := range c.want {
				if !strings.Contains(msg, part) {
					t.Errorf("the refusal does not say %q:\n%s", part, msg)
				}
			}
		})
	}
}

func TestFlowRetryValuesTheRuntimeCannotHonorAreRefused(t *testing.T) {
	step := func(modifiers string) string {
		return ignoredValueFlow("      - id: w\n        run: sql\n" + modifiers + "        with: { query: \"SELECT 1 AS n\" }\n")
	}
	runIgnoredValueCases(t, []ignoredValueCase{
		{name: "retry negative", flow: step("        retry: -2\n"), want: []string{`step steps[0] ("w")`, "`retry: -2`", "whole number of 1 or more", "The step runs once"}},
		{name: "retry_delay words", flow: step("        retry: 3\n        retry_delay: 1 second\n"), want: []string{"`retry_delay: 1 second` is not a duration", "`500ms`", "whole number of seconds", "default 2s"}},
		{name: "retry_delay negative", flow: step("        retry: 3\n        retry_delay: -5s\n"), want: []string{"`retry_delay: -5s` is not greater than zero"}},
		{name: "retry_delay zero", flow: step("        retry: 3\n        retry_delay: 0\n"), want: []string{"`retry_delay: 0` is not greater than zero", "default 2s"}},
		{name: "retry_delay decimal seconds", flow: step("        retry: 3\n        retry_delay: \"1.5\"\n"), want: []string{"`retry_delay: 1.5` is not a duration"}},

		{name: "retry 3 with a duration", flow: step("        retry: 3\n        retry_delay: 5s\n")},
		{name: "retry_delay in milliseconds", flow: step("        retry: 2\n        retry_delay: 650ms\n")},
		{name: "retry_delay whole seconds", flow: step("        retry: 3\n        retry_delay: 5\n")},
		{name: "retry_delay whole seconds quoted", flow: step("        retry: 3\n        retry_delay: \"5\"\n")},
		{name: "retry 1", flow: step("        retry: 1\n")},
		{name: "retry 0", flow: step("        retry: 0\n")},
		{name: "no retry", flow: step("")},
	})
}

// A step's `retry_delay` and its `timeout` take the same two forms.
func TestRetryDelayReadsWhatTimeoutReads(t *testing.T) {
	for _, text := range []string{"5s", "650ms", "1m", "5", " 7 "} {
		delay, err := parseFlowRetryDelay(text)
		if err != nil {
			t.Errorf("retry_delay %q: %v", text, err)
			continue
		}
		if timeout := parseFlexDuration(text); timeout != delay {
			t.Errorf("%q is %s as a retry_delay and %s as a timeout", text, delay, timeout)
		}
	}
	for _, text := range []string{"1 second", "abc", "-5s", "-5", "0", "0s", "1.5"} {
		if delay, err := parseFlowRetryDelay(text); err == nil {
			t.Errorf("retry_delay %q is read as %s; want an error", text, delay)
		}
	}
	if delay, err := parseFlowRetryDelay(""); delay != 0 || err != nil {
		t.Errorf("an unset retry_delay = %s, %v", delay, err)
	}
}

func TestFlowPaginateValuesTheRuntimeCannotHonorAreRefused(t *testing.T) {
	step := func(paginate string) string {
		return ignoredValueFlow("      - id: c\n        run: api\n        with:\n          url: https://api.example.com/v1/contacts\n          paginate: " + paginate + "\n")
	}
	runIgnoredValueCases(t, []ignoredValueCase{
		{name: "not a map", flow: step("true"), want: []string{"`with.paginate` must be a map", "the boolean `true`", "makes one request and does not paginate", "cursor_field, cursor_param, items_field, max_pages, page_param, page_start, strategy"}},
		{name: "a list", flow: step("[page]"), want: []string{"`with.paginate` must be a map", "not a list"}},
		{name: "unknown keys", flow: step("{ strategy: page, limit: 100, next_field: $.next }"), want: []string{"`with.paginate.limit` is not read", "`with.paginate.next_field` is not read", "`paginate` reads: cursor_field"}},
		{name: "unknown strategy", flow: step("{ strategy: offset, items_field: $.data }"), want: []string{"`with.paginate.strategy: offset` is not a strategy", "`cursor`", "`page`", "fails when it runs"}},
		{name: "strategy not text", flow: step("{ strategy: 1 }"), want: []string{"`with.paginate.strategy: 1` is not a strategy"}},
		{name: "max_pages quoted", flow: step("{ strategy: page, max_pages: \"2\" }"), want: []string{"`with.paginate.max_pages` must be a whole number written without quotes", `the text "2"`, "up to the default 50 pages"}},
		{name: "page_start quoted", flow: step("{ strategy: page, page_start: \"0\" }"), want: []string{"`with.paginate.page_start` must be a whole number written without quotes", "starts at page 1"}},
		{name: "max_pages decimal", flow: step("{ strategy: page, max_pages: 2.5 }"), want: []string{"`with.paginate.max_pages` must be a whole number", "the decimal 2.5"}},
		{name: "max_pages zero", flow: step("{ strategy: page, max_pages: 0 }"), want: []string{"`with.paginate.max_pages: 0` is outside 1 to 500", "up to the default 50 pages"}},
		{name: "max_pages negative", flow: step("{ strategy: page, max_pages: -1 }"), want: []string{"`with.paginate.max_pages: -1` is outside 1 to 500"}},
		{name: "max_pages over the cap", flow: step("{ strategy: page, max_pages: 1000 }"), want: []string{"`with.paginate.max_pages: 1000` is outside 1 to 500", "at most 500 pages"}},
		{name: "page_start negative", flow: step("{ strategy: page, page_start: -5 }"), want: []string{"`with.paginate.page_start: -5` is not a page number", "starts at page 1"}},
		{name: "cursor without cursor_field", flow: step("{ strategy: cursor, items_field: $.data }"), want: []string{"has no `cursor_field`", "`cursor_field: $.next_cursor`", "fails when it runs", "`strategy: page`"}},
		{name: "default strategy without cursor_field", flow: step("{ items_field: $.data }"), want: []string{"cursor strategy (the default)", "has no `cursor_field`"}},
		{name: "empty map", flow: step("{}"), want: []string{"has no `cursor_field`"}},
		{name: "cursor key on the page strategy", flow: step("{ strategy: page, cursor_field: $.next }"), want: []string{"`with.paginate.cursor_field` is read only with `strategy: cursor`", "with `strategy: page` it would be ignored"}},
		{name: "page key on the cursor strategy", flow: step("{ cursor_field: $.next, page_start: 2 }"), want: []string{"`with.paginate.page_start` is read only with `strategy: page`"}},
		{name: "items_field not text", flow: step("{ strategy: page, items_field: 5 }"), want: []string{"`with.paginate.items_field` must be text", "the default `$.items`"}},
		{name: "items_field indexed", flow: step("{ strategy: page, items_field: \"$.data[0].rows\" }"), want: []string{"`with.paginate.items_field` `$.data[0].rows` is a dotted path", "Indexing"}},
		{name: "items_field templated", flow: step("{ strategy: page, items_field: \"${{ params.field }}\" }"), want: []string{"`with.paginate.items_field` is literal text"}},

		{name: "page strategy", flow: step("{ strategy: page, page_param: \"page[number]\", page_start: 1, items_field: \"$.data\", max_pages: 50 }")},
		{name: "page_start 0 for a zero-based upstream", flow: step("{ strategy: page, page_param: p, page_start: 0 }")},
		{name: "cursor strategy", flow: step("{ strategy: cursor, cursor_field: \"$.nextPageToken\", cursor_param: pageToken, items_field: \"$.connections\", max_pages: 25 }")},
		{name: "default strategy with cursor_field", flow: step("{ cursor_field: $.next }")},
		{name: "strategy in capitals", flow: step("{ strategy: Page }")},
		{name: "the answer itself is the list", flow: step("{ strategy: page, items_field: \"$\" }")},
		{name: "max_pages at the cap", flow: step("{ strategy: page, max_pages: 500 }")},
	})
}

// flowPaginateKeys against the loader: withToPaginate reads every key the
// table lists, nothing sets a FlowAPIPaginate field the table does not name,
// and a number key is read only as a YAML integer.
func TestFlowPaginateKeysMatchLoader(t *testing.T) {
	probes := map[string]any{
		"strategy": "page", "items_field": "$.probe", "max_pages": 7,
		"cursor_field": "$.next", "cursor_param": "after", "page_param": "p", "page_start": 3,
	}
	empty := *withToPaginate(map[string]any{})
	set := map[string]bool{}
	for _, key := range flowPaginateKeys {
		probe, ok := probes[key.name]
		if !ok {
			t.Fatalf("flowPaginateKeys has a new key %q: add a probe value for it", key.name)
		}
		loaded := *withToPaginate(map[string]any{key.name: probe})
		if reflect.DeepEqual(loaded, empty) {
			t.Errorf("flowPaginateKeys lists %q but withToPaginate does not read it", key.name)
		}
		before, after := reflect.ValueOf(empty), reflect.ValueOf(loaded)
		for i := 0; i < after.NumField(); i++ {
			if !reflect.DeepEqual(before.Field(i).Interface(), after.Field(i).Interface()) {
				set[after.Type().Field(i).Name] = true
			}
		}
		if _, isNumber := probe.(int); isNumber != key.number {
			t.Errorf("%q: number = %v, but its probe is %T", key.name, key.number, probe)
		}
		// The other YAML type is not read: quoted for a number, a number for text.
		var wrong any = 5
		if key.number {
			wrong = "5"
		}
		if got := *withToPaginate(map[string]any{key.name: wrong}); !reflect.DeepEqual(got, empty) {
			t.Errorf("withToPaginate reads %s: %#v; the gate says it is not read", key.name, wrong)
		}
	}
	for i := 0; i < reflect.TypeOf(empty).NumField(); i++ {
		if name := reflect.TypeOf(empty).Field(i).Name; !set[name] {
			t.Errorf("FlowAPIPaginate.%s is set by no key of flowPaginateKeys: add the key withToPaginate reads it from", name)
		}
	}
	if got := *withToPaginate(map[string]any{"limit": 5, "next_field": "$.next"}); !reflect.DeepEqual(got, empty) {
		t.Errorf("withToPaginate reads a key outside flowPaginateKeys: %+v", got)
	}
}

func TestParallelSQLInATransactionalFlowIsRefused(t *testing.T) {
	flow := func(trigger, parallel string) string {
		return "on:\n" + trigger + "jobs:\n  j:\n    steps:\n" + parallel
	}
	request := func(tx string) string {
		return "  request:\n    method: POST\n    path: /api/probe\n" + tx
	}
	const sqlInParallel = "      - run: parallel\n        steps:\n          - id: a\n            run: sql\n            with: { query: \"INSERT INTO probes (k) VALUES ('a')\" }\n          - id: b\n            run: sql\n            with: { query: \"INSERT INTO probes (k) VALUES ('b')\" }\n"
	const nestedSQL = "      - run: parallel\n        steps:\n          - if: ${{ params.go }}\n            steps:\n              - query: \"SELECT 1 AS n\"\n          - id: b\n            run: api\n            with: { url: https://example.com/ }\n"
	const apiInParallel = "      - run: parallel\n        steps:\n          - id: a\n            run: api\n            with: { url: https://example.com/a }\n          - id: b\n            run: api\n            with: { url: https://example.com/b }\n      - run: sql\n        with: { query: \"INSERT INTO probes (k) VALUES ('after')\" }\n"
	runIgnoredValueCases(t, []ignoredValueCase{
		{name: "request flow", flow: flow(request("    transaction: true\n"), sqlInParallel), want: []string{`job "j" has SQL steps inside a ` + "`run: parallel` block", "`transaction: true`", "one transaction cannot be shared", "its route would answer 404", "Move the SQL steps out of the parallel block"}},
		{name: "nested under an if", flow: flow(request("    transaction: true\n"), nestedSQL), want: []string{"SQL steps inside a `run: parallel` block"}},
		{name: "scheduled flow", flow: flow("  schedule:\n    cron: \"every 15m\"\n    transaction: true\n", sqlInParallel), want: []string{"SQL steps inside a `run: parallel` block", "it would never run"}},

		{name: "no transaction", flow: flow(request(""), sqlInParallel)},
		{name: "SQL after the block", flow: flow(request("    transaction: true\n"), apiInParallel)},
	})
	// What the loader does with such a file is unchanged: it loads, and
	// registration refuses the flow with its own reason.
	flows, err := parseGHAFlowFile("flows/probe.yaml", []byte(flow(request("    transaction: true\n"), sqlInParallel)))
	if err != nil || len(flows) != 1 {
		t.Fatalf("a deployed file with SQL in a transactional parallel block no longer loads: %v", err)
	}
	if err := flowValidateParallelTx(&flows[0]); err == nil || !strings.Contains(err.Error(), "parallel block contains SQL steps") {
		t.Fatalf("registration accepts the flow: %v", err)
	}
}

func TestForEachLoopNamesTheRuntimeOwnsAreRefused(t *testing.T) {
	loop := func(as string) string {
		return ignoredValueFlow("      - for_each: ${{ params.items }}\n" + as + "        steps:\n          - run: set\n            with: { seen: \"1\" }\n")
	}
	const fails = "the loop is not run: it fails the flow"
	cases := []ignoredValueCase{
		{name: "user", flow: loop("        as: user\n"), want: []string{`step steps[0]`, "`as: user` names the signed-in caller's identity", "`${{ user.* }}`", fails, "`as: row`"}},
		{name: "user_id", flow: loop("        as: user_id\n"), want: []string{"`as: user_id` names the signed-in caller's identity", fails}},
		{name: "user_email", flow: loop("        as: user_email\n"), want: []string{"`as: user_email` names the signed-in caller's identity"}},
		{name: "user_role", flow: loop("        as: user_role\n"), want: []string{"`as: user_role` names the signed-in caller's identity"}},
		{name: "user_group_id", flow: loop("        as: user_group_id\n"), want: []string{"`as: user_group_id` names the signed-in caller's identity"}},
		{name: "_group_id", flow: loop("        as: _group_id\n"), want: []string{"`as: _group_id` names the signed-in caller's identity"}},
		{name: "_group_key", flow: loop("        as: _group_key\n"), want: []string{"`as: _group_key` names the signed-in caller's identity"}},
		{name: "a user field", flow: loop("        as: user.email\n"), want: []string{"`as: user.email` names the signed-in caller's identity"}},
		{name: "env", flow: loop("        as: env\n"), want: []string{"`as: env` names the app's environment", fails}},
		{name: "runtime private", flow: loop("        as: __benmore_step_named_params\n"), want: []string{"starts with `__benmore_`", fails}},
		{name: "params", flow: loop("        as: params\n"), want: []string{"`as: params` collides with `${{ params.<name> }}`"}},
		{name: "steps", flow: loop("        as: steps\n"), want: []string{"`as: steps` collides with `${{ steps.<id>.outputs.<name> }}`"}},
		{name: "error", flow: loop("        as: error\n"), want: []string{"`as: error` is the name of the failed step's error"}},
		{name: "a request field path", flow: loop("        as: params.row\n"), want: []string{"`as: params.row` collides with `${{ params.<name> }}`"}},
		{name: "a step path", flow: loop("        as: steps.row\n"), want: []string{"`as: steps.row` collides with `${{ steps.<id>.outputs.<name> }}`"}},
		{name: "a name with a space", flow: loop("        as: my item\n"), want: []string{"`as: my item` is not a name every reference can read", "an `if:` condition on it would be false", "letters, digits, `_`, `-` and `.`"}},
		{name: "a name with a colon", flow: loop("        as: \"x:y\"\n"), want: []string{"`as: x:y` is not a name every reference can read"}},
		{name: "a template", flow: loop("        as: \"${{ params.name }}\"\n"), want: []string{"is not a name every reference can read"}},

		{name: "no as", flow: loop("")},
		{name: "item", flow: loop("        as: item\n")},
		{name: "row", flow: loop("        as: row\n")},
		{name: "an underscore name", flow: loop("        as: deep_project\n")},
		{name: "users is not user", flow: loop("        as: users\n")},
		{name: "member", flow: loop("        as: member2\n")},
		{name: "a hyphen name", flow: loop("        as: line-item\n")},
		{name: "a dotted name", flow: loop("        as: order.line\n")},
	}
	runIgnoredValueCases(t, cases)
	// Every identity name the runtime strips from a request is refused as a
	// loop variable: a new one added to flowIdentityKeys is covered.
	for _, name := range flowIdentityKeys {
		if flowLoopNameProblem(name) == "" || !flowLoopNameReplacesIdentity(name) {
			t.Errorf("identity name %q is accepted as a loop variable", name)
		}
	}
}

func TestEmailAttachmentShapesTheRuntimeCannotSendAreRefused(t *testing.T) {
	step := func(attachments string) string {
		return ignoredValueFlow("      - run: email\n        with:\n          to: \"a@example.com\"\n          subject: \"S\"\n          text: \"T\"\n          attachments: " + attachments + "\n")
	}
	const unsent = "The step fails when it runs and nothing is sent."
	runIgnoredValueCases(t, []ignoredValueCase{
		{name: "a map", flow: step("{ filename: a.txt, content: \"aGk=\" }"), want: []string{"`with.attachments` must be a list of `{ filename, content, content_type }` entries", "not a map", unsent}},
		{name: "a template", flow: step("\"${{ params.files }}\""), want: []string{"`with.attachments` must be a list", unsent}},
		{name: "a text entry", flow: step("[\"aGk=\"]"), want: []string{"`with.attachments[0]` must be a map", `the text "aGk="`, unsent}},
		{name: "no content", flow: step("[{ filename: report.csv }]"), want: []string{"`with.attachments[0]` has no `content`", "base64", unsent}},
		{name: "path instead of content", flow: step("[{ filename: report.csv, path: uploads/private/x.csv }]"), want: []string{"`with.attachments[0]` has no `content`", "there is no `path:` key", unsent}},
		{name: "the second entry", flow: step("[{ filename: a.txt, content: \"aGk=\" }, { filename: b.txt, content: \"\" }]"), want: []string{"`with.attachments[1]` has no `content`"}},
		{name: "an unknown key", flow: step("[{ filename: a.txt, content: \"aGk=\", name: a.txt }]"), want: []string{"`with.attachments[0].name` is not read", "content, content_type, filename"}},
		{name: "no filename", flow: step("[{ content: \"aGk=\" }]"), want: []string{"`with.attachments[0]` has no `filename`"}},
		{name: "literal content that is not base64", flow: step("[{ filename: a.txt, content: \"hello world!\" }]"), want: []string{"`with.attachments[0].content` is not base64", "| base64", unsent}},
		{name: "templated content_type", flow: step("[{ filename: a.txt, content: \"aGk=\", content_type: \"${{ params.type }}\" }]"), want: []string{"`with.attachments[0].content_type` is literal text"}},

		{name: "literal base64", flow: step("[{ filename: a.txt, content: \"aGk=\" }]")},
		{name: "content from a value", flow: step("[{ filename: \"hours-${{ params.month }}.csv\", content: \"${{ params.csv | base64 }}\", content_type: text/csv }]")},
		{name: "two entries", flow: step("[{ filename: a.txt, content: \"aGk=\" }, { filename: b.txt, content: \"${{ params.b }}\" }]")},
		{name: "an empty list", flow: step("[]")},
	})
}

// eventTableApp is an app directory with a schema, for the gate's
// cross-file check of on.event.table.
func eventTableApp(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

const eventTableSchema = `model Task {
  id     Int    @id @default(autoincrement())
  title  String
  userId Int    @map("user_id")
  @@map("tasks")
}

model TimeEntry {
  id     Int   @id @default(autoincrement())
  hours  Float
  @@map("time_entries")
}
`

func eventTableFlow(table string) string {
	return "on:\n  event:\n    table: " + table + "\n    op: insert\njobs:\n  log:\n    steps:\n      - run: sql\n        with: { query: \"INSERT INTO time_entries (hours) VALUES (1)\" }\n"
}

func TestEventTableIsCheckedAgainstTheAppsTables(t *testing.T) {
	dir := eventTableApp(t, map[string]string{
		"schema.prisma":                     eventTableSchema,
		"migrations/0001_legacy_orders.sql": "CREATE TABLE IF NOT EXISTS legacy_orders (id INTEGER PRIMARY KEY, total REAL);\n",
	})
	for _, c := range []struct {
		name, table string
		want        []string
	}{
		{"the model name", "Task", []string{`on.event.table "Task" is the schema's model name; its table is "tasks"`, "matched exactly", "`table: tasks`", "the flow never runs"}},
		{"a typo", "taskz", []string{`on.event.table "taskz" is not a table of this app`, "Did you mean `table: tasks`?", "Tables: tasks, time_entries"}},
		{"another letter case", "Tasks", []string{`on.event.table "Tasks" differs from the table "tasks" only in letter case`, "`table: tasks`"}},
		{"nothing like a table", "invoices_archive", []string{`on.event.table "invoices_archive" is not a table of this app`, "Tables: tasks, time_entries"}},
		{"the users table", "_benmore_users", []string{`on.event.table "_benmore_users" is a framework table`, "no event flow ever starts on it", "hooks.yaml"}},
		{"a table of the schema", "tasks", nil},
		{"a second table", "time_entries", nil},
		{"a table a migration creates", "legacy_orders", nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			msg := ValidateOnWriteIn(dir, "flows/on-task.yaml", eventTableFlow(c.table))
			if len(c.want) == 0 {
				if msg != "" {
					t.Fatalf("the gate refuses an event on a table the app has:\n%s", msg)
				}
				return
			}
			if msg == "" {
				t.Fatalf("the gate accepts on.event.table %q", c.table)
			}
			for _, part := range c.want {
				if !strings.Contains(msg, part) {
					t.Errorf("the refusal does not say %q:\n%s", part, msg)
				}
			}
		})
	}

	t.Run("benmore check reports it on the flow file", func(t *testing.T) {
		app := eventTableApp(t, map[string]string{"schema.prisma": eventTableSchema, "flows/on-task.yaml": eventTableFlow("Task")})
		report := RunSourceCheck(app, "")
		var found bool
		for _, f := range report.Findings {
			if f.Severity == "error" && f.File == "flows/on-task.yaml" && strings.Contains(f.Message, `its table is "tasks"`) {
				found = true
			}
		}
		if !found {
			t.Fatalf("no error on flows/on-task.yaml: %+v", report.Findings)
		}
	})

	t.Run("a migration table spelled another way is a warning", func(t *testing.T) {
		app := eventTableApp(t, map[string]string{
			"schema.prisma":                     eventTableSchema,
			"migrations/0001_legacy_orders.sql": "CREATE TABLE Legacy_Orders (id INTEGER PRIMARY KEY);\n",
			"flows/on-order.yaml":               eventTableFlow("legacy_orders"),
		})
		if msg := ValidateOnWriteIn(app, "flows/on-order.yaml", eventTableFlow("legacy_orders")); msg != "" {
			t.Fatalf("the gate refuses a table a migration creates:\n%s", msg)
		}
		report := RunSourceCheck(app, "flows/on-order.yaml")
		var warned bool
		for _, f := range report.Findings {
			if f.Severity == "warning" && f.File == "flows/on-order.yaml" && strings.Contains(f.Message, "a migration creates it") && strings.Contains(f.Message, "exactly this name") {
				warned = true
			}
			if f.Severity == "error" {
				t.Errorf("an error for a table that can exist: %s", f.Message)
			}
		}
		if !warned {
			t.Fatalf("no warning about the table's spelling: %+v", report.Findings)
		}
	})

	t.Run("no schema, nothing to judge against", func(t *testing.T) {
		app := eventTableApp(t, map[string]string{"app.yaml": "site_name: x\n"})
		if msg := ValidateOnWriteIn(app, "flows/on-task.yaml", eventTableFlow("anything")); msg != "" {
			t.Fatalf("refused without a schema to check against:\n%s", msg)
		}
	})

	t.Run("a schema file later in the same batch decides", func(t *testing.T) {
		msg, _ := ValidateOnWriteInPending(dir, "flows/on-order.yaml", eventTableFlow("orders"), []string{"schema.prisma"})
		if msg != "" {
			t.Fatalf("refused although the batch still writes the schema:\n%s", msg)
		}
		if msg, _ := ValidateOnWriteInPending(dir, "flows/on-order.yaml", eventTableFlow("orders"), []string{"static/app.tsx"}); msg == "" {
			t.Fatal("accepted an unknown table when the batch writes no schema")
		}
	})

	t.Run("schema.sql", func(t *testing.T) {
		app := eventTableApp(t, map[string]string{"schema.sql": "CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, body TEXT);\n"})
		if msg := ValidateOnWriteIn(app, "flows/on-note.yaml", eventTableFlow("notes")); msg != "" {
			t.Fatalf("refused a schema.sql table:\n%s", msg)
		}
		if msg := ValidateOnWriteIn(app, "flows/on-note.yaml", eventTableFlow("note")); !strings.Contains(msg, "Did you mean `table: notes`?") {
			t.Fatalf("a typo of a schema.sql table: %q", msg)
		}
	})
}

// `min` and `max` on an input that is not a number are not checked. Deployed
// apps declare them, so the gate accepts the file and warns.
func TestInputBoundsOnANonNumberWarn(t *testing.T) {
	flow := func(inputs string) string {
		return "on:\n  request:\n    method: POST\n    path: /api/probe\n    inputs:\n" + inputs + "jobs:\n  j:\n    steps:\n      - run: respond\n        with: { status: 200, json: { ok: true } }\n"
	}
	bounded := flow("      title: { type: text, min: 3, max: 10 }\n      reason: { type: textarea, max: 500 }\n      hours: { type: number, min: 0.25, max: 24 }\n")
	if msg := validateFlowsYAML(bounded); msg != "" {
		t.Fatalf("the gate refuses a file deployed apps carry:\n%s", msg)
	}
	problems := flowInputBoundsProblems(mustParseFlowFile(t, bounded).On.Request.Inputs)
	if len(problems) != 2 {
		t.Fatalf("problems = %q, want one for reason and one for title", problems)
	}
	for i, want := range [][]string{
		{"on.request.inputs.reason sets `max`", `its type is "textarea"`, "bound a `type: number` input only", "do not limit a text's length"},
		{"on.request.inputs.title sets `min` and `max`", `its type is "text"`},
	} {
		for _, part := range want {
			if !strings.Contains(problems[i], part) {
				t.Errorf("problem %d does not say %q: %s", i, part, problems[i])
			}
		}
	}
	if got := flowInputBoundsProblems(mustParseFlowFile(t, flow("      hours: { type: number, min: 0.25, max: 24 }\n      kind: { type: enum, values: [a, b] }\n")).On.Request.Inputs); len(got) != 0 {
		t.Errorf("a bounded number is reported: %q", got)
	}

	app := eventTableApp(t, map[string]string{"schema.prisma": eventTableSchema, "flows/bounded.yaml": bounded})
	for _, written := range []string{"flows/bounded.yaml", ""} {
		report := RunSourceCheck(app, written)
		warnings := 0
		for _, f := range report.Findings {
			if f.Severity == "error" {
				t.Errorf("check (written %q) has an error: %s", written, f.Message)
			}
			if f.Severity == "warning" && f.File == "flows/bounded.yaml" && strings.Contains(f.Message, "bound a `type: number` input only") {
				warnings++
			}
		}
		if warnings != 2 {
			t.Errorf("check (written %q) has %d bounds warnings, want 2: %+v", written, warnings, report.Findings)
		}
	}
}

func mustParseFlowFile(t *testing.T, content string) FlowFileGHA {
	t.Helper()
	var file FlowFileGHA
	if err := yamlUnmarshal([]byte(content), &file); err != nil {
		t.Fatal(err)
	}
	return file
}

// flowEmailAttachmentKeys against the loader: withToEmail reads each key of
// an attachment the table lists, and no other.
func TestFlowEmailAttachmentKeysMatchLoader(t *testing.T) {
	entry := map[string]any{"content": "cHJvYmU="}
	base := withToEmail(map[string]any{"attachments": []any{entry}})
	if len(base.Attachments) != 1 || base.AttachmentsError != "" {
		t.Fatalf("an entry with content alone is not loaded: %+v", base)
	}
	probes := map[string]string{"content": "b3RoZXI=", "content_type": "text/csv", "filename": "probe.csv"}
	for _, key := range flowEmailAttachmentKeys {
		probe, ok := probes[key]
		if !ok {
			t.Fatalf("flowEmailAttachmentKeys has a new key %q: add a probe value for it", key)
		}
		probed := map[string]any{"content": "cHJvYmU=", key: probe}
		if got := withToEmail(map[string]any{"attachments": []any{probed}}); reflect.DeepEqual(got.Attachments, base.Attachments) {
			t.Errorf("flowEmailAttachmentKeys lists %q but withToEmail does not read it", key)
		}
	}
	for _, key := range []string{"path", "name", "data", "type", "url"} {
		probed := map[string]any{"content": "cHJvYmU=", key: "probe"}
		if got := withToEmail(map[string]any{"attachments": []any{probed}}); !reflect.DeepEqual(got.Attachments, base.Attachments) {
			t.Errorf("withToEmail reads the attachment key %q, which flowEmailAttachmentKeys does not list", key)
		}
	}
	if fields := reflect.TypeOf(FlowAttachment{}).NumField(); fields != len(flowEmailAttachmentKeys) {
		t.Errorf("FlowAttachment has %d fields and flowEmailAttachmentKeys %d keys: list the key each field is read from", fields, len(flowEmailAttachmentKeys))
	}
	// A value that names no file is carried to the step as the reason it fails.
	for _, raw := range []any{map[string]any{"filename": "a.txt", "content": "aGk="}, []any{"aGk="}, []any{map[string]any{"filename": "a.txt", "path": "uploads/x"}}, "text", true} {
		if got := withToEmail(map[string]any{"attachments": raw}); got.AttachmentsError == "" || len(got.Attachments) != 0 {
			t.Errorf("attachments %#v loads as %d attachment(s) with no error", raw, len(got.Attachments))
		}
	}
}

// An optional request field with no fallback on the right-hand side of an
// `if:` has no value when the request leaves it out, and in a redirect target
// it is sent as the reference's own text. The file is accepted; the write and
// `benmore check` warn, naming the fallback to write.
func TestOptionalRequestFieldWithNoFallbackWarns(t *testing.T) {
	flow := func(trigger, steps string) string {
		return "on:\n  request:\n    method: POST\n    path: /api/orders/:id/close\n" + trigger + "jobs:\n  j:\n    steps:\n" + steps
	}
	gate := func(cond string) string {
		return "      - id: row\n        run: sql\n        with: { query: \"SELECT token FROM orders WHERE id = :id\" }\n      - if: " + cond + "\n        run: respond\n        with: { status: 403, json: { error: forbidden } }\n      - run: respond\n        with: { status: 200, json: { ok: true } }\n"
	}
	redirect := func(to string) string {
		return "      - run: redirect\n        with: { to: \"" + to + "\" }\n"
	}
	const inputs = "    inputs:\n      token: { type: text, required: true }\n      tab: { type: text, default: all }\n      note: { type: text }\n"
	for _, c := range []struct {
		name, content string
		want          []string
	}{
		{"if, != a request field", flow("", gate("${{ steps.row.outputs.token }} != ${{ params.token }}")),
			[]string{`job "j" step steps[1]: ` + "`if: ${{ steps.row.outputs.token }} != ${{ params.token }}` has the request field `token` on its right-hand side with no fallback", "that side has no value and equals nothing", "`!=` holds and `==` does not", "`${{ params.token || '' }}`", "`required: true`"}},
		{"if, one span", flow("", gate("${{ steps.row.outputs.token == params.token }}")), []string{"has the request field `token` on its right-hand side"}},
		{"if, an optional declared input", flow(inputs, gate("${{ steps.row.outputs.token }} == ${{ params.note }}")), []string{"has the request field `note` on its right-hand side"}},
		{"redirect, an optional query value", flow("", redirect("/done?tab=${{ params.tab }}")),
			[]string{`job "j" step steps[0]: ` + "`to: /done?tab=${{ params.tab }}` reads the request field `tab` with no fallback", "the redirect is still sent, with the text `{{params.tab}}` in its target", "`${{ params.tab || '' }}`"}},
		{"redirect, two fields", flow("", redirect("/done?tab=${{ params.tab }}&q=${{ params.q }}&again=${{ params.tab }}")), []string{"reads the request field `tab`", "reads the request field `q`"}},

		{"if, a fallback with ||", flow("", gate("${{ steps.row.outputs.token }} != ${{ params.token || '' }}")), nil},
		{"if, a default pipe", flow("", gate("${{ steps.row.outputs.token }} != ${{ params.token | default:'' }}")), nil},
		{"if, a required input", flow(inputs, gate("${{ steps.row.outputs.token }} != ${{ params.token }}")), nil},
		{"if, an input with a default", flow(inputs, gate("${{ steps.row.outputs.token }} != ${{ params.tab }}")), nil},
		{"if, a path parameter", flow("", gate("${{ steps.row.outputs.token }} != ${{ params.id }}")), nil},
		{"if, the request field on the left", flow("", gate("${{ params.token }} != ${{ steps.row.outputs.token }}")), nil},
		{"if, a literal on the right", flow("", gate("${{ params.token }} != 'secret'")), nil},
		{"if, joined comparisons read a missing value as empty", flow("", gate("${{ steps.row.outputs.token }} != ${{ params.token }} && ${{ params.token }} != ''")), nil},
		{"if, the caller's identity", flow("    auth: required\n", gate("${{ steps.row.outputs.token }} != ${{ user.id }}")), nil},
		{"redirect, a fallback", flow("", redirect("/done?tab=${{ params.tab || 'all' }}")), nil},
		{"redirect, a default pipe", flow("", redirect("/done?tab=${{ params.tab | default:'all' }}")), nil},
		{"redirect, a path parameter", flow("", redirect("/orders/${{ params.id }}")), nil},
		{"redirect, an input with a default", flow(inputs, redirect("/done?tab=${{ params.tab }}")), nil},
		{"redirect, a literal target", flow("", redirect("/done")), nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			if msg := validateFlowsYAML(c.content); msg != "" {
				t.Fatalf("the gate refuses the file; this is a warning only:\n%s", msg)
			}
			got := ghaMissingRequestValueWarnings(c.content)
			if len(c.want) == 0 {
				if len(got) != 0 {
					t.Fatalf("warned although the value is always there or has a fallback: %q", got)
				}
				return
			}
			all := strings.Join(got, "\n")
			for _, part := range c.want {
				if !strings.Contains(all, part) {
					t.Errorf("the warning does not say %q:\n%s", part, all)
				}
			}
		})
	}
	// A step output on a redirect (`/orders/${{ steps.new.outputs.id }}`) and
	// an env value are not request fields: no warning.
	const created = "      - id: created\n        run: sql\n        with: { query: \"INSERT INTO orders (token) VALUES ('t') RETURNING id\" }\n      - run: redirect\n        with: { to: \"/orders/${{ steps.created.outputs.id }}?from=${{ env.SOURCE }}\" }\n"
	if got := ghaMissingRequestValueWarnings(flow("", created)); len(got) != 0 {
		t.Errorf("a step output or env value in a redirect is warned about: %q", got)
	}
	// Scheduled and event flows have no request.
	if got := ghaMissingRequestValueWarnings("on:\n  schedule:\n    cron: \"every 15m\"\njobs:\n  j:\n    steps:\n" + gate("${{ steps.row.outputs.token }} != ${{ params.token }}")); len(got) != 0 {
		t.Errorf("a scheduled flow is warned about: %q", got)
	}

	app := eventTableApp(t, map[string]string{
		"schema.prisma":      "model Order {\n  id    Int    @id @default(autoincrement())\n  token String\n  @@map(\"orders\")\n}\n",
		"flows/close.yaml":   flow("", gate("${{ steps.row.outputs.token }} != ${{ params.token }}")),
		"flows/tab.yaml":     strings.Replace(flow("", redirect("/done?tab=${{ params.tab }}")), "/api/orders/:id/close", "/api/orders/:id/tab", 1),
		"flows/guarded.yaml": strings.Replace(flow("", gate("${{ steps.row.outputs.token }} != ${{ params.token || '' }}")), "/api/orders/:id/close", "/api/orders/:id/guarded", 1),
	})
	for written, want := range map[string]map[string]bool{
		"flows/close.yaml":   {"flows/close.yaml": true},
		"flows/tab.yaml":     {"flows/tab.yaml": true},
		"flows/guarded.yaml": {},
		"":                   {"flows/close.yaml": true, "flows/tab.yaml": true},
	} {
		report := RunSourceCheck(app, written)
		got := map[string]bool{}
		for _, f := range report.Findings {
			if f.Severity == "error" {
				t.Errorf("check (written %q) has an error: %s", written, f.Message)
			}
			if f.Severity == "warning" && strings.Contains(f.Message, "with no fallback") {
				got[f.File] = true
			}
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("check (written %q) warns on %v, want %v", written, got, want)
		}
	}
}
