//go:build !cli

package main

import (
	"strings"
	"testing"
)

// A `run: respond` whose `with:` answers something other than it reads as:
// two bodies (the step sends one), or a body YAML reads as a number or a
// boolean rather than as text. Each is accepted (deployed files carry
// them), answers what its warning says, and is warned about when the file is
// written, in `benmore check` and in the log when the file loads.
func TestRespondBodyShapesAreWarnedAbout(t *testing.T) {
	const head = "on:\n  request: { method: POST, path: /api/shape, auth: required }\njobs:\n  answer:\n    steps:\n      - id: out\n        run: respond\n        with: "
	const where = `flows/shape.yaml: job "answer" step steps[0] ("out"): this ` + "`run: respond` "

	app, _ := auditApp(t)
	sid := createCrudScopeSession(t, app, "caller@example.com", "user", "", "")
	dir := t.TempDir()
	writeTestFile(t, dir, "app.yaml", "site_name: shape\n")

	for name, c := range map[string]struct {
		with string
		// What the step answers.
		status int
		body   string
		ctype  string
		// The warnings it gets, each a part of one message; none when empty.
		warnings []string
	}{
		"text body beside json": {
			with: `{ status: 200, body: "hello", json: { a: 1 } }`, status: 200, body: "hello", ctype: "text/plain; charset=utf-8",
			warnings: []string{"sets both `with.body` and `with.json`, and sends one body: only the `body` one is sent. Keep one."},
		},
		"map body beside json": {
			with: `{ status: 200, body: { from: body }, json: { from: json } }`, status: 200, body: `{"from":"body"}`, ctype: "application/json",
			warnings: []string{"sets both `with.body` and `with.json`, and sends one body: only the `body` one is sent. Keep one."},
		},
		"number body beside json": {
			with: `{ status: 200, body: 7, json: { a: 1 } }`, status: 200, body: `{"a":1}`, ctype: "application/json",
			warnings: []string{"sets both `with.body` and `with.json`, and sends one body: only the `json` one is sent. Keep one."},
		},
		"number body": {
			with: `{ status: 200, body: 1.50 }`, status: 200, body: "1.5", ctype: "application/json",
			warnings: []string{"has a `with.body` that YAML reads as a number, not as text: the step answers the JSON value `1.5` (Content-Type application/json), which need not be the text as typed. For text, put the value in quotes; for the JSON value, write it under `json:`."},
		},
		"boolean body": {
			with: `{ status: 200, body: true }`, status: 200, body: "true", ctype: "application/json",
			warnings: []string{"has a `with.body` that YAML reads as a boolean, not as text: the step answers the JSON value `true` (Content-Type application/json)"},
		},
		"number body under a declared type": {
			with: `{ status: 200, body: 0x10, content_type: "text/plain" }`, status: 200, body: "16", ctype: "text/plain",
			warnings: []string{"has a `with.body` that YAML reads as a number, not as text: the step answers the JSON value `16` (Content-Type text/plain)"},
		},
		"not-a-number body": {
			with: `{ status: 200, body: .nan }`, status: 200,
			warnings: []string{"has a `with.body` that YAML reads as a number with no JSON form, and it is not sent: the step answers status 200 with an empty body. Put the value in quotes to send it as text."},
		},

		// Shapes that answer what they read as.
		"blank body beside json":  {with: `{ status: 403, body: "", json: { error: forbidden } }`, status: 403, body: `{"error":"forbidden"}`, ctype: "application/json"},
		"date body":               {with: `{ status: 200, body: 2026-01-31 }`, status: 200, body: "2026-01-31", ctype: "text/plain; charset=utf-8"},
		"timestamp json":          {with: `{ status: 201, json: 2026-01-31T10:00:00Z }`, status: 201, body: "2026-01-31T10:00:00Z", ctype: "text/plain; charset=utf-8"},
		"status alone":            {with: `{ status: 204 }`, status: 204},
		"refusal with no body":    {with: `{ status: 403 }`, status: 403},
		"empty body alone":        {with: `{ status: 201, body: "" }`, status: 201},
		"quoted date":             {with: `{ status: 200, body: "2026-01-31" }`, status: 200, body: "2026-01-31", ctype: "text/plain; charset=utf-8"},
		"quoted number":           {with: `{ status: 200, body: "1.50" }`, status: 200, body: "1.50", ctype: "text/plain; charset=utf-8"},
		"number written as json":  {with: `{ status: 200, json: 0 }`, status: 200, body: "0", ctype: "application/json"},
		"boolean written as json": {with: `{ status: 200, json: false }`, status: 200, body: "false", ctype: "application/json"},
		"json alone":              {with: `{ status: 200, json: { ok: true, n: 1.50 } }`, status: 200, body: `{"n":1.5,"ok":true}`, ctype: "application/json"},
		"body with an empty json": {with: "\n          status: 200\n          body: hello\n          json:\n", status: 200, body: "hello", ctype: "text/plain; charset=utf-8"},
		"json with an empty body": {with: "\n          status: 200\n          body:\n          json: { ok: true }\n", status: 200, body: `{"ok":true}`, ctype: "application/json"},
	} {
		src := head + c.with + "\n"

		// The file loads, and the step answers what the warning says.
		var flows []Flow
		logged := captureLog(t, func() { flows = notifyFlows(t, "flows/shape.yaml", src) })
		rr := respondShapeRun(t, app, &flows[0], sid, nil)
		if got := strings.TrimSpace(rr.Body.String()); rr.Code != c.status || got != c.body {
			t.Errorf("%s: answered %d %q, want %d %q", name, rr.Code, got, c.status, c.body)
		}
		if got := rr.Header().Get("Content-Type"); got != c.ctype {
			t.Errorf("%s: Content-Type %q, want %q", name, got, c.ctype)
		}
		for _, want := range c.warnings {
			if !strings.Contains(logged, "WARNING: "+where+want) {
				t.Errorf("%s: loading the file did not log %q:\n%s", name, where+want, logged)
			}
		}
		if len(c.warnings) == 0 && strings.Contains(logged, "this `run: respond`") {
			t.Errorf("%s: loading the file logged a respond warning:\n%s", name, logged)
		}

		// The write gate accepts it; the post-write check and `benmore
		// check` carry the warning, on the flow file, with its docs address.
		if msg := ValidateOnWriteIn(dir, "flows/shape.yaml", src); msg != "" {
			t.Fatalf("%s: the write gate refuses a flow shape deployed apps carry: %s", name, msg)
		}
		writeTestFile(t, dir, "flows/shape.yaml", src)
		for from, report := range map[string]CheckReport{
			"the post-write check of the flow file": RunSourceCheck(dir, "flows/shape.yaml"),
			"benmore check":                         RunSourceCheck(dir, ""),
		} {
			var got []string
			for _, f := range report.Findings {
				if !strings.Contains(f.Message, "this `run: respond`") {
					continue
				}
				got = append(got, f.Message)
				if f.Severity != "warning" || f.Source != "flows" || f.File != "flows/shape.yaml" {
					t.Errorf("%s, %s: finding is not a flows warning on the file: %+v", name, from, f)
				}
				if at := checkFindingDocs(f); at != "flows.respond_bodies" {
					t.Errorf("%s, %s: the warning is documented at %q, want flows.respond_bodies", name, from, at)
				}
			}
			if len(got) != len(c.warnings) {
				t.Errorf("%s, %s: %d warning(s), want %d: %q", name, from, len(got), len(c.warnings), got)
				continue
			}
			for i, want := range c.warnings {
				if !strings.Contains(got[i], where+want) {
					t.Errorf("%s, %s: warning %q, want it to hold %q", name, from, got[i], where+want)
				}
			}
			if report.Errors != 0 {
				t.Errorf("%s, %s reports %d error(s): %+v", name, from, report.Errors, report.Findings)
			}
		}
		if report := RunSourceCheck(dir, "app.yaml"); strings.Contains(strings.Join(checkMessages(report), "\n"), "this `run: respond`") {
			t.Errorf("%s: a write of another file repeats the warning", name)
		}
	}
}

// A respond with no `with:` followed by a respond under the same `if:` is the
// duplicated-condition shape: the second step is the answer the author meant
// and it never runs. The warning says so.
func TestBareRespondInFrontOfItsOwnAnswerIsNamed(t *testing.T) {
	const head = "on:\n  request: { method: POST, path: /api/guard, auth: required }\njobs:\n  guard:\n    steps:\n"
	const gate = "        if: ${{ params.a || '' }} == 'x'\n"
	const refusal = "        run: respond\n        with: { status: 403, json: { error: forbidden } }\n"
	const tail = "      - run: respond\n        with: { status: 200, json: { ok: true } }\n"
	const plain = "has no `with:`, so it answers 200 with an empty body and ends the flow here; later steps do not run. Give it a `status:` (and a body), or delete it."
	const shadow = "has no `with:`, so it answers 200 with an empty body and ends the flow here; later steps do not run. The next step is a `run: respond` under the same `if:` (status 403) and can never answer: when the condition holds, the caller gets this step's 200 instead. Delete this step."

	dir := t.TempDir()
	writeTestFile(t, dir, "app.yaml", "site_name: guard\n")
	app, _ := auditApp(t)
	sid := createCrudScopeSession(t, app, "caller@example.com", "user", "", "")

	for name, c := range map[string]struct {
		src  string
		want string
	}{
		"same inline if":              {head + "      -" + gate[7:] + "        run: respond\n" + "      -" + gate[7:] + refusal + tail, shadow},
		"same if, spaced differently": {head + "      - if:   ${{ params.a || '' }} == 'x'  \n        run: respond\n" + "      -" + gate[7:] + refusal + tail, shadow},
		"inside one if block": {head + "      -" + gate[7:] + "        steps:\n          - run: respond\n          - run: respond\n            with: { status: 403, json: { error: forbidden } }\n" + tail,
			strings.NewReplacer(" under the same `if:`", "", "when the condition holds, the", "the").Replace(shadow)},
		"another condition":          {head + "      -" + gate[7:] + "        run: respond\n" + "      - if: ${{ params.a || '' }} == 'y'\n" + refusal + tail, plain},
		"a step in between":          {head + "      -" + gate[7:] + "        run: respond\n      - query: SELECT 1\n      -" + gate[7:] + refusal + tail, plain},
		"the next respond is bare":   {head + "      -" + gate[7:] + "        run: respond\n      -" + gate[7:] + "        run: respond\n" + tail, plain},
		"the last step of its block": {head + "      -" + gate[7:] + "        steps:\n          - run: respond\n" + tail, plain},
	} {
		// The first respond is the answer, whatever follows it. (A deployed
		// file loads even where the write gate refuses the steps after an
		// unconditional respond, as inside the block.)
		var flows []Flow
		logged := captureLog(t, func() {
			var err error
			if flows, err = parseGHAFlowFile("flows/guard.yaml", []byte(c.src)); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		})
		if rr := respondShapeRun(t, app, &flows[0], sid, map[string]any{"a": "x"}); rr.Code != 200 || strings.TrimSpace(rr.Body.String()) != "" {
			t.Errorf("%s: the bare respond answered %d %q, want 200 with an empty body", name, rr.Code, rr.Body.String())
		}
		if !strings.Contains(logged, "this `run: respond` "+c.want) {
			t.Errorf("%s: loading the file did not log %q:\n%s", name, c.want, logged)
		}
		writeTestFile(t, dir, "flows/guard.yaml", c.src)
		for from, report := range map[string]CheckReport{
			"the post-write check of the flow file": RunSourceCheck(dir, "flows/guard.yaml"),
			"benmore check":                         RunSourceCheck(dir, ""),
		} {
			var got []string
			for _, f := range report.Findings {
				if strings.Contains(f.Message, "has no `with:`") {
					got = append(got, f.Message)
					if at := checkFindingDocs(f); f.Severity != "warning" || at != "flows.step_types" {
						t.Errorf("%s, %s: finding %+v documented at %q", name, from, f, at)
					}
				}
			}
			wantN := 1
			if name == "the next respond is bare" {
				wantN = 2
			}
			if len(got) != wantN || !strings.HasSuffix(got[0], "this `run: respond` "+c.want) {
				t.Errorf("%s, %s: got %q, want %d warning(s), the first ending %q", name, from, got, wantN, c.want)
			}
		}
	}
}

func checkMessages(report CheckReport) (out []string) {
	for _, f := range report.Findings {
		out = append(out, f.Message)
	}
	return out
}
