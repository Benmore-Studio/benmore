//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// A respond step sends what its author wrote. Blank text under `body:`
// beside a `json:` used to be sent in place of the JSON, and a body written
// as an unquoted date was dropped: both answered the status with nothing.

var respondWrittenShapes = []struct {
	name, with string
	// same is a `with:` that must answer exactly alike, "" for none.
	same       string
	wantStatus int
	wantBody   string
	wantType   string
}{
	// Blank text beside a json: the JSON is the body.
	{name: "empty body beside a json map", with: `{ status: 403, body: "", json: { error: forbidden } }`,
		same: `{ status: 403, json: { error: forbidden } }`, wantStatus: 403, wantBody: `{"error":"forbidden"}`, wantType: "application/json"},
	{name: "whitespace body beside a json list", with: `{ status: 200, body: "  ", json: [1, 2] }`,
		same: `{ status: 200, json: [1, 2] }`, wantStatus: 200, wantBody: `[1,2]`, wantType: "application/json"},
	{name: "empty body beside a json number", with: `{ status: 200, body: '', json: 0 }`,
		same: `{ status: 200, json: 0 }`, wantStatus: 200, wantBody: `0`, wantType: "application/json"},
	{name: "empty body beside json text", with: `{ status: 200, body: "", json: "plain words" }`,
		same: `{ status: 200, json: "plain words" }`, wantStatus: 200, wantBody: `plain words`, wantType: "text/plain; charset=utf-8"},

	// An unquoted date or timestamp is the text that was written.
	{name: "date body", with: `{ status: 200, body: 2026-11-12 }`,
		same: `{ status: 200, body: "2026-11-12" }`, wantStatus: 200, wantBody: `2026-11-12`, wantType: "text/plain; charset=utf-8"},
	{name: "timestamp body", with: `{ status: 201, body: 2026-11-12T08:30:00Z }`,
		same: `{ status: 201, body: "2026-11-12T08:30:00Z" }`, wantStatus: 201, wantBody: `2026-11-12T08:30:00Z`, wantType: "text/plain; charset=utf-8"},
	{name: "timestamp body with a space and an offset", with: `{ status: 200, body: 2026-11-12 08:30:00.50 +02:00 }`,
		same: `{ status: 200, body: "2026-11-12 08:30:00.50 +02:00" }`, wantStatus: 200, wantBody: `2026-11-12 08:30:00.50 +02:00`, wantType: "text/plain; charset=utf-8"},
	{name: "date json", with: `{ status: 200, json: 2026-11-12 }`,
		same: `{ status: 200, json: "2026-11-12" }`, wantStatus: 200, wantBody: `2026-11-12`, wantType: "text/plain; charset=utf-8"},
	{name: "date body under a declared type", with: `{ status: 200, body: 2026-11-12, content_type: "text/csv" }`,
		same: `{ status: 200, body: "2026-11-12", content_type: "text/csv" }`, wantStatus: 200, wantBody: `2026-11-12`, wantType: "text/csv"},
	{name: "date body beside a json", with: `{ status: 200, body: 2026-11-12, json: { a: 1 } }`,
		same: `{ status: 200, body: "2026-11-12", json: { a: 1 } }`, wantStatus: 200, wantBody: `2026-11-12`, wantType: "text/plain; charset=utf-8"},

	// Unchanged: text that is not blank is the body, a number or boolean is
	// that JSON value, and blank text with no json is an empty body.
	{name: "text body beside a json", with: `{ status: 200, body: "hello", json: { a: 1 } }`, wantStatus: 200, wantBody: `hello`, wantType: "text/plain; charset=utf-8"},
	{name: "map body beside a json", with: `{ status: 200, body: { from: body }, json: { from: json } }`, wantStatus: 200, wantBody: `{"from":"body"}`, wantType: "application/json"},
	{name: "number body", with: `{ status: 200, body: 1.50 }`, wantStatus: 200, wantBody: `1.5`, wantType: "application/json"},
	{name: "boolean body", with: `{ status: 200, body: true }`, wantStatus: 200, wantBody: `true`, wantType: "application/json"},
	{name: "number body beside a json", with: `{ status: 200, body: 7, json: { a: 1 } }`, wantStatus: 200, wantBody: `{"a":1}`, wantType: "application/json"},
	{name: "boolean json", with: `{ status: 200, json: false }`, wantStatus: 200, wantBody: `false`, wantType: "application/json"},
	{name: "empty body alone", with: `{ status: 201, body: "" }`, wantStatus: 201},
	{name: "empty body beside an empty json", with: `{ status: 202, body: "", json: "" }`, wantStatus: 202},
	{name: "whitespace body alone", with: `{ status: 200, body: "  " }`, wantStatus: 200, wantType: "text/plain; charset=utf-8"},
}

// Each shape, with and without a transaction, as the last step and behind an
// `if:`: status, Content-Type and body are what was written, the write before
// the respond is kept exactly once and the steps after it do not run.
func TestRespondSendsWhatWasWritten(t *testing.T) {
	for _, transaction := range []bool{true, false} {
		for _, place := range []string{"last_step", "inline_if"} {
			for _, shape := range respondWrittenShapes {
				name := map[bool]string{true: "transaction", false: "no transaction"}[transaction] + "/" + place + "/" + shape.name
				t.Run(name, func(t *testing.T) {
					app, _ := auditApp(t)
					sid := createCrudScopeSession(t, app, "caller@example.com", "user", "", "")
					flows := notifyFlows(t, "flows/respond-shape.yaml", respondShapeFlow(place, shape.with, transaction))
					rr := respondShapeRun(t, app, &flows[0], sid, map[string]any{"mark": "written", "take": "yes"})
					if got := rr.Body.String(); rr.Code != shape.wantStatus || strings.TrimSpace(got) != shape.wantBody {
						t.Errorf("answer = %d %q, want %d %q", rr.Code, got, shape.wantStatus, shape.wantBody)
					}
					if got := rr.Header().Get("Content-Type"); got != shape.wantType {
						t.Errorf("Content-Type = %q, want %q", got, shape.wantType)
					}
					if got := rr.Header().Get("Cache-Control"); got != "private, no-store" {
						t.Errorf("Cache-Control = %q on a signed-in caller's answer, want private, no-store", got)
					}
					if n := respondShapeNotes(t, app, "before written"); n != 1 {
						t.Errorf("the write before the respond was kept %d times, want once", n)
					}
					if n := respondShapeNotes(t, app, "after written"); n != 0 {
						t.Errorf("a step after the taken respond ran (%d rows)", n)
					}
					if shape.same == "" {
						return
					}
					// The other spelling of the same answer.
					flows = notifyFlows(t, "flows/respond-shape.yaml", respondShapeFlow(place, shape.same, transaction))
					other := respondShapeRun(t, app, &flows[0], sid, map[string]any{"mark": "same", "take": "yes"})
					if other.Code != rr.Code || other.Body.String() != rr.Body.String() || other.Header().Get("Content-Type") != rr.Header().Get("Content-Type") {
						t.Errorf("`with: %s` answers %d %q (%s), but `with: %s` answers %d %q (%s)", shape.with, rr.Code, rr.Body.String(), rr.Header().Get("Content-Type"),
							shape.same, other.Code, other.Body.String(), other.Header().Get("Content-Type"))
					}
				})
			}
		}
	}
}

// The JSON beside a blank body is a JSON body like any other: one that reads
// a value the request did not send answers template_unresolved, and a
// transactional flow keeps nothing. (It used to answer 403 with an empty
// body and commit.)
func TestJSONBesideABlankBodyThatCannotAnswerRollsBack(t *testing.T) {
	const with = `{ status: 403, body: "", json: { error: "${{ params.reason }}" } }`
	for _, transaction := range []bool{true, false} {
		t.Run(map[bool]string{true: "transaction", false: "no transaction"}[transaction], func(t *testing.T) {
			app, _ := auditApp(t)
			sid := createCrudScopeSession(t, app, "caller@example.com", "user", "", "")
			flows := notifyFlows(t, "flows/respond-shape.yaml", respondShapeFlow("last_step", with, transaction))

			rr := respondShapeRun(t, app, &flows[0], sid, map[string]any{"mark": "failed"})
			var out map[string]any
			_ = json.Unmarshal(rr.Body.Bytes(), &out)
			if rr.Code != http.StatusInternalServerError || out["error"] != "template_unresolved" {
				t.Fatalf("answer = %d %q, want 500 template_unresolved", rr.Code, rr.Body.String())
			}
			// Without a transaction the earlier step's write is already durable.
			if n, want := respondShapeNotes(t, app, "before failed"), map[bool]int{true: 0, false: 1}[transaction]; n != want {
				t.Errorf("rows kept = %d, want %d", n, want)
			}

			rr = respondShapeRun(t, app, &flows[0], sid, map[string]any{"mark": "sent", "reason": "closed"})
			if rr.Code != http.StatusForbidden || strings.TrimSpace(rr.Body.String()) != `{"error":"closed"}` {
				t.Errorf("answer = %d %q, want 403 with the reason", rr.Code, rr.Body.String())
			}
			if n := respondShapeNotes(t, app, "before sent"); n != 1 {
				t.Errorf("the write before the respond was kept %d times, want once", n)
			}
		})
	}
}

// A date written once and reused through a YAML anchor or a merged `with:`
// is the same text everywhere it is used.
func TestRespondDateTextThroughAnchorsAndMerges(t *testing.T) {
	const src = `on:
  request: { method: POST, path: /api/dated, auth: required }
jobs:
  answer:
    steps:
      - if: ${{ params.a || '' }} == 'anchor'
        run: respond
        with: &dated { status: 200, body: &day 2026-11-12 }
      - if: ${{ params.a || '' }} == 'alias'
        run: respond
        with: { status: 201, json: *day }
      - if: ${{ params.a || '' }} == 'merge'
        run: respond
        with: { <<: *dated, status: 202 }
      - if: ${{ params.a || '' }} == 'override'
        run: respond
        with: { <<: *dated, body: 2027-01-02T03:04:05Z }
      - run: respond
        with: { status: 200, json: { on: *day } }
`
	app, _ := auditApp(t)
	sid := createCrudScopeSession(t, app, "caller@example.com", "user", "", "")
	flows := notifyFlows(t, "flows/dated.yaml", src)
	for a, want := range map[string]struct {
		status int
		body   string
	}{
		"anchor":   {200, "2026-11-12"},
		"alias":    {201, "2026-11-12"},
		"merge":    {202, "2026-11-12"},
		"override": {200, "2027-01-02T03:04:05Z"},
	} {
		rr := respondShapeRun(t, app, &flows[0], sid, map[string]any{"a": a})
		if rr.Code != want.status || rr.Body.String() != want.body || rr.Header().Get("Content-Type") != "text/plain; charset=utf-8" {
			t.Errorf("%s: answer = %d %q (%s), want %d %q as text/plain", a, rr.Code, rr.Body.String(), rr.Header().Get("Content-Type"), want.status, want.body)
		}
	}
	// A date inside a JSON body is not a respond body of its own: it stays
	// the JSON value it was.
	rr := respondShapeRun(t, app, &flows[0], sid, map[string]any{"a": "none"})
	if rr.Code != 200 || strings.TrimSpace(rr.Body.String()) != `{"on":"2026-11-12T00:00:00Z"}` {
		t.Errorf("a date inside a json map answers %d %q, want it unchanged", rr.Code, rr.Body.String())
	}
}

// A `with:` built in code has no source text; a time in it is still sent.
func TestRespondTimeWithNoSourceTextIsStillSent(t *testing.T) {
	var with map[string]any
	if err := decodeConfigYAML([]byte("status: 200\nbody: 2026-11-12\n"), &with); err != nil {
		t.Fatal(err)
	}
	if got := withToRespond(with).Body; got != "2026-11-12" {
		t.Errorf("a date body with no source text is %q, want 2026-11-12", got)
	}
	with = nil
	if err := decodeConfigYAML([]byte("status: 200\njson: 2026-11-12T08:30:00.5+02:00\n"), &with); err != nil {
		t.Fatal(err)
	}
	if got := withToRespond(with).Body; got != "2026-11-12T08:30:00.5+02:00" {
		t.Errorf("a timestamp body with no source text is %q, want 2026-11-12T08:30:00.5+02:00", got)
	}
}
