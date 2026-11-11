//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// bodyTooLargeAnswer asserts a 413 whose JSON states the limit.
func bodyTooLargeAnswer(t *testing.T, name string, rr *httptest.ResponseRecorder, limit int64) {
	t.Helper()
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("%s: status %d, want 413: %.300s", name, rr.Code, rr.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("%s: 413 body is not JSON: %v %.300s", name, err, rr.Body.String())
	}
	msg, _ := got["error"].(string)
	if !strings.Contains(msg, "request body too large") || !strings.Contains(msg, strconv.FormatInt(limit, 10)) {
		t.Fatalf("%s: 413 error %q does not state the limit %d", name, msg, limit)
	}
	if n, _ := got["limit_bytes"].(float64); int64(n) != limit {
		t.Fatalf("%s: limit_bytes %v, want %d", name, got["limit_bytes"], limit)
	}
}

const bodyLimitFlow = `on:
  request:
    method: POST
    path: /api/big
jobs:
  main:
    steps:
      - run: sql
        with:
          query: "INSERT INTO runs (text_len) VALUES (length(:text))"
      - if: ${{ params.text }}
        run: respond
        with:
          status: 200
          body: { ok: true }
      - run: respond
        with:
          status: 422
          body: { error: "text is required" }
`

// A flow's JSON body over the 1 MiB binding limit was cut at the limit,
// failed to decode and was bound as nothing, so the flow ran with every field
// empty and answered the app's own "text is required" (measured: 1,048,000
// characters worked, 1,100,000 did not). It answers 413 with the limit and
// runs no step.
func TestFlowOversizedJSONBodyAnswers413(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	mustExec(t, app.DB, `CREATE TABLE runs (id INTEGER PRIMARY KEY, text_len INTEGER)`)

	under := runProbeGHAFlow(t, app, bodyLimitFlow, `{"text":"`+strings.Repeat("x", 1048000)+`"}`)
	if under.Code != http.StatusOK {
		t.Fatalf("a body under the limit must bind: %d %s", under.Code, under.Body.String())
	}
	over := runProbeGHAFlow(t, app, bodyLimitFlow, `{"text":"`+strings.Repeat("x", 1100000)+`"}`)
	bodyTooLargeAnswer(t, "flow JSON body", over, flowVerifyBodyMaxBytes)
	var runs int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM runs`).Scan(&runs); err != nil || runs != 1 {
		t.Fatalf("the oversized request ran a step: runs=%d err=%v", runs, err)
	}

	// A flow with declared inputs answered 400 "Invalid or oversized"; the
	// size is now named.
	withInputs := strings.Replace(bodyLimitFlow, "    path: /api/big\n", "    path: /api/big\n    inputs:\n      text: { type: string }\n", 1)
	bodyTooLargeAnswer(t, "flow with inputs", runProbeGHAFlow(t, app, withInputs, `{"text":"`+strings.Repeat("x", 1100000)+`"}`), flowVerifyBodyMaxBytes)
}

// A `parse: body` step read the same 1 MiB and failed as cut JSON; a form
// body over net/http's cap parsed as no fields. Both now fail the flow as too
// large (413) before any later step runs.
func TestFlowParseStepOversizedBodyAnswers413(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	mustExec(t, app.DB, `CREATE TABLE runs (id INTEGER PRIMARY KEY, text_len INTEGER)`)
	flow := `on:
  request:
    method: PUT
    path: /api/parse
jobs:
  main:
    steps:
      - id: body
        run: parse
        with: { source: body }
      - run: sql
        with:
          query: "INSERT INTO runs (text_len) VALUES (1)"
      - run: respond
        with: { status: 200, body: { ok: true } }
`
	flows, err := parseGHAFlowFile("flows/parse.yaml", []byte(flow))
	if err != nil || len(flows) != 1 {
		t.Fatalf("parse flow: %v", err)
	}
	call := func(contentType, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPut, "/api/parse", strings.NewReader(body))
		r.Header.Set("Content-Type", contentType)
		w := httptest.NewRecorder()
		captureLog(t, func() { executeFlowHTTP(app, &flows[0], w, r) })
		return w
	}
	if ok := call("text/plain", `{"a":1}`); ok.Code != http.StatusOK {
		t.Fatalf("a small body must parse: %d %s", ok.Code, ok.Body.String())
	}
	bodyTooLargeAnswer(t, "parse step JSON", call("text/plain", `{"a":"`+strings.Repeat("x", 1100000)+`"}`), flowVerifyBodyMaxBytes)
	bodyTooLargeAnswer(t, "parse step form", call("application/x-www-form-urlencoded", "a="+strings.Repeat("x", int(netHTTPMaxFormBytes))), netHTTPMaxFormBytes)
	var runs int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM runs`).Scan(&runs); err != nil || runs != 1 {
		t.Fatalf("an oversized request ran the step after parse: runs=%d err=%v", runs, err)
	}
}

// Behind the app's global body cap (MAX_REQUEST_BODY_BYTES), every flow and
// auto-CRUD body reader answers 413 with that cap. A form post to a flow or an
// auto-CRUD create used to parse as no fields (a flow ran with empty input,
// a create inserted an empty row), a JSON update was applied as an update of
// nothing, and the JSON create, batch and transaction routes answered a
// misleading 400.
func TestGlobalBodyCapAnswers413OnFlowsAndAutoCRUD(t *testing.T) {
	app := newGateApp(t, "CREATE TABLE widgets (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, name TEXT)")
	uid, sid := gateUser(t, app, "owner@example.com")
	mustExec(t, app.DB, "INSERT INTO widgets (user_id, name) VALUES ("+strconv.FormatInt(uid, 10)+", 'one')")
	mustExec(t, app.DB, `CREATE TABLE runs (id INTEGER PRIMARY KEY, text_len INTEGER)`)
	const limit = 4096
	SetAppEnv(app.Dir, "MAX_REQUEST_BODY_BYTES", strconv.Itoa(limit))
	flows, err := parseGHAFlowFile("flows/big.yaml", []byte(bodyLimitFlow))
	if err != nil || len(flows) != 1 {
		t.Fatalf("parse flow: %v", err)
	}
	big := strings.Repeat("x", 2*limit)
	jsonBig := `{"name":"` + big + `"}`
	formBig := url.Values{"name": {big}, "text": {big}}.Encode()
	cases := []struct {
		name, method, path, ctype, body string
		handler                         func(http.ResponseWriter, *http.Request)
	}{
		{"flow form", "POST", "/api/big", "application/x-www-form-urlencoded", formBig,
			func(w http.ResponseWriter, r *http.Request) { executeFlowHTTP(app, &flows[0], w, r) }},
		{"flow JSON", "POST", "/api/big", "application/json", `{"text":"` + big + `"}`,
			func(w http.ResponseWriter, r *http.Request) { executeFlowHTTP(app, &flows[0], w, r) }},
		{"create JSON", "POST", "/api/widgets", "application/json", jsonBig,
			func(w http.ResponseWriter, r *http.Request) { handleCreate(w, r, app, "widgets") }},
		{"create form", "POST", "/api/widgets", "application/x-www-form-urlencoded", formBig,
			func(w http.ResponseWriter, r *http.Request) { handleCreate(w, r, app, "widgets") }},
		{"update JSON", "PATCH", "/api/widgets/1", "application/json", jsonBig,
			func(w http.ResponseWriter, r *http.Request) { handleUpdate(w, r, app, "widgets") }},
		{"update form", "PATCH", "/api/widgets/1", "application/x-www-form-urlencoded", formBig,
			func(w http.ResponseWriter, r *http.Request) { handleUpdate(w, r, app, "widgets") }},
		{"batch create", "POST", "/api/widgets/batch", "application/json", `[` + jsonBig + `]`,
			func(w http.ResponseWriter, r *http.Request) { handleBatchCreate(w, r, app, "widgets") }},
		{"batch update", "PATCH", "/api/widgets/batch", "application/json", `{"ids":[1],"fields":` + jsonBig + `}`,
			func(w http.ResponseWriter, r *http.Request) { handleBatchUpdate(w, r, app, "widgets") }},
		{"batch delete", "DELETE", "/api/widgets/batch", "application/json", `{"ids":[1],"pad":"` + big + `"}`,
			func(w http.ResponseWriter, r *http.Request) { handleBatchDelete(w, r, app, "widgets") }},
		{"transaction", "POST", "/api/_transaction", "application/json", `{"operations":[{"table":"widgets","action":"insert","data":` + jsonBig + `}]}`,
			func(w http.ResponseWriter, r *http.Request) { handleTransaction(w, r, app) }},
	}
	for _, c := range cases {
		handler := serverBodyLimitMiddleware(http.HandlerFunc(c.handler), app, nil)
		r := httptest.NewRequest(c.method, "https://app.example.com"+c.path, strings.NewReader(c.body))
		r.Header.Set("Content-Type", c.ctype)
		r.Header.Set("Authorization", "Bearer "+sid)
		w := httptest.NewRecorder()
		captureLog(t, func() { handler.ServeHTTP(w, r) })
		bodyTooLargeAnswer(t, c.name, w, limit)
	}
	if n := gateScalar(t, app, "SELECT COUNT(*) FROM widgets"); n != "1" {
		t.Fatalf("an oversized request wrote widgets: %s rows", n)
	}
	if name := gateScalar(t, app, "SELECT name FROM widgets WHERE id = 1"); name != "one" {
		t.Fatalf("an oversized update changed the row: %q", name)
	}
	if n := gateScalar(t, app, "SELECT COUNT(*) FROM runs"); n != "0" {
		t.Fatalf("an oversized request ran a flow step: %s runs", n)
	}

	// Under the cap nothing changes: the same routes accept a small body.
	small := httptest.NewRequest("POST", "https://app.example.com/api/widgets", strings.NewReader(`{"name":"two"}`))
	small.Header.Set("Content-Type", "application/json")
	small.Header.Set("Authorization", "Bearer "+sid)
	w := httptest.NewRecorder()
	serverBodyLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handleCreate(w, r, app, "widgets") }), app, nil).ServeHTTP(w, small)
	if w.Code != http.StatusOK && w.Code != http.StatusCreated {
		t.Fatalf("a small create: %d %s", w.Code, w.Body.String())
	}
}
