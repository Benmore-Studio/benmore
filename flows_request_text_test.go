//go:build !cli

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// runRequestTextFlow runs one GHA flow file against body (sent with
// contentType) and returns the answer and every outbound request body.
func runRequestTextFlow(t *testing.T, app *App, flowYAML, contentType, body string) (*httptest.ResponseRecorder, []string) {
	t.Helper()
	flows, err := parseGHAFlowFile(filepath.Join(app.Dir, "flows", "probe.yaml"), []byte(flowYAML))
	if err != nil || len(flows) != 1 {
		t.Fatalf("parse flow: %v (%d flows)", err, len(flows))
	}
	var sent []string
	client := &http.Client{Transport: outboundRoundTrip(func(r *http.Request) (*http.Response, error) {
		b, _ := io.ReadAll(r.Body)
		sent = append(sent, string(b))
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}},
			Body: io.NopCloser(strings.NewReader(`{"ok":true}`)), Request: r}, nil
	})}
	r := httptest.NewRequest(flows[0].Trigger.Method, flows[0].Trigger.Path, strings.NewReader(body))
	r.Header.Set("Content-Type", contentType)
	rr := httptest.NewRecorder()
	executeFlowHTTPAsWithAPIClient(app, &flows[0], rr, r, nil, client)
	return rr, sent
}

func requestTextObject(t *testing.T, text string) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("not a JSON object: %v\n%s", err, text)
	}
	return out
}

// A form field `a={"admin":true}` came back from `respond json: {a: ${{
// params.a }}}` as an object, and the same text inside a `run: api` json:
// map or a JSON text body was sent upstream as an object: request text could
// inject structure (a NoSQL operator object, extra keys). It now stays the
// string the caller sent, while "true" and "123" stay strings as before.
func TestRequestTextStaysTextInJSONBodies(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	flowYAML := `on:
  request:
    method: POST
    path: /api/probe
jobs:
  main:
    steps:
      - id: copy
        run: set
        with:
          echoed: "${{ params.a }}"
      - id: call
        run: api
        with:
          method: POST
          url: https://api.telegram.org/search
          json:
            filter: "${{ params.a }}"
            copied: "${{ steps.copy.outputs.echoed }}"
            flag: "${{ params.flag }}"
      - id: post
        run: api
        with:
          method: POST
          url: https://api.telegram.org/raw
          body: '{"filter": ${{ params.a }}, "n": ${{ params.n }}}'
      - run: respond
        with:
          json:
            a: "${{ params.a }}"
            bare: "${{ a }}"
            copied: "${{ steps.copy.outputs.echoed }}"
            quoted: '{"q": "${{ params.q }}"}'
            flag: "${{ params.flag }}"
            n: "${{ params.n }}"
`
	form := url.Values{
		"a":    {`{"admin":true}`},
		"q":    {`x", "admin": "1`},
		"flag": {"true"},
		"n":    {"123"},
	}
	rr, sent := runRequestTextFlow(t, app, flowYAML, "application/x-www-form-urlencoded", form.Encode())
	if rr.Code != http.StatusOK || len(sent) != 2 {
		t.Fatalf("status %d, %d outbound calls: %s", rr.Code, len(sent), rr.Body.String())
	}
	got := requestTextObject(t, rr.Body.String())
	want := map[string]any{
		"a": `{"admin":true}`, "bare": `{"admin":true}`, "copied": `{"admin":true}`,
		"quoted": map[string]any{"q": `x", "admin": "1`},
		"flag":   "true", "n": "123",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("respond =\n%#v\nwant\n%#v", got, want)
	}
	apiJSON := requestTextObject(t, sent[0])
	if !reflect.DeepEqual(apiJSON, map[string]any{"filter": `{"admin":true}`, "copied": `{"admin":true}`, "flag": "true"}) {
		t.Fatalf("api json: body = %s", sent[0])
	}
	textBody := requestTextObject(t, sent[1])
	if !reflect.DeepEqual(textBody, map[string]any{"filter": `{"admin":true}`, "n": float64(123)}) {
		t.Fatalf("api text body = %s", sent[1])
	}
}

// Structure that is not request text keeps its documented decoding: a SQL
// json_group_array() column (even from a lookup keyed by request input,
// read directly, copied through run: set, or through a loop over the rows),
// and an object a JSON request body sent as an object.
func TestStructuredValuesKeepTheirStructure(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	mustExec(t, app.DB, `CREATE TABLE items (id INTEGER PRIMARY KEY, owner TEXT, tag TEXT)`)
	mustExec(t, app.DB, `INSERT INTO items (owner, tag) VALUES ('ann', 'red'), ('ann', 'blue'), ('bob', 'green')`)
	flowYAML := `on:
  request:
    method: POST
    path: /api/structured
jobs:
  main:
    steps:
      - id: lookup
        run: sql
        with:
          query: "SELECT json_group_array(tag) AS tags FROM (SELECT tag FROM items WHERE owner = :owner ORDER BY id)"
      - id: copy
        run: set
        with:
          tags: "${{ steps.lookup.outputs.tags }}"
      - for_each: ${{ steps.lookup.outputs }}
        as: row
        steps:
          - id: inloop
            run: set
            with:
              seen: "${{ row.tags }}"
      - run: respond
        with:
          json:
            direct: "${{ steps.lookup.outputs.tags }}"
            copied: "${{ steps.copy.outputs.tags }}"
            filter: "${{ params.filter }}"
            list: "${{ params.list }}"
`
	rr, _ := runRequestTextFlow(t, app, flowYAML, "application/json", `{"owner":"ann","filter":{"$gt":""},"list":["a","b"]}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	got := requestTextObject(t, rr.Body.String())
	want := map[string]any{
		"direct": []any{"red", "blue"}, "copied": []any{"red", "blue"},
		"filter": map[string]any{"$gt": ""}, "list": []any{"a", "b"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("respond =\n%#v\nwant\n%#v", got, want)
	}
}

// The loop variable over a SQL step's rows is computed data (its JSON
// column decodes); over a request array it is request text.
func TestLoopVariableRequestText(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	mustExec(t, app.DB, `CREATE TABLE docs (id INTEGER PRIMARY KEY, owner TEXT, meta TEXT)`)
	mustExec(t, app.DB, `INSERT INTO docs (owner, meta) VALUES ('ann', '{"pages":3}')`)
	flowYAML := `on:
  request:
    method: POST
    path: /api/loop
jobs:
  main:
    steps:
      - id: rows
        run: sql
        with:
          query: "SELECT meta FROM docs WHERE owner = :owner"
      - for_each: ${{ steps.rows.outputs }}
        as: doc
        steps:
          - id: call
            run: api
            with:
              method: POST
              url: https://api.telegram.org/doc
              json: { meta: "${{ doc.meta }}" }
      - for_each: ${{ params.notes }}
        as: note
        steps:
          - id: send
            run: api
            with:
              method: POST
              url: https://api.telegram.org/note
              json: { note: "${{ note }}" }
      - run: respond
        with: { status: 200, json: { ok: true } }
`
	rr, sent := runRequestTextFlow(t, app, flowYAML, "application/json", `{"owner":"ann","notes":["{\"$where\":\"1\"}"]}`)
	if rr.Code != http.StatusOK || len(sent) != 2 {
		t.Fatalf("status %d, %d outbound calls: %s", rr.Code, len(sent), rr.Body.String())
	}
	if !reflect.DeepEqual(requestTextObject(t, sent[0]), map[string]any{"meta": map[string]any{"pages": float64(3)}}) {
		t.Fatalf("a SQL row's JSON column in a loop lost its structure: %s", sent[0])
	}
	if !reflect.DeepEqual(requestTextObject(t, sent[1]), map[string]any{"note": `{"$where":"1"}`}) {
		t.Fatalf("a request string in a loop became structure: %s", sent[1])
	}
}

// An enqueued job flow sees the same split: a payload value copied from a
// step's computed output (a lookup keyed by request input) keeps decoding in
// the job's JSON bodies, and a payload value copied from request text stays
// a string.
func TestEnqueuedPayloadKeepsRequestTextSplit(t *testing.T) {
	app := newJobsTestApp(t)
	mustExec(t, app.DB, `CREATE TABLE items (id INTEGER PRIMARY KEY, owner TEXT, tag TEXT)`)
	mustExec(t, app.DB, `INSERT INTO items (owner, tag) VALUES ('ann', 'red'), ('ann', 'blue')`)
	var file FlowFileGHA
	if err := yamlUnmarshal([]byte(`on:
  request: {method: POST, path: /api/queue}
jobs:
  queue:
    steps:
      - id: lookup
        run: sql
        with:
          query: "SELECT json_group_array(tag) AS tags FROM (SELECT tag FROM items WHERE owner = :owner ORDER BY id)"
      - id: queued
        run: enqueue
        with:
          flow: worker
          with: {tags: "${{ steps.lookup.outputs.tags }}", raw: "${{ params.raw }}"}
`), &file); err != nil {
		t.Fatal(err)
	}
	steps := convertGHASteps(file.Jobs["queue"].Steps)
	ctx := &FlowContext{App: app, Data: map[string]any{"owner": "ann", "raw": `{"$ne":null}`},
		Params: map[string]string{"owner": "ann", "raw": `{"$ne":null}`}, RequestKeys: map[string]bool{"owner": true, "raw": true},
		Writes: newFlowWriteLog()}
	executeSteps(ctx, steps)
	if ctx.Error != nil {
		t.Fatal(ctx.Error)
	}
	var payload string
	if err := app.DB.QueryRow("SELECT payload FROM _benmore_jobs").Scan(&payload); err != nil {
		t.Fatal(err)
	}
	var data map[string]any
	if err := json.Unmarshal([]byte(payload), &data); err != nil {
		t.Fatal(err)
	}
	job := &FlowContext{App: app, Data: data, RequestKeys: takeFlowRequestKeys(data), computedKeys: takeFlowComputedKeys(data)}
	if !job.RequestKeys["tags"] || !job.RequestKeys["raw"] {
		t.Fatalf("both payload values must stay request input for sql_dynamic: %v", job.RequestKeys)
	}
	got := interpolateJSONValues(map[string]any{"tags": "{{tags}}", "raw": "{{raw}}"}, job)
	want := map[string]any{"tags": []any{"red", "blue"}, "raw": `{"$ne":null}`}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("job JSON body = %#v, want %#v", got, want)
	}
}
