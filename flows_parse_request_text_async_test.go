//go:build !cli

package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The merge of #788 (an async flow's parse step runs in the worker on the
// body its job carried, bindFlowParsedBody) with #822 (a string the caller
// sent stays a string in JSON bodies; jobs.go carries computedKeys): the
// worker's parsed body is request text, so "007" stays the string "007" and a
// string spelling a JSON object is not decoded into one, exactly as when the
// same flow runs synchronously. Before #822 the object-shaped string was sent
// upstream as an object (NoSQL operator injection).
func TestAsyncParseKeepsRequestStringsAsStrings(t *testing.T) {
	sent := make(chan string, 4)
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		sent <- string(body)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	}))
	defer receiver.Close()
	// The step's URL is a public address literal (it passes the SSRF guard);
	// the strict transport is pointed at the local receiver for this test.
	saved := strictOutboundTransport
	strictOutboundTransport = &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", receiver.Listener.Addr().String())
	}}
	defer func() { strictOutboundTransport = saved }()

	const body = `{"code":"007","filter":"{\"$gt\":\"\"}"}`
	want := map[string]any{"code": "007", "filter": `{"$gt":""}`}
	for _, async := range []bool{false, true} {
		t.Run(map[bool]string{false: "sync", true: "async"}[async], func(t *testing.T) {
			app, done := newTestApp(t)
			defer done()
			EnsureJobsTable(app.DB)
			// No declared type: SQLite keeps the type each value is bound with.
			mustExec(t, app.DB, `CREATE TABLE codes (code, filter)`)
			mode := ""
			if async {
				mode = "    mode: async\n"
			}
			src := "on:\n  request:\n    method: POST\n    path: /api/codes\n" + mode + `jobs:
  codes:
    steps:
      - id: evt
        run: parse
      - run: sql
        with:
          query: "INSERT INTO codes (code, filter) VALUES (:parsed_code, :parsed_filter)"
          params:
            parsed_code: "${{ steps.evt.outputs.code }}"
            parsed_filter: "${{ steps.evt.outputs.filter }}"
      - id: forward
        run: api
        with:
          method: POST
          url: http://93.184.216.34/codes
          json:
            code: "${{ steps.evt.outputs.code }}"
            filter: "${{ steps.evt.outputs.filter }}"
      - run: respond
        with:
          json:
            code: "${{ steps.evt.outputs.code }}"
            filter: "${{ steps.evt.outputs.filter }}"
`
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "flows.yaml"), []byte(src), 0o644); err != nil {
				t.Fatal(err)
			}
			flows := LoadFlowsGHA(dir)
			if len(flows) != 1 || flows[0].Async != async {
				t.Fatalf("loaded flows = %+v, want one flow (async=%v)", flows, async)
			}
			app.mu.Lock()
			app.Flows = flows
			app.mu.Unlock()

			r := httptest.NewRequest(http.MethodPost, "/api/codes", strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			if err := executeFlowHTTP(app, &flows[0], rec, r); err != nil {
				t.Fatalf("run: %v", err)
			}
			if async {
				if rec.Code != http.StatusAccepted {
					t.Fatalf("enqueue status = %d, want 202 (body %s)", rec.Code, rec.Body.String())
				}
				FlushJobs(app)
				var status, jobErr string
				if err := app.DB.QueryRow("SELECT status, COALESCE(error,'') FROM _benmore_jobs ORDER BY id DESC LIMIT 1").Scan(&status, &jobErr); err != nil {
					t.Fatalf("read job: %v", err)
				}
				if status != "completed" {
					t.Fatalf("job status = %q error = %q, want completed", status, jobErr)
				}
			} else {
				var answer map[string]any
				if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &answer) != nil || !reflect.DeepEqual(answer, want) {
					t.Fatalf("respond: status %d body %s, want %v", rec.Code, rec.Body.String(), want)
				}
			}

			select {
			case got := <-sent:
				var forwarded map[string]any
				if err := json.Unmarshal([]byte(got), &forwarded); err != nil || !reflect.DeepEqual(forwarded, want) {
					t.Fatalf("run: api sent %s, want the caller's strings %v", got, want)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("run: api sent nothing")
			}

			var code, codeType, filter, filterType string
			if err := app.DB.QueryRow(`SELECT code, typeof(code), filter, typeof(filter) FROM codes`).Scan(&code, &codeType, &filter, &filterType); err != nil {
				t.Fatalf("the flow stored no row: %v", err)
			}
			if code != "007" || codeType != "text" || filter != `{"$gt":""}` || filterType != "text" {
				t.Fatalf("stored code=%q (%s) filter=%q (%s), want the text the caller sent", code, codeType, filter, filterType)
			}
		})
	}
}

// bindFlowParsedBody is where both paths bind a parse step's output, inline
// and in the worker. A key a step had marked computed (data a JSON body may
// decode) holds request text again once a parse step writes it: the latest
// write decides (#822's unmarkComputed, carried into #788's shared binder).
func TestParsedBodyBindingIsRequestText(t *testing.T) {
	for _, parsed := range []*flowParsedBody{
		{Value: map[string]any{"filter": `{"$gt":""}`, "code": "007"}},
		{Form: true, Value: map[string]any{"filter": `{"$gt":""}`, "code": "007"}},
	} {
		ctx := &FlowContext{
			Data:         map[string]any{},
			Params:       map[string]string{},
			RequestKeys:  map[string]bool{},
			computedKeys: map[string]bool{"evt": true},
		}
		bindFlowParsedBody(ctx, "evt", parsed)
		if !ctx.RequestKeys["evt"] || ctx.computedKeys["evt"] {
			t.Fatalf("form=%v: request keys %v, computed keys %v; want evt request text", parsed.Form, ctx.RequestKeys, ctx.computedKeys)
		}
		got := interpolateJSONValues(map[string]any{"filter": "{{evt.filter}}", "code": "{{evt.code}}"}, ctx)
		if want := map[string]any{"filter": `{"$gt":""}`, "code": "007"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("form=%v: JSON body = %#v, want %#v", parsed.Form, got, want)
		}
	}
}
