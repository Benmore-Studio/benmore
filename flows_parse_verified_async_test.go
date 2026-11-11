//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// parseQueryFlow loads one flow whose `run: parse` body step and the request
// query land in a row: the parsed body's id, note and extra, and the request
// field extra read through params. async adds `mode: async` (#788 carries the
// body to the worker); verified adds an hmac_sha256_body `verify:` (#796
// keeps a verified flow's parsed form to the signed body).
func parseQueryFlow(t *testing.T, app *App, async, verified bool) Flow {
	t.Helper()
	var src strings.Builder
	src.WriteString("on:\n  request:\n    method: POST\n    path: /api/partner/events\n")
	if async {
		src.WriteString("    mode: async\n")
	}
	if verified {
		src.WriteString("    verify:\n      recipe: hmac_sha256_body\n      header: X-Partner-Signature\n      secret: \"${{ env.PARTNER_SECRET }}\"\n")
	}
	src.WriteString(`jobs:
  partner:
    steps:
      - id: evt
        run: parse
      - run: sql
        with:
          query: "INSERT INTO parsed (event_id, body_note, body_extra, query_extra) VALUES (:parsed_id, :parsed_note, :parsed_extra, :request_extra)"
          params:
            parsed_id: "${{ steps.evt.outputs.id | default:'unset' }}"
            parsed_note: "${{ steps.evt.outputs.note | default:'unset' }}"
            parsed_extra: "${{ steps.evt.outputs.extra | default:'unset' }}"
            request_extra: "${{ params.extra | default:'unset' }}"
      - run: respond
        with:
          json: {ok: true}
`)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "flows.yaml"), []byte(src.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	flows := LoadFlowsGHA(dir)
	if len(flows) != 1 || flows[0].Async != async || (flows[0].VerifyConfig != nil) != verified {
		t.Fatalf("loaded flows = %+v, want one flow (async=%v verified=%v)", flows, async, verified)
	}
	app.mu.Lock()
	app.Flows = flows
	app.mu.Unlock()
	return flows[0]
}

// The merge of #788 (an async flow's parse step reads the body its job
// carried, queueFlowParseBody) with #796 (a verified flow's parse step reads
// only r.PostForm, never the unsigned query that r.Form merges in): the body
// an async verified flow queues is read with bodyOnly, so a replayed signed
// form body with `?extra=x&note=forged` reaches the worker's parse step
// exactly as signed. The synchronous verified flow keeps the same answer, and
// an unverified async flow still parses query and form together as before.
func TestAsyncVerifiedParseReadsOnlyTheSignedForm(t *testing.T) {
	const signedBody = "id=evt_1&note=signed"
	const target = "/api/partner/events?extra=x&note=forged"
	cases := []struct {
		name            string
		async, verified bool
		// queued is the body the job carries to the worker (async only).
		queued map[string]any
		// row is event_id/body_note/body_extra/query_extra as the flow stored them.
		row string
	}{
		{
			name: "async verified", async: true, verified: true,
			queued: map[string]any{"id": "evt_1", "note": "signed"},
			row:    "evt_1/signed/unset/unset",
		},
		{
			name: "sync verified", verified: true,
			row: "evt_1/signed/unset/unset",
		},
		{
			// r.Form lists body values before query values, so the body's
			// note still wins; the query-only extra is parsed as before.
			name: "async unverified", async: true,
			queued: map[string]any{"id": "evt_1", "note": "signed", "extra": "x"},
			row:    "evt_1/signed/x/x",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			app, done := newTestApp(t)
			defer done()
			EnsureJobsTable(app.DB)
			SetAppEnv(app.Dir, "PARTNER_SECRET", "partner-secret")
			mustExec(t, app.DB, `CREATE TABLE parsed (event_id TEXT, body_note TEXT, body_extra TEXT, query_extra TEXT)`)
			flow := parseQueryFlow(t, app, c.async, c.verified)

			r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(signedBody))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Set("X-Partner-Signature", hmacHex(t, "partner-secret", []byte(signedBody)))
			rec := httptest.NewRecorder()
			if err := executeFlowHTTP(app, &flow, rec, r); err != nil {
				t.Fatalf("run: %v", err)
			}
			if c.async {
				if rec.Code != http.StatusAccepted {
					t.Fatalf("enqueue status = %d, want 202 (body %s)", rec.Code, rec.Body.String())
				}
				var raw string
				if err := app.DB.QueryRow("SELECT payload FROM _benmore_jobs ORDER BY id DESC LIMIT 1").Scan(&raw); err != nil {
					t.Fatalf("read queued payload: %v", err)
				}
				var payload map[string]any
				if err := json.Unmarshal([]byte(raw), &payload); err != nil {
					t.Fatalf("decode payload: %v", err)
				}
				carried, _ := payload[flowRequestBodyPayloadField].(map[string]any)
				if carried == nil || carried["form"] != true || !reflect.DeepEqual(carried["value"], c.queued) {
					t.Fatalf("queued body = %#v, want a form body %#v", payload[flowRequestBodyPayloadField], c.queued)
				}
				FlushJobs(app)
				var status, jobErr string
				if err := app.DB.QueryRow("SELECT status, COALESCE(error,'') FROM _benmore_jobs ORDER BY id DESC LIMIT 1").Scan(&status, &jobErr); err != nil {
					t.Fatalf("read job: %v", err)
				}
				if status != "completed" {
					t.Fatalf("job status = %q error = %q, want completed", status, jobErr)
				}
			} else if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
			}

			var id, note, extra, queryExtra string
			if err := app.DB.QueryRow(`SELECT event_id, body_note, body_extra, query_extra FROM parsed`).Scan(&id, &note, &extra, &queryExtra); err != nil {
				t.Fatalf("the flow stored no row: %v", err)
			}
			if got := id + "/" + note + "/" + extra + "/" + queryExtra; got != c.row {
				t.Fatalf("stored row = %s, want %s", got, c.row)
			}
		})
	}
}
