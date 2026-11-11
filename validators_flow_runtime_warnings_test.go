//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFlowFixture(t *testing.T, dir, rel, content string) {
	t.Helper()
	path := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func findingWith(report CheckReport, file, text string) *CheckFinding {
	for i, f := range report.Findings {
		if f.File == file && strings.Contains(f.Message, text) {
			return &report.Findings[i]
		}
	}
	return nil
}

const txLimitTimeoutFlow = `on:
  request:
    method: POST
    path: /api/slow
    transaction: true
    timeout: 90s
jobs:
  main:
    steps:
      - run: sql
        with: { query: "SELECT 1 AS ok" }
      - run: respond
        with: { status: 200, body: "ok" }
`

// A transactional flow whose time limit is longer than the write-transaction
// limit is rolled back at that limit: the push of the file and `benmore check`
// warn, unless the app raised BENMORE_DB_WRITE_TX_LIMIT.
func TestTransactionTimeoutOverWriteLimitWarns(t *testing.T) {
	t.Setenv("BENMORE_DB_WRITE_TX_LIMIT", "")
	dir := t.TempDir()
	writeFlowFixture(t, dir, "flows/slow.yaml", txLimitTimeoutFlow)
	const text = "write-transaction limit (1m0s, BENMORE_DB_WRITE_TX_LIMIT)"
	for name, report := range map[string]CheckReport{"push": RunSourceCheck(dir, "flows/slow.yaml"), "check": runCheck(dir, "", false)} {
		f := findingWith(report, "flows/slow.yaml", text)
		if f == nil || f.Severity != "warning" {
			t.Fatalf("%s: no transaction-timeout warning: %+v", name, report.Findings)
		}
	}
	// Under the limit, or with the limit raised for the app: no warning.
	writeFlowFixture(t, dir, "flows/slow.yaml", strings.Replace(txLimitTimeoutFlow, "timeout: 90s", "timeout: 45s", 1))
	if f := findingWith(RunSourceCheck(dir, "flows/slow.yaml"), "flows/slow.yaml", "write-transaction limit"); f != nil {
		t.Fatalf("a 45s transactional flow warned: %s", f.Message)
	}
	writeFlowFixture(t, dir, "flows/slow.yaml", txLimitTimeoutFlow)
	writeFlowFixture(t, dir, ".benmore/env", "BENMORE_DB_WRITE_TX_LIMIT=120s\n")
	if f := findingWith(RunSourceCheck(dir, "flows/slow.yaml"), "flows/slow.yaml", "write-transaction limit"); f != nil {
		t.Fatalf("an app with a 120s limit warned: %s", f.Message)
	}
}

// An async flow's respond step is dead code. The warning names the flow's
// own file, so pushing flows/<name>.yaml shows it; it used to be filed under
// flows.yaml and only `benmore check` showed it.
func TestAsyncRespondWarningShownOnPush(t *testing.T) {
	dir := t.TempDir()
	writeFlowFixture(t, dir, "flows/later.yaml", `on:
  request:
    method: POST
    path: /api/later
    mode: async
jobs:
  main:
    steps:
      - run: sql
        with: { query: "SELECT 1 AS ok" }
      - run: respond
        with: { status: 200, body: "done" }
`)
	if f := findingWith(RunSourceCheck(dir, "flows/later.yaml"), "flows/later.yaml", "is `mode: async` but has a respond"); f == nil {
		t.Fatal("pushing an async flow with a respond step did not warn")
	}
}

// A respond step that passes an api step's status through answers the
// upstream's 502/504, whose body Cloudflare replaces on the hosted platform.
func TestUpstreamStatusRespondWarns(t *testing.T) {
	dir := t.TempDir()
	writeFlowFixture(t, dir, "flows/relay.yaml", `on:
  request:
    method: GET
    path: /api/relay
jobs:
  main:
    steps:
      - id: up
        run: api
        with: { url: "https://api.example.com/v1/status" }
      - run: respond
        with:
          status: "${{ steps.up.outputs.status }}"
          body: "${{ steps.up.outputs.body }}"
`)
	f := findingWith(RunSourceCheck(dir, "flows/relay.yaml"), "flows/relay.yaml", "answers the upstream's status")
	if f == nil || !strings.Contains(f.Message, "error code: 502") {
		t.Fatalf("no upstream-status warning: %+v", f)
	}
}

// A request flow's `run: api` whose host comes from request input while the
// call carries credentials is refused by the runtime every time, so the write
// gate refuses it; a literal or env host, or a call without credentials,
// passes.
func TestAPIRequestHostWithCredentialsRefusedAtWrite(t *testing.T) {
	flow := func(url, extra string) string {
		return `on:
  request:
    method: POST
    path: /api/relay
jobs:
  main:
    steps:
      - id: call
        run: api
        with:
          url: "` + url + `"` + extra + `
      - run: respond
        with: { status: 200, body: "ok" }
`
	}
	const envHeader = "\n          headers: { Authorization: \"Bearer ${{ env.PARTNER_API_TOKEN }}\" }"
	for _, url := range []string{"https://${{ params.host }}/v1/items", "${{ params.base_url }}/v1/items"} {
		msg := ValidateOnWrite("flows/relay.yaml", flow(url, envHeader))
		if !strings.Contains(msg, "would choose the scheme or host") || !strings.Contains(msg, "params.") {
			t.Fatalf("url %q with an env header: write gate = %q", url, msg)
		}
	}
	for name, src := range map[string]string{
		"literal host":    flow("https://api.example.com/v1/items/${{ params.id }}", envHeader),
		"env host":        flow("${{ env.API_BASE }}/v1/items/${{ params.id }}", envHeader),
		"no credentials":  flow("https://${{ params.host }}/v1/items", ""),
		"request in path": flow("https://api.example.com/${{ params.path }}", envHeader),
	} {
		if msg := ValidateOnWrite("flows/relay.yaml", src); strings.Contains(msg, "would choose the scheme or host") {
			t.Fatalf("%s refused: %s", name, msg)
		}
	}
}

// The background `source: headers` refusal suggests a `run: enqueue` that
// works as written: the `flow:` key and the payload nested under `with:`.
func TestBackgroundParseHeadersRefusalSnippet(t *testing.T) {
	msg := ValidateOnWrite("flows/probe.yaml", "on:\n  request:\n    method: POST\n    path: /api/probe\n    mode: async\n"+asyncParseHeadersSteps)
	for _, want := range []string{"run: enqueue", "with: { flow: <background flow>, with: { name:", "params.name"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("refusal = %q, want %q", msg, want)
		}
	}
}
