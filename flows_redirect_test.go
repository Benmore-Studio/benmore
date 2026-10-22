//go:build !cli

package main

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// TestFlowRedirectRefusesOpenRedirect pins item 23: `run: redirect` followed
// any rendered `to:`, so `to: ${{ params.next }}` was an open redirect. A
// templated target now has to stay same-origin unless its host is listed in
// `allow_hosts:`; a literal off-origin target the author wrote still works.
func TestFlowRedirectRefusesOpenRedirect(t *testing.T) {
	app, done := newTestApp(t)
	defer done()

	type tc struct {
		to       string
		allow    []string
		next     string
		location string // "" = must be refused
	}
	cases := map[string]tc{
		"relative path from request":    {to: "{{next}}", next: "/dashboard", location: "/dashboard"},
		"same host absolute":            {to: "{{next}}", next: "https://app.example.test/x", location: "https://app.example.test/x"},
		"off-origin from request":       {to: "{{next}}", next: "https://evil.example/phish"},
		"protocol-relative":             {to: "{{next}}", next: "//evil.example/phish"},
		"backslash protocol-relative":   {to: "{{next}}", next: `/\evil.example`},
		"scheme-relative host":          {to: "{{next}}", next: "https:evil.example"},
		"userinfo trick":                {to: "{{next}}", next: "https://app.example.test@evil.example/"},
		"javascript from request":       {to: "{{next}}", next: "javascript:alert(1)"},
		"templated host suffix":         {to: "https://checkout.example.com{{next}}", next: ".evil.example/"},
		"templated path on fixed host":  {to: "https://checkout.example.com/pay/{{next}}", next: "abc"},
		"allow_hosts permits host":      {to: "https://checkout.example.com/pay/{{next}}", allow: []string{"checkout.example.com"}, next: "abc", location: "https://checkout.example.com/pay/abc"},
		"allow_hosts is exact":          {to: "{{next}}", allow: []string{"checkout.example.com"}, next: "https://checkout.example.com.evil.example/"},
		"literal off-origin still ok":   {to: "https://partner.example/welcome", next: "ignored", location: "https://partner.example/welcome"},
		"literal javascript refused":    {to: "javascript:alert(1)", next: "x"},
		"colon param makes it template": {to: "https://partner.example/:next", next: "x"},
	}
	for name, c := range cases {
		flow := Flow{Name: "go", Trigger: FlowTrigger{Type: "http", Method: "GET", Path: "/api/go"}, Steps: []FlowStep{
			{Name: "r", Type: "redirect", Redirect: c.to, RedirectAllowHosts: c.allow},
		}}
		req := httptest.NewRequest("GET", "/api/go", nil)
		req.Host = "app.example.test"
		q := req.URL.Query()
		q.Set("next", c.next)
		req.URL.RawQuery = q.Encode()
		rec := httptest.NewRecorder()
		err := executeFlowHTTP(app, &flow, rec, req)
		loc := rec.Header().Get("Location")
		if c.location == "" {
			if err == nil || loc != "" {
				t.Errorf("%s: open redirect not refused (err=%v, Location=%q)", name, err, loc)
			}
			continue
		}
		if err != nil || rec.Code != 303 || loc != c.location {
			t.Errorf("%s: want 303 to %q, got %d Location=%q err=%v", name, c.location, rec.Code, loc, err)
		}
	}
}

// TestFlowRedirectAllowHostsParsedAndWarned covers the YAML side: the GHA
// parser reads `allow_hosts:` (list or comma string), and the shared
// validator warns about a templated, unpinned `to:` without one in both
// write-time reporting and `benmore check`.
func TestFlowRedirectAllowHostsParsedAndWarned(t *testing.T) {
	steps := convertGHASteps([]FlowStepGHA{
		{Run: "redirect", With: map[string]any{"to": "${{ steps.s.outputs.url }}", "allow_hosts": []any{"Checkout.Example.com", "https://billing.example.com/x"}}},
		{Run: "redirect", With: map[string]any{"to": "/x", "allow_hosts": "a.example, b.example"}},
	})
	if got := strings.Join(steps[0].RedirectAllowHosts, ","); got != "checkout.example.com,billing.example.com" {
		t.Fatalf("allow_hosts list parsed as %q", got)
	}
	if got := strings.Join(steps[1].RedirectAllowHosts, ","); got != "a.example,b.example" {
		t.Fatalf("allow_hosts string parsed as %q", got)
	}

	const head = "on:\n  request:\n    method: GET\n    path: /api/go\njobs:\n  go:\n    steps:\n"
	warn := head + "      - if: ${{ params.next }}\n        steps:\n        - id: out\n          run: redirect\n          with: { to: \"${{ params.next }}\" }\n      - run: respond\n        with: { status: 200, body: { ok: true } }\n"
	quiet := []string{
		head + "      - run: redirect\n        with: { to: \"/orders/${{ params.id }}\" }\n",
		head + "      - run: redirect\n        with: { to: \"${{ params.next }}\", allow_hosts: [checkout.example.com] }\n",
		head + "      - run: redirect\n        with: { to: \"https://partner.example/welcome\" }\n",
	}
	if w := ghaRedirectWarnings(warn); len(w) != 1 || !strings.Contains(w[0], "allow_hosts") {
		t.Fatalf("templated redirect should warn once, got %q", w)
	}
	for _, c := range quiet {
		if w := ghaRedirectWarnings(c); len(w) != 0 {
			t.Errorf("no warning expected for %q, got %q", c, w)
		}
	}

	dir := writeApp(t, map[string]string{
		"app.yaml":          "seo:\n  site_name: T\n",
		"flows/go.yaml":     warn,
		"flows/pinned.yaml": strings.Replace(quiet[0], "/api/go", "/api/pinned", 1),
	})
	rpt := RunCompleteCheck(dir, "flows/go.yaml")
	var hits []CheckFinding
	for _, f := range rpt.Findings {
		if f.Source == "flows" && strings.Contains(f.Message, "templated `to:") {
			hits = append(hits, f)
		}
	}
	if len(hits) != 1 || hits[0].Severity != "warning" || hits[0].File != "flows/go.yaml" {
		t.Fatalf("benmore check should warn once for flows/go.yaml, got:\n%s", FormatReport(rpt))
	}
}
