//go:build !cli

package main

import (
	neturl "net/url"
	"strings"
	"testing"
)

// Env placeholders are author syntax. A value that came from a request, a
// row or another step is data and must reach its destination verbatim:
// expanding `{{env.X}}` (or any `{{ref}}`) found inside it would let anyone
// who can submit text read the app's secrets back out of a response, an
// outbound request, an email or a notification.

const reexpandSecret = "sk_reexpand_value_7f3a"

func TestInterpolateCtxDoesNotExpandRequestValues(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	SetAppEnv(app.Dir, "REEXPAND_SECRET", reexpandSecret)
	ctx := &FlowContext{
		App:  app,
		Data: map[string]any{"q": "{{env.REEXPAND_SECRET}}", "private": "row-secret"},
		Params: map[string]string{
			"name":  "{{env.REEXPAND_SECRET}}",
			"other": "{{private}}",
			"piped": "{{ env.REEXPAND_SECRET | upper }}",
		},
	}
	cases := map[string]string{
		"hello :name":                 "hello {{env.REEXPAND_SECRET}}",
		":other!":                     "{{private}}!",
		"x=:piped":                    "x={{ env.REEXPAND_SECRET | upper }}",
		"q={{q}}":                     "q={{env.REEXPAND_SECRET}}",
		"k={{env.REEXPAND_SECRET}}":   "k=" + reexpandSecret,
		"k={{ env.REEXPAND_SECRET }}": "k=" + reexpandSecret,
		"k={{ env.REEXPAND_MISSING | default:'none' }}": "k=none",
		"https://api.example.com/u/:name/x":             "https://api.example.com/u/{{env.REEXPAND_SECRET}}/x",
	}
	for tmpl, want := range cases {
		if got := interpolateCtx(tmpl, ctx); got != want {
			t.Errorf("interpolateCtx(%q) = %q, want %q", tmpl, got, want)
		}
	}
}

func TestAPIStepDoesNotExpandEnvInsideValues(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	SetAppEnv(app.Dir, "REEXPAND_SECRET", reexpandSecret)
	for name, api := range map[string]*FlowAPICall{
		"url":   {URL: "http://127.0.0.1:1/search?q={{q}}"},
		"colon": {URL: "http://127.0.0.1:1/search/:q"},
		"query": {URL: "http://127.0.0.1:1/search", Query: map[string]string{"q": "{{q}}"}},
	} {
		ctx := &FlowContext{
			App:    app,
			Data:   map[string]any{"q": "{{env.REEXPAND_SECRET}}"},
			Params: map[string]string{"q": "{{env.REEXPAND_SECRET}}"},
		}
		err := execStepAPI(ctx, &FlowStep{Name: "call", API: api})
		if err == nil {
			t.Fatalf("%s: expected the private-address refusal", name)
		}
		if strings.Contains(err.Error(), reexpandSecret) {
			t.Errorf("%s: request value was env-expanded into the outbound URL: %v", name, err)
		}
	}
}

func TestInterpolateRowDoesNotExpandRowValues(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	SetAppEnv(app.Dir, "REEXPAND_SECRET", reexpandSecret)
	row := map[string]any{"name": "{{env.REEXPAND_SECRET}}", "note": "{{email}}", "email": "owner@example.com"}
	cases := map[string]string{
		"Hi {{name}}":                   "Hi {{env.REEXPAND_SECRET}}",
		"{{note}} / {{email}}":          "{{email}} / owner@example.com",
		"key {{env.REEXPAND_SECRET}}":   "key " + reexpandSecret,
		"missing {{nope}} {{env.NOPE}}": "missing {{nope}} {{env.NOPE}}",
	}
	for tmpl, want := range cases {
		// Run each case several times: map iteration order used to decide
		// whether one field's value was re-expanded by a later field.
		for i := 0; i < 20; i++ {
			if got := interpolateRow(tmpl, row, app.Dir); got != want {
				t.Fatalf("interpolateRow(%q) = %q, want %q", tmpl, got, want)
			}
		}
	}
}

func TestFetchTagDoesNotExpandEnvInsideRenderedData(t *testing.T) {
	app, _ := auditApp(t)
	SetAppEnv(app.Dir, "REEXPAND_SECRET", reexpandSecret)
	ctx := &RenderContext{App: app, Data: map[string]any{"q": "{{env.REEXPAND_SECRET}}"}}
	out := ExpandFetchTagsAsync(`<fetch url="https://93.184.216.34/search?q={{q}}" as="r">{{r}}</fetch>`, app, ctx)
	i := strings.Index(out, "/_internal/fetch?d=")
	if i < 0 {
		t.Fatalf("no descriptor in output: %s", out)
	}
	token := out[i+len("/_internal/fetch?d="):]
	token = token[:strings.IndexByte(token, '"')]
	token, _ = neturl.QueryUnescape(token)
	desc, err := openFetchDescriptor(app, token, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(desc.URL, reexpandSecret) {
		t.Fatalf("rendered data was env-expanded into the fetch URL: %s", desc.URL)
	}
}

func TestPaginatedAPICursorIsLiteral(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	SetAppEnv(app.Dir, "REEXPAND_SECRET", reexpandSecret)
	ctx := &FlowContext{App: app, Data: map[string]any{}, Params: map[string]string{}}
	api := &FlowAPICall{URL: "https://api.example.com/items", Query: map[string]string{"cursor": "{{env.REEXPAND_SECRET}}", "limit": "10"}}
	got := apiRequestURL(ctx, api, map[string]string{"cursor": "{{env.REEXPAND_SECRET}}"})
	if strings.Contains(got, reexpandSecret) {
		t.Fatalf("upstream cursor was read as a template: %s", got)
	}
	if !strings.Contains(got, "limit=10") || strings.Count(got, "cursor=") != 1 {
		t.Fatalf("literal cursor should replace the template entry and keep the rest: %s", got)
	}
}
