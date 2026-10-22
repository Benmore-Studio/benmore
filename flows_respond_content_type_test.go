//go:build !cli

package main

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// A `respond:` text body is typed from the author's template, never by
// sniffing the rendered output: a request value at the start of a plain-text
// body must not turn the response into an HTML page on the app's origin.
func TestFlowRespondBodyTypeComesFromTemplate(t *testing.T) {
	app, done := newTestApp(t)
	defer done()
	for name, c := range map[string]struct{ body, want string }{
		"text body led by a value": {"{{name}} says hi", "text/plain"},
		"two values":               {"{{name}}{{name}}", "text/plain"},
		"author html stays html":   {"<p>Hello {{name}}</p>", "text/html"},
	} {
		flow := Flow{Name: "hi", Trigger: FlowTrigger{Type: "http", Method: "GET", Path: "/api/hi"}, Steps: []FlowStep{
			{Name: "out", Type: "respond", Respond: &FlowRespond{Body: c.body}},
		}}
		req := httptest.NewRequest("GET", "/api/hi?name=%3Chtml%3E%3Cscript%3Ealert(1)%3C/script%3E", nil)
		rec := httptest.NewRecorder()
		if err := executeFlowHTTP(app, &flow, rec, req); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, c.want) {
			t.Errorf("%s: Content-Type %q, want %s", name, got, c.want)
		}
	}
}

// A body made only of refs keeps the rendered type unless it would be HTML.
func TestRespondBodyContentTypeRefOnlyBodies(t *testing.T) {
	for rendered, want := range map[string]string{
		"%PDF-1.7 ...":             "application/pdf",
		"ISA*00*~GS*HS*~":          "text/plain",
		"<html><script>x</script>": "text/plain",
		"<?xml version=\"1.0\"?>":  "text/plain",
	} {
		if got := respondBodyContentType("{{file}}{{pad}}", rendered); !strings.HasPrefix(got, want) {
			t.Errorf("rendered %q: got %q, want %s", rendered, got, want)
		}
	}
}
