//go:build !cli

package main

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestErrorClientContextValidation(t *testing.T) {
	var body clientErrorBody
	if err := json.Unmarshal([]byte(`{"message":"failure","kind":"http","level":"fatal","request_id":"abcdef0123456789","method":"GET","path":"/api/items?secret=yes","status":502,"tags":{"screen":"editor","BAD KEY":"no","request_id":"spoofed"},"breadcrumbs":[{"type":"http","message":"GET /items","data":{"path":"/items?secret=yes","status":502}},{"type":"unknown","message":"drop"}]}`), &body); err != nil {
		t.Fatal(err)
	}
	validateClientErrorContext(&body)
	ev := clientReportedEvent(body)
	if ev.RequestID != "abcdef0123456789" || ev.Route != "/api/items" || ev.Method != "GET" || ev.Level != "fatal" || ev.Extra["status"] != 502 {
		t.Fatalf("correlation lost: %+v", ev)
	}
	if len(ev.Breadcrumbs) != 1 || ev.Breadcrumbs[0].Data["path"] != "/items" || ev.Tags["BAD KEY"] != "" {
		t.Fatalf("invalid context retained: %+v", ev)
	}
	body.RequestID, body.Level = "not-a-request-id", "invented"
	body.Tags = map[string]string{"long": strings.Repeat("界", 201)}
	body.Breadcrumbs = nil
	for i := 0; i < 40; i++ {
		body.Breadcrumbs = append(body.Breadcrumbs, breadcrumb{Type: "console", Message: strings.Repeat("界", 301), Data: map[string]any{"nested": map[string]any{"secret": "no"}, "value": "form content"}})
	}
	validateClientErrorContext(&body)
	if body.RequestID != "" || body.Level != "error" || len(body.Tags) != 0 || len(body.Breadcrumbs) != 30 {
		t.Fatalf("limits not enforced: %+v", body)
	}
	for _, crumb := range body.Breadcrumbs {
		if utf8.RuneCountInString(crumb.Message) > 300 || len(crumb.Data) != 0 {
			t.Fatalf("breadcrumb not bounded: %+v", crumb)
		}
	}
}

func TestErrorClientBreadcrumbExportScrubs(t *testing.T) {
	app := &App{Dir: t.TempDir()}
	storeAppEnv(app.Dir, map[string]string{"SECRET": "private123value"})
	body := clientErrorBody{Message: "manual", Kind: "manual", Tags: map[string]string{"screen": "owner@example.com"}, Breadcrumbs: []breadcrumb{{Type: "console", Message: "private123value owner@example.com 123456789012"}}}
	validateClientErrorContext(&body)
	b, err := json.Marshal(clientSentryEvent(app, body))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"private123value", "owner@example.com", "123456789012"} {
		if strings.Contains(string(b), forbidden) {
			t.Fatalf("export leaked %q: %s", forbidden, b)
		}
	}
}
