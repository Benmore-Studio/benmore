//go:build !cli

package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestErrorAuditScrubsBeforeTruncationAndNormalization(t *testing.T) {
	app := &App{Dir: t.TempDir()}
	storeAppEnv(app.Dir, map[string]string{"OPAQUE": "opaque-private-value-abcdef", "MULTILINE": "private\nmultiline-value"})
	for _, input := range []string{
		strings.Repeat("x", 2035) + "opaque-private-value-abcdef",
		"private\nmultiline-value",
		"private multiline-value",
	} {
		got := scrubForExport(app, input)
		if strings.Contains(got, "opaque-priv") || strings.Contains(got, "multiline-value") {
			t.Fatalf("secret survived export: %q", got)
		}
	}
}

func TestErrorAuditIntakeScrubsCompleteFields(t *testing.T) {
	app := errorGroupsFixture(t)
	defer stopReportingTest(app)
	secret := "opaque-private-value-abcdef"
	storeAppEnv(app.Dir, map[string]string{"OPAQUE": secret})
	mux := http.NewServeMux()
	RegisterErrorCaptureRoute(mux, app)
	body := clientErrorBody{Message: strings.Repeat("x", 990) + secret, Breadcrumbs: []breadcrumb{{Type: "console", Message: strings.Repeat("x", 290) + secret}}}
	data, _ := json.Marshal(body)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("POST", "/api/_errors", strings.NewReader(string(data))))
	if w.Code != 204 {
		t.Fatalf("intake: %d", w.Code)
	}
	flushReportingTest(t, app)
	var sample string
	if err := app.DB.QueryRow("SELECT sample FROM _benmore_error_groups").Scan(&sample); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sample, "opaque-pr") {
		t.Fatalf("partial secret in sample: %s", sample)
	}
}

func TestErrorAuditRequestScrubsBeforeLegacyLogCut(t *testing.T) {
	app := errorGroupsFixture(t)
	defer stopReportingTest(app)
	secret := "opaque-private-value-abcdef"
	storeAppEnv(app.Dir, map[string]string{"OPAQUE": secret})
	h := requestLogMiddleware(app, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverErrorJSON(w, r, app, "audit", errors.New(strings.Repeat("x", 2028)+secret), "Failed")
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/api/test", nil))
	flushReportingTest(t, app)
	var sample string
	if err := app.DB.QueryRow("SELECT sample FROM _benmore_error_groups").Scan(&sample); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sample, "opaque-pr") {
		t.Fatalf("partial request secret in sample: %s", sample)
	}
}

func TestErrorAuditRejectsBreadcrumbTimestampText(t *testing.T) {
	body := clientErrorBody{Breadcrumbs: []breadcrumb{{Type: "click", Timestamp: "secret@example.com"}, {Type: "http", Timestamp: "2026-10-27T12:00:00Z"}}}
	validateClientErrorContext(&body)
	if body.Breadcrumbs[0].Timestamp != "" || body.Breadcrumbs[1].Timestamp != "2026-10-27T12:00:00Z" {
		t.Fatalf("unexpected timestamps: %+v", body.Breadcrumbs)
	}
}
