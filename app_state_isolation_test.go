//go:build !cli

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Translations belong to their own app: loading one app must not leave its
// strings visible to a later app that ships none.
func TestI18nIsPerApp(t *testing.T) {
	withStrings := &App{I18n: &I18n{DefaultLang: "en", Translations: map[string]map[string]string{
		"en": {"greeting": "Hello there"},
	}}}
	without := &App{}

	page := &Page{Route: "/", RawHTML: `<p>{{t "greeting"}}</p>`}
	ctxFor := func(app *App) *RenderContext {
		return &RenderContext{Data: map[string]any{}, App: app, Page: page}
	}
	out, err := RenderTemplate(withStrings, page, ctxFor(withStrings))
	if err != nil || !strings.Contains(out, "Hello there") {
		t.Fatalf("app with translations: %q (%v)", out, err)
	}
	out, err = RenderTemplate(without, page, ctxFor(without))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "Hello there") {
		t.Fatalf("an app with no i18n rendered another app's translation: %q", out)
	}

	// And T on a nil app I18n echoes the key rather than another app's value.
	if got := without.I18n.T("greeting", "en"); got != "greeting" {
		t.Fatalf("nil-i18n T = %q, want the key", got)
	}
}

// Recordings belong to their own app: app A's admin must not read the sessions
// posted to app B.
func TestRecordingStoreIsPerApp(t *testing.T) {
	newRecApp := func(t *testing.T) (*App, string) {
		app := ssrTestApp(t)
		app.Design = &DesignConfig{Recording: map[string]string{"enabled": "true", "production": "true"}}
		app.DevMode = false
		admin := createCrudScopeSession(t, app, "admin@example.com", "admin", "", "")
		return app, admin
	}
	a, adminA := newRecApp(t)
	b, _ := newRecApp(t)
	muxA := buildAppMux(a, false, "https://a.example.com")
	muxB := buildAppMux(b, false, "https://b.example.com")

	post := func(mux *http.ServeMux, id, note string) {
		body, _ := json.Marshal(map[string]any{"id": id, "events": []map[string]any{{"type": "snapshot", "data": note}}})
		req := httptest.NewRequest(http.MethodPost, "/_internal/recording", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("post recording: %d", rec.Code)
		}
	}
	post(muxA, "sid-a", "app-a-capture")
	post(muxB, "sid-b", "app-b-capture")

	req := httptest.NewRequest(http.MethodGet, "/_internal/recordings", nil)
	req.Header.Set("Authorization", "Bearer "+adminA)
	rec := httptest.NewRecorder()
	muxA.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list recordings: %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "app-a-capture") {
		t.Fatalf("app A admin missing app A's recording: %s", body)
	}
	if strings.Contains(body, "app-b-capture") || strings.Contains(body, "sid-b") {
		t.Fatalf("app A admin read app B's recordings: %s", body)
	}
}
