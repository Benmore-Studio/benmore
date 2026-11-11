//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestErrorGroupListFilters(t *testing.T) {
	app := errorGroupsFixture(t)
	now := time.Now()
	for _, ev := range []errorEvent{
		{Source: "server", Kind: "server", Level: "error", Message: "current failure", RequestID: "abcdef0123456789"},
		{Source: "client", Kind: "error", Level: "warning", Message: "browser warning"},
	} {
		if _, _, err := recordGroupAt(app, ev, now); err != nil {
			t.Fatal(err)
		}
	}
	old := errorEvent{Source: "server", Kind: "job", Level: "error", Message: "old job"}
	if _, _, err := recordGroupAt(app, old, now.Add(-48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	result, err := listErrorGroups(t.Context(), app, ErrorGroupParams{Source: "server", Level: "error", Since: "1h", Limit: 1})
	if err != nil || len(result.Groups) != 1 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if result.Groups[0].LastRequestID != "abcdef0123456789" || !json.Valid(result.Groups[0].Sample) {
		t.Fatal("sample/correlation missing")
	}
	for _, bad := range []ErrorGroupParams{{Source: "injected'"}, {Level: "invalid"}, {Since: "yesterday"}, {GroupKey: "bad"}} {
		if _, err := listErrorGroups(t.Context(), app, bad); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
}

func TestErrorHealthAdminOnly(t *testing.T) {
	app := newGateApp(t)
	if err := ensureErrorGroups(app.DB); err != nil {
		t.Fatal(err)
	}
	if _, _, err := recordGroup(app, errorEvent{Source: "server", Kind: "test", Level: "error", Message: "health failure"}); err != nil {
		t.Fatal(err)
	}
	uid, sid := gateUser(t, app, "admin@test.example")
	if _, err := app.DB.Exec("UPDATE _benmore_users SET role='admin' WHERE id=?", uid); err != nil {
		t.Fatal(err)
	}
	for _, authenticated := range []bool{false, true} {
		r := httptest.NewRequest(http.MethodGet, "/health", nil)
		if authenticated {
			r.Header.Set("Authorization", "Bearer "+sid)
		}
		w := httptest.NewRecorder()
		healthHandler(app)(w, r)
		if strings.Contains(w.Body.String(), `"last_24h"`) != authenticated || strings.Contains(w.Body.String(), `"unresolved"`) != authenticated {
			t.Fatalf("admin=%v: %s", authenticated, w.Body.String())
		}
	}
}
