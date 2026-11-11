//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
)

// A body field that is no column (a typo) is named in X-Ignored-Fields on
// create and update; the write still succeeds as before.
func TestCRUDNamesIgnoredFields(t *testing.T) {
	app, _ := auditApp(t)
	sid := createCrudScopeSession(t, app, "typo@example.com", "user", "", "")
	mux := http.NewServeMux()
	RegisterCRUD(mux, app)
	w := crudScopeRequest(t, mux, http.MethodPost, "/api/notes", sid, map[string]any{"title": "kept", "titel": "typo", "_expected_updated_at": ""})
	if w.Code != http.StatusOK {
		t.Fatalf("create %d %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get(ignoredFieldsHeader); got != "titel" {
		t.Fatalf("create X-Ignored-Fields = %q", got)
	}
	var created map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	id := created["id"]
	w = crudScopeRequest(t, mux, http.MethodPatch, "/api/notes/"+fmt.Sprint(id), sid, map[string]any{"title": "renamed", "tilte": "typo", "qty": 2})
	if w.Code != http.StatusOK {
		t.Fatalf("update %d %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get(ignoredFieldsHeader); got != "qty,tilte" {
		t.Fatalf("update X-Ignored-Fields = %q", got)
	}
	w = crudScopeRequest(t, mux, http.MethodPatch, "/api/notes/"+fmt.Sprint(id), sid, map[string]any{"title": "clean"})
	if got := w.Header().Get(ignoredFieldsHeader); got != "" {
		t.Fatalf("clean update named %q", got)
	}
}

// A list filter on a column the table does not have is named in
// X-Ignored-Params instead of silently answering every row.
func TestListNamesIgnoredParams(t *testing.T) {
	app, _ := auditApp(t)
	sid := createCrudScopeSession(t, app, "filter@example.com", "user", "", "")
	mux := http.NewServeMux()
	RegisterCRUD(mux, app)
	for _, title := range []string{"a", "b"} {
		if w := crudScopeRequest(t, mux, http.MethodPost, "/api/notes", sid, map[string]any{"title": title}); w.Code != http.StatusOK {
			t.Fatalf("seed %d %s", w.Code, w.Body.String())
		}
	}
	w := crudScopeRequest(t, mux, http.MethodGet, "/api/notes?titel=a&title__bogus=x&title=a&page=1&_=123", sid, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list %d %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get(ignoredParamsHeader); got != "titel,title__bogus" {
		t.Fatalf("X-Ignored-Params = %q", got)
	}
	w = crudScopeRequest(t, mux, http.MethodGet, "/api/notes?title__in=a,b&per_page=10", sid, nil)
	if got := w.Header().Get(ignoredParamsHeader); got != "" {
		t.Fatalf("applied filters named as ignored: %q", got)
	}
}
