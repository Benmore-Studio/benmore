//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func pageRouteGraphMetadata(app *App) (map[string]map[string]any, error) {
	tx, err := app.DB.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	extractPages(tx, app, nil)
	rows, err := tx.Query("SELECT ref, metadata FROM _benmore_context_nodes WHERE node_type = 'page'")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]map[string]any{}
	for rows.Next() {
		var ref, raw string
		if err := rows.Scan(&ref, &raw); err != nil {
			return nil, err
		}
		var meta map[string]any
		if err := json.Unmarshal([]byte(raw), &meta); err != nil {
			return nil, err
		}
		out[ref] = meta
	}
	return out, rows.Err()
}

func TestPageRouteRegistrationPreservesGraphSource(t *testing.T) {
	app := ssrTestApp(t)
	ssrLoadPages(t, app, map[string]string{
		"frontmatter.html": "---\nauth: required\nrequire: plan:pro\nlayout: none\n---\nfrontmatter-body",
	})
	// Sources constructed outside LoadPages still get the historical route
	// defaults. Graph extraction must report those same gates before or after
	// registration, without changing the source shared by other consumers.
	app.Pages["/fallback"] = &Page{Route: "/fallback", File: "fallback.html", Auth: " YES ", Layout: "none",
		RawHTML: `<page require="plan:pro">fallback-body</page>`}
	_, _, single := ParseSingleFile(`<page route="/single" auth="true">single-body</page>`)
	app.Pages["/single"] = single["/single"]
	EnsureRequiredUserFields(app.DB, app.Pages)
	if app.Pages["/single"].Auth != "required" {
		t.Error("single-file auth was not normalized before publishing its page")
	}
	before := map[string]Page{}
	for route, page := range app.Pages {
		before[route] = *page
	}
	EnsureContextGraphTables(app.DB)
	assertGraph := func() {
		t.Helper()
		metadata, err := pageRouteGraphMetadata(app)
		if err != nil {
			t.Fatal(err)
		}
		if len(metadata) != 3 {
			t.Fatalf("graph has %d pages, want 3", len(metadata))
		}
		for _, route := range []string{"/frontmatter", "/fallback", "/single"} {
			wantRequire := "plan:pro"
			if route == "/single" {
				wantRequire = ""
			}
			meta := metadata["page:"+route]
			if meta["auth"] != "required" || meta["require"] != wantRequire {
				t.Errorf("%s graph gates: auth=%v require=%v, want required/%q", route, meta["auth"], meta["require"], wantRequire)
			}
		}
	}
	assertGraph()
	mux := http.NewServeMux()
	if got := registerAppPageRoutes(mux, app, false); len(got) != 3 {
		t.Fatalf("registered %d routes, want 3", len(got))
	}
	assertGraph()
	for route, page := range app.Pages {
		if *page != before[route] {
			t.Errorf("registration mutated published page %s", route)
		}
	}
	free := createCrudScopeSession(t, app, "free@example.test", "user", "", "")
	pro := createCrudScopeSession(t, app, "pro@example.test", "user", "", "")
	crudScopeMustExec(t, app.DB, `UPDATE _benmore_users SET plan = 'pro' WHERE email = 'pro@example.test'`)
	for _, route := range []string{"/frontmatter", "/fallback", "/single"} {
		if rec := ssrGet(mux, route, ""); rec.Code != http.StatusSeeOther {
			t.Errorf("anonymous %s: status %d, want sign-in redirect", route, rec.Code)
		}
		if route != "/single" {
			if rec := ssrGet(mux, route, free); rec.Code != http.StatusForbidden {
				t.Errorf("free user %s: status %d, want 403", route, rec.Code)
			}
		}
		if rec := ssrGet(mux, route, pro); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), strings.TrimPrefix(route, "/")+"-body") {
			t.Errorf("pro user %s: status %d, want the page body", route, rec.Code)
		}
	}
}

func TestPageRouteRegistrationConcurrentGraphExtraction(t *testing.T) {
	app := ssrTestApp(t)
	ssrLoadPages(t, app, map[string]string{
		"public.html": `<page auth="none">public-body</page>`,
		"gated.html":  "---\nauth: required\nrequire: plan:pro\n---\ngated-body",
	})
	EnsureContextGraphTables(app.DB)
	start := make(chan struct{})
	results := make(chan error, 2)
	go func() {
		<-start
		for range 32 {
			if got := registerAppPageRoutes(http.NewServeMux(), app, false); len(got) != 2 {
				results <- fmt.Errorf("registered %d routes, want 2", len(got))
				return
			}
		}
		results <- nil
	}()
	go func() {
		<-start
		for range 12 {
			metadata, err := pageRouteGraphMetadata(app)
			if err != nil {
				results <- err
				return
			}
			if len(metadata) != 2 || metadata["page:/gated"]["require"] != "plan:pro" || metadata["page:/public"]["auth"] != "none" {
				results <- fmt.Errorf("graph did not preserve both pages and gates")
				return
			}
		}
		results <- nil
	}()
	close(start)
	for range 2 {
		if err := <-results; err != nil {
			t.Error(err)
		}
	}
}
