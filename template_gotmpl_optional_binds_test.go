//go:build !cli

package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func gotmplRowIDs(rows []map[string]any) string {
	ids := make([]string, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, fmt.Sprint(row["id"]))
	}
	return strings.Join(ids, ",")
}

// An optional URL filter, `(:param_name IS NULL OR name = :param_name)`, binds
// NULL when the page is opened without ?name= or with an empty one, so the
// page lists every row it would otherwise show. It used to stay unbound and
// the query failed ("not enough args to execute query: want 2 got 1"), which
// pages answer with a 500 since failed page queries became visible (#829).
// A name the framework does not bind still fails the query.
func TestGotmplParamBindWithoutValueIsNull(t *testing.T) {
	app, mux := legacyQueryFixture(t, map[string]string{
		"report-filter.html": legacyQueryPage("auth: required\n",
			"SELECT id, name FROM projects WHERE company_id = :user_group_id AND (:param_name IS NULL OR name = :param_name) ORDER BY id"),
		"unknown-bind.html": legacyQueryPage("auth: required\n",
			"SELECT id FROM projects WHERE company_id = :user_group_id AND name = :totally_made_up"),
	})
	crudScopeMustExec(t, app.DB, "INSERT INTO projects (id, company_id, name) VALUES (3, 1, 'acme-q')")
	member, _ := tenantMember(t, app, "member@example.com", "user", 1, "viewer")

	for _, tc := range []struct{ path, want string }{
		{"/report-filter", "1,3"},
		{"/report-filter?name=", "1,3"},
		{"/report-filter?name=acme-q", "3"},
		{"/report-filter?name=globex-p", ""},
		{"/report-filter?other=x", "1,3"},
	} {
		if got := gotmplRowIDs(legacyQueryRows(t, mux, tc.path, member)); got != tc.want {
			t.Fatalf("%s: rows %q, want %q", tc.path, got, tc.want)
		}
	}

	w := ssrGet(mux, "/unknown-bind", member)
	if w.Code != http.StatusInternalServerError || w.Header().Get(requestIDHeader) == "" {
		t.Fatalf("an unknown bind must still fail the page: %d %s", w.Code, w.Body.String())
	}
}

// A name the page's route declares (`:company` for /projects/:company) binds
// that path value, and NULL when the render has none (an empty segment, or a
// render outside the page's own route such as /pdf/...). A name that is
// neither a framework bind nor a route parameter stays unbound.
func TestGotmplPathValueBindWithoutValueIsNull(t *testing.T) {
	// The page is set before the mux is built: the context graph rebuild a
	// mux starts reads app.Pages.
	app := legacyQueryApp(t, nil)
	const route = "/projects/:company"
	source := legacyQueryPage("", "SELECT id FROM projects WHERE (:company IS NULL OR company_id = :company) ORDER BY id")
	page := &Page{Route: route, File: "projects.html"}
	setPageAttrsFromSource(page, source)
	app.Pages = map[string]*Page{route: page}
	mux := buildAppMux(app, false, legacyQueryBaseURL)

	// Opened through its own route, the path value binds.
	if got := gotmplRowIDs(legacyQueryRows(t, mux, "/projects/2", "")); got != "2" {
		t.Fatalf("/projects/2: rows %q", got)
	}

	sqlText := "SELECT id FROM projects WHERE (:company IS NULL OR company_id = :company) ORDER BY id"
	render := func(r *http.Request) string {
		t.Helper()
		ctx := &RenderContext{Data: map[string]any{}, Request: r, App: app, Page: page}
		rows, err := runFrontmatterQuery(app, page, ctx, sqlText)
		if err != nil {
			t.Fatalf("path value query: %v", err)
		}
		return gotmplRowIDs(rows)
	}
	absent := httptest.NewRequest(http.MethodGet, "/pdf/projects/:company", nil)
	if got := render(absent); got != "1,2" {
		t.Fatalf("absent path value: rows %q, want every row", got)
	}
	empty := httptest.NewRequest(http.MethodGet, "/projects/", nil)
	empty.SetPathValue("company", "")
	if got := render(empty); got != "1,2" {
		t.Fatalf("empty path value: rows %q, want every row", got)
	}
	set := httptest.NewRequest(http.MethodGet, "/projects/1", nil)
	set.SetPathValue("company", "1")
	if got := render(set); got != "1" {
		t.Fatalf("path value 1: rows %q", got)
	}

	ctx := &RenderContext{Request: absent, Page: page}
	if v, ok := resolveBind(ctx, "company"); !ok || v != nil {
		t.Fatalf("route parameter without a value: %v %v", v, ok)
	}
	if v, ok := resolveBind(ctx, "param_company"); !ok || v != nil {
		t.Fatalf("param_ without a value: %v %v", v, ok)
	}
	if _, ok := resolveBind(ctx, "slug"); ok {
		t.Fatal("a name the route does not declare resolved")
	}
	if _, ok := resolveBind(&RenderContext{Request: absent}, "company"); ok {
		t.Fatal("a route parameter resolved without the page")
	}
	// A query that fails on an unbound name says which name it is.
	_, err := runFrontmatterQuery(app, page, &RenderContext{Data: map[string]any{}, Request: absent, App: app, Page: page},
		"SELECT id FROM projects WHERE company_id = :company AND name = :slug")
	if err == nil || !strings.Contains(err.Error(), ":slug") || strings.Contains(err.Error(), ":company") {
		t.Fatalf("unbound name not named in the error: %v", err)
	}
}

// A page whose render fails (a page query here) answers a signed-in app admin
// on a full-access credential with the error text and the request id, as a
// failed flow does; on hosted dev instances, which run in production mode,
// that was only in the request log. Anonymous visitors, ordinary users and an
// admin's scoped token still get only the request id.
func TestPageRenderErrorShowsDetailOnlyToAppAdmin(t *testing.T) {
	const marker = "partial-render-marker"
	bad := "---\nengine: gotmpl\nqueries:\n  rows: SELECT nope FROM projects\n---\n<h1>" + marker + "</h1>"
	// A template error can quote authored text; the admin answer is the
	// request log's form of it, with credential-shaped text redacted.
	failing := "---\nengine: gotmpl\n---\n<h1>" + marker + "</h1>{{ fail \"upstream refused password=hunter2\" }}"
	app, mux := legacyQueryFixture(t, map[string]string{"bad.html": bad, "fail.html": failing})
	member, _ := tenantMember(t, app, "member@example.com", "user", 1, "viewer")
	admin := createCrudScopeSession(t, app, "boss@example.com", "admin", "", "")
	scopedAdmin := createCrudScopeSession(t, app, "scoped@example.com", "admin", "", "")
	crudScopeMustExec(t, app.DB, "UPDATE _benmore_sessions SET scopes = 'projects:read' WHERE id = '"+sessionStorageKey(scopedAdmin)+"'")

	for _, tc := range []struct {
		who, token string
		detail     bool
	}{
		{"anonymous", "", false},
		{"member", member, false},
		{"scoped admin token", scopedAdmin, false},
		{"admin", admin, true},
	} {
		w := ssrGet(mux, "/bad", tc.token)
		body := w.Body.String()
		id := w.Header().Get(requestIDHeader)
		if w.Code != http.StatusInternalServerError || !requestIDPattern.MatchString(id) || !strings.Contains(body, "(request id: "+id+")") {
			t.Fatalf("%s: %d id %q: %s", tc.who, w.Code, id, body)
		}
		if strings.Contains(body, marker) {
			t.Fatalf("%s: the failed page rendered: %s", tc.who, body)
		}
		if tc.detail {
			if !strings.Contains(body, `query "rows"`) || !strings.Contains(body, "no such column: nope") {
				t.Fatalf("%s must see the query error: %s", tc.who, body)
			}
			if cc := w.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
				t.Fatalf("%s: detailed error answer is cacheable: %q", tc.who, cc)
			}
			if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
				t.Fatalf("%s: detailed error answer Content-Type %q", tc.who, ct)
			}
			continue
		}
		for _, secret := range []string{"nope", "no such column", "SELECT", "projects"} {
			if strings.Contains(body, secret) {
				t.Fatalf("%s: production answer disclosed %q: %s", tc.who, secret, body)
			}
		}
		if body != "Internal Server Error (request id: "+id+")\n" {
			t.Fatalf("%s: answer changed shape: %q", tc.who, body)
		}
		if w := ssrGet(mux, "/fail", tc.token); w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "upstream refused") {
			t.Fatalf("%s: template error disclosed: %d %s", tc.who, w.Code, w.Body.String())
		}
	}

	w := ssrGet(mux, "/fail", admin)
	if body := w.Body.String(); w.Code != http.StatusInternalServerError || !strings.Contains(body, "upstream refused password=[redacted]") || strings.Contains(body, "hunter2") {
		t.Fatalf("admin template error answer: %d %s", w.Code, body)
	}
}
