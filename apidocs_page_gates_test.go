//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
)

// The page list in the generated docs holds the pages the page route would
// serve this caller. It used to match a page's role= against every role in
// the session, tenant roles included, while the route counts only roles held
// globally (and the built-in hierarchy): a member holding `manager` inside
// one tenant was shown a role="manager" page the route answers 403 for, and
// a manager was not shown a role="editor" page the route serves. A require=
// page was listed for every signed-in caller, and a sign-in page for a scoped
// credential, which no such page accepts.
func TestAPIDocsListThePagesTheRouteServes(t *testing.T) {
	app, mux := newDocsAudienceApp(t)
	if err := EnsureUsersTable(app.DB); err != nil {
		t.Fatal(err)
	}
	if err := EnsureUserRolesTable(app.DB); err != nil {
		t.Fatal(err)
	}
	app.Pages = map[string]*Page{
		"/":        {Route: "/", File: "index.html"},
		"/reports": {Route: "/reports", File: "reports.html", RawHTML: `<page role="manager"></page>`},
		"/drafts":  {Route: "/drafts", File: "drafts.html", RawHTML: `<page role="editor"></page>`},
		"/billing": {Route: "/billing", File: "billing.html", Require: "plan:pro"},
	}
	crudScopeMustExec(t, app.DB, `ALTER TABLE _benmore_users ADD COLUMN plan TEXT`)
	// A manager inside tenant org-a only, a global manager, and a plain user
	// on the pro plan.
	tenantManager := createCrudScopeSession(t, app, "tenant-manager@example.com", "user", "org-a", "")
	crudScopeMustExec(t, app.DB, `INSERT INTO _benmore_user_roles (user_id, role, group_id) SELECT id, 'manager', 'org-a' FROM _benmore_users WHERE email = 'tenant-manager@example.com'`)
	manager := createCrudScopeSession(t, app, "manager@example.com", "manager", "", "")
	pro := createCrudScopeSession(t, app, "pro@example.com", "user", "", "")
	crudScopeMustExec(t, app.DB, `UPDATE _benmore_users SET plan = 'pro' WHERE email = 'pro@example.com'`)
	// A scoped token of the global manager: pages are for browser sign-ins.
	EnsureAPITokensTable(app.DB)
	scoped := auditToken(t, app, manager, "posts:read")

	served := func(route, bearer string) bool {
		page := app.Pages[route]
		handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
		if page.Require != "" {
			handler = RequireMiddleware(app, page, handler)
		}
		if role := pageRole(page); role != "" && role != "public" {
			handler = RoleMiddleware(app, page, handler)
		}
		req := httptest.NewRequest(http.MethodGet, route, nil)
		req.Header.Set("Authorization", "Bearer "+bearer)
		rec := httptest.NewRecorder()
		scopedCredentialPageGate(app, page, handler)(rec, req)
		return rec.Code == http.StatusOK
	}
	listed := func(bearer string) map[string]bool {
		var doc struct {
			Pages []map[string]any `json:"pages"`
		}
		if err := json.Unmarshal([]byte(docsGet(t, mux, "/api/_docs", bearer)), &doc); err != nil {
			t.Fatal(err)
		}
		out := map[string]bool{}
		for _, p := range doc.Pages {
			out[p["route"].(string)] = true
		}
		return out
	}

	routes := make([]string, 0, len(app.Pages))
	for route := range app.Pages {
		routes = append(routes, route)
	}
	sort.Strings(routes)
	want := map[string]string{ // the routes each caller is served
		"tenant-manager": "/",
		"manager":        "/,/drafts,/reports",
		"pro":            "/,/billing",
		"scoped token":   "/",
	}
	for who, bearer := range map[string]string{"tenant-manager": tenantManager, "manager": manager, "pro": pro, "scoped token": scoped} {
		pages := listed(bearer)
		var servedRoutes []string
		for _, route := range routes {
			ok := served(route, bearer)
			if ok {
				servedRoutes = append(servedRoutes, route)
			}
			if pages[route] != ok {
				t.Errorf("%s: %s listed=%v, served=%v", who, route, pages[route], ok)
			}
		}
		if got := strings.Join(servedRoutes, ","); got != want[who] {
			t.Errorf("%s is served %s, want %s", who, got, want[who])
		}
		md := docsGet(t, mux, "/docs?format=md", bearer)
		for _, route := range routes {
			if strings.Contains(md, "- `"+route+"`") != served(route, bearer) {
				t.Errorf("%s: the markdown docs and the route disagree on %s", who, route)
			}
		}
	}
}
