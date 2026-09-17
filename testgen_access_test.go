//go:build !cli

package main

import "testing"

func TestCRUDReadExpectationMatchesPlainFrameworkUserAccess(t *testing.T) {
	cases := []struct {
		mode   string
		denied bool
	}{
		{"off", true},
		{"admin", true},
		{"role:manager", true},
		{"perm:reports.read", true},
		{"self", false},
		{"everyone", false},
		{"anon", false},
		{"group", false},
		{"member-of:members(project_id,user_id)", false},
		{"owner_or_role:manager", false},
	}
	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			app := &App{Access: &AccessConfig{rules: map[string]map[AccessOp]string{
				"records": {OpRead: tc.mode},
			}}}
			if got := crudReadClosed(app, "records"); got != tc.denied {
				t.Fatalf("crudReadClosed(%q) = %v, want %v", tc.mode, got, tc.denied)
			}
		})
	}
}

func TestGeneratedDocsTestsRespectAppOwnedDocsRoute(t *testing.T) {
	app := &App{Pages: map[string]*Page{"/docs": {Route: "/docs"}}}
	tests := generateDocsTests(app).Tests
	if _, ok := tests["api_docs_json"]; !ok {
		t.Fatal("JSON schema docs must always be tested")
	}
	if _, ok := tests["api_docs_html"]; ok {
		t.Fatal("framework HTML docs test must not shadow an app-owned /docs page")
	}
	if _, ok := tests["api_docs_markdown"]; ok {
		t.Fatal("framework Markdown docs test must not shadow an app-owned /docs page")
	}
}
