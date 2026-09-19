//go:build !cli

package main

import "testing"

// TestDiscoverAuthPaths_DeterministicOnDuplicateType covers the case where
// two pages (e.g. cli-auth.html and login.html) both declared
// type="login", and the unordered map range made app.Paths.Login
// resolve to /login on one boot and /cli-auth on another - so
// POST /login 404'd nondeterministically. The conventional /login
// route must always win, and the result must be identical every run.
func TestDiscoverAuthPaths_DeterministicOnDuplicateType(t *testing.T) {
	pages := map[string]*Page{
		"/login":    {Route: "/login", Type: "login"},
		"/cli-auth": {Route: "/cli-auth", Type: "login"}, // mislabeled duplicate
		"/signup":   {Route: "/signup", Type: "signup"},
	}
	// Run many times - map iteration order varies between ranges, so a
	// nondeterministic implementation would eventually disagree.
	for i := 0; i < 200; i++ {
		p := DiscoverAuthPaths(pages)
		if p.Login != "/login" {
			t.Fatalf("iter %d: Login = %q, want /login (conventional route must win over /cli-auth)", i, p.Login)
		}
		if p.Signup != "/signup" {
			t.Fatalf("iter %d: Signup = %q, want /signup", i, p.Signup)
		}
	}
}

// TestDiscoverAuthPaths_NonDefaultStable verifies that when NO page sits
// at the conventional route, the choice is still stable (sorted-first)
// rather than map-order-dependent.
func TestDiscoverAuthPaths_NonDefaultStable(t *testing.T) {
	pages := map[string]*Page{
		"/sign-in": {Route: "/sign-in", Type: "login"},
		"/enter":   {Route: "/enter", Type: "login"},
	}
	want := "" // first run establishes the baseline
	for i := 0; i < 200; i++ {
		got := DiscoverAuthPaths(pages).Login
		if i == 0 {
			want = got
			if got != "/enter" { // lexicographically first
				t.Fatalf("expected sorted-first /enter, got %q", got)
			}
		} else if got != want {
			t.Fatalf("iter %d: Login = %q, want stable %q", i, got, want)
		}
	}
}

// TestDiscoverAuthPaths_DefaultsWhenNoPages confirms the documented
// fallbacks survive the rewrite.
func TestDiscoverAuthPaths_DefaultsWhenNoPages(t *testing.T) {
	p := DiscoverAuthPaths(map[string]*Page{})
	if p.Login != "/login" || p.Signup != "/signup" || p.Logout != "/logout" {
		t.Fatalf("defaults wrong: %+v", p)
	}
}
