package main

import "testing"

// A role holding x:read and x:write must not make a consented `x:write` grant
// carry an extra, unadvertised `x:read` (which the approve step refused).
func TestAppMCPRequestedScopeTokensDropsImpliedScopes(t *testing.T) {
	grant := "app:read leads:write"
	role := "app:read leads:read leads:write tasks:write"
	got := appMCPRequestedScopeTokens(intersectScopes(grant, role), grant)
	if got != "app:read leads:write" {
		t.Fatalf("actor scopes = %q", got)
	}
	if !hasScope(&Session{Scopes: got}, "leads", "read") {
		t.Fatal("write must still imply read at check time")
	}
	if got := appMCPRequestedScopeTokens(intersectScopes("leads:write", "leads:read"), "leads:write"); got != "_none_:read" {
		t.Fatalf("a role with only read must not hold the write grant: %q", got)
	}
}
