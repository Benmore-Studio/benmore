//go:build !cli && !windows

package main

import (
	"context"
	"strings"
	"testing"
)

// A refresh during a writes-off window (every reload turns writes off until
// the owner re-enables them) issues read-only use for now but must not strip
// the write scopes the user consented to from the stored grant.
func TestAppMCPRefreshWhileWritesOffKeepsStoredWriteScopes(t *testing.T) {
	f := newCanonicalUpdateFixture(t, "", "", "")
	writeScopes := f.pair.Scopes
	if strings.Contains(writeScopes, "notes:read") || writeScopes == "" {
		t.Fatalf("fixture grant scopes: %q", writeScopes)
	}
	if _, err := f.app.DB.Exec("UPDATE main._benmore_mcp_grants SET scopes=? WHERE id=?", "notes:read "+writeScopes, f.pair.GrantID); err != nil {
		t.Fatal(err)
	}
	if _, err := setAppMCPApprovedWrites(f.app.Dir, false); err != nil {
		t.Fatal(err)
	}
	offPair, err := refreshAppMCPGrantFor(context.Background(), f.app, f.pair.RefreshToken, "native-fixture", grantFixtureResource, "", f.now)
	if err != nil {
		t.Fatalf("refresh while writes off: %v", err)
	}
	if offPair.Scopes != "notes:read" {
		t.Fatalf("writes-off refresh reported scopes %q, want notes:read", offPair.Scopes)
	}
	var stored string
	if err := f.app.DB.QueryRow("SELECT scopes FROM main._benmore_mcp_grants WHERE id=?", f.pair.GrantID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	for _, scope := range strings.Fields(writeScopes) {
		if !strings.Contains(" "+stored+" ", " "+scope+" ") {
			t.Fatalf("writes-off refresh stripped %q from the stored grant: %q", scope, stored)
		}
	}
	if _, err := enableAppMCPRevisionEnrolledWrites(context.Background(), f.app, snapshotAppMCPGeneration(f.app)); err != nil {
		t.Fatal(err)
	}
	// A native table.update permission is never a live command scope, so
	// before the fix even a writes-on refresh stripped it; the stored grant
	// must keep it across further refreshes.
	if _, err := refreshAppMCPGrantFor(context.Background(), f.app, offPair.RefreshToken, "native-fixture", grantFixtureResource, "", f.now); err != nil {
		t.Fatalf("refresh after writes back on: %v", err)
	}
	if err := f.app.DB.QueryRow("SELECT scopes FROM main._benmore_mcp_grants WHERE id=?", f.pair.GrantID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	for _, scope := range strings.Fields(writeScopes) {
		if !strings.Contains(" "+stored+" ", " "+scope+" ") {
			t.Fatalf("writes-on refresh stripped %q from the stored grant: %q", scope, stored)
		}
	}
}
