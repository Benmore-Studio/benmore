//go:build !cli

package main

import (
	"testing"
	"time"
)

func TestSignedInPasswordWriteRechecksAuthority(t *testing.T) {
	for _, change := range []string{
		"UPDATE _benmore_users SET password_hash='concurrent-change'",
		"UPDATE _benmore_users SET password_change_required=1",
		"UPDATE _benmore_users SET deactivated_at=datetime('now')",
		"DELETE FROM _benmore_sessions",
		"UPDATE _benmore_sessions SET expires_at=datetime('now','-1 second')",
		"UPDATE _benmore_sessions SET scopes='notes:read'",
		"UPDATE _benmore_sessions SET is_impersonation=1",
		"UPDATE _benmore_sessions SET acting_as_group='another-tenant'",
	} {
		t.Run(change, func(t *testing.T) {
			app := recoveryHardeningApp(t)
			uid := recoveryUser(t, app, "proof@example.com", "Before!Password123", 1)
			session := GetSessionFromDB(app.DB, CreateSession(app.DB, uid, "proof@example.com", "", time.Hour))
			proof, locked := currentPasswordProof(app, uid, "Before!Password123")
			if proof == "" || locked {
				t.Fatal("fixture proof failed")
			}
			mustExec(t, app.DB, change)
			var before string
			if err := app.DB.QueryRow("SELECT password_hash FROM _benmore_users WHERE id=?", uid).Scan(&before); err != nil {
				t.Fatal(err)
			}
			if _, err := changeSignedInPassword(app, session, proof, "must-not-be-written"); err == nil {
				t.Fatal("stale authority accepted")
			}
			var after string
			if err := app.DB.QueryRow("SELECT password_hash FROM _benmore_users WHERE id=?", uid).Scan(&after); err != nil {
				t.Fatal(err)
			}
			if after != before {
				t.Fatal("refused change modified credentials")
			}
		})
	}
}
