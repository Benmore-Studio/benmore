//go:build !cli

package main

import "testing"

// The sign-in code table is created once at startup with an index on its
// lookup key, and expired codes are removed by the periodic cleanup instead of
// staying forever.
func TestOTPTableIndexedAndExpiredCodesRemoved(t *testing.T) {
	app := recoveryHardeningApp(t)
	var idx int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_benmore_otp_email' AND tbl_name='_benmore_otp'").Scan(&idx); err != nil || idx != 1 {
		t.Fatalf("email index on _benmore_otp: %d (%v)", idx, err)
	}
	mustExec(t, app.DB, "INSERT INTO _benmore_otp (email, code, expires_at) VALUES ('old@example.com','111111',datetime('now','-1 minute')),('new@example.com','222222',datetime('now','+10 minutes'))")
	deleteExpiredOTPCodes(app.DB)
	var left string
	if err := app.DB.QueryRow("SELECT group_concat(email) FROM _benmore_otp").Scan(&left); err != nil || left != "new@example.com" {
		t.Fatalf("codes left after cleanup: %q (%v)", left, err)
	}
}
