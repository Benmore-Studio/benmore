//go:build !cli

package main

import (
	"encoding/base32"
	"testing"
	"time"
)

// A TOTP code from an earlier time step must not be accepted again after a
// later code was used: replay protection must track the step, not only the
// last code string.
func TestAuditTOTPOlderStepNotReplayable(t *testing.T) {
	app, _ := auditApp(t)
	EnsureMFAColumns(app.DB)
	raw := []byte("synthetic-totp-seed2")
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	passwordChangeExec(t, app.DB, "INSERT INTO _benmore_users (username, email, password_hash, totp_secret) VALUES ('r', 'r@example.com', '', ?)", secret)
	var uid int64
	app.DB.QueryRow("SELECT id FROM _benmore_users WHERE email='r@example.com'").Scan(&uid)

	// Stay clear of a step boundary so all three checks share one step.
	if rem := 30 - time.Now().Unix()%30; rem < 5 {
		time.Sleep(time.Duration(rem+1) * time.Second)
	}
	step := uint64(time.Now().Unix() / 30)
	previous, current := computeHOTP(raw, step-1), computeHOTP(raw, step)
	if previous == current {
		t.Skip("adjacent steps produced the same code")
	}
	if !ValidateMFACode(app.DB, uid, previous) {
		t.Fatal("previous-step code rejected on first use")
	}
	if !ValidateMFACode(app.DB, uid, current) {
		t.Fatal("current-step code rejected on first use")
	}
	if ValidateMFACode(app.DB, uid, previous) {
		t.Fatal("previous-step code accepted a second time after a later code was used")
	}
}
