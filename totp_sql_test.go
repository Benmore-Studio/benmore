//go:build !cli

package main

// Tests for the benmore_totp_valid() SQL function (registered in
// encryption.go's ConnectHook).
//
// This is an authentication primitive reachable from app-authored SQL, so the
// cases that matter are the refusals: a wrong code, a `pending:` enrollment
// nobody has proven they hold, and empty input must never come back true.

import (
	"crypto/rand"
	"database/sql"
	"encoding/base32"
	"path/filepath"
	"testing"
)

// newTOTPSecret mirrors /api/_auth/mfa/setup: 20 random bytes, base32 with no
// padding.
func newTOTPSecret(t *testing.T) string {
	t.Helper()
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}

// totpTestDB opens a DB on the framework's own driver so the ConnectHook
// registrations (including benmore_totp_valid) are in place.
func totpTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3_benmore", filepath.Join(t.TempDir(), "totp_test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func totpValid(t *testing.T, db *sql.DB, secret, code string) bool {
	t.Helper()
	var ok bool
	if err := db.QueryRow("SELECT benmore_totp_valid(?, ?)", secret, code).Scan(&ok); err != nil {
		t.Fatalf("benmore_totp_valid(%q, %q): %v", secret, code, err)
	}
	return ok
}

// A freshly generated secret plus the code its own algorithm produces right
// now must validate - this is the happy path an admin step-up gate depends on.
func TestTOTPSQLAcceptsCurrentCode(t *testing.T) {
	db := totpTestDB(t)
	secret := newTOTPSecret(t)
	code := currentTOTPCode(t, secret)
	if !totpValid(t, db, secret, code) {
		t.Errorf("current code %q rejected for a valid secret", code)
	}
}

func TestTOTPSQLRejectsWrongCode(t *testing.T) {
	db := totpTestDB(t)
	secret := newTOTPSecret(t)
	current := currentTOTPCode(t, secret)
	wrong := "000000"
	if wrong == current {
		wrong = "111111"
	}
	if totpValid(t, db, secret, wrong) {
		t.Errorf("wrong code %q accepted", wrong)
	}
}

// An abandoned enrollment is not a factor. `pending:` secrets live in the same
// column as live ones, so a gate querying totp_secret directly would otherwise
// accept a code for a factor the user never finished proving they hold.
func TestTOTPSQLRejectsPendingEnrollment(t *testing.T) {
	db := totpTestDB(t)
	secret := newTOTPSecret(t)
	code := currentTOTPCode(t, secret)
	if totpValid(t, db, "pending:"+secret, code) {
		t.Error("a pending: enrollment secret must never validate")
	}
}

func TestTOTPSQLRejectsEmptyInput(t *testing.T) {
	db := totpTestDB(t)
	secret := newTOTPSecret(t)
	code := currentTOTPCode(t, secret)
	for _, tc := range []struct{ name, secret, code string }{
		{"no secret", "", code},
		{"no code", secret, ""},
		{"neither", "", ""},
		{"whitespace secret", "   ", code},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if totpValid(t, db, tc.secret, tc.code) {
				t.Error("empty input must not validate")
			}
		})
	}
}

// Garbage in the secret column (truncated, non-base32) must fail closed rather
// than error the whole statement - a gate's SQL should return "denied", not 500.
func TestTOTPSQLFailsClosedOnMalformedSecret(t *testing.T) {
	db := totpTestDB(t)
	for _, bad := range []string{"not-base32!!", "AAAA", "!!!!!!!!"} {
		if totpValid(t, db, bad, "123456") {
			t.Errorf("malformed secret %q validated", bad)
		}
	}
}

// The realistic shape: a gate joins the users table and never handles the
// secret itself. Proves the secret can stay inside the engine.
func TestTOTPSQLWorksAgainstAUsersTableWithoutExposingTheSecret(t *testing.T) {
	db := totpTestDB(t)
	db.Exec(`CREATE TABLE _benmore_users (id INTEGER PRIMARY KEY, totp_secret TEXT)`)
	live := newTOTPSecret(t)
	db.Exec(`INSERT INTO _benmore_users (id, totp_secret) VALUES (1, ?), (2, ?), (3, '')`,
		live, "pending:"+newTOTPSecret(t))

	code := currentTOTPCode(t, live)
	var enrolled int
	err := db.QueryRow(`
		SELECT COUNT(*) FROM _benmore_users
		WHERE id = ? AND benmore_totp_valid(totp_secret, ?)`, 1, code).Scan(&enrolled)
	if err != nil {
		t.Fatalf("gate query: %v", err)
	}
	if enrolled != 1 {
		t.Errorf("enrolled user should pass the gate, got %d", enrolled)
	}

	for _, id := range []int{2, 3} { // pending enrollment, and no secret at all
		var n int
		db.QueryRow(`SELECT COUNT(*) FROM _benmore_users
			WHERE id = ? AND benmore_totp_valid(totp_secret, ?)`, id, code).Scan(&n)
		if n != 0 {
			t.Errorf("user %d must not pass the gate", id)
		}
	}
}

// currentTOTPCode uses the framework's own generator so the test proves the
// SQL function agrees with ValidateTOTP, rather than with a second copy of the
// HOTP maths written here.
func currentTOTPCode(t *testing.T, secretB32 string) string {
	t.Helper()
	code := GenerateTOTP(secretB32)
	if !ValidateTOTP(secretB32, code) {
		t.Fatalf("GenerateTOTP produced %q which ValidateTOTP rejects", code)
	}
	return code
}
