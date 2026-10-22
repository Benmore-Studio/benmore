//go:build !cli

package main

// Account and source-IP login attempt tracking and lockout policy.

import (
	"database/sql"
	"hash/fnv"
	"log"
	"strings"
	"sync"
	"time"
)

// EnsureLoginAttemptsTable creates the login attempts tracking table.
func EnsureLoginAttemptsTable(db *sql.DB) {
	db.Exec(`CREATE TABLE IF NOT EXISTS _benmore_login_attempts (
		email TEXT NOT NULL,
		attempted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		success BOOLEAN DEFAULT 0
	)`)
	db.Exec("CREATE INDEX IF NOT EXISTS idx_login_attempts_email ON _benmore_login_attempts(email, attempted_at)")
	// The age sweep filters on attempted_at alone, which the (email, ...)
	// index can't serve.
	db.Exec("CREATE INDEX IF NOT EXISTS idx_login_attempts_time ON _benmore_login_attempts(attempted_at)")
}

// loginAttemptSweeps records when each database last dropped old attempts.
// The sweep only bounds the table's size (every lockout query has its own
// 15-minute window), so running it once a minute instead of on every
// attempt changes no decision.
var loginAttemptSweeps sync.Map // *sql.DB -> time.Time

const loginAttemptSweepEvery = time.Minute

func sweepLoginAttempts(db *sql.DB) {
	now := time.Now()
	if last, ok := loginAttemptSweeps.Load(db); ok && now.Sub(last.(time.Time)) < loginAttemptSweepEvery {
		return
	}
	loginAttemptSweeps.Store(db, now)
	db.Exec("DELETE FROM _benmore_login_attempts WHERE attempted_at < datetime('now', '-1 hour')")
}

// normalizeEmail lower-cases + trims an email-shaped identifier so
// `A@example.com` and `a@example.com` are the same account everywhere -
// store, lookup, and lockout key (2026-06-11 audit: case variation allowed
// duplicate accounts and lockout-counter evasion).
func normalizeEmail(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// recordLoginAttempt logs a login attempt. The key is normalized so an
// attacker can't dodge the lockout counter by case-varying the email.
func recordLoginAttempt(db *sql.DB, email string, success bool) {
	if _, err := db.Exec("INSERT INTO _benmore_login_attempts (email, success) VALUES (?, ?)", normalizeEmail(email), success); err != nil {
		log.Printf("ERROR recording login attempt: %s", err)
	}
	sweepLoginAttempts(db)
}

// isAccountLocked checks if an account has too many failed attempts since last success (within 15 min window).
// Only counts failures AFTER the most recent successful login, so a successful login resets the counter.
func isAccountLocked(db *sql.DB, email string) bool {
	email = normalizeEmail(email)
	var count int
	db.QueryRow(
		`SELECT COUNT(*) FROM _benmore_login_attempts
		 WHERE email = ? AND success = 0
		 AND attempted_at > COALESCE(
			(SELECT MAX(attempted_at) FROM _benmore_login_attempts WHERE email = ? AND success = 1),
			'1970-01-01'
		 )
		 AND attempted_at > datetime('now', '-15 minutes')`,
		email, email,
	).Scan(&count)
	return count >= 5
}

// authIPLockKey namespaces a client IP into the shared
// _benmore_login_attempts table so per-IP throttling reuses the same
// rolling-window machinery as the per-account lockout without a second
// table. The "ip:" prefix can never collide with a normalized email
// (emails always contain "@" and never a leading "ip:"). An IPv6 client is
// counted by its /64 (clientRateBucket), like the rate limits: one subscriber
// is routinely handed a whole /64, and keying on the full address let a spray
// take a fresh address for every guess and never reach the cap.
func authIPLockKey(ip string) string {
	return "ip:" + strings.ToLower(clientRateBucket(strings.TrimSpace(ip)))
}

// authIsIPLocked reports whether a single source IP has accumulated too
// many failed login attempts in the rolling 15-minute window. This sits
// ALONGSIDE the per-account lockout (isAccountLocked): the account lock
// stops a focused attack on one victim, while this per-IP cap blunts a
// spray attack that rotates the username to dodge the per-account
// counter. The IP threshold is deliberately higher than the per-account
// one so shared-NAT / office-egress users aren't locked out by a few
// unrelated typos. Empty/unknown IPs are never locked (fail open - we
// must not wedge a whole deployment on a missing RemoteAddr).
func authIsIPLocked(db *sql.DB, ip string) bool {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return false
	}
	key := authIPLockKey(ip)
	var count int
	db.QueryRow(
		`SELECT COUNT(*) FROM _benmore_login_attempts
		 WHERE email = ? AND success = 0
		 AND attempted_at > datetime('now', '-15 minutes')`,
		key,
	).Scan(&count)
	return count >= authIPLoginLimit
}

// authIPLoginLimit is the per-IP failed-login ceiling in the 15-minute
// window. Higher than the per-account limit (5) so shared egress IPs
// tolerate a handful of unrelated bad logins before throttling.
const authIPLoginLimit = 25

// attemptLocks serializes credential checks per account key. The lockout
// is check → verify → record; without serialization a burst of parallel
// guesses all passed the check before any failure was recorded and got far
// more than the allowed tries (password, TOTP, change-password). A fixed set
// of striped locks bounds memory no matter how many keys are sprayed.
var attemptLocks [256]sync.Mutex

// lockAttempt blocks until no other check for key is in flight in this
// process and returns the unlock func. Use: defer lockAttempt(key)().
func lockAttempt(key string) func() {
	h := fnv.New32a()
	h.Write([]byte(normalizeEmail(key)))
	m := &attemptLocks[h.Sum32()%uint32(len(attemptLocks))]
	m.Lock()
	return m.Unlock
}
