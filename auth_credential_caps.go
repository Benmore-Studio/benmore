//go:build !cli

package main

import (
	"database/sql"
	"log"
)

// Per-account ceilings on credentials an account can mint for itself. Each
// row is small, but nothing else bounded how many one signed-in account (or
// anyone holding its password) could create, and the tables live in the
// app's own database: a loop filled the app's storage, every other user's
// writes then failed, and the token list and every revocation scanned the
// pile. The numbers sit far above any use a person or an integration makes.
const (
	// maxAPITokensPerUser caps an account's live API tokens: the ones it
	// creates (bmr_) and the ones an OAuth client is issued for it (bma_),
	// expired rows not counted. At the cap a new token is refused until one
	// is revoked or expires.
	maxAPITokensPerUser = 100
	// maxTokenSessionsPerUser caps an account's live sessions from the
	// password-for-Bearer exchange (POST /api/_auth/token). A client that
	// signs in again instead of keeping its token leaves a session behind
	// each time, so the exchange is never refused: the oldest ones beyond
	// the cap are ended instead.
	maxTokenSessionsPerUser = 200
)

// apiTokenExecer is the INSERT side of *sql.DB and *sql.Tx.
type apiTokenExecer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

// insertAPITokenWithinCap stores a new API token unless the account already
// holds maxAPITokensPerUser live ones. The count and the insert are one
// statement, so concurrent mints cannot both take the last place. It reports
// false, with no error, when the account is at the cap.
func insertAPITokenWithinCap(db apiTokenExecer, userID int64, name, tokenHash, scopes string, expiresAt any) (bool, error) {
	res, err := db.Exec(
		`INSERT INTO _benmore_api_tokens (user_id, name, token_hash, scopes, expires_at)
		SELECT ?, ?, ?, ?, ?
		WHERE (SELECT COUNT(*) FROM _benmore_api_tokens WHERE user_id = ?
			AND (expires_at IS NULL OR datetime(expires_at) > datetime('now'))) < ?`,
		userID, name, tokenHash, scopes, expiresAt, userID, maxAPITokensPerUser,
	)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

const apiTokenCapMessage = "this account already has the maximum number of API tokens (100): revoke one you no longer use (DELETE /api/_auth/api-tokens/{id}) and try again"

// tokenExchangeSessionsSQL selects one account's sessions that came from the
// Bearer token exchange (first argument: the user id): not a person's
// interactive sign-in (login_at, set by createSignInSession), not a support
// or delegated row, not a dashboard embed. Rows from before login_at existed
// match too; they are the oldest an account has and age out with it.
const tokenExchangeSessionsSQL = "user_id = ? AND COALESCE(login_at, 0) = 0 AND COALESCE(is_impersonation, 0) = 0 AND COALESCE(scopes, '') <> 'embed'"

// trimTokenExchangeSessions ends the account's oldest token-exchange sessions
// beyond the newest maxTokenSessionsPerUser. Called after each exchange, so
// the one just minted always survives.
func trimTokenExchangeSessions(db *sql.DB, userID int64) {
	res, err := db.Exec(
		`DELETE FROM _benmore_sessions WHERE `+tokenExchangeSessionsSQL+`
		AND id NOT IN (SELECT id FROM _benmore_sessions WHERE `+tokenExchangeSessionsSQL+`
			ORDER BY datetime(created_at) DESC, rowid DESC LIMIT ?)`,
		userID, userID, maxTokenSessionsPerUser,
	)
	if err != nil {
		log.Printf("auth: trimming token-exchange sessions of user %d: %v", userID, err)
		return
	}
	if n, _ := res.RowsAffected(); n > 0 {
		log.Printf("auth: ended %d oldest token-exchange session(s) of user %d (more than %d live)", n, userID, maxTokenSessionsPerUser)
	}
}
