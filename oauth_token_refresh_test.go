//go:build !cli

package main

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func oauthTokenStoreFixture(t *testing.T) *sql.DB {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	oldKey := appEncryptionKey
	appEncryptionKey = []byte("0123456789abcdef0123456789abcdef")
	t.Cleanup(func() { appEncryptionKey = oldKey })
	if err := EnsureUsersTable(db); err != nil {
		t.Fatal(err)
	}
	EnsureOAuthTokensTable(db)
	mustExec(t, db, `INSERT INTO _benmore_users (id, username, email, verified) VALUES (1, 'alice', 'alice@example.com', 1)`)
	return db
}

// storedOAuthToken returns the decrypted access and refresh token and the
// stored expiry of one connection.
func storedOAuthToken(t *testing.T, db *sql.DB, provider string) (access, refresh, expires string) {
	t.Helper()
	var rawAccess string
	var rawRefresh, rawExpires sql.NullString
	if err := db.QueryRow(`SELECT access_token, refresh_token, expires_at FROM _benmore_oauth_tokens WHERE user_id = 1 AND provider = ?`, provider).Scan(&rawAccess, &rawRefresh, &rawExpires); err != nil {
		t.Fatal(err)
	}
	access, err := fieldDecryptForDB(db, rawAccess)
	if err != nil {
		t.Fatal(err)
	}
	if rawRefresh.String != "" {
		if refresh, err = fieldDecryptForDB(db, rawRefresh.String); err != nil {
			t.Fatal(err)
		}
	}
	return access, refresh, rawExpires.String
}

// A provider returns a refresh token on the first consent and, as a rule,
// none on later sign-ins. Each later sign-in stored the encryption of the
// empty string over the refresh token the account had, so the connection
// could never be refreshed again.
func TestStoreOAuthTokenKeepsTheRefreshTokenWhenNoneIsReturned(t *testing.T) {
	db := oauthTokenStoreFixture(t)
	StoreOAuthToken(db, 1, "google", "access-1", "refresh-1", "Bearer", 3600, "email")
	StoreOAuthToken(db, 1, "google", "access-2", "", "Bearer", 3600, "email")
	if access, refresh, _ := storedOAuthToken(t, db, "google"); access != "access-2" || refresh != "refresh-1" {
		t.Fatalf("after a sign-in that returned no refresh token: access %q, refresh %q; want access-2 and the stored refresh-1", access, refresh)
	}
	// A provider that does send one replaces it.
	StoreOAuthToken(db, 1, "google", "access-3", "refresh-3", "Bearer", 3600, "email")
	if access, refresh, _ := storedOAuthToken(t, db, "google"); access != "access-3" || refresh != "refresh-3" {
		t.Fatalf("after a sign-in with a new refresh token: access %q, refresh %q", access, refresh)
	}
	// A first connection without one stores none.
	StoreOAuthToken(db, 1, "github", "gh-access", "", "Bearer", 0, "")
	if access, refresh, expires := storedOAuthToken(t, db, "github"); access != "gh-access" || refresh != "" || expires != "" {
		t.Fatalf("a first connection without a refresh token: access %q, refresh %q, expires %q", access, refresh, expires)
	}
}

// GetOAuthToken refreshed an expired access token and returned it, but kept
// nothing: the row stayed expired, so every later call refreshed again, and
// with a provider that rotates refresh tokens the second call sent the spent
// one, failed, and handed back the expired access token.
func TestGetOAuthTokenKeepsWhatARefreshReturns(t *testing.T) {
	db := oauthTokenStoreFixture(t)
	appDir := t.TempDir()
	// A provider that rotates: each refresh token works once.
	next := map[string]oauthRefreshResult{
		"refresh-1": {AccessToken: "access-2", RefreshToken: "refresh-2", TokenType: "Bearer", ExpiresIn: 3600},
		"refresh-2": {AccessToken: "access-3", ExpiresIn: 1800}, // no rotation this time
	}
	calls := 0
	oldExchange := oauthRefreshExchange
	oauthRefreshExchange = func(tokenURL, clientID, clientSecret, refreshToken string) (oauthRefreshResult, bool) {
		calls++
		res, ok := next[refreshToken]
		delete(next, "refresh-1")
		return res, ok
	}
	t.Cleanup(func() { oauthRefreshExchange = oldExchange })
	expire := func() {
		mustExecArgs(t, db, `UPDATE _benmore_oauth_tokens SET expires_at = ? WHERE user_id = 1`, time.Now().Add(-time.Minute).UTC().Format(time.RFC3339))
	}

	StoreOAuthToken(db, 1, "google", "access-1", "refresh-1", "Bearer", 3600, "email")
	if got := GetOAuthToken(db, appDir, 1, "google"); got != "access-1" || calls != 0 {
		t.Fatalf("an unexpired token: %q after %d refresh(es)", got, calls)
	}
	expire()
	if got := GetOAuthToken(db, appDir, 1, "google"); got != "access-2" || calls != 1 {
		t.Fatalf("the first call after expiry: %q after %d refresh(es)", got, calls)
	}
	// The refreshed token is the stored one now: no second exchange, and the
	// rotated refresh token and the new expiry are kept with it.
	if got := GetOAuthToken(db, appDir, 1, "google"); got != "access-2" || calls != 1 {
		t.Errorf("the next call: %q after %d refresh(es); want the stored access-2 and no new exchange", got, calls)
	}
	access, refresh, expires := storedOAuthToken(t, db, "google")
	if access != "access-2" || refresh != "refresh-2" {
		t.Errorf("stored after the refresh: access %q, refresh %q; want access-2, refresh-2", access, refresh)
	}
	if at, err := time.Parse(time.RFC3339, expires); err != nil || !at.After(time.Now().Add(50*time.Minute)) {
		t.Errorf("stored expiry after the refresh: %q, want about an hour ahead", expires)
	}
	// When that one expires too, the rotated token is what is sent. A reply
	// without a refresh token keeps the one in store.
	expire()
	if got := GetOAuthToken(db, appDir, 1, "google"); got != "access-3" || calls != 2 {
		t.Errorf("after the second expiry: %q after %d refresh(es); want access-3 from the rotated refresh token", got, calls)
	}
	if access, refresh, _ := storedOAuthToken(t, db, "google"); access != "access-3" || refresh != "refresh-2" {
		t.Errorf("stored after the second refresh: access %q, refresh %q; want access-3 and refresh-2 kept", access, refresh)
	}

	// A connection removed while the provider was answering is not written back.
	expire()
	oauthRefreshExchange = func(string, string, string, string) (oauthRefreshResult, bool) {
		mustExec(t, db, `DELETE FROM _benmore_oauth_tokens WHERE user_id = 1 AND provider = 'google'`)
		return oauthRefreshResult{AccessToken: "access-late", RefreshToken: "refresh-late", ExpiresIn: 3600}, true
	}
	GetOAuthToken(db, appDir, 1, "google")
	var rows int
	db.QueryRow(`SELECT COUNT(*) FROM _benmore_oauth_tokens WHERE user_id = 1 AND provider = 'google'`).Scan(&rows)
	if rows != 0 {
		t.Error("a refresh that finished after the user disconnected brought the connection back")
	}
}
