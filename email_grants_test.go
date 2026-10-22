//go:build !cli

package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// A tenant invite, a membership row, a record share and a pending user_roles
// invite addressed to ceo@corp.example must not flow to whoever signs up
// with that address first. They apply once the account proves the address.
func TestEmailKeyedGrantsWaitForVerification(t *testing.T) {
	app, _ := auditApp(t)
	app.Paths = DiscoverAuthPaths(nil)
	EnsureLoginAttemptsTable(app.DB)
	EnsurePasswordResetsTable(app.DB)
	for _, stmt := range []string{
		`CREATE TABLE channels (id INTEGER PRIMARY KEY, title TEXT)`,
		`CREATE TABLE channel_members (id INTEGER PRIMARY KEY, channel_id INTEGER, member_email TEXT)`,
		`CREATE TABLE user_roles (id INTEGER PRIMARY KEY, email TEXT, user_id INTEGER, is_active INTEGER DEFAULT 0, invite_accepted_at TEXT)`,
		`INSERT INTO members (org_id, email) VALUES ('tenant-a', 'ceo@corp.example')`,
		`INSERT INTO channels VALUES (1, 'board-channel')`,
		`INSERT INTO channel_members (channel_id, member_email) VALUES (1, 'ceo@corp.example')`,
		`INSERT INTO user_roles (email) VALUES ('ceo@corp.example')`,
		`INSERT INTO notes (id, user_id, title) VALUES (50, 999, 'shared-secret')`,
		`INSERT INTO _benmore_permissions (resource_type, resource_id, grant_type, grantee_id, permission) VALUES ('notes', '50', 'user', 'ceo@corp.example', 'view')`,
	} {
		mustExec(t, app.DB, stmt)
	}
	for _, name := range []string{"channels", "channel_members", "user_roles"} {
		cols, err := GetTableColumns(app.DB, name)
		if err != nil {
			t.Fatal(err)
		}
		app.Tables = append(app.Tables, Table{Name: name, Columns: cols})
	}
	app.Access.rules["channels"] = map[AccessOp]string{"all": "member-of:channel_members(channel_id, member_email)"}
	mux := http.NewServeMux()
	RegisterCRUD(mux, app)

	// The squatter signs up with the invited address (no verification
	// configured, so signup signs them straight in).
	form := url.Values{"email": {"ceo@corp.example"}, "password": {fixturePassword}, "_csrf": {authMintCSRFToken("")}}
	r := httptest.NewRequest(http.MethodPost, app.Paths.Signup, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleSignup(w, r, app)
	var sid string
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookieName {
			sid = c.Value
		}
	}
	if sid == "" {
		t.Fatalf("signup issued no session: %d %v", w.Code, w.Header())
	}
	uid := GetSessionFromDB(app.DB, sid).UserID
	// A session row that already cached the tenant (e.g. from before the
	// rule) must not keep it either.
	stale := CreateSession(app.DB, uid, "ceo@corp.example", "tenant-a", time.Hour)

	get := func(path, credential string) string {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.Header.Set("Authorization", "Bearer "+credential)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w.Body.String()
	}
	inviteActive := func() bool {
		var active int
		app.DB.QueryRow("SELECT COALESCE(is_active,0) FROM user_roles WHERE email = 'ceo@corp.example'").Scan(&active)
		return active == 1
	}
	for _, cred := range []string{sid, stale} {
		if body := get("/api/orgdocs", cred); strings.Contains(body, "private-a") {
			t.Fatalf("unverified account read the invited tenant's rows: %s", body)
		}
		if body := get("/api/channels", cred); strings.Contains(body, "board-channel") {
			t.Fatalf("unverified account joined an email-keyed room: %s", body)
		}
		if body := get("/api/notes/50", cred); strings.Contains(body, "shared-secret") {
			t.Fatalf("unverified account read a record shared with the address: %s", body)
		}
	}
	if inviteActive() {
		t.Fatal("signup activated the pending invite for an unverified address")
	}
	if g := ResolveGroupID(app.DB, app.Group, "ceo@corp.example"); g != "" {
		t.Fatalf("unverified email resolved tenant %q", g)
	}

	// The real owner of the inbox verifies: the grants now apply.
	passwordChangeExec(t, app.DB, "INSERT INTO _benmore_password_resets (token, email, expires_at, type) VALUES (?, 'ceo@corp.example', datetime('now','+1 hour'), 'verify')", hashResetToken("verify-tok"))
	// They click in the browser that signed up, so its session survives the
	// click while every other session of the account is revoked.
	vr := httptest.NewRequest(http.MethodGet, app.Paths.VerifyEmail+"?token=verify-tok", nil)
	vr.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
	vr.AddCookie(&http.Cookie{Name: devSessionCookieName, Value: sid})
	handleVerifyEmail(httptest.NewRecorder(), vr, app)
	if GetSessionFromDB(app.DB, stale) != nil {
		t.Fatal("a session other than the clicking one survived the verification click")
	}
	if body := get("/api/orgdocs", sid); !strings.Contains(body, "private-a") {
		t.Fatalf("verified member cannot read their tenant: %s", body)
	}
	if body := get("/api/channels", sid); !strings.Contains(body, "board-channel") {
		t.Fatalf("verified member cannot see their room: %s", body)
	}
	if body := get("/api/notes/50", sid); !strings.Contains(body, "shared-secret") {
		t.Fatalf("verified grantee cannot read the shared record: %s", body)
	}
	if !inviteActive() {
		t.Fatal("verification did not activate the pending invite")
	}
}

// A provider-verified OAuth sign-in for an address that already has a
// never-verified password account takes that account over for the proven
// owner: whatever the earlier registrant set up (password, sessions) dies.
func TestVerifiedOAuthClaimsUnverifiedAccount(t *testing.T) {
	app, _ := auditApp(t)
	hash, _ := bcrypt.GenerateFromPassword([]byte(fixturePassword), bcrypt.MinCost)
	seed := func(email string) (int64, string) {
		res, err := app.DB.Exec("INSERT INTO _benmore_users (username, email, password_hash) VALUES (?, ?, ?)", strings.Split(email, "@")[0], email, string(hash))
		if err != nil {
			t.Fatal(err)
		}
		id, _ := res.LastInsertId()
		return id, CreateSession(app.DB, id, email, "", time.Hour)
	}
	passwordWorks := func(id int64) bool {
		var h string
		app.DB.QueryRow("SELECT password_hash FROM _benmore_users WHERE id = ?", id).Scan(&h)
		return bcrypt.CompareHashAndPassword([]byte(h), []byte(fixturePassword)) == nil
	}

	squatID, squatSID := seed("owner@corp.example")
	got, err := oauthFindOrCreateUser(app, "owner@corp.example", "", true)
	if err != nil || got != squatID {
		t.Fatalf("link: %d %v", got, err)
	}
	var verified int
	app.DB.QueryRow("SELECT COALESCE(verified,0) FROM _benmore_users WHERE id = ?", squatID).Scan(&verified)
	if verified != 1 || passwordWorks(squatID) || GetSessionFromDB(app.DB, squatSID) != nil {
		t.Fatalf("claimed account kept the unproven credentials: verified=%d password=%v session=%v", verified, passwordWorks(squatID), GetSessionFromDB(app.DB, squatSID) != nil)
	}

	// An unverified provider email is refused and changes nothing.
	otherID, otherSID := seed("other@corp.example")
	if _, err := oauthFindOrCreateUser(app, "other@corp.example", "", false); !errors.Is(err, errOAuthUnverifiedLink) {
		t.Fatalf("unverified OAuth email linked: %v", err)
	}
	app.DB.QueryRow("SELECT COALESCE(verified,0) FROM _benmore_users WHERE id = ?", otherID).Scan(&verified)
	if verified != 0 || !passwordWorks(otherID) || GetSessionFromDB(app.DB, otherSID) == nil {
		t.Fatal("unverified OAuth email altered the existing account")
	}
}
