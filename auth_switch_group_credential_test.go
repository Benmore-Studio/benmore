//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// POST /api/_switch_group stores the chosen tenant on the session row. An API
// token has no row, so the UPDATE matched nothing and the endpoint still
// answered with its success redirect; the token kept resolving to the
// member's oldest tenant, and a script that "switched" to tenant B before
// writing put its rows into tenant A, where A's members read them.
func TestSwitchGroupRefusesCredentialsWithoutASessionRow(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	app := &App{Dir: dir, DB: db}
	if err := EnsureUsersTable(db); err != nil {
		t.Fatal(err)
	}
	EnsureSessionsTable(db)
	EnsureAPITokensTable(db)
	if err := EnsureUserRolesTable(db); err != nil {
		t.Fatal(err)
	}
	mustExec(t, db, "CREATE TABLE members (id INTEGER PRIMARY KEY, org_id TEXT, user_id INTEGER)")
	app.Group = &GroupConfig{Table: "members", Key: "org_id", UserField: "user_id"}
	app.Design = &DesignConfig{Auth: map[string]string{}, SEO: map[string]string{}}
	app.SessionDuration = time.Hour
	res, err := db.Exec("INSERT INTO _benmore_users (username, email, role, verified) VALUES ('m', 'm@example.com', 'user', 1)")
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := res.LastInsertId()
	mustExec(t, db, "INSERT INTO members (org_id, user_id) VALUES ('tenant-a', "+itoaInt(uid)+"), ('tenant-b', "+itoaInt(uid)+")")
	apiToken := "bmr_" + generateToken(32)
	if _, err := db.Exec("INSERT INTO _benmore_api_tokens (user_id, name, token_hash, scopes) VALUES (?, 'script', ?, '*')", uid, hashToken(apiToken)); err != nil {
		t.Fatal(err)
	}
	switchTo := func(bearer, group string) int {
		form := url.Values{"group_id": {group}, "_csrf": {authMintCSRFToken("")}}
		r := httptest.NewRequest(http.MethodPost, "/api/_switch_group", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Authorization", "Bearer "+bearer)
		w := httptest.NewRecorder()
		handleSwitchGroup(w, r, app)
		return w.Code
	}
	tenant := func(bearer string) string {
		r := httptest.NewRequest(http.MethodGet, "/api/notes", nil)
		r.Header.Set("Authorization", "Bearer "+bearer)
		if s := getSession(app, r); s != nil {
			return s.EffectiveGroupID()
		}
		return "?"
	}

	if code := switchTo(apiToken, "tenant-b"); code < 400 {
		t.Fatalf("an API token was told it switched tenant (%d) while it still resolves to %q", code, tenant(apiToken))
	}

	// Control: a session token switches.
	sessionToken := CreateSession(db, uid, "m@example.com", "tenant-a", time.Hour)
	if code := switchTo(sessionToken, "tenant-b"); code != http.StatusSeeOther {
		t.Fatalf("session switch: %d", code)
	}
	if got := tenant(sessionToken); got != "tenant-b" {
		t.Fatalf("session tenant after switch = %q", got)
	}

	// A Bearer request carries its credential explicitly and has no CSRF
	// token: a native client's session switches, and an API token gets the
	// documented 400 instead of a CSRF refusal.
	noCSRF := func(bearer, group string) int {
		r := httptest.NewRequest(http.MethodPost, "/api/_switch_group", strings.NewReader(url.Values{"group_id": {group}}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Authorization", "Bearer "+bearer)
		w := httptest.NewRecorder()
		handleSwitchGroup(w, r, app)
		return w.Code
	}
	if code := noCSRF(sessionToken, "tenant-a"); code != http.StatusSeeOther || tenant(sessionToken) != "tenant-a" {
		t.Fatalf("Bearer session switch without a CSRF token: %d, tenant %q", code, tenant(sessionToken))
	}
	if code := noCSRF(apiToken, "tenant-b"); code != http.StatusBadRequest {
		t.Fatalf("API token switch without a CSRF token: %d, want 400", code)
	}
	// A cookie request still needs the token.
	r := httptest.NewRequest(http.MethodPost, "/api/_switch_group", strings.NewReader(url.Values{"group_id": {"tenant-b"}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: devSessionCookieName, Value: sessionToken})
	w := httptest.NewRecorder()
	handleSwitchGroup(w, r, app)
	if w.Code != http.StatusForbidden || tenant(sessionToken) != "tenant-a" {
		t.Fatalf("cookie switch without a CSRF token: %d, tenant %q", w.Code, tenant(sessionToken))
	}
}

func itoaInt(n int64) string {
	const digits = "0123456789"
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{digits[n%10]}, b...)
		n /= 10
	}
	return string(b)
}

// A JSON client (bm.api, fetch with a JSON body or Accept: application/json)
// got a 303 to "/" from POST /api/_switch_group; fetch followed it and handed
// the client the home page's HTML as the result, and refusals came back as
// text. It now answers JSON - the new tenant on success, {"error"} on a
// refusal - while a browser form post keeps the redirect.
func TestSwitchGroupAnswersJSONToJSONClients(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	app := &App{Dir: dir, DB: db}
	if err := EnsureUsersTable(db); err != nil {
		t.Fatal(err)
	}
	EnsureSessionsTable(db)
	if err := EnsureUserRolesTable(db); err != nil {
		t.Fatal(err)
	}
	mustExec(t, db, "CREATE TABLE members (id INTEGER PRIMARY KEY, org_id TEXT, user_id INTEGER)")
	app.Group = &GroupConfig{Table: "members", Key: "org_id", UserField: "user_id"}
	app.Design = &DesignConfig{Auth: map[string]string{}, SEO: map[string]string{}}
	app.SessionDuration = time.Hour
	res, err := db.Exec("INSERT INTO _benmore_users (username, email, role, verified) VALUES ('m', 'm@example.com', 'user', 1)")
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := res.LastInsertId()
	mustExec(t, db, "INSERT INTO members (org_id, user_id) VALUES ('tenant-a', "+itoaInt(uid)+"), ('tenant-b', "+itoaInt(uid)+")")
	sid := CreateSession(db, uid, "m@example.com", "tenant-a", time.Hour)
	tenant := func() string {
		r := httptest.NewRequest(http.MethodGet, "/api/notes", nil)
		r.Header.Set("Authorization", "Bearer "+sid)
		if s := getSession(app, r); s != nil {
			return s.EffectiveGroupID()
		}
		return "?"
	}
	call := func(contentType, accept, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/api/_switch_group", strings.NewReader(body))
		r.Header.Set("Content-Type", contentType)
		if accept != "" {
			r.Header.Set("Accept", accept)
		}
		r.Header.Set("Authorization", "Bearer "+sid)
		w := httptest.NewRecorder()
		handleSwitchGroup(w, r, app)
		return w
	}
	decode := func(w *httptest.ResponseRecorder) map[string]any {
		t.Helper()
		if !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
			t.Fatalf("JSON client got %d %q: %s", w.Code, w.Header().Get("Content-Type"), w.Body.String())
		}
		var out map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("body %q: %v", w.Body.String(), err)
		}
		return out
	}

	// JSON body.
	w := call("application/json", "", `{"group_id":"tenant-b"}`)
	if out := decode(w); w.Code != http.StatusOK || out["status"] != "switched" || out["group_id"] != "tenant-b" || tenant() != "tenant-b" {
		t.Fatalf("JSON switch: %d %v, tenant %q", w.Code, out, tenant())
	}
	// Form body from a client that asks for JSON.
	w = call("application/x-www-form-urlencoded", "application/json", url.Values{"group_id": {"tenant-a"}}.Encode())
	if out := decode(w); w.Code != http.StatusOK || out["group_id"] != "tenant-a" || tenant() != "tenant-a" {
		t.Fatalf("Accept JSON switch: %d %v, tenant %q", w.Code, out, tenant())
	}
	// Refusals are JSON too, and change nothing.
	w = call("application/json", "", `{"group_id":"tenant-c"}`)
	if out := decode(w); w.Code != http.StatusForbidden || out["error"] == nil || tenant() != "tenant-a" {
		t.Fatalf("JSON switch into a tenant the user is not in: %d %v, tenant %q", w.Code, out, tenant())
	}
	w = call("application/json", "", `{}`)
	if out := decode(w); w.Code != http.StatusBadRequest || out["error"] == nil {
		t.Fatalf("JSON switch without group_id: %d %v", w.Code, out)
	}
	// A browser form post keeps the redirect.
	w = call("application/x-www-form-urlencoded", "text/html,application/xhtml+xml,*/*", url.Values{"group_id": {"tenant-b"}}.Encode())
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/" || tenant() != "tenant-b" {
		t.Fatalf("form switch: %d Location %q, tenant %q", w.Code, w.Header().Get("Location"), tenant())
	}
}
