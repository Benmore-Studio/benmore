//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Honest answers outside /api/: a busy database is 503 on a page route, a
// form post, the admin panel and the sign-in forms (never a sentence about
// the caller's credentials); the settings forms read a JSON body; an update
// names the rule of its foreign-key refusal as a create does; and a file the
// server could not store is a 5xx, not the 400 of a bad request.

const outsideAPIPassword = "Correct-Horse-1"

// outsideAPIUser adds an account with a password and returns its id and a
// cookie session.
func (f *busyRouteFixture) outsideAPIUser(email, role string) (int64, string) {
	f.t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(outsideAPIPassword), bcrypt.MinCost)
	if err != nil {
		f.t.Fatal(err)
	}
	id := f.insert("INSERT INTO _benmore_users (username, email, role, verified, password_hash) VALUES (?, ?, ?, 1, ?)", email, email, role, string(hash))
	sid := CreateSession(f.app.DB, id, email, "", time.Hour)
	if sid == "" {
		f.t.Fatal("no session")
	}
	return id, sid
}

// browser sends a request the way a page does: a cookie session (sid may be
// empty), the CSRF token in the body, and the Accept header of a form post
// (html) or of fetch (json).
func (f *busyRouteFixture) browser(method, path, sid, accept string, form url.Values, jsonBody string) *httptest.ResponseRecorder {
	f.t.Helper()
	var r *http.Request
	if jsonBody != "" {
		r = httptest.NewRequest(method, "https://busy.example.test"+path, strings.NewReader(jsonBody))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", authMintCSRFToken(sid))
	} else {
		if form == nil {
			form = url.Values{}
		}
		form.Set("_csrf", authMintCSRFToken(sid))
		r = httptest.NewRequest(method, "https://busy.example.test"+path, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	r.Header.Set("Accept", accept)
	r.Header.Set("Origin", "https://busy.example.test")
	if sid != "" {
		r.AddCookie(sessionCookie(sid, false, time.Hour))
	}
	w := httptest.NewRecorder()
	f.mux.ServeHTTP(w, r)
	return w
}

// A request that could not get the write lock answers 503 with Retry-After on
// the routes outside /api/ too. They used to answer whatever their error path
// said: a sign-in with the right password "Credentials changed. Sign in
// again.", a sign-up and a reset "Server error" (400 for a JSON caller), a
// password change "Unable to change password", the admin panel 500, and a
// sign-out answered ok while the session row stayed.
func TestBusyDatabaseAnswers503OutsideAPI(t *testing.T) {
	f := newBusyRouteFixture(t)
	_, adminSID := f.outsideAPIUser("boss@example.com", "admin")
	memberID, memberSID := f.outsideAPIUser("member@example.com", "user")
	_, leavingSID := f.outsideAPIUser("leaving@example.com", "user")
	_, signOutSID := f.outsideAPIUser("signout@example.com", "user")
	const resetToken = "reset-token-for-the-busy-test"
	f.insert("INSERT INTO _benmore_password_resets (token, email, expires_at, type) VALUES (?, 'member@example.com', datetime('now', '+1 hour'), 'reset')", hashResetToken(resetToken))

	const html, js = "text/html,application/xhtml+xml", "application/json"
	signIn := `{"email":"member@example.com","password":"` + outsideAPIPassword + `"}`
	newPassword := url.Values{"current_password": {outsideAPIPassword}, "new_password": {"Another-Horse-2"}, "confirm_password": {"Another-Horse-2"}}
	routes := []struct {
		name, method, path, sid, accept string
		form                            url.Values
		json                            string
	}{
		{"sign-in form", "POST", f.app.Paths.Login, "", html, url.Values{"email": {"member@example.com"}, "password": {outsideAPIPassword}}, ""},
		{"sign-in json", "POST", f.app.Paths.Login, "", js, nil, signIn},
		{"token sign-in", "POST", "/api/_auth/token", "", js, nil, signIn},
		{"sign-up form", "POST", f.app.Paths.Signup, "", html, url.Values{"email": {"new@example.com"}, "password": {outsideAPIPassword}}, ""},
		{"sign-up json", "POST", f.app.Paths.Signup, "", js, nil, `{"email":"new2@example.com","password":"` + outsideAPIPassword + `"}`},
		{"reset form", "POST", f.app.Paths.ResetPassword, "", html, url.Values{"token": {resetToken}, "password": {"Another-Horse-2"}, "confirm": {"Another-Horse-2"}}, ""},
		{"sign-out", "POST", f.app.Paths.Logout, signOutSID, js, nil, `{}`},
		{"settings password form", "POST", "/settings/password", memberSID, html, newPassword, ""},
		{"settings password json", "POST", "/settings/password", memberSID, js, nil, `{"current_password":"` + outsideAPIPassword + `","new_password":"Another-Horse-2","confirm_password":"Another-Horse-2"}`},
		{"settings delete-account", "POST", "/settings/delete-account", leavingSID, html, url.Values{"confirm": {"DELETE"}}, ""},
		{"admin panel create", "POST", "/_admin/api/items/create", adminSID, html, url.Values{"title": {"from the panel"}}, ""},
		{"admin panel set-role", "POST", "/_admin/set-role", adminSID, html, url.Values{"user_id": {strconv.FormatInt(memberID, 10)}, "role": {"admin"}}, ""},
	}
	for _, route := range routes {
		t.Run(route.name, func(t *testing.T) {
			release := f.holdWriteLock()
			var w *httptest.ResponseRecorder
			logged := captureLog(t, func() { w = f.browser(route.method, route.path, route.sid, route.accept, route.form, route.json) })
			release()

			answer := strings.TrimSpace(w.Body.String())
			if w.Code != http.StatusServiceUnavailable {
				t.Fatalf("%s %s with the write lock held: %d Location %q %s, want 503", route.method, route.path, w.Code, w.Header().Get("Location"), answer)
			}
			id := w.Header().Get(requestIDHeader)
			if w.Header().Get("Retry-After") != "1" || !requestIDPattern.MatchString(id) {
				t.Errorf("Retry-After %q, X-Request-Id %q", w.Header().Get("Retry-After"), id)
			}
			if route.accept == js {
				// A caller that asked for JSON gets the /api/ body.
				body := decodeJSONAnswer(t, w)
				if body["error"] != "database_busy" || body["request_id"] != id || body["docs"] != "recovery.write_lock" {
					t.Errorf("body %v", body)
				}
			} else if !strings.Contains(answer, "atabase is busy") || !strings.Contains(answer, id) {
				t.Errorf("answer %q does not say the database is busy with the request id", answer)
			}
			for _, wrong := range []string{"redentials", "Server error", "locked", "Unable to"} {
				if strings.Contains(answer, wrong) {
					t.Errorf("the busy answer says %q: %s", wrong, answer)
				}
			}
			if len(w.Result().Cookies()) != 0 {
				t.Errorf("a request answered 503 set cookies: %v", w.Result().Cookies())
			}
			if n := strings.Count(logged, "DATABASE BUSY ["); n != 1 || strings.Contains(logged, "SERVER ERROR") {
				t.Errorf("journal has %d DATABASE BUSY lines (and no SERVER ERROR wanted):\n%s", n, logged)
			}
		})
	}

	// Nothing the refused requests tried to write was kept, and the session
	// a sign-out could not delete is still there to be signed out again.
	if n := f.count(`SELECT (SELECT COUNT(*) FROM _benmore_users WHERE email LIKE 'new%') + (SELECT COUNT(*) FROM items WHERE title = 'from the panel')
		+ (SELECT COUNT(*) FROM _benmore_users WHERE email = 'member@example.com' AND role = 'admin')
		+ (SELECT COUNT(*) FROM _benmore_password_resets WHERE used = 1)
		+ (SELECT COUNT(*) FROM _benmore_users WHERE email = 'leaving@example.com') - 1`); n != 0 {
		t.Fatalf("requests answered 503 changed %d rows", n)
	}
	key, _ := presentedSessionKey(signOutSID)
	if n := f.count("SELECT COUNT(*) FROM _benmore_sessions WHERE id = ?", key); n != 1 {
		t.Fatalf("the session of the refused sign-out: %d rows, want it still there", n)
	}
	// With the lock free the same sign-in and sign-out go through: the old
	// password still works, so the refused change and reset wrote nothing.
	retry := func(send func() *httptest.ResponseRecorder) *httptest.ResponseRecorder {
		w := send()
		for try := 0; try < 20 && w.Code == http.StatusServiceUnavailable; try++ {
			time.Sleep(50 * time.Millisecond)
			w = send()
		}
		return w
	}
	if w := retry(func() *httptest.ResponseRecorder { return f.browser("POST", f.app.Paths.Login, "", js, nil, signIn) }); w.Code != http.StatusOK || decodeJSONAnswer(t, w)["ok"] != true {
		t.Errorf("sign-in with the lock free: %d %s", w.Code, w.Body.String())
	}
	if w := retry(func() *httptest.ResponseRecorder {
		return f.browser("POST", f.app.Paths.Logout, signOutSID, js, nil, `{}`)
	}); w.Code != http.StatusOK {
		t.Errorf("sign-out with the lock free: %d %s", w.Code, w.Body.String())
	}
	if n := f.count("SELECT COUNT(*) FROM _benmore_sessions WHERE id = ?", key); n != 0 {
		t.Errorf("the session after sign-out: %d rows", n)
	}
	// A wrong password is still a wrong password while the database is busy.
	release := f.holdWriteLock()
	w := f.browser("POST", f.app.Paths.Login, "", js, nil, `{"email":"member@example.com","password":"not-the-password-1"}`)
	release()
	if w.Code != http.StatusUnauthorized || decodeJSONAnswer(t, w)["error"] != "Invalid credentials" {
		t.Errorf("wrong password with the write lock held: %d %s, want 401 Invalid credentials", w.Code, w.Body.String())
	}
}

// POST /settings/profile and POST /settings/delete-account read a JSON body
// like POST /settings/password. They used to read form fields only, so a
// page that posts JSON got "Email is required" and "Type DELETE to confirm
// account deletion" for a body that carried both. The CSRF token, the current
// password and the typed confirmation are checked the same for every body.
func TestSettingsProfileAndDeleteAccountReadJSONBodies(t *testing.T) {
	app, mux, uid, sid := accountSettingsMuxFixture(t, nil)
	sent := fakeEmailGateway(t)
	post := func(path, body, csrf string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json")
		if csrf != "" {
			r.Header.Set("X-CSRF-Token", csrf)
		}
		r.AddCookie(sessionCookie(sid, true, time.Hour))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	stored := func(query string) string {
		var v string
		if err := app.DB.QueryRow(query, uid).Scan(&v); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
		return v
	}
	const change = `{"email":"allowed@example.com","current_password":"Correct-Horse-1"}`

	// The checks a form post passes are the checks a JSON post passes.
	if w := post("/settings/profile", change, ""); w.Code != http.StatusForbidden {
		t.Fatalf("JSON email change without a CSRF token: %d %s, want 403", w.Code, w.Body.String())
	}
	if w := post("/settings/profile", `{"email":"allowed@example.com","current_password":"wrong-password-1"}`, authMintCSRFToken(sid)); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "Incorrect password") {
		t.Fatalf("JSON email change with a wrong password: %d %s, want 400 Incorrect password", w.Code, w.Body.String())
	}
	if w := post("/settings/profile", `{"email":"allowed@example.com"}`, authMintCSRFToken(sid)); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "current password") {
		t.Fatalf("JSON email change without the password: %d %s, want 400", w.Code, w.Body.String())
	}
	if n := len(sent()); n != 0 {
		t.Fatalf("%d emails were sent by refused requests", n)
	}
	w := post("/settings/profile", change, authMintCSRFToken(sid))
	if body := decodeJSONAnswer(t, w); w.Code != http.StatusOK || body["ok"] != true || !strings.Contains(body["message"].(string), "allowed@example.com") {
		t.Fatalf("JSON email change: %d %s, want 200 with the confirmation notice", w.Code, w.Body.String())
	}
	if n := len(sent()); n != 1 {
		t.Fatalf("%d confirmation emails sent, want 1", n)
	}
	if got := stored("SELECT email FROM _benmore_users WHERE id = ?"); got != "owner@example.com" {
		t.Fatalf("the email changed to %q before the new address confirmed", got)
	}

	if w := post("/settings/delete-account", `{"confirm":"DELETE"}`, ""); w.Code != http.StatusForbidden {
		t.Fatalf("JSON account deletion without a CSRF token: %d %s, want 403", w.Code, w.Body.String())
	}
	if w := post("/settings/delete-account", `{"confirm":"delete"}`, authMintCSRFToken(sid)); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "Type DELETE") {
		t.Fatalf("JSON account deletion without the typed word: %d %s, want 400", w.Code, w.Body.String())
	}
	if got := stored("SELECT COALESCE(email, '') FROM _benmore_users WHERE id = ?"); got != "owner@example.com" {
		t.Fatalf("a refused deletion changed the account: email %q", got)
	}
	// A client that asks for JSON gets the JSON answer naming the sign-in
	// page, not a redirect it would follow into HTML.
	w = post("/settings/delete-account", `{"confirm":"DELETE"}`, authMintCSRFToken(sid))
	if body := decodeJSONAnswer(t, w); w.Code != http.StatusOK || body["deleted"] != true || body["redirect"] != app.Paths.Login {
		t.Fatalf("JSON account deletion: %d %s, want 200 with deleted and the sign-in page", w.Code, w.Body.String())
	}
	if got := stored("SELECT COALESCE(email, '') || '|' || COALESCE(password_hash, '') FROM _benmore_users WHERE id = ?"); strings.Contains(got, "owner@example.com") || strings.Contains(got, "$2") {
		t.Fatalf("the account after deletion still holds its login: %q", got)
	}
	if GetSessionFromDB(app.DB, sid) != nil {
		t.Fatal("the deleted account's session is still live")
	}
}

// An update that names a parent the caller cannot read answers 422 with the
// `docs` address a create's refusal carries. Single PATCH, batch update and
// an /api/_transaction update answered the sentence alone.
func TestUpdateForeignKeyRefusalCarriesDocs(t *testing.T) {
	app := newUnscopedParentApp(t)
	uidA, _ := gateUser(t, app, "a@example.com")
	uidB, sidB := gateUser(t, app, "b@example.com")
	a, b := strconv.FormatInt(uidA, 10), strconv.FormatInt(uidB, 10)
	mustExec(t, app.DB, "INSERT INTO projects (id, user_id, name) VALUES (1, "+a+", 'A'), (2, "+b+", 'B')")
	mustExec(t, app.DB, "INSERT INTO requests (id, user_id, vendor_id, project_id, title) VALUES (10, "+b+", 1, 2, 'mine')")
	transaction := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "https://app.example.com/api/_transaction", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+sidB)
		w := httptest.NewRecorder()
		handleTransaction(w, r, app)
		return w
	}
	const js = "application/json"
	calls := map[string]*httptest.ResponseRecorder{
		"create (control)":                   gateCall(app, handleCreate, "requests", "POST", "/api/requests", js, `{"project_id":1,"title":"x"}`, sidB),
		"update, forbidden parent":           gateCall(app, handleUpdate, "requests", "PATCH", "/api/requests/10", js, `{"project_id":1}`, sidB),
		"update, missing parent":             gateCall(app, handleUpdate, "requests", "PATCH", "/api/requests/10", js, `{"vendor_id":999}`, sidB),
		"batch update, forbidden parent":     gateCall(app, handleBatchUpdate, "requests", "PATCH", "/api/requests/batch", js, `{"ids":[10],"fields":{"project_id":"1"}}`, sidB),
		"batch update, missing parent":       gateCall(app, handleBatchUpdate, "requests", "PATCH", "/api/requests/batch", js, `{"ids":[10],"fields":{"vendor_id":"999"}}`, sidB),
		"transaction update, forbidden":      transaction(`{"operations":[{"table":"requests","action":"update","id":10,"data":{"project_id":1}}]}`),
		"transaction update, missing parent": transaction(`{"operations":[{"table":"requests","action":"update","id":10,"data":{"vendor_id":999}}]}`),
	}
	for name, w := range calls {
		code, body := statusBody(w)
		text, _ := body["error"].(string)
		if code != http.StatusUnprocessableEntity || !strings.HasSuffix(text, "references a record that does not exist or is not accessible") {
			t.Errorf("%s: %d %s, want the 422 foreign-key refusal", name, code, w.Body.String())
			continue
		}
		if body["docs"] != "scoping.foreign_keys" {
			t.Errorf("%s: docs = %v, want scoping.foreign_keys: %s", name, body["docs"], w.Body.String())
		}
	}
	if got := gateScalar(t, app, "SELECT vendor_id || ',' || project_id FROM requests WHERE id = 10"); got != "1,2" {
		t.Fatalf("a refused update applied: vendor_id,project_id = %s", got)
	}
	// Another 422 of an update (a validator) does not claim the address.
	other := &updateRequestError{status: http.StatusUnprocessableEntity, message: "title is required"}
	w := httptest.NewRecorder()
	writeUpdateRequestError(w, httptest.NewRequest("PATCH", "/api/requests/10", nil), app, "requests update", other)
	if _, body := statusBody(w); body["docs"] != nil {
		t.Errorf("a validation 422 carries docs %v", body["docs"])
	}
}

// A file the server could not store is the server's failure: 502 when the
// store is reached over the network, 500 for local disk, with a request id
// and one general sentence. All three upload paths answered 400, the status
// of a request the client should change, and for local disk the answer was
// the operating system's error with the server's directory in it. A request
// that is wrong stays 400.
func TestUploadStoreFaultAnswers5xx(t *testing.T) {
	paths := func(sid string) map[string]*http.Request {
		return map[string]*http.Request{
			"_upload": uploadRequest(t, "POST", "/api/_upload", sid, nil, uploadPart{"file", "scan.png", pngBytes}),
			"_files":  uploadRequest(t, "POST", "/api/_files", sid, nil, uploadPart{"file", "scan.png", pngBytes}),
			"create":  uploadRequest(t, "POST", "/api/docs", sid, map[string]string{"title": "store fault"}, uploadPart{"attachment", "scan.png", pngBytes}),
		}
	}
	check := func(t *testing.T, app *App, sid string, want int) {
		t.Helper()
		mux := uploadRoutes(app)
		for name, r := range paths(sid) {
			w := httptest.NewRecorder()
			logged := captureLog(t, func() { mux.ServeHTTP(w, r) })
			body := answerJSON(t, w)
			id, _ := body["request_id"].(string)
			if msg, _ := body["error"].(string); w.Code != want || !strings.Contains(msg, "did not accept the file") || !requestIDPattern.MatchString(id) || w.Header().Get(requestIDHeader) != id {
				t.Errorf("%s: %d %s, want %d with the general sentence and a request id", name, w.Code, w.Body.String(), want)
			}
			// The cause stays server-side: no directory of the server, no
			// name of the store's components.
			for _, internal := range []string{app.Dir, "uploads/", "presign", "broker", "not a directory"} {
				if strings.Contains(w.Body.String(), internal) {
					t.Errorf("%s: the answer names %q: %s", name, internal, w.Body.String())
				}
			}
			if !strings.Contains(logged, "SERVER ERROR [upload]") {
				t.Errorf("%s: the store fault is not in the journal:\n%s", name, logged)
			}
		}
		if got := gateScalar(t, app, "SELECT COUNT(*) FROM docs WHERE title = 'store fault'"); got != "0" {
			t.Errorf("a create whose file was not stored kept %s rows", got)
		}
		// A request with no file is the client's to fix.
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, uploadRequest(t, "POST", "/api/_upload", sid, map[string]string{"kind": "avatars"}))
		if w.Code != http.StatusBadRequest {
			t.Errorf("an upload with no file: %d %s, want 400", w.Code, w.Body.String())
		}
	}
	t.Run("media store", func(t *testing.T) {
		app := newGateApp(t, docsTable)
		_, sid := gateUser(t, app, "owner@example.com")
		withPlatformMedia(t, &PlatformMediaConfig{Bucket: "media", Region: "us-east-1", CDNDomain: "cdn.example.test"})
		startFakeMediaBroker(t, map[string]any{"error": "presign failed"})
		check(t, app, sid, http.StatusBadGateway)
	})
	t.Run("local disk", func(t *testing.T) {
		app := newGateApp(t, docsTable)
		_, sid := gateUser(t, app, "owner@example.com")
		// A file where the uploads directory belongs: nothing can be saved.
		uploads := filepath.Join(app.Dir, "uploads")
		if err := os.RemoveAll(uploads); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(uploads, []byte("not a directory"), 0o644); err != nil {
			t.Fatal(err)
		}
		check(t, app, sid, http.StatusInternalServerError)
	})
}

// The feedback page of the admin panel answers a signed-out caller as every
// other admin page does: the redirect to sign-in, from the panel's own gate.
// (The page function's own 403 for a missing session is behind that gate.)
func TestFeedbackAdminSignedOutRedirectsToSignIn(t *testing.T) {
	app := authzApp(t)
	on := true
	if app.Design == nil {
		app.Design = &DesignConfig{}
	}
	app.Design.Features = &FeaturesConfig{Testing: &on}
	app.Paths = DiscoverAuthPaths(nil)
	EnsureFeedbackTables(app.DB)
	mux := http.NewServeMux()
	RegisterAdminRoutes(mux, app)
	for _, path := range []string{"/_admin/feedback", "/_admin/tools"} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if loc := w.Header().Get("Location"); w.Code != http.StatusSeeOther || !strings.HasPrefix(loc, app.Paths.Login) {
			t.Errorf("signed-out GET %s: %d Location %q, want 303 to %s", path, w.Code, loc, app.Paths.Login)
		}
	}
	member := authzUser(t, app, "member@example.com", "user")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, authzReq("GET", "/_admin/feedback", authzSession(t, app, member, "member@example.com"), ""))
	if w.Code != http.StatusForbidden {
		t.Errorf("signed-in member GET /_admin/feedback: %d, want 403", w.Code)
	}
}
