//go:build !cli

package main

import (
	"encoding/base32"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// stepClient drives an app mux like a browser: one origin, a cookie jar,
// and the Origin header a same-origin fetch or form post sends.
type stepClient struct {
	t    *testing.T
	mux  http.Handler
	jar  map[string]string
	base string
}

func (c *stepClient) do(method, path, contentType, body string, header map[string]string) *httptest.ResponseRecorder {
	c.t.Helper()
	r := httptest.NewRequest(method, c.base+path, strings.NewReader(body))
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	if method != http.MethodGet {
		r.Header.Set("Origin", c.base)
	}
	for k, v := range header {
		r.Header.Set(k, v)
	}
	for name, value := range c.jar {
		r.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	w := httptest.NewRecorder()
	c.mux.ServeHTTP(w, r)
	for _, ck := range w.Result().Cookies() {
		if ck.MaxAge < 0 || ck.Value == "" {
			delete(c.jar, ck.Name)
		} else {
			c.jar[ck.Name] = ck.Value
		}
	}
	return w
}

func (c *stepClient) json(method, path string, body any) (*httptest.ResponseRecorder, map[string]any) {
	c.t.Helper()
	raw, _ := json.Marshal(body)
	w := c.do(method, path, "application/json", string(raw), map[string]string{
		"Accept": "application/json", "X-CSRF-Token": authMintCSRFToken(""),
	})
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w, out
}

func (c *stepClient) signedIn() bool {
	for name, value := range c.jar {
		if strings.Contains(name, "benmore_session") && value != "" {
			return true
		}
	}
	return false
}

func (c *stepClient) hasCookie(base string) bool {
	return c.jar[base] != "" || c.jar["__Host-"+base] != ""
}

// stepPagesApp is the unmodified HTML scaffold, served, with auth.yaml's
// require_mfa_for_roles listing "manager", an MFA-enrolled member and a
// manager who has not enrolled.
func stepPagesApp(t *testing.T) (*App, http.Handler, string, []string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "steps")
	if err := writeHTMLScaffoldFiles(dir, "Steps", false); err != nil {
		t.Fatal(err)
	}
	yamlPath := filepath.Join(dir, "app.yaml")
	conf, err := os.ReadFile(yamlPath)
	if err != nil {
		t.Fatal(err)
	}
	conf = []byte(strings.Replace(string(conf), "auth:\n", "auth:\n  require_mfa_for_roles: \"manager\"\n", 1))
	if err := os.WriteFile(yamlPath, conf, 0o644); err != nil {
		t.Fatal(err)
	}
	app, err := loadAppForServerTests(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	// Building the mux creates the framework's auth tables.
	mux := buildAppMux(app, false, "http://steps.example.test")
	hash, err := generateBcryptHash([]byte("Steps!Password1"))
	if err != nil {
		t.Fatal(err)
	}
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("step-pages-fixture-1"))
	backups := []string{"backupone", "backuptwo"}
	var hashed []string
	for _, code := range backups {
		h, _ := bcrypt.GenerateFromPassword([]byte(code), bcrypt.MinCost)
		hashed = append(hashed, string(h))
	}
	codes, _ := json.Marshal(hashed)
	for _, u := range []struct{ email, role, secret, backups string }{
		{"mfa@steps.test", "user", secret, string(codes)},
		{"manager@steps.test", "manager", "", "[]"},
	} {
		if _, err := app.DB.Exec(`INSERT INTO _benmore_users (username, email, password_hash, verified, role, totp_secret, backup_codes)
			VALUES (?, ?, ?, 1, ?, NULLIF(?, ''), ?)`, strings.Split(u.email, "@")[0], u.email, string(hash), u.role, u.secret, u.backups); err != nil {
			t.Fatal(err)
		}
	}
	return app, mux, secret, backups
}

func newStepClient(t *testing.T, mux http.Handler) *stepClient {
	return &stepClient{t: t, mux: mux, jar: map[string]string{}, base: "http://steps.example.test"}
}

// The finding (round 2026-11-05 F7): an MFA user signing in from the
// scaffold's login page got a 303 to /verify-mfa even for the JSON request
// bm.auth.signIn sends; fetch followed it to a page the scaffold did not ship
// (404) and the login form showed that 404's HTML. A JSON sign-in now gets
// the step as JSON with the step cookie set, the scaffold serves the step
// page, and posting the page's form signs the person in.
func TestJSONLoginMFAStepAndScaffoldVerifyPage(t *testing.T) {
	_, mux, secret, backups := stepPagesApp(t)

	c := newStepClient(t, mux)
	w, body := c.json(http.MethodPost, "/login", map[string]string{"email": "mfa@steps.test", "password": "Steps!Password1", "next": "/notes?x=1"})
	if w.Code != http.StatusOK || body["mfa_required"] != true || body["redirect"] != "/verify-mfa?next=%2Fnotes%3Fx%3D1" {
		t.Fatalf("JSON login of an MFA user: %d %v (Location %q)", w.Code, body, w.Header().Get("Location"))
	}
	if !c.hasCookie(flowCookieMFA) || c.signedIn() {
		t.Fatalf("JSON MFA step must set the step cookie and no session: %v", c.jar)
	}

	// The page the SDK navigates to is the scaffold's, not the SPA home.
	page := c.do(http.MethodGet, "/verify-mfa?next=%2Fnotes%3Fx%3D1", "", "", map[string]string{"Accept": "text/html"})
	html := page.Body.String()
	if page.Code != http.StatusOK || !strings.Contains(html, `id="verify-mfa-form"`) || !strings.Contains(html, `action="/verify-mfa"`) ||
		!strings.Contains(html, `name="mfa_code"`) || !strings.Contains(html, `name="next"`) || strings.Contains(html, `data-route="home"`) {
		t.Fatalf("GET /verify-mfa did not serve the code page: %d %.300s", page.Code, html)
	}

	// The page's form post (no script): the code and next go back, the
	// person lands on next with a session.
	form := url.Values{"mfa_code": {GenerateTOTP(secret)}, "next": {"/notes?x=1"}, "_csrf": {authMintCSRFToken("")}}
	w = c.do(http.MethodPost, "/verify-mfa", "application/x-www-form-urlencoded", form.Encode(), map[string]string{"Accept": "text/html"})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/notes?x=1" || !c.signedIn() {
		t.Fatalf("verify-mfa form post: %d Location=%q signed in=%v body=%.200s", w.Code, w.Header().Get("Location"), c.signedIn(), w.Body.String())
	}

	// A JSON caller of the step (bm.api.post('/verify-mfa', ...)) gets the
	// user like /login answers, with a backup code this time.
	c2 := newStepClient(t, mux)
	if w, body = c2.json(http.MethodPost, "/login", map[string]string{"email": "mfa@steps.test", "password": "Steps!Password1"}); body["redirect"] != "/verify-mfa" {
		t.Fatalf("JSON login without next: %d %v", w.Code, body)
	}
	w, body = c2.json(http.MethodPost, "/verify-mfa", map[string]string{"code": "wrong-code"})
	if w.Code != http.StatusBadRequest || body["error"] != "Invalid MFA code" || c2.signedIn() {
		t.Fatalf("JSON verify-mfa with a wrong code: %d %v", w.Code, body)
	}
	w, body = c2.json(http.MethodPost, "/verify-mfa", map[string]string{"code": backups[0]})
	user, _ := body["user"].(map[string]any)
	if w.Code != http.StatusOK || body["ok"] != true || user["email"] != "mfa@steps.test" || !c2.signedIn() {
		t.Fatalf("JSON verify-mfa: %d %v", w.Code, body)
	}

	// A browser form login keeps the 303 (now carrying next).
	c3 := newStepClient(t, mux)
	form = url.Values{"email": {"mfa@steps.test"}, "password": {"Steps!Password1"}, "next": {"/notes"}, "_csrf": {authMintCSRFToken("")}}
	w = c3.do(http.MethodPost, "/login", "application/x-www-form-urlencoded", form.Encode(), map[string]string{"Accept": "text/html"})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/verify-mfa?next=%2Fnotes" || !c3.hasCookie(flowCookieMFA) {
		t.Fatalf("form login of an MFA user: %d %q", w.Code, w.Header().Get("Location"))
	}
}

// A role in auth.require_mfa_for_roles signing in with JSON gets the
// enrollment step as JSON; the scaffold's /mfa-setup page drives
// /api/_auth/mfa/setup + /verify with the setup cookie and ends signed in.
func TestJSONLoginMFASetupStepAndScaffoldSetupPage(t *testing.T) {
	_, mux, _, _ := stepPagesApp(t)
	c := newStepClient(t, mux)
	w, body := c.json(http.MethodPost, "/login", map[string]string{"email": "manager@steps.test", "password": "Steps!Password1"})
	if w.Code != http.StatusOK || body["mfa_setup_required"] != true || body["redirect"] != "/mfa-setup" {
		t.Fatalf("JSON login of a role that must enroll: %d %v (Location %q)", w.Code, body, w.Header().Get("Location"))
	}
	if _, leaked := body["setup_token"]; leaked || !c.hasCookie(flowCookieMFASetup) || c.signedIn() {
		t.Fatalf("browser enrollment step must ride the cookie only: body=%v jar=%v", body, c.jar)
	}
	page := c.do(http.MethodGet, "/mfa-setup", "", "", map[string]string{"Accept": "text/html"})
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), `id="mfa-setup"`) || !strings.Contains(page.Body.String(), `id="mfa-setup-form"`) {
		t.Fatalf("GET /mfa-setup did not serve the setup page: %d %.300s", page.Code, page.Body.String())
	}
	// What lib/auth.ts initMFASetup does: bm.mfa.enroll() then bm.mfa.verify(code).
	w, body = c.json(http.MethodPost, "/api/_auth/mfa/setup", map[string]string{})
	secret, _ := body["secret"].(string)
	if w.Code != http.StatusOK || secret == "" {
		t.Fatalf("setup with the enrollment cookie: %d %v", w.Code, body)
	}
	w, body = c.json(http.MethodPost, "/api/_auth/mfa/verify", map[string]string{"code": GenerateTOTP(secret)})
	if w.Code != http.StatusOK || body["status"] != "mfa_enabled" || !c.signedIn() {
		t.Fatalf("verify with the enrollment cookie: %d %v", w.Code, body)
	}
}

// Every path the sign-in handlers send a person to is a page in the
// scaffold, posting to the handler for that path, and the shared bundle the
// pages load compiles.
func TestScaffoldServesEverySignInStepPage(t *testing.T) {
	_, mux, _, _ := stepPagesApp(t)
	c := newStepClient(t, mux)
	for path, want := range map[string][]string{
		"/verify-mfa":                     {`action="/verify-mfa"`, `name="mfa_code"`},
		"/mfa-setup":                      {`id="mfa-setup-form"`, `name="code"`},
		"/verify-otp?next=%2Fnotes":       {`action="/verify-otp"`, `name="code"`, `name="next"`},
		"/forgot-password":                {`action="/forgot-password"`, `name="email"`, `name="_csrf"`},
		"/reset-password?token=abc1":      {`action="/reset-password"`, `name="token"`, `name="password"`, `name="confirm"`},
		"/login?success=Password+updated": {`class="success`, `href="/forgot-password"`},
	} {
		w := c.do(http.MethodGet, path, "", "", map[string]string{"Accept": "text/html"})
		html := w.Body.String()
		if w.Code != http.StatusOK || strings.Contains(html, `data-route="home"`) || !strings.Contains(html, "data-auth-page") {
			t.Errorf("GET %s: %d, not a sign-in page: %.200s", path, w.Code, html)
			continue
		}
		for _, s := range want {
			if !strings.Contains(html, s) {
				t.Errorf("GET %s: page lacks %s", path, s)
			}
		}
	}
	w := c.do(http.MethodGet, "/static/app.js", "", "", nil)
	js, _ := io.ReadAll(w.Result().Body)
	if w.Code != http.StatusOK || !strings.Contains(w.Header().Get("Content-Type"), "javascript") || !strings.Contains(string(js), "mfa-setup-form") || !strings.Contains(string(js), "data-auth-page") {
		t.Fatalf("scaffold bundle: %d %q %.300s", w.Code, w.Header().Get("Content-Type"), js)
	}
}
