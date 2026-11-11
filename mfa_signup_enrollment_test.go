//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	esbuild "github.com/benmore-studio/benmore/third_party/esbuild/pkg/api"
	"github.com/dop251/goja"
	"golang.org/x/crypto/bcrypt"
)

const signupMFAPassword = "Signup!Password1"

// signupMFAApp is the unmodified HTML scaffold with authLines added under
// app.yaml's auth:, served behind the enrollment gate as the server mounts it.
func signupMFAApp(t *testing.T, authLines ...string) (*App, http.Handler) {
	t.Helper()
	return signupMFAAppWithFiles(t, nil, authLines...)
}

// signupMFAAppWithFiles also writes files (app-relative path to content).
func signupMFAAppWithFiles(t *testing.T, files map[string]string, authLines ...string) (*App, http.Handler) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "signup")
	if err := writeHTMLScaffoldFiles(dir, "Signup", false); err != nil {
		t.Fatal(err)
	}
	for rel, content := range files {
		if err := os.WriteFile(filepath.Join(dir, rel), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	yamlPath := filepath.Join(dir, "app.yaml")
	conf, err := os.ReadFile(yamlPath)
	if err != nil {
		t.Fatal(err)
	}
	added := ""
	for _, line := range authLines {
		added += "  " + line + "\n"
	}
	if !strings.Contains(string(conf), "auth:\n") {
		t.Fatal("scaffold app.yaml has no auth: block")
	}
	if err := os.WriteFile(yamlPath, []byte(strings.Replace(string(conf), "auth:\n", "auth:\n"+added, 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	app, err := loadAppForServerTests(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	mux := buildAppMux(app, false, "http://steps.example.test")
	return app, requestSessionCacheMiddleware(mfaEnrollmentMiddleware(mux, app))
}

func signupMFASessions(t *testing.T, app *App, email string) int {
	t.Helper()
	var n int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_sessions WHERE user_id IN (SELECT id FROM _benmore_users WHERE email=?)", email).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// signupMFAHeldClient is a browser holding a sign-in session of an account
// with no factor: one that signed in before the rule applied to it.
func signupMFAHeldClient(t *testing.T, app *App, h http.Handler, email string) (*stepClient, int64) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(signupMFAPassword), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	res, err := app.DB.Exec("INSERT INTO _benmore_users (username, email, password_hash, role, verified) VALUES (?, ?, ?, 'user', 1)", strings.Split(email, "@")[0], email, string(hash))
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := res.LastInsertId()
	c := newStepClient(t, h)
	c.jar[sessionCookieName] = createSignInSession(app.DB, uid, email, "", time.Hour)
	return c, uid
}

// compliance F1 (round 1110): POST /signup issued a full session without the
// enrollment decision every other sign-in makes. With the sign-up role listed
// in auth.require_mfa_for_roles (every account under compliance: hipaa) the
// new person held a session the gate refused everywhere. Sign-up now starts
// the enrollment step: the setup cookie, no session, and the step as JSON or
// a 303; the scaffold page's two calls then enroll and sign the person in.
func TestSignupStartsMFAEnrollmentInsteadOfASession(t *testing.T) {
	for _, roles := range []string{`"*"`, `"user"`, `"auditor, User"`} {
		app, h := signupMFAApp(t, "require_mfa_for_roles: "+roles)

		// JSON, as bm.auth.signUp sends it.
		c := newStepClient(t, h)
		w, body := c.json(http.MethodPost, "/signup", map[string]string{"email": "new@signup.test", "password": signupMFAPassword, "first_name": "New", "next": "/notes?x=1"})
		if w.Code != http.StatusOK || body["ok"] != true || body["mfa_setup_required"] != true || body["redirect"] != "/mfa-setup?next=%2Fnotes%3Fx%3D1" {
			t.Fatalf("roles %s: JSON sign-up: %d %v", roles, w.Code, body)
		}
		if _, leaked := body["user"]; leaked || body["setup_token"] != nil {
			t.Fatalf("roles %s: JSON sign-up step carries more than the step: %v", roles, body)
		}
		if c.signedIn() || !c.hasCookie(flowCookieMFASetup) || signupMFASessions(t, app, "new@signup.test") != 0 {
			t.Fatalf("roles %s: sign-up must set the setup cookie and no session: jar=%v sessions=%d", roles, c.jar, signupMFASessions(t, app, "new@signup.test"))
		}
		var first string
		if err := app.DB.QueryRow("SELECT COALESCE(first_name,'') FROM _benmore_users WHERE email='new@signup.test'").Scan(&first); err != nil || first != "New" {
			t.Fatalf("roles %s: the account was not created with its sign-up fields: %q %v", roles, first, err)
		}
		// Nothing is signed in yet.
		if w := c.do(http.MethodGet, "/api/_auth/profile", "", "", map[string]string{"Accept": "application/json"}); w.Code != http.StatusUnauthorized {
			t.Fatalf("roles %s: profile before enrollment: %d %s", roles, w.Code, w.Body.String())
		}
		// The page the SDK navigates to, then what its script sends:
		// bm.mfa.enroll() with no password, bm.mfa.verify(code).
		if page := c.do(http.MethodGet, "/mfa-setup?next=%2Fnotes%3Fx%3D1", "", "", map[string]string{"Accept": "text/html"}); page.Code != http.StatusOK || !strings.Contains(page.Body.String(), `id="mfa-setup-form"`) {
			t.Fatalf("roles %s: GET /mfa-setup: %d %.200s", roles, page.Code, page.Body.String())
		}
		w, body = c.json(http.MethodPost, "/api/_auth/mfa/setup", map[string]string{})
		secret, _ := body["secret"].(string)
		if w.Code != http.StatusOK || secret == "" {
			t.Fatalf("roles %s: setup with the sign-up's cookie: %d %v", roles, w.Code, body)
		}
		w, body = c.json(http.MethodPost, "/api/_auth/mfa/verify", map[string]string{"code": GenerateTOTP(secret)})
		if w.Code != http.StatusOK || body["status"] != "mfa_enabled" || !c.signedIn() || c.hasCookie(flowCookieMFASetup) {
			t.Fatalf("roles %s: verify with the sign-up's cookie: %d %v jar=%v", roles, w.Code, body, c.jar)
		}
		// Continue: the session verify issued acts.
		if w := c.do(http.MethodGet, "/api/_auth/profile", "", "", map[string]string{"Accept": "application/json"}); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "new@signup.test") {
			t.Fatalf("roles %s: profile after enrollment: %d %s", roles, w.Code, w.Body.String())
		}

		// A browser form post gets the 303.
		c2 := newStepClient(t, h)
		form := url.Values{"email": {"form@signup.test"}, "password": {signupMFAPassword}, "first_name": {"Form"}, "_csrf": {authMintCSRFToken("")}}
		w = c2.do(http.MethodPost, "/signup", "application/x-www-form-urlencoded", form.Encode(), map[string]string{"Accept": "text/html"})
		if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/mfa-setup" {
			t.Fatalf("roles %s: form sign-up: %d Location=%q", roles, w.Code, w.Header().Get("Location"))
		}
		if c2.signedIn() || !c2.hasCookie(flowCookieMFASetup) || signupMFASessions(t, app, "form@signup.test") != 0 {
			t.Fatalf("roles %s: form sign-up must set the setup cookie and no session: jar=%v", roles, c2.jar)
		}
	}
}

// Sign-up is unchanged where the new account need not enroll, and the steps
// that come before enrollment at /login come before it here too.
func TestSignupWithoutRequiredEnrollmentIsUnchanged(t *testing.T) {
	signup := func(lines ...string) (*stepClient, int, map[string]any) {
		_, h := signupMFAApp(t, lines...)
		c := newStepClient(t, h)
		w, body := c.json(http.MethodPost, "/signup", map[string]string{"email": "plain@signup.test", "password": signupMFAPassword, "first_name": "Plain"})
		return c, w.Code, body
	}
	// No rule, and a rule that does not list the sign-up role: a session.
	for _, lines := range [][]string{nil, {`require_mfa_for_roles: "manager"`}} {
		c, code, body := signup(lines...)
		user, _ := body["user"].(map[string]any)
		if code != http.StatusOK || body["ok"] != true || user["email"] != "plain@signup.test" || !c.signedIn() || c.hasCookie(flowCookieMFASetup) {
			t.Fatalf("%v: sign-up: %d %v jar=%v", lines, code, body, c.jar)
		}
	}
	// auth.otp: the emailed code first; the OTP step decides on enrollment.
	c, code, body := signup(`require_mfa_for_roles: "*"`, `otp: true`)
	if code != http.StatusOK || body["otp_required"] != true || c.signedIn() || c.hasCookie(flowCookieMFASetup) || !c.hasCookie(flowCookieOTP) {
		t.Fatalf("otp sign-up: %d %v jar=%v", code, body, c.jar)
	}
	// auth.require_verified: no step that would end in a session it refuses.
	c, code, body = signup(`require_mfa_for_roles: "*"`, `require_verified: true`)
	if code != http.StatusForbidden || body["error"] != emailVerificationRequiredCode || c.signedIn() || c.hasCookie(flowCookieMFASetup) {
		t.Fatalf("require_verified sign-up: %d %v jar=%v", code, body, c.jar)
	}
}

// The decision is made for the account as created. A role an on_insert hook
// assigns afterwards (hooks are queued jobs; one live app turns a sign-up
// field into its role this way) is not seen at sign-up: that sign-up keeps
// answering with a session, whenever the job runs, and the account is held
// from its next request. The scaffold's setup page then enrolls it.
func TestSignupRoleAssignedByAHookIsHeldAndEnrollsFromThePage(t *testing.T) {
	app, h := signupMFAAppWithFiles(t, map[string]string{
		"hooks.yaml": "on_insert:\n  _benmore_users:\n    - sql: \"UPDATE _benmore_users SET role = 'manager' WHERE id = {{id}}\"\n",
	}, `require_mfa_for_roles: "manager"`)
	c := newStepClient(t, h)
	w, body := c.json(http.MethodPost, "/signup", map[string]string{"email": "hooked@signup.test", "password": signupMFAPassword, "first_name": "Hooked"})
	user, _ := body["user"].(map[string]any)
	if w.Code != http.StatusOK || user["email"] != "hooked@signup.test" || !c.signedIn() || c.hasCookie(flowCookieMFASetup) {
		t.Fatalf("sign-up whose role a hook assigns later: %d %v jar=%v", w.Code, body, c.jar)
	}
	FlushJobs(app)
	var role string
	if err := app.DB.QueryRow("SELECT role FROM _benmore_users WHERE email='hooked@signup.test'").Scan(&role); err != nil || role != "manager" {
		t.Fatalf("the on_insert hook did not assign the role: %q %v", role, err)
	}
	if w := c.do(http.MethodGet, "/api/_auth/profile", "", "", map[string]string{"Accept": "application/json"}); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), mfaEnrollmentRequiredError) {
		t.Fatalf("session after the hook listed its role: %d %s", w.Code, w.Body.String())
	}
	p := openScaffoldAuthPage(t, app, c, "/mfa-setup")
	if got := p.eval(`shown()`); got != "password signout" {
		t.Fatalf("setup page shows %q, want the password form and sign-out", got)
	}
	p.vm.Set("password", signupMFAPassword)
	p.eval(`submit('#mfa-setup-password-form', {password: password})`)
	p.vm.Set("code", GenerateTOTP(p.eval(`el('.mfa-secret').textContent`)))
	p.eval(`submit('#mfa-setup-form', {code: code})`)
	if got := p.eval(`location.href`); got != "/" {
		t.Fatalf("after enrolling the page went to %q (page shows %q)", got, p.eval(`shown()`))
	}
	if w := c.do(http.MethodGet, "/api/_auth/profile", "", "", map[string]string{"Accept": "application/json"}); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "hooked@signup.test") {
		t.Fatalf("profile after enrolling from the page: %d %s", w.Code, w.Body.String())
	}
}

// A held credential may reach the sign-in pages under their file names too:
// scaffolds link to /login.html and /signup.html, and the gate sent those
// back to the setup page, whose only link was /login.html.
func TestMFAEnrollmentStepRequestCoversSignInPageFileNames(t *testing.T) {
	app := &App{Paths: DiscoverAuthPaths(nil), Design: &DesignConfig{Auth: map[string]string{"require_mfa_for_roles": "*"}}}
	custom := &App{Paths: DiscoverAuthPaths(nil), Design: app.Design}
	custom.Paths.Login = "/signin"
	for _, c := range []struct {
		app          *App
		method, path string
		want         bool
	}{
		{app, "GET", "/login", true}, {app, "GET", "/login.html", true},
		{app, "GET", "/signup", true}, {app, "GET", "/signup.html", true},
		{app, "GET", "/forgot-password", true}, {app, "GET", "/forgot-password.html", true},
		{app, "POST", "/login", true}, {app, "POST", "/signup", true}, {app, "POST", "/forgot-password", true},
		{app, "POST", "/logout", true}, {app, "GET", "/mfa-setup", true}, {app, "GET", "/api/_csrf", true},
		{custom, "GET", "/signin", true}, {custom, "GET", "/signin.html", true}, {custom, "GET", "/login.html", false},
		// Only the sign-in pages, only as pages.
		{app, "GET", "/", false}, {app, "GET", "/index.html", false}, {app, "GET", "/notes", false}, {app, "GET", "/notes.html", false},
		{app, "GET", "/settings", false}, {app, "GET", "/settings.html", false}, {app, "GET", "/logout.html", false},
		{app, "GET", "/login.htm", false}, {app, "GET", "/login.html/x", false}, {app, "GET", "/x/login.html", false},
		{app, "GET", "/login.html.html", false}, {app, "GET", "/loginx.html", false}, {app, "GET", "/.html", false},
		{app, "POST", "/login.html", false}, {app, "DELETE", "/login", false}, {app, "GET", "/logout", false},
		{app, "GET", "/api/notes", false}, {app, "POST", "/api/_auth/api-tokens", false}, {app, "POST", "/api/notes", false},
	} {
		r, err := http.NewRequest(c.method, "http://steps.example.test"+c.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := mfaEnrollmentStepRequest(c.app, r); got != c.want {
			t.Errorf("%s %s (login page %s): step request = %v, want %v", c.method, c.path, c.app.Paths.Login, got, c.want)
		}
	}
}

// An app scaffolded before this fix keeps its pages: its setup page links to
// /login.html, and signing in again from there is its way to enroll (the
// sign-in issues the setup cookie, which needs no password).
func TestHeldSessionReachesSignInPagesByFileName(t *testing.T) {
	app, h := signupMFAApp(t, `require_mfa_for_roles: "*"`)
	c, _ := signupMFAHeldClient(t, app, h, "held@signup.test")
	html := map[string]string{"Accept": "text/html"}
	for path, want := range map[string]string{
		"/login.html": `id="login-form"`, "/signup.html": `id="signup-form"`, "/forgot-password.html": `id="forgot-password-form"`,
		"/login": `id="login-form"`, "/signup": `id="signup-form"`, "/forgot-password": `id="forgot-password-form"`,
	} {
		if w := c.do(http.MethodGet, path, "", "", html); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), want) {
			t.Errorf("held session GET %s: %d Location=%q, want the page with %s", path, w.Code, w.Header().Get("Location"), want)
		}
	}
	for _, path := range []string{"/", "/index.html", "/notes"} {
		if w := c.do(http.MethodGet, path, "", "", html); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/mfa-setup" {
			t.Errorf("held session GET %s: %d Location=%q, want the setup page", path, w.Code, w.Header().Get("Location"))
		}
	}
	if w := c.do(http.MethodGet, "/api/notes", "", "", map[string]string{"Accept": "application/json"}); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), mfaEnrollmentRequiredError) {
		t.Fatalf("held session GET /api/notes: %d %s", w.Code, w.Body.String())
	}
	// Signing in again from the login page, then the old page's enroll() with
	// no password.
	w, body := c.json(http.MethodPost, "/login", map[string]string{"email": "held@signup.test", "password": signupMFAPassword})
	if w.Code != http.StatusOK || body["mfa_setup_required"] != true || !c.hasCookie(flowCookieMFASetup) {
		t.Fatalf("held session signing in again: %d %v", w.Code, body)
	}
	if w, body = c.json(http.MethodPost, "/api/_auth/mfa/setup", map[string]string{}); w.Code != http.StatusOK || body["secret"] == nil {
		t.Fatalf("enroll() with the setup cookie beside a held session: %d %v", w.Code, body)
	}
}

// ---- the scaffold's page script and the SDK, run against the app ----

// sdkPageVM runs embedded/bm.js's request layer, bm.mfa and bm.auth.signOut as
// shipped, with fetch going to the app through c: the browser's cookie jar and
// origin. No browser is started.
type sdkPageVM struct {
	t  *testing.T
	vm *goja.Runtime
}

func newSDKPageVM(t *testing.T, c *stepClient, csrf string) *sdkPageVM {
	t.Helper()
	src, err := os.ReadFile("embedded/bm.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(src)
	cut := func(from, to string) string {
		t.Helper()
		i := strings.Index(js, from)
		if i < 0 {
			t.Fatalf("embedded/bm.js: %q not found", from)
		}
		j := strings.Index(js[i:], to)
		if j < 0 {
			t.Fatalf("embedded/bm.js: end %q after %q not found", to, from)
		}
		return js[i : i+j+len(to)]
	}
	core := strings.TrimSuffix(cut("const CSRF_META", "export const api = {"), "export const api = {")
	api := strings.Replace(cut("export const api = {", "\n};\n"), "export const api", "const api", 1)
	signOut := cut("async function signOut() {", "\n}\n")
	mfa := strings.Replace(cut("export const mfa = {", "\n};\n"), "export const mfa", "const mfa", 1)

	vm := goja.New()
	vm.Set("csrfToken", csrf)
	vm.Set("goFetch", func(method, path string, headers map[string]any, body any) map[string]any {
		h := map[string]string{}
		for k, v := range headers {
			h[k] = fmt.Sprint(v)
		}
		payload := ""
		if s, ok := body.(string); ok {
			payload = s
		}
		w := c.do(method, path, h["content-type"], payload, h)
		return map[string]any{"status": w.Code, "type": w.Header().Get("Content-Type"), "body": w.Body.String()}
	})
	harness := `
var requests = [];
function Headers(init) {
  this.m = {};
  if (init) for (var k in init) this.m[k.toLowerCase()] = init[k];
}
Headers.prototype.set = function (k, v) { this.m[k.toLowerCase()] = String(v); };
Headers.prototype.get = function (k) { var v = this.m[k.toLowerCase()]; return v === undefined ? null : v; };
Headers.prototype.forEach = function (fn) { for (var k in this.m) fn(this.m[k], k); };
var document = { querySelector: function (sel) { return sel === 'meta[name="csrf-token"]' ? { content: csrfToken } : null; } };
function observeSessionResponse() {}
function captureRequest() {}
async function fetch(url, init) {
  init = init || {};
  var method = init.method || 'GET';
  var body = init.body === undefined ? null : init.body;
  requests.push({ method: method, url: url, body: body });
  var r = goFetch(method, url, init.headers ? init.headers.m : {}, body);
  var h = {};
  if (r.type) h['content-type'] = r.type;
  return {
    status: r.status, ok: r.status >= 200 && r.status < 300, redirected: false, url: '', headers: new Headers(h),
    text: async function () { return r.body; },
    blob: async function () { return { isBlob: true }; },
    json: async function () { return JSON.parse(r.body); },
  };
}
var out;
function run(p) {
  out = undefined;
  p.then(function (v) { out = { value: v }; }, function (e) { out = { error: String(e && e.message), status: e && e.status }; });
}
`
	if _, err := vm.RunString(harness + core + api + signOut + mfa + "\nvar fixtureBM = { api: api, mfa: mfa, auth: { signOut: signOut } };\n"); err != nil {
		t.Fatalf("embedded/bm.js request, mfa and signOut do not load: %v", err)
	}
	return &sdkPageVM{t: t, vm: vm}
}

// eval runs js (promise jobs it starts finish before it returns) and returns
// the value as a string.
func (p *sdkPageVM) eval(js string) string {
	p.t.Helper()
	v, err := p.vm.RunString(js)
	if err != nil {
		p.t.Fatalf("%s: %v", js, err)
	}
	return v.String()
}

var csrfMetaRe = regexp.MustCompile(`<meta name="csrf-token" content="([^"]+)"`)

// openScaffoldAuthPage loads path as the browser would: it fetches the page
// with c's cookies, compiles the scaffold's static/lib/auth.ts as written,
// and runs initAuthPage (what app.tsx calls on a sign-in page) on a DOM that
// holds exactly the elements the served HTML has, hidden where it hides them.
func openScaffoldAuthPage(t *testing.T, app *App, c *stepClient, path string) *sdkPageVM {
	t.Helper()
	w := c.do(http.MethodGet, path, "", "", map[string]string{"Accept": "text/html"})
	html := w.Body.String()
	meta := csrfMetaRe.FindStringSubmatch(html)
	if w.Code != http.StatusOK || meta == nil {
		t.Fatalf("GET %s: %d, no CSRF meta: %.200s", path, w.Code, html)
	}
	script, err := os.ReadFile(filepath.Join(app.Dir, "static", "lib", "auth.ts"))
	if err != nil {
		t.Fatal(err)
	}
	compiled := esbuild.Build(esbuild.BuildOptions{
		Stdin:  &esbuild.StdinOptions{Contents: string(script), Loader: esbuild.LoaderTS},
		Bundle: true, Write: false, Format: esbuild.FormatIIFE, GlobalName: "page", Target: esbuild.ES2020,
		Plugins: []esbuild.Plugin{{Name: "fixture-bm", Setup: func(build esbuild.PluginBuild) {
			build.OnResolve(esbuild.OnResolveOptions{Filter: "^bm$"}, func(args esbuild.OnResolveArgs) (esbuild.OnResolveResult, error) {
				return esbuild.OnResolveResult{Path: args.Path, Namespace: "fixture"}, nil
			})
			build.OnLoad(esbuild.OnLoadOptions{Filter: ".*", Namespace: "fixture"}, func(args esbuild.OnLoadArgs) (esbuild.OnLoadResult, error) {
				source := "export default globalThis.fixtureBM;"
				return esbuild.OnLoadResult{Contents: &source, Loader: esbuild.LoaderJS}, nil
			})
		}}},
	})
	if len(compiled.Errors) != 0 {
		t.Fatalf("compile the scaffold's lib/auth.ts: %v", compiled.Errors)
	}
	p := newSDKPageVM(t, c, meta[1])
	search := ""
	if i := strings.Index(path, "?"); i >= 0 {
		search = path[i:]
	}
	p.vm.Set("pageHTML", html)
	p.vm.Set("pageSearch", search)
	p.vm.Set("pageURL", c.base+path)
	if _, err := p.vm.RunString(`
var els = {};
function tagOf(sel) {
  var m, re;
  if ((m = /^#([\w-]+)$/.exec(sel))) re = new RegExp('<[a-z0-9]+\\s(?:[^>]*\\s)?id="' + m[1] + '"[^>]*>');
  else if ((m = /^\.([\w-]+)$/.exec(sel))) re = new RegExp('<[a-z0-9]+\\s(?:[^>]*\\s)?class="(?:[^"]*\\s)?' + m[1] + '(?:\\s[^"]*)?"[^>]*>');
  else if ((m = /^\[([\w-]+)="([^"]*)"\]$/.exec(sel))) re = new RegExp('<[a-z0-9]+\\s(?:[^>]*\\s)?' + m[1] + '="' + m[2] + '"[^>]*>');
  else return null;
  m = re.exec(pageHTML);
  return m ? m[0] : null;
}
// el is the page's element for a selector the scaffold script uses (#id,
// .class, [attr="v"]), or null when the served HTML has none.
function el(sel) {
  if (sel in els) return els[sel];
  var tag = tagOf(sel);
  if (!tag) return (els[sel] = null);
  var e = { tag: tag, hidden: /\shidden(?=[\s>])/.test(tag), textContent: '', href: '', handlers: {}, values: {} };
  e.addEventListener = function (type, fn) { e.handlers[type] = fn; };
  e.querySelector = function (s) { return el(s); };
  return (els[sel] = e);
}
document = {
  querySelector: function (sel) { return sel === 'meta[name="csrf-token"]' ? { content: csrfToken } : el(sel); },
  getElementById: function (id) { return el('#' + id); },
  querySelectorAll: function () { return []; },
};
var location = { origin: pageURL.split('/').slice(0, 3).join('/'), search: pageSearch, href: pageURL, assign: function (u) { this.href = u; }, reload: function () { this.reloaded = true; } };
function URLSearchParams(s) {
  var m = this.m = {};
  String(s || '').replace(/^\?/, '').split('&').forEach(function (kv) {
    if (!kv) return;
    var i = kv.indexOf('=');
    var k = decodeURIComponent((i < 0 ? kv : kv.slice(0, i)).replace(/\+/g, ' '));
    if (!(k in m)) m[k] = decodeURIComponent((i < 0 ? '' : kv.slice(i + 1)).replace(/\+/g, ' '));
  });
}
URLSearchParams.prototype.get = function (k) { return k in this.m ? this.m[k] : null; };
function FormData(form) {
  this.get = function (k) { var v = form.values[k]; return v === undefined ? null : v; };
  this.entries = function () { return Object.keys(form.values).map(function (k) { return [k, form.values[k]]; }); };
}
function submit(sel, values) { var f = el(sel); f.values = values || {}; return f.handlers.submit({ preventDefault: function () {} }); }
function click(sel) { return el(sel).handlers.click({ preventDefault: function () {} }); }
// shown lists which of the setup page's parts are visible, and its message.
function shown() {
  var s = [];
  [['password', '#mfa-setup-password-form'], ['key', '.mfa-key'], ['code', '#mfa-setup-form'], ['signout', '.mfa-signout'], ['error', '.error']].forEach(function (p) {
    var e = el(p[1]);
    if (e && !e.hidden) s.push(p[0] === 'error' ? 'error:' + e.textContent : p[0]);
  });
  return s.join(' ');
}
`); err != nil {
		t.Fatal(err)
	}
	if _, err := p.vm.RunString(string(compiled.OutputFiles[0].Contents)); err != nil {
		t.Fatalf("the scaffold's lib/auth.ts does not load: %v", err)
	}
	p.eval(`run(page.initAuthPage())`)
	if out := p.eval(`JSON.stringify(out)`); out != `{}` {
		t.Fatalf("initAuthPage on %s did not finish cleanly: %s", path, out)
	}
	return p
}

var backToLoginRe = regexp.MustCompile(`<a href="([^"]+)"[^>]*>Back to log in</a>`)

// compliance F1, the page: a person who holds a session when the rule starts
// to apply (the key was just turned on, a role was granted, they turned their
// factor off) is sent to /mfa-setup signed in. The scaffold page called
// bm.mfa.enroll() with no password, showed the server's "password required to
// enable MFA" with no field to type one and no sign-out, and its only link
// came back to the same page. The page's own script now asks for the
// password, enrolls, and the same session works again.
func TestScaffoldMFASetupPageEnrollsAHeldSession(t *testing.T) {
	app, h := signupMFAApp(t, `require_mfa_for_roles: "*"`)
	c, uid := signupMFAHeldClient(t, app, h, "held@signup.test")
	if w := c.do(http.MethodGet, "/notes", "", "", map[string]string{"Accept": "text/html"}); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/mfa-setup" {
		t.Fatalf("held session navigation: %d %q", w.Code, w.Header().Get("Location"))
	}

	p := openScaffoldAuthPage(t, app, c, "/mfa-setup?next=%2Fnotes")
	if got := p.eval(`shown()`); got != "password signout" {
		t.Fatalf("setup page for a held session shows %q, want the password form and sign-out", got)
	}
	// A wrong password says so and leaves the form up.
	p.eval(`submit('#mfa-setup-password-form', {password: 'not-the-password'})`)
	if got := p.eval(`shown()`); got != "password signout error:incorrect password" {
		t.Fatalf("after a wrong password the page shows %q", got)
	}
	p.vm.Set("password", signupMFAPassword)
	p.eval(`submit('#mfa-setup-password-form', {password: password})`)
	if got := p.eval(`shown()`); got != "key code signout" {
		t.Fatalf("after the password the page shows %q, want the key and the code form", got)
	}
	secret := p.eval(`el('.mfa-secret').textContent`)
	if len(secret) < 16 || !strings.Contains(p.eval(`el('.mfa-link').href`), "otpauth://totp/") || strings.Count(p.eval(`el('.mfa-backup-codes').textContent`), "\n") != 9 {
		t.Fatalf("key view: secret=%q link=%q codes=%q", secret, p.eval(`el('.mfa-link').href`), p.eval(`el('.mfa-backup-codes').textContent`))
	}
	// A wrong code stays on the page; the right one continues to ?next=.
	p.eval(`submit('#mfa-setup-form', {code: '000000'})`)
	if got := p.eval(`shown()`); !strings.HasPrefix(got, "key code signout error:") || p.eval(`location.href`) != "http://steps.example.test/mfa-setup?next=%2Fnotes" {
		t.Fatalf("after a wrong code the page shows %q at %s", got, p.eval(`location.href`))
	}
	code := GenerateTOTP(secret)
	p.vm.Set("code", code)
	p.eval(`submit('#mfa-setup-form', {code: code})`)
	if got := p.eval(`location.href`); got != "/notes" {
		t.Fatalf("after enrolling the page went to %q (page shows %q), want /notes", got, p.eval(`shown()`))
	}
	if !CheckMFA(app.DB, uid) {
		t.Fatal("the held session's account has no factor after the page finished")
	}
	// The same session acts again.
	if w := c.do(http.MethodGet, "/api/_auth/profile", "", "", map[string]string{"Accept": "application/json"}); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "held@signup.test") {
		t.Fatalf("profile with the session after enrollment: %d %s", w.Code, w.Body.String())
	}
	// What the page sent: enroll with no password, then with it; never the
	// password to verify.
	var sent []struct{ Method, URL, Body string }
	if err := json.Unmarshal([]byte(p.eval(`JSON.stringify(requests.map(function (r) { return {Method: r.method, URL: r.url, Body: r.body || ''}; }))`)), &sent); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 5 || sent[0].URL != "/api/_auth/mfa/setup" || sent[0].Body != "{}" || !strings.Contains(sent[2].Body, `"password":"`+signupMFAPassword+`"`) ||
		sent[3].URL != "/api/_auth/mfa/verify" || sent[4].Body != `{"code":"`+code+`"}` {
		t.Fatalf("requests the page made: %+v", sent)
	}
}

// The page offers sign-out to a held session, and its link back to log in
// reaches the login page.
func TestScaffoldMFASetupPageSignsOutAndLinksToLogin(t *testing.T) {
	app, h := signupMFAApp(t, `require_mfa_for_roles: "*"`)
	c, _ := signupMFAHeldClient(t, app, h, "held@signup.test")
	page := c.do(http.MethodGet, "/mfa-setup", "", "", map[string]string{"Accept": "text/html"})
	back := backToLoginRe.FindStringSubmatch(page.Body.String())
	if back == nil {
		t.Fatalf("setup page has no link back to log in: %.300s", page.Body.String())
	}
	if w := c.do(http.MethodGet, back[1], "", "", map[string]string{"Accept": "text/html"}); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `id="login-form"`) {
		t.Fatalf("held session following %q: %d Location=%q", back[1], w.Code, w.Header().Get("Location"))
	}

	p := openScaffoldAuthPage(t, app, c, "/mfa-setup")
	if got := p.eval(`shown()`); got != "password signout" {
		t.Fatalf("setup page for a held session shows %q", got)
	}
	p.eval(`click('[data-action="signout"]')`)
	if got := p.eval(`location.href`); got != "/login" {
		t.Fatalf("after sign-out the page went to %q", got)
	}
	if c.signedIn() || signupMFASessions(t, app, "held@signup.test") != 0 {
		t.Fatalf("sign-out left a session: jar=%v rows=%d", c.jar, signupMFASessions(t, app, "held@signup.test"))
	}
	if w := c.do(http.MethodGet, "/login", "", "", map[string]string{"Accept": "text/html"}); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `id="login-form"`) {
		t.Fatalf("login page after sign-out: %d", w.Code)
	}
}

// After a sign-up (or sign-in) that must enroll, the same page needs no
// password: the setup cookie is the proof, and verify signs the person in.
func TestScaffoldMFASetupPageAfterSignupNeedsNoPassword(t *testing.T) {
	app, h := signupMFAApp(t, `require_mfa_for_roles: "*"`)
	c := newStepClient(t, h)
	if w, body := c.json(http.MethodPost, "/signup", map[string]string{"email": "new@signup.test", "password": signupMFAPassword, "first_name": "New"}); body["redirect"] != "/mfa-setup" {
		t.Fatalf("sign-up: %d %v", w.Code, body)
	}
	p := openScaffoldAuthPage(t, app, c, "/mfa-setup")
	if got := p.eval(`shown()`); got != "key code" {
		t.Fatalf("setup page after sign-up shows %q, want the key and the code form", got)
	}
	p.vm.Set("code", GenerateTOTP(p.eval(`el('.mfa-secret').textContent`)))
	p.eval(`submit('#mfa-setup-form', {code: code})`)
	if got := p.eval(`location.href`); got != "/" || !c.signedIn() {
		t.Fatalf("after enrolling: went to %q, signed in=%v, page shows %q", got, c.signedIn(), p.eval(`shown()`))
	}
	if w := c.do(http.MethodGet, "/api/_auth/profile", "", "", map[string]string{"Accept": "application/json"}); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "new@signup.test") {
		t.Fatalf("profile after sign-up enrollment: %d %s", w.Code, w.Body.String())
	}
}

// compliance F6: bm.mfa.disable posted {password} to an endpoint that reads
// {code}, so the call could never succeed (403 "invalid code", spending one
// of the account's five MFA attempts each time).
func TestSDKMFADisableSendsTheCodeTheEndpointReads(t *testing.T) {
	app, h := signupMFAApp(t)
	c, uid := signupMFAHeldClient(t, app, h, "enrolled@signup.test")
	secret := "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	if _, err := app.DB.Exec("UPDATE _benmore_users SET totp_secret=? WHERE id=?", secret, uid); err != nil {
		t.Fatal(err)
	}
	p := newSDKPageVM(t, c, authMintCSRFToken(""))
	code := GenerateTOTP(secret)
	p.vm.Set("code", code)
	p.eval(`run(mfa.disable(code))`)
	if out := p.eval(`JSON.stringify(out)`); out != `{"value":{"status":"mfa_disabled"}}` {
		t.Fatalf("bm.mfa.disable(code) with a current code: %s (sent %s)", out, p.eval(`JSON.stringify(requests)`))
	}
	if CheckMFA(app.DB, uid) {
		t.Fatal("the factor is still active after bm.mfa.disable(code)")
	}
	if sent := p.eval(`requests[0].body`); sent != `{"code":"`+code+`"}` {
		t.Fatalf("bm.mfa.disable sent %s", sent)
	}
	// Both declaration files (the app's bm.d.ts and the @benmore/bm package).
	for file, want := range map[string]string{
		"bm_types.go":            "disable(code: string): Promise<{ status: 'mfa_disabled' }>",
		"packages/bm/index.d.ts": `disable(code: string): Promise<{ status: "mfa_disabled" }>`,
	} {
		types, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(types), want) {
			t.Errorf("%s does not type bm.mfa.disable(code) with the endpoint's answer", file)
		}
	}
}
