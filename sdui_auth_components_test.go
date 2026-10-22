//go:build !cli

package main

import (
	"strings"
	"testing"

	esbuild "github.com/benmore-studio/benmore/third_party/esbuild/pkg/api"
	"github.com/dop251/goja"
)

// sduiAuthVM runs the shipped auth components on a small DOM double that
// keeps each element's event handlers, so a test can submit a form.
func sduiAuthVM(t *testing.T) *goja.Runtime {
	t.Helper()
	compiled := esbuild.Build(esbuild.BuildOptions{
		Stdin:  &esbuild.StdinOptions{Contents: "export { Login, Signup, StepUp, MfaSetup } from 'sdui';"},
		Bundle: true, Write: false, Format: esbuild.FormatIIFE, GlobalName: "sdui", Target: esbuild.ES2020,
		Plugins: []esbuild.Plugin{{Name: "fixture-modules", Setup: func(build esbuild.PluginBuild) {
			build.OnResolve(esbuild.OnResolveOptions{Filter: "^(sdui|bm)$"}, func(args esbuild.OnResolveArgs) (esbuild.OnResolveResult, error) {
				return esbuild.OnResolveResult{Path: args.Path, Namespace: "fixture"}, nil
			})
			build.OnLoad(esbuild.OnLoadOptions{Filter: ".*", Namespace: "fixture"}, func(args esbuild.OnLoadArgs) (esbuild.OnLoadResult, error) {
				source := "export default globalThis.fixtureBM;"
				if args.Path == "sdui" {
					source = string(sduiJS)
				}
				return esbuild.OnLoadResult{Contents: &source, Loader: esbuild.LoaderJS}, nil
			})
		}}},
	})
	if len(compiled.Errors) != 0 {
		t.Fatalf("compile shipped components: %v", compiled.Errors)
	}
	vm := goja.New()
	if _, err := vm.RunString(`
function mkEl(name) {
  var e = {name: name, kids: {}, handlers: {}, values: {}, hidden: true, textContent: '', style: {}};
  var html = '';
  Object.defineProperty(e, 'innerHTML', {get: function () { return html; }, set: function (v) { html = String(v); e.kids = {}; }});
  e.querySelector = function (sel) { if (!e.kids[sel]) e.kids[sel] = mkEl(sel); return e.kids[sel]; };
  e.querySelectorAll = function () { return []; };
  e.addEventListener = function (type, fn) { e.handlers[type] = fn; };
  e.removeEventListener = function () {};
  e.setAttribute = function () {};
  e.appendChild = function (c) { return c; };
  e.remove = function () {};
  return e;
}
var created = [];
var document = {getElementById: function () { return {}; }, createElement: function (tag) { var e = mkEl(tag); created.push(e); return e; }, body: mkEl('body')};
var window = {addEventListener: function () {}, removeEventListener: function () {}};
var location = {href: 'https://app.example.test/login', origin: 'https://app.example.test'};
function FormData(form) { this.get = function (k) { return form.values[k] === undefined ? null : form.values[k]; }; }
function setTimeout(fn) { fn(); }
var fetched = [];
function fetch(url, init) { fetched.push({url: url, init: init || {}}); return Promise.resolve({ok: true, status: 200, json: function () { return Promise.resolve({ok: true}); }}); }
var me = {id: 7, email: 'member@example.test', mfa_enabled: false};
var enrolled = [];
var fixtureBM = {
  auth: {
    me: function () { return Promise.resolve(me); },
    refreshMe: function () { return Promise.resolve(me); },
    signIn: function () { return Promise.resolve(me); },
    signUp: function () { return Promise.resolve(me); },
  },
  mfa: {
    // The server refuses enrollment from a session without the password.
    enroll: function (password) {
      enrolled.push(password);
      if (!password) return Promise.reject(new Error('password required to enable MFA'));
      return Promise.resolve({secret: 'SECRETB32', otpauth_uri: 'otpauth://totp/App:member@example.test?secret=SECRETB32&issuer=App', backup_codes: ['bkp-one-1111', 'bkp-two-2222']});
    },
    verify: function () { return Promise.resolve({ok: true}); },
    disable: function () { return Promise.resolve({ok: true}); },
  },
  api: {raw: {post: function (path, body) {
    fetched.push({url: path, init: {method: 'POST', body: body}});
    if (path === '/api/_auth/token' && body.password === 'right-password') return Promise.resolve({ok: true, status: 200, data: {token: 'minted-session-token', user_id: 7}});
    return Promise.resolve({ok: false, status: 401, data: {error: 'invalid credentials'}});
  }}},
};
function submit(form, values) { form.values = values || {}; return form.handlers.submit({preventDefault: function () {}}); }
`); err != nil {
		t.Fatal(err)
	}
	if _, err := vm.RunString(string(compiled.OutputFiles[0].Contents)); err != nil {
		t.Fatal(err)
	}
	return vm
}

func sduiRun(t *testing.T, vm *goja.Runtime, js string) goja.Value {
	t.Helper()
	v, err := vm.RunString(js)
	if err != nil {
		t.Fatal(err)
	}
	if p, ok := v.Export().(*goja.Promise); ok {
		if p.State() != goja.PromiseStateFulfilled {
			t.Fatalf("component operation did not complete: %v", p.Result())
		}
		return p.Result()
	}
	return v
}

// StepUp confirmed a password by exchanging it at /api/_auth/token and threw
// the returned session token away: every confirmation left a live 30-day
// Bearer session in _benmore_sessions. It now ends that session at once,
// with the token as the only credential (credentials: 'omit', so the
// browser's own cookie session is untouched).
func TestSDUIStepUpRevokesTheTokenItMints(t *testing.T) {
	vm := sduiAuthVM(t)
	sduiRun(t, vm, `var result; sdui.StepUp({}).then(function (v) { result = v; }); 0`)
	sduiRun(t, vm, `submit(created[1].kids['[data-bm-body]'].kids['form'], {password: 'right-password'});`)
	if got := vm.Get("result").Export(); got != true {
		t.Fatalf("StepUp with the right password resolved %v", got)
	}
	revoked := sduiRun(t, vm, `JSON.stringify(fetched.filter(function (c) { return c.url === '/logout'; }).map(function (c) { return c.init; }))`).String()
	if !strings.Contains(revoked, `"Authorization":"Bearer minted-session-token"`) || !strings.Contains(revoked, `"credentials":"omit"`) || !strings.Contains(revoked, `"method":"POST"`) {
		t.Fatalf("minted step-up token was not revoked with only its own credential: %s", revoked)
	}

	vm = sduiAuthVM(t)
	sduiRun(t, vm, `var result; sdui.StepUp({}).then(function (v) { result = v; }); 0`)
	sduiRun(t, vm, `submit(created[1].kids['[data-bm-body]'].kids['form'], {password: 'wrong'});`)
	if got := vm.Get("result").Export(); got != nil {
		t.Fatalf("StepUp settled on a wrong password: %v", got)
	}
	if n := sduiRun(t, vm, `fetched.filter(function (c) { return c.url === '/logout'; }).length`).ToInteger(); n != 0 {
		t.Fatalf("a refused confirmation sent %d logout requests", n)
	}
}

// MfaSetup enrolled without the password the server requires from a signed-
// in session (so it could not enroll at all), read otpauth_url where the
// server returns otpauth_uri, and never showed the backup codes the server
// returns exactly once.
func TestSDUIMfaSetupEnrollsWithPasswordAndShowsBackupCodes(t *testing.T) {
	vm := sduiAuthVM(t)
	sduiRun(t, vm, `var el = mkEl('target'); sdui.MfaSetup(el, {});`)
	if n := sduiRun(t, vm, `enrolled.length`).ToInteger(); n != 0 {
		t.Fatalf("MfaSetup enrolled before the user confirmed their password (%d calls)", n)
	}
	sduiRun(t, vm, `submit(el.kids['form'], {password: 'right-password'});`)
	if got := sduiRun(t, vm, `JSON.stringify(enrolled)`).String(); got != `["right-password"]` {
		t.Fatalf("enroll called with %s, want the confirmed password", got)
	}
	html := vm.Get("el").ToObject(vm).Get("innerHTML").String()
	for _, want := range []string{"SECRETB32", "otpauth://totp/App:member@example.test", "bkp-one-1111", "bkp-two-2222"} {
		i := strings.Index(html, want)
		if i < 0 {
			t.Fatalf("enrollment view lacks %q: %s", want, html)
		}
		open := strings.LastIndex(html[:i], "<")
		if tag := html[open:i]; !strings.Contains(tag, "data-bm-mask") {
			t.Errorf("%q is not inside a [data-bm-mask] element (session recordings would capture it): %s", want, tag)
		}
	}
	if !strings.Contains(html, "6-digit code") {
		t.Fatalf("enrollment view lacks the verify form: %s", html)
	}
}

// Login/Signup navigated to opts.redirect through safeUrl, which blocks
// script URLs but allowed any other site, so an app that forwards a ?next=
// value became an open redirect after sign-in. Only this origin is honored.
func TestSDUILoginRedirectStaysOnThisOrigin(t *testing.T) {
	cases := map[string]string{
		"/dashboard?tab=1":                       "/dashboard?tab=1",
		"settings":                               "settings",
		"https://app.example.test/projects":      "https://app.example.test/projects",
		"https://app.example.test?tab=2":         "https://app.example.test?tab=2",
		"https://app.example.test":               "https://app.example.test",
		`https://app.example.test\@evil.example`: "/",
		"https://evil.example/phish":             "/",
		"//evil.example/phish":                   "/",
		`/\evil.example`:                         "/",
		`\\evil.example`:                         "/",
		"/\t/evil.example":                       "/",
		" https://evil.example":                  "/",
		"https://app.example.test.evil.example/": "/",
		"https://app.example.test@evil.example/": "/",
		"javascript:alert(1)":                    "/",
	}
	for _, component := range []string{"Login", "Signup"} {
		for in, want := range cases {
			vm := sduiAuthVM(t)
			vm.Set("redirectTo", in)
			sduiRun(t, vm, `var el = mkEl('target'); sdui.`+component+`(el, {redirect: redirectTo});`)
			sduiRun(t, vm, `submit(el.kids['form'], {identifier: 'member@example.test', email: 'member@example.test', password: 'right-password'});`)
			if got := sduiRun(t, vm, `location.href`).String(); got != want {
				t.Errorf("%s redirect %q navigated to %q, want %q", component, in, got, want)
			}
		}
	}
}
