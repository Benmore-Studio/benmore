package main

import (
	"os"
	"strings"
	"testing"

	"github.com/dop251/goja"
)

// signInStepVM loads signInStepURL exactly as embedded/bm.js ships it.
func signInStepVM(t *testing.T) (*goja.Runtime, string) {
	t.Helper()
	src, err := os.ReadFile("embedded/bm.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(src)
	start := strings.Index(js, "function signInStepURL(")
	if start < 0 {
		t.Fatal("embedded/bm.js: signInStepURL not found")
	}
	end := strings.Index(js[start:], "\n}\n")
	if end < 0 {
		t.Fatal("embedded/bm.js: end of signInStepURL not found")
	}
	vm := goja.New()
	page := "function PAGE(search) { return {origin: 'https://a.test', search: search, assign: function () {}}; }\n"
	if _, err := vm.RunString(page + js[start:start+end+3]); err != nil {
		t.Fatalf("signInStepURL does not run: %v", err)
	}
	return vm, js
}

// A sign-in that still needs the emailed code (auth.otp) or an authenticator
// code answers with the step's page instead of a session. The SDK sends the
// browser there, keeping the page's ?next=, and only to a same-origin path:
// before, bm.auth.passkey.signIn() resolved null and the caller's own
// redirect left the person signed out with the code already emailed.
func TestSDKSignInStepURL(t *testing.T) {
	vm, _ := signInStepVM(t)
	cases := []struct {
		name, script, want string
	}{
		{"otp step", `signInStepURL('/api/_auth/passkeys/login', {data: {ok: true, otp_required: true, redirect: '/verify-otp'}}, PAGE(''))`, "/verify-otp"},
		{"otp step keeps next", `signInStepURL('/login', {data: {otp_required: true, redirect: '/verify-otp'}}, PAGE('?next=%2Fapps%3Fx%3D1'))`, "/verify-otp?next=%2Fapps%3Fx%3D1"},
		{"server's next wins", `signInStepURL('/login', {data: {otp_required: true, redirect: '/verify-otp?next=%2Fa'}}, PAGE('?next=%2Fb'))`, "/verify-otp?next=%2Fa"},
		{"unsafe next dropped", `signInStepURL('/login', {data: {otp_required: true, redirect: '/verify-otp'}}, PAGE('?next=%2F%2Fevil.test'))`, "/verify-otp"},
		{"backslash next dropped", `signInStepURL('/login', {data: {otp_required: true, redirect: '/verify-otp'}}, PAGE('?next=%2F%5Cevil.test'))`, "/verify-otp"},
		{"mfa step", `signInStepURL('/login', {data: {mfa_required: true, redirect: '/verify-mfa'}}, PAGE(''))`, "/verify-mfa"},
		{"mfa enrollment step", `signInStepURL('/api/_auth/passkeys/login', {data: {mfa_setup_required: true, redirect: '/mfa-setup'}}, PAGE(''))`, "/mfa-setup"},
		{"token exchange setup has no page", `signInStepURL('/login', {data: {mfa_setup_required: true, setup_token: 'x'}}, PAGE(''))`, "null"},
		{"mfa enrollment step after login", `signInStepURL('/login', {data: {ok: true, mfa_setup_required: true, redirect: '/mfa-setup'}}, PAGE('?next=%2Fa'))`, "/mfa-setup?next=%2Fa"},
		{"followed redirect to the step", `signInStepURL('/login', {redirected: true, url: 'https://a.test/verify-mfa', data: {error: '<html>'}}, PAGE(''))`, "/verify-mfa"},
		{"redirect back to the same page", `signInStepURL('/login', {redirected: true, url: 'https://a.test/login?error=x', data: {error: '<html>'}}, PAGE(''))`, "null"},
		{"redirect to another origin", `signInStepURL('/login', {redirected: true, url: 'https://evil.test/verify-mfa'}, PAGE(''))`, "null"},
		{"origin prefix is not the origin", `signInStepURL('/login', {redirected: true, url: 'https://a.test.evil.test/x'}, PAGE(''))`, "null"},
		{"protocol-relative step", `signInStepURL('/login', {data: {otp_required: true, redirect: '//evil.test/x'}}, PAGE(''))`, "null"},
		{"absolute step", `signInStepURL('/login', {data: {otp_required: true, redirect: 'https://evil.test/x'}}, PAGE(''))`, "null"},
		{"backslash step", `signInStepURL('/login', {data: {otp_required: true, redirect: '/\\evil.test'}}, PAGE(''))`, "null"},
		{"signed in", `signInStepURL('/login', {data: {ok: true, user: {id: 1}}}, PAGE(''))`, "null"},
		{"no page, redirect", `signInStepURL('/login', {redirected: true, url: 'https://a.test/verify-mfa'}, null)`, "null"},
		{"no page, step", `signInStepURL('/login', {data: {otp_required: true, redirect: '/verify-otp'}}, null)`, "null"},
	}
	for _, c := range cases {
		v, err := vm.RunString(c.script)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got := "null"
		if !goja.IsNull(v) && !goja.IsUndefined(v) {
			got = v.String()
		}
		if got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

// Every SDK call that can start a sign-in follows the step, and request()
// reports where a followed redirect ended.
func TestSDKSignInCallsFollowTheStep(t *testing.T) {
	_, js := signInStepVM(t)
	for _, s := range []string{
		"signInStepURL('/login', res, _pageLocation())",
		"signInStepURL('/signup', res, _pageLocation())",
		"signInStepURL('/api/_auth/passkeys/login', { data }, _pageLocation())",
		"redirected: !!res.redirected, url: res.url || ''",
	} {
		if !strings.Contains(js, s) {
			t.Errorf("embedded/bm.js missing %q", s)
		}
	}
}
