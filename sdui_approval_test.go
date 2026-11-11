//go:build !cli

package main

import (
	"strings"
	"testing"

	esbuild "github.com/benmore-studio/benmore/third_party/esbuild/pkg/api"
	"github.com/dop251/goja"
)

// sduiApprovalHTML renders the shipped Approval component for one signed-in
// user and one pending request, on the DOM double the auth components use.
func sduiApprovalHTML(t *testing.T, meJSON, pendingJSON string) string {
	t.Helper()
	compiled := esbuild.Build(esbuild.BuildOptions{
		Stdin:  &esbuild.StdinOptions{Contents: "export { Approval } from 'sdui';"},
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
		t.Fatalf("compile shipped component: %v", compiled.Errors)
	}
	vm := goja.New()
	if _, err := vm.RunString(`
function mkEl(name) {
  var e = {name: name, kids: {}, handlers: {}, hidden: true, textContent: '', style: {}};
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
var document = {getElementById: function () { return {}; }, createElement: function (tag) { return mkEl(tag); }, body: mkEl('body')};
var window = {addEventListener: function () {}, removeEventListener: function () {}};
var location = {href: 'https://app.example.test/', origin: 'https://app.example.test'};
function setTimeout(fn) { fn(); }
var fixtureBM = {
  auth: {me: function () { return Promise.resolve(` + meJSON + `); }},
  api: {
    get: function () { return Promise.resolve({approvals: [` + pendingJSON + `]}); },
    post: function () { return Promise.resolve({}); },
  },
};
var mount = mkEl('mount');
`); err != nil {
		t.Fatal(err)
	}
	if _, err := vm.RunString(string(compiled.OutputFiles[0].Contents)); err != nil {
		t.Fatal(err)
	}
	sduiRun(t, vm, `sdui.Approval(mount, {table: 'wire', id: 1})`)
	return sduiRun(t, vm, `mount.innerHTML`).String()
}

// The Approval component offered Approve/Reject only when the request's
// approver_email equalled the user's address character for character, so a
// request stored as `Bob@Example.com` showed bob no buttons although the
// server lets him decide it.
func TestSDUIApprovalOffersDecisionToApproverInAnyLetterCase(t *testing.T) {
	const pending = `{id: 5, status: 'pending', requested_by: 1, approver_email: 'Bob@Example.com', title: 'Wire'}`
	if html := sduiApprovalHTML(t, `{id: 2, email: 'bob@example.com', role: 'user'}`, pending); !strings.Contains(html, `data-decide="approved"`) {
		t.Errorf("approver addressed in another letter case gets no decision buttons: %s", html)
	}
	if html := sduiApprovalHTML(t, `{id: 3, email: 'carol@example.com', role: 'user'}`, pending); strings.Contains(html, "data-decide") {
		t.Errorf("a user the request does not name gets decision buttons: %s", html)
	}
	if html := sduiApprovalHTML(t, `{id: 1, email: 'bob@example.com', role: 'user'}`, pending); strings.Contains(html, "data-decide") {
		t.Errorf("the requester gets decision buttons on their own request: %s", html)
	}
	// A request that names no address is nobody's by address.
	if html := sduiApprovalHTML(t, `{id: 2, role: 'user'}`, `{id: 6, status: 'pending', requested_by: 1, approver_email: '', title: 'Wire'}`); strings.Contains(html, "data-decide") {
		t.Errorf("a user without an address gets decision buttons on a request without one: %s", html)
	}
}
