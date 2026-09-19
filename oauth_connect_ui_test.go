//go:build !cli

package main

import (
	"strings"
	"testing"

	"github.com/dop251/goja"
	esbuild "github.com/evanw/esbuild/pkg/api"
)

// Execute the shipped component with the existing embedded JS toolchain. The
// small mount double captures rendered HTML; API outcomes are fixture data.
func oauthConnectVM(t *testing.T) *goja.Runtime {
	t.Helper()
	compiled := esbuild.Build(esbuild.BuildOptions{
		Stdin:  &esbuild.StdinOptions{Contents: "export { OAuthConnect } from 'sdui';"},
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
	_, err := vm.RunString(`
var document = {getElementById: () => ({})};
var el = {innerHTML: '', querySelectorAll: () => [], querySelector: () => ({addEventListener: () => {}})};
var tokens = [], configured = [], failure = '', controller;
var fixtureBM = {api: {get: path => {
  if (failure) return Promise.reject(new Error(failure));
  if (path === '/api/_auth/oauth-tokens') return Promise.resolve(tokens);
  if (path === '/api/_auth/oauth-providers') return Promise.resolve(configured);
  throw new Error('Unexpected API: ' + path);
}}};
`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vm.RunString(string(compiled.OutputFiles[0].Contents)); err != nil {
		t.Fatal(err)
	}
	return vm
}

func runOAuthUI(t *testing.T, vm *goja.Runtime, js string) string {
	t.Helper()
	v, err := vm.RunString(js)
	if err != nil {
		t.Fatal(err)
	}
	if p, ok := v.Export().(*goja.Promise); ok && p.State() != goja.PromiseStateFulfilled {
		t.Fatalf("component operation did not complete: %v", p.Result())
	}
	return vm.Get("el").ToObject(vm).Get("innerHTML").String()
}

func TestOAuthConnectUsesConfiguredRoutesAndTokenCapabilities(t *testing.T) {
	vm := oauthConnectVM(t)
	html := runOAuthUI(t, vm, `
configured = [{provider:'google', token_storage:true}, {provider:'microsoft', token_storage:false}];
tokens = [{provider:'retired'}];
sdui.OAuthConnect(el, {providers:['google','microsoft','github','retired']}).then(c => controller = c);
`)
	for _, want := range []string{`href="/auth/google"`, "Sign-in only", "Not configured", `data-disc="retired"`} {
		if !strings.Contains(html, want) {
			t.Errorf("missing %s in %s", want, html)
		}
	}
	for _, bad := range []string{"href=\"/api/_auth/oauth/", "href=\"/auth/microsoft", "href=\"/auth/github"} {
		if strings.Contains(html, bad) {
			t.Errorf("offered unavailable connection: %s", html)
		}
	}
}

func TestOAuthConnectReadFailuresRemainVisibleAndRecover(t *testing.T) {
	vm := oauthConnectVM(t)
	html := runOAuthUI(t, vm, `failure = '<img src=x> expired'; sdui.OAuthConnect(el).then(c => controller = c);`)
	if !strings.Contains(html, `role="alert"`) || !strings.Contains(html, "&lt;img") || strings.Contains(html, "href=") {
		t.Fatalf("failed read presented false connection state or unescaped error: %s", html)
	}
	html = runOAuthUI(t, vm, `failure=''; controller.refresh();`)
	if !strings.Contains(html, "No OAuth providers configured") {
		t.Fatalf("empty success not distinguished from failure: %s", html)
	}
	html = runOAuthUI(t, vm, `configured=[{provider:'custom',token_storage:true}]; controller.refresh();`)
	if !strings.Contains(html, `href="/auth/custom"`) {
		t.Fatalf("refresh did not recover: %s", html)
	}
}

func TestOAuthConnectDestroyIgnoresPendingRefresh(t *testing.T) {
	vm := oauthConnectVM(t)
	runOAuthUI(t, vm, `sdui.OAuthConnect(el).then(c => controller = c);`)
	_, err := vm.RunString(`var resolveTokens, resolveProviders;
fixtureBM.api.get = path => new Promise(resolve => {
  if (path.endsWith('oauth-tokens')) resolveTokens = resolve; else resolveProviders = resolve;
});
controller.refresh(); controller.destroy();
resolveTokens([]); resolveProviders([{provider:'google',token_storage:true}]);`)
	if err != nil {
		t.Fatal(err)
	}
	if html := vm.Get("el").ToObject(vm).Get("innerHTML").String(); html != "" {
		t.Fatalf("pending response repopulated destroyed component: %s", html)
	}
}
