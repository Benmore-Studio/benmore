package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dop251/goja"
)

// bmFlowsVM loads request() and the bm.flows proxy exactly as embedded/bm.js
// ships them, over a fake fetch that behaves like a browser's: a GET or HEAD
// with a body throws, and each response reads its body once as text or Blob.
func bmFlowsVM(t *testing.T) *goja.Runtime {
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
		return js[i : i+j]
	}
	core := cut("const CSRF_META", "export const api = {")
	seg := cut("function _seg(v) {", "\n}\n") + "\n}\n"
	flows := cut("let _flowsRegistry = null;", "\n// ======")
	flows = strings.Replace(flows, "export const flows", "const flows", 1)

	harness := `
var calls = [];
var routes = {};
function Headers(init) {
  this.m = {};
  if (init) for (var k in init) this.m[k.toLowerCase()] = init[k];
}
Headers.prototype.set = function (k, v) { this.m[k.toLowerCase()] = String(v); };
Headers.prototype.get = function (k) { var v = this.m[k.toLowerCase()]; return v === undefined ? null : v; };
Headers.prototype.forEach = function (fn) { for (var k in this.m) fn(this.m[k], k); };
var document = { querySelector: function () { return { content: 'csrf-token' }; } };
function observeSessionResponse() {}
function captureRequest() {}
function makeJob(id, url) { return { job: id, url: url }; }
function respond(status, type, body) {
  var read = false;
  function once() { if (read) throw new TypeError('body used already'); read = true; }
  var h = {};
  if (type) h['content-type'] = type;
  return {
    status: status, ok: status >= 200 && status < 300, redirected: false, url: '',
    headers: new Headers(h),
    text: async function () { once(); return body; },
    blob: async function () { once(); return { isBlob: true, type: type, size: body.length, text: body }; },
    json: async function () { once(); return JSON.parse(body); },
  };
}
async function fetch(url, init) {
  init = init || {};
  var method = init.method || 'GET';
  if ((method === 'GET' || method === 'HEAD') && init.body !== undefined) {
    throw new TypeError("Failed to execute 'fetch' on 'Window': Request with GET/HEAD method cannot have body.");
  }
  calls.push({ url: url, method: method, body: init.body === undefined ? null : init.body });
  var route = routes[method + ' ' + url.split('?')[0]];
  if (!route) return respond(404, 'application/json', '{"error":"not_found"}');
  return respond(route[0], route[1], method === 'HEAD' ? '' : route[2]);
}
routes['GET /_internal/flows.json'] = [200, 'application/json', JSON.stringify({
  img:     { method: 'GET',  path: '/api/img/:id' },
  docFile: { method: 'GET',  path: '/api/docs/:id/file' },
  search:  { method: 'GET',  path: '/api/search' },
  probe:   { method: 'HEAD', path: '/api/probe/:id' },
  save:    { method: 'POST', path: '/api/save/:id' },
  denied:  { method: 'GET',  path: '/api/denied' },
  broken:  { method: 'POST', path: '/api/broken' },
  later:   { method: 'POST', path: '/api/later' },
})];
var out;
function run(p) {
  out = undefined;
  p.then(function (v) { out = { value: v }; }, function (e) { out = { error: String(e && e.message), status: e && e.status, code: e && e.code }; });
}
`
	vm := goja.New()
	if _, err := vm.RunString(harness + core + seg + flows); err != nil {
		t.Fatalf("bm.js request/flows do not load: %v", err)
	}
	return vm
}

// bmRun runs one async expression to completion and returns {value} or
// {error, status, code} plus the requests it made.
func bmRun(t *testing.T, vm *goja.Runtime, setup, expr string) (map[string]any, []map[string]any) {
	t.Helper()
	// Promise jobs run when a script returns, so the result is read by a
	// second script.
	if _, err := vm.RunString(setup + "\ncalls = [];\nrun((async function () { return " + expr + "; })());"); err != nil {
		t.Fatalf("%s: %v", expr, err)
	}
	v, err := vm.RunString("JSON.stringify({out: out, calls: calls})")
	if err != nil {
		t.Fatalf("%s: %v", expr, err)
	}
	var got struct {
		Out   map[string]any   `json:"out"`
		Calls []map[string]any `json:"calls"`
	}
	if err := json.Unmarshal([]byte(v.String()), &got); err != nil {
		t.Fatalf("%s: %v (%s)", expr, err, v.String())
	}
	if got.Out == nil {
		t.Fatalf("%s did not settle", expr)
	}
	var flowCalls []map[string]any
	for _, c := range got.Calls {
		if c["url"] != "/_internal/flows.json" {
			flowCalls = append(flowCalls, c)
		}
	}
	return got.Out, flowCalls
}

// A flow that answers bytes (run: proxy, run: serve_file) resolves to a
// Blob, and a text/* answer (a CSV export) to its text. request() used to
// turn every non-JSON body into {error: <body>}, so an image resolved as
// {error: "<PNG bytes>"} with the bytes mangled into a string.
func TestBMFlowsResolveBinaryAndTextAnswers(t *testing.T) {
	vm := bmFlowsVM(t)

	got, calls := bmRun(t, vm, `routes['GET /api/img/7'] = [200, 'image/png', '\x89PNG\r\n\x1a\nbytes'];`, `flows.img({ id: 7 })`)
	blob, _ := got["value"].(map[string]any)
	if blob == nil || blob["isBlob"] != true || blob["type"] != "image/png" || blob["text"] != "\u0089PNG\r\n\x1a\nbytes" {
		t.Fatalf("image flow resolved %v, want the response Blob", got)
	}
	if len(calls) != 1 || calls[0]["url"] != "/api/img/7" || calls[0]["method"] != "GET" {
		t.Fatalf("image flow requests = %v", calls)
	}

	got, _ = bmRun(t, vm, `routes['GET /api/docs/1/file'] = [200, 'text/csv; charset=utf-8', 'id,name\n1,Ada\n'];`, `flows.docFile({ id: 1 })`)
	if got["value"] != "id,name\n1,Ada\n" {
		t.Fatalf("CSV flow resolved %v, want its text", got)
	}

	// JSON answers are unchanged, including the async-job handle.
	got, calls = bmRun(t, vm, `routes['POST /api/save/3'] = [200, 'application/json', '{"ok":true,"id":3}'];`, `flows.save({ id: 3 }, { title: 'x' })`)
	if v, _ := got["value"].(map[string]any); v == nil || v["ok"] != true || v["id"] != float64(3) {
		t.Fatalf("JSON flow resolved %v", got)
	}
	if len(calls) != 1 || calls[0]["url"] != "/api/save/3" || calls[0]["body"] != `{"title":"x"}` {
		t.Fatalf("POST flow requests = %v", calls)
	}
	got, _ = bmRun(t, vm, `routes['POST /api/later'] = [202, 'application/json', '{"job_id":"j1","status_url":"/api/_jobs/j1/status"}'];`, `flows.later({})`)
	if v, _ := got["value"].(map[string]any); v == nil || v["job"] != "j1" {
		t.Fatalf("async flow resolved %v, want a job handle", got)
	}

	// A HEAD flow has no body to read.
	got, _ = bmRun(t, vm, `routes['HEAD /api/probe/2'] = [200, 'image/png', ''];`, `flows.probe({ id: 2 })`)
	if v, ok := got["value"]; !ok || v != nil {
		t.Fatalf("HEAD flow resolved %v, want null", got)
	}
}

// Errors stay errors: a non-2xx answer throws whatever its type, with the
// server's text as the message.
func TestBMFlowsNon2xxStillThrows(t *testing.T) {
	vm := bmFlowsVM(t)
	got, _ := bmRun(t, vm, `routes['GET /api/denied'] = [403, 'text/plain; charset=utf-8', 'Forbidden'];`, `flows.denied()`)
	if got["error"] != "Forbidden" || got["status"] != float64(403) {
		t.Fatalf("403 text flow = %v, want a thrown error with the text", got)
	}
	got, _ = bmRun(t, vm, `routes['POST /api/broken'] = [500, 'application/json', '{"error":"flow_failed","message":"step 2 failed"}'];`, `flows.broken({})`)
	if got["error"] != "step 2 failed" || got["code"] != "flow_failed" || got["status"] != float64(500) {
		t.Fatalf("500 JSON flow = %v", got)
	}
	got, _ = bmRun(t, vm, `routes['GET /api/denied'] = [502, 'image/png', 'not an image'];`, `flows.denied()`)
	if got["error"] != "not an image" || got["status"] != float64(502) {
		t.Fatalf("502 with a binary type = %v, want a thrown error", got)
	}
}

// A GET flow's params that no :path segment uses go in the query string,
// where the flow binds them. They used to be dropped, and a body made the
// browser's fetch throw "Request with GET/HEAD method cannot have body".
func TestBMFlowsGETSendsInputsAsQuery(t *testing.T) {
	vm := bmFlowsVM(t)
	setup := `routes['GET /api/img/7'] = [200, 'image/png', 'png']; routes['GET /api/search'] = [200, 'application/json', '[]'];`

	_, calls := bmRun(t, vm, setup, `flows.img({ id: 7, kind: 'png', size: 64 })`)
	if len(calls) != 1 || calls[0]["url"] != "/api/img/7?kind=png&size=64" || calls[0]["body"] != nil {
		t.Fatalf("GET flow requests = %v, want /api/img/7?kind=png&size=64 with no body", calls)
	}

	// Values are encoded, null/undefined are left out, objects and arrays
	// travel as JSON text (as a JSON body binds them).
	_, calls = bmRun(t, vm, setup, `flows.search({ q: 'a b&c=d', skip: null, none: undefined, tags: ['x', 'y'], on: true })`)
	want := "/api/search?q=a%20b%26c%3Dd&tags=" + "%5B%22x%22%2C%22y%22%5D" + "&on=true"
	if len(calls) != 1 || calls[0]["url"] != want {
		t.Fatalf("GET query = %v, want %s", calls, want)
	}

	// A body given to a GET flow (FlowForm and FlowButton pass one) is sent
	// as query values instead of breaking the request; params win.
	got, calls := bmRun(t, vm, setup, `flows.search({ q: 'from-params' }, { q: 'from-body', limit: 5 })`)
	if _, ok := got["value"]; !ok || len(calls) != 1 || calls[0]["url"] != "/api/search?q=from-params&limit=5" || calls[0]["body"] != nil {
		t.Fatalf("GET with a body = %v %v", got, calls)
	}
	// A path value given in the body argument fills the path and is not
	// repeated in the query (the flow answers 400 on a conflicting value).
	_, calls = bmRun(t, vm, setup, `flows.img({}, { id: 7, kind: 'png' })`)
	if len(calls) != 1 || calls[0]["url"] != "/api/img/7?kind=png" {
		t.Fatalf("path value in the body argument = %v, want /api/img/7?kind=png", calls)
	}
	got, _ = bmRun(t, vm, setup, `flows.search({}, 'raw text')`)
	if !strings.Contains(fmtAny(got["error"]), "GET") {
		t.Fatalf("GET with a non-object body = %v, want a clear error", got)
	}

	// Path values are still one segment each and never dot segments.
	got, _ = bmRun(t, vm, setup, `flows.img({ id: '..' })`)
	if !strings.Contains(fmtAny(got["error"]), "invalid path segment") {
		t.Fatalf("dot path segment = %v", got)
	}
	_, calls = bmRun(t, vm, setup, `flows.img({ id: 'a/b?c' })`)
	if len(calls) != 1 || calls[0]["url"] != "/api/img/a%2Fb%3Fc" {
		t.Fatalf("encoded path segment = %v", calls)
	}

	// POST flows keep sending only the body; extra params are not added.
	_, calls = bmRun(t, vm, `routes['POST /api/save/3'] = [200, 'application/json', '{}'];`, `flows.save({ id: 3, extra: 1 }, { a: 1 })`)
	if len(calls) != 1 || calls[0]["url"] != "/api/save/3" {
		t.Fatalf("POST flow URL = %v", calls)
	}
}

// bm.api returns the same shapes as bm.flows: a 2xx non-JSON answer is a
// success carrying text or a Blob, a non-2xx one is {error: text}.
func TestBMAPIRawReturnsBodyByContentType(t *testing.T) {
	vm := bmFlowsVM(t)
	setup := `routes['GET /u/a.pdf'] = [200, 'application/pdf', '%PDF-1.7']; routes['GET /notes.txt'] = [200, 'text/plain', 'hello']; routes['GET /gone'] = [410, 'text/plain', 'gone']; routes['GET /p'] = [200, 'application/problem+json', '{"title":"x"}'];`
	got, _ := bmRun(t, vm, setup, `request('GET', '/u/a.pdf')`)
	res, _ := got["value"].(map[string]any)
	data, _ := res["data"].(map[string]any)
	if res["ok"] != true || data == nil || data["isBlob"] != true || data["type"] != "application/pdf" {
		t.Fatalf("PDF request = %v, want ok with a Blob", got)
	}
	got, _ = bmRun(t, vm, setup, `request('GET', '/notes.txt')`)
	if res, _ := got["value"].(map[string]any); res["ok"] != true || res["data"] != "hello" {
		t.Fatalf("text request = %v", got)
	}
	got, _ = bmRun(t, vm, setup, `request('GET', '/gone')`)
	if res, _ := got["value"].(map[string]any); res["ok"] != false {
		t.Fatalf("410 request = %v", got)
	} else if d, _ := res["data"].(map[string]any); d == nil || d["error"] != "gone" {
		t.Fatalf("410 request data = %v, want {error: text}", got)
	}
	got, _ = bmRun(t, vm, setup, `request('GET', '/p')`)
	if res, _ := got["value"].(map[string]any); res == nil {
		t.Fatalf("problem+json request = %v", got)
	} else if d, _ := res["data"].(map[string]any); d == nil || d["title"] != "x" {
		t.Fatalf("problem+json request data = %v, want the parsed object", got)
	}
}

func getFlowsApp() *App {
	return &App{Tables: []Table{{Name: "notes", Columns: []Column{
		{Name: "id", Type: "INTEGER", PK: true, NotNull: true},
		{Name: "title", Type: "TEXT", NotNull: true},
	}}}, Flows: []Flow{
		{Name: "img", Trigger: FlowTrigger{Type: "http", Method: "GET", Path: "/api/img/:id",
			Inputs: map[string]FlowInput{"kind": {Type: "enum", Values: []string{"png", "jpg"}}, "size": {Type: "number"}}}},
		{Name: "feed", Trigger: FlowTrigger{Type: "http", Method: "GET", Path: "/api/feed"}},
		{Name: "doc_file", Trigger: FlowTrigger{Type: "http", Method: "GET", Path: "/api/docs/:id/file"}},
		{Name: "lookup", Trigger: FlowTrigger{Type: "http", Method: "get", Path: "/api/lookup",
			Inputs: map[string]FlowInput{"email": {Type: "email", Required: true}}}},
		{Name: "save", Trigger: FlowTrigger{Type: "http", Method: "POST", Path: "/api/save/:id",
			Inputs: map[string]FlowInput{"title": {Type: "text"}}}},
	}}
}

// GET flows are typed without a body: their inputs and path params are the
// one params argument, sent as the path and query string.
func TestGeneratedFlowTypesGETHasNoBody(t *testing.T) {
	full := GenerateBMTypes(getFlowsApp())
	out := flowMapSection(full)
	for _, want := range []string{
		"  img: (params: { id: string | number; kind?: 'png' | 'jpg'; size?: number }) => Promise<unknown>;",
		"  feed: (params?: Record<string, unknown>) => Promise<unknown>;",
		"  docFile: (params: { id: string | number } & Record<string, unknown>) => Promise<unknown>;",
		"  lookup: (params: { email: string }) => Promise<unknown>;",
		"  save: (params: { id: string | number }, body?: { title?: string }) => Promise<unknown>;",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("FlowMap missing %q\n%s", want, out)
		}
	}
	if !strings.Contains(full, "or a Blob for any other type") || !strings.Contains(full, "GET and HEAD flows take no body") {
		t.Error("FlowMap does not document the Blob/text answers and the GET query string")
	}
}

// The GET flow signatures compile, accept the calls the runtime serves and
// refuse a body (tsc fixture, like TestGeneratedTypesRuntimeShapesCompile).
func TestGeneratedFlowTypesGETCompile(t *testing.T) {
	tsc, err := exec.LookPath("tsc")
	if err != nil {
		if os.Getenv("CI") != "" || os.Getenv("BM_REQUIRE_TSC") != "" {
			t.Fatal("tsc not installed but CI/BM_REQUIRE_TSC is set")
		}
		t.Skip("tsc not installed")
	}
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("bm.d.ts", GenerateBMTypes(getFlowsApp()))
	write("fixture.ts", `
import bm from 'bm';

async function validUses() {
  const img = await bm.flows.img({ id: 7, kind: 'png', size: 64 });
  if (img instanceof Blob) URL.createObjectURL(img);
  await bm.flows.feed();
  await bm.flows.feed({ q: 'x', page: 2, tags: ['a'] });
  await bm.flows.docFile({ id: 1, download: 1 });
  await bm.flows.lookup({ email: 'a@example.test' });
  await bm.flows.save({ id: 3 }, { title: 't' });
}

async function invalidUses() {
  // @ts-expect-error a GET flow takes no body
  await bm.flows.img({ id: 7 }, { kind: 'png' });
  // @ts-expect-error the path parameter is required
  await bm.flows.img({ kind: 'png' });
  // @ts-expect-error a declared enum input is typed
  await bm.flows.img({ id: 7, kind: 'gif' });
  // @ts-expect-error a required input must be sent
  await bm.flows.lookup({});
  // @ts-expect-error a GET flow takes no body
  await bm.flows.feed({}, {});
}

void validUses;
void invalidUses;
`)
	write("tsconfig.json", `{
  "compilerOptions": {
    "noEmit": true, "strict": true, "target": "ES2020", "module": "ESNext",
    "moduleResolution": "Bundler", "lib": ["ES2020", "DOM"],
    "paths": { "bm": ["./bm.d.ts"] }
  },
  "files": ["fixture.ts"]
}`)
	cmd := exec.Command(tsc, "--project", "tsconfig.json")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if strings.Contains(string(out), "TS2578") {
		t.Fatalf("an invalid use type-checked (unused @ts-expect-error):\n%s", out)
	}
	if err != nil {
		t.Fatalf("generated GET flow types failed the fixture:\n%s", out)
	}
}
