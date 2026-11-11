//go:build !cli

package main

import (
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	esbuild "github.com/benmore-studio/benmore/third_party/esbuild/pkg/api"
	"github.com/dop251/goja"
)

// sduiFormHarness runs the shipped RecordForm, WizardForm and DataTable
// against a real app: /api/_schema and every bm.table call go through the
// app's own mux with the owner's Bearer session, so what a component sends is
// applied by the CRUD pipeline and read back from the database.
type sduiFormHarness struct {
	t   *testing.T
	app *App
	vm  *goja.Runtime
}

func newSDUIFormHarness(t *testing.T) *sduiFormHarness {
	t.Helper()
	app := sduiEventsApp(t)
	sid := createCrudScopeSession(t, app, "organizer@example.com", "user", "", "")
	mux := buildAppMux(app, true, "http://localhost")

	compiled := esbuild.Build(esbuild.BuildOptions{
		Stdin:  &esbuild.StdinOptions{Contents: "export { RecordForm, WizardForm, DataTable } from 'sdui';"},
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
	vm.Set("goAPI", func(method, path, body string) map[string]any {
		r := httptest.NewRequest(method, "http://localhost"+path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+sid)
		if body != "" {
			r.Header.Set("Content-Type", "application/json")
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		out, _ := io.ReadAll(w.Result().Body)
		return map[string]any{"status": w.Code, "body": string(out)}
	})
	if _, err := vm.RunString(sduiFormDOM); err != nil {
		t.Fatal(err)
	}
	if _, err := vm.RunString(string(compiled.OutputFiles[0].Contents)); err != nil {
		t.Fatal(err)
	}
	return &sduiFormHarness{t: t, app: app, vm: vm}
}

// sduiFormDOM is a DOM double with a browser's form semantics: FormData reads
// the controls out of the rendered HTML (an input's value after the browser's
// value sanitization, a checked checkbox, the selected option, a textarea's
// text) and then what the "user" typed into form.values.
const sduiFormDOM = `
var sent = [];
function call(method, path, body) {
  var r = goAPI(method, path, body === undefined ? '' : JSON.stringify(body));
  var data = r.body ? JSON.parse(r.body) : null;
  if (r.status >= 400) return Promise.reject(new Error(r.status + ' ' + r.body));
  return Promise.resolve(data);
}
var fixtureBM = {
  api: {get: function (p) { return call('GET', p); }},
  table: function (t) {
    return {
      get: function (id) { return call('GET', '/api/' + t + '/' + id); },
      list: function (o) { return call('GET', '/api/' + t + '?limit=' + ((o && o.limit) || 50)).then(function (d) { return Array.isArray(d) ? d : (d.rows || d.data || []); }); },
      count: function () { return Promise.resolve(0); },
      create: function (b) { sent.push({op: 'create', table: t, body: b}); return call('POST', '/api/' + t, b); },
      update: function (id, b) { sent.push({op: 'update', table: t, id: id, body: b}); return call('PATCH', '/api/' + t + '/' + id, b); },
    };
  },
  live: function () { return function () {}; },
};
function fetch(u) {
  var r = goAPI('GET', u, '');
  return Promise.resolve({ok: r.status < 400, status: r.status, json: function () { return Promise.resolve(JSON.parse(r.body)); }});
}
function URLSearchParams() { this.m = []; }
URLSearchParams.prototype.set = function (k, v) { this.m.push(encodeURIComponent(k) + '=' + encodeURIComponent(v)); };
URLSearchParams.prototype.toString = function () { return this.m.join('&'); };
function setTimeout(fn) { fn(); }
function clearTimeout() {}
var document = {getElementById: function () { return {}; }, createElement: function () { return mkEl(); }, head: {appendChild: function () {}}, body: {appendChild: function () {}}};
var window = {addEventListener: function () {}, removeEventListener: function () {}};

function unesc(s) { return s.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&'); }
function attrsOf(s) { var o = {}; s.replace(/([\w-]+)(?:="([^"]*)")?/g, function (_, k, v) { o[k.toLowerCase()] = v === undefined ? '' : unesc(v); return ''; }); return o; }
// The value sanitization algorithm of each input type: a value the type
// can't hold reads as ''.
function sanitize(type, v) {
  if (type === 'number') return /^-?(\d+(\.\d+)?|\.\d+)([eE][-+]?\d+)?$/.test(v) ? v : '';
  if (type === 'date') return /^\d{4}-\d{2}-\d{2}$/.test(v) ? v : '';
  if (type === 'datetime-local') return /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d{1,3})?)?$/.test(v) ? v : '';
  if (type === 'time') return /^\d{2}:\d{2}(:\d{2}(\.\d{1,3})?)?$/.test(v) ? v : '';
  return v.replace(/[\r\n]/g, '');
}
function controlsOf(html) {
  var out = [];
  html.replace(/<input\b([^>]*)>/g, function (_, a) {
    var at = attrsOf(a); if (!at.name) return '';
    var type = (at.type || 'text').toLowerCase();
    out.push({name: at.name, type: type, value: type === 'checkbox' ? (at.value || 'on') : sanitize(type, at.value || ''), checked: 'checked' in at});
    return '';
  });
  html.replace(/<textarea\b([^>]*)>([\s\S]*?)<\/textarea>/g, function (_, a, body) {
    var at = attrsOf(a); if (at.name) out.push({name: at.name, type: 'textarea', value: unesc(body)}); return '';
  });
  html.replace(/<select\b([^>]*)>([\s\S]*?)<\/select>/g, function (_, a, body) {
    var at = attrsOf(a); var opts = [];
    body.replace(/<option\b([^>]*)>/g, function (_, oa) { opts.push(attrsOf(oa)); return ''; });
    var sel = opts.filter(function (o) { return 'selected' in o; }).pop() || opts[0];
    if (at.name) out.push({name: at.name, type: 'select', value: sel ? sel.value : '', options: opts.map(function (o) { return o.value; })});
    return '';
  });
  return out;
}
function FormData(form) {
  var m = {};
  controlsOf(form.html()).forEach(function (c) {
    var typed = form.values[c.name];
    var v = c.value;
    if (c.type === 'checkbox') {
      if (!(typed !== undefined ? !!typed : c.checked)) return;
    } else if (typed !== undefined) {
      v = String(typed);
    }
    if (!(c.name in m)) m[c.name] = v;
  });
  this.get = function (k) { return k in m ? m[k] : null; };
}
function mkEl(owner) {
  var e = {kids: {}, handlers: {}, values: {}, hidden: true, textContent: '', style: {}};
  var html = '';
  Object.defineProperty(e, 'innerHTML', {get: function () { return html; }, set: function (v) { html = String(v); e.kids = {}; }});
  e.html = function () { return owner ? owner.innerHTML : html; };
  e.querySelector = function (sel) {
    if (sel === '[data-bm-search]' || sel === '[data-bm-pager]') return null;
    if (!e.kids[sel]) e.kids[sel] = mkEl(sel === 'form' ? e : null);
    return e.kids[sel];
  };
  e.querySelectorAll = function () { return []; };
  e.addEventListener = function (type, fn) { e.handlers[type] = fn; };
  e.removeEventListener = function () {};
  e.setAttribute = function () {};
  e.getAttribute = function () { return null; };
  e.appendChild = function (c) { return c; };
  e.reset = function () { e.values = {}; };
  e.remove = function () {};
  return e;
}
function submit(el, values) { var form = el.kids['form']; form.values = values || {}; return form.handlers.submit({preventDefault: function () {}}); }
function control(el, name) { return controlsOf(el.innerHTML).filter(function (c) { return c.name === name; })[0] || null; }
`

// run executes js and, when it returns a promise, requires it settled
// successfully (goja runs the job queue before RunString returns).
func (h *sduiFormHarness) run(js string) goja.Value {
	h.t.Helper()
	v, err := h.vm.RunString(js)
	if err != nil {
		h.t.Fatal(err)
	}
	if p, ok := v.Export().(*goja.Promise); ok {
		if p.State() != goja.PromiseStateFulfilled {
			h.t.Fatalf("component did not complete: %v", p.Result())
		}
		return p.Result()
	}
	return v
}

func (h *sduiFormHarness) str(js string) string { h.t.Helper(); return h.run(js).String() }

// sent returns the bodies RecordForm/WizardForm handed to create/update.
func (h *sduiFormHarness) sent() []map[string]any {
	h.t.Helper()
	var out []map[string]any
	if err := json.Unmarshal([]byte(h.str(`JSON.stringify(sent)`)), &out); err != nil {
		h.t.Fatal(err)
	}
	return out
}

// scalar reads one value as text (JSON for json_object results, "<nil>" for NULL).
func (h *sduiFormHarness) scalar(q string, args ...any) string {
	h.t.Helper()
	var v any
	if err := h.app.DB.QueryRow(q, args...).Scan(&v); err != nil {
		h.t.Fatalf("%s: %v", q, err)
	}
	switch x := v.(type) {
	case nil:
		return "<nil>"
	case []byte:
		return string(x)
	case string:
		return x
	case time.Time:
		return x.UTC().Format(time.RFC3339Nano)
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// Finding 2a and 3: a create form started from the SQL default literal (city
// held two apostrophes and saved them), and a Boolean was a text box holding
// "0". The form now starts from the parsed default and a checkbox, and the
// saved row holds exactly those values.
func TestSDUIRecordFormCreateStartsFromParsedDefaults(t *testing.T) {
	h := newSDUIFormHarness(t)

	h.run(`var venue = mkEl(); sdui.RecordForm(venue, {table: 'venues'});`)
	if got := h.str(`JSON.stringify(control(venue, 'city'))`); !strings.Contains(got, `"value":""`) {
		t.Fatalf("city control should start empty: %s", got)
	}
	if got := h.str(`control(venue, 'capacity').value`); got != "100" {
		t.Fatalf("capacity starts at %q, want the default 100", got)
	}
	h.run(`submit(venue, {name: 'Main Hall'});`)
	if got := h.scalar("SELECT city FROM venues WHERE name = 'Main Hall'"); got != "" {
		t.Fatalf("saved city = %q, want the empty string", got)
	}
	if got := h.scalar("SELECT capacity FROM venues WHERE name = 'Main Hall'"); got != "100" {
		t.Fatalf("saved capacity = %q", got)
	}

	h.run(`var ev = mkEl(); sdui.RecordForm(ev, {table: 'events'});`)
	for name, wantType := range map[string]string{"published": "checkbox", "featured": "checkbox", "starts_at": "datetime-local", "remind_at": "datetime-local"} {
		if got := h.str(`control(ev, '` + name + `') ? control(ev, '` + name + `').type : 'missing'`); got != wantType {
			t.Errorf("events.%s renders as %q, want %q", name, got, wantType)
		}
	}
	if got := h.str(`JSON.stringify([control(ev, 'published').checked, control(ev, 'featured').checked, control(ev, 'summary').value, control(ev, 'body').value, control(ev, 'remind_at').value])`); got != `[false,true,"","",""]` {
		t.Fatalf("create form start values [published, featured, summary, body, remind_at] = %s", got)
	}
	h.run(`submit(ev, {title: 'Launch', starts_at: '2026-12-01T18:00'});`)
	row := h.scalar("SELECT json_object('summary', summary, 'body', body, 'published', published, 'featured', featured, 'venue', venue_id, 'remind', remind_at IS NOT NULL) FROM events WHERE title = 'Launch'")
	if row != `{"summary":"","body":"","published":0,"featured":1,"venue":null,"remind":1}` {
		t.Fatalf("created event = %s", row)
	}
	body := h.sent()[1]["body"].(map[string]any)
	if body["published"] != false || body["featured"] != true {
		t.Fatalf("Booleans must be sent as true/false: %v", body)
	}
	if _, ok := body["venue_id"]; ok {
		t.Fatalf("an empty optional relation on create must be left out (the column default applies): %v", body)
	}
	if _, ok := body["remind_at"]; ok {
		t.Fatalf("an empty now() column on create must be left out: %v", body)
	}
}

// Finding 2b and 3: saving an edit without touching anything cut starts_at to
// midnight (the date control kept the first 10 characters), and an event
// with no venue could not be saved at all (the picker sent "" and the PATCH
// failed: venue_id must be an integer). An edit now sends only what the
// person changed, and clearing a relation sends null.
func TestSDUIRecordFormEditSendsOnlyChangedValues(t *testing.T) {
	h := newSDUIFormHarness(t)
	uid := h.scalar("SELECT id FROM _benmore_users WHERE email = 'organizer@example.com'")
	mustExec(t, h.app.DB, "INSERT INTO venues (id, name, user_id) VALUES (1, 'Main Hall', "+uid+")")
	mustExec(t, h.app.DB, "INSERT INTO events (id, title, starts_at, published, venue_id, user_id) VALUES (1, 'Launch', '2026-12-01T18:00:00Z', 1, NULL, "+uid+")")
	mustExec(t, h.app.DB, "INSERT INTO events (id, title, starts_at, published, venue_id, user_id) VALUES (2, 'Party', '2026-12-02T20:30:00Z', 0, 1, "+uid+")")
	before := h.scalar("SELECT json_group_array(json_object('id', id, 'starts_at', starts_at, 'published', published, 'venue', venue_id, 'updated', title)) FROM events")

	for _, id := range []string{"1", "2"} {
		h.run(`var ed = mkEl(); sdui.RecordForm(ed, {table: 'events', id: ` + id + `});`)
		if got := h.str(`control(ed, 'published').type + ' ' + control(ed, 'starts_at').type`); got != "checkbox datetime-local" {
			t.Fatalf("event %s edit controls = %s", id, got)
		}
		h.run(`submit(ed, {});`)
	}
	if got := h.scalar("SELECT json_group_array(json_object('id', id, 'starts_at', starts_at, 'published', published, 'venue', venue_id, 'updated', title)) FROM events"); got != before {
		t.Fatalf("an unchanged edit changed the rows:\n before %s\n after  %s", before, got)
	}
	for _, s := range h.sent() {
		if body, _ := s["body"].(map[string]any); len(body) != 0 {
			t.Fatalf("an unchanged edit sent %v", s)
		}
	}

	// Event 2 keeps its venue in the picker; choosing "- none -" clears it.
	h.run(`var ed2 = mkEl(); sdui.RecordForm(ed2, {table: 'events', id: 2});`)
	if got := h.str(`control(ed2, 'venue_id').value`); got != "1" {
		t.Fatalf("event 2's venue picker shows %q, want its venue 1", got)
	}
	h.run(`submit(ed2, {venue_id: '', published: true, title: 'Party!'});`)
	if got := h.scalar("SELECT json_object('venue', venue_id, 'published', published, 'title', title, 'starts_at', starts_at) FROM events WHERE id = 2"); got != `{"venue":null,"published":1,"title":"Party!","starts_at":"2026-12-02T20:30:00Z"}` {
		t.Fatalf("event 2 after clearing its venue = %s", got)
	}
	last := h.sent()[len(h.sent())-1]["body"].(map[string]any)
	if v, ok := last["venue_id"]; !ok || v != nil {
		t.Fatalf("clearing the venue must send venue_id: null, sent %v", last)
	}
	if _, ok := last["starts_at"]; ok {
		t.Fatalf("an untouched starts_at was sent: %v", last)
	}

	// A venue the picker can't list (another owner's) stays selected instead
	// of reading as "- none -".
	mustExec(t, h.app.DB, "INSERT INTO venues (id, name, user_id) VALUES (2, 'Other Hall', 999)")
	mustExec(t, h.app.DB, "UPDATE events SET venue_id = 2 WHERE id = 1")
	h.run(`var ed3 = mkEl(); sdui.RecordForm(ed3, {table: 'events', id: 1});`)
	if got := h.str(`control(ed3, 'venue_id').value`); got != "2" {
		t.Fatalf("an unlisted venue reads as %q in the picker, want 2", got)
	}
	h.run(`submit(ed3, {title: 'Launch 2'});`)
	if got := h.scalar("SELECT json_object('venue', venue_id, 'title', title) FROM events WHERE id = 1"); got != `{"venue":2,"title":"Launch 2"}` {
		t.Fatalf("editing another field changed an unlisted venue: %s", got)
	}
}

// WizardForm shares RecordForm's payload rules.
func TestSDUIWizardFormSendsOnlyChangedValues(t *testing.T) {
	h := newSDUIFormHarness(t)
	uid := h.scalar("SELECT id FROM _benmore_users WHERE email = 'organizer@example.com'")
	mustExec(t, h.app.DB, "INSERT INTO events (id, title, starts_at, published, user_id) VALUES (1, 'Launch', '2026-12-01T18:00:00Z', 1, "+uid+")")
	h.run(`var wz = mkEl(); sdui.WizardForm(wz, {table: 'events', id: 1});`)
	h.run(`submit(wz, {title: 'Launch day'});`)
	if got := h.scalar("SELECT json_object('title', title, 'starts_at', starts_at, 'published', published, 'venue', venue_id) FROM events WHERE id = 1"); got != `{"title":"Launch day","starts_at":"2026-12-01T18:00:00Z","published":1,"venue":null}` {
		t.Fatalf("wizard edit = %s", got)
	}
	if got := h.sent()[0]["body"].(map[string]any); len(got) != 1 || got["title"] != "Launch day" {
		t.Fatalf("wizard sent %v, want only the title", got)
	}
}

// DataTable showed a relation as the raw id; it now shows the related row's
// label (the field relation pickers already label options by), through the
// list API's ?include=, which applies the related table's own access rules.
func TestSDUIDataTableLabelsRelations(t *testing.T) {
	h := newSDUIFormHarness(t)
	uid := h.scalar("SELECT id FROM _benmore_users WHERE email = 'organizer@example.com'")
	mustExec(t, h.app.DB, "INSERT INTO venues (id, name, user_id) VALUES (1, 'Main Hall', "+uid+")")
	mustExec(t, h.app.DB, "INSERT INTO events (id, title, starts_at, venue_id, user_id) VALUES (1, 'Launch', '2026-12-01T18:00:00Z', 1, "+uid+"), (2, 'Party', '2026-12-02T18:00:00Z', NULL, "+uid+")")
	html := h.str(`var tbl = mkEl(); sdui.DataTable(tbl, {table: 'events', columns: 'title,venue_id', paginate: false}).then(function () { return tbl.kids['[data-bm-tablebody]'].innerHTML; })`)
	if !strings.Contains(html, ">Main Hall<") {
		t.Fatalf("venue column does not show the venue's name: %s", html)
	}
	if strings.Contains(html, `<td class="px-4 py-2.5 align-top">1</td>`) {
		t.Fatalf("venue column still shows the raw id: %s", html)
	}
}

// A datetime-local control holds wall time in the viewer's zone. The form
// shows the stored instant in that zone and turns an edited value back into
// the same instant in UTC; it used to show (and save) the first 10
// characters, and a zone-less value is read by the server as UTC, so sending
// the control's text unconverted would shift it by the viewer's offset.
// Each zone runs in a child process (TZ is read once, at start).
func TestSDUIRecordFormDateTimeRoundTripsAcrossZones(t *testing.T) {
	if os.Getenv("BENMORE_SDUI_TZ_CHILD") != "" {
		sduiRecordFormDateTimeInZone(t)
		return
	}
	for _, zone := range []string{"UTC", "America/New_York", "Asia/Kolkata"} {
		if _, err := time.LoadLocation(zone); err != nil {
			t.Skipf("zone %s unavailable: %v", zone, err)
		}
		cmd := exec.Command(os.Args[0], "-test.run=^TestSDUIRecordFormDateTimeRoundTripsAcrossZones$", "-test.count=1")
		cmd.Env = append(os.Environ(), "TZ="+zone, "BENMORE_SDUI_TZ_CHILD="+zone)
		out, err := cmd.CombinedOutput()
		if err != nil || !strings.Contains(string(out), "PASS") {
			t.Fatalf("zone %s: %v\n%s", zone, err, out)
		}
	}
}

func sduiRecordFormDateTimeInZone(t *testing.T) {
	zone := os.Getenv("BENMORE_SDUI_TZ_CHILD")
	loc, err := time.LoadLocation(zone)
	if err != nil {
		t.Fatal(err)
	}
	probe := time.Date(2026, 12, 1, 12, 0, 0, 0, time.UTC)
	if _, local := probe.In(time.Local).Zone(); func() bool { _, want := probe.In(loc).Zone(); return local != want }() {
		t.Fatalf("child process is not running in %s (TZ ignored?)", zone)
	}
	h := newSDUIFormHarness(t)
	uid := h.scalar("SELECT id FROM _benmore_users WHERE email = 'organizer@example.com'")
	mustExec(t, h.app.DB, "INSERT INTO events (id, title, starts_at, user_id) VALUES (1, 'Launch', '2026-12-01T18:00:00Z', "+uid+")")

	stored := time.Date(2026, 12, 1, 18, 0, 0, 0, time.UTC)
	h.run(`var ed = mkEl(); sdui.RecordForm(ed, {table: 'events', id: 1});`)
	if got, want := h.str(`control(ed, 'starts_at').value`), stored.In(loc).Format("2006-01-02T15:04"); got != want {
		t.Fatalf("%s: control shows %q, want the stored instant's local time %q", zone, got, want)
	}
	h.run(`submit(ed, {});`)
	if got := h.scalar("SELECT starts_at FROM events WHERE id = 1"); got != "2026-12-01T18:00:00Z" {
		t.Fatalf("%s: unchanged edit rewrote starts_at to %q", zone, got)
	}

	h.run(`var ed2 = mkEl(); sdui.RecordForm(ed2, {table: 'events', id: 1});`)
	h.run(`submit(ed2, {starts_at: '2026-12-01T14:30'});`)
	want := time.Date(2026, 12, 1, 14, 30, 0, 0, loc).UTC()
	got := h.scalar("SELECT starts_at FROM events WHERE id = 1")
	at, err := time.Parse(time.RFC3339Nano, got)
	if err != nil || !at.Equal(want) {
		t.Fatalf("%s: 14:30 local saved as %q, want the instant %s", zone, got, want.Format(time.RFC3339))
	}
	// And the form shows what the person typed.
	h.run(`var ed3 = mkEl(); sdui.RecordForm(ed3, {table: 'events', id: 1});`)
	if got := h.str(`control(ed3, 'starts_at').value`); got != "2026-12-01T14:30" {
		t.Fatalf("%s: reopened form shows %q", zone, got)
	}
}
