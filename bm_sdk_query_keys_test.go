package main

import (
	"os"
	"strings"
	"testing"

	"github.com/dop251/goja"
)

// bmQueryHarness stands in for the rest of the SDK around bm.query: a manual
// clock behind setTimeout, an api.post that answers /api/_query with one row
// naming the table and the current rowVersion, and a bm.live stand-in that
// keeps the '*' handler so a test can deliver change events.
const bmQueryHarness = `
var now = 0, timers = [], nextTimer = 1;
function setTimeout(fn, ms) { var id = nextTimer++; timers.push({ id: id, at: now + (ms || 0), fn: fn }); return id; }
function clearTimeout(id) { timers = timers.filter(function (t) { return t.id !== id; }); }
function advance(ms) {
  var end = now + ms;
  for (;;) {
    timers.sort(function (a, b) { return a.at - b.at || a.id - b.id; });
    var t = timers[0];
    if (!t || t.at > end) break;
    timers.shift();
    now = t.at;
    t.fn();
  }
  now = end;
}
Date.now = function () { return now; };
var logged = [];
var console = { error: function (e) { logged.push(String(e)); }, warn: function (e) { logged.push(String(e)); } };
var _authRevision = 0;
function inBackground(fn) { return fn(); }
function EventSource() {}
var liveHandlers = [];
function live(name, fn) { liveHandlers.push({ name: name, fn: fn }); return function () {}; }
function emit(ev) { liveHandlers.forEach(function (h) { h.fn(ev); }); }
var rowVersion = 1, posts = [];
var api = { post: function (path, spec) {
  posts.push({ path: path, spec: spec });
  return Promise.resolve({ rows: [{ table: spec.table, version: rowVersion }] });
} };
function versions(snaps) { return snaps.map(function (s) { return s.data === undefined ? null : s.data[0].version; }); }
`

// bmQueryVM loads bm.query exactly as embedded/bm.js ships it.
func bmQueryVM(t *testing.T) *goja.Runtime {
	t.Helper()
	src, err := os.ReadFile("embedded/bm.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(src)
	// From the first query helper through the end of the query object.
	start := strings.Index(js, "function stableStringify(value) {")
	end := strings.Index(js, "\nconst bm = {")
	if start < 0 || end < start || !strings.Contains(js[start:end], "export const query = {") {
		t.Fatal("embedded/bm.js: the bm.query block was not found")
	}
	block := strings.Replace(js[start:end], "export const query", "const query", 1)
	vm := goja.New()
	if _, err := vm.RunString(bmQueryHarness + block); err != nil {
		t.Fatalf("bm.js query block does not load: %v", err)
	}
	return vm
}

// A page subscribes to a table read by asking tableKey for its key. tableKey
// used to answer ['table', name, spec], a key nothing writes: table() caches
// under ['query', {...spec, table}], so the subscriber stayed at undefined
// with no error. tableKey now answers the key table() caches under, for the
// same arguments.
func TestBMQueryTableKeyIsTheKeyTableCachesUnder(t *testing.T) {
	vm := bmQueryVM(t)
	roomRun(t, vm, `
var spec = { where: { team_id: 7 }, order_by: [{ col: 'position' }], limit: 50 };
var key = query.tableKey('team_cards', spec);
var snaps = [];
query.subscribe(key, function (s) { snaps.push(s); });
var result;
query.table('team_cards', spec).then(function (rows) { result = rows; });
`)
	roomWant(t, vm, `{result: result, cached: query.get(key), rendered: snaps[snaps.length - 1].data, pending: snaps[snaps.length - 1].pending}`,
		`{"result":[{"table":"team_cards","version":1}],"cached":[{"table":"team_cards","version":1}],"rendered":[{"table":"team_cards","version":1}],"pending":false}`)
	roomWant(t, vm, `posts`, `[{"path":"/api/_query","spec":{"where":{"team_id":7},"order_by":[{"col":"position"}],"limit":50,"table":"team_cards"}}]`)

	// The key table() uses is the one it has always used: the default key of
	// bm.query.read for the same request, so the two share one cache entry.
	roomWant(t, vm, `query.key(key)`, `"[\"query\",{\"limit\":50,\"order_by\":[{\"col\":\"position\"}],\"table\":\"team_cards\",\"where\":{\"team_id\":7}}]"`)
	roomWant(t, vm, `query.get(['query', { table: 'team_cards', where: { team_id: 7 }, order_by: [{ col: 'position' }], limit: 50 }])`,
		`[{"table":"team_cards","version":1}]`)
	roomWant(t, vm, `query.key(query.tableKey('team_cards'))`, `"[\"query\",{\"table\":\"team_cards\"}]"`)

	// Options that only steer the client (stale window, force, live) are not
	// part of the request, so they are not part of the key either.
	roomWant(t, vm, `query.key(query.tableKey('team_cards', { where: { team_id: 7 }, order_by: [{ col: 'position' }], limit: 50, staleTime: 60000, staleMs: 5, force: true, live: false })) === query.key(key)`, `true`)
	roomWant(t, vm, `logged`, `[]`)
}

// The subscriber found through tableKey also receives what live invalidation
// refetches: a change event for the table reaches the same cache entry.
func TestBMQueryTableKeySubscriberFollowsLiveInvalidation(t *testing.T) {
	vm := bmQueryVM(t)
	roomRun(t, vm, `
var spec = { where: { team_id: 7 } };
var snaps = [];
query.subscribe(query.tableKey('team_cards', spec), function (s) { snaps.push(s); });
query.table('team_cards', spec);
`)
	roomWant(t, vm, `{live: liveHandlers.map(function (h) { return h.name; }), versions: versions(snaps)}`, `{"live":["*"],"versions":[null,null,1]}`)
	roomRun(t, vm, `rowVersion = 2; emit({ table: 'other_table', action: 'update' }); advance(50);`)
	roomWant(t, vm, `{reads: posts.length, last: versions(snaps).pop()}`, `{"reads":1,"last":1}`)
	roomRun(t, vm, `emit({ table: 'team_cards', action: 'update' }); advance(50);`)
	roomWant(t, vm, `{reads: posts.length, last: versions(snaps).pop(), cached: query.get(query.tableKey('team_cards', spec))}`,
		`{"reads":2,"last":2,"cached":[{"table":"team_cards","version":2}]}`)
	// A tableless refresh hint (private and member-of tables) does the same.
	roomRun(t, vm, `rowVersion = 3; emit({ action: 'refresh' }); advance(50);`)
	roomWant(t, vm, `{reads: posts.length, last: versions(snaps).pop()}`, `{"reads":3,"last":3}`)
}

// A page that names its own key keeps working: table() caches under it,
// tableKey answers it for the same options, and the key is not sent to the
// server.
func TestBMQueryTableKeyAnswersACustomKey(t *testing.T) {
	vm := bmQueryVM(t)
	roomRun(t, vm, `
var opts = { where: { team_id: 7 }, key: 'board' };
var snaps = [];
query.subscribe('board', function (s) { snaps.push(s); });
query.table('team_cards', opts);
`)
	roomWant(t, vm, `{key: query.tableKey('team_cards', opts), versions: versions(snaps), sent: posts[0].spec}`,
		`{"key":"board","versions":[null,null,1],"sent":{"where":{"team_id":7},"table":"team_cards"}}`)
	// Live invalidation still finds a custom key.
	roomRun(t, vm, `rowVersion = 2; emit({ table: 'team_cards', action: 'insert' }); advance(50);`)
	roomWant(t, vm, `{last: versions(snaps).pop(), invalidated: query.invalidateTable('team_cards')}`, `{"last":2,"invalidated":["board"]}`)
}
