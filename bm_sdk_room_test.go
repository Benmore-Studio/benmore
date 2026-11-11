package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dop251/goja"
)

// bmRoomHarness stands in for the browser around bm.room(): a WebSocket that
// behaves like a browser's (send while CONNECTING throws, send on a CLOSING or
// CLOSED socket is discarded without an error, close() fires onclose later), a
// manual clock behind setTimeout/Date.now, a fixed Math.random, and a fetch
// that answers the /ws probe with probeStatus.
const bmRoomHarness = `
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
Math.random = function () { return 0.5; };
var logged = [];
var console = { error: function (e) { logged.push(String(e)); }, warn: function (e) { logged.push(String(e)); } };
var location = { protocol: 'https:', host: 'app.test' };
var sockets = [];
function WebSocket(url) {
  this.url = url; this.readyState = 0; this.sent = []; this.discarded = []; this.closeCodes = [];
  sockets.push(this);
}
WebSocket.CONNECTING = 0; WebSocket.OPEN = 1; WebSocket.CLOSING = 2; WebSocket.CLOSED = 3;
WebSocket.prototype.send = function (d) {
  if (this.readyState === 0) throw new Error('InvalidStateError: still CONNECTING');
  if (this.readyState !== 1) { this.discarded.push(JSON.parse(d)); return; }
  this.sent.push(JSON.parse(d));
};
WebSocket.prototype.close = function (code) {
  this.closeCodes.push(code === undefined ? null : code);
  if (this.readyState >= 2) return;
  this.readyState = 2;
  var s = this;
  setTimeout(function () { s.readyState = 3; if (s.onclose) s.onclose({ code: code || 1005 }); }, 0);
};
// Test drivers: the server accepts, sends a frame, or drops the connection
// (a restart: TCP close with no close frame, which browsers report as 1006).
WebSocket.prototype.accept = function () { this.readyState = 1; if (this.onopen) this.onopen({}); };
WebSocket.prototype.recv = function (o) { if (this.onmessage) this.onmessage({ data: JSON.stringify(o) }); };
WebSocket.prototype.drop = function (code) {
  this.readyState = 3;
  if (this.onerror) this.onerror({});
  if (this.onclose) this.onclose({ code: code || 1006 });
};
var probeStatus = 400, probes = [];
function fetch(url, init) { probes.push({ url: url, init: init }); return Promise.resolve({ status: probeStatus }); }
var _sessionListeners = new Set();
var events = [];
function track(r) {
  r.onAny(function (payload, from, kind) { events.push({ kind: kind, payload: payload, from: from === undefined ? 'undefined' : from }); });
  return r;
}
function statuses() { return events.filter(function (e) { return e.kind === 'bm:status'; }).map(function (e) { return e.payload; }); }
function lastStatus() { var s = statuses(); return s[s.length - 1] || null; }
function errors() { return events.filter(function (e) { return e.kind === 'bm:error'; }).map(function (e) { return e.payload; }); }
function sendErr(r, p) { try { r.send(p); return null; } catch (e) { return { code: e.code, message: e.message }; } }
`

// bmRoomVM loads room() exactly as embedded/bm.js ships it.
func bmRoomVM(t *testing.T) *goja.Runtime {
	t.Helper()
	src, err := os.ReadFile("embedded/bm.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(src)
	// From the room constants and helpers through the end of room().
	start := strings.Index(js, "const ROOM_QUEUE_MAX")
	fnStart := strings.Index(js, "export function room(name) {")
	if start < 0 || fnStart < start {
		t.Fatal("embedded/bm.js: room() and its constants not found")
	}
	end := strings.Index(js[fnStart:], "\n}\n")
	if end < 0 {
		t.Fatal("embedded/bm.js: end of room() not found")
	}
	fn := strings.Replace(js[start:fnStart+end+3], "export function room", "function room", 1)
	vm := goja.New()
	if _, err := vm.RunString(bmRoomHarness + fn); err != nil {
		t.Fatalf("bm.js room() does not load: %v", err)
	}
	return vm
}

// roomRun runs a script; pending promise jobs (the /ws probe) settle when it
// returns, so state is read by a following roomGet.
func roomRun(t *testing.T, vm *goja.Runtime, script string) {
	t.Helper()
	if _, err := vm.RunString(script); err != nil {
		t.Fatalf("%s: %v", script, err)
	}
}

func roomGet(t *testing.T, vm *goja.Runtime, expr string) any {
	t.Helper()
	v, err := vm.RunString("JSON.stringify(" + expr + ")")
	if err != nil {
		t.Fatalf("%s: %v", expr, err)
	}
	if goja.IsUndefined(v) {
		return nil
	}
	var out any
	if err := json.Unmarshal([]byte(v.String()), &out); err != nil {
		t.Fatalf("%s: %v (%s)", expr, err, v.String())
	}
	return out
}

func roomWant(t *testing.T, vm *goja.Runtime, expr, wantJSON string) {
	t.Helper()
	var want any
	if err := json.Unmarshal([]byte(wantJSON), &want); err != nil {
		t.Fatalf("bad want %s: %v", wantJSON, err)
	}
	if got := roomGet(t, vm, expr); !reflect.DeepEqual(got, want) {
		gotJSON, _ := json.Marshal(got)
		t.Fatalf("%s\n got: %s\nwant: %s", expr, gotJSON, wantJSON)
	}
}

// A restart, env change or the server's heartbeat close drops every room
// socket. The room used to stay dead: no reconnect, and send() kept writing to
// the closed socket, which a browser discards without an error. It now
// reconnects, joins the room again, sends what was queued while it was down
// and reports each change of state.
func TestBMRoomReconnectsAndRejoinsAfterServerClose(t *testing.T) {
	vm := bmRoomVM(t)
	roomRun(t, vm, `
var r = track(room('lobby'));
var got = [];
r.on('chat', function (p, from) { got.push({ text: p.text, from: from }); });
sockets[0].accept();
var sentOpen = r.send({ kind: 'chat', text: 'before' });
sockets[0].recv({ type: 'message', room: 'lobby', from: 2, payload: { kind: 'chat', text: 'hi' } });
sockets[0].recv({ type: 'presence', room: 'lobby', from: 3, payload: { join: true } });
advance(2000);
sockets[0].drop(1006);
var queued = r.send({ kind: 'chat', text: 'during' });
`)
	roomWant(t, vm, `sockets[0].sent`, `[{"type":"join","room":"lobby"},{"type":"broadcast","room":"lobby","payload":{"kind":"chat","text":"before"}}]`)
	roomWant(t, vm, `{sentOpen: sentOpen, queued: queued, state: r.state, sockets: sockets.length, discarded: sockets[0].discarded}`,
		`{"sentOpen":true,"queued":false,"state":"reconnecting","sockets":1,"discarded":[]}`)
	roomWant(t, vm, `events.filter(function (e) { return e.kind === 'presence'; })`, `[{"kind":"presence","payload":{"join":true},"from":3}]`)
	roomWant(t, vm, `statuses()`, `[{"state":"open"},{"state":"reconnecting","attempt":1,"retryIn":375,"code":1006}]`)

	// Nothing reconnects before the delay; then a new socket joins again and
	// flushes the queued message after the join.
	roomRun(t, vm, `advance(374);`)
	roomWant(t, vm, `sockets.length`, `1`)
	roomRun(t, vm, `advance(1); sockets[1].accept();`)
	roomWant(t, vm, `{url: sockets[1].url, sent: sockets[1].sent, raw: r.raw === sockets[1], state: r.state}`,
		`{"url":"wss://app.test/ws","sent":[{"type":"join","room":"lobby"},{"type":"broadcast","room":"lobby","payload":{"kind":"chat","text":"during"}}],"raw":true,"state":"open"}`)
	roomWant(t, vm, `lastStatus()`, `{"state":"open","reconnected":true}`)

	// The new socket delivers; a late frame from the old one does not.
	roomRun(t, vm, `
sockets[1].recv({ type: 'message', room: 'lobby', from: 'server', payload: { kind: 'chat', text: 'after' } });
sockets[0].recv({ type: 'message', room: 'lobby', from: 9, payload: { kind: 'chat', text: 'stale' } });
var sentAfter = r.send({ kind: 'chat', text: 'again' });
`)
	roomWant(t, vm, `got`, `[{"text":"hi","from":2},{"text":"after","from":"server"}]`)
	roomWant(t, vm, `{sentAfter: sentAfter, last: sockets[1].sent[2], logged: logged}`,
		`{"sentAfter":true,"last":{"type":"broadcast","room":"lobby","payload":{"kind":"chat","text":"again"}},"logged":[]}`)
}

// Retries back off exponentially with jitter up to a 30 s ceiling. A handshake
// that fails before opening asks /ws once (a plain same-origin GET) whether it
// is refused; 400 (would upgrade), 429 and 5xx are transient. A connection
// that stays open 10 s starts the backoff over; one that drops at once does
// not, so an accept-then-close loop cannot spin.
func TestBMRoomRetryBackoffIsJitteredAndCapped(t *testing.T) {
	vm := bmRoomVM(t)
	roomRun(t, vm, `var r = track(room('lobby'));`)
	statuses := []int{400, 502, 429, 503, 400, 400, 400, 400, 400}
	var delays []float64
	for i, status := range statuses {
		roomRun(t, vm, `probeStatus = `+roomJSON(status)+`; sockets[sockets.length - 1].drop(1006);`)
		st, _ := roomGet(t, vm, `lastStatus()`).(map[string]any)
		if st == nil || st["state"] != "reconnecting" {
			t.Fatalf("attempt %d: status %v", i, st)
		}
		if st["http"] != float64(status) || st["attempt"] != float64(i+1) {
			t.Fatalf("attempt %d: status %v, want http %d attempt %d", i, st, status, i+1)
		}
		d := st["retryIn"].(float64)
		delays = append(delays, d)
		roomRun(t, vm, `advance(`+roomJSON(d)+`);`)
		roomWant(t, vm, `sockets.length`, roomJSON(i+2))
	}
	want := []float64{375, 750, 1500, 3000, 6000, 12000, 22500, 22500, 22500}
	if !reflect.DeepEqual(delays, want) {
		t.Fatalf("delays %v, want %v", delays, want)
	}
	roomWant(t, vm, `probes.length`, roomJSON(len(statuses)))
	roomWant(t, vm, `probes[0]`, `{"url":"/ws","init":{"credentials":"same-origin","cache":"no-store"}}`)

	// Jitter stays within [ceiling/2, ceiling].
	roomRun(t, vm, `Math.random = function () { return 0.999999; }; sockets[sockets.length - 1].drop(1006);`)
	if d := roomGet(t, vm, `lastStatus().retryIn`).(float64); d > 30000 || d < 15000 {
		t.Fatalf("capped jittered delay %v outside [15000, 30000]", d)
	}
	roomRun(t, vm, `Math.random = function () { return 0.5; }; advance(30000);`)

	// An open that drops at once keeps the backoff growing; ten stable
	// seconds reset it. Opens never probe.
	roomRun(t, vm, `var before = probes.length; sockets[sockets.length - 1].accept(); sockets[sockets.length - 1].drop(1013);`)
	roomWant(t, vm, `{retryIn: lastStatus().retryIn, probed: probes.length - before}`, `{"retryIn":22500,"probed":0}`)
	roomRun(t, vm, `advance(22500); sockets[sockets.length - 1].accept(); advance(10000); sockets[sockets.length - 1].drop(1000);`)
	roomWant(t, vm, `{retryIn: lastStatus().retryIn, attempt: lastStatus().attempt}`, `{"retryIn":375,"attempt":1}`)
}

// The server answers a refused join (ws_rooms membership) with
// {type:'error', room, body}. It was dropped, so a non-member's room failed
// silently. It now reaches on('bm:error') and onAny, and the room closes
// without reconnecting: retrying cannot change a membership answer.
func TestBMRoomSurfacesJoinRefusalAndStops(t *testing.T) {
	vm := bmRoomVM(t)
	roomRun(t, vm, `
var r = track(room('channel-7'));
var errs = [];
r.on('bm:error', function (e, from) { errs.push({ e: e, from: from }); });
sockets[0].accept();
sockets[0].recv({ type: 'error', room: 'channel-7', body: 'not a member of this room' });
advance(120000);
`)
	roomWant(t, vm, `errs`, `[{"e":{"code":"not_member","message":"not a member of this room","room":"channel-7"},"from":null}]`)
	roomWant(t, vm, `{state: r.state, last: lastStatus(), sockets: sockets.length, closed: sockets[0].closeCodes, probes: probes.length}`,
		`{"state":"closed","last":{"state":"closed","reason":"refused"},"sockets":1,"closed":[1000],"probes":0}`)
	roomWant(t, vm, `sendErr(r, { kind: 'chat' })`, `{"code":"room_closed","message":"bm.room('channel-7') is closed (refused); call bm.room() to join again"}`)
	roomWant(t, vm, `sockets[0].discarded`, `[]`)
}

// An app may send a table subscribe on the room's socket (room.raw). The
// server answers unknown table names with {type:'error', tables, body}, which
// says nothing about the room: the room stays open and reports no bm:error.
func TestBMRoomIgnoresTableSubscribeErrorFrame(t *testing.T) {
	vm := bmRoomVM(t)
	roomRun(t, vm, `
var r = track(room('channel-7'));
sockets[0].accept();
sockets[0].recv({ type: 'error', tables: ['notez'], body: 'subscribe: unknown table notez' });
advance(1000);
`)
	roomWant(t, vm, `{state: r.state, errors: errors(), sockets: sockets.length, closed: sockets[0].closeCodes}`,
		`{"state":"open","errors":[],"sockets":1,"closed":[]}`)
}

// A handshake the server refuses with 401 (signed out) or 403 (cross-origin)
// cannot succeed by retrying. Browsers hide the status from the WebSocket, so
// the room asks /ws once; a 401/403 ends the room with a bm:error and the
// count of queued messages that were never sent.
func TestBMRoomStopsOnUpgradeRefusal(t *testing.T) {
	for _, tc := range []struct {
		status int
		code   string
	}{{401, "unauthorized"}, {403, "forbidden"}} {
		t.Run(tc.code, func(t *testing.T) {
			vm := bmRoomVM(t)
			roomRun(t, vm, `
var r = track(room('lobby'));
r.send({ kind: 'chat', text: 'queued 1' });
r.send({ kind: 'chat', text: 'queued 2' });
probeStatus = `+roomJSON(tc.status)+`;
sockets[0].drop(1006);
`)
			roomRun(t, vm, `advance(120000);`)
			roomWant(t, vm, `{state: r.state, sockets: sockets.length, probes: probes.length, errors: errors()}`,
				`{"state":"closed","sockets":1,"probes":1,"errors":[{"code":"`+tc.code+`","message":"the server refused the WebSocket connection (HTTP `+roomJSON(tc.status)+`)","room":"lobby"}]}`)
			roomWant(t, vm, `statuses()`, `[{"state":"closed","reason":"`+tc.code+`","unsent":2}]`)
			roomWant(t, vm, `sendErr(r, {}).code`, `"room_closed"`)
		})
	}
}

// leave() is final: no reconnect from an open socket, from a pending retry
// timer, or from a probe still in flight.
func TestBMRoomLeaveStopsReconnect(t *testing.T) {
	t.Run("open", func(t *testing.T) {
		vm := bmRoomVM(t)
		roomRun(t, vm, `var r = track(room('lobby')); sockets[0].accept(); r.leave(); advance(120000);`)
		roomWant(t, vm, `{sent: sockets[0].sent, closed: sockets[0].closeCodes, sockets: sockets.length, state: r.state, last: lastStatus()}`,
			`{"sent":[{"type":"join","room":"lobby"},{"type":"leave","room":"lobby"}],"closed":[1000],"sockets":1,"state":"closed","last":{"state":"closed","reason":"left"}}`)
		roomWant(t, vm, `_sessionListeners.size`, `0`)
	})
	t.Run("retry timer", func(t *testing.T) {
		vm := bmRoomVM(t)
		roomRun(t, vm, `var r = track(room('lobby')); sockets[0].accept(); sockets[0].drop(1006); r.leave(); advance(120000);`)
		roomWant(t, vm, `{sockets: sockets.length, state: r.state, timers: timers.length}`, `{"sockets":1,"state":"closed","timers":0}`)
	})
	t.Run("probe in flight", func(t *testing.T) {
		vm := bmRoomVM(t)
		// The probe resolves (400: transient) after leave() in the same turn.
		roomRun(t, vm, `var r = track(room('lobby')); sockets[0].drop(1006); r.leave();`)
		roomRun(t, vm, `advance(120000);`)
		roomWant(t, vm, `{sockets: sockets.length, state: r.state, probes: probes.length, last: lastStatus()}`,
			`{"sockets":1,"state":"closed","probes":1,"last":{"state":"closed","reason":"left"}}`)
	})
	t.Run("leave from a status handler", func(t *testing.T) {
		vm := bmRoomVM(t)
		roomRun(t, vm, `
var r = track(room('lobby'));
r.on('bm:status', function (s) { if (s.state === 'reconnecting') r.leave(); });
sockets[0].accept(); sockets[0].drop(1006); advance(120000);`)
		roomWant(t, vm, `{sockets: sockets.length, state: r.state}`, `{"sockets":1,"state":"closed"}`)
	})
}

// A room the server refused (signed out, not a member) opens again when the
// page's session changes (bm.auth sign-in, tenant switch), like the bm.live
// stream. A room the app left does not.
func TestBMRoomSessionChangeReconnects(t *testing.T) {
	vm := bmRoomVM(t)
	roomRun(t, vm, `
var r = track(room('lobby'));
var gone = track(room('other'));
probeStatus = 401;
sockets[0].drop(1006);
gone.leave();
`)
	roomWant(t, vm, `{state: r.state, sessionListeners: _sessionListeners.size}`, `{"state":"closed","sessionListeners":1}`)
	roomRun(t, vm, `_sessionListeners.forEach(function (fn) { fn(true); });`)
	roomWant(t, vm, `{sockets: sockets.length, state: r.state, url: sockets[2].url}`, `{"sockets":3,"state":"connecting","url":"wss://app.test/ws"}`)
	roomRun(t, vm, `sockets[2].accept();`)
	roomWant(t, vm, `{sent: sockets[2].sent, state: r.state, gone: gone.state}`, `{"sent":[{"type":"join","room":"lobby"}],"state":"open","gone":"closed"}`)

	// An open room's socket still carries the old session: it is replaced.
	roomRun(t, vm, `_sessionListeners.forEach(function (fn) { fn(false); }); advance(0);`)
	roomWant(t, vm, `{sockets: sockets.length, oldClosed: sockets[2].closeCodes, state: r.state, last: lastStatus()}`,
		`{"sockets":4,"oldClosed":[1000],"state":"reconnecting","last":{"state":"reconnecting","attempt":0,"retryIn":0}}`)
}

// Sends made while the room is not open wait (in order) and go out after the
// join. The queue holds 16, below the server's 20 frames per second per
// connection, so its flush cannot trip the rate limit; the 17th throws rather
// than vanishing.
func TestBMRoomQueueIsBoundedAndNeverSilent(t *testing.T) {
	vm := bmRoomVM(t)
	roomRun(t, vm, `
var r = room('lobby');
var queuedAll = true;
for (var i = 0; i < 16; i++) queuedAll = r.send({ n: i }) === false && queuedAll;
var overflow = sendErr(r, { n: 16 });
sockets[0].accept();
`)
	roomWant(t, vm, `{queuedAll: queuedAll, overflow: overflow.code, frames: sockets[0].sent.length, first: sockets[0].sent[0].type, last: sockets[0].sent[16].payload}`,
		`{"queuedAll":true,"overflow":"room_queue_full","frames":17,"first":"join","last":{"n":15}}`)
	// The payload is serialized at send time, so a later mutation does not
	// change a queued message.
	roomRun(t, vm, `sockets[0].drop(1006); var p = { text: 'a' }; r.send(p); p.text = 'b'; advance(375); sockets[1].accept();`)
	roomWant(t, vm, `sockets[1].sent[1].payload`, `{"text":"a"}`)
}

// bm.room() reads a handshake that failed before opening by sending GET /ws
// without upgrade headers: 401/403 end the room, anything else is retried.
// This pins the answers it relies on through the full app mux, so no login
// redirect or other middleware stands in front of the WebSocket gate: signed
// out in an app with an auth: block 401, a foreign Origin 403, and a caller
// the upgrade would admit 400.
func TestWSPlainGETAnswersTheRoomProbe(t *testing.T) {
	resetWSHub(t)
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := EnsureUsersTable(db); err != nil {
		t.Fatal(err)
	}
	EnsureSessionsTable(db)
	app := &App{Dir: dir, DB: db, SessionDuration: time.Hour, Stop: make(chan struct{}), Paths: DiscoverAuthPaths(nil),
		Design: &DesignConfig{Auth: map[string]string{"identifier": "email"}}}
	t.Cleanup(app.Shutdown)
	mux := buildAppMux(app, false, "http://app.test")
	sid := createCrudScopeSession(t, app, "member@example.test", "user", "", "")

	probe := func(cookie, origin string) int {
		req := httptest.NewRequest("GET", "http://app.test/ws", nil)
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookie})
		}
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Code
	}
	if got := probe("", ""); got != http.StatusUnauthorized {
		t.Fatalf("signed-out probe: %d, want 401 (the room stops)", got)
	}
	if got := probe(sid, "https://elsewhere.test"); got != http.StatusForbidden {
		t.Fatalf("cross-origin probe: %d, want 403 (the room stops)", got)
	}
	if got := probe(sid, ""); got != http.StatusBadRequest {
		t.Fatalf("signed-in probe: %d, want 400 (would upgrade; the room retries)", got)
	}
}

func roomJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
