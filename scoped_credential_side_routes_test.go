//go:build !cli

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"io/fs"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The routes below answered a credential scoped to one table as the whole
// account: a notes:read token read and stopped the account's live streams,
// joined and spoke in any room, registered a push device that then receives
// the account's notifications, stored files, read the account's usage and
// TURN credentials, and wrote feedback under the account's address.

// A broadcast slug is a room name: the membership table its ws_rooms pattern
// names decides, read to watch and write to publish, as for presence.
func TestScopedCredentialBroadcastNeedsTheRoomTableScope(t *testing.T) {
	f := newScopedRoutesFixture(t)
	for _, slug := range []string{"huddle-7", "lobby"} {
		crudScopeMustExec(t, f.app.DB, `INSERT INTO _benmore_broadcasts (slug, publisher_session_id, publisher_user_id) VALUES ('`+slug+`', 'sfu-`+slug+`', 1)`)
	}
	on := func(slug string) map[string]any { return map[string]any{"slug": slug, "sdp": "v=0"} }
	live := func(label string, rec *httptest.ResponseRecorder, want bool) {
		t.Helper()
		var body struct {
			Live bool `json:"live"`
		}
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &body) != nil || body.Live != want {
			t.Errorf("%s: %d %s, want live=%v", label, rec.Code, rec.Body.String(), want)
		}
	}

	for name, cred := range f.without() {
		assertScopeRefusal(t, name+" stats of a declared room", f.call(t, http.MethodGet, "/api/_broadcast/stats/huddle-7", cred, nil), "room_members:read")
		assertScopeRefusal(t, name+" subscribe to a declared room", f.call(t, http.MethodPost, "/api/_broadcast/subscribe", cred, on("huddle-7")), "room_members:read")
		assertScopeRefusal(t, name+" publish to a declared room", f.call(t, http.MethodPost, "/api/_broadcast/publish", cred, on("huddle-7")), "room_members:write")
		assertScopeRefusal(t, name+" heartbeat a declared room", f.call(t, http.MethodPost, "/api/_broadcast/heartbeat", cred, on("huddle-7")), "room_members:write")
		assertScopeRefusal(t, name+" stop a declared room", f.call(t, http.MethodPost, "/api/_broadcast/stop", cred, on("huddle-7")), "room_members:write")
		assertScopeRefusal(t, name+" stats of an undeclared room", f.call(t, http.MethodGet, "/api/_broadcast/stats/lobby", cred, nil), "names no table")
		assertScopeRefusal(t, name+" stop an undeclared room", f.call(t, http.MethodPost, "/api/_broadcast/stop", cred, on("lobby")), "names no table")
	}
	read, write := f.owner["token room_members:read"], f.owner["token room_members:write"]
	assertScopeRefusal(t, "room_members:read heartbeat", f.call(t, http.MethodPost, "/api/_broadcast/heartbeat", read, on("huddle-7")), "room_members:write")
	assertScopeRefusal(t, "room_members:read stop", f.call(t, http.MethodPost, "/api/_broadcast/stop", read, on("huddle-7")), "room_members:write")
	assertScopeRefusal(t, "room_members:write stats of an undeclared room", f.call(t, http.MethodGet, "/api/_broadcast/stats/lobby", write, nil), "names no table")
	if n := f.count(t, "SELECT COUNT(*) FROM _benmore_broadcasts"); n != 2 {
		t.Fatalf("refused stops left %d of 2 live broadcasts", n)
	}

	live("room_members:read stats", f.call(t, http.MethodGet, "/api/_broadcast/stats/huddle-7", read, nil), true)
	live("*:read stats of an undeclared room", f.call(t, http.MethodGet, "/api/_broadcast/stats/lobby", f.owner["token *:read"], nil), true)
	assertSideRouteStatus(t, "room_members:write heartbeat", f.call(t, http.MethodPost, "/api/_broadcast/heartbeat", write, on("huddle-7")), http.StatusOK)
	for name, cred := range f.unscoped() {
		live(name+" stats of a declared room", f.call(t, http.MethodGet, "/api/_broadcast/stats/huddle-7", cred, nil), true)
		live(name+" stats of an undeclared room", f.call(t, http.MethodGet, "/api/_broadcast/stats/lobby", cred, nil), true)
		assertSideRouteStatus(t, name+" heartbeat an undeclared room", f.call(t, http.MethodPost, "/api/_broadcast/heartbeat", cred, on("lobby")), http.StatusOK)
	}
	assertSideRouteStatus(t, "room_members:write stop", f.call(t, http.MethodPost, "/api/_broadcast/stop", write, on("huddle-7")), http.StatusOK)
	assertSideRouteStatus(t, "sign-in stop an undeclared room", f.call(t, http.MethodPost, "/api/_broadcast/stop", f.owner["sign-in"], on("lobby")), http.StatusOK)
	if n := f.count(t, "SELECT COUNT(*) FROM _benmore_broadcasts"); n != 0 {
		t.Fatalf("allowed stops left %d live broadcasts", n)
	}
}

// scopedRoutesSocket is one /ws connection of the fixture app held by cred.
type scopedRoutesSocket struct {
	client *wsClient
	wire   net.Conn
}

func (f *scopedRoutesFixture) socket(t *testing.T, cred string) *scopedRoutesSocket {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	req.Header.Set("Authorization", "Bearer "+cred)
	session := getSession(f.app, req)
	if session == nil {
		t.Fatal("fixture credential has no session")
	}
	srv, cli := net.Pipe()
	client := &wsClient{
		ws: &wsConn{conn: srv, br: bufio.NewReader(srv)}, send: make(chan []byte, 32),
		principal: realtimePrincipal{app: f.app, session: session},
		appID:     realtimeAppID(f.app.Dir), userID: session.UserID, email: session.Email,
		subscriptions: map[string]bool{}, rooms: map[string]bool{},
	}
	registerWSClient(client)
	go io.Copy(io.Discard, cli)
	done := make(chan struct{})
	go func() { wsReadLoop(client, f.app); close(done) }()
	t.Cleanup(func() { cli.Close(); <-done })
	return &scopedRoutesSocket{client: client, wire: cli}
}

// say sends one client message and returns the frames the server queued for
// this connection by the time it answered the ping sent right after.
func (s *scopedRoutesSocket) say(t *testing.T, msg wsClientMsg) string {
	t.Helper()
	for _, m := range []wsClientMsg{msg, {Type: "ping"}} {
		data, _ := json.Marshal(m)
		if _, err := s.wire.Write(wsTestTextFrame(string(data))); err != nil {
			t.Fatal(err)
		}
	}
	var frames []string
	for {
		select {
		case b := <-s.client.send:
			if strings.Contains(string(b), `"type":"pong"`) {
				return strings.Join(frames, "\n")
			}
			frames = append(frames, string(b))
		case <-time.After(5 * time.Second):
			t.Fatal("no pong after the message")
		}
	}
}

// heard drains the frames queued for this connection.
func (s *scopedRoutesSocket) heard() string {
	var frames []string
	for {
		select {
		case b := <-s.client.send:
			frames = append(frames, string(b))
		default:
			return strings.Join(frames, "\n")
		}
	}
}

func (s *scopedRoutesSocket) joined(room string) bool {
	s.client.subMu.RLock()
	defer s.client.subMu.RUnlock()
	return s.client.rooms[scopedRoomID(s.client, room)]
}

// A WebSocket room is the same room: joining (and so receiving) needs the
// membership table's read scope, sending its write scope, and a room no
// ws_rooms pattern declares names no table.
func TestScopedCredentialWSRoomsNeedTheRoomTableScope(t *testing.T) {
	resetWSHub(t)
	t.Cleanup(func() { resetWSHub(t) })
	f := newScopedRoutesFixture(t)
	join := func(room string) wsClientMsg { return wsClientMsg{Type: "join", Room: room} }
	speak := func(room string) wsClientMsg {
		return wsClientMsg{Type: "broadcast", Room: room, Payload: json.RawMessage(`{"m":1}`)}
	}

	listener := f.socket(t, f.owner["sign-in"])
	for _, room := range []string{"huddle-7", "lobby"} {
		if got := listener.say(t, join(room)); got != "" || !listener.joined(room) {
			t.Fatalf("sign-in join %s answered %q", room, got)
		}
	}

	for name, cred := range f.without() {
		s := f.socket(t, cred)
		if got := s.say(t, join("huddle-7")); !strings.Contains(got, "scope denied") || !strings.Contains(got, "room_members:read") || s.joined("huddle-7") {
			t.Errorf("%s join a declared room: joined=%v, answered %q, want a room_members:read scope refusal", name, s.joined("huddle-7"), got)
		}
		if got := s.say(t, join("lobby")); !strings.Contains(got, "names no table") || s.joined("lobby") {
			t.Errorf("%s join an undeclared room: joined=%v, answered %q, want a names-no-table refusal", name, s.joined("lobby"), got)
		}
		s.say(t, speak("huddle-7"))
		s.say(t, speak("lobby"))
	}
	if got := listener.heard(); got != "" {
		t.Errorf("refused joins and sends reached the room: %s", got)
	}

	reader := f.socket(t, f.owner["token room_members:read"])
	if got := reader.say(t, join("huddle-7")); got != "" || !reader.joined("huddle-7") {
		t.Fatalf("room_members:read join answered %q", got)
	}
	if got := listener.heard(); !strings.Contains(got, `"type":"presence"`) {
		t.Errorf("the room did not hear the reader join: %q", got)
	}
	if got := reader.say(t, speak("huddle-7")); !strings.Contains(got, "scope denied") || !strings.Contains(got, "room_members:write") {
		t.Errorf("room_members:read send answered %q, want a room_members:write scope refusal", got)
	}
	if got := listener.heard(); got != "" {
		t.Errorf("a read-only credential's message reached the room: %s", got)
	}
	if got := reader.say(t, join("lobby")); !strings.Contains(got, "names no table") || reader.joined("lobby") {
		t.Errorf("room_members:read join an undeclared room answered %q", got)
	}

	writer := f.socket(t, f.owner["token room_members:write"])
	writer.say(t, join("huddle-7"))
	listener.heard()
	reader.heard()
	if got := writer.say(t, speak("huddle-7")); got != "" {
		t.Errorf("room_members:write send answered %q", got)
	}
	for name, s := range map[string]*scopedRoutesSocket{"the sign-in": listener, "the read-scoped credential": reader} {
		if got := s.heard(); !strings.Contains(got, `"type":"message"`) || !strings.Contains(got, `"m":1`) {
			t.Errorf("%s did not hear the writer: %q", name, got)
		}
	}

	wild := f.socket(t, f.owner["token *:write"])
	if got := wild.say(t, join("lobby")); got != "" || !wild.joined("lobby") {
		t.Fatalf("*:write join an undeclared room answered %q", got)
	}
	listener.heard()
	wild.say(t, speak("lobby"))
	if got := listener.heard(); !strings.Contains(got, `"type":"message"`) {
		t.Errorf("a wildcard credential's message did not reach the undeclared room: %q", got)
	}
	full := f.socket(t, f.owner["token *"])
	full.say(t, join("lobby"))
	listener.heard()
	full.say(t, speak("lobby"))
	if got := listener.heard(); !strings.Contains(got, `"type":"message"`) {
		t.Errorf("an unscoped token's message did not reach the undeclared room: %q", got)
	}
}

// A registered device receives the account's push notifications: device
// registration is the account's own, like its sessions.
func TestScopedCredentialCannotRegisterOrRemoveDevices(t *testing.T) {
	f := newScopedRoutesFixture(t)
	device := map[string]any{"token": "device-1", "platform": "ios"}
	assertSideRouteStatus(t, "sign-in registers a device", f.call(t, http.MethodPost, "/api/_devices", f.owner["sign-in"], device), http.StatusOK)
	scoped := f.without()
	scoped["API token *:write"] = f.owner["token *:write"]
	for name, cred := range scoped {
		assertAccountRouteRefusal(t, name+" POST /api/_devices", f.call(t, http.MethodPost, "/api/_devices", cred, map[string]any{"token": "integration-phone", "platform": "android"}))
		assertAccountRouteRefusal(t, name+" DELETE /api/_devices", f.call(t, http.MethodDelete, "/api/_devices", cred, nil))
	}
	if n := f.count(t, "SELECT COUNT(*) FROM _benmore_devices WHERE user_id = 1 AND token = 'device-1'"); n != 1 {
		t.Errorf("the account's device row count is %d after refused removals, want 1", n)
	}
	if n := f.count(t, "SELECT COUNT(*) FROM _benmore_devices WHERE token = 'integration-phone'"); n != 0 {
		t.Errorf("a scoped credential registered %d devices", n)
	}
	assertSideRouteStatus(t, "API token * removes the device", f.call(t, http.MethodDelete, "/api/_devices", f.owner["token *"], device), http.StatusOK)
	if n := f.count(t, "SELECT COUNT(*) FROM _benmore_devices WHERE user_id = 1"); n != 0 {
		t.Errorf("%d devices left after the unscoped removal", n)
	}
}

func assertAccountRouteRefusal(t *testing.T, label string, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "full-access sign-in") {
		t.Errorf("%s: %d %s, want the 403 the account's own routes give a scoped credential", label, rec.Code, rec.Body.String())
	}
}

func (f *scopedRoutesFixture) upload(t *testing.T, path, cred string, fields map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for k, v := range fields {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatal(err)
		}
	}
	part, err := mw.CreateFormFile("file", "note.txt")
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(part, "scoped credential upload fixture")
	mw.Close()
	req := httptest.NewRequest(http.MethodPost, path, &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+cred)
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	return rec
}

// An upload is a write: a scoped credential stores a file only for a table
// its scopes write, named with the `table` field, and an upload naming none
// has no scope to ask for.
func TestScopedCredentialUploadsNeedATableWriteScope(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	f := newScopedRoutesFixture(t)
	SetAppEnv(f.app.Dir, "RATE_LIMIT_PER_MIN", "0")
	stored := func() (n int) {
		filepath.WalkDir(filepath.Join(f.app.Dir, "uploads"), func(_ string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				n++
			}
			return nil
		})
		return n
	}
	for _, path := range []string{"/api/_upload", "/api/_files"} {
		before := stored()
		for name, cred := range f.without() {
			assertScopeRefusal(t, name+" "+path, f.upload(t, path, cred, nil), "names no table")
			assertScopeRefusal(t, name+" "+path+" table=ledger", f.upload(t, path, cred, map[string]string{"table": "ledger"}), "ledger:write")
			assertScopeRefusal(t, name+" "+path+" table=notes", f.upload(t, path, cred, map[string]string{"table": "notes"}), "notes:write")
		}
		assertScopeRefusal(t, "ledger:read "+path, f.upload(t, path, f.owner["token ledger:read"], map[string]string{"table": "ledger"}), "ledger:write")
		assertScopeRefusal(t, "ledger:write "+path+" without a table", f.upload(t, path, f.owner["token ledger:write"], nil), "names no table")
		assertScopeRefusal(t, "ledger:write "+path+" for another table", f.upload(t, path, f.owner["token ledger:write"], map[string]string{"table": "notes"}), "notes:write")
		assertScopeRefusal(t, "ledger:write "+path+" for a name that is no table", f.upload(t, path, f.owner["token ledger:write"], map[string]string{"table": "nowhere"}), "names no table")
		if n := stored(); n != before {
			t.Fatalf("%s: refused uploads stored %d files", path, n-before)
		}
		assertSideRouteStatus(t, "ledger:write "+path+" table=ledger", f.upload(t, path, f.owner["token ledger:write"], map[string]string{"table": "ledger"}), http.StatusOK)
		assertSideRouteStatus(t, "ledger:write "+path+" table=LEDGER", f.upload(t, path, f.owner["token ledger:write"], map[string]string{"table": "LEDGER"}), http.StatusOK)
		assertSideRouteStatus(t, "*:write "+path, f.upload(t, path, f.owner["token *:write"], nil), http.StatusOK)
		for name, cred := range f.unscoped() {
			assertSideRouteStatus(t, name+" "+path, f.upload(t, path, cred, nil), http.StatusOK)
		}
		if n := stored(); n != before+5 {
			t.Fatalf("%s: %d of 5 allowed uploads stored", path, n-before)
		}
	}
}

// Usage counters describe the account (or its tenant), and TURN credentials
// relay traffic on the app's account: no table scope names either.
func TestScopedCredentialCannotReadUsageOrTURNCredentials(t *testing.T) {
	t.Setenv("BENMORE_PLATFORM_TURN_PROVIDER", "static")
	t.Setenv("BENMORE_PLATFORM_TURN_URL", "turn:turn.example.com:3478")
	t.Setenv("BENMORE_PLATFORM_TURN_USERNAME", "relay-user")
	t.Setenv("BENMORE_PLATFORM_TURN_CREDENTIAL", "relay-"+"secret")
	f := newScopedRoutesFixture(t)
	scoped := f.without()
	scoped["API token *:read"] = f.owner["token *:read"]
	for name, cred := range scoped {
		assertAccountRouteRefusal(t, name+" GET /api/_usage", f.call(t, http.MethodGet, "/api/_usage", cred, nil))
		rec := f.call(t, http.MethodGet, "/api/_webrtc/ice", cred, nil)
		assertAccountRouteRefusal(t, name+" GET /api/_webrtc/ice", rec)
		if strings.Contains(rec.Body.String(), "relay-") {
			t.Errorf("%s was handed the TURN credentials: %s", name, rec.Body.String())
		}
	}
	for name, cred := range f.unscoped() {
		rec := f.call(t, http.MethodGet, "/api/_usage", cred, nil)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"scope":"user:1"`) {
			t.Errorf("%s GET /api/_usage = %d %s, want the account's usage", name, rec.Code, rec.Body.String())
		}
		rec = f.call(t, http.MethodGet, "/api/_webrtc/ice", cred, nil)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "relay-user") {
			t.Errorf("%s GET /api/_webrtc/ice = %d %s, want the TURN server", name, rec.Code, rec.Body.String())
		}
	}
	anon := f.call(t, http.MethodGet, "/api/_webrtc/ice", "", nil)
	if anon.Code != http.StatusOK || strings.Contains(anon.Body.String(), "relay-user") || !strings.Contains(anon.Body.String(), "stun:") {
		t.Errorf("signed-out GET /api/_webrtc/ice = %d %s, want the STUN-only list", anon.Code, anon.Body.String())
	}
}

// Where the app admits anonymous realtime, anyone is handed TURN credentials:
// a scoped credential is answered as that anonymous caller, not refused.
func TestScopedCredentialGetsTheAnonymousICEAnswerWhereAnonymousIsAdmitted(t *testing.T) {
	t.Setenv("BENMORE_PLATFORM_TURN_PROVIDER", "static")
	t.Setenv("BENMORE_PLATFORM_TURN_URL", "turn:turn.example.com:3478")
	t.Setenv("BENMORE_PLATFORM_TURN_USERNAME", "relay-user")
	yes := true
	f := newScopedRoutesFixtureConfigured(t, nil, func(app *App) {
		app.Design.Features = &FeaturesConfig{WSAnonymous: &yes}
	})
	for name, cred := range f.without() {
		rec := f.call(t, http.MethodGet, "/api/_webrtc/ice", cred, nil)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "relay-user") {
			t.Errorf("%s GET /api/_webrtc/ice = %d %s, want what a signed-out caller gets", name, rec.Code, rec.Body.String())
		}
	}
}

// Feedback from a signed-in caller is stored under the account's address and
// skips the anonymous limit; in testing mode any sign-in reads the inbox.
func TestScopedCredentialCannotWriteOrReadFeedback(t *testing.T) {
	yes := true
	f := newScopedRoutesFixtureConfigured(t, nil, func(app *App) {
		app.Design.Features = &FeaturesConfig{Testing: &yes}
	})
	note := func(text string) map[string]any { return map[string]any{"body": text} }
	assertSideRouteStatus(t, "sign-in feedback", f.call(t, http.MethodPost, "/api/_feedback", f.owner["token *"], note("from the owner")), http.StatusOK)
	scoped := f.without()
	scoped["API token *:write"] = f.owner["token *:write"]
	for name, cred := range scoped {
		assertAccountRouteRefusal(t, name+" POST /api/_feedback", f.call(t, http.MethodPost, "/api/_feedback", cred, note("from an integration")))
		rec := f.call(t, http.MethodGet, "/api/_feedback", cred, nil)
		if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != "[]" {
			t.Errorf("%s GET /api/_feedback = %d %s, want the empty list a caller without access gets", name, rec.Code, rec.Body.String())
		}
		assertAccountRouteRefusal(t, name+" GET /api/_feedback/1", f.call(t, http.MethodGet, "/api/_feedback/1", cred, nil))
	}
	if n := f.count(t, "SELECT COUNT(*) FROM _benmore_feedback WHERE body = 'from an integration'"); n != 0 {
		t.Errorf("scoped credentials stored %d feedback items", n)
	}
	if n := f.count(t, "SELECT COUNT(*) FROM _benmore_feedback WHERE body = 'from the owner' AND visitor_email = 'owner@example.com'"); n != 1 {
		t.Errorf("the owner's feedback rows = %d, want 1 under the account's address", n)
	}
	for name, cred := range f.unscoped() {
		rec := f.call(t, http.MethodGet, "/api/_feedback", cred, nil)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "from the owner") {
			t.Errorf("%s GET /api/_feedback = %d %s, want the inbox", name, rec.Code, rec.Body.String())
		}
		assertSideRouteStatus(t, name+" GET /api/_feedback/1", f.call(t, http.MethodGet, "/api/_feedback/1", cred, nil), http.StatusOK)
	}
}
