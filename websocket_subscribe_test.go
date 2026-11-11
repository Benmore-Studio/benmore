//go:build !cli

package main

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// wsSubscribeConn is a /ws connection as the handler builds it (a real read
// loop over a pipe, the caller's principal, registered in the hub), so a test
// sends the client frames an app sends and reads the frames it would get.
type wsSubscribeConn struct {
	t      *testing.T
	client *wsClient
	peer   net.Conn
}

func openWSSubscribeConn(t *testing.T, app *App, sid string) *wsSubscribeConn {
	t.Helper()
	req := httptest.NewRequest("GET", "/ws", nil)
	req.Header.Set("Authorization", "Bearer "+sid)
	session := getSession(app, req)
	if session == nil {
		t.Fatal("connection session did not resolve")
	}
	srv, peer := net.Pipe()
	client := newWSTestClient(realtimeAppID(app.Dir), session.UserID, session.EffectiveGroupID())
	client.ws = &wsConn{conn: srv, br: bufio.NewReader(srv)}
	client.principal = realtimePrincipal{app: app, request: req, session: session}
	client.isAdmin = session.IsAdminBypass()
	client.send = make(chan []byte, 32)
	registerWSClient(client)
	go io.Copy(io.Discard, peer)
	done := make(chan struct{})
	go func() { wsReadLoop(client, app); close(done) }()
	t.Cleanup(func() {
		peer.Close()
		<-done
		unregisterWSClient(client)
	})
	return &wsSubscribeConn{t: t, client: client, peer: peer}
}

// say sends one client frame and returns the frames the server queued in
// answer. The read loop handles frames in order, so the pong that answers a
// trailing ping proves the frame before it was handled.
func (c *wsSubscribeConn) say(frame string) []string {
	c.t.Helper()
	for _, f := range []string{frame, `{"type":"ping"}`} {
		if _, err := c.peer.Write(wsTestTextFrame(f)); err != nil {
			c.t.Fatal(err)
		}
	}
	var got []string
	for {
		select {
		case b := <-c.client.send:
			if string(b) == `{"type":"pong"}` {
				return got
			}
			got = append(got, string(b))
		case <-time.After(5 * time.Second):
			c.t.Fatalf("no pong after %s (frames so far %q)", frame, got)
		}
	}
}

// events returns the frames delivered since the last call.
func (c *wsSubscribeConn) events() []string {
	realtimeFlush()
	var got []string
	for {
		select {
		case b := <-c.client.send:
			got = append(got, string(b))
		default:
			return got
		}
	}
}

func wsChangeFrame(table, action string) string {
	b, _ := json.Marshal(wsServerMsg{Type: "change", Table: table, Action: action})
	return string(b)
}

// wsSubscribeApp is a two-table app whose tenant-a member reads both tables'
// events in full: orgdocs is tenant-keyed, rooms_public is readable by all.
func wsSubscribeApp(t *testing.T) (*App, string) {
	t.Helper()
	app := flowRealtimeApp(t)
	mustExec(t, app.DB, `CREATE TABLE rooms_public (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT)`)
	cols, err := GetTableColumns(app.DB, "rooms_public")
	if err != nil {
		t.Fatal(err)
	}
	app.Tables = append(app.Tables, Table{Name: "rooms_public", Columns: cols})
	app.Access.rules["rooms_public"] = map[AccessOp]string{"all": "everyone"}
	mustExec(t, app.DB, "INSERT INTO members (org_id, email) VALUES ('tenant-a', 'sub@example.com'), ('tenant-a', 'peer@example.com')")
	return app, createCrudScopeSession(t, app, "sub@example.com", "user", "tenant-a", "")
}

// raiseBoth writes to both tables as another member of the tenant would.
func wsRaiseBoth(app *App) {
	BroadcastChangeScoped(app, "orgdocs", "update", "tenant-a", 0)
	BroadcastChangeScoped(app, "rooms_public", "insert", "tenant-a", 0)
}

// A connection that never subscribes hears every table it may read.
func TestWSNoSubscribeReceivesEveryReadableTable(t *testing.T) {
	resetWSHub(t)
	app, sid := wsSubscribeApp(t)
	conn := openWSSubscribeConn(t, app, sid)
	wsRaiseBoth(app)
	got := strings.Join(conn.events(), "\n")
	for _, want := range []string{wsChangeFrame("orgdocs", "update"), wsChangeFrame("rooms_public", "insert")} {
		if !strings.Contains(got, want) {
			t.Fatalf("unsubscribed connection missed %s; got %q", want, got)
		}
	}
}

// A subscribe that names only unknown tables asked for none of the app's
// tables. It used to leave the every-table default on, so a misspelt name
// silently widened the stream to every readable table. Now no named event
// arrives, an error frame names what was not recognised, and the generic
// refresh (it names no table) still arrives.
func TestWSSubscribeUnknownTablesOnlyDeliversNoNamedEvents(t *testing.T) {
	resetWSHub(t)
	app, sid := wsSubscribeApp(t)
	conn := openWSSubscribeConn(t, app, sid)

	answer := conn.say(`{"type":"subscribe","tables":["__none__","orgdoc"]}`)
	if len(answer) != 1 {
		t.Fatalf("subscribe to unknown tables answered %q, want one error frame", answer)
	}
	var frame struct {
		Type   string   `json:"type"`
		Tables []string `json:"tables"`
		Body   string   `json:"body"`
	}
	if err := json.Unmarshal([]byte(answer[0]), &frame); err != nil {
		t.Fatal(err)
	}
	if frame.Type != "error" || strings.Join(frame.Tables, ",") != "__none__,orgdoc" || !strings.Contains(frame.Body, "__none__") {
		t.Fatalf("error frame = %s, want type error naming __none__ and orgdoc", answer[0])
	}

	wsRaiseBoth(app)
	BroadcastChangeScoped(app, "", "refresh", "", 0)
	got := conn.events()
	if len(got) != 1 || got[0] != string(realtimeWSGenericRefresh) {
		t.Fatalf("after subscribing to unknown tables only, got %q; want only the generic refresh", got)
	}
}

// Valid names among unknown ones are subscribed; the error frame names only
// the unknown ones.
func TestWSSubscribeKeepsValidNamesAndReportsUnknown(t *testing.T) {
	resetWSHub(t)
	app, sid := wsSubscribeApp(t)
	conn := openWSSubscribeConn(t, app, sid)

	answer := conn.say(`{"type":"subscribe","tables":["orgdocs","typo"]}`)
	if len(answer) != 1 || !strings.Contains(answer[0], `"tables":["typo"]`) || strings.Contains(answer[0], "orgdocs") {
		t.Fatalf("subscribe answered %q, want one error frame naming only typo", answer)
	}
	wsRaiseBoth(app)
	if got := conn.events(); len(got) != 1 || got[0] != wsChangeFrame("orgdocs", "update") {
		t.Fatalf("subscribed to orgdocs, got %q; want only its event", got)
	}
	if answer := conn.say(`{"type":"subscribe","tables":["rooms_public"]}`); len(answer) != 0 {
		t.Fatalf("subscribe to a known table answered %q, want nothing", answer)
	}
	wsRaiseBoth(app)
	if got := conn.events(); len(got) != 2 {
		t.Fatalf("subscribed to both tables, got %q; want both events", got)
	}
}

// A subscribe that carries no tables (`{type:'subscribe', room:'x'}`, a
// missing key, an empty list) changes nothing and is not answered: the
// every-table default stays on a connection that never subscribed, and an
// earlier subscription stays as it was.
func TestWSSubscribeWithoutTablesChangesNothing(t *testing.T) {
	resetWSHub(t)
	app, sid := wsSubscribeApp(t)
	conn := openWSSubscribeConn(t, app, sid)

	for _, frame := range []string{`{"type":"subscribe","room":"board-1"}`, `{"type":"subscribe"}`, `{"type":"subscribe","tables":[]}`} {
		if answer := conn.say(frame); len(answer) != 0 {
			t.Fatalf("%s answered %q, want nothing", frame, answer)
		}
	}
	wsRaiseBoth(app)
	if got := conn.events(); len(got) != 2 {
		t.Fatalf("after a subscribe without tables, got %q; want both tables' events", got)
	}

	conn.say(`{"type":"subscribe","tables":["orgdocs"]}`)
	conn.say(`{"type":"subscribe","room":"board-1"}`)
	wsRaiseBoth(app)
	if got := conn.events(); len(got) != 1 || got[0] != wsChangeFrame("orgdocs", "update") {
		t.Fatalf("a subscribe without tables changed an earlier subscription: got %q", got)
	}
}

// Unsubscribing from every subscribed table restores the every-table
// default; an unsubscribe on a connection that subscribed to nothing valid
// does too.
func TestWSUnsubscribeFromAllRestoresEveryTable(t *testing.T) {
	resetWSHub(t)
	app, sid := wsSubscribeApp(t)
	conn := openWSSubscribeConn(t, app, sid)

	conn.say(`{"type":"subscribe","tables":["orgdocs","rooms_public"]}`)
	conn.say(`{"type":"unsubscribe","tables":["rooms_public"]}`)
	wsRaiseBoth(app)
	if got := conn.events(); len(got) != 1 || got[0] != wsChangeFrame("orgdocs", "update") {
		t.Fatalf("after unsubscribing rooms_public, got %q; want only orgdocs", got)
	}
	conn.say(`{"type":"unsubscribe","tables":["orgdocs"]}`)
	wsRaiseBoth(app)
	if got := conn.events(); len(got) != 2 {
		t.Fatalf("after unsubscribing from every table, got %q; want both tables' events", got)
	}
}

// The notification event is a named change event for _benmore_notifications,
// addressed to the recipient. A connection that subscribed could never get
// it: the name was dropped as unknown, so the subscription filtered the
// event out, while SSE and an unsubscribed connection received it. The name
// is now a table a connection can subscribe to.
func TestWSSubscribedConnectionReceivesItsNotificationEvent(t *testing.T) {
	resetWSHub(t)
	app, sid := wsSubscribeApp(t)
	named := openWSSubscribeConn(t, app, sid)
	other := openWSSubscribeConn(t, app, sid)
	plain := openWSSubscribeConn(t, app, sid)
	peer := openWSSubscribeConn(t, app, createCrudScopeSession(t, app, "peer@example.com", "user", "tenant-a", ""))

	if answer := named.say(`{"type":"subscribe","tables":["orgdocs","_benmore_notifications"]}`); len(answer) != 0 {
		t.Fatalf("subscribing to _benmore_notifications answered %q, want nothing", answer)
	}
	other.say(`{"type":"subscribe","tables":["orgdocs"]}`)
	if answer := peer.say(`{"type":"subscribe","tables":["_benmore_notifications","_benmore_presence"]}`); len(answer) != 0 {
		t.Fatalf("subscribing to the framework event tables answered %q, want nothing", answer)
	}

	if _, err := CreateNotification(app.DB, named.client.userID, "Approval needed", "", "info", ""); err != nil {
		t.Fatal(err)
	}
	want := wsChangeFrame(notificationsTable, "insert")
	if got := named.events(); len(got) != 1 || got[0] != want {
		t.Fatalf("recipient's connection subscribed to _benmore_notifications got %q, want %s", got, want)
	}
	if got := plain.events(); len(got) != 1 || got[0] != want {
		t.Fatalf("recipient's unsubscribed connection got %q, want %s", got, want)
	}
	if got := other.events(); len(got) != 0 {
		t.Fatalf("recipient's connection subscribed to orgdocs only got %q, want nothing", got)
	}
	if got := peer.events(); len(got) != 0 {
		t.Fatalf("another user's connection got %q for a notification that is not theirs", got)
	}

	// The presence event is subscribable the same way.
	BroadcastScopedDirect(app, presenceTable, "insert", "tenant-a", 0)
	if got := peer.events(); len(got) != 1 || got[0] != wsChangeFrame(presenceTable, "insert") {
		t.Fatalf("connection subscribed to _benmore_presence got %q, want its event", got)
	}
	if got := named.events(); len(got) != 0 {
		t.Fatalf("connection not subscribed to _benmore_presence got %q, want nothing", got)
	}
}

// The unknown names echoed in an error frame are bounded, however many a
// frame carries.
func TestWSSubscribeErrorFrameIsBounded(t *testing.T) {
	resetWSHub(t)
	app, sid := wsSubscribeApp(t)
	conn := openWSSubscribeConn(t, app, sid)
	names := make([]string, 0, 400)
	for i := 0; i < 400; i++ {
		names = append(names, strings.Repeat("x", 100)+string(rune('a'+i%26)))
	}
	frame, _ := json.Marshal(wsClientMsg{Type: "subscribe", Tables: names})
	payload := string(frame)
	// A 16-bit length frame: the test helper writes 7-bit lengths only.
	head := []byte{0x80 | wsOpText, 0x80 | 126, byte(len(payload) >> 8), byte(len(payload)), 0, 0, 0, 0}
	if _, err := conn.peer.Write(append(head, payload...)); err != nil {
		t.Fatal(err)
	}
	answer := conn.say(`{"type":"subscribe","tables":["orgdocs"]}`)
	if len(answer) != 1 || len(answer[0]) > 2048 {
		t.Fatalf("error frame for 400 unknown names: %d frame(s), first %d bytes; want one frame under 2 KiB", len(answer), len(strings.Join(answer, "")))
	}
}
