//go:build !cli

package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// WebSocket support - zero external dependencies.
// Implements RFC 6455 handshake + text frame reading/writing.
//
// Route: GET /ws - upgrades to WebSocket connection
// Auth: session cookie required (same as SSE) when app uses auth
// Scoping: same model as SSE - group_id, user_id, admin bypass
//
// Server → Client: {"type":"change","table":"contacts","action":"create"}
// Client → Server: {"type":"subscribe","tables":["contacts","deals"]}

const (
	wsMaxMessageSize     = 64 * 1024 // 64KB max client message
	wsReadIdleTimeout    = 5 * time.Minute
	wsWriteTimeout       = 10 * time.Second
	wsClientMsgRateLimit = 20 // max messages per second per connection
	wsMaxConnsPerUser    = 10
	wsSendBufferSize     = 64
	wsMagicGUID          = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11" // RFC 6455 §4.2.2

	// H-16: the per-user cap keys on userID, so every anonymous client
	// shares userID==0 and - when the app has no auth, or ws_anonymous is
	// on - the cap was either skipped entirely or pooled all anon clients
	// into one bucket. These two caps close that hole:
	//   - realtimeWSMaxConnsGlobal bounds total concurrent WS connections
	//     across the whole hub (a hard ceiling no client class can exceed).
	//   - realtimeWSMaxConnsPerAnonIP bounds concurrent connections from a
	//     single source IP for clients that have NO authenticated user
	//     (userID==0), so one anonymous host can't exhaust the global pool.
	realtimeWSMaxConnsGlobal    = 5000
	realtimeWSMaxConnsPerAnonIP = 30
)

// Frame opcodes (RFC 6455 §5.2)
const (
	wsOpText  = 1
	wsOpClose = 8
	wsOpPing  = 9
	wsOpPong  = 10
)

// wsConn wraps a hijacked net.Conn with WebSocket frame read/write.
type wsConn struct {
	conn net.Conn
	br   *bufio.Reader
	mu   sync.Mutex // protects writes
}

// wsClient represents a connected WebSocket client.
type wsClient struct {
	ws      *wsConn
	send    chan []byte
	appID   string // app identity (set to app.Name on connect - prevents cross-app room collision in host mode)
	userID  int64
	email   string // session email - ws_rooms membership checks against email-shaped user columns
	groupID string
	isAdmin bool
	// remoteIP is the connecting client's source host (no port), captured
	// at connect time for the H-16 per-anonymous-IP connection cap.
	remoteIP string
	// wsAnonShared signals that this app has features.ws_anonymous: true
	// AND no groups: scoping - i.e. the developer explicitly opted in to
	// "let anon viewers participate in the same rooms as authed users."
	// When set, scopedRoomID treats anon and authed clients as sharing
	// the same `<appID>|app:<room>` bucket so broadcasts reach both.
	// Without this, anon clients live in their own `<appID>|anon:<room>`
	// bucket and never see authed-user broadcasts - which broke the
	// canonical livestream pattern (authed host, anon viewers).
	wsAnonShared  bool
	subscriptions map[string]bool
	rooms         map[string]bool // room ID -> joined
	subMu         sync.RWMutex
}

// WSHub manages WebSocket connections.
type WSHub struct {
	mu      sync.RWMutex
	clients map[*wsClient]bool
}

var wsHub = &WSHub{clients: make(map[*wsClient]bool)}

type wsClientMsg struct {
	Type    string          `json:"type"`
	Tables  []string        `json:"tables,omitempty"`
	Room    string          `json:"room,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

type wsServerMsg struct {
	Type    string          `json:"type"`
	Table   string          `json:"table,omitempty"`
	Action  string          `json:"action,omitempty"`
	Title   string          `json:"title,omitempty"`
	Body    string          `json:"body,omitempty"`
	Room    string          `json:"room,omitempty"`
	From    int64           `json:"from,omitempty"` // user_id of broadcaster
	Payload json.RawMessage `json:"payload,omitempty"`
}

// ===== RFC 6455 Handshake =====

func wsAcceptKey(clientKey string) string {
	h := sha1.New()
	h.Write([]byte(clientKey + wsMagicGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func wsUpgrade(w http.ResponseWriter, r *http.Request) (*wsConn, error) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") ||
		!strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
		return nil, errors.New("not a websocket upgrade request")
	}

	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		return nil, errors.New("missing Sec-WebSocket-Key")
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("server does not support hijacking")
	}

	conn, bufrw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}

	// Write the upgrade response
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + wsAcceptKey(key) + "\r\n\r\n"
	if _, err := conn.Write([]byte(resp)); err != nil {
		conn.Close()
		return nil, err
	}

	return &wsConn{conn: conn, br: bufrw.Reader}, nil
}

// ===== RFC 6455 Frame Read/Write =====

func (ws *wsConn) readFrame() (opcode byte, payload []byte, err error) {
	ws.conn.SetReadDeadline(time.Now().Add(wsReadIdleTimeout))

	// Read first 2 bytes: FIN + opcode + MASK + payload length
	header := make([]byte, 2)
	if _, err := io.ReadFull(ws.br, header); err != nil {
		return 0, nil, err
	}

	opcode = header[0] & 0x0F
	masked := header[1]&0x80 != 0
	length := uint64(header[1] & 0x7F)

	// Extended payload length
	switch length {
	case 126:
		ext := make([]byte, 2)
		if _, err := io.ReadFull(ws.br, ext); err != nil {
			return 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(ext))
	case 127:
		ext := make([]byte, 8)
		if _, err := io.ReadFull(ws.br, ext); err != nil {
			return 0, nil, err
		}
		length = binary.BigEndian.Uint64(ext)
	}

	if length > wsMaxMessageSize {
		return 0, nil, errors.New("message too large")
	}

	// Masking key (client → server frames MUST be masked per RFC 6455 §5.3)
	var maskKey [4]byte
	if masked {
		if _, err := io.ReadFull(ws.br, maskKey[:]); err != nil {
			return 0, nil, err
		}
	}

	// Payload
	payload = make([]byte, length)
	if _, err := io.ReadFull(ws.br, payload); err != nil {
		return 0, nil, err
	}

	// Unmask
	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}

	return opcode, payload, nil
}

func (ws *wsConn) writeFrame(opcode byte, payload []byte) error {
	ws.mu.Lock()
	defer ws.mu.Unlock()

	ws.conn.SetWriteDeadline(time.Now().Add(wsWriteTimeout))

	// Server → client frames are NOT masked
	length := len(payload)

	// Header: FIN=1 + opcode
	header := []byte{0x80 | opcode}

	// Payload length encoding
	switch {
	case length <= 125:
		header = append(header, byte(length))
	case length <= 65535:
		header = append(header, 126)
		ext := make([]byte, 2)
		binary.BigEndian.PutUint16(ext, uint16(length))
		header = append(header, ext...)
	default:
		header = append(header, 127)
		ext := make([]byte, 8)
		binary.BigEndian.PutUint64(ext, uint64(length))
		header = append(header, ext...)
	}

	if _, err := ws.conn.Write(header); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := ws.conn.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

func (ws *wsConn) writeText(data []byte) error {
	return ws.writeFrame(wsOpText, data)
}

func (ws *wsConn) writePong(data []byte) error {
	return ws.writeFrame(wsOpPong, data)
}

func (ws *wsConn) writeClose(code uint16, reason string) error {
	payload := make([]byte, 2+len(reason))
	binary.BigEndian.PutUint16(payload, code)
	copy(payload[2:], reason)
	ws.writeFrame(wsOpClose, payload)
	return ws.conn.Close()
}

func (ws *wsConn) close() {
	ws.writeClose(1000, "")
}

// ===== Hub + Routes =====

func RegisterWebSocketRoutes(mux *http.ServeMux, app *App) {
	needsAuth := NeedsAuth(app)

	mux.HandleFunc("GET /ws", func(w http.ResponseWriter, r *http.Request) {
		// Re-read the wsAnonymous flag PER REQUEST so SIGHUP reloads pick
		// it up without a full unit restart. Closure-captured snapshots
		// of app.Design would be stale after hot reload swaps the pointer.
		wsAnonymous := app.Design != nil && app.Design.Features != nil &&
			app.Design.Features.WSAnonymous != nil && *app.Design.Features.WSAnonymous
		if !isSameOriginRequest(r) {
			http.Error(w, "cross-origin websocket blocked", http.StatusForbidden)
			return
		}
		var userID int64
		var email string
		var groupID string
		var isAdmin bool
		if needsAuth && !wsAnonymous {
			session := getSession(app, r)
			if session == nil {
				http.Error(w, "authentication required", http.StatusUnauthorized)
				return
			}
			userID = session.UserID
			email = session.Email
			groupID = session.GroupID
			isAdmin = session.IsAdmin()
		} else if needsAuth && wsAnonymous {
			// Best-effort session attach so authed visitors still get
			// their scoped fan-out, but unauthed visitors aren't blocked.
			if session := getSession(app, r); session != nil {
				userID = session.UserID
				email = session.Email
				groupID = session.GroupID
				isAdmin = session.IsAdmin()
			}
		}

		// Source host for the H-16 per-anonymous-IP cap. Use RemoteAddr
		// (not X-Forwarded-For, which is spoofable) so an attacker can't
		// evade the per-IP ceiling by forging a header. Drop the ephemeral
		// port so reconnects from the same host count together.
		remoteIP := r.RemoteAddr
		if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			remoteIP = h
		}

		// Connection caps. H-16: the per-user cap below keys on userID,
		// which is 0 for every anonymous client - so without a global cap
		// and a per-anon-IP cap, an app with no auth (or ws_anonymous on)
		// had effectively no WS connection limit. We take a single RLock
		// and tally all three counts at once.
		isAnon := userID == 0
		wsHub.mu.RLock()
		globalCount := len(wsHub.clients)
		var userCount, anonIPCount int
		for c := range wsHub.clients {
			if needsAuth && !isAdmin && userID != 0 && c.userID == userID {
				userCount++
			}
			if isAnon && c.userID == 0 && c.remoteIP == remoteIP {
				anonIPCount++
			}
		}
		wsHub.mu.RUnlock()

		// Global ceiling: a hard cap no client class can exceed (admins
		// included - this protects the process, not a tenant).
		if globalCount >= realtimeWSMaxConnsGlobal {
			http.Error(w, "too many connections", http.StatusServiceUnavailable)
			return
		}
		// Per-anonymous-IP cap: closes the userID==0 pooling bypass.
		if isAnon && anonIPCount >= realtimeWSMaxConnsPerAnonIP {
			http.Error(w, "too many connections", http.StatusTooManyRequests)
			return
		}
		// Per-user connection limit (authenticated, non-admin clients).
		if needsAuth && !isAdmin && userID != 0 && userCount >= wsMaxConnsPerUser {
			http.Error(w, "too many connections", http.StatusTooManyRequests)
			return
		}

		// Upgrade - reject non-WebSocket requests with proper HTTP error
		ws, err := wsUpgrade(w, r)
		if err != nil {
			http.Error(w, "WebSocket upgrade required", http.StatusBadRequest)
			return
		}

		// When ws_anonymous is on AND no groups: scoping is configured,
		// anon viewers and authed broadcasters should share the same
		// app-wide room bucket. Multi-tenant apps (groups: set) still
		// partition by group so cross-org isolation holds.
		anonShared := wsAnonymous && (app.Group == nil || app.Group.Key == "")

		client := &wsClient{
			ws:            ws,
			send:          make(chan []byte, wsSendBufferSize),
			appID:         filepath.Base(app.Dir),
			userID:        userID,
			email:         email,
			groupID:       groupID,
			isAdmin:       isAdmin,
			remoteIP:      remoteIP,
			wsAnonShared:  anonShared,
			subscriptions: make(map[string]bool),
			rooms:         make(map[string]bool),
		}

		// H-16: re-check the global ceiling under the write lock before
		// inserting. The pre-upgrade RLock count above is racy (many
		// handshakes can pass it concurrently); this authoritative check
		// guarantees the hub size never exceeds realtimeWSMaxConnsGlobal.
		wsHub.mu.Lock()
		if len(wsHub.clients) >= realtimeWSMaxConnsGlobal {
			wsHub.mu.Unlock()
			ws.writeClose(1013, "server overloaded") // 1013 = Try Again Later
			return
		}
		wsHub.clients[client] = true
		wsHub.mu.Unlock()

		// Write loop in goroutine
		done := make(chan struct{})
		go func() {
			defer close(done)
			wsWriteLoop(client)
		}()

		// Read loop blocks until connection closes
		wsReadLoop(client, app)

		// Cleanup
		wsHub.mu.Lock()
		delete(wsHub.clients, client)
		wsHub.mu.Unlock()
		close(client.send)
		ws.close()
		<-done
	})

	log.Printf("  ws: /ws (bidirectional, zero deps, RFC 6455)")
}

func wsReadLoop(client *wsClient, app *App) {
	var msgCount int
	var windowStart time.Time

	for {
		opcode, payload, err := client.ws.readFrame()
		if err != nil {
			return
		}

		switch opcode {
		case wsOpText:
			// Rate limit
			now := time.Now()
			if now.Sub(windowStart) > time.Second {
				msgCount = 0
				windowStart = now
			}
			msgCount++
			if msgCount > wsClientMsgRateLimit {
				client.ws.writeClose(1008, "rate limit exceeded")
				return
			}

			var msg wsClientMsg
			if err := json.Unmarshal(payload, &msg); err != nil {
				continue
			}

			switch msg.Type {
			case "subscribe":
				client.subMu.Lock()
				for _, t := range msg.Tables {
					if wsTableExists(app, t) {
						client.subscriptions[t] = true
					}
				}
				client.subMu.Unlock()
			case "unsubscribe":
				client.subMu.Lock()
				for _, t := range msg.Tables {
					delete(client.subscriptions, t)
				}
				client.subMu.Unlock()
			case "join":
				// ws_rooms authorization (v2.7.164): room names matching
				// a declared pattern require a membership row. Join is
				// the single gate - "broadcast" already requires having
				// joined, so gating here covers sends too. Rooms with no
				// matching pattern keep the historical scope-bucket-only
				// behavior.
				if !wsRoomAuthorized(app, client, msg.Room) {
					denied, _ := json.Marshal(wsServerMsg{Type: "error", Room: msg.Room, Body: "not a member of this room"})
					select {
					case client.send <- denied:
					default:
					}
					break
				}
				// Room IDs are namespaced under the client's scope so
				// anonymous traffic can't talk to authenticated rooms,
				// and one tenant can't eavesdrop on another's room.
				// Storage keys use the scoped form; broadcasts pass the
				// raw room and let broadcastToRoom re-scope per receiver
				// (which lets two solo-auth users of the same app
				// actually reach each other - the v2.7.10 fix).
				if scoped := scopedRoomID(client, msg.Room); scoped != "" {
					client.subMu.Lock()
					client.rooms[scoped] = true
					client.subMu.Unlock()
					// Notify others in the room. Lightweight; the
					// payload is just the joining user_id so clients
					// can update presence lists.
					broadcastToRoom(client, msg.Room, "presence", json.RawMessage([]byte(`{"join":true}`)))
				}
			case "leave":
				if scoped := scopedRoomID(client, msg.Room); scoped != "" {
					client.subMu.Lock()
					delete(client.rooms, scoped)
					client.subMu.Unlock()
					broadcastToRoom(client, msg.Room, "presence", json.RawMessage([]byte(`{"leave":true}`)))
				}
			case "broadcast":
				// Relay a payload to every other member of the room.
				// Sender's user_id is stamped so clients can dedupe /
				// attribute messages. Room must be one the client has
				// joined - prevents spraying to arbitrary rooms.
				scoped := scopedRoomID(client, msg.Room)
				if scoped == "" || len(msg.Payload) == 0 {
					break
				}
				client.subMu.RLock()
				joined := client.rooms[scoped]
				client.subMu.RUnlock()
				if !joined {
					break
				}
				broadcastToRoom(client, msg.Room, "message", msg.Payload)
			case "ping":
				pong, _ := json.Marshal(wsServerMsg{Type: "pong"})
				select {
				case client.send <- pong:
				default:
				}
			}

		case wsOpPing:
			client.ws.writePong(payload)

		case wsOpClose:
			return
		}
	}
}

// wsRoomAuthorized enforces app.yaml `ws_rooms:` (v2.7.164). A room
// matching a declared pattern requires the client to hold a membership
// row (same semantics as the member-of: access mode); anonymous
// clients are always refused on declared rooms. Rooms matching no
// pattern - and apps with no ws_rooms block - are authorized as
// before. Admins bypass, matching CRUD scoping.
func wsRoomAuthorized(app *App, client *wsClient, room string) bool {
	if app == nil || len(app.WSRooms) == 0 || room == "" {
		return true
	}
	for _, wr := range app.WSRooms {
		val, ok := matchWSRoomPattern(wr.Pattern, room)
		if !ok {
			continue
		}
		if client.userID == 0 {
			return false // membership rooms require authentication
		}
		if client.isAdmin {
			return true
		}
		userVal := any(client.userID)
		if strings.Contains(wr.Rule.UserCol, "email") {
			userVal = client.email
		}
		q := fmt.Sprintf("SELECT 1 FROM %s WHERE %s = ? AND %s = ? LIMIT 1",
			wr.Rule.Table, wr.Rule.JoinCol, wr.Rule.UserCol)
		var x int
		if val == "" {
			// Literal pattern (no placeholder): membership in ANY row
			// of the membership table grants the room.
			q = fmt.Sprintf("SELECT 1 FROM %s WHERE %s = ? LIMIT 1", wr.Rule.Table, wr.Rule.UserCol)
			return app.DB.QueryRow(q, userVal).Scan(&x) == nil
		}
		return app.DB.QueryRow(q, val, userVal).Scan(&x) == nil
	}
	return true
}

func wsWriteLoop(client *wsClient) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case msg, ok := <-client.send:
			if !ok {
				return
			}
			if err := client.ws.writeText(msg); err != nil {
				return
			}
		case <-ticker.C:
			// Keepalive ping
			if err := client.ws.writeFrame(wsOpPing, nil); err != nil {
				return
			}
		}
	}
}

// ===== Broadcasting =====

func BroadcastWSChange(table, action string, groupID string, userID int64) {
	msg, _ := json.Marshal(wsServerMsg{Type: "change", Table: table, Action: action})
	genericMsg, _ := json.Marshal(wsServerMsg{Type: "change", Action: "refresh"})

	wsHub.mu.RLock()
	defer wsHub.mu.RUnlock()

	for client := range wsHub.clients {
		// Same scoping rules as broadcastToSSE in pubsub.go - group-
		// scoped events drop non-group clients, owner-scoped events
		// send a generic refresh to non-owners, unscoped events go to
		// everyone. The operator-precedence bug that was here pre-
		// v2.7.5 (missing parens around the OR) meant the owner
		// themselves never got detailed events for their own
		// mutations - see the comment in broadcastToSSE for the
		// failure mode.
		if groupID != "" && groupID != "0" && !client.isAdmin && client.groupID != groupID {
			continue
		}
		ownerScoped := (groupID == "" || groupID == "0") && userID > 0
		if ownerScoped && !client.isAdmin && client.userID != userID {
			select {
			case client.send <- genericMsg:
			default:
			}
			continue
		}
		if !wsClientSubscribed(client, table) {
			continue
		}
		select {
		case client.send <- msg:
		default:
		}
	}
}

func BroadcastWSNotification(userID int64, title, body string) {
	msg, _ := json.Marshal(wsServerMsg{Type: "notification", Title: title, Body: body})

	wsHub.mu.RLock()
	defer wsHub.mu.RUnlock()

	for client := range wsHub.clients {
		if client.userID == userID || client.isAdmin {
			select {
			case client.send <- msg:
			default:
			}
		}
	}
}

func wsClientSubscribed(client *wsClient, table string) bool {
	client.subMu.RLock()
	defer client.subMu.RUnlock()
	if len(client.subscriptions) == 0 {
		return true
	}
	return client.subscriptions[table]
}

func wsTableExists(app *App, name string) bool {
	for _, t := range app.Tables {
		if t.Name == name {
			return true
		}
	}
	return false
}

// scopedRoomID namespaces a client-supplied room ID under the client's
// tenant scope so traffic can't cross scopes. Three regimes, all prefixed
// with the app ID first so the process-global wsHub can host many apps
// without room collisions in `benmore host` mode:
//
//	anon  (no userID)       → "<appID>|anon:<room>"
//	group ("groups:" set)   → "<appID>|g<groupID>:<room>"
//	solo  (auth, no group)  → "<appID>|app:<room>"   ← shared across all
//	                                                    authed users in
//	                                                    the same app
//
// The solo case being app-wide (not per-user) is what makes chat,
// huddle signaling, presence - any multi-user broadcast room - work
// without forcing every app to configure `groups:`. Pre-2.7.10 it was
// `u<userID>:<room>` and two solo-auth users in the same app could
// not see each other's broadcasts. Every chat-shaped app discovered
// this and worked around it via DB-backed signaling tables.
//
// Cross-app isolation: the app-ID prefix is the load-bearing piece.
// In host mode every app's clients land in the same wsHub; without
// the prefix, "lobby" in app A would deliver to clients of app B who
// also joined "lobby".
//
// Cross-tenant isolation: differing group IDs still produce different
// scope keys, so `gA:secrets` and `gB:secrets` never match.
//
// Returns empty if the room ID itself is empty or contains unsafe
// characters (only [a-zA-Z0-9_:.-] allowed).
func scopedRoomID(c *wsClient, raw string) string {
	if raw == "" {
		return ""
	}
	if len(raw) > 128 {
		return ""
	}
	for i := 0; i < len(raw); i++ {
		b := raw[i]
		ok := (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') ||
			b == '_' || b == '-' || b == '.' || b == ':'
		if !ok {
			return ""
		}
	}
	// appID is set on connect from app.Name; in standalone mode or
	// tests where it isn't populated, fall back to "_" so the rest of
	// the namespace still functions (it just means there's no host-mode
	// isolation, which matches the single-app case).
	appPrefix := c.appID
	if appPrefix == "" {
		appPrefix = "_"
	}
	switch {
	case c.userID == 0:
		// features.ws_anonymous: true (without groups: scoping) is the
		// explicit opt-in to "let anon viewers see authed broadcasts
		// in the same rooms." Without this branch, the canonical
		// livestream / public-broadcast pattern is broken - the host
		// broadcasts under "app:<room>" and anon viewers only see
		// "anon:<room>", so signaling + chat never crosses.
		if c.wsAnonShared {
			return appPrefix + "|app:" + raw
		}
		return appPrefix + "|anon:" + raw
	case c.groupID != "" && c.groupID != "0":
		return fmt.Sprintf("%s|g%s:%s", appPrefix, c.groupID, raw)
	default:
		return appPrefix + "|app:" + raw
	}
}

// BroadcastWSToRoomGlobal is the server-originated counterpart to
// the client-driven broadcastToRoom. It fans out a payload to every
// connected WS client whose scope-prefixed room matches the supplied
// raw room ID - meaning a hook firing room="order-42" reaches:
//
//   - every group-scoped client where "g<groupID>:order-42" is joined
//   - every user-scoped client where "u<userID>:order-42" is joined
//   - every anonymous client where "anon:order-42" is joined
//
// Sender is nil (this is a server broadcast, not a client one), so
// every matching client receives the message - no echo-skip logic.
// payload is sent verbatim; callers serialize their own JSON.
//
// Used by flows.yaml `ws:` steps and hooks.yaml `ws:` actions to
// push real-time updates without polling.
func BroadcastWSToRoomGlobal(rawRoom, payload string) {
	if rawRoom == "" {
		return
	}
	wsHub.mu.RLock()
	defer wsHub.mu.RUnlock()
	for c := range wsHub.clients {
		scoped := scopedRoomID(c, rawRoom)
		if scoped == "" {
			continue
		}
		c.subMu.RLock()
		joined := c.rooms[scoped]
		c.subMu.RUnlock()
		if !joined {
			continue
		}
		msg, err := json.Marshal(wsServerMsg{
			Type:    "message",
			Room:    scoped,
			From:    0, // 0 = server-originated
			Payload: json.RawMessage(payload),
		})
		if err != nil {
			continue
		}
		select {
		case c.send <- msg:
		default:
			// drop on backpressure
		}
	}
}

// broadcastToRoom relays a typed message to every wsHub client that
// has joined the given room - EXCEPT the sender (skip echo).
//
// rawRoom is the user-facing room name (e.g. "huddle-123"). We compute
// the sender's scoped key once and look it up in each receiver's rooms
// map. The v2.7.10 bug was NOT in this function - the algorithm here
// is sound. The bug was in `scopedRoomID`: solo-auth users (no
// `groups:` config) were keyed `u<userID>:<room>`, so two distinct
// users of the same app never shared a scope key. The fix was to give
// all solo-auth users in the same app a shared `<appID>|app:<room>`
// key while keeping `<appID>|g<groupID>:<room>` for multi-tenant
// isolation and `<appID>|anon:<room>` for anonymous traffic.
//
// With the corrected scopedRoomID, this loop naturally:
//   - matches all same-app same-scope receivers (chat / huddle)
//   - mismatches cross-tenant (different groupID → different key)
//   - mismatches cross-app (different appID prefix → different key)
func broadcastToRoom(sender *wsClient, rawRoom, msgType string, payload json.RawMessage) {
	senderScoped := scopedRoomID(sender, rawRoom)
	if senderScoped == "" {
		return
	}
	wireMsg, err := json.Marshal(wsServerMsg{
		Type:    msgType,
		Room:    rawRoom,
		From:    sender.userID,
		Payload: payload,
	})
	if err != nil {
		return
	}
	wsHub.mu.RLock()
	defer wsHub.mu.RUnlock()
	for c := range wsHub.clients {
		if c == sender {
			continue
		}
		c.subMu.RLock()
		joined := c.rooms[senderScoped]
		c.subMu.RUnlock()
		if !joined {
			continue
		}
		select {
		case c.send <- wireMsg:
		default:
			// drop on buffer-full - broadcasts are best-effort
		}
	}
}

// WSClientScript is JavaScript for auto-connecting WebSocket on pages with [data-live] elements.
const WSClientScript = `
(function() {
  if (!document.querySelector('[data-live]') && !document.querySelector('[data-live-table]')) return;
  var proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  var ws = new WebSocket(proto + '//' + location.host + '/ws');
  var tables = [];
  document.querySelectorAll('[data-live-table]').forEach(function(el) {
    var t = el.getAttribute('data-live-table');
    if (t && tables.indexOf(t) === -1) tables.push(t);
  });
  ws.onopen = function() {
    if (tables.length > 0) {
      ws.send(JSON.stringify({type: 'subscribe', tables: tables}));
    }
  };
  ws.onmessage = function(e) {
    try {
      var data = JSON.parse(e.data);
      if (data.type === 'change' && data.table) {
        document.querySelectorAll('[data-live-table="' + data.table + '"]').forEach(function(el) {
          htmx.trigger(el, 'refresh');
        });
      } else if (data.type === 'change' && data.action === 'refresh') {
        document.querySelectorAll('[data-live]').forEach(function(el) {
          htmx.trigger(el, 'refresh');
        });
      }
    } catch(err) {}
  };
  ws.onclose = function() { setTimeout(function() { location.reload(); }, 5000); };
})();
`
