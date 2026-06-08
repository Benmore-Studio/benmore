package main

import (
	"encoding/json"
	"testing"
)

// TestBroadcastToRoom_CrossUserSoloAuth pins the v2.7.10 fix for the
// silent-drop bug that bricked every chat / WebRTC-huddle agent build
// before it: two solo-authenticated users (no `groups:` config) both
// join the same room and one broadcasts; pre-fix, scopedRoomID() keyed
// Alice's join as `u1:huddle` and Bob's as `u2:huddle`, so Alice's
// broadcast looked for `u1:huddle` in Bob's rooms map — never matched.
// Many chat-style apps discovered this empirically and
// worked around it by routing signaling through a DB table.
//
// Post-fix, broadcastToRoom() takes the RAW room name and scopes per
// receiver, so Alice's "huddle" matches Bob's `u2:huddle` (because the
// loop computes scopedRoomID(Bob, "huddle") = "u2:huddle" and checks
// THAT against Bob's joined rooms).
func TestBroadcastToRoom_CrossUserSoloAuth(t *testing.T) {
	resetWSHub(t)

	// Two solo-auth users, no group scoping. Pre-fix this is the case
	// that always silently dropped.
	alice := newWSTestClient("chatapp", 1, "")
	bob := newWSTestClient("chatapp", 2, "")
	registerWSClient(alice)
	registerWSClient(bob)
	defer unregisterWSClient(alice)
	defer unregisterWSClient(bob)

	// Both join the same logical room. Each stores under their OWN
	// scoped key — that's the intended security model. The fix is
	// about how broadcasts traverse the scope barrier, not about
	// flattening the keys themselves.
	wsJoinAs(alice, "huddle")
	wsJoinAs(bob, "huddle")

	// Alice broadcasts — pass the RAW room name, same as the WS
	// read loop now does.
	broadcastToRoom(alice, "huddle", "message", json.RawMessage(`{"hello":"world"}`))

	// Bob must receive. Pre-fix: drain timeout (nothing in channel).
	if !wsReceivedAny(bob) {
		t.Fatal("Bob never received Alice's broadcast — silent-drop bug returned")
	}
	// Alice must NOT receive her own echo.
	if wsReceivedAny(alice) {
		t.Fatal("Alice received her own broadcast — echo-skip logic broken")
	}
}

// TestBroadcastToRoom_CrossTenantStillIsolated pins the security
// invariant the original scoping was designed to protect: two clients
// in DIFFERENT groups must NOT see each other's broadcasts, even if
// they pick the same room name. The fix re-scopes per receiver, so
// receiver Bob (in group B) computes "gB:secrets" while sender Alice's
// (group A) scope makes her broadcast look for matches against
// "gA:secrets" in everyone — Bob has "gB:secrets" in his rooms map,
// not "gA:secrets", so it naturally mismatches.
func TestBroadcastToRoom_CrossTenantStillIsolated(t *testing.T) {
	resetWSHub(t)

	alice := newWSTestClient("multitenant", 1, "groupA")
	bob := newWSTestClient("multitenant", 2, "groupB")
	registerWSClient(alice)
	registerWSClient(bob)
	defer unregisterWSClient(alice)
	defer unregisterWSClient(bob)

	wsJoinAs(alice, "secrets")
	wsJoinAs(bob, "secrets")

	broadcastToRoom(alice, "secrets", "message", json.RawMessage(`{"tenant":"leak"}`))

	if wsReceivedAny(bob) {
		t.Fatal("cross-tenant leak: groupB client received groupA client's broadcast")
	}
}

// TestBroadcastToRoom_CrossAppIsolated pins the OTHER load-bearing
// security invariant the v2.7.10 fix had to preserve. In `benmore
// host` mode the wsHub is process-global — every connected client
// from every hosted app lands in the same map. Without an app-ID
// prefix in scopedRoomID, "lobby" in app A would deliver to clients
// of app B who also joined "lobby". The fix prefixes every scope key
// with the connecting client's app name, so app A's "alice|app:lobby"
// and app B's "alice|app:lobby" use different namespaces and never
// match.
func TestBroadcastToRoom_CrossAppIsolated(t *testing.T) {
	resetWSHub(t)

	// Two solo-auth users with the same userID, in DIFFERENT apps.
	// Pre-fix (when scope was just "u<id>:" with no app prefix) they
	// would have shared the room key and leaked.
	appAUser := newWSTestClient("appA", 1, "")
	appBUser := newWSTestClient("appB", 1, "")
	registerWSClient(appAUser)
	registerWSClient(appBUser)
	defer unregisterWSClient(appAUser)
	defer unregisterWSClient(appBUser)

	wsJoinAs(appAUser, "lobby")
	wsJoinAs(appBUser, "lobby")

	broadcastToRoom(appAUser, "lobby", "message", json.RawMessage(`{"app":"A"}`))

	if wsReceivedAny(appBUser) {
		t.Fatal("cross-app leak: appB client received appA broadcast (host-mode isolation broken)")
	}
}

// ===== helpers =====

func resetWSHub(t *testing.T) {
	t.Helper()
	wsHub.mu.Lock()
	wsHub.clients = make(map[*wsClient]bool)
	wsHub.mu.Unlock()
}

func newWSTestClient(appID string, userID int64, groupID string) *wsClient {
	return &wsClient{
		send:          make(chan []byte, 8),
		appID:         appID,
		userID:        userID,
		groupID:       groupID,
		isAdmin:       false,
		subscriptions: make(map[string]bool),
		rooms:         make(map[string]bool),
	}
}

func registerWSClient(c *wsClient) {
	wsHub.mu.Lock()
	wsHub.clients[c] = true
	wsHub.mu.Unlock()
}

func unregisterWSClient(c *wsClient) {
	wsHub.mu.Lock()
	delete(wsHub.clients, c)
	wsHub.mu.Unlock()
}

func wsJoinAs(c *wsClient, rawRoom string) {
	scoped := scopedRoomID(c, rawRoom)
	c.subMu.Lock()
	c.rooms[scoped] = true
	c.subMu.Unlock()
}

func wsReceivedAny(c *wsClient) bool {
	select {
	case <-c.send:
		return true
	default:
		return false
	}
}
