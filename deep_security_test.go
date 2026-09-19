//go:build !cli

package main

import (
	"bufio"
	"bytes"
	"image"
	"image/png"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReviewWebSocketRejectsMalformedFrames(t *testing.T) {
	for _, tc := range []struct {
		name  string
		frame []byte
		valid bool
	}{
		{"masked text", []byte{0x81, 0x82, 0, 0, 0, 0, '{', '}'}, true},
		{"unmasked", []byte{0x81, 2, '{', '}'}, false},
		{"reserved", []byte{0xc1, 0x80, 0, 0, 0, 0}, false},
		{"fragment", []byte{0x01, 0x80, 0, 0, 0, 0}, false},
		{"large ping", []byte{0x89, 0xfe, 0, 126}, false},
		{"unknown opcode", []byte{0x83, 0x80, 0, 0, 0, 0}, false},
		{"short close", []byte{0x88, 0x81, 0, 0, 0, 0, 0}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			ws := &wsConn{conn: a, br: bufio.NewReader(bytes.NewReader(tc.frame))}
			_, _, err := ws.readFrame()
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, error=%v", tc.valid, err)
			}
		})
	}
}

func reviewImageApp(t *testing.T) (*App, *http.ServeMux) {
	t.Helper()
	app := &App{Dir: t.TempDir()}
	var b bytes.Buffer
	if err := png.Encode(&b, image.NewRGBA(image.Rect(0, 0, 8, 8))); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"public.png", "private/secret.png"} {
		p := filepath.Join(app.Dir, "uploads", name)
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
	}
	// A stable synthetic key, restored after each fixture.
	signedURLKeyMu.Lock()
	old := signedURLKey
	signedURLKey = bytes.Repeat([]byte{42}, 32)
	signedURLKeyMu.Unlock()
	t.Cleanup(func() { signedURLKeyMu.Lock(); signedURLKey = old; signedURLKeyMu.Unlock() })
	mux := http.NewServeMux()
	RegisterImageTransformRoute(mux, app)
	return app, mux
}

func reviewTransform(mux *http.ServeMux, src, format, signature string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/_images/transform?src="+url.QueryEscape(src)+"&fmt="+url.QueryEscape(format)+signature, nil)
	mux.ServeHTTP(w, r)
	return w
}

func TestReviewPrivateTransformCacheCannotBypassSignature(t *testing.T) {
	app, mux := reviewImageApp(t)
	signed, err := url.Parse(GenerateSignedURL("example.com", "private/secret.png", time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	valid := reviewTransform(mux, signed.Path, "png", "&"+signed.RawQuery)
	if valid.Code != 200 {
		t.Fatalf("signed transform: %d %s", valid.Code, valid.Body.String())
	}
	if !strings.Contains(valid.Header().Get("Cache-Control"), "no-store") {
		t.Error("private transform is cacheable")
	}
	unsigned := reviewTransform(mux, signed.Path, "png", "")
	if unsigned.Code != 403 {
		t.Errorf("unsigned warm-cache transform: %d", unsigned.Code)
	}
	cache := filepath.Join(app.Dir, "uploads", "_transforms", imageCacheKey(signed.Path, 0, 0, "png", 82)+".png")
	if _, err := os.Stat(cache); err == nil {
		t.Error("private derivative written into public uploads cache")
	}
}

func TestReviewTransformRejectsFormatTraversal(t *testing.T) {
	app, mux := reviewImageApp(t)
	r := reviewTransform(mux, "/uploads/public.png", "../../../../escaped.jpg", "")
	if r.Code != 400 {
		t.Errorf("unsafe format accepted: %d", r.Code)
	}
	if _, err := os.Stat(filepath.Join(app.Dir, "escaped.jpg")); err == nil {
		t.Error("transform escaped the cache directory")
	}
}

func TestReviewPublicTransformCacheBounded(t *testing.T) {
	app, mux := reviewImageApp(t)
	cacheDir := filepath.Join(app.Dir, ".benmore/image-transforms")
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(cacheDir, "existing-cache-entry"))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(imageTransformCacheBytes); err != nil {
		t.Fatal(err)
	}
	f.Close()
	r := reviewTransform(mux, "/uploads/public.png", "png", "")
	if r.Code != 200 {
		t.Fatalf("cache limit prevented serving: %d", r.Code)
	}
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatal("visitor-controlled transforms exceeded cache quota")
	}
}

func TestReviewTransformRejectsSymlinkSources(t *testing.T) {
	for _, private := range []bool{true, false} {
		t.Run(map[bool]string{true: "private", false: "outside"}[private], func(t *testing.T) {
			app, mux := reviewImageApp(t)
			target := filepath.Join(app.Dir, "uploads", "private", "secret.png")
			if !private {
				data, err := os.ReadFile(target)
				if err != nil {
					t.Fatal(err)
				}
				target = filepath.Join(app.Dir, "outside.png")
				if err := os.WriteFile(target, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink(target, filepath.Join(app.Dir, "uploads", "alias.png")); err != nil {
				t.Fatal(err)
			}
			r := reviewTransform(mux, "/uploads/alias.png", "png", "")
			if r.Code == 200 {
				t.Fatal("unsigned transform disclosed symlink target")
			}
		})
	}
}

func TestReviewRevertUsesMutationPolicy(t *testing.T) {
	for _, policy := range []string{"update denied", "before hook", "protected owner", "allowed"} {
		t.Run(policy, func(t *testing.T) {
			app, mux := auditApp(t)
			sid := createCrudScopeSession(t, app, "reverter@example.com", "user", "", "")
			uid := GetSessionFromDB(app.DB, sid).UserID
			mustExec(t, app.DB, "INSERT INTO notes(id,user_id,title) VALUES(1,999,'old')")
			cfg := &VersionedConfig{Tables: []string{"notes"}}
			InstallVersioningTriggers(app.DB, cfg)
			if _, err := app.DB.Exec("UPDATE notes SET user_id=?, title='current' WHERE id=1", uid); err != nil {
				t.Fatal(err)
			}
			RegisterVersioningAPI(mux, app, cfg)
			if policy == "update denied" {
				app.Access.rules["notes"][OpUpdate] = "admin"
			}
			if policy == "before hook" {
				app.Hooks = &HookConfig{BeforeUpdate: map[string][]Hook{"notes": {{SQL: "SELECT 'blocked' AS error"}}}}
			}
			r := crudScopeRequest(t, mux, "POST", "/api/notes/1/revert/1", sid, nil)
			var owner int64
			var title string
			if err := app.DB.QueryRow("SELECT user_id,title FROM notes WHERE id=1").Scan(&owner, &title); err != nil {
				t.Fatal(err)
			}
			if policy == "update denied" || policy == "before hook" {
				if r.Code == 200 || title != "current" {
					t.Fatalf("revert bypassed %s: HTTP %d, title=%q", policy, r.Code, title)
				}
			} else {
				if r.Code != 200 || title != "old" {
					t.Fatalf("authorized revert failed: HTTP %d %s, title=%q", r.Code, r.Body.String(), title)
				}
				if owner != uid {
					t.Fatalf("revert rewrote protected owner: got %d want %d", owner, uid)
				}
			}
		})
	}
}

func TestReviewVersionHistoryUsesSourcePolicy(t *testing.T) {
	app, _ := auditApp(t)
	sid := createCrudScopeSession(t, app, "history@example.com", "user", "", "")
	uid := GetSessionFromDB(app.DB, sid).UserID
	if _, err := app.DB.Exec("INSERT INTO notes(id,user_id,title) VALUES (1,?,'historical-secret')", uid); err != nil {
		t.Fatal(err)
	}
	cfg := &VersionedConfig{Tables: []string{"notes"}}
	InstallVersioningTriggers(app.DB, cfg)
	mustExec(t, app.DB, "UPDATE notes SET title='current' WHERE id=1")
	mustExec(t, app.DB, "CREATE TABLE business_history(id INTEGER PRIMARY KEY,title TEXT)")
	mux := http.NewServeMux()
	RegisterCRUD(mux, app)
	RegisterVersioningAPI(mux, app, cfg)
	for _, method := range []string{"GET", "PATCH", "DELETE"} {
		r := crudScopeRequest(t, mux, method, "/api/notes_history/1", sid, map[string]any{"title": "tampered"})
		if r.Code < 400 {
			t.Fatalf("raw history exposed through %s: %d", method, r.Code)
		}
	}
	valid, err := GetTableNames(app.DB)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, table := range valid {
		if table == "business_history" {
			found = true
		}
	}
	if !found {
		t.Fatal("ordinary business history table hidden")
	}
	app.Access.rules["notes"][OpRead] = "admin"
	for _, path := range []string{"/api/notes/1/versions", "/api/notes/1/versions/1"} {
		r := crudScopeRequest(t, mux, "GET", path, sid, nil)
		if r.Code < 400 || strings.Contains(r.Body.String(), "historical-secret") {
			t.Fatalf("source read policy bypassed: %d", r.Code)
		}
	}
}

func TestReviewServerRoomBroadcastIsolated(t *testing.T) {
	resetWSHub(t)
	app := &App{Dir: "/synthetic/app-a"}
	a := newWSTestClient(realtimeAppID(app.Dir), 1, "")
	b := newWSTestClient("app-b", 1, "")
	for _, c := range []*wsClient{a, b} {
		registerWSClient(c)
		defer unregisterWSClient(c)
		wsJoinAs(c, "lobby")
	}
	ctx := &FlowContext{App: app, Data: map[string]any{}, Params: map[string]string{}}
	if err := execStepWS(ctx, &FlowStep{WS: &FlowWS{Room: "lobby", Payload: `{"private":"app-a"}`}}); err != nil {
		t.Fatal(err)
	}
	if !wsReceivedAny(a) {
		t.Error("intended receiver missed broadcast")
	}
	if wsReceivedAny(b) {
		t.Error("another app received server room payload")
	}
}

func TestReviewSignedURLBoundToHost(t *testing.T) {
	_, _ = reviewImageApp(t)
	u := GenerateSignedURL("app-a.example", "private/secret.png", time.Minute)
	r := httptest.NewRequest("GET", "https://app-a.example"+u, nil)
	if !ValidateSignedURL("private/secret.png", r) {
		t.Fatal("intended host rejected signed URL")
	}
	r.Host = "app-b.example"
	if ValidateSignedURL("private/secret.png", r) {
		t.Fatal("private file signature accepted by another app host")
	}
}

func TestReviewDataExportHonorsReadPolicy(t *testing.T) {
	app, mux := auditApp(t)
	sid := createCrudScopeSession(t, app, "exporter@example.com", "user", "", "")
	uid := GetSessionFromDB(app.DB, sid).UserID
	if _, err := app.DB.Exec("INSERT INTO notes(user_id,title) VALUES(?,'restricted-export-data')", uid); err != nil {
		t.Fatal(err)
	}
	app.Access.rules["notes"][OpRead] = "admin"
	RegisterDSARRoute(mux, app)
	for _, token := range []string{sid, auditToken(t, app, sid, "rooms:read")} {
		r := crudScopeRequest(t, mux, "GET", "/api/_my-data", token, nil)
		if strings.Contains(r.Body.String(), "restricted-export-data") {
			t.Errorf("data export bypassed read policy: HTTP %d", r.Code)
		}
	}
}

func TestReviewExpiredSessionRejected(t *testing.T) {
	app, _ := auditApp(t)
	sid := createCrudScopeSession(t, app, "expired@example.com", "user", "", "")
	if _, err := app.DB.Exec("UPDATE _benmore_sessions SET expires_at=? WHERE id=?", time.Now().UTC().Add(-time.Minute).Format(time.RFC3339), sid); err != nil {
		t.Fatal(err)
	}
	if GetSessionFromDB(app.DB, sid) != nil {
		t.Fatal("expired RFC3339 session was accepted")
	}
}

func TestReviewExpiredGrantsRejected(t *testing.T) {
	app, _ := auditApp(t)
	expired := time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)
	if _, err := app.DB.Exec("INSERT INTO _benmore_permissions(resource_type,resource_id,grant_type,grantee_id,permission,expires_at) VALUES ('notes','1','user','expired@example.com','admin',?)", expired); err != nil {
		t.Fatal(err)
	}
	if hasPermission(app.DB, "notes", "1", "expired@example.com", "view") {
		t.Fatal("expired RFC3339 ACL accepted")
	}
	if err := EnsureUserRolesTable(app.DB); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec("INSERT INTO _benmore_user_roles(user_id,role,expires_at) VALUES (1,'admin',?)", expired); err != nil {
		t.Fatal(err)
	}
	for _, role := range LoadSessionRoles(app.DB, 1, "user", "") {
		if role == "admin" {
			t.Fatal("expired RFC3339 role accepted")
		}
	}
}

func TestReviewRealtimeDataIsolationAndRevocation(t *testing.T) {
	app, _ := auditApp(t)
	other, _ := auditApp(t)
	sid := createCrudScopeSession(t, app, "live@example.com", "user", "", "")
	request := httptest.NewRequest("GET", "/ws", nil)
	request.Header.Set("Authorization", "Bearer "+sid)
	principal := realtimePrincipal{app: app, request: request, session: getSession(app, request)}
	a := newWSTestClient(realtimeAppID(app.Dir), principal.session.UserID, "")
	a.principal = principal
	b := newWSTestClient(realtimeAppID(other.Dir), a.userID, "")
	b.principal = realtimePrincipal{app: other, session: &Session{UserID: a.userID, Role: "admin", GlobalAdmin: true}}
	for _, c := range []*wsClient{a, b} {
		registerWSClient(c)
		defer unregisterWSClient(c)
	}
	sa := &sseClient{ch: make(chan string, 10), userID: a.userID, principal: principal}
	sb := &sseClient{ch: make(chan string, 10), userID: b.userID, isAdmin: true, principal: b.principal}
	sseHub.mu.Lock()
	sseHub.clients[sa] = true
	sseHub.clients[sb] = true
	sseHub.mu.Unlock()
	defer func() { sseHub.mu.Lock(); delete(sseHub.clients, sa); delete(sseHub.clients, sb); sseHub.mu.Unlock() }()
	Broadcast(app, "notes", "update", principal.session)
	if !wsReceivedAny(a) || len(sa.ch) != 1 {
		t.Fatal("authorized same-app user missed data event")
	}
	if wsReceivedAny(b) || len(sb.ch) != 0 {
		t.Fatal("data event crossed app boundary to matching user/admin")
	}
	<-sa.ch
	app.Access.rules["notes"][OpRead] = "admin"
	BroadcastUnscoped(app, "notes", "update")
	if wsReceivedAny(a) || len(sa.ch) != 0 {
		t.Fatal("data event bypassed table read policy")
	}
	app.Access.rules["notes"][OpRead] = "self"
	DeleteSessionFromDB(app.DB, sid)
	Broadcast(app, "notes", "update", principal.session)
	if wsReceivedAny(a) || len(sa.ch) != 0 {
		t.Fatal("revoked session received data event")
	}
}

func TestReviewServerRoomTenantAndMembership(t *testing.T) {
	app, _ := auditApp(t)
	app.WSRooms = []WSRoomRule{{Pattern: "room-:id", Rule: &memberOfRule{Table: "room_members", JoinCol: "room_id", UserCol: "member_id"}}}
	sid := createCrudScopeSession(t, app, "roomuser@example.com", "user", "tenant-a", "")
	session := GetSessionFromDB(app.DB, sid)
	if _, err := app.DB.Exec("INSERT INTO room_members(room_id,member_id) VALUES(1,?)", session.UserID); err != nil {
		t.Fatal(err)
	}
	a := newWSTestClient(realtimeAppID(app.Dir), session.UserID, "tenant-a")
	a.principal = realtimePrincipal{app: app, session: session}
	b := newWSTestClient(realtimeAppID(app.Dir), session.UserID, "tenant-b")
	b.principal = realtimePrincipal{app: app, session: &Session{UserID: session.UserID, GroupID: "tenant-b"}}
	for _, c := range []*wsClient{a, b} {
		registerWSClient(c)
		defer unregisterWSClient(c)
		wsJoinAs(c, "room-1")
	}
	if err := BroadcastWSToRoom(app, "tenant-a", "room-1", `{"ok":true}`); err != nil {
		t.Fatal(err)
	}
	if !wsReceivedAny(a) || wsReceivedAny(b) {
		t.Fatal("server room broadcast crossed tenants or missed its tenant")
	}
	if err := BroadcastWSToRoom(app, "", "room-1", `{}`); err == nil {
		t.Fatal("ambiguous tenant broadcast accepted")
	}
	mustExec(t, app.DB, "DELETE FROM room_members")
	if err := BroadcastWSToRoom(app, "tenant-a", "room-1", `{}`); err != nil {
		t.Fatal(err)
	}
	if wsReceivedAny(a) {
		t.Fatal("revoked room member received payload")
	}
}
