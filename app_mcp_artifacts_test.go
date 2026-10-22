//go:build !cli && !windows

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestMCPArtifact(t *testing.T, app *App, actorID int64, data []byte) appMCPArtifact {
	t.Helper()
	if err := ensureAppMCPArtifactTables(app.DB); err != nil {
		t.Fatal(err)
	}
	var createdAt string
	if err := app.DB.QueryRow(`SELECT created_at FROM _benmore_users WHERE id=?`, actorID).Scan(&createdAt); err != nil {
		t.Fatal(err)
	}
	a, err := createAppMCPArtifact(context.Background(), app, actorID, createdAt, "17", "editor", []string{"tasks:write"}, "operation-test", "html", data, "bundle-digest", map[string]string{"tasks": "7"}, "engine-test")
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func mcpArtifactFixture(t *testing.T) (*App, string, int64) {
	t.Helper()
	app, _, actorID := newCommandProviderTaskFixtureWithPolicies(t, hookTaskFlow, "")
	sessionID := CreateSession(app.DB, actorID, "task-actor@example.com", "17", time.Hour)
	t.Cleanup(app.Shutdown)
	return app, sessionID, actorID
}

func mcpArtifactGet(t *testing.T, app *App, id, sessionID string) (int, []byte) {
	t.Helper()
	mux := http.NewServeMux()
	registerAppMCPArtifactRoutes(mux, app)
	req := httptest.NewRequest(http.MethodGet, "/api/_mcp/artifacts/"+id, nil)
	if sessionID != "" {
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionID})
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes()
}

func TestAppMCPArtifactCreateRetrieveBytesHashAndImmutable(t *testing.T) {
	app, sessionID, actorID := mcpArtifactFixture(t)
	want := []byte("immutable artifact bytes")
	a := newTestMCPArtifact(t, app, actorID, want)
	if a.SchemaVersion != mcpArtifactManifestVersion {
		t.Fatalf("artifact schema version = %d, want %d", a.SchemaVersion, mcpArtifactManifestVersion)
	}
	var schemaVersion int
	if err := app.DB.QueryRow(`SELECT schema_version FROM _benmore_mcp_artifacts WHERE id=?`, a.ID).Scan(&schemaVersion); err != nil || schemaVersion != mcpArtifactManifestVersion {
		t.Fatalf("stored artifact schema version=%d err=%v", schemaVersion, err)
	}
	status, got := mcpArtifactGet(t, app, a.ID, sessionID)
	if status != http.StatusOK || !bytes.Equal(got, want) {
		t.Fatalf("retrieve status=%d bytes=%q", status, got)
	}
	sum := sha256.Sum256(got)
	if hex.EncodeToString(sum[:]) != a.SHA256 {
		t.Fatal("retrieved bytes do not match manifest hash")
	}
	if _, err := app.DB.Exec(`UPDATE _benmore_mcp_artifacts SET kind='pdf' WHERE id=?`, a.ID); err == nil {
		t.Fatal("artifact row update succeeded")
	}
}

func TestAppMCPArtifactManifestMigratesLegacyRows(t *testing.T) {
	app, _, actorID := mcpArtifactFixture(t)
	var createdAt string
	if err := app.DB.QueryRow(`SELECT created_at FROM _benmore_users WHERE id=?`, actorID).Scan(&createdAt); err != nil {
		t.Fatal(err)
	}
	_, err := app.DB.Exec(`CREATE TABLE _benmore_mcp_artifacts (
		id TEXT PRIMARY KEY, owner_user_id INTEGER NOT NULL, owner_created_at TEXT NOT NULL, tenant TEXT NOT NULL,
		kind TEXT NOT NULL, content_sha256 TEXT NOT NULL, size INTEGER NOT NULL, storage_ref TEXT NOT NULL,
		source_bundle_digest TEXT NOT NULL, source_revisions TEXT NOT NULL, template_version TEXT NOT NULL,
		engine_version TEXT NOT NULL, created_at TEXT NOT NULL, operation_id TEXT NOT NULL,
		required_role TEXT NOT NULL, required_scopes TEXT NOT NULL)`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = app.DB.Exec(`INSERT INTO _benmore_mcp_artifacts
		(id,owner_user_id,owner_created_at,tenant,kind,content_sha256,size,storage_ref,source_bundle_digest,source_revisions,template_version,engine_version,created_at,operation_id,required_role,required_scopes)
		VALUES('legacy',?,?,?,?,?,1,'private/legacy','bundle','{}','template','engine','created','operation','editor','["tasks:write"]')`,
		actorID, createdAt, "17", "html", strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureAppMCPArtifactTables(app.DB); err != nil {
		t.Fatal(err)
	}
	var version int
	if err := app.DB.QueryRow(`SELECT schema_version FROM _benmore_mcp_artifacts WHERE id='legacy'`).Scan(&version); err != nil || version != mcpArtifactManifestVersion {
		t.Fatalf("legacy manifest schema version=%d err=%v", version, err)
	}
}

func TestAppMCPArtifactRejectsOtherUserAndLostRole(t *testing.T) {
	app, sessionID, actorID := mcpArtifactFixture(t)
	a := newTestMCPArtifact(t, app, actorID, []byte("artifact"))
	other := createCrudScopeSession(t, app, "other-artifact@example.com", "editor", "17", "")
	status, _ := mcpArtifactGet(t, app, a.ID, other)
	if status != http.StatusNotFound {
		t.Fatalf("other user status = %d", status)
	}
	if err := SetUserRole(app.DB, actorID, "user"); err != nil {
		t.Fatal(err)
	}
	status, _ = mcpArtifactGet(t, app, a.ID, sessionID)
	if status != http.StatusNotFound {
		t.Fatalf("owner after role loss status = %d", status)
	}
}

func TestAppMCPArtifactUsesCurrentMembershipRole(t *testing.T) {
	app, sessionID, actorID := mcpArtifactFixture(t)
	if _, err := app.DB.Exec(`ALTER TABLE members ADD COLUMN member_role TEXT`); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec(`UPDATE members SET member_role='editor' WHERE org_id='17'`); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec(`UPDATE _benmore_users SET role='user' WHERE id=?`, actorID); err != nil {
		t.Fatal(err)
	}
	app.Group.RoleField = "member_role"
	app.Roles.Roles["user"] = RoleDef{Scopes: "tasks:read"}
	app.Roles.Roles["editor"] = RoleDef{Scopes: "tasks:write"}
	a := newTestMCPArtifact(t, app, actorID, []byte("membership-scoped artifact"))
	status, body := mcpArtifactGet(t, app, a.ID, sessionID)
	if status != http.StatusOK || string(body) != "membership-scoped artifact" {
		t.Fatalf("membership-role artifact status=%d body=%q", status, body)
	}
}

func TestAppMCPArtifactRequiresInteractiveSessionAndCurrentScopes(t *testing.T) {
	app, sessionID, actorID := mcpArtifactFixture(t)
	a := newTestMCPArtifact(t, app, actorID, []byte("artifact"))
	mux := http.NewServeMux()
	registerAppMCPArtifactRoutes(mux, app)
	request := func(cookie, authorization, edgeUser string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/_mcp/artifacts/"+a.ID, nil)
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookie})
		}
		if authorization != "" {
			req.Header.Set("Authorization", authorization)
		}
		if edgeUser != "" {
			req.Header.Set("X-Benmore-Edge-User", edgeUser)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}
	if got := request("", "Bearer "+sessionID, ""); got.Code != http.StatusUnauthorized {
		t.Fatalf("bearer session status = %d", got.Code)
	}
	if got := request("", "", fmt.Sprint(actorID)); got.Code != http.StatusUnauthorized {
		t.Fatalf("edge identity status = %d", got.Code)
	}
	storedID, ok := presentedSessionKey(sessionID)
	if !ok {
		t.Fatal("could not resolve session storage key")
	}
	if _, err := app.DB.Exec(`UPDATE _benmore_sessions SET scopes=? WHERE id=?`, "tasks:read", storedID); err != nil {
		t.Fatal(err)
	}
	if got := request(sessionID, "", ""); got.Code != http.StatusUnauthorized {
		t.Fatalf("scoped credential status = %d", got.Code)
	}
	if _, err := app.DB.Exec(`UPDATE _benmore_sessions SET scopes=? WHERE id=?`, "", storedID); err != nil {
		t.Fatal(err)
	}
	role := app.Roles.Roles["editor"]
	app.Roles.Roles["editor"] = RoleDef{Scopes: "tasks:read"}
	if got := request(sessionID, "", ""); got.Code != http.StatusNotFound {
		t.Fatalf("owner after required scope loss status = %d", got.Code)
	}
	app.Roles.Roles["editor"] = role
	var createdAt string
	if err := app.DB.QueryRow(`SELECT created_at FROM _benmore_users WHERE id=?`, actorID).Scan(&createdAt); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec(`UPDATE _benmore_users SET created_at=? WHERE id=?`, "different-account-incarnation", actorID); err != nil {
		t.Fatal(err)
	}
	if got := request(sessionID, "", ""); got.Code != http.StatusNotFound {
		t.Fatalf("recreated owner status = %d", got.Code)
	}
	if _, err := app.DB.Exec(`UPDATE _benmore_users SET created_at=? WHERE id=?`, createdAt, actorID); err != nil {
		t.Fatal(err)
	}
}

// Artifact bytes live under uploads/private/, but only the artifact route may
// read them: a record that merely names the storage path must not mint a
// generic signed URL (a bearer credential, no owner/role/scope recheck), and a
// signature minted anyway must not serve them.
func TestAppMCPArtifactStorageIsNotSignableOrServable(t *testing.T) {
	previous := serverSecret
	serverSecret = "artifact-storage-test-secret-0123456789"
	t.Cleanup(func() { serverSecret = previous })
	app, sessionID, actorID := mcpArtifactFixture(t)
	want := []byte("owner-only artifact bytes")
	a := newTestMCPArtifact(t, app, actorID, want)
	auditExec(t, app.DB, `INSERT INTO tasks(id,project_id,org_id,title,status) VALUES(900,7,'17',?,'open')`, "/"+a.StorageRef)
	mux := http.NewServeMux()
	RegisterSignedURLRoutes(mux, app)
	mux.HandleFunc("GET /uploads/", func(w http.ResponseWriter, r *http.Request) {
		serveUploadAsset(w, r, app, false, filepath.Clean(strings.TrimPrefix(r.URL.Path, "/uploads/")))
	})
	logical := strings.TrimPrefix(a.StorageRef, "uploads/")
	for _, spelling := range []string{"/" + a.StorageRef, a.StorageRef, logical, strings.ToUpper(logical[:1]) + logical[1:]} {
		req := httptest.NewRequest(http.MethodGet, "/api/_signed_url?"+url.Values{"path": {spelling}, "record_table": {"tasks"}, "record_id": {"900"}}.Encode(), nil)
		req.Header.Set("Authorization", "Bearer "+sessionID)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code == http.StatusOK {
			t.Errorf("signed URL minted for artifact storage spelled %q: %s", spelling, rec.Body.String())
		}
	}
	for _, rel := range []string{logical, strings.Replace(logical, "mcp-artifacts", "MCP-Artifacts", 1)} {
		signed := GenerateSignedURL("example.com", rel, time.Minute)
		req := httptest.NewRequest(http.MethodGet, signed, nil)
		req.Host = "example.com"
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code == http.StatusOK || bytes.Contains(rec.Body.Bytes(), want) {
			t.Errorf("artifact storage %q served through /uploads/: %d", rel, rec.Code)
		}
	}
	for _, raw := range []string{"/" + a.StorageRef, a.StorageRef, logical} {
		if rec := serveFileForTest(t, app, raw); rec.Code == http.StatusOK || bytes.Contains(rec.Body.Bytes(), want) {
			t.Errorf("serve_file served artifact storage %q: %d", raw, rec.Code)
		}
	}
	if status, got := mcpArtifactGet(t, app, a.ID, sessionID); status != http.StatusOK || !bytes.Equal(got, want) {
		t.Fatalf("artifact route status=%d body=%q", status, got)
	}
}

func TestAppMCPArtifactDetectsStoredTampering(t *testing.T) {
	app, sessionID, actorID := mcpArtifactFixture(t)
	a := newTestMCPArtifact(t, app, actorID, []byte("original"))
	path := app.Dir + "/" + a.StorageRef
	if err := os.WriteFile(path, []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	status, body := mcpArtifactGet(t, app, a.ID, sessionID)
	if status != http.StatusInternalServerError || !strings.Contains(string(body), "integrity check failed") {
		t.Fatalf("tampered artifact status=%d body=%q", status, body)
	}
}

func TestAppMCPArtifactRestoreKeepsLiveManifest(t *testing.T) {
	app, _, actorID := mcpArtifactFixture(t)
	live := newTestMCPArtifact(t, app, actorID, []byte("live artifact"))
	liveRows, err := readCredTable(context.Background(), app.DB, mcpArtifactsTable, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := newTestMCPArtifact(t, app, actorID, []byte("snapshot-only artifact"))
	tx, err := app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	summary := &restoreCredentialSummary{Kept: map[string]int{}, Removed: map[string]int{}}
	if err := carryForwardMCPArtifacts(context.Background(), tx, map[string]*credTable{mcpArtifactsTable: liveRows}, map[int64]int64{actorID: actorID}, summary); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var liveCount, snapshotCount int
	if err := app.DB.QueryRow(`SELECT count(*) FROM _benmore_mcp_artifacts WHERE id=?`, live.ID).Scan(&liveCount); err != nil {
		t.Fatal(err)
	}
	if err := app.DB.QueryRow(`SELECT count(*) FROM _benmore_mcp_artifacts WHERE id=?`, snapshot.ID).Scan(&snapshotCount); err != nil {
		t.Fatal(err)
	}
	if liveCount != 1 || snapshotCount != 0 || summary.Kept[mcpArtifactsTable] != 1 {
		t.Fatalf("restore kept=%v removed=%v live=%d snapshot=%d", summary.Kept, summary.Removed, liveCount, snapshotCount)
	}
}

func TestAppMCPArtifactAccountPurgeRemovesManifest(t *testing.T) {
	app, cleanup := newPurgeTestApp(t)
	defer cleanup()
	insertPurgeUser(t, app, 1, "artifact-owner@example.com")
	if err := ensureAppMCPArtifactTables(app.DB); err != nil {
		t.Fatal(err)
	}
	var createdAt string
	if err := app.DB.QueryRow(`SELECT created_at FROM _benmore_users WHERE id=1`).Scan(&createdAt); err != nil {
		t.Fatal(err)
	}
	if _, err := createAppMCPArtifact(context.Background(), app, 1, createdAt, "17", "editor", []string{"tasks:write"}, "operation-purge", "html", []byte("private artifact"), "bundle", nil, "test"); err != nil {
		t.Fatal(err)
	}
	sessionID := CreateSession(app.DB, 1, "artifact-owner@example.com", "17", time.Hour)
	flow := &Flow{
		Name:    "account-delete",
		Trigger: FlowTrigger{Type: "http", Method: http.MethodPost, Path: "/api/account-delete"},
		Auth:    "required", Transaction: true,
		Steps: []FlowStep{
			{Name: "purge", Type: "purge_current_user", PurgeCurrentUserConfirm: "{{confirm}}"},
			{Type: "respond", Respond: &FlowRespond{Status: http.StatusOK, JSON: map[string]any{"deleted": true}}},
		},
	}
	req := httptest.NewRequest(http.MethodPost, "/api/account-delete", strings.NewReader(`{"confirm":"DELETE"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+sessionID)
	rec := httptest.NewRecorder()
	executeFlowHTTP(app, flow, rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("purge status=%d body=%s", rec.Code, rec.Body.String())
	}
	var remaining int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM _benmore_mcp_artifacts WHERE owner_user_id=1`).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatalf("account purge retained %d artifact manifests", remaining)
	}
}

func purgeArtifactFixture(t *testing.T, email string) (*App, appMCPArtifact) {
	t.Helper()
	app, cleanup := newPurgeTestApp(t)
	t.Cleanup(cleanup)
	insertPurgeUser(t, app, 1, email)
	if err := ensureAppMCPArtifactTables(app.DB); err != nil {
		t.Fatal(err)
	}
	var createdAt string
	if err := app.DB.QueryRow(`SELECT created_at FROM _benmore_users WHERE id=1`).Scan(&createdAt); err != nil {
		t.Fatal(err)
	}
	artifact, err := createAppMCPArtifact(context.Background(), app, 1, createdAt, "17", "editor", []string{"tasks:write"}, "operation-purge", "html", []byte("private artifact"), "bundle", nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(app.Dir, filepath.FromSlash(artifact.StorageRef))); err != nil {
		t.Fatalf("artifact bytes were not stored: %v", err)
	}
	return app, artifact
}

func artifactBytesExist(t *testing.T, app *App, artifact appMCPArtifact) bool {
	t.Helper()
	_, err := os.Stat(filepath.Join(app.Dir, filepath.FromSlash(artifact.StorageRef)))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return err == nil
}

// Purging an account removed its artifact manifests but left the artifact
// bytes at rest. They are now deleted once the purge commits, and only then.
func TestAppMCPArtifactAccountPurgeDeletesStoredBytesAfterCommit(t *testing.T) {
	purgeFlow := func(final FlowStep) *Flow {
		return &Flow{
			Name:    "account-delete",
			Trigger: FlowTrigger{Type: "http", Method: http.MethodPost, Path: "/api/account-delete"},
			Auth:    "required", Transaction: true,
			Steps: []FlowStep{{Name: "purge", Type: "purge_current_user", PurgeCurrentUserConfirm: "{{confirm}}"}, final},
		}
	}
	run := func(app *App, flow *Flow) int {
		sessionID := CreateSession(app.DB, 1, "artifact-owner@example.com", "17", time.Hour)
		req := httptest.NewRequest(http.MethodPost, "/api/account-delete", strings.NewReader(`{"confirm":"DELETE"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+sessionID)
		rec := httptest.NewRecorder()
		executeFlowHTTP(app, flow, rec, req)
		return rec.Code
	}

	// A later step fails: the purge rolls back and the bytes stay with their manifest.
	app, artifact := purgeArtifactFixture(t, "artifact-owner@example.com")
	if code := run(app, purgeFlow(FlowStep{Name: "boom", Type: "sql", SQL: "SELECT * FROM missing_table_for_rollback"})); code == http.StatusOK {
		t.Fatal("failing purge flow succeeded")
	}
	assertCount(t, app, `SELECT COUNT(*) FROM _benmore_mcp_artifacts WHERE owner_user_id=1`, 1)
	if !artifactBytesExist(t, app, artifact) {
		t.Fatal("rolled-back purge deleted artifact bytes")
	}
	// The committed purge removes manifest and bytes.
	if code := run(app, purgeFlow(FlowStep{Type: "respond", Respond: &FlowRespond{Status: http.StatusOK, JSON: map[string]any{"deleted": true}}})); code != http.StatusOK {
		t.Fatalf("purge status=%d", code)
	}
	assertCount(t, app, `SELECT COUNT(*) FROM _benmore_mcp_artifacts WHERE owner_user_id=1`, 0)
	if artifactBytesExist(t, app, artifact) {
		t.Fatal("account purge left the artifact bytes at rest")
	}

	// Self-service delete takes the same path (the platform operator delete is
	// covered in mcp_tools_user_delete_test.go).
	app, artifact = purgeArtifactFixture(t, "self@example.com")
	if err := deleteOwnAccount(app, &Session{UserID: 1, Email: "self@example.com"}); err != nil {
		t.Fatal(err)
	}
	if artifactBytesExist(t, app, artifact) {
		t.Fatal("self-service account delete left the artifact bytes at rest")
	}
}

// A restore drops manifests without touching storage; the start-up sweep
// removes artifact files no manifest names once they are past the grace period.
func TestAppMCPArtifactOrphanSweep(t *testing.T) {
	app, kept := purgeArtifactFixture(t, "sweep@example.com")
	var createdAt string
	if err := app.DB.QueryRow(`SELECT created_at FROM _benmore_users WHERE id=1`).Scan(&createdAt); err != nil {
		t.Fatal(err)
	}
	orphan, err := createAppMCPArtifact(context.Background(), app, 1, createdAt, "17", "editor", []string{"tasks:write"}, "operation-orphan", "pdf", []byte("orphaned artifact"), "bundle", nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := createAppMCPArtifact(context.Background(), app, 1, createdAt, "17", "editor", []string{"tasks:write"}, "operation-fresh", "xlsx", []byte("fresh orphan"), "bundle", nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec(`DELETE FROM _benmore_mcp_artifacts WHERE id IN (?, ?)`, orphan.ID, fresh.ID); err != nil {
		t.Fatal(err)
	}
	stranger := filepath.Join(app.Dir, "uploads", "private", "mcp-artifacts", "notes.html")
	if err := os.WriteFile(stranger, []byte("not an artifact"), 0600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * mcpArtifactOrphanGrace)
	for _, path := range []string{filepath.Join(app.Dir, filepath.FromSlash(kept.StorageRef)), filepath.Join(app.Dir, filepath.FromSlash(orphan.StorageRef)), stranger} {
		if err := os.Chtimes(path, old, old); err != nil {
			t.Fatal(err)
		}
	}
	sweepAppMCPOrphanArtifacts(app)
	if artifactBytesExist(t, app, orphan) {
		t.Fatal("sweep kept an orphaned artifact past the grace period")
	}
	if !artifactBytesExist(t, app, kept) {
		t.Fatal("sweep deleted an artifact its manifest still names")
	}
	if !artifactBytesExist(t, app, fresh) {
		t.Fatal("sweep deleted an orphan inside the grace period (it may be mid-create)")
	}
	if _, err := os.Stat(stranger); err != nil {
		t.Fatalf("sweep touched a file that is not a framework artifact: %v", err)
	}
	// Without the manifest table nothing is swept.
	mustExec(t, app.DB, `DROP TABLE _benmore_mcp_artifacts`)
	if err := os.Chtimes(filepath.Join(app.Dir, filepath.FromSlash(fresh.StorageRef)), old, old); err != nil {
		t.Fatal(err)
	}
	sweepAppMCPOrphanArtifacts(app)
	if !artifactBytesExist(t, app, fresh) {
		t.Fatal("sweep ran without the artifact manifest table")
	}
}

func TestAppMCPArtifactExportsCommittedReviewedCommand(t *testing.T) {
	h := newExposureHarness(t)
	operationID := h.prepare()
	h.approveOK(operationID)
	if result, code := h.call(h.client, appMCPCommitTool, map[string]any{"operation_id": operationID}); code != "" || result["outcome"] != "applied" {
		t.Fatalf("command commit: code=%q result=%#v", code, result)
	}
	generation := snapshotAppMCPGeneration(h.app)
	grant, actor, err := resolveAppMCPAccessForGeneration(context.Background(), h.app, generation, h.pair.AccessToken, h.resource, time.Now())
	if err != nil {
		t.Fatalf("resolve export authority: %v", err)
	}
	var createdAt string
	if err := h.app.DB.QueryRow(`SELECT created_at FROM _benmore_users WHERE id=?`, h.actorID).Scan(&createdAt); err != nil {
		t.Fatal(err)
	}
	exported, code := h.call(h.client, mcpArtifactExportTool, map[string]any{"operation_id": operationID, "format": "html"})
	if code != "" {
		t.Fatalf("artifact export: %s", code)
	}
	artifactID, _ := exported["artifact_id"].(string)
	if artifactID == "" || exported["kind"] != "html" {
		t.Fatalf("artifact result = %#v", exported)
	}
	var recordedOperation, digest, ownerCreatedAt, requiredScopes string
	if err := h.app.DB.QueryRow(`SELECT operation_id,content_sha256,owner_created_at,required_scopes FROM _benmore_mcp_artifacts WHERE id=?`, artifactID).Scan(&recordedOperation, &digest, &ownerCreatedAt, &requiredScopes); err != nil {
		t.Fatal(err)
	}
	if recordedOperation != operationID || digest != exported["sha256"] || !sameAccountIncarnation(ownerCreatedAt, createdAt) || requiredScopes != `["tasks:write"]` {
		t.Fatalf("artifact provenance mismatch: operation=%q digest=%q incarnation=%q scopes=%q result=%#v", recordedOperation, digest, ownerCreatedAt, requiredScopes, exported)
	}
	status, data := mcpArtifactGet(t, h.app, artifactID, h.cookie)
	if status != http.StatusOK || !bytes.Contains(data, []byte("task-actor@example.com")) || !bytes.Contains(data, []byte("done")) {
		t.Fatalf("artifact retrieval status=%d body=%s", status, data)
	}
	if _, err := h.app.DB.Exec(`UPDATE _benmore_users SET created_at=? WHERE id=?`, "different-account-incarnation", h.actorID); err != nil {
		t.Fatal(err)
	}
	if _, err := exportAppMCPCommittedArtifact(context.Background(), h.app, generation, grant, actor, operationID, "html"); err == nil {
		t.Fatal("artifact export accepted a different account incarnation")
	}
	if _, err := h.app.DB.Exec(`UPDATE _benmore_users SET created_at=? WHERE id=?`, createdAt, h.actorID); err != nil {
		t.Fatal(err)
	}
}

func TestAppMCPArtifactMultiSheetXLSXOpensIngestXLSX(t *testing.T) {
	data, err := WriteXLSXSheets([]XLSXSheet{
		{Name: "First", Headers: []string{"name"}, Rows: [][]string{{"alpha"}}},
		{Name: "Second", Headers: []string{"count"}, Rows: [][]string{{"2"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := IngestXLSX(bytes.NewReader(data), int64(len(data)), DefaultIngestLimits())
	if err != nil || !res.Complete {
		t.Fatalf("ingest: complete=%t err=%v", res.Complete, err)
	}
	seen := map[string]bool{}
	for _, block := range res.Blocks {
		seen[block.Sheet] = true
	}
	if !seen["First"] || !seen["Second"] {
		t.Fatalf("sheets were not preserved: %v", seen)
	}
}

func TestAppMCPArtifactHTMLTextIsEscaped(t *testing.T) {
	b, err := renderAppMCPArtifactHTML("<script>title</script>", []string{"<img>"}, [][]string{{"<script>row</script>"}})
	if err != nil || bytes.Contains(b, []byte("<script>")) || !bytes.Contains(b, []byte("&lt;script&gt;")) {
		t.Fatalf("HTML was not escaped: err=%v html=%s", err, b)
	}
}

func TestAppMCPArtifactPDFUsesSandbox(t *testing.T) {
	if findChrome() == "" {
		t.Skip("Chrome is required for PDF artifact rendering")
	}
	pdf, err := renderAppMCPArtifactPDF(context.Background(), nil, []byte("<!doctype html><title>report</title><p>frozen</p>"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(pdf, []byte("%PDF-")) {
		t.Fatalf("rendered output is not a PDF: %q", pdf[:min(len(pdf), 8)])
	}
}

// A PDF artifact starts a headless Chrome per call; it shares the per-user
// PDF budget of GET /pdf/ instead of letting a connector fan out renders.
func TestAppMCPArtifactPDFExportIsRateLimited(t *testing.T) {
	h := newExposureHarness(t)
	operationID := h.prepare()
	h.approveOK(operationID)
	if result, code := h.call(h.client, appMCPCommitTool, map[string]any{"operation_id": operationID}); code != "" || result["outcome"] != "applied" {
		t.Fatalf("command commit: code=%q result=%#v", code, result)
	}
	previous := pdfLimiter
	pdfLimiter = NewRateLimiter(1, time.Minute)
	t.Cleanup(func() { pdfLimiter = previous })
	if !pdfLimiter.Allow(appLimiterKey(h.app, "pdf", fmt.Sprintf("user:%d", h.actorID))) {
		t.Fatal("fresh PDF budget refused")
	}
	if _, code := h.call(h.client, mcpArtifactExportTool, map[string]any{"operation_id": operationID, "format": "pdf"}); code != "operation_limit" {
		t.Fatalf("PDF export past the per-user budget: code=%q, want operation_limit", code)
	}
	if exported, code := h.call(h.client, mcpArtifactExportTool, map[string]any{"operation_id": operationID, "format": "html"}); code != "" || exported["kind"] != "html" {
		t.Fatalf("HTML export shares no PDF budget: code=%q result=%#v", code, exported)
	}
}

// An app without groups has no workspace: its grants and sessions carry an
// empty tenant, and its artifacts must be exportable and retrievable under
// that tenant. A group app still refuses an empty tenant on both sides.
func TestAppMCPArtifactTenantlessOnlyWithoutGroups(t *testing.T) {
	app, _, _ := mcpArtifactFixture(t)
	sessionID := createCrudScopeSession(t, app, "solo-artifact@example.com", "editor", "", "")
	actorID := GetSessionFromDB(app.DB, sessionID).UserID
	var createdAt string
	if err := app.DB.QueryRow(`SELECT created_at FROM _benmore_users WHERE id=?`, actorID).Scan(&createdAt); err != nil {
		t.Fatal(err)
	}
	create := func(tenant string) (appMCPArtifact, error) {
		return createAppMCPArtifact(context.Background(), app, actorID, createdAt, tenant, "editor", []string{"tasks:write"}, "operation-tenantless", "html", []byte("tenantless artifact"), "bundle", nil, "test")
	}
	group := app.Group
	app.Group = nil
	a, err := create("")
	if err != nil {
		t.Fatalf("artifact on an app without groups refused: %v", err)
	}
	if status, body := mcpArtifactGet(t, app, a.ID, sessionID); status != http.StatusOK || string(body) != "tenantless artifact" {
		t.Fatalf("tenantless artifact retrieval status=%d body=%q", status, body)
	}
	app.Group = group
	for _, tenant := range []string{"", "0"} {
		if _, err := create(tenant); err == nil {
			t.Fatalf("a group app accepted artifact tenant %q", tenant)
		}
	}
	if status, _ := mcpArtifactGet(t, app, a.ID, sessionID); status != http.StatusNotFound {
		t.Fatalf("a group app served a tenantless artifact: %d", status)
	}
}
