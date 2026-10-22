//go:build !cli && !windows

package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	portabilityRecipient = "recipient-private@example.test"
	portabilitySubject   = "private-subject-marker-7dbe"
)

type portabilityFixture struct {
	app      *App
	ownerKey string
	foreign  *appMCPTokenPair
}

func newPortabilityFixture(t *testing.T) *portabilityFixture {
	t.Helper()
	app, ownerID, _ := appMCPGrantFixture(t)
	root := filepath.Join("testdata", "mcp-portability")
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		writeTestFile(t, app.Dir, rel, string(data))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, "schema.sql"))
	if err != nil {
		t.Fatal(err)
	}
	auditExec(t, app.DB, string(data))
	reviewAppMCPFixture(t, app.Dir)
	config, err := loadRuntimeConfig(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	app.MCP, app.Flows, app.sourceFiles, app.Access = config.mcp, config.flows, config.sourceFiles, config.access
	if app.Access == nil || app.Access.ModeFor("messages", OpRead, true, false) != "self" {
		t.Fatal("public fixture comment widened the declared self-only access rule")
	}
	app.Roles = &RolesConfig{Roles: map[string]RoleDef{"editor": {Scopes: "messages:read"}, "admin": {Scopes: "messages:read"}}}
	if len(app.MCP.Tools) != 2 {
		t.Fatalf("fixture tool count: %d, want native and remote status only", len(app.MCP.Tools))
	}
	for _, tool := range app.MCP.Tools {
		if tool.Effect != "read" || strings.Contains(tool.Name, "send") || tool.Component != "ui://notify/status" {
			t.Fatalf("fixture exposed a non-read/send tool: %+v", tool)
		}
	}
	auditExec(t, app.DB, `INSERT INTO messages(id,user_id,status,sent_at,delivered_at,recipient,subject) VALUES
		(1,?,?,?,? ,?,?), (2,999,'delivered','2026-10-06T10:00:00Z','2026-10-06T10:01:00Z','foreign@example.test','foreign subject'),
		(3,?,'pending','2026-10-06T09:02:00Z',NULL,?,?)`,
		ownerID, "delivered", "2026-10-06T09:00:00Z", "2026-10-06T09:01:00Z", portabilityRecipient, portabilitySubject,
		ownerID, portabilityRecipient, portabilitySubject)
	grant, err := createAppMCPGrant(app, ownerID, "17", "portability-test", grantFixtureResource, "messages:read", time.Now())
	if err != nil {
		t.Fatalf("owner grant: %v (supported=%q resource=%t)", err, appMCPSupportedScopes(app.MCP), validAppMCPResource(app, grantFixtureResource))
	}
	connection := portabilityConnection(t, app)
	if err := setAppMCPConnectionCredential(context.Background(), app, ownerID, connection, externalSecret); err != nil {
		t.Fatal(err)
	}
	foreignSID := createCrudScopeSession(t, app, "foreign@example.test", "editor", "17", "")
	foreignID := GetSessionFromDB(app.DB, foreignSID).UserID
	auditExec(t, app.DB, "INSERT INTO members(org_id,email) VALUES ('17',?)", "foreign@example.test")
	auditExec(t, app.DB, "UPDATE messages SET user_id=? WHERE id=2", foreignID)
	foreign, err := createAppMCPGrant(app, foreignID, "17", "portability-test", grantFixtureResource, "messages:read", time.Now())
	if err != nil {
		t.Fatalf("foreign grant: %v", err)
	}
	if err := setAppMCPConnectionCredential(context.Background(), app, foreignID, connection, externalSecret+"-foreign"); err != nil {
		t.Fatal(err)
	}
	EnsureReadAuditTable(app.DB)
	app.mu.Lock()
	app.readAudit = &readAuditBuffer{db: app.DB, sync: true}
	app.mu.Unlock()
	return &portabilityFixture{app: app, ownerKey: grant.AccessToken, foreign: foreign}
}

func portabilityConnection(t *testing.T, app *App) *AppMCPConnection {
	t.Helper()
	for i := range app.MCP.Connections {
		if app.MCP.Connections[i].Name == "provider" {
			return &app.MCP.Connections[i]
		}
	}
	t.Fatal("fixture remote connection missing")
	return nil
}

func assertPortabilityProjection(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	if strings.Contains(text, portabilityRecipient) || strings.Contains(text, portabilitySubject) {
		t.Fatalf("private message fields escaped projection: %s", text)
	}
	var row map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &row); err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, len(row))
	for key := range row {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	if want := []string{"delivered_at", "id", "sent_at", "status"}; !reflect.DeepEqual(keys, want) {
		t.Fatalf("projected keys %v, want %v", keys, want)
	}
	return text
}

func portabilityWidgetCacheText() string {
	appMCPWidgetCache.Lock()
	defer appMCPWidgetCache.Unlock()
	data, _ := json.Marshal(appMCPWidgetCache.entries)
	return string(data)
}

func TestAppMCPNotifyHubPortabilityProjectionAndForeignDenial(t *testing.T) {
	f := newPortabilityFixture(t)
	upstream := newExternalUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/messages/1" && r.URL.Path != "/api/messages/3" {
			t.Errorf("unexpected upstream path %q", r.URL.Path)
		}
		switch r.Header.Get("Authorization") {
		case "Bearer " + externalSecret + "-foreign":
			http.Error(w, "private message is outside this credential", http.StatusForbidden)
			return
		case "Bearer " + externalSecret:
		default:
			t.Errorf("unexpected per-user provider credential %q", r.Header.Get("Authorization"))
			http.Error(w, "credential denied", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/messages/3" {
			_, _ = w.Write([]byte(`{"id":3,"status":"pending","sent_at":"2026-10-06T09:02:00Z","delivered_at":"","recipient":"` + portabilityRecipient + `","subject":"` + portabilitySubject + `"}`))
			return
		}
		_, _ = w.Write([]byte(`{"id":1,"status":"delivered","sent_at":"2026-10-06T09:00:00Z","delivered_at":"2026-10-06T09:01:00Z","recipient":"` + portabilityRecipient + `","subject":"` + portabilitySubject + `"}`))
	})
	var logs strings.Builder
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	native, err := runAppMCPNativeRead(context.Background(), f.app, f.ownerKey, grantFixtureResource, "message_status", map[string]any{"id": 1})
	if err != nil {
		t.Fatalf("native status read: %v", err)
	}
	nativeOutput := assertPortabilityProjection(t, native.Data)
	nativeEnvelope, err := json.Marshal(native)
	if err != nil {
		t.Fatal(err)
	}

	remote, err := runAppMCPExternalRead(context.Background(), f.app, snapshotAppMCPGeneration(f.app), f.ownerKey, grantFixtureResource, "remote_message_status", map[string]any{"path": map[string]any{"id": json.Number("1")}})
	if err != nil {
		t.Fatalf("remote status read: %v", err)
	}
	remoteOutput := assertPortabilityProjection(t, remote.Data)
	remoteEnvelope, err := json.Marshal(remote)
	if err != nil {
		t.Fatal(err)
	}
	wantOutput := `{"delivered_at":"2026-10-06T09:01:00Z","id":1,"sent_at":"2026-10-06T09:00:00Z","status":"delivered"}`
	if nativeOutput != wantOutput || remoteOutput != wantOutput {
		t.Fatalf("native/remote status projection differs: native=%s remote=%s", nativeOutput, remoteOutput)
	}
	if upstream.hits() != 1 {
		t.Fatalf("remote read requests: %d, want 1", upstream.hits())
	}
	pendingNative, err := runAppMCPNativeRead(context.Background(), f.app, f.ownerKey, grantFixtureResource, "message_status", map[string]any{"id": 3})
	if err != nil {
		t.Fatalf("native pending status read: %v", err)
	}
	pendingRemote, err := runAppMCPExternalRead(context.Background(), f.app, snapshotAppMCPGeneration(f.app), f.ownerKey, grantFixtureResource, "remote_message_status", map[string]any{"path": map[string]any{"id": json.Number("3")}})
	if err != nil {
		t.Fatalf("remote pending status read: %v", err)
	}
	if got, want := assertPortabilityProjection(t, pendingNative.Data), `{"delivered_at":"","id":3,"sent_at":"2026-10-06T09:02:00Z","status":"pending"}`; got != want {
		t.Fatalf("native pending status projection: got %s, want %s", got, want)
	}
	if got, want := assertPortabilityProjection(t, pendingRemote.Data), `{"delivered_at":"","id":3,"sent_at":"2026-10-06T09:02:00Z","status":"pending"}`; got != want {
		t.Fatalf("remote pending status projection: got %s, want %s", got, want)
	}
	if upstream.hits() != 2 {
		t.Fatalf("remote status requests before foreign denial: %d, want 2", upstream.hits())
	}

	foreignOwn, err := runAppMCPNativeRead(context.Background(), f.app, f.foreign.AccessToken, grantFixtureResource, "message_status", map[string]any{"id": 2})
	if err != nil {
		t.Fatalf("foreign user could not read their own status: %v", err)
	}
	assertPortabilityProjection(t, foreignOwn.Data)
	if _, err := runAppMCPNativeRead(context.Background(), f.app, f.foreign.AccessToken, grantFixtureResource, "message_status", map[string]any{"id": 1}); err == nil {
		t.Fatal("native flow returned another user's message")
	}
	_, foreignErr := runAppMCPExternalRead(context.Background(), f.app, snapshotAppMCPGeneration(f.app), f.foreign.AccessToken, grantFixtureResource, "remote_message_status", map[string]any{"path": map[string]any{"id": json.Number("1")}})
	if foreignErr == nil || externalErrorCode(t, foreignErr) != "denied" {
		t.Fatalf("remote provider did not deny the foreign user's message: %v", foreignErr)
	}
	if upstream.hits() != 3 {
		t.Fatalf("foreign remote denial did not reach the fake provider: %d requests", upstream.hits())
	}

	telemetry, err := QueryRows(f.app.DB, `SELECT table_name, row_id, query_type, user_email FROM _benmore_read_audit`)
	if err != nil {
		t.Fatal(err)
	}
	telemetryJSON, _ := json.Marshal(telemetry)
	widgets := appMCPGenerationWidgets(context.Background(), snapshotAppMCPGeneration(f.app))
	widget := widgets["ui://notify/status"]
	if widget == nil || !slices.Contains(widget.Tools, "message_status") || !slices.Contains(widget.Tools, "remote_message_status") {
		t.Fatalf("shared StatusCard is not linked to both bindings: %+v", widget)
	}
	if !strings.Contains(widget.HTML, "pending") {
		t.Fatal("shared StatusCard does not render an empty delivery timestamp as pending")
	}
	if strings.Contains(widget.HTML, portabilityRecipient) || strings.Contains(widget.HTML, portabilitySubject) {
		t.Fatal("shared StatusCard contains per-message data")
	}
	cacheAfter := portabilityWidgetCacheText()
	for name, text := range map[string]string{"native output": string(nativeEnvelope), "remote output": string(remoteEnvelope), "foreign denial": foreignErr.Error(), "telemetry": string(telemetryJSON), "logs": logs.String(), "component cache": cacheAfter} {
		if strings.Contains(text, portabilityRecipient) || strings.Contains(text, portabilitySubject) {
			t.Fatalf("private message fields reached %s: %s", name, text)
		}
	}
}
