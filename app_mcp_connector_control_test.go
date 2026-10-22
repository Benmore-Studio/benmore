//go:build !cli && !windows

package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func connectorStatus(t *testing.T, app *App) appMCPConnectorStatus {
	t.Helper()
	return appMCPConnectorStatusFor(context.Background(), app)
}

func connectorApply(t *testing.T, app *App, action string, writes bool) error {
	t.Helper()
	return appMCPConnectorApply(context.Background(), app, appMCPConnectorRequest{Action: action, Writes: writes})
}

func connectorRevoke(t *testing.T, app *App) error {
	t.Helper()
	return appMCPConnectorApply(context.Background(), app, appMCPConnectorRequest{Action: "disable", Revoke: true})
}

func TestAppMCPConnectorSwitchesRoundTripFromFirstEnable(t *testing.T) {
	app, _, _ := newUnenrolledCommandProviderTaskFixture(t, commandTaskFlowFixture, "")
	st := connectorStatus(t, app)
	if !st.AuthorityConfigured || st.Exposed || st.ApprovedWrites || !st.ManifestPresent || !st.ManifestValid || st.CommandTools != 1 || st.Enrollment != "none" || st.Problem != "" {
		t.Fatalf("initial status: %+v", st)
	}
	if err := connectorApply(t, app, "enable", false); err != nil {
		t.Fatal(err)
	}
	if st = connectorStatus(t, app); !st.Exposed || st.ApprovedWrites || st.Enrollment != "none" {
		t.Fatalf("exposure only: %+v", st)
	}
	if err := connectorApply(t, app, "enable", true); err != nil {
		t.Fatal(err)
	}
	if st = connectorStatus(t, app); !st.Exposed || !st.ApprovedWrites || st.Enrollment != "active" {
		t.Fatalf("writes on: %+v", st)
	}
	if _, live := appMCPWritesLive(app); !live {
		t.Fatal("approved writes are not live for the connector")
	}
	if err := connectorApply(t, app, "disable", true); err != nil {
		t.Fatal(err)
	}
	if st = connectorStatus(t, app); !st.Exposed || st.ApprovedWrites || st.Enrollment != "active" {
		t.Fatalf("writes off keeps exposure and enrollment: %+v", st)
	}
	if _, live := appMCPWritesLive(app); live {
		t.Fatal("writes still live after disable --writes")
	}
	// Re-enable writes, then disable everything and enable again: the full
	// disable retired the revision ledger, and enable --writes re-enrolls it.
	if err := connectorApply(t, app, "enable", true); err != nil {
		t.Fatal(err)
	}
	if err := connectorApply(t, app, "disable", false); err != nil {
		t.Fatal(err)
	}
	if st = connectorStatus(t, app); st.Exposed || st.ApprovedWrites {
		t.Fatalf("full disable: %+v", st)
	}
	if err := connectorApply(t, app, "enable", true); err != nil {
		t.Fatalf("re-enable after full disable: %v", err)
	}
	if st = connectorStatus(t, app); !st.Exposed || !st.ApprovedWrites || st.Enrollment != "active" {
		t.Fatalf("re-enabled: %+v", st)
	}
}

func TestAppMCPConnectorDisableWithoutStateIsANoOp(t *testing.T) {
	app, _, _ := newUnenrolledCommandProviderTaskFixture(t, commandTaskFlowFixture, "")
	for _, writes := range []bool{true, false} {
		if err := connectorApply(t, app, "disable", writes); err != nil {
			t.Fatalf("disable writes=%v with nothing enabled: %v", writes, err)
		}
	}
	if st := connectorStatus(t, app); st.Exposed || st.ApprovedWrites {
		t.Fatalf("status: %+v", st)
	}
}

func TestAppMCPConnectorWritesStayOffWithoutCommandTools(t *testing.T) {
	f := newCanonicalUpdateSourceFixture(t, "", "", "", false)
	before := connectorStatus(t, f.app)
	err := connectorApply(t, f.app, "enable", true)
	if err == nil || !strings.Contains(err.Error(), "no command tools") {
		t.Fatalf("enable --writes without commands: %v", err)
	}
	if st := connectorStatus(t, f.app); st != before || st.ApprovedWrites || st.CommandTools != 0 || !st.ManifestValid {
		t.Fatalf("a refused enable must change nothing: %+v", st)
	}
	// Plain exposure of a reviewed manifest remains available.
	if err := connectorApply(t, f.app, "enable", false); err != nil {
		t.Fatal(err)
	}
}

func TestAppMCPConnectorWritesStayOffWhenEnrollmentFails(t *testing.T) {
	app, _, _ := newUnenrolledCommandProviderTaskFixture(t, commandTaskFlowFixture, "")
	previous := appMCPRevisionEnrollmentFault
	appMCPRevisionEnrollmentFault = func(string, appMCPRevisionEnrollmentStage) error { return errors.New("injected") }
	t.Cleanup(func() { appMCPRevisionEnrollmentFault = previous })
	err := connectorApply(t, app, "enable", true)
	if err == nil || !strings.Contains(err.Error(), "enrollment") {
		t.Fatalf("enable --writes with failing enrollment: %v", err)
	}
	if st := connectorStatus(t, app); st.Exposed || st.ApprovedWrites {
		t.Fatalf("a refused enable must not leave the connector exposed: %+v", st)
	}
	appMCPRevisionEnrollmentFault = previous
	// A connector the owner had already exposed stays exposed when only the
	// write step fails.
	if err := connectorApply(t, app, "enable", false); err != nil {
		t.Fatal(err)
	}
	// The first failure left an enrollment stuck pending; enable --writes says
	// so and what to do, and changes nothing.
	err = connectorApply(t, app, "enable", true)
	if err == nil || !strings.Contains(err.Error(), "pending") || !strings.Contains(err.Error(), "operator must repair") {
		t.Fatalf("enable --writes over a pending enrollment: %v", err)
	}
	if st := connectorStatus(t, app); !st.Exposed || st.ApprovedWrites || st.Enrollment != "pending" {
		t.Fatalf("status after failed write enable: %+v", st)
	}
}

func TestAppMCPConnectorDisablePausesAndRevokeInvalidatesGrants(t *testing.T) {
	h := newExposureHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	// tools lists with the original grant's token; a refused connect is an error.
	tools := func() error {
		httpClient := &http.Client{Transport: appMCPBearerRoundTripper{base: h.server.Client().Transport, token: h.pair.AccessToken}}
		transport := &sdk.StreamableClientTransport{Endpoint: h.resource, HTTPClient: httpClient, DisableStandaloneSSE: true}
		session, err := sdk.NewClient(&sdk.Implementation{Name: "owner-switch", Version: "1"}, nil).Connect(ctx, transport, nil)
		if err != nil {
			return err
		}
		defer session.Close()
		_, err = session.ListTools(ctx, nil)
		return err
	}
	if err := tools(); err != nil {
		t.Fatalf("grant must work before: %v", err)
	}
	// Pause: every call stops, then the earlier grant works again.
	if err := connectorApply(t, h.app, "disable", false); err != nil {
		t.Fatal(err)
	}
	if err := tools(); err == nil {
		t.Fatal("a paused connector answered")
	}
	if err := connectorApply(t, h.app, "enable", true); err != nil {
		t.Fatal(err)
	}
	if err := tools(); err != nil {
		t.Fatalf("a pause must not revoke the grant: %v", err)
	}
	// Revoke: the same grant and token stay dead after the connector returns.
	if err := connectorRevoke(t, h.app); err != nil {
		t.Fatal(err)
	}
	if st := connectorStatus(t, h.app); st.Exposed || st.ApprovedWrites || st.Enrollment != "retired" {
		t.Fatalf("status after revoke: %+v", st)
	}
	if err := connectorApply(t, h.app, "enable", false); err != nil {
		t.Fatal(err)
	}
	if err := tools(); err == nil {
		t.Fatal("a revoked grant answered after re-enable")
	}
	// enable --writes re-enrolls the retired enrollment; the old grant stays dead.
	if err := connectorApply(t, h.app, "enable", true); err != nil {
		t.Fatalf("re-enable writes after revoke: %v", err)
	}
	if st := connectorStatus(t, h.app); !st.Exposed || !st.ApprovedWrites || st.Enrollment != "active" {
		t.Fatalf("status after re-enrolling: %+v", st)
	}
	if err := tools(); err == nil {
		t.Fatal("a revoked grant answered after writes were re-enabled")
	}
	if err := appMCPConnectorApply(ctx, h.app, appMCPConnectorRequest{Action: "enable", Revoke: true}); err == nil {
		t.Fatal("revoke is only valid with disable")
	}
}

func TestAppMCPConnectorControlSerializesPerApp(t *testing.T) {
	unlock := lockAppMCPControl("/same/app")
	entered := make(chan struct{})
	go func() {
		defer lockAppMCPControl("/same/app")()
		close(entered)
	}()
	select {
	case <-entered:
		t.Fatal("a second change entered while the first held the app lock")
	case <-time.After(50 * time.Millisecond):
	}
	defer lockAppMCPControl("/another/app")() // other apps are independent
	unlock()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the waiting change never ran")
	}
}

func TestAppMCPConnectorStatusAndErrorsCarryNoPaths(t *testing.T) {
	app, _, _ := newUnenrolledCommandProviderTaskFixture(t, commandTaskFlowFixture, "")
	loose := t.TempDir()
	if err := os.Chmod(loose, 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BENMORE_MCP_AUTHORITY_DIR", loose)
	st := connectorStatus(t, app)
	if st.Problem == "" || strings.Contains(st.Problem, "/") {
		t.Fatalf("status problem %q must be a fixed phrase without paths", st.Problem)
	}
	err := &fs.PathError{Op: "open", Path: "/var/lib/benmore/authority/abc.json", Err: errors.New("denied")}
	if text := appMCPControlText(err); strings.Contains(text, "/var") || strings.Contains(text, "authority") {
		t.Fatalf("path leaked: %q", text)
	}
}

func TestAppMCPConnectorDisableBlocksApprovedUncommittedOperation(t *testing.T) {
	h := newExposureHarness(t)
	id := h.prepare()
	h.approveOK(id)
	if err := connectorApply(t, h.app, "disable", true); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	result, err := h.client.CallTool(ctx, &sdk.CallToolParams{Name: appMCPCommitTool, Arguments: map[string]any{"operation_id": id}})
	if err == nil && !result.IsError {
		t.Fatal("_commit ran after writes were turned off")
	}
	if h.taskDone() {
		t.Fatal("business row changed after disable")
	}
	// Re-enabling rotates the write epoch: the earlier operation never runs.
	if err := connectorApply(t, h.app, "enable", true); err != nil {
		t.Fatal(err)
	}
	h.client = appMCPClient(t, h.server, h.pair.AccessToken, nil)
	if _, code := h.call(h.client, appMCPCommitTool, map[string]any{"operation_id": id}); code == "" {
		t.Fatal("the stale operation committed after re-enable")
	}
	if h.taskDone() {
		t.Fatal("business row changed after re-enable")
	}
	// Audit rows and the stored operation are kept.
	if h.count("SELECT count(*) FROM _benmore_audit_log") == 0 {
		t.Fatal("audit rows were erased")
	}
	if state := h.status(id); state["state"] != "expired" {
		t.Fatalf("operation state after rotation: %#v", state)
	}
	// Full disable also stops new calls at once.
	if err := connectorApply(t, h.app, "disable", false); err != nil {
		t.Fatal(err)
	}
	if _, err := h.client.ListTools(ctx, nil); err == nil {
		t.Fatal("connector still answered after a full disable")
	}
}

func TestAppMCPEpochStateWithoutNewFieldsLoadsAndFlagsPersist(t *testing.T) {
	dir := epochFixture(t)
	app, cleanup := newTestApp(t)
	defer cleanup()
	state, err := updateAppMCPEpoch(app.Dir, true, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if state.ExternalExport || state.PublicPublication {
		t.Fatal("new switches must default to false")
	}
	root, key, err := appMCPAuthorityRoot(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	raw, err := os.ReadFile(filepath.Join(dir, key+".json"))
	if err != nil {
		t.Fatal(err)
	}
	// A file written before the fields existed is byte-identical to today's.
	if bytes.Contains(raw, []byte("external_export")) || bytes.Contains(raw, []byte("public_publication")) {
		t.Fatalf("default state serializes the new fields: %s", raw)
	}
	loaded, err := readAppMCPEpoch(root, key)
	if err != nil || loaded.Epoch != state.Epoch {
		t.Fatalf("old-shape state did not load: %v", err)
	}
	// Set both through the canonical encoding; they load and survive an update.
	withFlags := *loaded
	withFlags.ExternalExport, withFlags.PublicPublication = true, true
	withFlags.ExternalExportEpoch, err = rotateAppMCPCapabilityEpoch()
	if err != nil {
		t.Fatal(err)
	}
	withFlags.PublicPublicationEpoch, err = rotateAppMCPCapabilityEpoch()
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(&withFlags)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, key+".json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if loaded, err = readAppMCPEpoch(root, key); err != nil || !loaded.ExternalExport || !loaded.PublicPublication {
		t.Fatalf("flagged state did not load: %v %+v", err, loaded)
	}
	for _, capability := range []string{"external_export", "public_publication"} {
		missingEpoch := *loaded
		if capability == "external_export" {
			missingEpoch.ExternalExportEpoch = ""
		} else {
			missingEpoch.PublicPublicationEpoch = ""
		}
		data, err = json.Marshal(&missingEpoch)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, key+".json"), data, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readAppMCPEpoch(root, key); err == nil {
			t.Fatalf("enabled %s capability without an epoch was accepted", capability)
		}
	}
	data, err = json.Marshal(loaded)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, key+".json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if after, err := updateAppMCPEpoch(app.Dir, true, false, false); err != nil || !after.ExternalExport || !after.PublicPublication {
		t.Fatalf("an exposure refresh dropped the flags: %v %+v", err, after)
	}
	// Turning the connector off clears them with exposure.
	if after, err := updateAppMCPEpoch(app.Dir, false, false, false); err != nil || after.ExternalExport || after.PublicPublication {
		t.Fatalf("disable kept the flags: %v %+v", err, after)
	}
}

func connectorRouteFixture(t *testing.T) (*App, *http.ServeMux) {
	t.Helper()
	app, _, _ := newUnenrolledCommandProviderTaskFixture(t, commandTaskFlowFixture, "")
	EnsureAuditLogTable(app.DB)
	previous := serverSecret
	serverSecret = "connector-control-test-secret-0123456789"
	t.Cleanup(func() { serverSecret = previous })
	mux := http.NewServeMux()
	registerAppMCPConnectorControl(mux, app)
	return app, mux
}

func connectorPost(mux *http.ServeMux, token, body string) (int, map[string]any) {
	req := httptest.NewRequest(http.MethodPost, appMCPControlRoute, strings.NewReader(body))
	if token != "" {
		req.Header.Set(appMCPControlTokenHeader, token)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func connectorToken(app *App, change appMCPConnectorRequest) string {
	return mintAppMCPControlToken(app.Dir, time.Now().Add(10*time.Second), serverSecret, "owner@example.com", change.binding())
}

func TestAppMCPConnectorControlRouteRequiresOwnerTokenAndAudits(t *testing.T) {
	app, mux := connectorRouteFixture(t)
	enable := appMCPConnectorRequest{Action: "enable"}
	at := time.Now().Add(10 * time.Second)
	for name, token := range map[string]string{
		"missing":          "",
		"import token":     mintImportOwnerTokenWithSecret(app, at, serverSecret, "owner@example.com"),
		"types token":      mintTypesTokenWithSecret(app.Dir, at, serverSecret),
		"other audience":   mintAppMCPControlToken(app.Dir+"-other", at, serverSecret, "owner@example.com", enable.binding()),
		"other secret":     mintAppMCPControlToken(app.Dir, at, "another-secret-0123456789abcdef0123", "owner@example.com", enable.binding()),
		"expired":          mintAppMCPControlToken(app.Dir, time.Now().Add(-time.Minute), serverSecret, "owner@example.com", enable.binding()),
		"over the ceiling": mintAppMCPControlToken(app.Dir, time.Now().Add(time.Hour), serverSecret, "owner@example.com", enable.binding()),
		"over 30 seconds":  mintAppMCPControlToken(app.Dir, time.Now().Add(time.Minute), serverSecret, "owner@example.com", enable.binding()),
		"empty subject":    mintAppMCPControlToken(app.Dir, at, serverSecret, "", enable.binding()),
	} {
		if code, _ := connectorPost(mux, token, `{"action":"enable"}`); code != http.StatusForbidden {
			t.Fatalf("%s token: status %d", name, code)
		}
	}
	if st := connectorStatus(t, app); st.Exposed {
		t.Fatal("a refused request changed the switches")
	}
	writesOn := appMCPConnectorRequest{Action: "enable", Writes: true}
	if code, out := connectorPost(mux, connectorToken(app, writesOn), `{"action":"enable","writes":true}`); code != http.StatusOK {
		t.Fatalf("owner enable: %d %v", code, out)
	}
	if code, out := connectorPost(mux, connectorToken(app, appMCPConnectorRequest{Action: "status"}), `{"action":"status"}`); code != http.StatusOK || out["status"].(map[string]any)["approved_writes"] != true {
		t.Fatalf("owner status: %d %v", code, out)
	}
	if code, _ := connectorPost(mux, connectorToken(app, appMCPConnectorRequest{Action: "explode"}), `{"action":"explode"}`); code != http.StatusBadRequest {
		t.Fatalf("unknown action status %d", code)
	}
	disableWrites := appMCPConnectorRequest{Action: "disable", Writes: true}
	if code, out := connectorPost(mux, connectorToken(app, disableWrites), `{"action":"disable","writes":true}`); code != http.StatusOK {
		t.Fatalf("owner disable writes: %d %v", code, out)
	}
	rows, err := QueryRows(app.DB, "SELECT user_email, old_values, new_values FROM _benmore_audit_log WHERE action='mcp_connector_switch' ORDER BY id")
	if err != nil || len(rows) != 2 {
		t.Fatalf("audit rows: %v %v", rows, err)
	}
	type switchState struct {
		ApprovedWrites    bool `json:"approved_writes"`
		Exposed           bool `json:"exposed"`
		ExternalExport    bool `json:"external_export"`
		PublicPublication bool `json:"public_publication"`
	}
	readSwitches := func(raw any) (switchState, error) {
		var state switchState
		encoded := []byte(raw.(string))
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(encoded, &fields); err != nil {
			return state, err
		}
		for _, name := range []string{"approved_writes", "exposed", "external_export", "public_publication"} {
			if _, ok := fields[name]; !ok {
				return state, fmt.Errorf("missing %s", name)
			}
		}
		return state, json.Unmarshal(encoded, &state)
	}
	oldOn, oldOnErr := readSwitches(rows[0]["old_values"])
	newOn, newOnErr := readSwitches(rows[0]["new_values"])
	if rows[0]["user_email"] != "owner@example.com" || oldOnErr != nil || newOnErr != nil ||
		oldOn != (switchState{}) || newOn != (switchState{ApprovedWrites: true, Exposed: true}) {
		t.Fatalf("enable audit row: %v", rows[0])
	}
	oldOff, oldOffErr := readSwitches(rows[1]["old_values"])
	newOff, newOffErr := readSwitches(rows[1]["new_values"])
	if rows[1]["user_email"] != "owner@example.com" || oldOffErr != nil || newOffErr != nil ||
		oldOff != (switchState{ApprovedWrites: true, Exposed: true}) || newOff != (switchState{Exposed: true}) {
		t.Fatalf("disable audit row: %v", rows[1])
	}
	epoch, err := currentAppMCPEpoch(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		for _, col := range []string{"old_values", "new_values"} {
			for _, secret := range []string{epoch.Epoch, epoch.ApprovedWriteEpoch, epoch.ExternalExportEpoch, epoch.PublicPublicationEpoch} {
				if secret != "" && strings.Contains(row[col].(string), secret) {
					t.Fatalf("audit row carries an epoch credential: %v", row)
				}
			}
		}
	}
}

func TestAppMCPConnectorControlTokenAuthorizesOnlyItsOwnChange(t *testing.T) {
	app, mux := connectorRouteFixture(t)
	enableToken := connectorToken(app, appMCPConnectorRequest{Action: "enable"})
	if code, _ := connectorPost(mux, enableToken, `{"action":"enable"}`); code != http.StatusOK {
		t.Fatalf("enable: %d", code)
	}
	// A captured enable token cannot be replayed as any other change.
	for name, body := range map[string]string{
		"disable":        `{"action":"disable"}`,
		"revoke":         `{"action":"disable","revoke":true}`,
		"enable writes":  `{"action":"enable","writes":true}`,
		"disable writes": `{"action":"disable","writes":true}`,
	} {
		if code, _ := connectorPost(mux, enableToken, body); code != http.StatusForbidden {
			t.Fatalf("enable token replayed as %s: status %d", name, code)
		}
	}
	if st := connectorStatus(t, app); !st.Exposed {
		t.Fatalf("a replayed token changed the switches: %+v", st)
	}
	// A pause token cannot revoke.
	if code, _ := connectorPost(mux, connectorToken(app, appMCPConnectorRequest{Action: "disable"}), `{"action":"disable","revoke":true}`); code != http.StatusForbidden {
		t.Fatalf("pause token replayed as revoke: %d", code)
	}
	// The MAC uses a purpose key: the same payload signed with the bare
	// server secret does not verify.
	payload := fmt.Sprintf("mcpctl.%d.%s.%s.%s", time.Now().Add(10*time.Second).Unix(), base64.RawURLEncoding.EncodeToString([]byte("owner@example.com")), "disable:0:0", app.Dir)
	bare := hmac.New(sha256.New, []byte(serverSecret))
	bare.Write([]byte(payload))
	forged := base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + base64.RawURLEncoding.EncodeToString(bare.Sum(nil))
	if code, _ := connectorPost(mux, forged, `{"action":"disable"}`); code != http.StatusForbidden {
		t.Fatalf("bare-secret MAC accepted: %d", code)
	}
	if code, out := connectorPost(mux, connectorToken(app, appMCPConnectorRequest{Action: "disable", Revoke: true}), `{"action":"disable","revoke":true}`); code != http.StatusOK {
		t.Fatalf("revoke: %d %v", code, out)
	}
}

func TestAppMCPConnectorControlReportsAppliedWhenAuditFails(t *testing.T) {
	app, mux := connectorRouteFixture(t)
	if _, err := app.DB.Exec("DROP TABLE _benmore_audit_log"); err != nil {
		t.Fatal(err)
	}
	code, out := connectorPost(mux, connectorToken(app, appMCPConnectorRequest{Action: "enable"}), `{"action":"enable"}`)
	if code != http.StatusInternalServerError || out["applied"] != true || !strings.HasPrefix(out["error"].(string), "applied; audit failed") {
		t.Fatalf("audit failure response: %d %v", code, out)
	}
	if st := connectorStatus(t, app); !st.Exposed {
		t.Fatalf("the change was applied and must stay applied: %+v", st)
	}
}

func TestAppMCPConnectorRevokeNeverReportsSuccessWithoutAuthority(t *testing.T) {
	app, _, _ := newUnenrolledCommandProviderTaskFixture(t, commandTaskFlowFixture, "")
	// A valid root with no state file for this app: nothing was ever enabled.
	for _, req := range []appMCPConnectorRequest{{Action: "disable", Revoke: true}, {Action: "disable"}, {Action: "disable", Writes: true}} {
		if err := appMCPConnectorApply(context.Background(), app, req); err != nil {
			t.Fatalf("%+v with nothing enabled: %v", req, err)
		}
	}
	// A missing authority root is not "nothing enabled".
	t.Setenv("BENMORE_MCP_AUTHORITY_DIR", filepath.Join(t.TempDir(), "missing-root"))
	for _, req := range []appMCPConnectorRequest{{Action: "disable", Revoke: true}, {Action: "disable"}, {Action: "disable", Writes: true}} {
		if err := appMCPConnectorApply(context.Background(), app, req); err == nil || !strings.Contains(err.Error(), "unavailable") {
			t.Fatalf("%+v over a missing root reported %v", req, err)
		}
	}
	// So is a root that is not owner-only.
	loose := t.TempDir()
	if err := os.Chmod(loose, 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BENMORE_MCP_AUTHORITY_DIR", loose)
	if err := appMCPConnectorApply(context.Background(), app, appMCPConnectorRequest{Action: "disable", Revoke: true}); err == nil {
		t.Fatal("revoke over an unusable root reported success")
	}
}

func TestAppMCPConnectorOwnerActionWaitsForTheAuthorityLockOnlyAsLongAsItsContext(t *testing.T) {
	app, _, _ := newUnenrolledCommandProviderTaskFixture(t, commandTaskFlowFixture, "")
	if err := connectorApply(t, app, "enable", false); err != nil {
		t.Fatal(err)
	}
	held, err := acquireAppMCPAuthorityLease(context.Background(), app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	for name, run := range map[string]func(ctx context.Context) error{
		"revoke": func(ctx context.Context) error {
			return appMCPConnectorApply(ctx, app, appMCPConnectorRequest{Action: "disable", Revoke: true})
		},
		"disable": func(ctx context.Context) error {
			return appMCPConnectorApply(ctx, app, appMCPConnectorRequest{Action: "disable"})
		},
		"disable writes": func(ctx context.Context) error {
			return appMCPConnectorApply(ctx, app, appMCPConnectorRequest{Action: "disable", Writes: true})
		},
		"enable": func(ctx context.Context) error {
			return appMCPConnectorApply(ctx, app, appMCPConnectorRequest{Action: "enable"})
		},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		start := time.Now()
		err := run(ctx)
		cancel()
		if err == nil || !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 5*time.Second {
			t.Fatalf("%s behind a held lease: err=%v after %v", name, err, time.Since(start))
		}
	}
	held.Close()
	if err := connectorRevoke(t, app); err != nil {
		t.Fatalf("revoke once the lease is released: %v", err)
	}
}

func TestAppMCPConnectorControlLockIsKeyedByCanonicalPath(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	unlock := lockAppMCPControl(dir)
	entered := make(chan struct{})
	go func() {
		defer lockAppMCPControl(link + "/")()
		close(entered)
	}()
	select {
	case <-entered:
		t.Fatal("a symlinked spelling of the same app took a second lock")
	case <-time.After(50 * time.Millisecond):
	}
	unlock()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the waiting change never ran")
	}
}

func TestAppMCPConnectorWaitingForTheLockDoesNotSpendTheDeadline(t *testing.T) {
	app, mux := connectorRouteFixture(t)
	unlock := lockAppMCPControl(app.Dir)
	done := make(chan int, 1)
	go func() {
		code, _ := connectorPost(mux, connectorToken(app, appMCPConnectorRequest{Action: "enable"}), `{"action":"enable"}`)
		done <- code
	}()
	select {
	case <-done:
		t.Fatal("enable ran while another change held the app lock")
	case <-time.After(100 * time.Millisecond):
	}
	unlock()
	select {
	case code := <-done:
		if code != http.StatusOK {
			t.Fatalf("enable after the wait: %d", code)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("enable never ran")
	}
}

func TestAppMCPControlTextRemovesEveryPathLikeToken(t *testing.T) {
	for _, in := range []string{
		"open /var/lib/benmore/authority/abc.json: denied",
		"Post \"http://127.0.0.1:41233/api/_internal/mcp/connector\": dial tcp: refused",
		"stat relative/dir/file: no such file",
	} {
		if got := appMCPControlText(errors.New(in)); strings.Contains(got, "/") || !strings.Contains(got, "<path>") {
			t.Fatalf("%q -> %q", in, got)
		}
	}
	if got := appMCPControlText(errors.New("revision enrollment is pending")); got != "revision enrollment is pending" {
		t.Fatalf("plain text changed: %q", got)
	}
}

// The revision triggers tax every write to an enrolled table and the ledger
// keeps every tombstone. Before, both stayed installed after the connector was
// disabled or mcp.yaml removed; now they go once nothing can use them, and
// enable --writes re-enrolls.
func TestAppMCPRevisionLedgerRetiredWhenConnectorUnused(t *testing.T) {
	app, _, _ := newUnenrolledCommandProviderTaskFixture(t, commandTaskFlowFixture, "")
	ctx := context.Background()
	installed := func() bool {
		t.Helper()
		ok, err := appMCPRevisionLedgerInstalled(ctx, app.DB)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if err := connectorApply(t, app, "enable", true); err != nil {
		t.Fatal(err)
	}
	if !installed() {
		t.Fatal("enable --writes did not install the revision ledger")
	}
	// Writes off, reads still exposed: reads cite revisions, so the ledger stays.
	if err := connectorApply(t, app, "disable", true); err != nil {
		t.Fatal(err)
	}
	if !installed() {
		t.Fatal("turning off only writes removed the ledger exposed reads cite")
	}
	retireUnusedAppMCPRevisionLedger(app)
	if !installed() {
		t.Fatal("start-up removed the ledger of an exposed connector")
	}
	// A pause turns exposure off: the ledger goes, and app writes no longer feed it.
	if err := connectorApply(t, app, "disable", false); err != nil {
		t.Fatal(err)
	}
	if installed() {
		t.Fatal("revision triggers stayed installed after the connector was disabled")
	}
	if st := connectorStatus(t, app); st.Exposed || st.ApprovedWrites || st.Enrollment != "retired" {
		t.Fatalf("status after disable: %+v", st)
	}
	if _, err := app.DB.Exec(`INSERT INTO tasks(id,project_id,org_id,title,status) VALUES(9001,1,'17','after disable','open')`); err != nil {
		t.Fatalf("app write after retirement: %v", err)
	}
	if _, err := app.DB.Exec(`DELETE FROM tasks WHERE id=9001`); err != nil {
		t.Fatalf("app delete after retirement: %v", err)
	}
	// enable --writes repairs: a fresh ledger, live writes.
	if err := connectorApply(t, app, "enable", true); err != nil {
		t.Fatalf("re-enable writes after retirement: %v", err)
	}
	if st := connectorStatus(t, app); !st.Exposed || !st.ApprovedWrites || st.Enrollment != "active" || !installed() {
		t.Fatalf("re-enrolled: %+v installed=%v", st, installed())
	}
	if _, live := appMCPWritesLive(app); !live {
		t.Fatal("approved writes are not live after re-enrolling")
	}
	// mcp.yaml removed: the start-up check retires the ledger even while the
	// owner state still says exposed, and turns approved writes off.
	manifest := app.MCP
	app.MCP = nil
	retireUnusedAppMCPRevisionLedger(app)
	app.MCP = manifest
	if installed() {
		t.Fatal("revision triggers stayed installed after mcp.yaml was removed")
	}
	if st := connectorStatus(t, app); st.ApprovedWrites || st.Enrollment != "retired" {
		t.Fatalf("status after mcp.yaml removal: %+v", st)
	}
	if err := connectorApply(t, app, "enable", true); err != nil {
		t.Fatalf("re-enable writes after mcp.yaml returned: %v", err)
	}
	if st := connectorStatus(t, app); st.Enrollment != "active" || !installed() {
		t.Fatalf("re-enrolled after mcp.yaml returned: %+v", st)
	}
	// A retirement interrupted after marking the record (ledger still
	// installed) leaves writes off, and enable --writes still repairs.
	_, release, lease, err := acquireAppMCPWritePolicy(ctx, app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	markErr := errors.Join(invalidateAppMCPWritesWithLease(lease), markAppMCPRevisionEnrollmentRetired(lease))
	release()
	if markErr != nil {
		t.Fatal(markErr)
	}
	if _, live := appMCPWritesLive(app); live || !installed() {
		t.Fatalf("interrupted retirement: writes live=%v installed=%v", live, installed())
	}
	if err := connectorApply(t, app, "enable", true); err != nil {
		t.Fatalf("enable --writes after an interrupted retirement: %v", err)
	}
	if st := connectorStatus(t, app); st.Enrollment != "active" || !st.ApprovedWrites {
		t.Fatalf("repaired after an interrupted retirement: %+v", st)
	}
}
