//go:build !cli && !windows

package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// approval: grant is a command-only policy; table.update keeps first-party
// review and every other value stays refused.
func TestAppMCPAutoApproveManifestPolicy(t *testing.T) {
	for _, approval := range []string{"first_party", "grant"} {
		manifest := commandManifest()
		manifest.Tools[0].Approval = approval
		if err := validateAppMCPManifestGated(manifest, true); err != nil {
			t.Fatalf("command approval %q refused: %v", approval, err)
		}
		if err := validateAppMCPCommandDeclaration(&manifest.Tools[0], &FlowCommand{}); err != nil && strings.Contains(err.Error(), "publicly dispatchable") {
			t.Fatalf("captured declaration refused approval %q: %v", approval, err)
		}
	}
	for _, approval := range []string{"none", "auto", "Grant", ""} {
		manifest := commandManifest()
		manifest.Tools[0].Approval = approval
		if err := validateAppMCPManifestGated(manifest, true); err == nil {
			t.Fatalf("command approval %q accepted", approval)
		}
	}
	if _, err := parseAppMCPManifest([]byte(strings.Replace(appMCPUpdateManifestFixture(), "approval: first_party", "approval: grant", 1))); err == nil {
		t.Fatal("table.update accepted approval: grant")
	}
}

// A transfer (push) command keeps per-write review: approval: grant is refused
// by the manifest and captured-declaration validators, never offered at
// consent and never eligible, so exported app data always has a human tick.
func TestAppMCPAutoApproveRefusesTransferTools(t *testing.T) {
	pushManifest := func(approval string) *AppMCPManifest {
		manifest := commandManifest()
		manifest.Connections = []AppMCPConnection{{Name: "files", BaseURL: "https://files.example.invalid/v1", Auth: AppMCPConnectionAuth{Kind: "none"}, OpenAPI: "openapi/transfers.yaml"}}
		manifest.Tools[0].Approval = approval
		manifest.Tools[0].Transfer = &AppMCPTransfer{Kind: "push", Connection: "files", OperationID: "pushFile", ArtifactIntentPath: "arguments.artifact_id",
			RequestContentField: "content_base64", RequestIdempotencyField: "idempotency_key", ReconcileOperationID: "findFileByKey", ReconcileParameter: "query.key", ResultIDField: "id", ResultChecksumField: "sha256"}
		return manifest
	}
	if err := validateAppMCPManifestGated(pushManifest("first_party"), true); err != nil {
		t.Fatalf("first_party push refused: %v", err)
	}
	if err := validateAppMCPManifestGated(pushManifest("grant"), true); err == nil || !strings.Contains(err.Error(), "unsupported private write policy") {
		t.Fatalf("grant push accepted: %v", err)
	}
	// The captured-declaration check, against a real complete command so only
	// the approval/transfer clause can decide.
	app := newGrantCommandFixture(t)
	captured, flow, err := appMCPFindCommandDeclaration(snapshotAppMCPGeneration(app), "complete_item")
	if err != nil {
		t.Fatal(err)
	}
	for _, approval := range []string{"first_party", "grant"} {
		declared := *captured
		declared.Approval, declared.Transfer = approval, &AppMCPTransfer{Kind: "push"}
		err := validateAppMCPCommandDeclaration(&declared, flow.Command)
		if refused := err != nil && strings.Contains(err.Error(), "publicly dispatchable"); refused != (approval == "grant") {
			t.Fatalf("captured push declaration with approval %q: %v", approval, err)
		}
	}
	tool := pushManifest("grant").Tools[0]
	cap := &appMCPCommandCapability{origin: appMCPCommandConnectorOrigin, originPin: &appMCPWriteAuthorityPin{AutoApproveEpoch: strings.Repeat("8", 64)},
		tool: &tool, autoApproveLive: true, autoApproveTools: []string{tool.Name}}
	if appMCPAutoApproveEligible(cap) {
		t.Fatal("push tool eligible for auto-approval")
	}
}

// writeAutoApproveStateFile stores a state exactly as the writer would
// serialize it, so a refusal is about the invariant, not the encoding.
func writeAutoApproveStateFile(t *testing.T, dir string, state appMCPEpochState) {
	t.Helper()
	root, key, err := appMCPAuthorityRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := root.WriteFile(key+".json", data, 0600); err != nil {
		t.Fatal(err)
	}
}

// The switch round-trips canonically, needs approved writes, and every path
// that turns writes off (or rotates them) ends it with a fresh epoch.
func TestAppMCPAutoApproveEpochLifecycle(t *testing.T) {
	epochFixture(t)
	app, cleanup := newTestApp(t)
	defer cleanup()
	ctx := context.Background()
	if _, err := updateAppMCPEpoch(app.Dir, true, false, true); err != nil {
		t.Fatal(err)
	}
	if _, err := setAppMCPAutoApproveContext(ctx, app.Dir, true); err == nil {
		t.Fatal("auto-approval turned on without approved writes")
	}
	enable := func() *appMCPEpochState {
		t.Helper()
		if _, err := setAppMCPApprovedWrites(app.Dir, true); err != nil {
			t.Fatal(err)
		}
		state, err := setAppMCPAutoApproveContext(ctx, app.Dir, true)
		if err != nil || !state.AutoApprove || !appMCPOperationHex(state.AutoApproveEpoch, 32) {
			t.Fatalf("enable auto-approval: %+v %v", state, err)
		}
		read, err := currentAppMCPEpoch(app.Dir)
		if err != nil || !read.AutoApprove || read.AutoApproveEpoch != state.AutoApproveEpoch {
			t.Fatalf("auto-approval did not round-trip: %+v %v", read, err)
		}
		return state
	}
	first := enable()
	again, err := setAppMCPAutoApproveContext(ctx, app.Dir, true)
	if err != nil || again.AutoApproveEpoch == first.AutoApproveEpoch {
		t.Fatalf("re-enabling auto-approval kept its epoch: %+v %v", again, err)
	}
	cleared := func(name string, before *appMCPEpochState) {
		t.Helper()
		state, err := currentAppMCPEpoch(app.Dir)
		if err != nil || state.AutoApprove || state.AutoApproveEpoch == before.AutoApproveEpoch || !appMCPOperationHex(state.AutoApproveEpoch, 32) {
			t.Fatalf("%s left auto-approval live: %+v %v", name, state, err)
		}
	}
	before := enable()
	if _, err := setAppMCPAutoApproveContext(ctx, app.Dir, false); err != nil {
		t.Fatal(err)
	}
	cleared("disable --auto-approve", before)
	if state, _ := currentAppMCPEpoch(app.Dir); state.ApprovedWrites == nil || !*state.ApprovedWrites {
		t.Fatal("disable --auto-approve turned writes off")
	}
	before = enable()
	if _, err := setAppMCPApprovedWrites(app.Dir, false); err != nil {
		t.Fatal(err)
	}
	cleared("disable --writes", before)
	before = enable()
	release, lease, err := beginAppMCPPolicyChange(ctx, app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	err = invalidateAppMCPWritesWithLease(lease)
	release()
	if err != nil {
		t.Fatal(err)
	}
	cleared("write invalidation", before)
	before = enable()
	if _, err := updateAppMCPEpoch(app.Dir, true, true, false); err != nil {
		t.Fatal(err)
	}
	cleared("epoch rotation", before)
	before = enable()
	if _, err := updateAppMCPEpoch(app.Dir, false, false, false); err != nil {
		t.Fatal(err)
	}
	cleared("disable", before)
	if _, err := updateAppMCPEpoch(app.Dir, true, false, false); err != nil {
		t.Fatal(err)
	}
	before = enable()
	if err := invalidateAppMCPForRestore(app.Dir); err != nil {
		t.Fatal(err)
	}
	cleared("restore", before)

	// Hand-written states that break the invariants are refused.
	if _, err := updateAppMCPEpoch(app.Dir, true, false, false); err != nil {
		t.Fatal(err)
	}
	enable()
	valid, err := currentAppMCPEpoch(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	off := false
	for name, mutate := range map[string]func(*appMCPEpochState){
		"on without epoch":     func(s *appMCPEpochState) { s.AutoApproveEpoch = "" },
		"on with short epoch":  func(s *appMCPEpochState) { s.AutoApproveEpoch = "ab" },
		"on with writes off":   func(s *appMCPEpochState) { s.ApprovedWrites = &off },
		"on while not exposed": func(s *appMCPEpochState) { s.Exposed = false },
		"on in version 1":      func(s *appMCPEpochState) { s.Version, s.ApprovedWrites, s.ApprovedWriteEpoch = 1, nil, "" },
	} {
		state := *valid
		mutate(&state)
		writeAutoApproveStateFile(t, app.Dir, state)
		if _, err := currentAppMCPEpoch(app.Dir); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	writeAutoApproveStateFile(t, app.Dir, *valid)
	if state, err := currentAppMCPEpoch(app.Dir); err != nil || !state.AutoApprove {
		t.Fatalf("valid state refused: %v", err)
	}
}

func newGrantCommandFixture(t *testing.T) *App {
	t.Helper()
	app, _, _ := newUnenrolledCommandProviderTaskFixtureWithManifest(t, commandTaskFlowFixture, "", func(m *AppMCPManifest, _ string) {
		m.Tools[0].Approval = "grant"
	})
	return app
}

func TestAppMCPAutoApproveConnectorControl(t *testing.T) {
	ctx := context.Background()
	apply := func(app *App, req appMCPConnectorRequest) error { return appMCPConnectorApply(ctx, app, req) }

	// A manifest without approval: grant tools refuses before any switch moves.
	firstParty, _, _ := newUnenrolledCommandProviderTaskFixture(t, commandTaskFlowFixture, "")
	if err := apply(firstParty, appMCPConnectorRequest{Action: "enable", Writes: true, AutoApprove: true}); err == nil || !strings.Contains(err.Error(), "approval: grant") {
		t.Fatalf("auto-approve without grant tools: %v", err)
	}
	if st := connectorStatus(t, firstParty); st.Exposed || st.ApprovedWrites || st.AutoApprove || st.GrantApprovalTools != 0 {
		t.Fatalf("refused enable changed a switch: %+v", st)
	}

	app := newGrantCommandFixture(t)
	if err := apply(app, appMCPConnectorRequest{Action: "enable", AutoApprove: true}); err == nil {
		t.Fatal("auto-approve accepted without writes")
	}
	if err := apply(app, appMCPConnectorRequest{Action: "disable", Revoke: true, AutoApprove: true}); err == nil {
		t.Fatal("revoke accepted with auto-approve")
	}
	if err := apply(app, appMCPConnectorRequest{Action: "enable", Writes: true, AutoApprove: true}); err != nil {
		t.Fatal(err)
	}
	st := connectorStatus(t, app)
	first, _ := currentAppMCPEpoch(app.Dir)
	if !st.Exposed || !st.ApprovedWrites || !st.AutoApprove || st.GrantApprovalTools != 1 || !first.AutoApprove {
		t.Fatalf("enable --writes --auto-approve: %+v", st)
	}
	// Re-enabling with writes already on still mints a fresh epoch.
	if err := apply(app, appMCPConnectorRequest{Action: "enable", Writes: true, AutoApprove: true}); err != nil {
		t.Fatal(err)
	}
	if again, _ := currentAppMCPEpoch(app.Dir); !again.AutoApprove || again.AutoApproveEpoch == first.AutoApproveEpoch || again.ApprovedWriteEpoch != first.ApprovedWriteEpoch {
		t.Fatalf("re-enable epochs: %+v vs %+v", again, first)
	}
	// enable --writes without the flag leaves the switch as it is.
	if err := apply(app, appMCPConnectorRequest{Action: "enable", Writes: true}); err != nil {
		t.Fatal(err)
	}
	if st = connectorStatus(t, app); !st.AutoApprove {
		t.Fatalf("plain enable --writes changed auto-approve: %+v", st)
	}
	if err := apply(app, appMCPConnectorRequest{Action: "disable", AutoApprove: true}); err != nil {
		t.Fatal(err)
	}
	if st = connectorStatus(t, app); st.AutoApprove || !st.ApprovedWrites || !st.Exposed {
		t.Fatalf("disable --auto-approve: %+v", st)
	}
	for _, off := range []appMCPConnectorRequest{{Action: "disable", Writes: true}, {Action: "disable"}, {Action: "disable", Writes: true, AutoApprove: true}} {
		if err := apply(app, appMCPConnectorRequest{Action: "enable", Writes: true, AutoApprove: true}); err != nil {
			t.Fatal(err)
		}
		if err := apply(app, off); err != nil {
			t.Fatalf("%+v: %v", off, err)
		}
		if st = connectorStatus(t, app); st.AutoApprove || st.ApprovedWrites {
			t.Fatalf("%+v left auto-approve or writes on: %+v", off, st)
		}
	}
}

func TestAppMCPAutoApproveControlTokenBinding(t *testing.T) {
	plain := appMCPConnectorRequest{Action: "enable", Writes: true}
	auto := appMCPConnectorRequest{Action: "enable", Writes: true, AutoApprove: true}
	if plain.binding() != "enable:1:0:0:0" || auto.binding() != "enable:1:0:0:0:1" {
		t.Fatalf("bindings: %q %q", plain.binding(), auto.binding())
	}
	app, mux := connectorRouteFixture(t)
	// A token minted for --writes alone cannot be replayed to add auto-approve.
	if code, _ := connectorPost(mux, connectorToken(app, plain), `{"action":"enable","writes":true,"auto_approve":true}`); code != 403 {
		t.Fatalf("writes token replayed for auto-approve: %d", code)
	}
	if code, _ := connectorPost(mux, connectorToken(app, appMCPConnectorRequest{Action: "status", AutoApprove: true}), `{"action":"status","auto_approve":true}`); code != 400 {
		t.Fatalf("status with auto-approve flag: %d", code)
	}
}

// grantConsentFixture is a grant-approval command app with writes and
// auto-approval on, a registered client that may request tasks:write, and a
// direct browser session of the task actor.
type grantConsentFixture struct {
	app      *App
	sid      string
	session  *Session
	values   url.Values
	verifier string
}

func newGrantConsentFixture(t *testing.T) *grantConsentFixture {
	t.Helper()
	app := newGrantCommandFixture(t)
	if err := appMCPConnectorApply(context.Background(), app, appMCPConnectorRequest{Action: "enable", Writes: true, AutoApprove: true}); err != nil {
		t.Fatal(err)
	}
	appOAuthEnsureTables(app)
	if _, err := app.DB.Exec("INSERT INTO _benmore_oauth_clients(client_id,name,redirect_uris,scopes) VALUES ('client-fixture','Reviewed client',?,'tasks:write')", `["`+mcpOAuthFixtureRedirect+`"]`); err != nil {
		t.Fatal(err)
	}
	var userID int64
	if err := app.DB.QueryRow("SELECT id FROM _benmore_users WHERE email='task-actor@example.com'").Scan(&userID); err != nil {
		t.Fatal(err)
	}
	sid := CreateSession(app.DB, userID, "task-actor@example.com", "17", time.Hour)
	verifier := strings.Repeat("v", 43)
	values := url.Values{"response_type": {"code"}, "client_id": {"client-fixture"}, "redirect_uri": {mcpOAuthFixtureRedirect}, "state": {"client-state"}, "scope": {"tasks:write"}, "code_challenge": {oauthPKCEChallenge(verifier)}, "code_challenge_method": {"S256"}, "resource": {grantFixtureResource}}
	return &grantConsentFixture{app: app, sid: sid, session: GetSessionFromDB(app.DB, sid), values: values, verifier: verifier}
}

// connect runs consent with the box ticked or not and returns the stored list.
func (f *grantConsentFixture) connect(t *testing.T, tick bool, between func()) (string, *appMCPOAuthConsent) {
	t.Helper()
	ctx, now := context.Background(), time.Now()
	consent, err := prepareAppMCPOAuthConsentFor(ctx, f.app, f.session, f.values, grantFixtureResource, "17", now)
	if err != nil {
		t.Fatal(err)
	}
	if between != nil {
		between()
	}
	code, err := approveAppMCPOAuthConsentFor(ctx, f.app, f.session, f.values, grantFixtureResource, "17", consent.Nonce, consent.Token, now, tick)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := exchangeAppMCPOAuthCodeFor(ctx, f.app, code, "client-fixture", mcpOAuthFixtureRedirect, grantFixtureResource, f.verifier, grantFixtureResource, now)
	if err != nil {
		t.Fatal(err)
	}
	var list string
	if err := f.app.DB.QueryRow("SELECT auto_approve FROM _benmore_mcp_grants WHERE id=?", pair.GrantID).Scan(&list); err != nil {
		t.Fatal(err)
	}
	return list, consent
}

func TestAppMCPAutoApproveConsent(t *testing.T) {
	f := newGrantConsentFixture(t)
	ctx := context.Background()
	m := snapshotAppMCPGeneration(f.app).manifest
	entry := appMCPAutoApproveEntry("complete_item", m.ContractDigest, m.ExecutionDigest)
	if list, consent := f.connect(t, true, nil); list != entry || !slices.Equal(consent.AutoApprove, []string{"complete_item"}) {
		t.Fatalf("ticked: %q offer=%v", list, consent.AutoApprove)
	}
	if list, _ := f.connect(t, false, nil); list != "" {
		t.Fatalf("unticked stored %q", list)
	}
	// The switch turned off between page and approval: the tick no longer counts.
	off := func() {
		if err := appMCPConnectorApply(ctx, f.app, appMCPConnectorRequest{Action: "disable", AutoApprove: true}); err != nil {
			t.Fatal(err)
		}
	}
	if list, _ := f.connect(t, true, off); list != "" {
		t.Fatalf("switch off still stored %q", list)
	}
	// Widening: a page rendered while nothing was offered cannot gain a tool
	// when the owner turns the switch on before the person approves.
	on := func() {
		if err := appMCPConnectorApply(ctx, f.app, appMCPConnectorRequest{Action: "enable", Writes: true, AutoApprove: true}); err != nil {
			t.Fatal(err)
		}
	}
	if list, consent := f.connect(t, true, on); list != "" || len(consent.AutoApprove) != 0 {
		t.Fatalf("widened to %q (offer %v)", list, consent.AutoApprove)
	}
	// The owner cycled the switch off and on between page and approval: the
	// page's consent was for the old epoch, so nothing is stored.
	cycle := func() { off(); on() }
	if list, consent := f.connect(t, true, cycle); list != "" || len(consent.AutoApprove) != 1 {
		t.Fatalf("consent survived an off/on cycle: %q (offer %v)", list, consent.AutoApprove)
	}
	// A refresh keeps the list as it is.
	list, _ := f.connect(t, true, nil)
	if list != entry {
		t.Fatalf("ticked again: %q", list)
	}
	// An account whose role lacks the permission is never offered the tool.
	if offer, _ := appMCPAutoApproveOffer(f.app, snapshotAppMCPGeneration(f.app), "tasks:read"); len(offer) != 0 {
		t.Fatalf("offer beyond scopes: %v", offer)
	}

	// The page renders an unticked box naming the tool, and only when offered.
	page := func() string {
		values := url.Values{}
		for k, v := range f.values {
			values[k] = v
		}
		values.Set("workspace", "17")
		r := httptest.NewRequest(http.MethodGet, "https://fixture.example/oauth/authorize?"+values.Encode(), nil)
		r.AddCookie(sessionCookie(f.sid, false, time.Hour))
		w := httptest.NewRecorder()
		appMCPOAuthAuthorize(w, r, f.app, grantFixtureResource)
		if w.Code != http.StatusOK {
			t.Fatalf("consent page: %d %s", w.Code, w.Body.String())
		}
		return w.Body.String()
	}
	if body := page(); !strings.Contains(body, `<input type="checkbox" name="auto_approve" value="1">`) || !strings.Contains(body, "complete_item") || strings.Contains(body, "checked") || strings.Contains(body, "<script") {
		t.Fatalf("consent page checkbox: %s", body)
	}
	off()
	if body := page(); strings.Contains(body, "auto_approve") {
		t.Fatal("checkbox shown with the switch off")
	}
	on()

	// The decision accepts no box or exactly one "1"; anything else is refused
	// before the consent is consumed.
	consent, err := prepareAppMCPOAuthConsentFor(ctx, f.app, f.session, f.values, grantFixtureResource, "17", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	decide := func(box []string) *httptest.ResponseRecorder {
		form := url.Values{}
		for k, v := range f.values {
			form[k] = v
		}
		form.Set("workspace", "17")
		form.Set("connector_nonce", consent.Nonce)
		form.Set("consent", consent.Token)
		form.Set("decision", "approve")
		if box != nil {
			form["auto_approve"] = box
		}
		r := httptest.NewRequest(http.MethodPost, "https://fixture.example/oauth/authorize", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		r.AddCookie(sessionCookie(f.sid, false, time.Hour))
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		appMCPOAuthDecision(w, r, f.app, grantFixtureResource)
		return w
	}
	for _, box := range [][]string{{"2"}, {"1", "1"}, {""}, {"true"}} {
		if w := decide(box); w.Code != http.StatusForbidden {
			t.Fatalf("box %q: %d", box, w.Code)
		}
	}
	if w := decide([]string{"1"}); w.Code != http.StatusFound || !strings.Contains(w.Header().Get("Location"), "code=bmcc_") {
		t.Fatalf("ticked decision: %d %s", w.Code, w.Header().Get("Location"))
	}
}

// A grants table created before auto-approval gains its column, and existing
// grants keep an empty list.
func TestAppMCPAutoApproveGrantColumnMigration(t *testing.T) {
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "old.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, statement := range []string{
		"CREATE TABLE _benmore_users (id INTEGER PRIMARY KEY)",
		`CREATE TABLE _benmore_mcp_grants (
   id TEXT PRIMARY KEY, app TEXT NOT NULL, user_id INTEGER NOT NULL REFERENCES _benmore_users(id) ON DELETE CASCADE,
   user_created TEXT NOT NULL, tenant TEXT NOT NULL, client TEXT NOT NULL, resource TEXT NOT NULL,
   epoch TEXT NOT NULL, scopes TEXT NOT NULL, expires_at INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1)))`,
		"INSERT INTO _benmore_users(id) VALUES (1)",
		"INSERT INTO _benmore_mcp_grants(id,app,user_id,user_created,tenant,client,resource,epoch,scopes,expires_at) VALUES ('g','a',1,'c','','x','r','e','s',1)",
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 2; i++ { // idempotent
		if err := ensureAppMCPGrantTables(db); err != nil {
			t.Fatal(err)
		}
	}
	var list, epoch string
	if err := db.QueryRow("SELECT auto_approve, auto_approve_epoch FROM _benmore_mcp_grants WHERE id='g'").Scan(&list, &epoch); err != nil || list != "" || epoch != "" {
		t.Fatalf("migrated grant: %q %q %v", list, epoch, err)
	}
}

// grantApprovalFixture stores one operation prepared by a hex grant id and a
// grant-domain approval for it, the shape appMCPPrepareOperation writes.
func grantApprovalFixture(t *testing.T) (*App, []byte, string, *appMCPStoredOperation, appMCPCommandApprovalRecord) {
	t.Helper()
	app, key := appMCPOperationStoreFixture(t)
	appID, err := appMCPOperationOwnerID(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	operationID := strings.Repeat("1", 64)
	prepared := appMCPOperationStoreRecord(app, operationID)
	prepared.Origin.GrantID = strings.Repeat("9", 64)
	prepared.CreatedAt = time.Now().Unix() - 60
	prepared.ExpiresAt = prepared.CreatedAt + 15*60
	ctx := context.Background()
	tx, err := app.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := initializeAppMCPCommandApprovalStorage(ctx, tx); err != nil {
		t.Fatal(err)
	}
	if err := initializeAppMCPCommandAttemptStorage(ctx, tx); err != nil {
		t.Fatal(err)
	}
	if _, err := initializeAppEncryptionState(ctx, tx, appID, key); err != nil {
		t.Fatal(err)
	}
	operation, err := appMCPInsertOperationTest(t, ctx, tx, app, prepared)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	epoch := strings.Repeat("8", 64)
	record := appMCPCommandApprovalRecord{
		Version: 1, Domain: appMCPGrantApprovalDomain, ApprovalID: strings.Repeat("2", 64),
		AppID: appID, OperationID: operationID, PreparedDigest: operation.PreparedDigest,
		DisclosureVersion: prepared.DisclosureVersion, OwnerEpoch: prepared.RuntimeAuthority.OwnerEpoch,
		WriteEpoch: prepared.RuntimeAuthority.WriteEpoch, ApproverUserID: prepared.Origin.ActorID,
		ApproverCreated: prepared.Origin.ActorCreated, Tenant: prepared.Origin.Tenant,
		ApprovedAt: prepared.CreatedAt, ExpiresAt: prepared.ExpiresAt,
		ReviewChallengeDigest: appMCPGrantApprovalChallenge(operation.PreparedDigest, prepared.Origin.GrantID, epoch),
		Basis:                 appMCPGrantConsentBasis + prepared.Origin.GrantID, AutoApproveEpoch: epoch,
	}
	return app, key, appID, operation, record
}

func TestAppMCPAutoApproveApprovalRecordDomains(t *testing.T) {
	app, key, appID, operation, grant := grantApprovalFixture(t)
	if err := appMCPValidateCommandApprovalRecord(grant, operation, appID); err != nil {
		t.Fatalf("grant-domain record refused: %v", err)
	}
	human := grant
	human.Domain, human.ApproverSessionID, human.Basis, human.AutoApproveEpoch = appMCPHumanApprovalDomain, sessionKeyPrefix+strings.Repeat("3", 64), "", ""
	human.ReviewChallengeDigest = strings.Repeat("4", 64)
	if err := appMCPValidateCommandApprovalRecord(human, operation, appID); err != nil {
		t.Fatalf("human record refused: %v", err)
	}
	// Human approvals keep their exact pre-existing encoding.
	encoded, _, err := appMCPEncodeCommandApproval(human)
	if err != nil || strings.Contains(string(encoded), "basis") || strings.Contains(string(encoded), "auto_approve") {
		t.Fatalf("human record encoding changed: %s %v", encoded, err)
	}
	for name, mutate := range map[string]func(*appMCPCommandApprovalRecord){
		"grant with a session":       func(r *appMCPCommandApprovalRecord) { r.ApproverSessionID = human.ApproverSessionID },
		"grant without basis":        func(r *appMCPCommandApprovalRecord) { r.Basis = "" },
		"grant basis of other grant": func(r *appMCPCommandApprovalRecord) { r.Basis = appMCPGrantConsentBasis + strings.Repeat("7", 64) },
		"grant basis other kind":     func(r *appMCPCommandApprovalRecord) { r.Basis = "human" },
		"grant without epoch":        func(r *appMCPCommandApprovalRecord) { r.AutoApproveEpoch = "" },
		"grant with short epoch":     func(r *appMCPCommandApprovalRecord) { r.AutoApproveEpoch = "ab" },
		"grant epoch not challenged": func(r *appMCPCommandApprovalRecord) { r.AutoApproveEpoch = strings.Repeat("6", 64) },
		"grant random challenge":     func(r *appMCPCommandApprovalRecord) { r.ReviewChallengeDigest = strings.Repeat("4", 64) },
		"grant other approver":       func(r *appMCPCommandApprovalRecord) { r.ApproverUserID++ },
		"grant other tenant":         func(r *appMCPCommandApprovalRecord) { r.Tenant = "18" },
		"unknown domain":             func(r *appMCPCommandApprovalRecord) { r.Domain = "benmore:mcp:grant-approval:v2" },
		"human domain on grant shape": func(r *appMCPCommandApprovalRecord) {
			r.Domain = appMCPHumanApprovalDomain
		},
	} {
		record := grant
		mutate(&record)
		if err := appMCPValidateCommandApprovalRecord(record, operation, appID); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	for name, mutate := range map[string]func(*appMCPCommandApprovalRecord){
		"human with basis":   func(r *appMCPCommandApprovalRecord) { r.Basis = grant.Basis },
		"human with epoch":   func(r *appMCPCommandApprovalRecord) { r.AutoApproveEpoch = grant.AutoApproveEpoch },
		"human with session": func(r *appMCPCommandApprovalRecord) { r.ApproverSessionID = "" },
	} {
		record := human
		mutate(&record)
		if err := appMCPValidateCommandApprovalRecord(record, operation, appID); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}

	// Stored through the only writer, it authenticates in the union and is
	// resealed unchanged by key rotation.
	ctx := context.Background()
	tx, err := app.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	state, err := insertAppMCPCommandApproval(ctx, tx, app, operation, grant)
	if err != nil || state.Approval != grant {
		t.Fatalf("insert grant approval: %+v %v", state, err)
	}
	if _, approvals, err := appMCPValidateCommandStoreUnion(ctx, tx, appID, key); err != nil || approvals[operation.Prepared.OperationID].Approval.Domain != appMCPGrantApprovalDomain {
		t.Fatalf("union: %v", err)
	}
	newKey, err := cryptoDeriveAppKey(strings.Repeat("57", 32))
	if err != nil {
		t.Fatal(err)
	}
	if n, err := rotateAppMCPCommandApprovalsTx(ctx, tx, appID, key, newKey); err != nil || n != 1 {
		t.Fatalf("reseal: %d %v", n, err)
	}
	rows, err := appMCPReadCommandApprovalRows(ctx, tx)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows: %v", err)
	}
	plain, err := appMCPOpenCommandApproval(newKey, rows[0].ciphertext)
	if err != nil || !bytes.Equal(plain, state.Plaintext) {
		t.Fatalf("resealed grant approval changed: %v", err)
	}
	if resealed, err := appMCPDecodeCommandApproval(plain, operation, appID); err != nil || resealed.Approval != grant {
		t.Fatalf("resealed grant approval: %v", err)
	}
}

// newGrantExposureHarness is the exposure harness on a manifest whose command
// declares approval (grant or first_party), with writes and the owner
// auto-approve switch on, and the connector grant's consented list set to list.
func newGrantExposureHarness(t *testing.T, approval, list string) *exposureHarness {
	t.Helper()
	return newGrantExposureHarnessWith(t, hookTaskFlow, func(m *AppMCPManifest) { m.Tools[0].Approval = approval }, list)
}

// newGrantExposureHarnessWith is newGrantExposureHarness on a chosen flow and
// manifest edit.
func newGrantExposureHarnessWith(t *testing.T, flow string, configure func(*AppMCPManifest), list string) *exposureHarness {
	t.Helper()
	app, _, actorID := newUnenrolledCommandProviderTaskFixtureWithManifest(t, flow, "", func(m *AppMCPManifest, _ string) {
		configure(m)
	})
	ensureCommandAuditFixture(t, app)
	if _, err := updateAppMCPEpoch(app.Dir, true, false, true); err != nil {
		t.Fatal(err)
	}
	generation := snapshotAppMCPGeneration(app)
	if _, err := initializeAppMCPRevisionEnrollment(context.Background(), app, generation); err != nil {
		t.Fatal(err)
	}
	if _, err := enableAppMCPRevisionEnrolledWrites(context.Background(), app, generation); err != nil {
		t.Fatal(err)
	}
	if _, err := setAppMCPAutoApproveContext(context.Background(), app.Dir, true); err != nil {
		t.Fatal(err)
	}
	h := &exposureHarness{t: t, app: app, actorID: actorID}
	mux := http.NewServeMux()
	h.server = httptest.NewTLSServer(mux)
	t.Cleanup(h.server.Close)
	h.resource = h.server.URL + "/api/_mcp"
	registerAppMCPTransport(mux, app, h.resource)
	h.browser = &http.Client{Transport: h.server.Client().Transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var err error
	if h.pair, err = createAppMCPNativeGrantFor(context.Background(), app, actorID, "17", "client-b2", h.resource, "complete_item", time.Now()); err != nil {
		t.Fatalf("grant: %v", err)
	}
	h.consent(list)
	h.cookie = CreateSession(app.DB, actorID, "task-actor@example.com", "17", time.Hour)
	h.client = appMCPClient(t, h.server, h.pair.AccessToken, nil)
	return h
}

// consent stores names as a ticked consent under the current owner epoch and
// manifest digest would.
func (h *exposureHarness) consent(names string) {
	h.t.Helper()
	state, err := currentAppMCPEpoch(h.app.Dir)
	if err != nil {
		h.t.Fatal(err)
	}
	manifest := snapshotAppMCPGeneration(h.app).manifest
	var entries []string
	for _, name := range strings.Fields(names) {
		entries = append(entries, appMCPAutoApproveEntry(name, manifest.ContractDigest, manifest.ExecutionDigest))
	}
	if _, err := h.app.DB.Exec("UPDATE _benmore_mcp_grants SET auto_approve=?, auto_approve_epoch=? WHERE id=?", strings.Join(entries, " "), state.AutoApproveEpoch, h.pair.GrantID); err != nil {
		h.t.Fatal(err)
	}
}

// connectorRequest builds the request a fresh connector call would: the
// origin pin is read from the current owner state and grant row.
func (h *exposureHarness) connectorRequest() (appMCPCommandRequest, error) {
	generation := snapshotAppMCPGeneration(h.app)
	grant, err := readAppMCPGrant(h.app.DB, h.pair.GrantID)
	if err != nil {
		return appMCPCommandRequest{}, err
	}
	tool, _, err := appMCPFindCommandDeclaration(generation, "complete_item")
	if err != nil {
		return appMCPCommandRequest{}, err
	}
	origin, err := appMCPConnectorOrigin(h.app, generation, grant, tool, h.pair.AccessToken, h.resource)
	return appMCPCommandRequest{app: h.app, generation: generation, toolName: "complete_item", origin: origin}, err
}

func (h *exposureHarness) countApprovals(domain string) int {
	h.t.Helper()
	tx, err := h.app.DB.Begin()
	if err != nil {
		h.t.Fatal(err)
	}
	defer tx.Rollback()
	appID, key, err := appMCPReadyOperationStorage(context.Background(), tx, h.app)
	if err != nil {
		h.t.Fatal(err)
	}
	_, approvals, err := appMCPValidateCommandStoreUnion(context.Background(), tx, appID, key)
	if err != nil {
		h.t.Fatal(err)
	}
	n := 0
	for _, approval := range approvals {
		if approval.Approval.Domain == domain {
			n++
		}
	}
	return n
}

func TestAppMCPAutoApproveAppliesInOneCall(t *testing.T) {
	h := newGrantExposureHarness(t, "grant", "complete_item")
	out, code := h.call(h.client, "complete_item", map[string]any{"arguments": map[string]any{"id": 1, "project_id": 7}})
	if code != "" || out["outcome"] != "applied" || out["review_url"] != nil {
		t.Fatalf("one-call apply: %q %#v", code, out)
	}
	id, _ := out["operation_id"].(string)
	receipt, _ := out["receipt"].(map[string]any)
	if !appMCPIsHex(id, 32) || receipt["operation_id"] != id || receipt["approval_basis"] != appMCPGrantConsentBasis+h.pair.GrantID {
		t.Fatalf("receipt: %#v", receipt)
	}
	if !h.taskDone() || h.count("SELECT count(*) FROM activities WHERE task_id=1") != 1 {
		t.Fatal("business rows were not written exactly once")
	}
	if h.countApprovals(appMCPGrantApprovalDomain) != 1 || h.countApprovals(appMCPHumanApprovalDomain) != 0 {
		t.Fatal("approval is not the grant domain")
	}
	for _, action := range []string{"mcp_command_prepare", "mcp_command_approve", "mcp_command_commit"} {
		if h.count("SELECT count(*) FROM _benmore_audit_log WHERE action=? AND row_id=?", action, id) != 1 {
			t.Fatalf("audit row %s missing", action)
		}
	}
	var approveAudit string
	if err := h.app.DB.QueryRow("SELECT new_values FROM _benmore_audit_log WHERE action='mcp_command_approve' AND row_id=?", id).Scan(&approveAudit); err != nil || !strings.Contains(approveAudit, `"basis":"grant_consent:`+h.pair.GrantID+`"`) {
		t.Fatalf("approve audit: %s %v", approveAudit, err)
	}
	again, code := h.call(h.client, appMCPCommitTool, map[string]any{"operation_id": id})
	if code != "" || again["outcome"] != "already_applied" || !reflect.DeepEqual(again["receipt"], receipt) {
		t.Fatalf("repeat: %q %#v", code, again)
	}
	if status := h.status(id); status["state"] != "succeeded" || !reflect.DeepEqual(status["receipt"], receipt) {
		t.Fatalf("status: %#v", status)
	}
	if h.count("SELECT count(*) FROM activities WHERE task_id=1") != 1 {
		t.Fatal("repeat re-applied")
	}
}

// The user's consent is bound to the owner epoch and the reviewed manifest it
// was given under. An owner off/on cycle, a manifest change, or a grant from
// before the binding (bare names, no epoch) each send a fresh prepare back to
// per-write review until the user consents again.
func TestAppMCPAutoApproveConsentBinding(t *testing.T) {
	input, _ := appMCPDecodeToolArguments(json.RawMessage(`{"arguments":{"id":1,"project_id":7}}`))
	prepared := func(t *testing.T, h *exposureHarness) bool {
		t.Helper()
		req, err := h.connectorRequest()
		if err != nil {
			t.Fatal(err)
		}
		view, err := appMCPPrepareOperation(context.Background(), req, input)
		if err != nil {
			t.Fatalf("prepare: %v", err)
		}
		return view.AutoApproved
	}
	t.Run("owner off/on cycle needs reconsent", func(t *testing.T) {
		h := newGrantExposureHarness(t, "grant", "complete_item")
		for _, on := range []bool{false, true} {
			if _, err := setAppMCPAutoApproveContext(context.Background(), h.app.Dir, on); err != nil {
				t.Fatal(err)
			}
		}
		if prepared(t, h) {
			t.Fatal("consent from before the off/on cycle auto-approved")
		}
		h.consent("complete_item") // the user ticks it again under the new epoch
		if !prepared(t, h) {
			t.Fatal("reconsent did not auto-approve")
		}
	})
	t.Run("manifest change needs reconsent", func(t *testing.T) {
		h := newGrantExposureHarness(t, "grant", "complete_item")
		if _, err := h.app.DB.Exec("UPDATE _benmore_mcp_grants SET auto_approve=? WHERE id=?", appMCPAutoApproveEntry("complete_item", strings.Repeat("e", 64), strings.Repeat("e", 64)), h.pair.GrantID); err != nil {
			t.Fatal(err)
		}
		if prepared(t, h) {
			t.Fatal("consent for another manifest digest auto-approved")
		}
	})
	t.Run("pre-binding grant never auto-approves", func(t *testing.T) {
		h := newGrantExposureHarness(t, "grant", "complete_item")
		if _, err := h.app.DB.Exec("UPDATE _benmore_mcp_grants SET auto_approve='complete_item', auto_approve_epoch='' WHERE id=?", h.pair.GrantID); err != nil {
			t.Fatal(err)
		}
		if prepared(t, h) {
			t.Fatal("bare-name grant auto-approved")
		}
		h.consent("complete_item")
		if _, err := h.app.DB.Exec("UPDATE _benmore_mcp_grants SET auto_approve_epoch='' WHERE id=?", h.pair.GrantID); err != nil {
			t.Fatal(err)
		}
		if prepared(t, h) {
			t.Fatal("grant without a consent epoch auto-approved")
		}
	})
}

func TestAppMCPAutoApproveNeedsAllThreeOptIns(t *testing.T) {
	prepareOnly := func(t *testing.T, h *exposureHarness) {
		t.Helper()
		id := h.prepare() // asserts the prepare shape and review_url
		if h.taskDone() || h.count("SELECT count(*) FROM _benmore_mcp_command_approvals") != 0 {
			t.Fatal("operation was approved or applied without every opt-in")
		}
		h.approveOK(id) // the human path still works
		if out, code := h.call(h.client, appMCPCommitTool, map[string]any{"operation_id": id}); code != "" || out["outcome"] != "applied" || out["receipt"].(map[string]any)["approval_basis"] != "human" {
			t.Fatalf("human commit: %q %#v", code, out)
		}
	}
	t.Run("owner switch off", func(t *testing.T) {
		h := newGrantExposureHarness(t, "grant", "complete_item")
		if err := appMCPConnectorApply(context.Background(), h.app, appMCPConnectorRequest{Action: "disable", AutoApprove: true}); err != nil {
			t.Fatal(err)
		}
		prepareOnly(t, h)
	})
	t.Run("tool not consented", func(t *testing.T) {
		prepareOnly(t, newGrantExposureHarness(t, "grant", "other_tool"))
	})
	t.Run("declared first_party", func(t *testing.T) {
		prepareOnly(t, newGrantExposureHarness(t, "first_party", "complete_item"))
	})
}

// A grant-domain approval that has not committed yet is re-checked by every
// retried _commit.
func TestAppMCPAutoApproveRetriedCommitIsRechecked(t *testing.T) {
	input, _ := appMCPDecodeToolArguments(json.RawMessage(`{"arguments":{"id":1,"project_id":7}}`))
	cases := map[string]func(t *testing.T, h *exposureHarness){
		"grant revoked": func(t *testing.T, h *exposureHarness) {
			if err := revokeAppMCPGrant(h.app, h.pair.GrantID); err != nil {
				t.Fatal(err)
			}
		},
		"disable --auto-approve": func(t *testing.T, h *exposureHarness) {
			if err := appMCPConnectorApply(context.Background(), h.app, appMCPConnectorRequest{Action: "disable", AutoApprove: true}); err != nil {
				t.Fatal(err)
			}
		},
		"re-enabled auto-approve": func(t *testing.T, h *exposureHarness) {
			if _, err := setAppMCPAutoApproveContext(context.Background(), h.app.Dir, false); err != nil {
				t.Fatal(err)
			}
			if _, err := setAppMCPAutoApproveContext(context.Background(), h.app.Dir, true); err != nil {
				t.Fatal(err)
			}
		},
		"tool removed from the grant": func(t *testing.T, h *exposureHarness) {
			if _, err := h.app.DB.Exec("UPDATE _benmore_mcp_grants SET auto_approve='' WHERE id=?", h.pair.GrantID); err != nil {
				t.Fatal(err)
			}
		},
		"role downgraded": func(t *testing.T, h *exposureHarness) {
			if _, err := h.app.DB.Exec("UPDATE _benmore_users SET role='viewer' WHERE id=?", h.actorID); err != nil {
				t.Fatal(err)
			}
			if _, err := h.app.DB.Exec("DELETE FROM _benmore_user_roles WHERE user_id=?", h.actorID); err != nil {
				t.Fatal(err)
			}
		},
		"disable --writes": func(t *testing.T, h *exposureHarness) {
			if err := appMCPConnectorApply(context.Background(), h.app, appMCPConnectorRequest{Action: "disable", Writes: true}); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			h := newGrantExposureHarness(t, "grant", "complete_item")
			req, err := h.connectorRequest()
			if err != nil {
				t.Fatal(err)
			}
			view, err := appMCPPrepareOperation(context.Background(), req, input)
			if err != nil || !view.AutoApproved {
				t.Fatalf("prepare: %+v %v", view, err)
			}
			change(t, h)
			if req, err = h.connectorRequest(); err == nil {
				_, err = appMCPCommitOperation(context.Background(), req, view.ID)
			}
			if err == nil {
				t.Fatal("retried commit applied")
			}
			if class := appMCPCommandErrorClass(err); class != "denied" && class != "expired_intent" {
				t.Fatalf("retried commit class %q: %v", class, err)
			}
			if h.taskDone() {
				t.Fatal("business row changed")
			}
		})
	}
	// Control: with nothing changed the same retry applies.
	h := newGrantExposureHarness(t, "grant", "complete_item")
	req, _ := h.connectorRequest()
	view, err := appMCPPrepareOperation(context.Background(), req, input)
	if err != nil || !view.AutoApproved {
		t.Fatalf("prepare: %+v %v", view, err)
	}
	if out, err := appMCPCommitOperation(context.Background(), req, view.ID); err != nil || out.Outcome != "applied" || !h.taskDone() {
		t.Fatalf("control commit: %+v %v", out, err)
	}
}

// The commit-time check itself, condition by condition: a manifest switched
// back to first_party, a pin from another grant or epoch, a lapsed switch and
// a list that no longer names the tool each deny.
func TestAppMCPAutoApproveGrantApprovalLiveMatrix(t *testing.T) {
	grantID, epoch := strings.Repeat("9", 64), strings.Repeat("8", 64)
	live := func() (*appMCPCommandCapability, *appMCPCommandApprovalState) {
		digest, exec := strings.Repeat("d", 64), strings.Repeat("c", 64)
		cap := &appMCPCommandCapability{origin: appMCPCommandConnectorOrigin, originPin: &appMCPWriteAuthorityPin{GrantID: grantID, AutoApproveEpoch: epoch},
			generation: &appMCPRuntimeGeneration{manifest: &AppMCPManifest{ContractDigest: digest, ExecutionDigest: exec}},
			tool:       &AppMCPTool{Name: "complete_item", Approval: "grant"}, autoApproveLive: true, autoApproveTools: []string{appMCPAutoApproveEntry("complete_item", digest, exec)}}
		return cap, &appMCPCommandApprovalState{Approval: appMCPCommandApprovalRecord{Domain: appMCPGrantApprovalDomain, Basis: appMCPGrantConsentBasis + grantID, AutoApproveEpoch: epoch}}
	}
	if cap, approval := live(); !appMCPGrantApprovalLive(cap, approval) {
		t.Fatal("live grant approval denied")
	}
	for name, mutate := range map[string]func(*appMCPCommandCapability, *appMCPCommandApprovalState){
		"manifest now first_party": func(c *appMCPCommandCapability, _ *appMCPCommandApprovalState) { c.tool.Approval = "first_party" },
		"session origin":           func(c *appMCPCommandCapability, _ *appMCPCommandApprovalState) { c.origin = appMCPCommandSessionOrigin },
		"switch not live":          func(c *appMCPCommandCapability, _ *appMCPCommandApprovalState) { c.autoApproveLive = false },
		"tool not listed": func(c *appMCPCommandCapability, _ *appMCPCommandApprovalState) {
			c.autoApproveTools = []string{appMCPAutoApproveEntry("other", c.generation.manifest.ContractDigest, c.generation.manifest.ExecutionDigest)}
		},
		// Review of #418: the contract digest names the handler flow, not its
		// body; an edited flow behind the same tool must need fresh consent.
		"handler flow body changed": func(c *appMCPCommandCapability, _ *appMCPCommandApprovalState) {
			c.generation.manifest.ExecutionDigest = strings.Repeat("f", 64)
		},
		"bare name (pre-binding grant)": func(c *appMCPCommandCapability, _ *appMCPCommandApprovalState) {
			c.autoApproveTools = []string{"complete_item"}
		},
		"manifest changed": func(c *appMCPCommandCapability, _ *appMCPCommandApprovalState) {
			c.generation.manifest.ContractDigest = strings.Repeat("e", 64)
		},
		"push transfer": func(c *appMCPCommandCapability, _ *appMCPCommandApprovalState) {
			c.tool.Transfer = &AppMCPTransfer{Kind: "push"}
		},
		"other grant": func(c *appMCPCommandCapability, _ *appMCPCommandApprovalState) {
			c.originPin.GrantID = strings.Repeat("7", 64)
		},
		"new epoch": func(c *appMCPCommandCapability, _ *appMCPCommandApprovalState) {
			c.originPin.AutoApproveEpoch = strings.Repeat("6", 64)
		},
		"pin without epoch": func(c *appMCPCommandCapability, a *appMCPCommandApprovalState) {
			c.originPin.AutoApproveEpoch, a.Approval.AutoApproveEpoch = "", ""
		},
	} {
		cap, approval := live()
		mutate(cap, approval)
		if appMCPGrantApprovalLive(cap, approval) {
			t.Fatalf("%s accepted", name)
		}
	}
}

var batchOpBoxes = regexp.MustCompile(`name="op" value="([0-9a-f]{64})"`)

func TestAppMCPAutoApproveBatchReviewPage(t *testing.T) {
	h := newExposureHarness(t)
	if _, err := h.app.DB.Exec(`INSERT INTO tasks(id,project_id,org_id,title,status) VALUES(2,7,'17','Second task','open'),(3,7,'17','Third task','open')`); err != nil {
		t.Fatal(err)
	}
	out, code := h.call(h.client, "complete_item", map[string]any{"arguments": map[string]any{"id": 1, "project_id": 7}})
	if code != "" {
		t.Fatal(code)
	}
	first := out["operation_id"].(string)
	batchURL := appMCPBatchReviewURL(h.resource, h.pair.GrantID)
	if out["batch_review_url"] != batchURL {
		t.Fatalf("batch_review_url %v, want %s", out["batch_review_url"], batchURL)
	}
	second := h.prepareTask(2)
	// Another connection of the same person: never on this grant's page.
	otherPair, err := createAppMCPNativeGrantFor(context.Background(), h.app, h.actorID, "17", "client-other", h.resource, "complete_item", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	otherClient := appMCPClient(t, h.server, otherPair.AccessToken, nil)
	otherOut, code := h.call(otherClient, "complete_item", map[string]any{"arguments": map[string]any{"id": 3, "project_id": 7}})
	if code != "" {
		t.Fatal(code)
	}
	foreign := otherOut["operation_id"].(string)

	path := appMCPBatchRoute + "?grant=" + h.pair.GrantID
	page := func(cookie string, header map[string]string) (int, string, []string, string) {
		resp, body := h.do("GET", path, cookie, nil, header)
		var ops []string
		for _, m := range batchOpBoxes.FindAllStringSubmatch(body, -1) {
			ops = append(ops, m[1])
		}
		token := ""
		if m := exposureCSRF.FindStringSubmatch(body); m != nil {
			token = m[1]
		}
		return resp.StatusCode, body, ops, token
	}
	status, body, ops, token := page(h.cookie, nil)
	if status != 200 || len(ops) != 2 || !slices.Contains(ops, first) || !slices.Contains(ops, second) || token == "" || strings.Contains(body, foreign) {
		t.Fatalf("batch page: %d ops=%v token=%v", status, ops, token != "")
	}
	// The page is the fallback for writes the owner kept under review, so
	// nothing is ticked for the person: one click must not approve them all.
	if strings.Contains(body, "checked") {
		t.Fatal("batch page pre-ticks an operation")
	}
	resp, pageBody := h.do("GET", path, h.cookie, nil, nil)
	assertMCPPageHeaders(t, resp, pageBody)
	// Bearer credentials, other people and delegated sessions see nothing.
	if status, _, ops, _ := page(h.cookie, map[string]string{"Authorization": "Bearer " + h.pair.AccessToken}); status != http.StatusNotFound || len(ops) != 0 {
		t.Fatalf("bearer page: %d %v", status, ops)
	}
	otherCookie := createCrudScopeSession(t, h.app, "other-user@example.com", "editor", "17", "")
	if status, body, ops, token := page(otherCookie, nil); status != 200 || len(ops) != 0 || token != "" || !strings.Contains(body, "Nothing from this connection") {
		t.Fatalf("other user page: %d %v", status, ops)
	}
	scoped := CreateSession(h.app.DB, h.actorID, "task-actor@example.com", "17", time.Hour)
	if _, err := h.app.DB.Exec("UPDATE _benmore_sessions SET scopes='tasks:write' WHERE id=?", sessionStorageKey(scoped)); err != nil {
		t.Fatal(err)
	}
	if status, _, ops, _ := page(scoped, nil); status == 200 || len(ops) != 0 {
		t.Fatalf("scoped session page: %d %v", status, ops)
	}

	approvals := func() int { return h.count("SELECT count(*) FROM _benmore_mcp_command_approvals") }
	post := func(cookie string, form url.Values, header map[string]string) int {
		resp, _ := h.do("POST", appMCPBatchRoute+"/approve", cookie, form, header)
		return resp.StatusCode
	}
	form := func(token string, ids ...string) url.Values {
		return url.Values{"_csrf": {token}, "grant": {h.pair.GrantID}, "op": ids}
	}
	_, _, singleToken := h.review(h.cookie, first)
	for name, got := range map[string]int{
		"no csrf":                post(h.cookie, form("", first), nil),
		"session csrf":           post(h.cookie, form(authMintCSRFToken(h.cookie), first), nil),
		"single-operation csrf":  post(h.cookie, form(singleToken, first), nil),
		"other grant's csrf":     post(h.cookie, form(authMintCSRFToken(appMCPBatchBinding(h.cookie, otherPair.GrantID)), first), nil),
		"cross-site":             post(h.cookie, form(token, first), map[string]string{"Origin": "https://evil.example"}),
		"bearer":                 post(h.cookie, form(token, first), map[string]string{"Authorization": "Bearer " + h.pair.AccessToken}),
		"another grant's op":     post(h.cookie, form(token, first, foreign), nil),
		"duplicate op":           post(h.cookie, form(token, first, first), nil),
		"other user":             post(otherCookie, form(token, first), nil),
		"other user own binding": post(otherCookie, form(authMintCSRFToken(appMCPBatchBinding(otherCookie, h.pair.GrantID)), first), nil),
	} {
		if got == http.StatusSeeOther || approvals() != 0 {
			t.Fatalf("%s: status %d approvals %d", name, got, approvals())
		}
	}
	// A valid submit with nothing ticked approves nothing and says so.
	if resp, _ := h.do("POST", appMCPBatchRoute+"/approve", h.cookie, form(token), nil); resp.StatusCode != http.StatusSeeOther ||
		!strings.HasSuffix(resp.Header.Get("Location"), "&notice=none") || approvals() != 0 {
		t.Fatalf("nothing selected: %d %q approvals %d", resp.StatusCode, resp.Header.Get("Location"), approvals())
	}
	if _, body, _, _ := page(h.cookie, nil); !strings.Contains(body, "Approve selected") {
		t.Fatal("batch page lost its form")
	}
	resp, _ = h.do("POST", appMCPBatchRoute+"/approve", h.cookie, form(token, first, second), nil)
	if resp.StatusCode != http.StatusSeeOther || approvals() != 2 || h.countApprovals(appMCPHumanApprovalDomain) != 2 {
		t.Fatalf("batch approve: %d approvals %d", resp.StatusCode, approvals())
	}
	if loc := resp.Header.Get("Location"); !strings.HasSuffix(loc, "&approved=2") {
		t.Fatalf("batch approve redirect %q", loc)
	}
	if _, body := h.do("GET", appMCPBatchRoute+"?grant="+h.pair.GrantID+"&approved=2", h.cookie, nil, nil); !strings.Contains(body, "Approved 2 changes") {
		t.Fatal("approved notice missing")
	}
	// A link from another site cannot make the page claim anything was approved.
	if _, body := h.do("GET", appMCPBatchRoute+"?grant="+h.pair.GrantID+"&approved=2&notice=none", h.cookie, nil, map[string]string{"Sec-Fetch-Site": "cross-site"}); strings.Contains(body, "Approved 2") || strings.Contains(body, "Tick at least one") {
		t.Fatal("cross-site link rendered a notice")
	}
	for raw, want := range map[string]int{"2": 2, "0": 0, "": -1, "02": -1, "-1": -1, "1e3": -1, "99999": -1} {
		if got := appMCPBatchApprovedCount(raw); got != want {
			t.Errorf("approved count %q = %d, want %d", raw, got, want)
		}
	}
	if h.count("SELECT count(*) FROM _benmore_audit_log WHERE action='mcp_command_approve'") != 2 {
		t.Fatal("each approval needs its own audit row")
	}
	for _, id := range []string{first, second} {
		if out, code := h.call(h.client, appMCPCommitTool, map[string]any{"operation_id": id}); code != "" || out["outcome"] != "applied" {
			t.Fatalf("commit %s: %q", id[:8], code)
		}
	}
	if status, body, ops, _ := page(h.cookie, nil); status != 200 || len(ops) != 0 || !strings.Contains(body, "Nothing from this connection") {
		t.Fatalf("page after approval: %d %v", status, ops)
	}
	if status, _, ops, _ := page(h.cookie, nil); status != 200 || len(ops) != 0 {
		t.Fatalf("reload: %d %v", status, ops)
	}
}
