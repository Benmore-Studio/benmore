//go:build !cli && !windows

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	sqlite3 "github.com/mattn/go-sqlite3"
)

type appMCPCanonicalUpdateFixture struct {
	app  *App
	uid  int64
	sid  string
	pair *appMCPTokenPair
	pin  appMCPWriteAuthorityPin
	now  time.Time
}

func newCanonicalUpdateFixture(t *testing.T, hook, page, validator string) appMCPCanonicalUpdateFixture {
	return newCanonicalUpdateFixtureWithAutoMembership(t, hook, page, validator, false)
}

func newCanonicalUpdateFixtureWithAutoMembership(t *testing.T, hook, page, validator string, autoMembership bool) appMCPCanonicalUpdateFixture {
	t.Helper()
	f := newCanonicalUpdateSourceFixture(t, hook, page, validator, autoMembership)
	state, err := currentAppMCPEpoch(f.app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if !autoMembership {
		if _, err := initializeAppMCPRevisionEnrollment(context.Background(), f.app, snapshotAppMCPGeneration(f.app)); err != nil {
			t.Fatalf("explicitly enroll native fixture revision universe: %v", err)
		}
		state, err = enableAppMCPRevisionEnrolledWrites(context.Background(), f.app, snapshotAppMCPGeneration(f.app))
	} else {
		state, err = setAppMCPApprovedWrites(f.app.Dir, true)
	}
	if err != nil {
		t.Fatal(err)
	}
	pair, err := createAppMCPNativeGrantFor(context.Background(), f.app, f.uid, "17", "native-fixture", grantFixtureResource, "notes_update_title", f.now)
	if err != nil {
		t.Fatalf("create trusted declared-scope grant: %v", err)
	}
	f.pair = pair
	f.pin = appMCPWriteAuthorityPin{
		Origin: f.app, Generation: snapshotAppMCPGeneration(f.app), CredentialHash: mustAppMCPCredentialHash(t, pair.AccessToken, "access"),
		GrantID: pair.GrantID, AppID: state.App, Epoch: state.Epoch, WriteEpoch: state.ApprovedWriteEpoch,
		Resource: grantFixtureResource, Client: "native-fixture", Tenant: "17", UserID: f.uid,
		UserCreated: readUserCreatedForTest(t, f.app, f.uid), Permissions: strings.Fields(pair.Scopes),
	}
	return f
}

// newCanonicalUpdateSourceFixture loads real reviewed source and seeds the
// native app, but leaves it unenrolled, disabled, and without a connector grant.
func newCanonicalUpdateSourceFixture(t *testing.T, hook, page, validator string, autoMembership bool) appMCPCanonicalUpdateFixture {
	return newCanonicalUpdateSourceFixtureWithSchema(t, hook, page, validator, "", autoMembership)
}

func newCanonicalUpdateSourceFixtureWithSchema(t *testing.T, hook, page, validator, prismaSchema string, autoMembership bool) appMCPCanonicalUpdateFixture {
	t.Helper()
	epochFixture(t)
	t.Setenv("BENMORE_TEST_BOOT", "1")
	dir := t.TempDir()
	if prismaSchema == "" {
		writeTestFile(t, dir, "schema.sql", `CREATE TABLE members (id INTEGER PRIMARY KEY, org_id TEXT NOT NULL, email TEXT NOT NULL);
CREATE TABLE notes (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, title TEXT NOT NULL, updated_at DATETIME, normalized TEXT, secret TEXT);
CREATE TABLE group_notes (id INTEGER PRIMARY KEY, org_id TEXT NOT NULL, title TEXT NOT NULL);
CREATE TABLE public_notes (id INTEGER PRIMARY KEY, title TEXT NOT NULL);
CREATE TABLE note_members (user_id INTEGER NOT NULL, note_id INTEGER NOT NULL, UNIQUE(user_id,note_id));
CREATE TABLE lifecycle_markers (id INTEGER PRIMARY KEY, value TEXT NOT NULL);
`)
	} else {
		writeTestFile(t, dir, "schema.prisma", prismaSchema)
	}
	appConfig := `groups: {table: members, key: org_id, user_field: email}
roles:
  editor: {scopes: [notes:read, notes:write, group_notes:read, public_notes:read]}
access:
  notes: {all: self}
  group_notes: {all: group}
  public_notes: {all: everyone}
`
	if autoMembership {
		appConfig += "auto_memberships:\n  notes:\n    table: note_members\n    parent: note_id\n"
	}
	writeTestFile(t, dir, "app.yaml", appConfig)
	manifest := strings.Replace(appMCPUpdateManifestFixture(), "tools:\n  - name: notes_update_title", `tools:
  - name: list_notes
    description: Read reviewed notes.
    handler: {kind: native, operation: table.list, table: notes}
    input_schema: {type: object, additionalProperties: false}
    output_schema:
      type: object
      additionalProperties: false
      required: [id, title]
      properties:
        id: {type: integer}
        title: {type: string, maxLength: 200}
    permissions: [notes:read]
    effect: read
    approval: none
    idempotency: none
    reconciliation: none
    output: {include: [id, title]}
    component: none
  - name: notes_update_title`, 1)
	manifest = strings.Replace(manifest, "properties:\n            title:", "properties:\n            user_id: {type: integer, minimum: 1, maximum: 9007199254740991}\n            updated_at: {type: string, minLength: 1, maxLength: 64}\n            normalized: {type: string, minLength: 1, maxLength: 200}\n            secret: {type: string, minLength: 1, maxLength: 200}\n            title:", 1)
	writeTestFile(t, dir, "mcp.yaml", manifest)
	writeTestFile(t, dir, "encrypted.yaml", "tables:\n  notes:\n    fields:\n      - secret\n    unmask_roles:\n      - editor\n")
	writeTestFile(t, dir, "env.yaml", "ENCRYPTION_KEY: canonical-test-encryption-key-with-sufficient-length\n")
	if hook != "" {
		writeTestFile(t, dir, "hooks.yaml", hook)
	}
	if page != "" {
		writeTestFile(t, dir, "index.html", page)
	}
	if validator != "" {
		writeTestFile(t, dir, "validators.yaml", validator)
	}
	writeTestFile(t, dir, "computed.yaml", "fields:\n  - table: notes\n    column: normalized\n    expr: lower(title)\n")
	reviewAppMCPFixture(t, dir)
	app, err := loadApp(dir)
	if err != nil {
		t.Fatalf("load real MCP app: %v", err)
	}
	t.Cleanup(func() { app.Shutdown() })
	var encryptedField bool
	for _, field := range app.Encrypted.Fields["notes"] {
		if field.Column == "secret" {
			encryptedField = true
		}
	}
	if !encryptedField {
		t.Fatal("dedicated encrypted.yaml did not load notes.secret")
	}
	var installedEncryptionTriggers int
	if err := app.DB.QueryRow("SELECT count(*) FROM main.sqlite_schema WHERE type='trigger' AND name LIKE '_benmore_enc_notes_secret_%'").Scan(&installedEncryptionTriggers); err != nil || installedEncryptionTriggers == 0 {
		t.Fatalf("notes.secret encryption triggers were not installed: count=%d err=%v", installedEncryptionTriggers, err)
	}
	// Match ordinary per-app route initialization before any request can mutate data.
	EnsureAuditLogTable(app.DB)
	EnsureWebhooksTable(app.DB)
	EnsureLocksTable(app.DB)
	EnsurePermissionsTable(app.DB)
	if err := EnsureUserRolesTable(app.DB); err != nil {
		t.Fatalf("initialize native actor role ledger: %v", err)
	}
	var permissionLedger int
	if err := app.DB.QueryRow("SELECT count(*) FROM main.sqlite_schema WHERE type='table' AND name='_benmore_permissions'").Scan(&permissionLedger); err != nil || permissionLedger != 1 {
		t.Fatalf("native ACL ledger was not installed: count=%d err=%v", permissionLedger, err)
	}
	app.DB.SetMaxOpenConns(1)
	sid := createCrudScopeSession(t, app, "canonical@example.com", "editor", "17", "")
	session := GetSessionFromDB(app.DB, sid)
	if _, err := app.DB.Exec("INSERT INTO main.members(org_id,email) VALUES('17',?)", session.Email); err != nil {
		t.Fatal(err)
	}
	updatedAtSeed := "datetime('now')"
	secretSeed := "'old-secret'"
	if prismaSchema != "" {
		updatedAtSeed = "'2000-01-01T00:00:00Z'"
		secretSeed = "'enc:fixture'"
	}
	if _, err := app.DB.Exec("INSERT INTO main.notes(id,user_id,title,updated_at,secret) VALUES(1,?,'before',"+updatedAtSeed+","+secretSeed+")", session.UserID); err != nil {
		t.Fatal(err)
	}
	if _, err := updateAppMCPEpoch(app.Dir, true, false, true); err != nil {
		t.Fatal(err)
	}
	// Establish explicit v2-disabled owner state; this helper never enables writes.
	state, err := setAppMCPApprovedWrites(app.Dir, false)
	if err != nil || state.ApprovedWrites == nil || *state.ApprovedWrites {
		t.Fatalf("source fixture owner writes are not disabled: %+v (%v)", state, err)
	}
	return appMCPCanonicalUpdateFixture{app: app, uid: session.UserID, sid: sid, now: time.Now().UTC()}
}

func canonicalTitleUpdate(title string) map[string]any {
	return map[string]any{"id": int64(1), "data": map[string]any{"title": title}}
}

func refreshCanonicalFixturePin(t *testing.T, f *appMCPCanonicalUpdateFixture) {
	t.Helper()
	pair, err := createAppMCPNativeGrantFor(context.Background(), f.app, f.uid, "17", "native-fixture", grantFixtureResource, "notes_update_title", f.now)
	if err != nil {
		t.Fatalf("mint grant for reloaded reviewed policy: %v", err)
	}
	f.pair = pair
	f.pin.Generation = snapshotAppMCPGeneration(f.app)
	f.pin.CredentialHash = mustAppMCPCredentialHash(t, pair.AccessToken, "access")
	f.pin.GrantID = pair.GrantID
	f.pin.Permissions = strings.Fields(pair.Scopes)
}

func readCanonicalNote(t *testing.T, db *sql.DB) string {
	t.Helper()
	var title string
	if err := db.QueryRow("SELECT title FROM main.notes WHERE id=1").Scan(&title); err != nil {
		t.Fatal(err)
	}
	return title
}

func resetCanonicalNote(t *testing.T, app *App) {
	t.Helper()
	if _, err := app.DB.Exec("UPDATE main.notes SET title='before', updated_at=datetime('now') WHERE id=1"); err != nil {
		t.Fatal(err)
	}
}

func canonicalEffectsSnapshot(t *testing.T, app *App) string {
	t.Helper()
	business := make(map[string][]map[string]any)
	for _, table := range app.Tables {
		if !isValidColumnName(table.Name) {
			t.Fatalf("invalid fixture app table name %q", table.Name)
		}
		rows, err := queryRowsWithMainKey(app.DB, "SELECT * FROM main."+quoteIdent(table.Name))
		if err != nil {
			t.Fatalf("snapshot business table %s: %v", table.Name, err)
		}
		business[table.Name] = rows
	}
	ledgers := map[string][]map[string]any{}
	for _, table := range []string{"_benmore_audit_log", "_benmore_jobs", "_benmore_webhooks", "_benmore_events", "_benmore_mcp_authorizations", "_benmore_locks"} {
		var exists int
		if err := app.DB.QueryRow("SELECT count(*) FROM main.sqlite_schema WHERE type='table' AND name=?", table).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if exists == 0 {
			continue
		}
		rows, err := queryRowsWithMainKey(app.DB, "SELECT * FROM main."+quoteIdent(table))
		if err != nil {
			t.Fatalf("snapshot effect ledger %s: %v", table, err)
		}
		ledgers[table] = rows
	}
	encoded, err := json.Marshal(struct {
		Business map[string][]map[string]any
		Ledgers  map[string][]map[string]any
	}{business, ledgers})
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func decodeCanonicalMCPRPC(t *testing.T, response *httptest.ResponseRecorder) struct {
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
	Result json.RawMessage `json:"result"`
} {
	t.Helper()
	body := strings.TrimSpace(response.Body.String())
	if strings.HasPrefix(body, "event:") {
		for _, line := range strings.Split(body, "\n") {
			if data, ok := strings.CutPrefix(strings.TrimSpace(line), "data:"); ok {
				body = strings.TrimSpace(data)
				break
			}
		}
	}
	var message struct {
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal([]byte(body), &message); err != nil {
		t.Fatalf("decode SDK JSON-RPC response: %v: %s", err, body)
	}
	return message
}

func canonicalPositiveThenReset(t *testing.T, f appMCPCanonicalUpdateFixture) {
	t.Helper()
	projected, _, err := applyAppMCPCanonicalUpdate(context.Background(), f.pin, "notes_update_title", canonicalTitleUpdate("positive"), f.now)
	if err != nil || projected["title"] != "positive" || readCanonicalNote(t, f.app.DB) != "positive" {
		var authorityErr *appMCPWriteAuthorityError
		if errors.As(err, &authorityErr) && authorityErr.cause != nil {
			t.Fatalf("positive coordinator precondition failed: projected=%v private_cause=%v", projected, authorityErr.cause)
		}
		t.Fatalf("positive coordinator precondition failed: projected=%v err=%v", projected, err)
	}
	resetCanonicalNote(t, f.app)
}

func TestAppMCPCanonicalUpdateUsesLoadedPolicyAndAuthoritativeSQLHookReadback(t *testing.T) {
	f := newCanonicalUpdateFixture(t,
		"on_update:\n  notes:\n    - sql: |\n        WITH chosen AS (SELECT id FROM notes WHERE id={{id}})\n        UPDATE notes SET title=CASE WHEN title='submitted' THEN 'after-hook' ELSE title END WHERE id IN (SELECT id FROM chosen);\n        INSERT INTO lifecycle_markers(id,value) VALUES(2,'after-hook')\n",
		`<form :create="notes"><input name="title" :validate="minlen:3"></form>`,
		"notes:\n  - rule: \"title != 'blocked'\"\n    error: blocked-title\n")
	f.app.DB.SetMaxOpenConns(1)
	input := map[string]any{"id": int64(1), "data": map[string]any{"title": "submitted", "secret": "new-secret"}}
	projected, refreshTables, err := applyAppMCPCanonicalUpdate(context.Background(), f.pin, "notes_update_title", input, f.now)
	if err != nil {
		t.Fatalf("canonical update: %v", err)
	}
	if got := readCanonicalNote(t, f.app.DB); got != "after-hook" || projected["title"] != "after-hook" {
		t.Fatalf("result was not authoritative post-hook readback: db=%q result=%v", got, projected)
	}
	if !reflect.DeepEqual(refreshTables, []string{"lifecycle_markers"}) {
		t.Fatalf("CTE/multiple-table hook refresh targets=%v, want [lifecycle_markers]", refreshTables)
	}
	var hookMarker string
	if err := f.app.DB.QueryRow("SELECT value FROM main.lifecycle_markers WHERE id=2").Scan(&hookMarker); err != nil || hookMarker != "after-hook" {
		t.Fatalf("second validated hook statement did not execute: value=%q err=%v", hookMarker, err)
	}
	var normalized string
	if err := f.app.DB.QueryRow("SELECT normalized FROM main.notes WHERE id=1").Scan(&normalized); err != nil || normalized != "after-hook" {
		t.Fatalf("computed trigger did not observe canonical+SQL-hook writes: %q (%v)", normalized, err)
	}
	if f.app.Computed == nil || f.app.Computed.Fields["notes"]["normalized"] == nil {
		t.Fatal("approved fields-array computed declaration was not loaded")
	}
	var storedSecret string
	if err := f.app.DB.QueryRow("SELECT secret FROM main.notes WHERE id=1").Scan(&storedSecret); err != nil || !cryptoIsEncrypted(storedSecret) {
		t.Fatalf("encrypted column was not stored as ciphertext: %q (%v)", storedSecret, err)
	}
	key, err := cryptoKeyForQuerierMainChecked(f.app.DB)
	if err != nil {
		t.Fatalf("resolve owning database key: %v", err)
	}
	plainSecret, err := fieldDecryptCtx(key, "secret", storedSecret)
	if err != nil || plainSecret != "new-secret" {
		t.Fatalf("owning key did not decrypt final encrypted field: %q (%v)", plainSecret, err)
	}
	var oldJSON, newJSON string
	if err := f.app.DB.QueryRow("SELECT old_values,new_values FROM main._benmore_audit_log WHERE action='update' AND table_name='notes' AND row_id='1' ORDER BY id DESC LIMIT 1").Scan(&oldJSON, &newJSON); err != nil {
		t.Fatalf("read transaction audit: %v", err)
	}
	var oldRow, newRow map[string]any
	if json.Unmarshal([]byte(oldJSON), &oldRow) != nil || json.Unmarshal([]byte(newJSON), &newRow) != nil || oldRow["title"] != "before" || newRow["title"] != "after-hook" || !cryptoIsEncrypted(fmt.Sprint(oldRow["secret"])) || !cryptoIsEncrypted(fmt.Sprint(newRow["secret"])) {
		t.Fatalf("audit lost immutable before/final after: old=%s new=%s", oldJSON, newJSON)
	}
	oldAuditSecret, err := fieldDecryptWithKey(key, fmt.Sprint(oldRow["secret"]))
	if err != nil || oldAuditSecret != "old-secret" {
		t.Fatalf("encrypted audit before value did not resolve through owner key: %q (%v)", oldAuditSecret, err)
	}
	newAuditSecret, err := fieldDecryptWithKey(key, fmt.Sprint(newRow["secret"]))
	if err != nil || newAuditSecret != "new-secret" {
		t.Fatalf("encrypted audit after value did not resolve through owner key: %q (%v)", newAuditSecret, err)
	}
}

func TestAppMCPCanonicalUpdateTreatsKnownCiphertextAsPlaintext(t *testing.T) {
	f := newCanonicalUpdateFixture(t, "", "", "")
	f.app.DB.SetMaxOpenConns(1)
	var supplied string
	if err := f.app.DB.QueryRow("SELECT secret FROM main.notes WHERE id=1").Scan(&supplied); err != nil {
		t.Fatal(err)
	}
	key, err := cryptoKeyForQuerierMainChecked(f.app.DB)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{supplied, appMCPTestV1Cipher(t, key, []byte("legacy-private")), "enc:v2:literal"} {
		_, _, err := applyAppMCPCanonicalUpdate(context.Background(), f.pin, "notes_update_title", map[string]any{"id": int64(1), "data": map[string]any{"title": "literal", "secret": input}}, f.now)
		if err != nil {
			t.Fatalf("native connector update: %v", err)
		}
		var stored string
		if err := f.app.DB.QueryRow("SELECT secret FROM main.notes WHERE id=1").Scan(&stored); err != nil {
			t.Fatal(err)
		}
		if plain, err := fieldDecryptCtx(key, "secret", stored); err != nil || plain != input || stored == input {
			t.Fatalf("private native update adopted ciphertext: plaintext=%q err=%v", plain, err)
		}
	}
}

func TestAppMCPCanonicalUpdateKeepsOrdinaryCiphertextTextLiteral(t *testing.T) {
	f := newCanonicalUpdateFixture(t, "", "", "")
	f.app.DB.SetMaxOpenConns(1)
	var supplied string
	if err := f.app.DB.QueryRow("SELECT secret FROM main.notes WHERE id=1").Scan(&supplied); err != nil {
		t.Fatal(err)
	}
	projected, _, err := applyAppMCPCanonicalUpdate(context.Background(), f.pin, "notes_update_title", map[string]any{"id": int64(1), "data": map[string]any{"title": supplied}}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if projected["title"] != supplied {
		t.Fatalf("ordinary private connector field decrypted: %#v", projected)
	}
}

func TestAppMCPCanonicalUpdateDenialsLeaveBusinessRowsAndAuditUntouched(t *testing.T) {
	f := newCanonicalUpdateFixture(t, "", `<form :create="notes"><input name="title" :validate="minlen:3"></form>`, "notes:\n  - rule: \"title != 'blocked'\"\n    error: blocked-title\n")
	deniedInputs := []struct {
		name  string
		input map[string]any
	}{
		{"unknown-field", map[string]any{"id": int64(1), "data": map[string]any{"title": "after", "unreviewed": "x"}}},
		{"page-validation", canonicalTitleUpdate("x")},
		{"cross-field-validator", canonicalTitleUpdate("blocked")},
		{"protected-owner", map[string]any{"id": int64(1), "data": map[string]any{"title": "after", "user_id": f.uid + 100}}},
		{"protected-timestamp", map[string]any{"id": int64(1), "data": map[string]any{"title": "after", "updated_at": "forged"}}},
		{"computed-field", map[string]any{"id": int64(1), "data": map[string]any{"title": "after", "normalized": "forged"}}},
	}
	for _, tc := range deniedInputs {
		t.Run(tc.name, func(t *testing.T) {
			canonicalPositiveThenReset(t, f)
			before := canonicalEffectsSnapshot(t, f.app)
			if _, _, err := applyAppMCPCanonicalUpdate(context.Background(), f.pin, "notes_update_title", tc.input, f.now); err == nil {
				t.Fatal("denied update was accepted")
			}
			if after := canonicalEffectsSnapshot(t, f.app); !reflect.DeepEqual(after, before) {
				t.Fatalf("denial changed business/effect state: before=%s after=%s", before, after)
			}
		})
	}

	// A public OAuth-style grant cannot borrow the private native write scope.
	readPair, err := createAppMCPGrant(f.app, f.uid, "17", "public-fixture", grantFixtureResource, "notes:read", f.now)
	if err != nil {
		t.Fatal(err)
	}
	readOnlyPin := f.pin
	readOnlyPin.CredentialHash = mustAppMCPCredentialHash(t, readPair.AccessToken, "access")
	readOnlyPin.GrantID, readOnlyPin.Client = readPair.GrantID, "public-fixture"
	canonicalPositiveThenReset(t, f)
	before := canonicalEffectsSnapshot(t, f.app)
	if _, _, err := applyAppMCPCanonicalUpdate(context.Background(), readOnlyPin, "notes_update_title", canonicalTitleUpdate("after"), f.now); !errors.Is(err, errAppMCPGrantDenied) {
		t.Fatalf("read-only grant did not fail closed: %v", err)
	}
	if after := canonicalEffectsSnapshot(t, f.app); after != before {
		t.Fatalf("read-only denial changed state: before=%s after=%s", before, after)
	}
	canonicalPositiveThenReset(t, f)
	before = canonicalEffectsSnapshot(t, f.app)
	if _, err := setAppMCPApprovedWrites(f.app.Dir, false); err != nil {
		t.Fatal(err)
	}
	if _, _, err := applyAppMCPCanonicalUpdate(context.Background(), f.pin, "notes_update_title", canonicalTitleUpdate("after"), f.now); !errors.Is(err, errAppMCPGrantDenied) {
		t.Fatalf("disabled owner authority did not fail closed: %v", err)
	}
	if after := canonicalEffectsSnapshot(t, f.app); after != before {
		t.Fatalf("disabled-owner denial changed state: before=%s after=%s", before, after)
	}
}

func TestAppMCPCanonicalUpdateRechecksLiveRoleAndRowScope(t *testing.T) {
	f := newCanonicalUpdateFixture(t, "", "", "")
	canonicalPositiveThenReset(t, f)
	if _, err := f.app.DB.Exec("UPDATE main._benmore_users SET role='unreviewed' WHERE id=?", f.uid); err != nil {
		t.Fatal(err)
	}
	before := canonicalEffectsSnapshot(t, f.app)
	if _, _, err := applyAppMCPCanonicalUpdate(context.Background(), f.pin, "notes_update_title", canonicalTitleUpdate("wrong-role"), f.now); !errors.Is(err, errAppMCPGrantDenied) {
		t.Fatalf("live role without notes:write was accepted: %v", err)
	}
	if after := canonicalEffectsSnapshot(t, f.app); after != before {
		t.Fatalf("wrong-role denial changed effects: before=%s after=%s", before, after)
	}
	if _, err := f.app.DB.Exec("UPDATE main._benmore_users SET role='editor' WHERE id=?", f.uid); err != nil {
		t.Fatal(err)
	}
	canonicalPositiveThenReset(t, f)
	if _, err := f.app.DB.Exec("UPDATE main.notes SET user_id=? WHERE id=1", f.uid+100); err != nil {
		t.Fatal(err)
	}
	before = canonicalEffectsSnapshot(t, f.app)
	if _, _, err := applyAppMCPCanonicalUpdate(context.Background(), f.pin, "notes_update_title", canonicalTitleUpdate("outside-row-scope"), f.now); err == nil {
		t.Fatal("row outside the actor's live self scope was accepted")
	}
	if after := canonicalEffectsSnapshot(t, f.app); after != before {
		t.Fatalf("row-scope denial changed effects: before=%s after=%s", before, after)
	}
}

func TestAppMCPCanonicalUpdateHonorsRecordLocksAndMissingLockLedger(t *testing.T) {
	f := newCanonicalUpdateFixture(t, "", "", "")
	canonicalPositiveThenReset(t, f)
	if _, err := f.app.DB.Exec(`INSERT INTO main._benmore_locks(table_name,row_id,user_id,user_email,expires_at) VALUES('notes','1',?,'other@example.com',datetime('now','+1 hour'))`, f.uid+1); err != nil {
		t.Fatal(err)
	}
	before := canonicalEffectsSnapshot(t, f.app)
	if _, _, err := applyAppMCPCanonicalUpdate(context.Background(), f.pin, "notes_update_title", canonicalTitleUpdate("locked"), f.now); err == nil {
		t.Fatal("record locked by another actor was updated")
	}
	if after := canonicalEffectsSnapshot(t, f.app); after != before {
		t.Fatalf("record-lock denial changed state: before=%s after=%s", before, after)
	}
	if _, err := f.app.DB.Exec("DELETE FROM main._benmore_locks WHERE table_name='notes' AND row_id='1'"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.app.DB.Exec("DROP TABLE main._benmore_locks"); err != nil {
		t.Fatal(err)
	}
	before = canonicalEffectsSnapshot(t, f.app)
	if _, _, err := applyAppMCPCanonicalUpdate(context.Background(), f.pin, "notes_update_title", canonicalTitleUpdate("missing-lock-ledger"), f.now); err == nil {
		t.Fatal("missing native lock ledger did not fail closed")
	}
	if after := canonicalEffectsSnapshot(t, f.app); after != before {
		t.Fatalf("missing-lock-ledger denial changed state: before=%s after=%s", before, after)
	}
}

func TestAppMCPCanonicalUpdateBeforeHookDenialRollsBack(t *testing.T) {
	f := newCanonicalUpdateFixture(t, "before_update:\n  notes:\n    - sql: \"SELECT 'blocked by hook' AS error WHERE {{title}}='blocked'\"\n", "", "")
	canonicalPositiveThenReset(t, f)
	before := canonicalEffectsSnapshot(t, f.app)
	if _, _, err := applyAppMCPCanonicalUpdate(context.Background(), f.pin, "notes_update_title", canonicalTitleUpdate("blocked"), f.now); err == nil {
		t.Fatal("aborting before-update hook did not deny the operation")
	}
	if after := canonicalEffectsSnapshot(t, f.app); after != before {
		t.Fatalf("before-hook denial changed state: before=%s after=%s", before, after)
	}
}

func installCanonicalHotHandler(t *testing.T) {
	t.Helper()
	previous := hostedHotHandler
	handler := &hotHandler{}
	handler.swap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	hostedHotHandler = handler
	t.Cleanup(func() { hostedHotHandler = previous })
}

func TestAppMCPCanonicalUpdateRejectsCancelledAndStaleGenerationBeforeMutation(t *testing.T) {
	installCanonicalHotHandler(t)
	f := newCanonicalUpdateFixture(t, "", "", "")
	before := canonicalEffectsSnapshot(t, f.app)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := applyAppMCPCanonicalUpdate(ctx, f.pin, "notes_update_title", canonicalTitleUpdate("cancelled"), f.now); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled coordinator call was accepted: %v", err)
	}
	if got := readCanonicalNote(t, f.app.DB); got != "before" {
		t.Fatalf("cancellation changed note: %q", got)
	}
	if after := canonicalEffectsSnapshot(t, f.app); after != before {
		t.Fatalf("cancellation changed state: before=%s after=%s", before, after)
	}
	// Reload unchanged source, then refresh only the epoch field on the stale
	// pin so this denial isolates the captured generation identity.
	if err := hotReloadApp(f.app, false); err != nil {
		t.Fatalf("reload unchanged reviewed source: %v", err)
	}
	state, err := setAppMCPApprovedWrites(f.app.Dir, true)
	if err != nil {
		t.Fatal(err)
	}
	staleGenerationPin := f.pin
	staleGenerationPin.WriteEpoch = state.ApprovedWriteEpoch
	freshPin := staleGenerationPin
	freshPin.Generation = snapshotAppMCPGeneration(f.app)
	projected, _, err := applyAppMCPCanonicalUpdate(context.Background(), freshPin, "notes_update_title", canonicalTitleUpdate("fresh-generation"), f.now)
	if err != nil || projected["title"] != "fresh-generation" {
		t.Fatalf("fresh generation positive precondition failed: %v %v", projected, err)
	}
	resetCanonicalNote(t, f.app)
	before = canonicalEffectsSnapshot(t, f.app)
	if _, _, err := applyAppMCPCanonicalUpdate(context.Background(), staleGenerationPin, "notes_update_title", canonicalTitleUpdate("stale"), f.now); !errors.Is(err, errAppMCPGrantDenied) {
		t.Fatalf("stale generation was accepted: %v", err)
	}
	if after := canonicalEffectsSnapshot(t, f.app); after != before {
		t.Fatalf("stale-generation denial changed state: before=%s after=%s", before, after)
	}
}

func TestAppMCPCanonicalUpdateCancelsRunningSQLAndReleasesLeases(t *testing.T) {
	installCanonicalHotHandler(t)
	f := newCanonicalUpdateFixture(t, "before_update:\n  notes:\n    - sql: \"WITH RECURSIVE n(x) AS (SELECT mcp_test_started() UNION ALL SELECT x+1 FROM n WHERE x < 100000000) SELECT sum(x) AS value FROM n\"\n", "", "")
	f.app.DB.SetMaxOpenConns(1)
	started := make(chan struct{})
	conn, err := f.app.DB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Raw(func(raw any) error {
		sqliteConn, ok := raw.(*sqlite3.SQLiteConn)
		if !ok {
			return fmt.Errorf("unexpected sqlite driver connection %T", raw)
		}
		return sqliteConn.RegisterFunc("mcp_test_started", func() int {
			select {
			case <-started:
			default:
				close(started)
			}
			return 1
		}, true)
	}); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	joined := false
	t.Cleanup(func() {
		cancel()
		if joined {
			return
		}
		select {
		case <-result:
			joined = true
		case <-time.After(5 * time.Second):
			t.Errorf("canceled canonical writer did not join during cleanup")
		}
	})
	go func() {
		_, _, err := applyAppMCPCanonicalUpdate(ctx, f.pin, "notes_update_title", canonicalTitleUpdate("cancel-running"), f.now)
		result <- err
	}()
	select {
	case <-started:
		cancel()
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("before-hook SQL did not start")
	}
	select {
	case err := <-result:
		joined = true
		if err == nil || !errors.Is(err, context.Canceled) || err.Error() != "validation check could not be evaluated" {
			t.Fatalf("running SQL cancellation was not propagated: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("canceled SQL retained the transaction/authority leases")
	}
	if got := readCanonicalNote(t, f.app.DB); got != "before" {
		t.Fatalf("running SQL cancellation changed the row: %q", got)
	}
	// Remove the deliberately long SQL hook and prove a subsequent command can
	// acquire the native policy/file leases and commit normally.
	if err := os.Remove(filepath.Join(f.app.Dir, "hooks.yaml")); err != nil {
		t.Fatal(err)
	}
	reviewAppMCPFixture(t, f.app.Dir)
	if err := hotReloadApp(f.app, false); err != nil {
		t.Fatalf("reload without canceled hook: %v", err)
	}
	state, err := setAppMCPApprovedWrites(f.app.Dir, true)
	if err != nil {
		t.Fatal(err)
	}
	freshPin := f.pin
	freshPin.WriteEpoch = state.ApprovedWriteEpoch
	freshPin.Generation = snapshotAppMCPGeneration(f.app)
	if _, _, err := applyAppMCPCanonicalUpdate(context.Background(), freshPin, "notes_update_title", canonicalTitleUpdate("after-cancel"), f.now); err != nil {
		t.Fatalf("following command could not reacquire leases: %v", err)
	}
}

func TestAppMCPCanonicalUpdateCancelsRunningWhenAndReusesConnection(t *testing.T) {
	f := newCanonicalUpdateFixture(t, "before_update:\n  notes:\n    - when: \"mcp_when_started()=1\"\n      sql: \"SELECT 1\"\n", "", "")
	f.app.DB.SetMaxOpenConns(1)
	started := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseWhen := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseWhen)
	conn, err := f.app.DB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Raw(func(raw any) error {
		return raw.(*sqlite3.SQLiteConn).RegisterFunc("mcp_when_started", func() int {
			select {
			case <-started:
			default:
				close(started)
			}
			<-release
			return 1
		}, true)
	}); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	joined := false
	t.Cleanup(func() {
		cancel()
		releaseWhen()
		if !joined {
			joinLifecycleError(t, "when cancellation writer", done)
		}
	})
	before := canonicalEffectsSnapshot(t, f.app)
	go func() {
		_, _, err := applyAppMCPCanonicalUpdate(ctx, f.pin, "notes_update_title", canonicalTitleUpdate("cancel-when"), f.now)
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("when expression never entered its SQLite function")
	}
	cancel()
	releaseWhen()
	err = waitLifecycleError(t, "when cancellation writer", done)
	joined = true
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("when cancellation cause was lost: %v", err)
	}
	if after := canonicalEffectsSnapshot(t, f.app); after != before {
		t.Fatalf("cancelled when evaluation changed effects: before=%s after=%s", before, after)
	}
	// SQLite cancels by discarding the interrupted pooled connection. Reinstall
	// only this test observer on the replacement native connection before the
	// same-source positive; do not treat connection-local UDF state as durable.
	registerCtx, cancelRegister := context.WithTimeout(context.Background(), 5*time.Second)
	conn, err = f.app.DB.Conn(registerCtx)
	cancelRegister()
	if err != nil {
		t.Fatalf("reacquire replacement SQLite connection: %v", err)
	}
	if err := conn.Raw(func(raw any) error {
		return raw.(*sqlite3.SQLiteConn).RegisterFunc("mcp_when_started", func() int { return 1 }, true)
	}); err != nil {
		_ = conn.Close()
		t.Fatalf("reinstall test-only when observer on replacement connection: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("return replacement SQLite connection: %v", err)
	}
	projected, _, err := applyAppMCPCanonicalUpdate(context.Background(), f.pin, "notes_update_title", canonicalTitleUpdate("after-cancel"), f.now)
	if err != nil || projected["title"] != "after-cancel" {
		t.Fatalf("native connection/policy gate did not recover after cancellation: result=%v err=%v", projected, err)
	}
}

func TestAppMCPWritePolicyLeaseIsContextBoundAndReleased(t *testing.T) {
	f := newCanonicalUpdateFixture(t, "", "", "")
	heldCtx, releaseHeld, _, err := acquireAppMCPWritePolicy(context.Background(), f.app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseHeld()
	if _, _, _, err := acquireAppMCPWritePolicy(heldCtx, f.app.Dir); err == nil {
		t.Fatal("same-call policy-gate reentry did not fail promptly")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		close(started)
		_, release, _, acquireErr := acquireAppMCPWritePolicy(ctx, f.app.Dir)
		if release != nil {
			release()
		}
		result <- acquireErr
	}()
	<-started
	if err := waitLifecycleError(t, "contended policy acquisition", result); !errors.Is(err, context.DeadlineExceeded) {
		releaseHeld()
		t.Fatalf("contended policy lease ignored its deadline: %v", err)
	}
	releaseHeld()
	reacquireCtx, cancelReacquire := context.WithTimeout(context.Background(), time.Second)
	defer cancelReacquire()
	_, releaseAgain, _, err := acquireAppMCPWritePolicy(reacquireCtx, f.app.Dir)
	if err != nil {
		t.Fatalf("canceled acquisition leaked policy gate or file lease: %v", err)
	}
	releaseAgain()
}

func TestAppMCPCanonicalUpdateKeepsPrivateSecondaryRefreshScopedAcrossReload(t *testing.T) {
	t.Setenv("BENMORE_CLUSTER", "false")
	hook := "on_update:\n  notes:\n    - sql: |\n        UPDATE group_notes SET title='private refresh marker' WHERE id=1;\n        UPDATE public_notes SET title='public refresh marker' WHERE id=1\n"
	f := newCanonicalUpdateFixture(t, hook, "", "")
	for _, row := range []struct{ org, email string }{{"17", "same@example.com"}, {"18", "foreign@example.com"}} {
		if _, err := f.app.DB.Exec("INSERT INTO main.members(org_id,email) VALUES(?,?)", row.org, row.email); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.app.DB.Exec("INSERT INTO main.group_notes(id,org_id,title) VALUES(1,'17','before')"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.app.DB.Exec("INSERT INTO main.public_notes(id,title) VALUES(1,'before')"); err != nil {
		t.Fatal(err)
	}
	same := subscribeFlowRealtime(t, f.app, createCrudScopeSession(t, f.app, "same@example.com", "editor", "17", ""))
	foreign := subscribeFlowRealtime(t, f.app, createCrudScopeSession(t, f.app, "foreign@example.com", "editor", "18", ""))
	type result struct {
		projected map[string]any
		err       error
	}
	done := make(chan result, 1)
	queryCache.mu.Lock()
	cacheHeld := true
	updateFinished := false
	t.Cleanup(func() {
		if cacheHeld {
			queryCache.mu.Unlock()
		}
		if !updateFinished {
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Errorf("canonical update goroutine did not stop during cleanup")
			}
		}
	})
	oldGeneration := snapshotAppMCPGeneration(f.app)
	go func() {
		projected, _, err := applyAppMCPCanonicalUpdate(context.Background(), f.pin, "notes_update_title", canonicalTitleUpdate("committed"), f.now)
		done <- result{projected: projected, err: err}
	}()
	pollCtx, cancelPoll := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelPoll()
	committed := ""
	for pollCtx.Err() == nil {
		var title string
		if err := f.app.DB.QueryRowContext(pollCtx, "SELECT title FROM main.group_notes WHERE id=1").Scan(&title); err == nil && title == "private refresh marker" {
			committed = title
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if committed != "private refresh marker" {
		queryCache.mu.Unlock()
		cacheHeld = false
		t.Fatalf("canonical SQL hook did not commit before delayed refresh: %q (poll error %v)", committed, pollCtx.Err())
	}
	config, err := os.ReadFile(filepath.Join(f.app.Dir, "app.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	widened := strings.Replace(string(config), "group_notes: {all: group}", "group_notes: {all: everyone}", 1)
	if widened == string(config) {
		t.Fatal("fixture lacks grouped secondary read policy")
	}
	writeTestFile(t, f.app.Dir, "app.yaml", widened)
	reviewAppMCPFixture(t, f.app.Dir)
	if err := reloadAppConfig(f.app); err != nil {
		t.Fatal(err)
	}
	if snapshotAppMCPGeneration(f.app) == oldGeneration || f.app.Access.ModeFor("group_notes", OpRead, false, true) != "everyone" {
		t.Fatal("broader reviewed secondary read policy was not published")
	}
	queryCache.mu.Unlock()
	cacheHeld = false
	select {
	case got := <-done:
		updateFinished = true
		if got.err != nil || got.projected["title"] != "committed" {
			t.Fatalf("canonical update result=%v err=%v", got.projected, got.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("post-commit event stayed blocked after cache release")
	}
	sameSSE, sameWS := same.drain()
	foreignSSE, foreignWS := foreign.drain()
	// notes is explicitly `self`: a tenant colleague of the actor learns only
	// that something changed (the generic refresh), not which table.
	wantSameSSE := []string{`{"table":"","action":"refresh"}`, `{"table":"group_notes","action":"refresh"}`, `{"table":"public_notes","action":"refresh"}`}
	wantSameWS := []string{`{"type":"change","action":"refresh"}`, `{"type":"change","table":"group_notes","action":"refresh"}`, `{"type":"change","table":"public_notes","action":"refresh"}`}
	if !reflect.DeepEqual(sameSSE, wantSameSSE) || !reflect.DeepEqual(sameWS, wantSameWS) {
		t.Fatalf("same-group events SSE=%q WS=%q", sameSSE, sameWS)
	}
	if !reflect.DeepEqual(foreignSSE, []string{`{"table":"public_notes","action":"refresh"}`}) || !reflect.DeepEqual(foreignWS, []string{`{"type":"change","table":"public_notes","action":"refresh"}`}) {
		t.Fatalf("foreign group received a private secondary hint: SSE=%q WS=%q", foreignSSE, foreignWS)
	}
	for _, event := range append(append(sameSSE, sameWS...), append(foreignSSE, foreignWS...)...) {
		if strings.Contains(event, "marker") || strings.Contains(event, "committed") {
			t.Fatalf("refresh event leaked row data: %s", event)
		}
	}
}

func TestAppMCPCanonicalPublicPrimaryDoesNotWidenPrivateSecondaryRefresh(t *testing.T) {
	t.Setenv("BENMORE_CLUSTER", "false")
	hook := "on_update:\n  notes:\n    - sql: |\n        UPDATE group_notes SET title='private refresh marker' WHERE id=1;\n        UPDATE public_notes SET title='public refresh marker' WHERE id=1\n"
	f := newCanonicalUpdateFixture(t, hook, "", "")
	config, err := os.ReadFile(filepath.Join(f.app.Dir, "app.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	widened := strings.Replace(string(config), "notes: {all: self}", "notes: {all: everyone}", 1)
	if widened == string(config) {
		t.Fatal("fixture lacks private primary read policy")
	}
	writeTestFile(t, f.app.Dir, "app.yaml", widened)
	reviewAppMCPFixture(t, f.app.Dir)
	if err := reloadAppConfig(f.app); err != nil {
		t.Fatal(err)
	}
	oldWriteEpoch := f.pin.WriteEpoch
	ownerState, err := currentAppMCPEpoch(f.app.Dir)
	if err != nil || ownerState.ApprovedWrites == nil || *ownerState.ApprovedWrites || ownerState.ApprovedWriteEpoch == oldWriteEpoch {
		t.Fatalf("reviewed source reload did not revoke and rotate write approval: state=%+v err=%v", ownerState, err)
	}
	approvedState, err := setAppMCPApprovedWrites(f.app.Dir, true)
	if err != nil || approvedState.ApprovedWrites == nil || !*approvedState.ApprovedWrites {
		t.Fatalf("owner did not explicitly reapprove the fixture writer: state=%+v err=%v", approvedState, err)
	}
	refreshCanonicalFixturePin(t, &f)
	f.pin.WriteEpoch = approvedState.ApprovedWriteEpoch
	for _, row := range []struct{ org, email string }{{"17", "same@example.com"}, {"18", "foreign@example.com"}} {
		if _, err := f.app.DB.Exec("INSERT INTO main.members(org_id,email) VALUES(?,?)", row.org, row.email); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.app.DB.Exec("INSERT INTO main.group_notes(id,org_id,title) VALUES(1,'17','before')"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.app.DB.Exec("INSERT INTO main.public_notes(id,title) VALUES(1,'before')"); err != nil {
		t.Fatal(err)
	}
	same := subscribeFlowRealtime(t, f.app, createCrudScopeSession(t, f.app, "same@example.com", "editor", "17", ""))
	foreign := subscribeFlowRealtime(t, f.app, createCrudScopeSession(t, f.app, "foreign@example.com", "editor", "18", ""))
	if _, _, err := applyAppMCPCanonicalUpdate(context.Background(), f.pin, "notes_update_title", canonicalTitleUpdate("committed"), f.now); err != nil {
		t.Fatal(err)
	}
	sameSSE, sameWS := same.drain()
	foreignSSE, foreignWS := foreign.drain()
	if !reflect.DeepEqual(sameSSE, []string{`{"table":"notes","action":"update"}`, `{"table":"group_notes","action":"refresh"}`, `{"table":"public_notes","action":"refresh"}`}) || !reflect.DeepEqual(sameWS, []string{`{"type":"change","table":"notes","action":"update"}`, `{"type":"change","table":"group_notes","action":"refresh"}`, `{"type":"change","table":"public_notes","action":"refresh"}`}) {
		t.Fatalf("same-group events SSE=%q WS=%q", sameSSE, sameWS)
	}
	if !reflect.DeepEqual(foreignSSE, []string{`{"table":"notes","action":"update"}`, `{"table":"public_notes","action":"refresh"}`}) || !reflect.DeepEqual(foreignWS, []string{`{"type":"change","table":"notes","action":"update"}`, `{"type":"change","table":"public_notes","action":"refresh"}`}) {
		t.Fatalf("public primary widened private secondary: SSE=%q WS=%q", foreignSSE, foreignWS)
	}
}

func TestAppMCPWriteDeclarationIsNotPubliclyDiscoverableOrConsentable(t *testing.T) {
	f := newCanonicalUpdateFixture(t, "", "", "")
	if got := appMCPSupportedScopes(appMCPManifestSnapshot(f.app)); got != "notes:read" {
		t.Fatalf("public supported scopes included a private write declaration: %q", got)
	}
	readPair, err := createAppMCPGrant(f.app, f.uid, "17", "public-read", grantFixtureResource, "notes:read", f.now)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, grantFixtureResource, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
	request.Header.Set("Authorization", "Bearer "+readPair.AccessToken)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("Mcp-Method", "tools/list")
	request.Header.Set("Mcp-Protocol-Version", "2025-11-25")
	response := httptest.NewRecorder()
	serveAppMCP(response, request, f.app, grantFixtureResource)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "list_notes") || strings.Contains(response.Body.String(), "notes_update_title") {
		t.Fatalf("public SDK did not preserve read-only discovery: %d %s", response.Code, response.Body.String())
	}
	readCall := httptest.NewRequest(http.MethodPost, grantFixtureResource, strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_notes","arguments":{}}}`))
	readCall.Header.Set("Authorization", "Bearer "+readPair.AccessToken)
	readCall.Header.Set("Content-Type", "application/json")
	readCall.Header.Set("Accept", "application/json, text/event-stream")
	readCall.Header.Set("Mcp-Method", "tools/call")
	readCall.Header.Set("Mcp-Protocol-Version", "2025-11-25")
	readBefore := canonicalEffectsSnapshot(t, f.app)
	readResponse := httptest.NewRecorder()
	serveAppMCP(readResponse, readCall, f.app, grantFixtureResource)
	readRPC := decodeCanonicalMCPRPC(t, readResponse)
	var readResult struct {
		IsError    *bool            `json:"isError"`
		Content    json.RawMessage  `json:"content"`
		Structured appMCPReadResult `json:"structuredContent"`
	}
	readDecodeErr := json.Unmarshal(readRPC.Result, &readResult)
	rows, rowsOK := readResult.Structured.Data.([]any)
	firstRow, rowOK := map[string]any(nil), false
	if rowsOK && len(rows) > 0 {
		firstRow, rowOK = rows[0].(map[string]any)
	}
	if readResponse.Code != http.StatusOK || readRPC.Error != nil || readDecodeErr != nil || readResult.IsError != nil && *readResult.IsError || !rowOK || firstRow["id"] != float64(1) || firstRow["title"] != "before" {
		t.Fatalf("public SDK read call did not succeed: %d %+v %s", readResponse.Code, readRPC.Error, readResponse.Body.String())
	}
	if after := canonicalEffectsSnapshot(t, f.app); after != readBefore {
		t.Fatalf("public read call changed state: before=%s after=%s", readBefore, after)
	}
	call := httptest.NewRequest(http.MethodPost, grantFixtureResource, strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"notes_update_title","arguments":{"id":1,"data":{"title":"public-call"}}}}`))
	call.Header.Set("Authorization", "Bearer "+readPair.AccessToken)
	call.Header.Set("Content-Type", "application/json")
	call.Header.Set("Accept", "application/json, text/event-stream")
	call.Header.Set("Mcp-Method", "tools/call")
	call.Header.Set("Mcp-Protocol-Version", "2025-11-25")
	callResponse := httptest.NewRecorder()
	serveAppMCP(callResponse, call, f.app, grantFixtureResource)
	callRPC := decodeCanonicalMCPRPC(t, callResponse)
	if callResponse.Code != http.StatusOK || callRPC.Error == nil || callRPC.Error.Code != -32602 || callRPC.Error.Message != `unknown tool "notes_update_title"` {
		t.Fatalf("read-only grant did not receive exact unknown-tool denial: %d %+v %s", callResponse.Code, callRPC.Error, callResponse.Body.String())
	}
	if after := canonicalEffectsSnapshot(t, f.app); after != readBefore {
		t.Fatalf("read-only grant reached private mutation: before=%s after=%s", readBefore, after)
	}
	if _, err := createAppMCPGrant(f.app, f.uid, "17", "oauth-write", grantFixtureResource, "notes:write", f.now); !errors.Is(err, errAppMCPGrantDenied) {
		t.Fatalf("public OAuth grant accepted a write scope: %v", err)
	}
	f.app.Design = &DesignConfig{Auth: map[string]string{"enabled": "true"}}
	f.app.Paths = DiscoverAuthPaths(nil)
	appOAuthEnsureTables(f.app)
	if _, err := f.app.DB.Exec(`INSERT INTO _benmore_oauth_clients(client_id,name,redirect_uris,scopes) VALUES ('canonical-public-client','Canonical client',?,'notes:read')`, `[`+`"`+mcpOAuthFixtureRedirect+`"`+`]`); err != nil {
		t.Fatal(err)
	}
	mux := buildAppMux(f.app, false, appMCPOAuthHTTPOrigin)
	metadataReq := httptest.NewRequest(http.MethodGet, appMCPOAuthHTTPOrigin+"/.well-known/oauth-authorization-server", nil)
	metadata := httptest.NewRecorder()
	mux.ServeHTTP(metadata, metadataReq)
	if metadata.Code != http.StatusOK || !strings.Contains(metadata.Body.String(), "notes:read") || strings.Contains(metadata.Body.String(), "notes:write") {
		t.Fatalf("registered OAuth metadata exposed private write scope: %d %s", metadata.Code, metadata.Body.String())
	}
	verifier := strings.Repeat("v", 43)
	values := url.Values{
		"response_type": {"code"}, "client_id": {"canonical-public-client"}, "redirect_uri": {mcpOAuthFixtureRedirect},
		"state": {"canonical-state"}, "scope": {"notes:read"}, "code_challenge": {oauthPKCEChallenge(verifier)},
		"code_challenge_method": {"S256"}, "resource": {grantFixtureResource}, "workspace": {"17"},
	}
	consentReq := httptest.NewRequest(http.MethodGet, appMCPOAuthHTTPOrigin+"/oauth/authorize?"+values.Encode(), nil)
	consentReq.AddCookie(sessionCookie(f.sid, false, time.Hour))
	consent := httptest.NewRecorder()
	mux.ServeHTTP(consent, consentReq)
	if consent.Code != http.StatusOK || !strings.Contains(consent.Body.String(), "notes:read") || strings.Contains(consent.Body.String(), "notes:write") {
		t.Fatalf("registered OAuth consent did not present narrowed read grant: %d %s", consent.Code, consent.Body.String())
	}
	values.Set("scope", "notes:write")
	deniedReq := httptest.NewRequest(http.MethodGet, appMCPOAuthHTTPOrigin+"/oauth/authorize?"+values.Encode(), nil)
	deniedReq.AddCookie(sessionCookie(f.sid, false, time.Hour))
	denied := httptest.NewRecorder()
	mux.ServeHTTP(denied, deniedReq)
	if denied.Code != http.StatusBadRequest || strings.Contains(denied.Body.String(), "approve") {
		t.Fatalf("registered OAuth consent accepted or presented private write scope: %d %s", denied.Code, denied.Body.String())
	}
}
