//go:build !cli

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func appMCPOperationStoreFixture(t *testing.T) (*App, []byte) {
	t.Helper()
	app, _ := auditApp(t)
	key, err := cryptoDeriveAppKey(strings.Repeat("42", 32))
	if err != nil {
		t.Fatal(err)
	}
	RegisterDBEncryptionKey(filepath.Join(app.Dir, "data.db"), key)
	tx, err := app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := initializeAppMCPOperationStorage(context.Background(), tx); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.DB.Close() })
	return app, append([]byte(nil), key...)
}

func appMCPOperationStoreRecord(app *App, id string) appMCPPreparedOperationRecord {
	appID, err := appMCPOperationStoreOwnerIDForFixture(app.Dir)
	if err != nil {
		panic(err)
	}
	return appMCPPreparedOperationRecord{
		Version: 1, OperationID: id, AppID: appID,
		Command: "notes.update_title", ContractDigest: strings.Repeat("a", 64), ExecutionDigest: strings.Repeat("b", 64),
		DisclosureVersion: "2026-10", RuntimeAuthority: appMCPOperationRuntimeAuthority{Version: 1, OwnerEpoch: strings.Repeat("c", 64), WriteEpoch: strings.Repeat("d", 64)},
		Origin:    appMCPOperationOriginRecord{Kind: "connector", ActorID: 7, ActorCreated: "2026-01-02T03:04:05Z", Tenant: "17", Permissions: []string{"notes:read", "notes:write"}, GrantID: "grant-fixture", Client: "client-fixture", Resource: "https://example.test/mcp", CredentialHash: strings.Repeat("e", 64)},
		CreatedAt: 1790942400, ExpiresAt: 1790943300, Intent: []byte(`{"note_id":9007199254740993}`),
		Arguments: []byte(`{"rows":[9007199254740993],"title":"marker-private-arguments"}`), Dependencies: []byte(`{"fixtures":[{"revision":"synthetic","table":"notes"}]}`), Preview: []byte(`{"changes":[{"after":"marker-private-preview","field":"title"}]}`),
	}
}

func appMCPOperationStoreOwnerIDForFixture(dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	return hashBytesSHA256([]byte(realPathForContainment(abs))), nil
}

func appMCPInsertOperationTest(t *testing.T, ctx context.Context, tx *sql.Tx, app *App, record appMCPPreparedOperationRecord) (*appMCPStoredOperation, error) {
	t.Helper()
	return insertAppMCPPreparedOperation(ctx, tx, app, record)
}

func appMCPStoreReadTest(t *testing.T, ctx context.Context, tx *sql.Tx, app *App, id string) (*appMCPStoredOperation, error) {
	t.Helper()
	return readAppMCPStoredOperation(ctx, tx, app, id)
}

func appMCPBeginOperationTest(t *testing.T, app *App) *sql.Tx {
	t.Helper()
	tx, err := app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	return tx
}

func TestAppMCPOperationStoreRoundTripAndSchemaLifecycle(t *testing.T) {
	app, _ := appMCPOperationStoreFixture(t)
	app.DB.SetMaxOpenConns(1)
	record := appMCPOperationStoreRecord(app, strings.Repeat("1", 64))
	tx := appMCPBeginOperationTest(t, app)
	first, err := appMCPInsertOperationTest(t, context.Background(), tx, app, record)
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if first.Prepared.ExpiresAt-first.Prepared.CreatedAt != 15*60 {
		t.Fatal("prepared lifetime changed")
	}
	if !bytes.Contains(first.Prepared.Arguments, []byte("9007199254740993")) {
		t.Fatal("typed large integer was rounded")
	}
	var preparedCipher string
	if err := app.DB.QueryRow("SELECT prepared_ciphertext FROM main._benmore_mcp_operations WHERE operation_id=?", record.OperationID).Scan(&preparedCipher); err != nil {
		t.Fatal(err)
	}
	plain, err := appMCPOpenOperation(cryptoKeysForDBPath(filepath.Join(app.Dir, "data.db")).aes, "prepared_ciphertext", preparedCipher)
	if err != nil {
		t.Fatal(err)
	}
	var envelope map[string]any
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.UseNumber()
	if err := decoder.Decode(&envelope); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"intent", "arguments", "dependencies", "preview"} {
		if _, ok := envelope[field].(map[string]any); !ok {
			t.Fatalf("decrypted %s is not a native JSON object: %T", field, envelope[field])
		}
	}
	argumentObject := envelope["arguments"].(map[string]any)
	rows := argumentObject["rows"].([]any)
	if rows[0] != json.Number("9007199254740993") {
		t.Fatalf("prepared array number lost precision: %#v", rows[0])
	}
	numeric := record
	numeric.OperationID = strings.Repeat("f", 64)
	numeric.Intent = []byte(`{"note_id":9007199254740993,"ratio":1.0}`)
	tx = appMCPBeginOperationTest(t, app)
	if _, err := appMCPInsertOperationTest(t, context.Background(), tx, app, numeric); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	tx = appMCPBeginOperationTest(t, app)
	numericRead, err := appMCPStoreReadTest(t, context.Background(), tx, app, numeric.OperationID)
	if err != nil || !bytes.Equal(numericRead.Prepared.Intent, numeric.Intent) {
		tx.Rollback()
		t.Fatalf("exact numeric spelling did not round trip: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	readTx := appMCPBeginOperationTest(t, app)
	if err := verifyAppMCPOperationStorage(context.Background(), readTx); err != nil {
		readTx.Rollback()
		t.Fatal(err)
	}
	got, err := appMCPStoreReadTest(t, context.Background(), readTx, app, record.OperationID)
	if err != nil {
		readTx.Rollback()
		t.Fatal(err)
	}
	if !bytes.Equal(got.Prepared.Arguments, record.Arguments) || !bytes.Equal(got.Prepared.Intent, record.Intent) || !bytes.Equal(got.Prepared.Dependencies, record.Dependencies) || !bytes.Equal(got.Prepared.Preview, record.Preview) || got.PreparedDigest != first.PreparedDigest {
		readTx.Rollback()
		t.Fatal("prepared binding bytes changed")
	}
	if err := readTx.Commit(); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(preparedCipher, encPrefixV2) || strings.Contains(preparedCipher, "marker-private") || strings.Contains(preparedCipher, "9007199254740993") {
		t.Fatal("prepared values were not stored only as v2 ciphertext")
	}
	bootstrap := appMCPBeginOperationTest(t, app)
	if err := initializeAppMCPOperationStorage(context.Background(), bootstrap); err == nil {
		bootstrap.Rollback()
		t.Fatal("second bootstrap repaired or accepted existing storage")
	}
	bootstrap.Rollback()
	if _, err := app.DB.Exec("CREATE TRIGGER operation_fixture AFTER UPDATE ON _benmore_mcp_operations BEGIN SELECT 1; END"); err != nil {
		t.Fatal(err)
	}
	check := appMCPBeginOperationTest(t, app)
	if err := verifyAppMCPOperationStorage(context.Background(), check); err == nil {
		check.Rollback()
		t.Fatal("trigger on internal store accepted")
	}
	check.Rollback()
}

func TestAppMCPOperationStoreMissingAlteredAndPartialSchemaRefused(t *testing.T) {
	app, key := appMCPOperationStoreFixture(t)
	app.DB.SetMaxOpenConns(1)
	path := filepath.Join(app.Dir, "data.db")
	if err := app.DB.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	reopenedDB, err := sql.Open("sqlite3", path+"?_journal_mode=WAL&_busy_timeout=5000&_txlock=immediate")
	if err != nil {
		t.Fatal(err)
	}
	app.DB = reopenedDB
	RegisterDBEncryptionKey(path, key)
	tx := appMCPBeginOperationTest(t, app)
	if err := verifyAppMCPOperationStorage(context.Background(), tx); err == nil {
		tx.Rollback()
		t.Fatal("missing table passed verification")
	}
	if err := initializeAppMCPOperationStorage(context.Background(), tx); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec("ALTER TABLE _benmore_mcp_operations RENAME TO _benmore_mcp_operations_old"); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec("CREATE TABLE _benmore_mcp_operations(operation_id TEXT)"); err != nil {
		t.Fatal(err)
	}
	tx = appMCPBeginOperationTest(t, app)
	if err := verifyAppMCPOperationStorage(context.Background(), tx); err == nil {
		tx.Rollback()
		t.Fatal("altered table passed verification")
	}
	tx.Rollback()
	if _, err := app.DB.Exec("DROP TABLE _benmore_mcp_operations"); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec("DROP TABLE _benmore_mcp_operations_old"); err != nil {
		t.Fatal(err)
	}
	tx = appMCPBeginOperationTest(t, app)
	if err := initializeAppMCPOperationStorage(context.Background(), tx); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	r := appMCPOperationStoreRecord(app, strings.Repeat("a", 64))
	tx = appMCPBeginOperationTest(t, app)
	stored, err := appMCPInsertOperationTest(t, context.Background(), tx, app, r)
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec("PRAGMA ignore_check_constraints=ON"); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec("UPDATE _benmore_mcp_operations SET receipt_digest=? WHERE operation_id=?", strings.Repeat("b", 64), r.OperationID); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec("PRAGMA ignore_check_constraints=OFF"); err != nil {
		t.Fatal(err)
	}
	tx = appMCPBeginOperationTest(t, app)
	if _, err := readAppMCPStoredOperation(context.Background(), tx, app, r.OperationID); err == nil {
		tx.Rollback()
		t.Fatal("partial receipt column pair accepted")
	}
	tx.Rollback()
	if stored.PreparedDigest == "" {
		t.Fatal("prepared digest missing")
	}
}

func TestAppMCPOperationStoreOwnerIdentityUsesAbsoluteResolvedPath(t *testing.T) {
	app, _ := appMCPOperationStoreFixture(t)
	got, err := appMCPOperationOwnerID(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	abs, err := filepath.Abs(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	want := hashBytesSHA256([]byte(realPathForContainment(abs)))
	if got != want {
		t.Fatal("owner identity differs from authority's absolute resolved-path calculation")
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	relative, err := filepath.Rel(cwd, app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	fromRelative, err := appMCPOperationOwnerID(relative)
	if err != nil || fromRelative != want {
		t.Fatalf("relative path identity mismatch: %v", err)
	}
	symlink := filepath.Join(t.TempDir(), "app-link")
	if err := os.Symlink(app.Dir, symlink); err != nil {
		t.Fatal(err)
	}
	fromSymlink, err := appMCPOperationOwnerID(symlink)
	if err != nil || fromSymlink != want {
		t.Fatalf("symlink path identity mismatch: %v", err)
	}
}

func TestAppMCPOperationStoreRejectsNoncanonicalAndInvalidBindings(t *testing.T) {
	app, _ := appMCPOperationStoreFixture(t)
	valid := appMCPOperationStoreRecord(app, strings.Repeat("2", 64))
	if err := appMCPValidateOperationRecord(valid, valid.AppID); err != nil {
		t.Fatalf("positive control rejected: %v", err)
	}
	badBytes := [][]byte{[]byte(`{"x": 1}`), []byte(`{"x":1,"x":2}`), []byte(`{"x":1} {}`), []byte(`[]`), []byte(`null`), []byte(`"{}"`), []byte("{\"x\":\"\xff\"}")}
	for _, data := range badBytes {
		if appMCPValidateOperationRecord(func() appMCPPreparedOperationRecord { r := valid; r.Intent = data; return r }(), valid.AppID) == nil {
			t.Fatalf("invalid canonical intent accepted: %q", data)
		}
	}
	bad := []func(*appMCPPreparedOperationRecord){
		func(r *appMCPPreparedOperationRecord) { r.Version = 2 },
		func(r *appMCPPreparedOperationRecord) { r.OperationID = "ABC" },
		func(r *appMCPPreparedOperationRecord) { r.AppID = strings.Repeat("f", 64) },
		func(r *appMCPPreparedOperationRecord) { r.Command = "" },
		func(r *appMCPPreparedOperationRecord) { r.ContractDigest = "bad" },
		func(r *appMCPPreparedOperationRecord) { r.ExecutionDigest = "bad" },
		func(r *appMCPPreparedOperationRecord) { r.DisclosureVersion = "" },
		func(r *appMCPPreparedOperationRecord) { r.RuntimeAuthority.OwnerEpoch = "" },
		func(r *appMCPPreparedOperationRecord) { r.RuntimeAuthority.WriteEpoch = "" },
		func(r *appMCPPreparedOperationRecord) { r.Origin.Kind = "unknown" },
		func(r *appMCPPreparedOperationRecord) { r.Origin.ActorID = 0 },
		func(r *appMCPPreparedOperationRecord) { r.Origin.ActorCreated = "" },
		func(r *appMCPPreparedOperationRecord) { r.Origin.Tenant = "\xff" },
		func(r *appMCPPreparedOperationRecord) { r.Origin.Permissions = []string{"notes:write", "notes:read"} },
		func(r *appMCPPreparedOperationRecord) { r.Origin.Permissions = []string{"notes:read", "notes:read"} },
		func(r *appMCPPreparedOperationRecord) { r.Origin.Permissions = []string{"notes:read other:read"} },
		func(r *appMCPPreparedOperationRecord) { r.Origin.Permissions = []string{"_none_:read"} },
		func(r *appMCPPreparedOperationRecord) { r.Origin.GrantID = "" },
		func(r *appMCPPreparedOperationRecord) { r.Origin.Client = "" },
		func(r *appMCPPreparedOperationRecord) { r.Origin.Resource = "" },
		func(r *appMCPPreparedOperationRecord) { r.Origin.CredentialHash = "" },
		func(r *appMCPPreparedOperationRecord) { r.Origin.SessionID = "sha256:" + strings.Repeat("f", 64) },
		func(r *appMCPPreparedOperationRecord) { r.Origin.SessionID = "sha256:bad" },
		func(r *appMCPPreparedOperationRecord) { r.ExpiresAt++ },
		func(r *appMCPPreparedOperationRecord) {
			r.CreatedAt = int64(^uint64(0) >> 1)
			r.ExpiresAt = r.CreatedAt
		},
		func(r *appMCPPreparedOperationRecord) { r.Arguments = bytes.Repeat([]byte("x"), appMCPInputLimit+1) },
	}
	for i, mutate := range bad {
		r := appMCPCopyOperationRecord(valid)
		r.OperationID = fmt.Sprintf("%064x", i+20)
		mutate(&r)
		tx := appMCPBeginOperationTest(t, app)
		if _, err := appMCPInsertOperationTest(t, context.Background(), tx, app, r); err == nil {
			tx.Rollback()
			t.Fatalf("invalid record %d inserted", i)
		}
		var count int
		if err := tx.QueryRow("SELECT count(*) FROM main._benmore_mcp_operations").Scan(&count); err != nil || count != 0 {
			tx.Rollback()
			t.Fatalf("invalid record %d added a row", i)
		}
		if err := tx.Rollback(); err != nil {
			t.Fatal(err)
		}
	}
	appSession := valid
	appSession.Origin = appMCPOperationOriginRecord{Kind: "app_session", ActorID: 7, ActorCreated: "2026-01-02T03:04:05Z", Tenant: "17", Permissions: []string{"notes:read"}, SessionID: sessionStorageKey("native-cookie-fixture")}
	if err := appMCPValidateOperationRecord(appSession, appSession.AppID); err != nil {
		t.Fatalf("source-shaped hashed session key rejected: %v", err)
	}
	appSession.OperationID = strings.Repeat("a", 64)
	tx := appMCPBeginOperationTest(t, app)
	if _, err := appMCPInsertOperationTest(t, context.Background(), tx, app, appSession); err != nil {
		tx.Rollback()
		t.Fatalf("valid app-session insert: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	tx = appMCPBeginOperationTest(t, app)
	sessionRead, err := appMCPStoreReadTest(t, context.Background(), tx, app, appSession.OperationID)
	if err != nil || sessionRead.Prepared.Origin.SessionID != appSession.Origin.SessionID {
		tx.Rollback()
		t.Fatalf("valid app-session reopen: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	for i, mutate := range []func(*appMCPOperationOriginRecord){
		func(o *appMCPOperationOriginRecord) { o.SessionID = sessionKeyPrefix + strings.Repeat("A", 64) },
		func(o *appMCPOperationOriginRecord) { o.SessionID = sessionKeyPrefix + strings.Repeat("a", 63) },
		func(o *appMCPOperationOriginRecord) { o.SessionID = "raw-native-cookie" },
		func(o *appMCPOperationOriginRecord) { o.SessionID = "" },
		func(o *appMCPOperationOriginRecord) { o.GrantID = "mixed-connector" },
	} {
		candidate := appMCPCopyOperationRecord(appSession)
		candidate.OperationID = fmt.Sprintf("%064x", i+100)
		mutate(&candidate.Origin)
		tx = appMCPBeginOperationTest(t, app)
		if _, err := appMCPInsertOperationTest(t, context.Background(), tx, app, candidate); err == nil {
			tx.Rollback()
			t.Fatalf("malformed app-session discriminator %d accepted", i)
		}
		if err := tx.Rollback(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAppMCPOperationStoreCopiesAndExactRetry(t *testing.T) {
	app, _ := appMCPOperationStoreFixture(t)
	r := appMCPOperationStoreRecord(app, strings.Repeat("3", 64))
	originalArguments := bytes.Clone(r.Arguments)
	tx := appMCPBeginOperationTest(t, app)
	first, err := appMCPInsertOperationTest(t, context.Background(), tx, app, r)
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	r.Arguments[2] = 'z'
	r.Origin.Permissions[0] = "corrupted:scope"
	first.Prepared.Preview[2] = 'x'
	first.Prepared.Origin.Permissions[0] = "mutated:scope"
	retry := appMCPOperationStoreRecord(app, strings.Repeat("3", 64))
	tx = appMCPBeginOperationTest(t, app)
	second, err := appMCPInsertOperationTest(t, context.Background(), tx, app, retry)
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(second.Prepared.Arguments, originalArguments) || second.Prepared.ExpiresAt != first.Prepared.ExpiresAt {
		t.Fatal("input or returned mutation changed stored bytes")
	}
	mutations := []func(*appMCPPreparedOperationRecord){
		func(x *appMCPPreparedOperationRecord) { x.Command += ".other" },
		func(x *appMCPPreparedOperationRecord) { x.ContractDigest = strings.Repeat("f", 64) },
		func(x *appMCPPreparedOperationRecord) { x.ExecutionDigest = strings.Repeat("f", 64) },
		func(x *appMCPPreparedOperationRecord) { x.DisclosureVersion += ".other" },
		func(x *appMCPPreparedOperationRecord) { x.RuntimeAuthority.OwnerEpoch = strings.Repeat("f", 64) },
		func(x *appMCPPreparedOperationRecord) { x.RuntimeAuthority.WriteEpoch = strings.Repeat("f", 64) },
		func(x *appMCPPreparedOperationRecord) { x.Origin.ActorID++ },
		func(x *appMCPPreparedOperationRecord) {
			x.Origin.Kind = "app_session"
			x.Origin.GrantID = ""
			x.Origin.Client = ""
			x.Origin.Resource = ""
			x.Origin.CredentialHash = ""
			x.Origin.SessionID = sessionStorageKey("same-id-new-origin")
		},
		func(x *appMCPPreparedOperationRecord) { x.Origin.ActorCreated += "x" },
		func(x *appMCPPreparedOperationRecord) { x.Origin.Tenant = "18" },
		func(x *appMCPPreparedOperationRecord) { x.Origin.Permissions = []string{"notes:read", "tasks:write"} },
		func(x *appMCPPreparedOperationRecord) { x.Origin.GrantID += ".other" },
		func(x *appMCPPreparedOperationRecord) { x.Origin.Client += ".other" },
		func(x *appMCPPreparedOperationRecord) { x.Origin.Resource += "/other" },
		func(x *appMCPPreparedOperationRecord) { x.Origin.CredentialHash = strings.Repeat("f", 64) },
		func(x *appMCPPreparedOperationRecord) { x.CreatedAt++; x.ExpiresAt++ },
		func(x *appMCPPreparedOperationRecord) { x.Intent = []byte(`{"note_id":9007199254740994}`) },
		func(x *appMCPPreparedOperationRecord) {
			x.Arguments = []byte(`{"rows":[9007199254740993],"title":"different"}`)
		},
		func(x *appMCPPreparedOperationRecord) {
			x.Dependencies = []byte(`{"fixtures":[{"revision":"changed","table":"notes"}]}`)
		},
		func(x *appMCPPreparedOperationRecord) {
			x.Preview = []byte(`{"changes":[{"after":"changed","field":"title"}]}`)
		},
	}
	for i, mutate := range mutations {
		candidate := appMCPOperationStoreRecord(app, strings.Repeat("3", 64))
		mutate(&candidate)
		tx = appMCPBeginOperationTest(t, app)
		if _, err := appMCPInsertOperationTest(t, context.Background(), tx, app, candidate); err == nil {
			tx.Rollback()
			t.Fatalf("changed binding %d did not conflict", i)
		}
		tx.Rollback()
	}
}

func TestAppMCPOperationStoreInsertErrorIsNotDuplicateSuccess(t *testing.T) {
	app, _ := appMCPOperationStoreFixture(t)
	app.DB.SetMaxOpenConns(1)
	record := appMCPOperationStoreRecord(app, strings.Repeat("c", 64))
	tx := appMCPBeginOperationTest(t, app)
	first, err := insertAppMCPPreparedOperation(context.Background(), tx, app, record)
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	tx = appMCPBeginOperationTest(t, app)
	if _, err := tx.Exec("PRAGMA query_only=ON"); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if got, err := insertAppMCPPreparedOperation(context.Background(), tx, app, record); err == nil || got != nil {
		tx.Rollback()
		t.Fatal("query-only refused INSERT was incorrectly reported as idempotent success")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec("PRAGMA query_only=OFF"); err != nil {
		t.Fatal(err)
	}
	check := appMCPBeginOperationTest(t, app)
	got, err := readAppMCPStoredOperation(context.Background(), check, app, record.OperationID)
	if err != nil || got.PreparedDigest != first.PreparedDigest || !bytes.Equal(got.Prepared.Arguments, record.Arguments) {
		check.Rollback()
		t.Fatalf("read-only failure changed matching row: %v", err)
	}
	if err := check.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestAppMCPOperationStoreReceiptTransactionAndExpiry(t *testing.T) {
	app, _ := appMCPOperationStoreFixture(t)
	if _, err := app.DB.Exec("CREATE TABLE operation_store_sentinel(value TEXT)"); err != nil {
		t.Fatal(err)
	}
	r := appMCPOperationStoreRecord(app, strings.Repeat("4", 64))
	tx := appMCPBeginOperationTest(t, app)
	prepared, err := appMCPInsertOperationTest(t, context.Background(), tx, app, r)
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	receipt := []byte(`{"result":{"status":"fixture"}}`)
	constraintTx := appMCPBeginOperationTest(t, app)
	if _, err := constraintTx.Exec("INSERT INTO operation_store_sentinel VALUES('constraint-failure')"); err != nil {
		constraintTx.Rollback()
		t.Fatal(err)
	}
	if _, err := constraintTx.Exec("UPDATE main._benmore_mcp_operations SET receipt_digest='invalid' WHERE operation_id=?", r.OperationID); err == nil {
		constraintTx.Rollback()
		t.Fatal("invalid digest bypassed native SQL constraint")
	}
	if err := constraintTx.Rollback(); err != nil {
		t.Fatal(err)
	}
	constraintCheck := appMCPBeginOperationTest(t, app)
	var constraintSentinel int
	if err := constraintCheck.QueryRow("SELECT count(*) FROM operation_store_sentinel").Scan(&constraintSentinel); err != nil || constraintSentinel != 0 {
		constraintCheck.Rollback()
		t.Fatal("SQL constraint failure left sentinel change")
	}
	constraintRead, err := appMCPStoreReadTest(t, context.Background(), constraintCheck, app, r.OperationID)
	if err != nil || constraintRead.Receipt != nil {
		constraintCheck.Rollback()
		t.Fatal("SQL constraint failure left receipt")
	}
	if err := constraintCheck.Commit(); err != nil {
		t.Fatal(err)
	}
	tx = appMCPBeginOperationTest(t, app)
	if _, err := tx.Exec("INSERT INTO operation_store_sentinel VALUES('rollback')"); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	candidate, err := storeAppMCPCommittedReceipt(context.Background(), tx, app, r.OperationID, prepared.PreparedDigest, receipt)
	if err != nil || !bytes.Equal(candidate.Receipt, receipt) {
		tx.Rollback()
		t.Fatalf("transaction-local receipt candidate: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	tx = appMCPBeginOperationTest(t, app)
	read, err := appMCPStoreReadTest(t, context.Background(), tx, app, r.OperationID)
	if err != nil || read.Receipt != nil {
		tx.Rollback()
		t.Fatalf("rollback left receipt: %v", err)
	}
	var sentinel int
	if err := tx.QueryRow("SELECT count(*) FROM operation_store_sentinel").Scan(&sentinel); err != nil || sentinel != 0 {
		tx.Rollback()
		t.Fatal("rollback left sentinel")
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	tx = appMCPBeginOperationTest(t, app)
	if _, err := tx.Exec("INSERT INTO operation_store_sentinel VALUES('commit')"); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	stored, err := storeAppMCPCommittedReceipt(context.Background(), tx, app, r.OperationID, prepared.PreparedDigest, receipt)
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if stored.ReceiptDigest != appMCPOperationDigest("benmore:mcp:receipt:v1", receipt) {
		t.Fatal("receipt digest mismatch")
	}
	tx = appMCPBeginOperationTest(t, app)
	retryPrepared, err := appMCPInsertOperationTest(t, context.Background(), tx, app, r)
	if err != nil || !bytes.Equal(retryPrepared.Receipt, receipt) || retryPrepared.Prepared.ExpiresAt != r.ExpiresAt {
		tx.Rollback()
		t.Fatalf("prepared retry changed existing receipt or expiry: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	tx = appMCPBeginOperationTest(t, app)
	again, err := storeAppMCPCommittedReceipt(context.Background(), tx, app, r.OperationID, prepared.PreparedDigest, receipt)
	if err != nil || !bytes.Equal(again.Receipt, receipt) {
		tx.Rollback()
		t.Fatalf("identical receipt retry: %v", err)
	}
	if _, err := storeAppMCPCommittedReceipt(context.Background(), tx, app, r.OperationID, prepared.PreparedDigest, []byte(`{"result":{"status":"other"}}`)); err == nil {
		tx.Rollback()
		t.Fatal("changed receipt accepted")
	}
	if _, err := storeAppMCPCommittedReceipt(context.Background(), tx, app, r.OperationID, strings.Repeat("f", 64), receipt); err == nil {
		tx.Rollback()
		t.Fatal("changed prepared digest accepted")
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	tx = appMCPBeginOperationTest(t, app)
	var committedSentinels int
	if err := tx.QueryRow("SELECT count(*) FROM operation_store_sentinel WHERE value='commit'").Scan(&committedSentinels); err != nil || committedSentinels != 1 {
		tx.Rollback()
		t.Fatal("committed sentinel was not durable exactly once")
	}
	committedRead, err := readAppMCPStoredOperation(context.Background(), tx, app, r.OperationID)
	if err != nil || !bytes.Equal(committedRead.Receipt, receipt) {
		tx.Rollback()
		t.Fatalf("receipt was not committed with sentinel: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	old := appMCPOperationStoreRecord(app, strings.Repeat("5", 64))
	old.CreatedAt = 100
	old.ExpiresAt = 100 + 15*60
	tx = appMCPBeginOperationTest(t, app)
	oldPrepared, err := appMCPInsertOperationTest(t, context.Background(), tx, app, old)
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if _, err := storeAppMCPCommittedReceipt(context.Background(), tx, app, old.OperationID, oldPrepared.PreparedDigest, []byte(`{"result":"expired-history"}`)); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	tx = appMCPBeginOperationTest(t, app)
	got, err := appMCPStoreReadTest(t, context.Background(), tx, app, old.OperationID)
	if err != nil || got.Prepared.ExpiresAt != old.ExpiresAt || !bytes.Equal(got.Receipt, []byte(`{"result":"expired-history"}`)) {
		tx.Rollback()
		t.Fatalf("expired committed receipt recovery refused: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestAppMCPOperationStoreIndependentConnectionRacesAndPoolReuse(t *testing.T) {
	app, _ := appMCPOperationStoreFixture(t)
	app.DB.SetMaxOpenConns(1)
	if _, err := app.DB.Exec("CREATE TABLE operation_store_sentinel(value TEXT)"); err != nil {
		t.Fatal(err)
	}
	secondDB, err := sql.Open("sqlite3", filepath.Join(app.Dir, "data.db")+"?_journal_mode=WAL&_busy_timeout=5000&_txlock=immediate")
	if err != nil {
		t.Fatal(err)
	}
	defer secondDB.Close()
	record := appMCPOperationStoreRecord(app, strings.Repeat("6", 64))
	start := make(chan struct{})
	type raceResult struct {
		db     *sql.DB
		stored *appMCPStoredOperation
		err    error
	}
	results := make(chan raceResult, 2)
	for _, db := range []*sql.DB{app.DB, secondDB} {
		go func(db *sql.DB) {
			<-start
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			tx, beginErr := db.BeginTx(ctx, nil)
			if beginErr != nil {
				results <- raceResult{db: db, err: beginErr}
				return
			}
			value, insertErr := insertAppMCPPreparedOperation(ctx, tx, app, record)
			if insertErr != nil {
				tx.Rollback()
				results <- raceResult{db: db, err: insertErr}
				return
			}
			if commitErr := tx.Commit(); commitErr != nil {
				results <- raceResult{db: db, err: commitErr}
				return
			}
			results <- raceResult{db: db, stored: value}
		}(db)
	}
	close(start)
	a, b := <-results, <-results
	if a.err != nil || b.err != nil || a.stored == nil || b.stored == nil || a.stored.PreparedDigest != b.stored.PreparedDigest {
		t.Fatalf("concurrent exact insert: %#v %#v", a.err, b.err)
	}
	receipts := [][]byte{[]byte(`{"winner":"a"}`), []byte(`{"winner":"b"}`)}
	start = make(chan struct{})
	attach := make(chan error, 2)
	for i, db := range []*sql.DB{app.DB, secondDB} {
		go func(db *sql.DB, receipt []byte) {
			<-start
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			tx, e := db.BeginTx(ctx, nil)
			if e != nil {
				attach <- e
				return
			}
			if _, e = tx.ExecContext(ctx, "INSERT INTO operation_store_sentinel(value) VALUES('competing-receipt')"); e != nil {
				tx.Rollback()
				attach <- e
				return
			}
			_, e = storeAppMCPCommittedReceipt(ctx, tx, app, record.OperationID, a.stored.PreparedDigest, receipt)
			if e != nil {
				tx.Rollback()
				attach <- e
				return
			}
			attach <- tx.Commit()
		}(db, receipts[i])
	}
	close(start)
	e1, e2 := <-attach, <-attach
	if (e1 == nil) == (e2 == nil) {
		t.Fatalf("competing receipts must yield exactly one successful commit: %v / %v", e1, e2)
	}
	loser := e1
	if loser == nil {
		loser = e2
	}
	if loser == nil || loser.Error() != "operation storage receipt conflicts with immutable receipt" {
		t.Fatalf("losing receipt was not an immutable conflict: %v", loser)
	}
	var receiptCipherBefore string
	if err := app.DB.QueryRow("SELECT receipt_ciphertext FROM main._benmore_mcp_operations WHERE operation_id=?", record.OperationID).Scan(&receiptCipherBefore); err != nil {
		t.Fatal(err)
	}
	tx := appMCPBeginOperationTest(t, app)
	read, err := readAppMCPStoredOperation(context.Background(), tx, app, record.OperationID)
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if !bytes.Equal(read.Receipt, receipts[0]) && !bytes.Equal(read.Receipt, receipts[1]) {
		tx.Rollback()
		t.Fatal("competing receipt did not persist exactly one supplied value")
	}
	if read.PreparedDigest != a.stored.PreparedDigest {
		tx.Rollback()
		t.Fatal("competing receipt changed prepared binding")
	}
	var sentinelCount int
	if err := tx.QueryRow("SELECT count(*) FROM operation_store_sentinel WHERE value='competing-receipt'").Scan(&sentinelCount); err != nil || sentinelCount != 1 {
		tx.Rollback()
		t.Fatal("receipt and sentinel were not committed exactly once")
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	start = make(chan struct{})
	same := make(chan error, 2)
	stableReceipt := bytes.Clone(read.Receipt)
	for _, db := range []*sql.DB{app.DB, secondDB} {
		go func(db *sql.DB) {
			<-start
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			tx, e := db.BeginTx(ctx, nil)
			if e != nil {
				same <- e
				return
			}
			_, e = storeAppMCPCommittedReceipt(ctx, tx, app, record.OperationID, a.stored.PreparedDigest, stableReceipt)
			if e != nil {
				tx.Rollback()
				same <- e
				return
			}
			same <- tx.Commit()
		}(db)
	}
	close(start)
	s1, s2 := <-same, <-same
	if s1 != nil || s2 != nil {
		t.Fatalf("identical concurrent receipt retries must both read back: %v / %v", s1, s2)
	}
	var receiptCipherAfter string
	if err := app.DB.QueryRow("SELECT receipt_ciphertext FROM main._benmore_mcp_operations WHERE operation_id=?", record.OperationID).Scan(&receiptCipherAfter); err != nil {
		t.Fatal(err)
	}
	if receiptCipherAfter != receiptCipherBefore {
		t.Fatal("identical receipt retries rewrote immutable ciphertext")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	tx = appMCPBeginOperationTest(t, app)
	if _, err := readAppMCPStoredOperation(canceled, tx, app, record.OperationID); err == nil {
		tx.Rollback()
		t.Fatal("canceled context accepted")
	}
	tx.Rollback()
	if _, err := app.DB.Exec("INSERT INTO operation_store_sentinel(value) VALUES('pool-reused')"); err != nil {
		t.Fatalf("MaxConns1 pool was not reusable: %v", err)
	}
}

func TestAppMCPOperationStoreDurableKeysAndCorruptionFailClosed(t *testing.T) {
	app, key := appMCPOperationStoreFixture(t)
	r1 := appMCPOperationStoreRecord(app, strings.Repeat("7", 64))
	r2 := appMCPOperationStoreRecord(app, strings.Repeat("8", 64))
	prepared1, digest1, _ := appMCPEncodePrepared(r1)
	_, digest2, _ := appMCPEncodePrepared(r2)
	for _, r := range []appMCPPreparedOperationRecord{r1, r2} {
		tx := appMCPBeginOperationTest(t, app)
		if _, err := insertAppMCPPreparedOperation(context.Background(), tx, app, r); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	receipt1, receipt2 := []byte(`{"ok":true}`), []byte(`{"ok":false}`)
	for _, item := range []struct {
		r       appMCPPreparedOperationRecord
		digest  string
		receipt []byte
	}{{r1, digest1, receipt1}, {r2, digest2, receipt2}} {
		tx := appMCPBeginOperationTest(t, app)
		if _, err := storeAppMCPCommittedReceipt(context.Background(), tx, app, item.r.OperationID, item.digest, item.receipt); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(app.Dir, "data.db")
	keyPath := canonicalDBPath(path)
	previousKeyState := cryptoKeysForDBPath(path)
	t.Cleanup(func() {
		if previousKeyState == nil {
			dbCryptoRegistry.Delete(keyPath)
		} else {
			dbCryptoRegistry.Store(keyPath, previousKeyState)
		}
	})
	if err := app.DB.Close(); err != nil {
		t.Fatal(err)
	}
	reopenedDB, err := sql.Open("sqlite3", path+"?_journal_mode=WAL&_busy_timeout=5000&_txlock=immediate")
	if err != nil {
		t.Fatal(err)
	}
	app.DB = reopenedDB
	RegisterDBEncryptionKey(path, key)
	tx := appMCPBeginOperationTest(t, app)
	got, err := readAppMCPStoredOperation(context.Background(), tx, app, r1.OperationID)
	if err != nil || !bytes.Equal(got.Receipt, receipt1) {
		tx.Rollback()
		t.Fatalf("reopen round trip: %v", err)
	}
	if _, err := readAppMCPStoredOperation(context.Background(), tx, app, r2.OperationID); err != nil {
		tx.Rollback()
		t.Fatalf("second durable round trip: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	wrong, _ := cryptoDeriveAppKey(strings.Repeat("99", 32))
	RegisterDBEncryptionKey(path, wrong)
	tx = appMCPBeginOperationTest(t, app)
	if _, err := readAppMCPStoredOperation(context.Background(), tx, app, r1.OperationID); err == nil {
		tx.Rollback()
		t.Fatal("wrong key accepted")
	}
	tx.Rollback()
	registerDBEncryptionKey(path, key, true)
	tx = appMCPBeginOperationTest(t, app)
	if _, err := readAppMCPStoredOperation(context.Background(), tx, app, r1.OperationID); err == nil {
		tx.Rollback()
		t.Fatal("ephemeral key accepted")
	}
	tx.Rollback()
	RegisterDBEncryptionKey(path, key)
	keys := cryptoKeysForDBPath(path)
	dbCryptoRegistry.Delete(canonicalDBPath(path))
	tx = appMCPBeginOperationTest(t, app)
	if _, err := readAppMCPStoredOperation(context.Background(), tx, app, r1.OperationID); err == nil {
		tx.Rollback()
		t.Fatal("missing key accepted")
	}
	tx.Rollback()
	dbCryptoRegistry.Store(canonicalDBPath(path), keys)
	var cipher1, cipher2, receiptCipher1, receiptCipher2 string
	if err := app.DB.QueryRow("SELECT prepared_ciphertext,receipt_ciphertext FROM main._benmore_mcp_operations WHERE operation_id=?", r1.OperationID).Scan(&cipher1, &receiptCipher1); err != nil {
		t.Fatal(err)
	}
	if err := app.DB.QueryRow("SELECT prepared_ciphertext,receipt_ciphertext FROM main._benmore_mcp_operations WHERE operation_id=?", r2.OperationID).Scan(&cipher2, &receiptCipher2); err != nil {
		t.Fatal(err)
	}
	assertRead := func(id string, wantReceipt []byte) {
		t.Helper()
		tx := appMCPBeginOperationTest(t, app)
		got, err := readAppMCPStoredOperation(context.Background(), tx, app, id)
		if err != nil || !bytes.Equal(got.Receipt, wantReceipt) {
			tx.Rollback()
			t.Fatalf("restored positive row %s: %v", id, err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	assertRead(r1.OperationID, receipt1)
	assertRead(r2.OperationID, receipt2)
	wrongAppDir := filepath.Join(t.TempDir(), "different-app")
	wrongApp := &App{Dir: wrongAppDir, DB: app.DB}
	tx = appMCPBeginOperationTest(t, app)
	if _, err := readAppMCPStoredOperation(context.Background(), tx, wrongApp, r1.OperationID); err == nil {
		tx.Rollback()
		t.Fatal("wrong transaction/application path accepted")
	}
	tx.Rollback()
	if _, err := app.DB.Exec("UPDATE main._benmore_mcp_operations SET prepared_ciphertext=? WHERE operation_id=?", cipher2, r1.OperationID); err != nil {
		t.Fatal(err)
	}
	tx = appMCPBeginOperationTest(t, app)
	if _, err := readAppMCPStoredOperation(context.Background(), tx, app, r1.OperationID); err == nil {
		tx.Rollback()
		t.Fatal("cross-row prepared ciphertext swap accepted")
	}
	tx.Rollback()
	if _, err := app.DB.Exec("UPDATE main._benmore_mcp_operations SET prepared_ciphertext=? WHERE operation_id=?", cipher1, r1.OperationID); err != nil {
		t.Fatal(err)
	}
	assertRead(r1.OperationID, receipt1)
	if _, err := app.DB.Exec("UPDATE main._benmore_mcp_operations SET receipt_ciphertext=? WHERE operation_id=?", cipher1, r1.OperationID); err != nil {
		t.Fatal(err)
	}
	tx = appMCPBeginOperationTest(t, app)
	if _, err := readAppMCPStoredOperation(context.Background(), tx, app, r1.OperationID); err == nil {
		tx.Rollback()
		t.Fatal("cross-column receipt ciphertext swap accepted")
	}
	tx.Rollback()
	if _, err := app.DB.Exec("UPDATE main._benmore_mcp_operations SET receipt_ciphertext=? WHERE operation_id=?", receiptCipher1, r1.OperationID); err != nil {
		t.Fatal(err)
	}
	assertRead(r1.OperationID, receipt1)
	if _, err := app.DB.Exec("UPDATE main._benmore_mcp_operations SET receipt_digest=? WHERE operation_id=?", strings.Repeat("f", 64), r1.OperationID); err != nil {
		t.Fatal(err)
	}
	tx = appMCPBeginOperationTest(t, app)
	if _, err := readAppMCPStoredOperation(context.Background(), tx, app, r1.OperationID); err == nil {
		tx.Rollback()
		t.Fatal("tampered receipt digest accepted")
	}
	tx.Rollback()
	if _, err := app.DB.Exec("UPDATE main._benmore_mcp_operations SET receipt_digest=? WHERE operation_id=?", appMCPOperationDigest("benmore:mcp:receipt:v1", receipt1), r1.OperationID); err != nil {
		t.Fatal(err)
	}
	assertRead(r1.OperationID, receipt1)
	if _, err := app.DB.Exec("UPDATE main._benmore_mcp_operations SET receipt_digest=?,receipt_ciphertext=? WHERE operation_id=?", appMCPOperationDigest("benmore:mcp:receipt:v1", receipt2), receiptCipher2, r1.OperationID); err != nil {
		t.Fatal(err)
	}
	tx = appMCPBeginOperationTest(t, app)
	if _, err := readAppMCPStoredOperation(context.Background(), tx, app, r1.OperationID); err == nil {
		tx.Rollback()
		t.Fatal("cross-row receipt envelope binding accepted")
	}
	tx.Rollback()
	if _, err := app.DB.Exec("UPDATE main._benmore_mcp_operations SET receipt_digest=?,receipt_ciphertext=? WHERE operation_id=?", appMCPOperationDigest("benmore:mcp:receipt:v1", receipt1), receiptCipher1, r1.OperationID); err != nil {
		t.Fatal(err)
	}
	assertRead(r1.OperationID, receipt1)
	tamperedReceipt := receiptCipher1
	if strings.HasSuffix(tamperedReceipt, "0") {
		tamperedReceipt = tamperedReceipt[:len(tamperedReceipt)-1] + "1"
	} else {
		tamperedReceipt = tamperedReceipt[:len(tamperedReceipt)-1] + "0"
	}
	if _, err := app.DB.Exec("UPDATE main._benmore_mcp_operations SET receipt_ciphertext=? WHERE operation_id=?", tamperedReceipt, r1.OperationID); err != nil {
		t.Fatal(err)
	}
	tx = appMCPBeginOperationTest(t, app)
	if _, err := readAppMCPStoredOperation(context.Background(), tx, app, r1.OperationID); err == nil {
		tx.Rollback()
		t.Fatal("tampered receipt ciphertext accepted")
	}
	tx.Rollback()
	if _, err := app.DB.Exec("UPDATE main._benmore_mcp_operations SET receipt_ciphertext=? WHERE operation_id=?", receiptCipher1, r1.OperationID); err != nil {
		t.Fatal(err)
	}
	assertRead(r1.OperationID, receipt1)
	if _, err := app.DB.Exec("UPDATE main._benmore_mcp_operations SET prepared_digest=? WHERE operation_id=?", strings.Repeat("f", 64), r2.OperationID); err != nil {
		t.Fatal(err)
	}
	tx = appMCPBeginOperationTest(t, app)
	if _, err := readAppMCPStoredOperation(context.Background(), tx, app, r2.OperationID); err == nil {
		tx.Rollback()
		t.Fatal("altered prepared digest accepted")
	}
	tx.Rollback()
	if _, err := app.DB.Exec("UPDATE main._benmore_mcp_operations SET prepared_digest=? WHERE operation_id=?", digest2, r2.OperationID); err != nil {
		t.Fatal(err)
	}
	assertRead(r2.OperationID, receipt2)
	tamperedPrepared := cipher2
	if strings.HasSuffix(tamperedPrepared, "0") {
		tamperedPrepared = tamperedPrepared[:len(tamperedPrepared)-1] + "1"
	} else {
		tamperedPrepared = tamperedPrepared[:len(tamperedPrepared)-1] + "0"
	}
	if _, err := app.DB.Exec("UPDATE main._benmore_mcp_operations SET prepared_ciphertext=? WHERE operation_id=?", tamperedPrepared, r2.OperationID); err != nil {
		t.Fatal(err)
	}
	tx = appMCPBeginOperationTest(t, app)
	if _, err := readAppMCPStoredOperation(context.Background(), tx, app, r2.OperationID); err == nil {
		tx.Rollback()
		t.Fatal("tampered prepared ciphertext accepted")
	}
	tx.Rollback()
	if _, err := app.DB.Exec("UPDATE main._benmore_mcp_operations SET prepared_ciphertext=? WHERE operation_id=?", cipher2, r2.OperationID); err != nil {
		t.Fatal(err)
	}
	assertRead(r2.OperationID, receipt2)
	assertRead(r1.OperationID, receipt1)
	if _, err := app.DB.Exec("UPDATE main._benmore_mcp_operations SET prepared_ciphertext=? WHERE operation_id=?", prepared1, r1.OperationID); err != nil {
		t.Fatal(err)
	}
	tx = appMCPBeginOperationTest(t, app)
	if _, err := readAppMCPStoredOperation(context.Background(), tx, app, r1.OperationID); err == nil {
		tx.Rollback()
		t.Fatal("plaintext canonical envelope accepted")
	}
	tx.Rollback()
	if _, err := app.DB.Exec("UPDATE main._benmore_mcp_operations SET prepared_ciphertext=? WHERE operation_id=?", cipher1, r1.OperationID); err != nil {
		t.Fatal(err)
	}
	assertRead(r1.OperationID, receipt1)
	legacy := appMCPTestV1Cipher(t, key, prepared1)
	legacyPlain, err := fieldDecryptCtx(key, "", legacy)
	if err != nil || !bytes.Equal([]byte(legacyPlain), prepared1) {
		t.Fatalf("legacy-v1 negative control is not authentic: %v", err)
	}
	if _, err := app.DB.Exec("UPDATE main._benmore_mcp_operations SET prepared_ciphertext=? WHERE operation_id=?", legacy, r1.OperationID); err != nil {
		t.Fatal(err)
	}
	tx = appMCPBeginOperationTest(t, app)
	if _, err := readAppMCPStoredOperation(context.Background(), tx, app, r1.OperationID); err == nil {
		tx.Rollback()
		t.Fatal("valid legacy v1 ciphertext accepted")
	}
	tx.Rollback()
	if _, err := app.DB.Exec("UPDATE main._benmore_mcp_operations SET prepared_ciphertext=? WHERE operation_id=?", cipher1, r1.OperationID); err != nil {
		t.Fatal(err)
	}
	assertRead(r1.OperationID, receipt1)
	other, _ := auditApp(t)
	RegisterDBEncryptionKey(filepath.Join(other.Dir, "data.db"), key)
	otherTx, err := other.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := initializeAppMCPOperationStorage(context.Background(), otherTx); err != nil {
		otherTx.Rollback()
		t.Fatal(err)
	}
	if err := otherTx.Commit(); err != nil {
		t.Fatal(err)
	}
	otherRecord := appMCPOperationStoreRecord(other, r2.OperationID)
	otherTx, err = other.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := insertAppMCPPreparedOperation(context.Background(), otherTx, other, otherRecord); err != nil {
		otherTx.Rollback()
		t.Fatal(err)
	}
	if err := otherTx.Commit(); err != nil {
		t.Fatal(err)
	}
	otherTx, err = other.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readAppMCPStoredOperation(context.Background(), otherTx, other, r2.OperationID); err != nil {
		otherTx.Rollback()
		t.Fatalf("other-app positive control: %v", err)
	}
	if err := otherTx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := other.DB.Exec("UPDATE main._benmore_mcp_operations SET prepared_digest=?,prepared_ciphertext=? WHERE operation_id=?", digest2, cipher2, r2.OperationID); err != nil {
		t.Fatal(err)
	}
	otherTx, err = other.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readAppMCPStoredOperation(context.Background(), otherTx, other, r2.OperationID); err == nil {
		otherTx.Rollback()
		t.Fatal("cross-application ciphertext with matching digest / wrong AppID accepted")
	}
	otherTx.Rollback()
	if err := other.DB.Close(); err != nil {
		t.Fatal(err)
	}
}

func appMCPTestV1Cipher(t *testing.T, key, plaintext []byte) string {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return encPrefix + hex.EncodeToString(ciphertext)
}

func TestAppMCPOperationStoreChildProcessHelper(t *testing.T) {
	mode := os.Getenv("APP_MCP_OPERATION_CHILD_MODE")
	if mode == "" {
		return
	}
	dir := os.Getenv("APP_MCP_OPERATION_CHILD_DIR")
	id := os.Getenv("APP_MCP_OPERATION_CHILD_ID")
	keyHex := os.Getenv("APP_MCP_OPERATION_CHILD_KEY")
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		os.Exit(31)
	}
	db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db")+"?_journal_mode=WAL&_busy_timeout=5000&_txlock=immediate")
	if err != nil {
		os.Exit(32)
	}
	app := &App{Dir: dir, DB: db}
	RegisterDBEncryptionKey(filepath.Join(dir, "data.db"), key)
	tx, err := db.Begin()
	if err != nil {
		os.Exit(33)
	}
	if mode == "prepared" {
		var r appMCPPreparedOperationRecord
		if jsonErr := json.NewDecoder(os.Stdin).Decode(&r); jsonErr != nil {
			os.Exit(35)
		}
		if _, err := insertAppMCPPreparedOperation(context.Background(), tx, app, r); err != nil {
			os.Exit(36)
		}
		if err := tx.Commit(); err != nil {
			os.Exit(37)
		}
		os.Exit(0)
	}
	var r appMCPPreparedOperationRecord
	if jsonErr := json.NewDecoder(os.Stdin).Decode(&r); jsonErr != nil {
		os.Exit(38)
	}
	if mode == "receipt_before_commit" {
		prepared, e := readAppMCPStoredOperation(context.Background(), tx, app, id)
		if e != nil {
			os.Exit(39)
		}
		if _, e = storeAppMCPCommittedReceipt(context.Background(), tx, app, id, prepared.PreparedDigest, []byte(`{"child":"before"}`)); e != nil {
			os.Exit(40)
		}
		fmt.Fprintln(os.Stdout, "ready")
		select {}
	}
	if mode == "receipt_after_commit" {
		prepared, e := readAppMCPStoredOperation(context.Background(), tx, app, id)
		if e != nil {
			os.Exit(41)
		}
		if _, e = storeAppMCPCommittedReceipt(context.Background(), tx, app, id, prepared.PreparedDigest, []byte(`{"child":"after"}`)); e != nil {
			os.Exit(42)
		}
		if e = tx.Commit(); e != nil {
			os.Exit(43)
		}
		os.Exit(0)
	}
	os.Exit(44)
}

type appMCPStoreChild struct {
	cmd     *exec.Cmd
	lines   chan string
	done    chan struct{}
	waitErr error
	cancel  context.CancelFunc
}

func startAppMCPStoreChild(t *testing.T, mode, dir, id string, key, stdin []byte) *appMCPStoreChild {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestAppMCPOperationStoreChildProcessHelper$")
	cmd.Env = append(os.Environ(), "APP_MCP_OPERATION_CHILD_MODE="+mode, "APP_MCP_OPERATION_CHILD_DIR="+dir, "APP_MCP_OPERATION_CHILD_ID="+id, "APP_MCP_OPERATION_CHILD_KEY="+hex.EncodeToString(key))
	cmd.Stdin = bytes.NewReader(stdin)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	child := &appMCPStoreChild{cmd: cmd, lines: make(chan string, 8), done: make(chan struct{}), cancel: cancel}
	t.Cleanup(func() {
		child.cancel()
		select {
		case <-child.done:
		default:
			if child.cmd.Process != nil {
				_ = child.cmd.Process.Kill()
			}
			select {
			case <-child.done:
			case <-time.After(5 * time.Second):
				t.Errorf("child %s did not finish cleanup", mode)
			}
		}
	})
	readDone := make(chan struct{})
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			child.lines <- scanner.Text()
		}
		close(child.lines)
		close(readDone)
	}()
	go func() {
		<-readDone
		child.waitErr = child.cmd.Wait()
		close(child.done)
	}()
	return child
}

func (child *appMCPStoreChild) wait(t *testing.T, timeout time.Duration) error {
	t.Helper()
	select {
	case <-child.done:
		return child.waitErr
	case <-time.After(timeout):
		return fmt.Errorf("child wait exceeded %s", timeout)
	}
}

func TestAppMCPOperationStoreChildProcessLostResponseRecovery(t *testing.T) {
	app, key := appMCPOperationStoreFixture(t)
	app.DB.Close()
	path := filepath.Join(app.Dir, "data.db")
	var openErr error
	app.DB, openErr = sql.Open("sqlite3", path+"?_journal_mode=WAL&_busy_timeout=5000&_txlock=immediate")
	if openErr != nil {
		t.Fatal(openErr)
	}
	RegisterDBEncryptionKey(path, key)
	r := appMCPOperationStoreRecord(app, strings.Repeat("9", 64))
	encoded, _ := json.Marshal(r)
	preparedChild := startAppMCPStoreChild(t, "prepared", app.Dir, r.OperationID, key, encoded)
	if err := preparedChild.wait(t, 12*time.Second); err != nil {
		t.Fatalf("prepared child exit: %v", err)
	}
	tx := appMCPBeginOperationTest(t, app)
	got, err := readAppMCPStoredOperation(context.Background(), tx, app, r.OperationID)
	if err != nil || !bytes.Equal(got.Prepared.Arguments, r.Arguments) {
		tx.Rollback()
		t.Fatalf("recover after child COMMIT before response: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	stdinJSON, _ := json.Marshal(r)
	beforeChild := startAppMCPStoreChild(t, "receipt_before_commit", app.Dir, r.OperationID, key, stdinJSON)
	select {
	case line, ok := <-beforeChild.lines:
		if !ok || line != "ready" {
			t.Fatalf("child did not reach receipt-before-COMMIT barrier: %q", line)
		}
	case <-time.After(12 * time.Second):
		t.Fatal("child receipt-before-COMMIT barrier timed out")
	}
	killErr := beforeChild.cmd.Process.Kill()
	if killErr != nil {
		t.Fatalf("kill child before COMMIT: %v", killErr)
	}
	waitErr := beforeChild.wait(t, 8*time.Second)
	exitErr, exitedAbnormally := waitErr.(*exec.ExitError)
	if !exitedAbnormally || exitErr.ExitCode() == 0 {
		t.Fatalf("killed child did not complete Wait with abnormal exit: %v", waitErr)
	}
	tx = appMCPBeginOperationTest(t, app)
	afterKill, err := readAppMCPStoredOperation(context.Background(), tx, app, r.OperationID)
	if err != nil || afterKill.Receipt != nil {
		tx.Rollback()
		t.Fatalf("uncommitted child receipt survived termination: %v", err)
	}
	tx.Commit()
	afterChild := startAppMCPStoreChild(t, "receipt_after_commit", app.Dir, r.OperationID, key, stdinJSON)
	if err := afterChild.wait(t, 12*time.Second); err != nil {
		t.Fatalf("receipt child exit: %v", err)
	}
	tx = appMCPBeginOperationTest(t, app)
	afterCommit, err := readAppMCPStoredOperation(context.Background(), tx, app, r.OperationID)
	if err != nil || !bytes.Equal(afterCommit.Receipt, []byte(`{"child":"after"}`)) {
		tx.Rollback()
		t.Fatalf("receipt lost after child COMMIT before response: %v", err)
	}
	tx.Commit()
}

type appMCPTestOperationCipherSnapshot struct {
	preparedDigest string
	preparedCipher string
	receiptDigest  sql.NullString
	receiptCipher  sql.NullString
}

func appMCPReadOperationCipherSnapshot(t *testing.T, db *sql.DB, operationID string) appMCPTestOperationCipherSnapshot {
	t.Helper()
	var row appMCPTestOperationCipherSnapshot
	if err := db.QueryRow("SELECT prepared_digest,prepared_ciphertext,receipt_digest,receipt_ciphertext FROM main._benmore_mcp_operations WHERE operation_id=?", operationID).
		Scan(&row.preparedDigest, &row.preparedCipher, &row.receiptDigest, &row.receiptCipher); err != nil {
		t.Fatal(err)
	}
	return row
}

func TestAppMCPOperationStoreRowsVerifyAndRotate(t *testing.T) {
	app, oldKey := appMCPOperationStoreFixture(t)
	app.DB.SetMaxOpenConns(1)
	newKey, err := cryptoDeriveAppKey(strings.Repeat("73", 32))
	if err != nil {
		t.Fatal(err)
	}
	appID, err := appMCPOperationStoreOwnerIDForFixture(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	first := appMCPOperationStoreRecord(app, strings.Repeat("a", 64))
	first.CreatedAt, first.ExpiresAt = 100, 100+15*60
	first.Intent = []byte(`{"note_id":9007199254740993,"ratio":1.0}`)
	second := appMCPOperationStoreRecord(app, strings.Repeat("b", 64))
	second.Command = "notes.archive"
	second.Arguments = []byte(`{"archived":true,"rows":[2]}`)
	insertTx := appMCPBeginOperationTest(t, app)
	firstStored, err := insertAppMCPPreparedOperation(context.Background(), insertTx, app, first)
	if err != nil {
		insertTx.Rollback()
		t.Fatal(err)
	}
	secondStored, err := insertAppMCPPreparedOperation(context.Background(), insertTx, app, second)
	if err != nil {
		insertTx.Rollback()
		t.Fatal(err)
	}
	if err := insertTx.Commit(); err != nil {
		t.Fatal(err)
	}
	receipt := []byte(`{"archive":{"rows":2},"ok":true}`)
	receiptTx := appMCPBeginOperationTest(t, app)
	if _, err := storeAppMCPCommittedReceipt(context.Background(), receiptTx, app, second.OperationID, secondStored.PreparedDigest, receipt); err != nil {
		receiptTx.Rollback()
		t.Fatal(err)
	}
	if err := receiptTx.Commit(); err != nil {
		t.Fatal(err)
	}
	if firstStored.Prepared.ExpiresAt >= time.Now().Unix() {
		t.Fatal("expired-record fixture is not expired")
	}

	snapshots := map[string]appMCPTestOperationCipherSnapshot{}
	preparedPlain := map[string][]byte{}
	receiptPlain := map[string][]byte{}
	for _, operationID := range []string{first.OperationID, second.OperationID} {
		row := appMCPReadOperationCipherSnapshot(t, app.DB, operationID)
		snapshots[operationID] = row
		prepared, err := appMCPOpenOperation(oldKey, "prepared_ciphertext", row.preparedCipher)
		if err != nil {
			t.Fatal(err)
		}
		preparedPlain[operationID] = prepared
		if row.receiptCipher.Valid {
			plain, err := appMCPOpenOperation(oldKey, "receipt_ciphertext", row.receiptCipher.String)
			if err != nil {
				t.Fatal(err)
			}
			receiptPlain[operationID] = plain
		}
	}
	if snapshots[first.OperationID].receiptCipher.Valid || !snapshots[second.OperationID].receiptCipher.Valid {
		t.Fatal("fixtures must distinguish committed and null receipts")
	}
	if !bytes.Contains(preparedPlain[first.OperationID], []byte(`"ratio":1.0`)) || !bytes.Contains(preparedPlain[first.OperationID], []byte("9007199254740993")) {
		t.Fatal("prepared fixture lost exact numeric JSON bytes")
	}
	if !bytes.Contains(receiptPlain[second.OperationID], []byte(`"committed_receipt"`)) {
		t.Fatal("receipt fixture is missing its authenticated envelope")
	}

	rollbackTx := appMCPBeginOperationTest(t, app)
	count, err := rotateAppMCPOperationRowsWithKeys(context.Background(), rollbackTx, appID, oldKey, newKey)
	if err != nil || count != 2 {
		rollbackTx.Rollback()
		t.Fatalf("rotation rollback candidate: count=%d err=%v", count, err)
	}
	if count, err := verifyAppMCPOperationRowsWithKey(context.Background(), rollbackTx, appID, newKey); err != nil || count != 2 {
		rollbackTx.Rollback()
		t.Fatalf("new key cannot verify in transaction: count=%d err=%v", count, err)
	}
	if _, err := verifyAppMCPOperationRowsWithKey(context.Background(), rollbackTx, appID, oldKey); err == nil {
		rollbackTx.Rollback()
		t.Fatal("old key verified rows after in-transaction rotation")
	}
	if err := rollbackTx.Rollback(); err != nil {
		t.Fatal(err)
	}
	checkTx := appMCPBeginOperationTest(t, app)
	if count, err := verifyAppMCPOperationRowsWithKey(context.Background(), checkTx, appID, oldKey); err != nil || count != 2 {
		checkTx.Rollback()
		t.Fatalf("rollback did not restore old-key readability: count=%d err=%v", count, err)
	}
	if _, err := verifyAppMCPOperationRowsWithKey(context.Background(), checkTx, appID, newKey); err == nil {
		checkTx.Rollback()
		t.Fatal("new key accepted after caller rollback")
	}
	if err := checkTx.Commit(); err != nil {
		t.Fatal(err)
	}

	rotateTx := appMCPBeginOperationTest(t, app)
	count, err = rotateAppMCPOperationRowsWithKeys(context.Background(), rotateTx, appID, oldKey, newKey)
	if err != nil || count != 2 {
		rotateTx.Rollback()
		t.Fatalf("rotation: count=%d err=%v", count, err)
	}
	if count, err := verifyAppMCPOperationRowsWithKey(context.Background(), rotateTx, appID, newKey); err != nil || count != 2 {
		rotateTx.Rollback()
		t.Fatalf("new-key verification before commit: count=%d err=%v", count, err)
	}
	if err := rotateTx.Commit(); err != nil {
		t.Fatal(err)
	}
	for _, operationID := range []string{first.OperationID, second.OperationID} {
		row := appMCPReadOperationCipherSnapshot(t, app.DB, operationID)
		before := snapshots[operationID]
		if row.preparedDigest != before.preparedDigest || row.receiptDigest != before.receiptDigest || row.receiptCipher.Valid != before.receiptCipher.Valid {
			t.Fatalf("rotation changed immutable digest or receipt-null state for %s", operationID)
		}
		if row.preparedCipher == before.preparedCipher || !appMCPOperationAAD(row.preparedCipher, "prepared_ciphertext") {
			t.Fatalf("prepared ciphertext was not resealed under the existing v2 AAD for %s", operationID)
		}
		prepared, err := appMCPOpenOperation(newKey, "prepared_ciphertext", row.preparedCipher)
		if err != nil || !bytes.Equal(prepared, preparedPlain[operationID]) {
			t.Fatalf("prepared plaintext changed for %s: %v", operationID, err)
		}
		if row.receiptCipher.Valid {
			if row.receiptCipher.String == before.receiptCipher.String || !appMCPOperationAAD(row.receiptCipher.String, "receipt_ciphertext") {
				t.Fatalf("receipt ciphertext was not resealed under the existing v2 AAD for %s", operationID)
			}
			plain, err := appMCPOpenOperation(newKey, "receipt_ciphertext", row.receiptCipher.String)
			if err != nil || !bytes.Equal(plain, receiptPlain[operationID]) {
				t.Fatalf("receipt envelope bytes changed for %s: %v", operationID, err)
			}
		} else if row.receiptDigest.Valid || row.receiptCipher.Valid {
			t.Fatalf("null receipt columns changed for %s", operationID)
		}
	}
	if err := app.DB.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(app.Dir, "data.db")
	reopenedDB, err := sql.Open("sqlite3", path+"?_journal_mode=WAL&_busy_timeout=5000&_txlock=immediate")
	if err != nil {
		t.Fatal(err)
	}
	app.DB = reopenedDB
	app.DB.SetMaxOpenConns(1)
	reopenTx := appMCPBeginOperationTest(t, app)
	if count, err := verifyAppMCPOperationRowsWithKey(context.Background(), reopenTx, appID, newKey); err != nil || count != 2 {
		reopenTx.Rollback()
		t.Fatalf("new-key reopen verification: count=%d err=%v", count, err)
	}
	if _, err := verifyAppMCPOperationRowsWithKey(context.Background(), reopenTx, appID, oldKey); err == nil {
		reopenTx.Rollback()
		t.Fatal("old key verified committed rotated rows")
	}
	for _, operationID := range []string{first.OperationID, second.OperationID} {
		if _, err := appMCPReadOperationWithKey(context.Background(), reopenTx, appID, oldKey, operationID); err == nil {
			reopenTx.Rollback()
			t.Fatalf("old key read rotated row %s", operationID)
		}
	}
	if err := reopenTx.Commit(); err != nil {
		t.Fatal(err)
	}
	committedImages := map[string]appMCPTestOperationCipherSnapshot{}
	for _, operationID := range []string{first.OperationID, second.OperationID} {
		committedImages[operationID] = appMCPReadOperationCipherSnapshot(t, app.DB, operationID)
	}
	obsoleteRetryTx := appMCPBeginOperationTest(t, app)
	if _, err := rotateAppMCPOperationRowsWithKeys(context.Background(), obsoleteRetryTx, appID, oldKey, newKey); err == nil {
		obsoleteRetryTx.Rollback()
		t.Fatal("full rotation accepted obsolete old key after committed reopen")
	}
	if err := obsoleteRetryTx.Rollback(); err != nil {
		t.Fatal(err)
	}
	for _, operationID := range []string{first.OperationID, second.OperationID} {
		after := appMCPReadOperationCipherSnapshot(t, app.DB, operationID)
		if after != committedImages[operationID] {
			t.Fatalf("obsolete-key retry changed committed ciphertext for %s", operationID)
		}
	}
}

func TestAppMCPOperationStoreMaintenanceRejectsInvalidStorageAndKey(t *testing.T) {
	app, key := appMCPOperationStoreFixture(t)
	app.DB.SetMaxOpenConns(1)
	appID, err := appMCPOperationStoreOwnerIDForFixture(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	verifyEmpty := func(label string) {
		t.Helper()
		positiveTx := appMCPBeginOperationTest(t, app)
		if count, err := verifyAppMCPOperationRowsWithKey(context.Background(), positiveTx, appID, key); err != nil || count != 0 {
			positiveTx.Rollback()
			t.Fatalf("%s positive baseline: count=%d err=%v", label, count, err)
		}
		if err := positiveTx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	tx := appMCPBeginOperationTest(t, app)
	if count, err := verifyAppMCPOperationRowsWithKey(context.Background(), tx, appID, key); err != nil || count != 0 {
		tx.Rollback()
		t.Fatalf("empty operation table: count=%d err=%v", count, err)
	}
	if count, err := rotateAppMCPOperationRowsWithKeys(context.Background(), tx, appID, key, bytes.Repeat([]byte{0x73}, 32)); err != nil || count != 0 {
		tx.Rollback()
		t.Fatalf("empty-table rotation: count=%d err=%v", count, err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	tx = appMCPBeginOperationTest(t, app)
	if _, err := verifyAppMCPOperationRowsWithKey(nil, tx, appID, key); err == nil {
		tx.Rollback()
		t.Fatal("nil verifier context accepted")
	}
	if _, err := verifyAppMCPOperationRowsWithKey(canceled, tx, appID, key); err == nil {
		tx.Rollback()
		t.Fatal("cancelled verifier context accepted")
	}
	if _, err := verifyAppMCPOperationRowsWithKey(context.Background(), nil, appID, key); err == nil {
		tx.Rollback()
		t.Fatal("nil verifier transaction accepted")
	}
	if _, err := verifyAppMCPOperationRowsWithKey(context.Background(), tx, "bad", key); err == nil {
		tx.Rollback()
		t.Fatal("invalid application identity accepted")
	}
	if _, err := verifyAppMCPOperationRowsWithKey(context.Background(), tx, appID, []byte("short")); err == nil {
		tx.Rollback()
		t.Fatal("invalid verifier key accepted")
	}
	newKey := bytes.Repeat([]byte{0x73}, 32)
	if _, err := rotateAppMCPOperationRowsWithKeys(nil, tx, appID, key, newKey); err == nil {
		tx.Rollback()
		t.Fatal("nil rotation context accepted")
	}
	if _, err := rotateAppMCPOperationRowsWithKeys(canceled, tx, appID, key, newKey); err == nil {
		tx.Rollback()
		t.Fatal("cancelled rotation context accepted")
	}
	if _, err := rotateAppMCPOperationRowsWithKeys(context.Background(), nil, appID, key, newKey); err == nil {
		tx.Rollback()
		t.Fatal("nil rotation transaction accepted")
	}
	if _, err := rotateAppMCPOperationRowsWithKeys(context.Background(), tx, "bad", key, newKey); err == nil {
		tx.Rollback()
		t.Fatal("invalid rotation application identity accepted")
	}
	if _, err := rotateAppMCPOperationRowsWithKeys(context.Background(), tx, appID, []byte("short"), newKey); err == nil {
		tx.Rollback()
		t.Fatal("invalid old rotation key accepted")
	}
	if _, err := rotateAppMCPOperationRowsWithKeys(context.Background(), tx, appID, key, []byte("short")); err == nil {
		tx.Rollback()
		t.Fatal("invalid new rotation key accepted")
	}
	if _, err := rotateAppMCPOperationRowsWithKeys(context.Background(), tx, appID, key, key); err == nil {
		tx.Rollback()
		t.Fatal("identical rotation keys accepted")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}

	dummyRow := appMCPOperationMaintenanceRow{}
	if err := appMCPCASOperationMaintenanceRow(nil, nil, dummyRow, "", sql.NullString{}); err == nil {
		t.Fatal("nil CAS context and transaction accepted")
	}
	canceledCAS, cancelCAS := context.WithCancel(context.Background())
	cancelCAS()
	tx = appMCPBeginOperationTest(t, app)
	if err := appMCPCASOperationMaintenanceRow(canceledCAS, tx, dummyRow, "", sql.NullString{}); err == nil {
		tx.Rollback()
		t.Fatal("cancelled CAS context accepted")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	tx = appMCPBeginOperationTest(t, app)
	if err := appMCPCASOperationMaintenanceRow(context.Background(), nil, dummyRow, "", sql.NullString{}); err == nil {
		tx.Rollback()
		t.Fatal("nil CAS transaction accepted")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}

	tx = appMCPBeginOperationTest(t, app)
	if _, err := tx.Exec("CREATE TEMP TABLE operation_shadow(value TEXT)"); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if _, err := verifyAppMCPOperationRowsWithKey(context.Background(), tx, appID, key); err == nil {
		tx.Rollback()
		t.Fatal("temporary schema object accepted")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	verifyEmpty("after TEMP rollback")

	conn, err := app.DB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	attachTx, err := conn.BeginTx(context.Background(), nil)
	if err != nil {
		conn.Close()
		t.Fatal(err)
	}
	if _, err := attachTx.Exec("ATTACH DATABASE ':memory:' AS operation_attached"); err != nil {
		attachTx.Rollback()
		conn.Close()
		t.Fatal(err)
	}
	if _, err := rotateAppMCPOperationRowsWithKeys(context.Background(), attachTx, appID, key, bytes.Repeat([]byte{0x74}, 32)); err == nil {
		attachTx.Rollback()
		conn.Close()
		t.Fatal("attached database accepted for rotation")
	}
	if err := attachTx.Rollback(); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(context.Background(), "DETACH DATABASE operation_attached"); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	databaseList, err := conn.QueryContext(context.Background(), "PRAGMA database_list")
	if err != nil {
		conn.Close()
		t.Fatal(err)
	}
	for databaseList.Next() {
		var seq int
		var name, file string
		if err := databaseList.Scan(&seq, &name, &file); err != nil {
			databaseList.Close()
			conn.Close()
			t.Fatal(err)
		}
		if name == "operation_attached" {
			databaseList.Close()
			conn.Close()
			t.Fatal("attached database remains after explicit detach")
		}
	}
	if err := databaseList.Err(); err != nil {
		databaseList.Close()
		conn.Close()
		t.Fatal(err)
	}
	if err := databaseList.Close(); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	cleanTx, err := conn.BeginTx(context.Background(), nil)
	if err != nil {
		conn.Close()
		t.Fatal(err)
	}
	if count, err := verifyAppMCPOperationRowsWithKey(context.Background(), cleanTx, appID, key); err != nil || count != 0 {
		cleanTx.Rollback()
		conn.Close()
		t.Fatalf("positive baseline after ATTACH cleanup: count=%d err=%v", count, err)
	}
	if err := cleanTx.Commit(); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := app.DB.Exec("CREATE TRIGGER operation_maintenance_fixture AFTER UPDATE ON _benmore_mcp_operations BEGIN SELECT 1; END"); err != nil {
		t.Fatal(err)
	}
	tx = appMCPBeginOperationTest(t, app)
	if _, err := verifyAppMCPOperationRowsWithKey(context.Background(), tx, appID, key); err == nil {
		tx.Rollback()
		t.Fatal("trigger-altered operation schema accepted")
	}
	tx.Rollback()
	if _, err := app.DB.Exec("DROP TRIGGER operation_maintenance_fixture"); err != nil {
		t.Fatal(err)
	}
	verifyEmpty("after trigger removal")

	if _, err := app.DB.Exec("ALTER TABLE main._benmore_mcp_operations RENAME TO _benmore_mcp_operations_original"); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec("CREATE TABLE main._benmore_mcp_operations(operation_id TEXT)"); err != nil {
		t.Fatal(err)
	}
	tx = appMCPBeginOperationTest(t, app)
	if _, err := verifyAppMCPOperationRowsWithKey(context.Background(), tx, appID, key); err == nil {
		tx.Rollback()
		t.Fatal("altered operation table accepted")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec("DROP TABLE main._benmore_mcp_operations"); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec("DROP TABLE main._benmore_mcp_operations_original"); err != nil {
		t.Fatal(err)
	}
	tx = appMCPBeginOperationTest(t, app)
	if _, err := verifyAppMCPOperationRowsWithKey(context.Background(), tx, appID, key); err == nil {
		tx.Rollback()
		t.Fatal("missing operation table accepted")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	var tableCount int
	if err := app.DB.QueryRow("SELECT count(*) FROM main.sqlite_schema WHERE name='_benmore_mcp_operations'").Scan(&tableCount); err != nil || tableCount != 0 {
		t.Fatal("maintenance verification recreated a missing table")
	}
}

func TestAppMCPOperationStoreMaintenanceValidatesBeforeWritingAndRollsBackFaults(t *testing.T) {
	app, oldKey := appMCPOperationStoreFixture(t)
	app.DB.SetMaxOpenConns(1)
	newKey := bytes.Repeat([]byte{0x75}, 32)
	appID, err := appMCPOperationStoreOwnerIDForFixture(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	first := appMCPOperationStoreRecord(app, strings.Repeat("c", 64))
	second := appMCPOperationStoreRecord(app, strings.Repeat("d", 64))
	firstTx := appMCPBeginOperationTest(t, app)
	firstStored, err := insertAppMCPPreparedOperation(context.Background(), firstTx, app, first)
	if err != nil {
		firstTx.Rollback()
		t.Fatal(err)
	}
	secondStored, err := insertAppMCPPreparedOperation(context.Background(), firstTx, app, second)
	if err != nil {
		firstTx.Rollback()
		t.Fatal(err)
	}
	if _, err := storeAppMCPCommittedReceipt(context.Background(), firstTx, app, second.OperationID, secondStored.PreparedDigest, []byte(`{"status":"committed"}`)); err != nil {
		firstTx.Rollback()
		t.Fatal(err)
	}
	if err := firstTx.Commit(); err != nil {
		t.Fatal(err)
	}
	beforeFirst := appMCPReadOperationCipherSnapshot(t, app.DB, first.OperationID)
	beforeSecond := appMCPReadOperationCipherSnapshot(t, app.DB, second.OperationID)
	if firstStored.PreparedDigest == secondStored.PreparedDigest || beforeFirst.preparedCipher == beforeSecond.preparedCipher {
		t.Fatal("maintenance rows are not distinguishable")
	}
	if _, err := app.DB.Exec("UPDATE main._benmore_mcp_operations SET prepared_ciphertext=? WHERE operation_id=?", beforeFirst.preparedCipher, second.OperationID); err != nil {
		t.Fatal(err)
	}
	corruptTx := appMCPBeginOperationTest(t, app)
	if _, err := rotateAppMCPOperationRowsWithKeys(context.Background(), corruptTx, appID, oldKey, newKey); err == nil {
		corruptTx.Rollback()
		t.Fatal("cross-row prepared ciphertext swap accepted")
	}
	var firstAfterFailedCipher string
	if err := corruptTx.QueryRow("SELECT prepared_ciphertext FROM main._benmore_mcp_operations WHERE operation_id=?", first.OperationID).Scan(&firstAfterFailedCipher); err != nil || firstAfterFailedCipher != beforeFirst.preparedCipher {
		corruptTx.Rollback()
		t.Fatal("later corrupt row caused an earlier write")
	}
	if err := corruptTx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec("UPDATE main._benmore_mcp_operations SET prepared_ciphertext=? WHERE operation_id=?", beforeSecond.preparedCipher, second.OperationID); err != nil {
		t.Fatal(err)
	}

	if _, err := app.DB.Exec("UPDATE main._benmore_mcp_operations SET receipt_ciphertext=? WHERE operation_id=?", beforeSecond.preparedCipher, second.OperationID); err != nil {
		t.Fatal(err)
	}
	columnTx := appMCPBeginOperationTest(t, app)
	if _, err := verifyAppMCPOperationRowsWithKey(context.Background(), columnTx, appID, oldKey); err == nil {
		columnTx.Rollback()
		t.Fatal("cross-column ciphertext swap accepted")
	}
	columnTx.Rollback()
	if _, err := app.DB.Exec("UPDATE main._benmore_mcp_operations SET receipt_ciphertext=? WHERE operation_id=?", beforeSecond.receiptCipher, second.OperationID); err != nil {
		t.Fatal(err)
	}
	wrongAppTx := appMCPBeginOperationTest(t, app)
	if _, err := verifyAppMCPOperationRowsWithKey(context.Background(), wrongAppTx, strings.Repeat("e", 64), oldKey); err == nil {
		wrongAppTx.Rollback()
		t.Fatal("wrong owner AppID accepted")
	}
	wrongAppTx.Rollback()

	faultTx := appMCPBeginOperationTest(t, app)
	if _, err := faultTx.Exec("PRAGMA query_only=ON"); err != nil {
		faultTx.Rollback()
		t.Fatal(err)
	}
	if _, err := rotateAppMCPOperationRowsWithKeys(context.Background(), faultTx, appID, oldKey, newKey); err == nil {
		faultTx.Rollback()
		t.Fatal("SQL update fault accepted")
	}
	if err := faultTx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec("PRAGMA query_only=OFF"); err != nil {
		t.Fatal(err)
	}
	verifyTx := appMCPBeginOperationTest(t, app)
	if count, err := verifyAppMCPOperationRowsWithKey(context.Background(), verifyTx, appID, oldKey); err != nil || count != 2 {
		verifyTx.Rollback()
		t.Fatalf("caller rollback did not restore every row: count=%d err=%v", count, err)
	}
	if err := verifyTx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestAppMCPOperationStoreMaintenanceCASRejectsStaleImages(t *testing.T) {
	app, oldKey := appMCPOperationStoreFixture(t)
	app.DB.SetMaxOpenConns(1)
	newKey, err := cryptoDeriveAppKey(strings.Repeat("76", 32))
	if err != nil {
		t.Fatal(err)
	}
	appID, err := appMCPOperationStoreOwnerIDForFixture(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	nullReceipt := appMCPOperationStoreRecord(app, strings.Repeat("1", 64))
	committedReceipt := appMCPOperationStoreRecord(app, strings.Repeat("2", 64))
	committedReceipt.Command = "notes.archive"
	setupTx := appMCPBeginOperationTest(t, app)
	if _, err := insertAppMCPPreparedOperation(context.Background(), setupTx, app, nullReceipt); err != nil {
		setupTx.Rollback()
		t.Fatal(err)
	}
	prepared, err := insertAppMCPPreparedOperation(context.Background(), setupTx, app, committedReceipt)
	if err != nil {
		setupTx.Rollback()
		t.Fatal(err)
	}
	if err := setupTx.Commit(); err != nil {
		t.Fatal(err)
	}
	receipt := []byte(`{"state":"committed"}`)
	setupTx = appMCPBeginOperationTest(t, app)
	if _, err := storeAppMCPCommittedReceipt(context.Background(), setupTx, app, committedReceipt.OperationID, prepared.PreparedDigest, receipt); err != nil {
		setupTx.Rollback()
		t.Fatal(err)
	}
	if err := setupTx.Commit(); err != nil {
		t.Fatal(err)
	}

	reseal := func(row appMCPOperationMaintenanceRow) (string, sql.NullString) {
		t.Helper()
		preparedPlain, err := appMCPOpenOperation(oldKey, "prepared_ciphertext", row.preparedCipher)
		if err != nil {
			t.Fatal(err)
		}
		preparedCipher, err := appMCPSealOperation(newKey, "prepared_ciphertext", preparedPlain)
		if err != nil {
			t.Fatal(err)
		}
		newReceipt := sql.NullString{}
		if row.receiptCipher.Valid {
			receiptPlain, err := appMCPOpenOperation(oldKey, "receipt_ciphertext", row.receiptCipher.String)
			if err != nil {
				t.Fatal(err)
			}
			receiptCipher, err := appMCPSealOperation(newKey, "receipt_ciphertext", receiptPlain)
			if err != nil {
				t.Fatal(err)
			}
			newReceipt = sql.NullString{String: receiptCipher, Valid: true}
		}
		return preparedCipher, newReceipt
	}
	rowsEqual := func(a, b []appMCPOperationMaintenanceRow) bool {
		if len(a) != len(b) {
			return false
		}
		for i := range a {
			if a[i].operationID != b[i].operationID || a[i].preparedDigest != b[i].preparedDigest || a[i].preparedCipher != b[i].preparedCipher ||
				a[i].receiptDigest != b[i].receiptDigest || a[i].receiptCipher != b[i].receiptCipher {
				return false
			}
		}
		return true
	}

	for _, staleID := range []string{nullReceipt.OperationID, committedReceipt.OperationID} {
		tx := appMCPBeginOperationTest(t, app)
		oldRows, err := appMCPReadOperationMaintenanceRows(context.Background(), tx)
		if err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		if count, err := verifyAppMCPOperationRowsWithKey(context.Background(), tx, appID, oldKey); err != nil || count != 2 {
			tx.Rollback()
			t.Fatalf("old operation rows did not authenticate: count=%d err=%v", count, err)
		}
		var stale appMCPOperationMaintenanceRow
		for _, row := range oldRows {
			if row.operationID == staleID {
				stale = row
			}
		}
		if stale.operationID == "" {
			tx.Rollback()
			t.Fatalf("old row image not found for %s", staleID)
		}
		if (staleID == nullReceipt.OperationID) != !stale.receiptCipher.Valid {
			tx.Rollback()
			t.Fatalf("stale row receipt discriminator wrong for %s", staleID)
		}

		for _, row := range oldRows {
			preparedCipher, receiptCipher := reseal(row)
			if err := appMCPCASOperationMaintenanceRow(context.Background(), tx, row, preparedCipher, receiptCipher); err != nil {
				tx.Rollback()
				t.Fatalf("positive CAS for %s: %v", row.operationID, err)
			}
			if _, err := appMCPReadOperationWithKey(context.Background(), tx, appID, newKey, row.operationID); err != nil {
				tx.Rollback()
				t.Fatalf("new-key readback for %s: %v", row.operationID, err)
			}
		}
		newRows, err := appMCPReadOperationMaintenanceRows(context.Background(), tx)
		if err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		for i := range oldRows {
			if newRows[i].preparedCipher == oldRows[i].preparedCipher || newRows[i].preparedDigest != oldRows[i].preparedDigest ||
				newRows[i].receiptDigest != oldRows[i].receiptDigest || newRows[i].receiptCipher.Valid != oldRows[i].receiptCipher.Valid {
				tx.Rollback()
				t.Fatalf("positive CAS did not preserve bindings while resealing row %s", oldRows[i].operationID)
			}
		}
		stalePreparedCipher, staleReceiptCipher := reseal(stale)
		casErr := appMCPCASOperationMaintenanceRow(context.Background(), tx, stale, stalePreparedCipher, staleReceiptCipher)
		if casErr == nil || casErr.Error() != "operation storage rotation compare-and-swap failed; caller must roll back" {
			tx.Rollback()
			t.Fatalf("stale old row image did not reach exact CAS mismatch: %v", casErr)
		}
		unchanged, err := appMCPReadOperationMaintenanceRows(context.Background(), tx)
		if err != nil || !rowsEqual(unchanged, newRows) {
			tx.Rollback()
			t.Fatalf("CAS mismatch changed an in-transaction row image: %v", err)
		}
		if err := tx.Rollback(); err != nil {
			t.Fatal(err)
		}
		if err := app.DB.Close(); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(app.Dir, "data.db")
		reopenedDB, err := sql.Open("sqlite3", path+"?_journal_mode=WAL&_busy_timeout=5000&_txlock=immediate")
		if err != nil {
			t.Fatal(err)
		}
		app.DB = reopenedDB
		app.DB.SetMaxOpenConns(1)
		RegisterDBEncryptionKey(path, oldKey)

		reopenTx := appMCPBeginOperationTest(t, app)
		if count, err := verifyAppMCPOperationRowsWithKey(context.Background(), reopenTx, appID, oldKey); err != nil || count != 2 {
			reopenTx.Rollback()
			t.Fatalf("caller rollback did not restore old-key rows: count=%d err=%v", count, err)
		}
		if _, err := verifyAppMCPOperationRowsWithKey(context.Background(), reopenTx, appID, newKey); err == nil {
			reopenTx.Rollback()
			t.Fatal("new key read rows after stale-CAS transaction rollback")
		}
		reopenedRows, err := appMCPReadOperationMaintenanceRows(context.Background(), reopenTx)
		if err != nil || !rowsEqual(reopenedRows, oldRows) {
			reopenTx.Rollback()
			t.Fatalf("rollback did not restore exact old ciphertext/digests/null states: %v", err)
		}
		if err := reopenTx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
}
