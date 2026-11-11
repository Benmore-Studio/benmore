//go:build !cli

package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	idemSealSSN    = "321-54-9876"
	idemSealSalary = 731904
)

// idempotencySealApp is an app whose patients table encrypts ssn and salary
// (readable in plaintext by every role) and whose notes table encrypts
// nothing, with two ordinary users.
func idempotencySealApp(t *testing.T) (*App, *http.ServeMux, string, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "data.db")
	key := testKeyBytes(0x5A)
	oldGlobal, oldEphemeral, oldBlind := appEncryptionKey, appEncryptionKeyEphemeral, appBlindIndexKey.Load()
	t.Cleanup(func() {
		appEncryptionKey, appEncryptionKeyEphemeral = oldGlobal, oldEphemeral
		appBlindIndexKey.Store(oldBlind)
		dbCryptoRegistry.Delete(canonicalDBPath(path))
	})
	registerDBEncryptionKey(path, key, false)
	if err := SetBlindIndexKey(key); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(path, dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	mustExec(t, db, `CREATE TABLE patients (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, name TEXT, ssn TEXT, salary INTEGER)`)
	mustExec(t, db, `CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, title TEXT)`)
	config := &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{"patients": {{Column: "ssn"}, {Column: "salary"}}}}
	InstallEncryptionTriggers(db, config)
	if err := EnsureUsersTable(db); err != nil {
		t.Fatal(err)
	}
	EnsureSessionsTable(db)
	EnsureAPITokensTable(db)
	EnsurePermissionsTable(db)
	EnsureAuditLogTable(db)
	EnsureIdempotencyTable(db)
	EnsureNotificationsTable(db)
	EnsureJobsTable(db)
	app := &App{Dir: dir, DB: db, Stop: make(chan struct{}), SessionDuration: time.Hour, Encrypted: config}
	t.Cleanup(app.Shutdown)
	for _, name := range []string{"patients", "notes"} {
		cols, err := GetTableColumns(db, name)
		if err != nil {
			t.Fatal(err)
		}
		app.Tables = append(app.Tables, Table{Name: name, Columns: cols})
	}
	alice := createCrudScopeSession(t, app, "alice@example.com", "user", "", "")
	bob := createCrudScopeSession(t, app, "bob@example.com", "user", "", "")
	mux := http.NewServeMux()
	RegisterCRUD(mux, app)
	return app, mux, alice, bob
}

func idempotentCreate(t *testing.T, mux *http.ServeMux, token, table, key string, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/"+table, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Idempotency-Key", key)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

type idemStoredRow struct {
	key      string
	userID   int64
	response string
}

func idempotencyStoredRows(t *testing.T, db *sql.DB) []idemStoredRow {
	t.Helper()
	rows, err := db.Query("SELECT key, user_id, response FROM _benmore_idempotency ORDER BY rowid")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []idemStoredRow
	for rows.Next() {
		var r idemStoredRow
		if err := rows.Scan(&r.key, &r.userID, &r.response); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

func idempotencyRequireNoPlaintext(t *testing.T, rows []idemStoredRow) {
	t.Helper()
	for _, r := range rows {
		for _, secret := range []string{idemSealSSN, "731904"} {
			if strings.Contains(r.response, secret) {
				t.Fatalf("stored idempotent response for user %d holds the plaintext %q: %s", r.userID, secret, r.response)
			}
		}
	}
}

func idempotencyCount(t *testing.T, db *sql.DB, table string) int {
	t.Helper()
	var n int
	if err := db.QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func patientBody(name string) map[string]any {
	return map[string]any{"name": name, "ssn": idemSealSSN, "salary": idemSealSalary}
}

// An idempotent create on a table with encrypted fields keeps the response
// it answers sealed at rest; a retry still answers it byte for byte, and keys
// stay per user.
func TestIdempotentCreateSealsEncryptedResponse(t *testing.T) {
	app, mux, alice, bob := idempotencySealApp(t)

	first := idempotentCreate(t, mux, alice, "patients", "intake-1", patientBody("Ada"))
	if first.Code != http.StatusOK {
		t.Fatalf("create = %d %s", first.Code, first.Body.String())
	}
	var created map[string]any
	if err := json.Unmarshal(first.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created["ssn"] != idemSealSSN || created["salary"] != float64(idemSealSalary) {
		t.Fatalf("control: the creator reads its encrypted fields in plaintext, got %s", first.Body.String())
	}

	stored := idempotencyStoredRows(t, app.DB)
	if len(stored) != 1 {
		t.Fatalf("stored %d idempotency rows, want 1", len(stored))
	}
	idempotencyRequireNoPlaintext(t, stored)
	if !strings.HasPrefix(stored[0].response, encPrefixV2) {
		t.Fatalf("stored response is not sealed: %s", stored[0].response)
	}

	replay := idempotentCreate(t, mux, alice, "patients", "intake-1", patientBody("Ada"))
	if replay.Code != http.StatusOK || replay.Body.String() != first.Body.String() {
		t.Fatalf("replay = %d %s, want the original 200 %s", replay.Code, replay.Body.String(), first.Body.String())
	}
	if got := replay.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("replay Content-Type = %q", got)
	}
	if n := idempotencyCount(t, app.DB, "patients"); n != 1 {
		t.Fatalf("replay inserted again: %d patients", n)
	}

	changed := idempotentCreate(t, mux, alice, "patients", "intake-1", patientBody("Grace"))
	if changed.Code != http.StatusConflict {
		t.Fatalf("same key with different input = %d %s, want 409", changed.Code, changed.Body.String())
	}

	// Bob's identical key is his own: a new row, and his replay answers his
	// response, never Alice's.
	bobFirst := idempotentCreate(t, mux, bob, "patients", "intake-1", patientBody("Ada"))
	if bobFirst.Code != http.StatusOK || bobFirst.Body.String() == first.Body.String() {
		t.Fatalf("bob create = %d %s", bobFirst.Code, bobFirst.Body.String())
	}
	bobReplay := idempotentCreate(t, mux, bob, "patients", "intake-1", patientBody("Ada"))
	if bobReplay.Body.String() != bobFirst.Body.String() {
		t.Fatalf("bob replay = %s, want %s", bobReplay.Body.String(), bobFirst.Body.String())
	}
	if n := idempotencyCount(t, app.DB, "patients"); n != 2 {
		t.Fatalf("patients = %d, want 2", n)
	}
	idempotencyRequireNoPlaintext(t, idempotencyStoredRows(t, app.DB))

	// A table without encrypted fields stores its response as before.
	note := idempotentCreate(t, mux, alice, "notes", "note-1", map[string]any{"title": "plain"})
	if note.Code != http.StatusOK {
		t.Fatalf("note create = %d %s", note.Code, note.Body.String())
	}
	var noteStored string
	if err := app.DB.QueryRow("SELECT response FROM _benmore_idempotency WHERE response NOT LIKE 'enc:%'").Scan(&noteStored); err != nil {
		t.Fatalf("read the notes response: %v", err)
	}
	if noteStored != note.Body.String() {
		t.Fatalf("notes response stored as %q, want the answered %q", noteStored, note.Body.String())
	}
}

// Key rotation re-seals the stored responses, so a retry after it still
// answers the original response.
func TestIdempotentReplayAfterKeyRotation(t *testing.T) {
	app, mux, alice, _ := idempotencySealApp(t)
	first := idempotentCreate(t, mux, alice, "patients", "intake-rot", patientBody("Ada"))
	if first.Code != http.StatusOK {
		t.Fatalf("create = %d %s", first.Code, first.Body.String())
	}
	before := idempotencyStoredRows(t, app.DB)

	newSource := strings.Repeat("r", 64)
	if _, err := RotateEncryptionKey(app, newSource, false); err != nil {
		t.Fatalf("rotation: %v", err)
	}
	newKey, _ := cryptoDeriveAppKey(newSource)
	after := idempotencyStoredRows(t, app.DB)
	if len(after) != 1 || after[0].response == before[0].response {
		t.Fatalf("stored response not re-sealed: before %q after %+v", before[0].response, after)
	}
	idempotencyRequireNoPlaintext(t, after)
	opened, err := fieldDecryptCtx(newKey, idempotencySealColumn(after[0].userID, after[0].key), after[0].response)
	if err != nil || opened != first.Body.String() {
		t.Fatalf("re-sealed response does not open to the original under the new key: %v %q", err, opened)
	}

	replay := idempotentCreate(t, mux, alice, "patients", "intake-rot", patientBody("Ada"))
	if replay.Code != http.StatusOK || replay.Body.String() != first.Body.String() {
		t.Fatalf("replay after rotation = %d %s, want the original %s", replay.Code, replay.Body.String(), first.Body.String())
	}
	if n := idempotencyCount(t, app.DB, "patients"); n != 1 {
		t.Fatalf("replay after rotation inserted again: %d patients", n)
	}
}

// A sealed response that no longer opens (the key was replaced outside a
// rotation, a per-process key was lost, or the value was moved to another
// entry) is never answered and never re-runs the create.
func TestIdempotentReplayRefusesUnreadableSealedResponse(t *testing.T) {
	app, mux, alice, _ := idempotencySealApp(t)
	first := idempotentCreate(t, mux, alice, "patients", "intake-lost", patientBody("Ada"))
	if first.Code != http.StatusOK {
		t.Fatalf("create = %d %s", first.Code, first.Body.String())
	}
	stored := idempotencyStoredRows(t, app.DB)[0]

	// Bound to its own entry: the same bytes under another key or user do
	// not open.
	if _, err := openIdempotentResponse(app.DB, stored.key+"x", stored.userID, stored.response); err == nil {
		t.Fatal("a sealed response opened for another idempotency key")
	}
	if _, err := openIdempotentResponse(app.DB, stored.key, stored.userID+1, stored.response); err == nil {
		t.Fatal("a sealed response opened for another user")
	}

	registerDBEncryptionKey(filepath.Join(app.Dir, "data.db"), testKeyBytes(0x77), false)
	replay := idempotentCreate(t, mux, alice, "patients", "intake-lost", patientBody("Ada"))
	if replay.Code != http.StatusConflict || !strings.Contains(replay.Body.String(), "verify the original operation") {
		t.Fatalf("replay with an unreadable stored response = %d %s, want 409", replay.Code, replay.Body.String())
	}
	if strings.Contains(replay.Body.String(), idemSealSSN) {
		t.Fatalf("refusal leaked the stored response: %s", replay.Body.String())
	}
	if n := idempotencyCount(t, app.DB, "patients"); n != 1 {
		t.Fatalf("an unreadable stored response re-ran the create: %d patients", n)
	}
}
