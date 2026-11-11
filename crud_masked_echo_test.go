//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

// maskedEchoFixture serves patients whose diagnosis (TEXT) and salary
// (INTEGER) are encrypted and unmasked only for the row's owner. alice owns
// both rows; bob has an edit share on both, so he can change them but reads
// the encrypted fields as the mask. Row 2's diagnosis is NULL.
func maskedEchoFixture(t *testing.T) (app *App, mux *http.ServeMux, alice, bob string) {
	t.Helper()
	oldKey := appEncryptionKey
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 41)
	}
	appEncryptionKey = key
	t.Cleanup(func() { appEncryptionKey = oldKey })

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "data.db")
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(dbPath, dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	RegisterDBEncryptionKey(dbPath, key)
	t.Cleanup(func() { dbCryptoRegistry.Delete(canonicalDBPath(dbPath)) })
	crudScopeMustExec(t, db, `CREATE TABLE patients (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, name TEXT, diagnosis TEXT, salary INTEGER)`)
	cfg := &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{
		"patients": {{Column: "diagnosis", Roles: []string{"owner"}}, {Column: "salary", Roles: []string{"owner"}}},
	}}
	if err := InstallEncryptionTriggers(db, cfg); err != nil {
		t.Fatal(err)
	}
	app = &App{
		Dir: dir, DB: db, SessionDuration: time.Hour, Stop: make(chan struct{}),
		Encrypted: cfg,
		Tables: []Table{{Name: "patients", Columns: []Column{
			{Name: "id", Type: "INTEGER", PK: true, prismaScalar: true},
			{Name: "user_id", Type: "INTEGER", prismaScalar: true},
			{Name: "name", Type: "TEXT", prismaScalar: true},
			{Name: "diagnosis", Type: "TEXT", prismaScalar: true},
			{Name: "salary", Type: "INTEGER", prismaScalar: true},
		}}},
	}
	t.Cleanup(app.Shutdown)
	mux = buildAppMux(app, true, "http://localhost")
	alice = createCrudScopeSession(t, app, "alice@example.com", "user", "", "")
	bob = createCrudScopeSession(t, app, "bob@example.com", "user", "", "")
	crudScopeMustExec(t, db, `INSERT INTO patients (user_id, name, diagnosis, salary) VALUES (1, 'p1', 'flu', 50000), (1, 'p2', NULL, 70000)`)
	EnsurePermissionsTable(db)
	crudScopeMustExec(t, db, `INSERT INTO _benmore_permissions (resource_type, resource_id, grant_type, grantee_id, permission) VALUES ('patients', '1', 'user', 'bob@example.com', 'edit'), ('patients', '2', 'user', 'bob@example.com', 'edit')`)
	return app, mux, alice, bob
}

func maskedEchoRead(t *testing.T, mux *http.ServeMux, sid, id string) map[string]any {
	t.Helper()
	w := crudScopeRequest(t, mux, http.MethodGet, "/api/patients/"+id, sid, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("GET patient %s: %d %s", id, w.Code, w.Body.String())
	}
	var row map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &row); err != nil {
		t.Fatal(err)
	}
	return row
}

// assertPatient checks the owner's (unmasked) view of a row.
func assertPatient(t *testing.T, mux *http.ServeMux, owner, id, where string, name string, diagnosis any, salary any) {
	t.Helper()
	row := maskedEchoRead(t, mux, owner, id)
	if row["name"] != name || row["diagnosis"] != diagnosis || row["salary"] != salary {
		t.Fatalf("%s: patient %s = name %#v diagnosis %#v salary %#v, want %#v %#v %#v", where, id, row["name"], row["diagnosis"], row["salary"], name, diagnosis, salary)
	}
}

// The reported overwrite: an editor who reads encrypted fields masked sends
// the read row back (GET, edit, PATCH). The mask is not a new value: the
// stored values survive, the echoed fields are named in X-Ignored-Fields, and
// the numeric field no longer fails the whole update with 422.
func TestMaskedEncryptedEchoIsNotStoredOnPatch(t *testing.T) {
	_, mux, alice, bob := maskedEchoFixture(t)

	row := maskedEchoRead(t, mux, bob, "1")
	if row["diagnosis"] != encryptedFieldMask || row["salary"] != encryptedFieldMask {
		t.Fatalf("fixture: bob should read the mask: %v", row)
	}
	row["name"] = "renamed"
	w := crudScopeRequest(t, mux, http.MethodPatch, "/api/patients/1", bob, row)
	if w.Code != http.StatusOK {
		t.Fatalf("echoed full-row PATCH: %d %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get(ignoredFieldsHeader); got != "diagnosis,salary" {
		t.Fatalf("X-Ignored-Fields = %q, want diagnosis,salary", got)
	}
	assertPatient(t, mux, alice, "1", "full-row echo", "renamed", "flu", float64(50000))

	// Only the numeric mask: before, 422 "salary must be an integer".
	w = crudScopeRequest(t, mux, http.MethodPatch, "/api/patients/1", bob, map[string]any{"name": "again", "salary": encryptedFieldMask})
	if w.Code != http.StatusOK || w.Header().Get(ignoredFieldsHeader) != "salary" {
		t.Fatalf("numeric mask echo: %d %q %s", w.Code, w.Header().Get(ignoredFieldsHeader), w.Body.String())
	}
	assertPatient(t, mux, alice, "1", "numeric echo", "again", "flu", float64(50000))

	// Nothing but the mask: a no-op, answered like an unchanged echo.
	w = crudScopeRequest(t, mux, http.MethodPatch, "/api/patients/1", bob, map[string]any{"diagnosis": encryptedFieldMask})
	if w.Code != http.StatusOK || w.Header().Get(ignoredFieldsHeader) != "diagnosis" {
		t.Fatalf("mask-only echo: %d %q %s", w.Code, w.Header().Get(ignoredFieldsHeader), w.Body.String())
	}
	assertPatient(t, mux, alice, "1", "mask-only echo", "again", "flu", float64(50000))

	// The decision is the caller's own masking, never the stored value: on
	// row 2, whose diagnosis is NULL (bob reads null there, not the mask),
	// the answer is the same and the NULL stays.
	w = crudScopeRequest(t, mux, http.MethodPatch, "/api/patients/2", bob, map[string]any{"diagnosis": encryptedFieldMask})
	if w.Code != http.StatusOK || w.Header().Get(ignoredFieldsHeader) != "diagnosis" || w.Body.String() != `{"status":"updated"}`+"\n" {
		t.Fatalf("mask echo on a NULL value: %d %q %q", w.Code, w.Header().Get(ignoredFieldsHeader), w.Body.String())
	}
	assertPatient(t, mux, alice, "2", "mask echo on NULL", "p2", nil, float64(70000))

	// A masked editor can still write a real new value.
	w = crudScopeRequest(t, mux, http.MethodPatch, "/api/patients/1", bob, map[string]any{"diagnosis": "cold", "salary": 51000})
	if w.Code != http.StatusOK || w.Header().Get(ignoredFieldsHeader) != "" {
		t.Fatalf("masked editor new value: %d %q %s", w.Code, w.Header().Get(ignoredFieldsHeader), w.Body.String())
	}
	assertPatient(t, mux, alice, "1", "masked editor new value", "again", "cold", float64(51000))
}

// A caller who reads the column unmasked writes the mask text as a value, as
// before; the decrypt-failure placeholder is never a value and is dropped for
// every caller.
func TestUnmaskedCallerStoresMaskTextAndDecryptPlaceholderIsDropped(t *testing.T) {
	_, mux, alice, bob := maskedEchoFixture(t)

	w := crudScopeRequest(t, mux, http.MethodPatch, "/api/patients/1", alice, map[string]any{"diagnosis": encryptedFieldMask})
	if w.Code != http.StatusOK || w.Header().Get(ignoredFieldsHeader) != "" {
		t.Fatalf("owner writes the mask text: %d %q %s", w.Code, w.Header().Get(ignoredFieldsHeader), w.Body.String())
	}
	assertPatient(t, mux, alice, "1", "owner wrote mask text", "p1", encryptedFieldMask, float64(50000))
	// The owner's numeric column keeps its type check.
	if w := crudScopeRequest(t, mux, http.MethodPatch, "/api/patients/1", alice, map[string]any{"salary": encryptedFieldMask}); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("owner writing the mask into an integer: %d %s", w.Code, w.Body.String())
	}

	for _, sid := range []string{alice, bob} {
		w = crudScopeRequest(t, mux, http.MethodPatch, "/api/patients/2", sid, map[string]any{"name": "kept", "salary": decryptFailMask, "diagnosis": decryptFailMask})
		if w.Code != http.StatusOK || w.Header().Get(ignoredFieldsHeader) != "diagnosis,salary" {
			t.Fatalf("decrypt placeholder echo: %d %q %s", w.Code, w.Header().Get(ignoredFieldsHeader), w.Body.String())
		}
		assertPatient(t, mux, alice, "2", "decrypt placeholder echo", "kept", nil, float64(70000))
	}
}

func TestMaskedEncryptedEchoIsNotStoredOnBatchAndTransaction(t *testing.T) {
	_, mux, alice, bob := maskedEchoFixture(t)

	w := crudScopeRequest(t, mux, http.MethodPatch, "/api/patients/batch", bob, map[string]any{
		"ids":    []int{1, 2},
		"fields": map[string]any{"name": "batched", "diagnosis": encryptedFieldMask, "salary": encryptedFieldMask},
	})
	if w.Code != http.StatusOK || w.Header().Get(ignoredFieldsHeader) != "diagnosis,salary" {
		t.Fatalf("batch echo: %d %q %s", w.Code, w.Header().Get(ignoredFieldsHeader), w.Body.String())
	}
	var batch map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &batch); err != nil || batch["updated"] != float64(2) {
		t.Fatalf("batch result: %s", w.Body.String())
	}
	assertPatient(t, mux, alice, "1", "batch echo", "batched", "flu", float64(50000))
	assertPatient(t, mux, alice, "2", "batch echo", "batched", nil, float64(70000))

	w = crudScopeRequest(t, mux, http.MethodPost, "/api/_transaction", bob, map[string]any{"operations": []map[string]any{
		{"table": "patients", "action": "update", "id": 1, "data": map[string]any{"name": "tx", "diagnosis": encryptedFieldMask, "salary": encryptedFieldMask}},
	}})
	if w.Code != http.StatusOK || w.Header().Get(ignoredFieldsHeader) != "patients.diagnosis,patients.salary" {
		t.Fatalf("transaction echo: %d %q %s", w.Code, w.Header().Get(ignoredFieldsHeader), w.Body.String())
	}
	assertPatient(t, mux, alice, "1", "transaction echo", "tx", "flu", float64(50000))

	// The owner's batch still stores the text it sent.
	w = crudScopeRequest(t, mux, http.MethodPatch, "/api/patients/batch", alice, map[string]any{
		"ids": []int{1}, "fields": map[string]any{"diagnosis": encryptedFieldMask},
	})
	if w.Code != http.StatusOK || w.Header().Get(ignoredFieldsHeader) != "" {
		t.Fatalf("owner batch: %d %q %s", w.Code, w.Header().Get(ignoredFieldsHeader), w.Body.String())
	}
	assertPatient(t, mux, alice, "1", "owner batch", "tx", encryptedFieldMask, float64(50000))
}
