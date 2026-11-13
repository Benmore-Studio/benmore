//go:build !cli

package main

import (
	"net/http"
	"net/url"
	"testing"
	"time"
)

// A blind-index equality filter answers "does a row I can list hold this
// plaintext?" even though the column comes back masked. Callers outside the
// column's unmask roles could confirm guessed SSNs one request at a time.
func TestBlindIndexFilter_RefusedForMaskedCallers(t *testing.T) {
	oldKey := appEncryptionKey
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 11)
	}
	appEncryptionKey = key
	if err := SetBlindIndexKey(key); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { appEncryptionKey = oldKey })

	dir := t.TempDir()
	db := openTestAppDB(t, dir)
	t.Cleanup(func() { _ = db.Close() })
	crudScopeMustExec(t, db, `CREATE TABLE patients (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, ssn TEXT)`)
	crudScopeMustExec(t, db, `CREATE TABLE journals (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, secret TEXT)`)
	cfg := &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{
		"patients": {{Column: "ssn", Roles: []string{"doctor"}, BlindIndex: true}},
		"journals": {{Column: "secret", Roles: []string{"self"}, BlindIndex: true}},
	}}
	EnsureBlindColumns(db, cfg)
	InstallEncryptionTriggers(db, cfg)
	InstallBlindIndexTriggers(db, cfg)

	app := &App{
		Dir: dir, DB: db, SessionDuration: time.Hour, Stop: make(chan struct{}),
		Encrypted: cfg,
		Access: &AccessConfig{rules: map[string]map[AccessOp]string{
			"patients": {"all": "everyone"},
			"journals": {"all": "everyone"},
		}},
		Tables: []Table{
			{Name: "patients", Columns: []Column{{Name: "id", PK: true}, {Name: "user_id"}, {Name: "ssn"}, {Name: "ssn_blind"}}},
			{Name: "journals", Columns: []Column{{Name: "id", PK: true}, {Name: "user_id"}, {Name: "secret"}, {Name: "secret_blind"}}},
		},
	}
	t.Cleanup(app.Shutdown)
	mux := buildAppMux(app, true, "http://localhost")
	alice := createCrudScopeSession(t, app, "alice@example.com", "user", "", "")
	doctor := createCrudScopeSession(t, app, "doctor@example.com", "doctor", "", "")
	crudScopeMustExec(t, db, `INSERT INTO patients (user_id, ssn) VALUES (1, '111-11-1111'), (2, '222-22-2222')`)
	crudScopeMustExec(t, db, `INSERT INTO journals (user_id, secret) VALUES (1, 'alice-secret'), (2, 'doctor-secret')`)
	guessHash, err := blindIndexForApp(app, "222-22-2222")
	if err != nil {
		t.Fatal(err)
	}

	for _, q := range []string{
		"ssn=222-22-2222",
		"ssn__in=222-22-2222,333-33-3333",
		"where%5Bssn%5D=222-22-2222",
		"ssn_blind=" + guessHash,
		"ssn_blind__gt=0",
		"sort=ssn_blind",
		"count=true&ssn=222-22-2222",
		"cursor=0&ssn=222-22-2222",
	} {
		assertStatus(t, mux, http.MethodGet, "/api/patients?"+q, alice, nil, http.StatusForbidden)
	}
	// Non-probe operators on the encrypted column can't be answered from
	// ciphertext: refused for everyone with the same 400 (it depends on no
	// row), rather than dropped so every row came back.
	assertStatus(t, mux, http.MethodGet, "/api/patients?ssn__like=222", alice, nil, http.StatusBadRequest)
	assertStatus(t, mux, http.MethodGet, "/api/patients?ssn__like=222", doctor, nil, http.StatusBadRequest)

	// A caller in the unmask role keeps equality search.
	assertListIDs(t, mux, doctor, "/api/patients?ssn=222-22-2222", []float64{2})
	assertListIDs(t, mux, doctor, "/api/patients?ssn_blind="+url.QueryEscape(guessHash), []float64{2})

	// `self` unmask: the probe only reaches the caller's own rows.
	assertListIDs(t, mux, alice, "/api/journals?secret=alice-secret", []float64{1})
	assertListIDs(t, mux, alice, "/api/journals?secret=doctor-secret", []float64{})
}

// Filters and sorts an encrypted column cannot answer used to look like real
// results: an equality filter without a blind index matched nothing, a range
// filter was dropped so every row came back, and a sort ordered ciphertext.
func TestEncryptedColumnListParamsRefusedWhenUnanswerable(t *testing.T) {
	oldKey := appEncryptionKey
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 29)
	}
	appEncryptionKey = key
	if err := SetBlindIndexKey(key); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { appEncryptionKey = oldKey })
	dir := t.TempDir()
	db := openTestAppDB(t, dir)
	t.Cleanup(func() { _ = db.Close() })
	crudScopeMustExec(t, db, `CREATE TABLE payroll (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, ssn TEXT, salary INTEGER, note TEXT)`)
	cfg := &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{
		"payroll": {{Column: "ssn", BlindIndex: true}, {Column: "salary"}},
	}}
	EnsureBlindColumns(db, cfg)
	InstallEncryptionTriggers(db, cfg)
	InstallBlindIndexTriggers(db, cfg)
	app := &App{
		Dir: dir, DB: db, SessionDuration: time.Hour, Stop: make(chan struct{}),
		Encrypted: cfg,
		Access:    &AccessConfig{rules: map[string]map[AccessOp]string{"payroll": {"all": "everyone"}}},
		Tables:    []Table{{Name: "payroll", Columns: []Column{{Name: "id", PK: true}, {Name: "user_id"}, {Name: "ssn"}, {Name: "ssn_blind"}, {Name: "salary"}, {Name: "note"}}}},
	}
	t.Cleanup(app.Shutdown)
	mux := buildAppMux(app, true, "http://localhost")
	alice := createCrudScopeSession(t, app, "alice@example.com", "user", "", "")
	crudScopeMustExec(t, db, `INSERT INTO payroll (user_id, ssn, salary, note) VALUES (1, '111-11-1111', 50000, 'a'), (1, '222-22-2222', 90000, 'b')`)
	for _, q := range []string{"salary=50000", "salary__in=50000,90000", "salary__gt=60000", "ssn__like=111", "ssn__ne=111-11-1111", "sort=salary", "orderBy=ssn:desc"} {
		assertStatus(t, mux, http.MethodGet, "/api/payroll?"+q, alice, nil, http.StatusBadRequest)
	}
	assertListIDs(t, mux, alice, "/api/payroll?ssn=222-22-2222", []float64{2})
	assertListIDs(t, mux, alice, "/api/payroll?note=a", []float64{1})
}
