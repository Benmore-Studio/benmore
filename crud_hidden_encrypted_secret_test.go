//go:build !cli

package main

import (
	"database/sql"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A secret-named column (api_secret) is hidden from every read. Declaring it
// in encrypted.yaml used to lift that: apiHiddenColumn exempted every
// encrypted column, and with no unmask_roles nothing is masked either, so
// encrypting a secret turned it from hidden into returned (decrypted) to
// every reader. It stays hidden unless unmask roles are declared for it.
func TestEncryptedSecretNamedColumnStaysHiddenWithoutUnmaskRoles(t *testing.T) {
	oldKey := appEncryptionKey
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 11)
	}
	appEncryptionKey = key
	t.Cleanup(func() { appEncryptionKey = oldKey })

	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	RegisterDBEncryptionKey(filepath.Join(dir, "data.db"), key)
	t.Cleanup(func() { dbCryptoRegistry.Delete(canonicalDBPath(filepath.Join(dir, "data.db"))) })
	crudScopeMustExec(t, db, `CREATE TABLE integrations (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, name TEXT, api_secret TEXT, notes TEXT)`)
	cfg := &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{
		"integrations": {{Column: "api_secret"}, {Column: "notes"}},
	}}
	InstallEncryptionTriggers(db, cfg)
	app := &App{
		Dir: dir, DB: db, SessionDuration: time.Hour, Stop: make(chan struct{}),
		Encrypted: cfg,
		Access:    &AccessConfig{rules: map[string]map[AccessOp]string{"integrations": {"all": "self"}}},
		Tables: []Table{{Name: "integrations", Columns: []Column{
			{Name: "id", PK: true}, {Name: "user_id"}, {Name: "name", Type: "TEXT"},
			{Name: "api_secret", Type: "TEXT"}, {Name: "notes", Type: "TEXT"},
		}}},
	}
	t.Cleanup(app.Shutdown)
	mux := buildAppMux(app, true, "http://localhost")
	token := createCrudScopeSession(t, app, "owner@example.com", "user", "", "")
	crudScopeMustExec(t, db, `INSERT INTO integrations (user_id, name, api_secret, notes) VALUES (1, 'crm', 'sk-live-abc', 'plain note')`)

	bodies := func() string {
		var all []string
		for _, path := range []string{"/api/integrations", "/api/integrations/1", "/api/integrations?fields=id,api_secret,notes"} {
			rec := crudScopeRequest(t, mux, http.MethodGet, path, token, nil)
			if rec.Code != http.StatusOK {
				t.Fatalf("GET %s status = %d body=%s", path, rec.Code, rec.Body.String())
			}
			all = append(all, rec.Body.String())
		}
		rec := crudScopeRequest(t, mux, http.MethodPost, "/api/integrations", token, map[string]any{"name": "new", "api_secret": "sk-live-new", "notes": "n"})
		if rec.Code != http.StatusOK {
			t.Fatalf("create status = %d body=%s", rec.Code, rec.Body.String())
		}
		return strings.Join(append(all, rec.Body.String()), "\n")
	}

	out := bodies()
	if strings.Contains(out, "api_secret") || strings.Contains(out, "sk-live") {
		t.Fatalf("an encrypted secret-named column with no unmask roles was returned: %s", out)
	}
	// An ordinary encrypted column with no unmask roles is still readable.
	if !strings.Contains(out, "plain note") {
		t.Fatalf("an ordinary encrypted column should stay visible: %s", out)
	}
	// Filtering on it stays refused, as for any hidden column.
	if rec := crudScopeRequest(t, mux, http.MethodGet, "/api/integrations?api_secret=sk-live-abc", token, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("filter on the hidden encrypted column: status %d body=%s", rec.Code, rec.Body.String())
	}

	// Declared unmask roles are the developer's explicit visibility: the
	// owner sees the value, as before.
	cfg.Fields["integrations"][0].Roles = []string{"owner"}
	if out := bodies(); !strings.Contains(out, "sk-live-abc") {
		t.Fatalf("declared unmask roles should make the column visible to its owner: %s", out)
	}
}
