//go:build !cli

package main

import (
	"net/http"
	"path/filepath"
	"testing"
)

func TestCustomFieldAddPreservesAllEncryptedHistory(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "rollback"}[corrupt], func(t *testing.T) {
			app, _ := newCrudScopeTestApp(t)
			token := createCrudScopeSession(t, app, "history-admin@example.com", "admin", "", "")
			path := filepath.Join(app.Dir, "data.db")
			key := bytesKey(0x31)
			RegisterDBEncryptionKey(path, key)
			t.Cleanup(func() { dbCryptoRegistry.Delete(canonicalDBPath(path)) })
			enc := &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{"records": {{Column: "secret"}}, "notes": {{Column: "secret"}}}}
			app.Encrypted = enc
			for _, table := range []string{"records", "notes"} {
				crudScopeMustExec(t, app.DB, "ALTER TABLE "+quoteIdent(table)+" ADD COLUMN secret TEXT")
			}
			InstallEncryptionTriggers(app.DB, enc)
			for _, table := range []string{"records", "notes"} {
				crudScopeMustExec(t, app.DB, "UPDATE "+quoteIdent(table)+" SET secret='before' WHERE id=1")
			}
			if err := InstallVersioningTriggers(app.DB, &VersionedConfig{Tables: []string{"records", "notes"}}, enc); err != nil {
				t.Fatal(err)
			}
			mux := http.NewServeMux()
			RegisterCustomFieldRoutes(mux, app)
			if corrupt {
				crudScopeMustExec(t, app.DB, `UPDATE records SET secret='intermediate' WHERE id=1`)
				crudScopeMustExec(t, app.DB, `UPDATE records_history SET secret='enc:v2:corrupt'`)
			}
			result := crudScopeRequest(t, mux, http.MethodPost, "/api/_schema/records/fields", token, map[string]any{"name": "summary", "type": "TEXT"})
			if corrupt {
				if result.Code != http.StatusInternalServerError {
					t.Fatalf("bad history add accepted: %d %s", result.Code, result.Body.String())
				}
				for _, table := range []string{"records", "records_history"} {
					cols, err := GetTableColumns(app.DB, table)
					if err != nil {
						t.Fatal(err)
					}
					if versionHasColumn(cols, "summary") {
						t.Fatalf("failed field change partly committed %s.summary", table)
					}
				}
				var tracked int
				if err := app.DB.QueryRow(`SELECT count(*) FROM _benmore_custom_fields WHERE table_name='records'`).Scan(&tracked); err != nil || tracked != 0 {
					t.Fatalf("failed field tracking=%d %v", tracked, err)
				}
			} else {
				if result.Code != http.StatusCreated {
					t.Fatalf("add field: %d %s", result.Code, result.Body.String())
				}
				crudScopeMustExec(t, app.DB, `UPDATE records SET secret='after',summary='new column' WHERE id=1`)
				var raw string
				if err := app.DB.QueryRow(`SELECT secret FROM records_history WHERE _version=1`).Scan(&raw); err != nil {
					t.Fatal(err)
				}
				if plain, sealed, err := appEncryptionRotationOpen(raw, key, "records", "secret"); err != nil || !sealed || plain != "before" {
					t.Fatalf("custom-field refresh lost encrypted history: %q %v", plain, err)
				}
				var unsealed int
				if err := app.DB.QueryRow(`SELECT count(*) FROM records_history WHERE secret NOT LIKE 'enc:v2:%'`).Scan(&unsealed); err != nil || unsealed != 0 {
					t.Fatalf("custom-field refresh leaked %d plaintext histories: %v", unsealed, err)
				}
			}
			// The scoped refresh must preserve capture on the other versioned table.
			crudScopeMustExec(t, app.DB, `UPDATE notes SET secret='after' WHERE id=1`)
			var raw string
			if err := app.DB.QueryRow(`SELECT secret FROM notes_history WHERE _version=1`).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			if plain, sealed, err := appEncryptionRotationOpen(raw, key, "notes", "secret"); err != nil || !sealed || plain != "before" {
				t.Fatalf("other table history lost: %q %v", plain, err)
			}
		})
	}
}

func TestCustomFieldAddDoesNotEnableRetainedHistory(t *testing.T) {
	app, _ := newCrudScopeTestApp(t)
	token := createCrudScopeSession(t, app, "history-admin@example.com", "admin", "", "")
	if err := InstallVersioningTriggers(app.DB, &VersionedConfig{Tables: []string{"records"}}); err != nil {
		t.Fatal(err)
	}
	crudScopeMustExec(t, app.DB, `UPDATE records SET title='historical' WHERE id=1`)
	if err := InstallVersioningTriggers(app.DB, nil); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	RegisterCustomFieldRoutes(mux, app)
	result := crudScopeRequest(t, mux, http.MethodPost, "/api/_schema/records/fields", token, map[string]any{"name": "summary", "type": "TEXT"})
	if result.Code != http.StatusCreated {
		t.Fatalf("add field: %d %s", result.Code, result.Body.String())
	}
	crudScopeMustExec(t, app.DB, `UPDATE records SET title='after disable',summary='new column' WHERE id=1`)
	var count int
	if err := app.DB.QueryRow(`SELECT count(*) FROM records_history`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("custom field re-enabled capture: history count=%d err=%v", count, err)
	}
}
