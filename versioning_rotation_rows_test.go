//go:build !cli

package main

import (
	"context"
	"testing"
)

func TestRotateAppEncryptionRowsTxIncludesHistory(t *testing.T) {
	db, _ := appEncryptionRotationTestDB(t)
	oldKey, newKey := bytesKey(0x17), bytesKey(0x29)
	crudScopeMustExec(t, db, `CREATE TABLE records(id INTEGER PRIMARY KEY,secret TEXT)`)
	cfg := &VersionedConfig{Tables: []string{"records"}}
	if err := InstallVersioningTriggers(db, cfg); err != nil {
		t.Fatal(err)
	}
	cipher, err := fieldEncryptCtx(oldKey, "records", "secret", "source-bound")
	if err != nil {
		t.Fatal(err)
	}
	appEncryptionRotationMustExec(t, db, `INSERT INTO records VALUES(1,?)`, cipher)
	crudScopeMustExec(t, db, `UPDATE records SET secret='legacy plaintext'`)
	appEncryptionRotationMustExec(t, db, `UPDATE records SET secret=?`, cipher)
	if err := InstallVersioningTriggers(db, nil); err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	enc := &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{"records": {{Column: "secret"}}}}
	counts, err := rotateAppEncryptionRowsTx(context.Background(), tx, enc, oldKey, newKey)
	if err != nil {
		t.Fatal(err)
	}
	if counts.ConfiguredValues != 3 {
		t.Fatalf("rotated configured values=%d", counts.ConfiguredValues)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	for version, want := range map[int]string{1: "source-bound", 2: "legacy plaintext"} {
		var raw string
		if err := db.QueryRow(`SELECT secret FROM records_history WHERE _version=?`, version).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		plain, sealed, err := appEncryptionRotationOpen(raw, newKey, "records", "secret")
		if err != nil || !sealed || plain != want {
			t.Fatalf("historical rotation %d=%q %v", version, plain, err)
		}
	}
}
