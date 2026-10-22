//go:build !cli

package main

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

func versionEncryptionDB(t *testing.T) (*sql.DB, string, []byte, *EncryptedFieldConfig) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "data.db")
	key := []byte("12345678901234567890123456789012")
	RegisterDBEncryptionKey(path, key)
	db, err := sql.Open("sqlite3_benmore", path)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close(); dbCryptoRegistry.Delete(canonicalDBPath(path)) })
	crudScopeMustExec(t, db, `CREATE TABLE records(id INTEGER PRIMARY KEY,user_id INTEGER,secret TEXT,number INTEGER,created_at DATETIME,updated_at DATETIME)`)
	enc := &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{"records": {{Column: "secret", Roles: []string{"admin"}}, {Column: "number", Roles: []string{"admin"}}}}}
	return db, path, key, enc
}

func TestVersionHistoryEncryptsSnapshotsAndPreservesMasking(t *testing.T) {
	db, _, key, enc := versionEncryptionDB(t)
	InstallEncryptionTriggers(db, enc)
	if err := InstallVersioningTriggers(db, &VersionedConfig{Tables: []string{"records"}}, enc); err != nil {
		t.Fatal(err)
	}
	crudScopeMustExec(t, db, `INSERT INTO records(id,user_id,secret,number) VALUES(1,1,'original-sensitive-value',50)`)
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM records_history`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("insert storage normalization recorded %d versions: %v", count, err)
	}
	crudScopeMustExec(t, db, `UPDATE records SET secret='replacement-sensitive-value',number=75 WHERE id=1`)
	rows, err := db.Query(`SELECT secret,number FROM records_history ORDER BY _version`)
	if err != nil {
		t.Fatal(err)
	}
	count = 0
	for rows.Next() {
		var secret, number string
		if err := rows.Scan(&secret, &number); err != nil {
			t.Fatal(err)
		}
		count++
		for column, raw := range map[string]string{"secret": secret, "number": number} {
			plain, sealed, err := appEncryptionRotationOpen(raw, key, "records", column)
			want := "original-sensitive-value"
			if column == "number" {
				want = "50"
			}
			if err != nil || !sealed || plain != want {
				t.Fatalf("%s snapshot sealed=%v plain=%q err=%v", column, sealed, plain, err)
			}
			if _, _, err := appEncryptionRotationOpen(raw, key, "records_history", column); err == nil {
				t.Fatal("history was rebound away from source AAD")
			}
		}
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("one logical update wrote %d versions", count)
	}
	decoded, err := QueryRows(db, `SELECT * FROM records_history`)
	if err != nil {
		t.Fatal(err)
	}
	app := &App{DB: db, Encrypted: enc}
	MaskEncryptedFields(app, "records", decoded, &Session{Role: "user"})
	if decoded[0]["secret"] == "original-sensitive-value" || decoded[0]["number"] == int64(50) {
		t.Fatalf("history lost field masking: %v", decoded)
	}
	admin, err := QueryRows(db, `SELECT * FROM records_history`)
	if err != nil {
		t.Fatal(err)
	}
	MaskEncryptedFields(app, "records", admin, &Session{Role: "admin"})
	if admin[0]["secret"] != "original-sensitive-value" {
		t.Fatalf("authorized read failed: %v", admin)
	}
	crudScopeMustExec(t, db, `UPDATE records SET secret=NULL,number=NULL WHERE id=1`)
	crudScopeMustExec(t, db, `DELETE FROM records WHERE id=1`)
	if err := db.QueryRow(`SELECT COUNT(*) FROM records_history WHERE secret IS NOT NULL AND secret NOT LIKE 'enc:v2:%'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("plaintext snapshots=%d: %v", count, err)
	}
	var nullSecret any
	if err := db.QueryRow(`SELECT secret FROM records_history WHERE _change_type='delete'`).Scan(&nullSecret); err != nil || nullSecret != nil {
		t.Fatalf("NULL became ciphertext: %v %v", nullSecret, err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM records_history`).Scan(&count); err != nil || count != 3 {
		t.Fatalf("logical snapshots=%d: %v", count, err)
	}
}

func TestVersionHistoryRepairsLegacyPlaintextAndV1(t *testing.T) {
	db, _, key, enc := versionEncryptionDB(t)
	cfg := &VersionedConfig{Tables: []string{"records"}}
	if err := InstallVersioningTriggers(db, cfg); err != nil {
		t.Fatal(err)
	}
	crudScopeMustExec(t, db, `INSERT INTO records(id,secret,number) VALUES(1,'legacy plaintext',25)`)
	crudScopeMustExec(t, db, `UPDATE records SET secret='next' WHERE id=1`)
	legacy := appEncryptionRotationV1(t, key, "legacy sealed")
	appEncryptionRotationMustExec(t, db, `UPDATE records SET secret=? WHERE id=1`, legacy)
	crudScopeMustExec(t, db, `DELETE FROM records WHERE id=1`)
	if err := InstallVersioningTriggers(db, cfg, enc); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM records_history WHERE secret NOT LIKE 'enc:v2:%' OR number NOT LIKE 'enc:v2:%'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("unrepaired snapshots=%d: %v", count, err)
	}
	decoded, err := QueryRows(db, `SELECT secret FROM records_history ORDER BY _version`)
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []string{"legacy plaintext", "next", "legacy sealed"} {
		if decoded[i]["secret"] != want {
			t.Fatalf("version %d=%v", i, decoded[i])
		}
	}
	// Removal stops new capture, but retained history remains encrypted and valid.
	if err := InstallVersioningTriggers(db, nil, enc); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_schema WHERE type='trigger' AND name LIKE '_benmore_ver_%'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("removed versioning left %d triggers: %v", count, err)
	}
}

func TestVersionHistoryRepairFailureRollsBack(t *testing.T) {
	for _, failure := range []string{"corrupt", "wrong source AAD", "missing key"} {
		t.Run(failure, func(t *testing.T) {
			db, path, key, enc := versionEncryptionDB(t)
			cfg := &VersionedConfig{Tables: []string{"records"}}
			if err := InstallVersioningTriggers(db, cfg); err != nil {
				t.Fatal(err)
			}
			crudScopeMustExec(t, db, `INSERT INTO records(id,secret) VALUES(1,'retained plaintext')`)
			crudScopeMustExec(t, db, `UPDATE records SET secret='later' WHERE id=1`)
			crudScopeMustExec(t, db, `DELETE FROM records WHERE id=1`)
			bad := "enc:v2:corrupt"
			if failure == "wrong source AAD" {
				var err error
				bad, err = fieldEncryptCtx(key, "other_records", "secret", "moved")
				if err != nil {
					t.Fatal(err)
				}
			}
			if failure == "missing key" {
				dbCryptoRegistry.Delete(canonicalDBPath(path))
				previous := appEncryptionKey
				appEncryptionKey = nil
				t.Cleanup(func() { appEncryptionKey = previous })
			} else {
				appEncryptionRotationMustExec(t, db, `UPDATE records_history SET secret=? WHERE _version=2`, bad)
			}
			var before string
			if err := db.QueryRow(`SELECT sql FROM sqlite_schema WHERE name='_benmore_ver_records_update'`).Scan(&before); err != nil {
				t.Fatal(err)
			}
			if err := InstallVersioningTriggers(db, cfg, enc); err == nil {
				t.Fatal("invalid historical state was accepted")
			}
			var after, raw string
			if err := db.QueryRow(`SELECT sql FROM sqlite_schema WHERE name='_benmore_ver_records_update'`).Scan(&after); err != nil {
				t.Fatal(err)
			}
			if before != after {
				t.Fatal("failed repair replaced active trigger")
			}
			if err := db.QueryRow(`SELECT secret FROM records_history WHERE _version=1`).Scan(&raw); err != nil || raw != "retained plaintext" {
				t.Fatalf("failed repair partly committed: %q %v", raw, err)
			}
		})
	}
}

func TestVersionHistoryRotationIncludesRetainedSnapshots(t *testing.T) {
	db, path, oldKey, enc := versionEncryptionDB(t)
	previous, ephemeral := appEncryptionKey, appEncryptionKeyEphemeral
	t.Cleanup(func() { appEncryptionKey = previous; appEncryptionKeyEphemeral = ephemeral })
	InstallEncryptionTriggers(db, enc)
	cfg := &VersionedConfig{Tables: []string{"records"}}
	if err := InstallVersioningTriggers(db, cfg, enc); err != nil {
		t.Fatal(err)
	}
	crudScopeMustExec(t, db, `INSERT INTO records(id,secret) VALUES(1,'old secret')`)
	crudScopeMustExec(t, db, `UPDATE records SET secret='current secret' WHERE id=1`)
	app := &App{DB: db, Dir: filepath.Dir(path), Encrypted: enc}
	newSource := strings.Repeat("new-source-", 5)
	if count, err := RotateEncryptionKey(app, newSource, true); err != nil || count != 2 {
		t.Fatalf("dry run count=%d err=%v", count, err)
	}
	if count, err := RotateEncryptionKey(app, newSource, false); err != nil || count != 2 {
		t.Fatalf("rotation count=%d err=%v", count, err)
	}
	newKey, err := cryptoDeriveAppKey(newSource)
	if err != nil {
		t.Fatal(err)
	}
	for table, want := range map[string]string{"records": "current secret", "records_history": "old secret"} {
		var raw string
		if err := db.QueryRow("SELECT secret FROM " + quoteIdent(table) + " WHERE id=1").Scan(&raw); err != nil {
			t.Fatal(err)
		}
		plain, sealed, err := appEncryptionRotationOpen(raw, newKey, "records", "secret")
		if err != nil || !sealed || plain != want {
			t.Fatalf("rotated %s=%q %v", table, plain, err)
		}
		if _, _, err := appEncryptionRotationOpen(raw, oldKey, "records", "secret"); err == nil {
			t.Fatal("old key still decrypts history")
		}
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM records_history`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("rotation generated history: %d %v", count, err)
	}
	crudScopeMustExec(t, db, `UPDATE records SET secret='post rotation' WHERE id=1`)
	if err := InstallVersioningTriggers(db, cfg, enc); err != nil {
		t.Fatalf("rotated histories fail reload: %v", err)
	}
}

func TestVersionHistoryRotationRollsBackOnUnreadableSnapshot(t *testing.T) {
	db, path, key, enc := versionEncryptionDB(t)
	InstallEncryptionTriggers(db, enc)
	cfg := &VersionedConfig{Tables: []string{"records"}}
	if err := InstallVersioningTriggers(db, cfg, enc); err != nil {
		t.Fatal(err)
	}
	crudScopeMustExec(t, db, `INSERT INTO records(id,secret) VALUES(1,'before')`)
	crudScopeMustExec(t, db, `UPDATE records SET secret='after' WHERE id=1`)
	crudScopeMustExec(t, db, `UPDATE records_history SET secret='enc:v2:corrupt'`)
	if _, err := RotateEncryptionKey(&App{DB: db, Dir: filepath.Dir(path), Encrypted: enc}, strings.Repeat("new-key-", 8), false); err == nil {
		t.Fatal("rotation accepted unreadable snapshot")
	}
	var raw string
	if err := db.QueryRow(`SELECT secret FROM records WHERE id=1`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if plain, sealed, err := appEncryptionRotationOpen(raw, key, "records", "secret"); err != nil || !sealed || plain != "after" {
		t.Fatalf("failed rotation changed live cell: %q %v", plain, err)
	}
	crudScopeMustExec(t, db, `UPDATE records SET secret='still works' WHERE id=1`)
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM records_history`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("failed rotation lost history trigger: %d %v", count, err)
	}
}

func TestVersionHistoryRepairUsesUnshadowedRowID(t *testing.T) {
	db, _, key, enc := versionEncryptionDB(t)
	crudScopeMustExec(t, db, `ALTER TABLE records ADD COLUMN rowid TEXT`)
	cfg := &VersionedConfig{Tables: []string{"records"}}
	if err := InstallVersioningTriggers(db, cfg); err != nil {
		t.Fatal(err)
	}
	crudScopeMustExec(t, db, `INSERT INTO records(id,secret,rowid) VALUES(1,'first','repeated'),(2,'second','repeated')`)
	crudScopeMustExec(t, db, `DELETE FROM records`)
	if err := InstallVersioningTriggers(db, cfg, enc); err != nil {
		t.Fatal(err)
	}
	for id, want := range map[int]string{1: "first", 2: "second"} {
		var raw string
		if err := db.QueryRow(`SELECT secret FROM records_history WHERE id=?`, id).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		if plain, _, err := appEncryptionRotationOpen(raw, key, "records", "secret"); err != nil || plain != want {
			t.Fatalf("row %d=%q %v", id, plain, err)
		}
	}
}

func TestVersionHistoryIgnoresBlindIndexMaintenance(t *testing.T) {
	db, path, _, enc := versionEncryptionDB(t)
	previous, ephemeral := appEncryptionKey, appEncryptionKeyEphemeral
	t.Cleanup(func() { appEncryptionKey = previous; appEncryptionKeyEphemeral = ephemeral })
	enc.Fields["records"][0].BlindIndex = true
	InstallEncryptionTriggers(db, enc)
	EnsureBlindColumns(db, enc)
	InstallBlindIndexTriggers(db, enc)
	if err := InstallVersioningTriggers(db, &VersionedConfig{Tables: []string{"records"}}, enc); err != nil {
		t.Fatal(err)
	}
	crudScopeMustExec(t, db, `INSERT INTO records(id,secret) VALUES(1,'before')`)
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM records_history`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("blind maintenance created insert versions: %d %v", count, err)
	}
	crudScopeMustExec(t, db, `UPDATE records SET secret='after' WHERE id=1`)
	if err := db.QueryRow(`SELECT COUNT(*) FROM records_history`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("blind maintenance created extra update versions: %d %v", count, err)
	}
	if _, err := RotateEncryptionKey(&App{DB: db, Dir: filepath.Dir(path), Encrypted: enc}, strings.Repeat("rotated-key-", 6), false); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM records_history`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("blind rebuild created versions: %d %v", count, err)
	}
}

func TestVersionHistoryNormalizesRealScalars(t *testing.T) {
	db, _, _, enc := versionEncryptionDB(t)
	crudScopeMustExec(t, db, `ALTER TABLE records ADD COLUMN amount REAL`)
	enc.Fields["records"] = append(enc.Fields["records"], EncryptedFieldDef{Column: "amount"})
	InstallEncryptionTriggers(db, enc)
	if err := InstallVersioningTriggers(db, &VersionedConfig{Tables: []string{"records"}}, enc); err != nil {
		t.Fatal(err)
	}
	crudScopeMustExec(t, db, `INSERT INTO records(id,amount) VALUES(1,1.0)`)
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM records_history`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("real normalization created versions: %d %v", count, err)
	}
	crudScopeMustExec(t, db, `UPDATE records SET amount=2.0 WHERE id=1`)
	if err := db.QueryRow(`SELECT COUNT(*) FROM records_history`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("real update created extra versions: %d %v", count, err)
	}
}
