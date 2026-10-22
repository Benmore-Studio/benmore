//go:build !cli

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func appEncryptionStateFixture(t *testing.T) (*App, []byte, string) {
	t.Helper()
	app, _ := auditApp(t)
	key, err := cryptoDeriveAppKey(strings.Repeat("7a", 32))
	if err != nil {
		t.Fatal(err)
	}
	RegisterDBEncryptionKey(filepath.Join(app.Dir, "data.db"), key)
	owner, err := appMCPOperationOwnerID(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	return app, key, owner
}

func initializeEncryptionStateFixture(t *testing.T, ctx context.Context, tx *sql.Tx, owner string, key []byte) (*appEncryptionState, error) {
	t.Helper()
	var exists int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM main.sqlite_schema WHERE lower(name)=lower(?)", "_benmore_mcp_operations").Scan(&exists); err != nil {
		return nil, err
	}
	if exists == 0 {
		if err := initializeAppMCPOperationStorage(ctx, tx); err != nil {
			return nil, err
		}
	}
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM main.sqlite_schema WHERE lower(name)=lower(?)", "_benmore_mcp_command_approvals").Scan(&exists); err != nil {
		return nil, err
	}
	if exists == 0 {
		if err := initializeAppMCPCommandApprovalStorage(ctx, tx); err != nil {
			return nil, err
		}
	}
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM main.sqlite_schema WHERE lower(name)=lower(?)", "_benmore_mcp_command_attempts").Scan(&exists); err != nil {
		return nil, err
	}
	if exists == 0 {
		if err := initializeAppMCPCommandAttemptStorage(ctx, tx); err != nil {
			return nil, err
		}
	}
	return initializeAppEncryptionState(ctx, tx, owner, key)
}

func TestAppEncryptionStateRoundTripAndAuthenticatedPayload(t *testing.T) {
	app, key, owner := appEncryptionStateFixture(t)
	tx, err := app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	state, err := initializeEncryptionStateFixture(t, context.Background(), tx, owner, key)
	if err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if state.Version != 2 || state.CommandStorageVersion != 2 || state.OwnerID != owner || len(state.KeyGeneration) != 64 || !state.OperationStorageProvisioned || state.LastRotationID != "" {
		t.Fatalf("unexpected initialized state: %+v", state)
	}
	tx, err = app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	got, err := readAppEncryptionState(context.Background(), tx, owner, key)
	_ = tx.Rollback()
	if err != nil || got == nil || *got != *state {
		t.Fatalf("authenticated state readback=%+v err=%v", got, err)
	}
	wrong, _ := cryptoDeriveAppKey(strings.Repeat("8b", 32))
	tx, err = app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readAppEncryptionState(context.Background(), tx, owner, wrong); err == nil {
		_ = tx.Rollback()
		t.Fatal("wrong key authenticated encryption state")
	}
	_ = tx.Rollback()
}

func TestAppEncryptionStateTamperingAndStrictSchemaFailClosed(t *testing.T) {
	app, key, owner := appEncryptionStateFixture(t)
	tx, err := app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := initializeEncryptionStateFixture(t, context.Background(), tx, owner, key); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec("UPDATE main._benmore_encryption_state SET owner_id=?", strings.Repeat("0", 64)); err != nil {
		t.Fatal(err)
	}
	tx, err = app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readAppEncryptionState(context.Background(), tx, owner, key); err == nil {
		_ = tx.Rollback()
		t.Fatal("altered owner was accepted")
	}
	_ = tx.Rollback()
	if _, err := app.DB.Exec("UPDATE main._benmore_encryption_state SET owner_id=?", owner); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec("CREATE INDEX state_fixture ON _benmore_encryption_state(owner_id)"); err != nil {
		t.Fatal(err)
	}
	tx, err = app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readAppEncryptionState(context.Background(), tx, owner, key); err == nil {
		_ = tx.Rollback()
		t.Fatal("extra index was accepted")
	}
	_ = tx.Rollback()
}

func TestAppEncryptionStateRejectsUnknownAndTrailingPayload(t *testing.T) {
	app, key, owner := appEncryptionStateFixture(t)
	tx, err := app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	state, err := initializeEncryptionStateFixture(t, context.Background(), tx, owner, key)
	if err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	valid, err := json.Marshal(appEncryptionStatePayloadFor(*state))
	if err != nil {
		t.Fatal(err)
	}
	unknown := append(append([]byte(nil), valid[:len(valid)-1]...), []byte(`,"extra":true}`)...)
	trailing := append(append([]byte(nil), valid...), []byte(` {}`)...)
	for _, bad := range [][]byte{unknown, trailing} {
		sealed, err := fieldEncryptCtx(key, "_benmore_encryption_state", "verification_ciphertext", string(bad))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := app.DB.Exec("UPDATE main._benmore_encryption_state SET verification_ciphertext=?", sealed); err != nil {
			t.Fatal(err)
		}
		tx, err := app.DB.Begin()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := readAppEncryptionState(context.Background(), tx, owner, key); err == nil {
			_ = tx.Rollback()
			t.Fatal("unknown or trailing payload bytes were accepted")
		}
		_ = tx.Rollback()
	}
}

func TestAppEncryptionStateRequiresAtomicOperationStoragePair(t *testing.T) {
	app, key, owner := appEncryptionStateFixture(t)
	tx, err := app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := initializeAppMCPOperationStorage(context.Background(), tx); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if _, err := initializeEncryptionStateFixture(t, context.Background(), tx, owner, key); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	var objects int
	if err := app.DB.QueryRow("SELECT count(*) FROM main.sqlite_schema WHERE name IN ('_benmore_mcp_operations','_benmore_mcp_command_approvals','_benmore_encryption_state')").Scan(&objects); err != nil || objects != 0 {
		t.Fatalf("paired initialization rollback left %d objects: %v", objects, err)
	}
}

func TestAppEncryptionStateRejectsRowAndAuthenticatedPayloadMismatches(t *testing.T) {
	app, key, owner := appEncryptionStateFixture(t)
	tx, err := app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	state, err := initializeEncryptionStateFixture(t, context.Background(), tx, owner, key)
	if err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	validCiphertext, err := sealAppEncryptionState(key, *state)
	if err != nil {
		t.Fatal(err)
	}
	read := func() error {
		t.Helper()
		tx, err := app.DB.Begin()
		if err != nil {
			return err
		}
		_, err = readAppEncryptionState(context.Background(), tx, owner, key)
		_ = tx.Rollback()
		return err
	}
	restore := func(tb *testing.T) {
		tb.Helper()
		if _, err := app.DB.Exec("UPDATE main._benmore_encryption_state SET owner_id=?,key_generation=?,operation_storage_provisioned=1,command_storage_version=2,last_rotation_id=NULL,verification_ciphertext=?", owner, state.KeyGeneration, validCiphertext); err != nil {
			tb.Fatal(err)
		}
	}
	cases := []struct {
		name   string
		mutate func() error
	}{
		{"row owner", func() error {
			_, err := app.DB.Exec("UPDATE main._benmore_encryption_state SET owner_id=?", strings.Repeat("0", 64))
			return err
		}},
		{"row generation", func() error {
			_, err := app.DB.Exec("UPDATE main._benmore_encryption_state SET key_generation=?", strings.Repeat("1", 64))
			return err
		}},
		{"provisioned flag", func() error {
			_, err := app.DB.Exec("UPDATE main._benmore_encryption_state SET operation_storage_provisioned=0,command_storage_version=0")
			return err
		}},
		{"rotation identifier", func() error {
			_, err := app.DB.Exec("UPDATE main._benmore_encryption_state SET last_rotation_id=?", strings.Repeat("2", 64))
			return err
		}},
		{"v1 ciphertext", func() error {
			_, err := app.DB.Exec("UPDATE main._benmore_encryption_state SET verification_ciphertext='enc:v1:legacy'")
			return err
		}},
		{"wrong v2 table and column AAD", func() error {
			sealed, err := fieldEncryptCtx(key, "other_table", "other_column", "ciphertext from a different field")
			if err != nil {
				return err
			}
			_, err = app.DB.Exec("UPDATE main._benmore_encryption_state SET verification_ciphertext=?", sealed)
			return err
		}},
		{"payload domain", func() error {
			payload := appEncryptionStatePayloadFor(*state)
			payload.Domain = "other:domain"
			plain, err := json.Marshal(payload)
			if err != nil {
				return err
			}
			sealed, err := fieldEncryptCtx(key, "_benmore_encryption_state", "verification_ciphertext", string(plain))
			if err != nil {
				return err
			}
			_, err = app.DB.Exec("UPDATE main._benmore_encryption_state SET verification_ciphertext=?", sealed)
			return err
		}},
		{"payload version", func() error {
			payload := appEncryptionStatePayloadFor(*state)
			payload.Version = 1
			plain, err := json.Marshal(payload)
			if err != nil {
				return err
			}
			sealed, err := fieldEncryptCtx(key, "_benmore_encryption_state", "verification_ciphertext", string(plain))
			if err != nil {
				return err
			}
			_, err = app.DB.Exec("UPDATE main._benmore_encryption_state SET verification_ciphertext=?", sealed)
			return err
		}},
		{"payload generation", func() error {
			payload := appEncryptionStatePayloadFor(*state)
			payload.KeyGeneration = strings.Repeat("3", 64)
			plain, err := json.Marshal(payload)
			if err != nil {
				return err
			}
			sealed, err := fieldEncryptCtx(key, "_benmore_encryption_state", "verification_ciphertext", string(plain))
			if err != nil {
				return err
			}
			_, err = app.DB.Exec("UPDATE main._benmore_encryption_state SET verification_ciphertext=?", sealed)
			return err
		}},
		{"payload provisioned flag", func() error {
			payload := appEncryptionStatePayloadFor(*state)
			payload.OperationStorageProvisioned = false
			payload.CommandStorageVersion = 0
			plain, err := json.Marshal(payload)
			if err != nil {
				return err
			}
			sealed, err := fieldEncryptCtx(key, "_benmore_encryption_state", "verification_ciphertext", string(plain))
			if err != nil {
				return err
			}
			_, err = app.DB.Exec("UPDATE main._benmore_encryption_state SET verification_ciphertext=?", sealed)
			return err
		}},
		{"payload rotation identifier", func() error {
			payload := appEncryptionStatePayloadFor(*state)
			rotation := strings.Repeat("4", 64)
			payload.LastRotationID = &rotation
			plain, err := json.Marshal(payload)
			if err != nil {
				return err
			}
			sealed, err := fieldEncryptCtx(key, "_benmore_encryption_state", "verification_ciphertext", string(plain))
			if err != nil {
				return err
			}
			_, err = app.DB.Exec("UPDATE main._benmore_encryption_state SET verification_ciphertext=?", sealed)
			return err
		}},
		{"noncanonical payload", func() error {
			plain, err := json.Marshal(appEncryptionStatePayloadFor(*state))
			if err != nil {
				return err
			}
			sealed, err := fieldEncryptCtx(key, "_benmore_encryption_state", "verification_ciphertext", " "+string(plain))
			if err != nil {
				return err
			}
			_, err = app.DB.Exec("UPDATE main._benmore_encryption_state SET verification_ciphertext=?", sealed)
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			restore(t)
			if err := tc.mutate(); err != nil {
				t.Fatal(err)
			}
			if err := read(); err == nil {
				t.Fatal("mismatched state was accepted")
			}
			restore(t)
			if err := read(); err != nil {
				t.Fatalf("restored valid state failed: %v", err)
			}
		})
	}
	rotation := strings.Repeat("4", 64)
	validRotating := *state
	validRotating.LastRotationID = rotation
	rotatingCiphertext, err := sealAppEncryptionState(key, validRotating)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec("UPDATE main._benmore_encryption_state SET last_rotation_id=?,verification_ciphertext=?", rotation, rotatingCiphertext); err != nil {
		t.Fatal(err)
	}
	if err := read(); err != nil {
		t.Fatalf("valid zero/non-null-rotation state failed: %v", err)
	}
	restore(t)
}

func TestAppEncryptionStateAbsenceEmptyAndIsolationBoundaries(t *testing.T) {
	app, key, owner := appEncryptionStateFixture(t)
	tx, err := app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	state, err := readAppEncryptionState(context.Background(), tx, owner, key)
	_ = tx.Rollback()
	if err != nil || state != nil {
		t.Fatalf("absent marker state=%+v err=%v", state, err)
	}
	tx, err = app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := initializeEncryptionStateFixture(t, context.Background(), tx, owner, key); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec("DELETE FROM main._benmore_encryption_state"); err != nil {
		t.Fatal(err)
	}
	tx, err = app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readAppEncryptionState(context.Background(), tx, owner, key); err == nil {
		_ = tx.Rollback()
		t.Fatal("empty marker table was accepted")
	}
	_ = tx.Rollback()
	if _, err := app.DB.Exec("DROP TABLE main._benmore_encryption_state"); err != nil {
		t.Fatal(err)
	}

	app.DB.SetMaxOpenConns(1)
	conn, err := app.DB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			t.Errorf("close isolation fixture connection: %v", err)
		}
	}()
	initTx, err := conn.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	validState, err := initializeEncryptionStateFixture(t, context.Background(), initTx, owner, key)
	if err != nil {
		_ = initTx.Rollback()
		t.Fatal(err)
	}
	if err := initTx.Commit(); err != nil {
		t.Fatal(err)
	}
	readSameConn := func() error {
		t.Helper()
		tx, err := conn.BeginTx(context.Background(), nil)
		if err != nil {
			return err
		}
		got, readErr := readAppEncryptionState(context.Background(), tx, owner, key)
		_ = tx.Rollback()
		if readErr != nil {
			return readErr
		}
		if got == nil || *got != *validState {
			return fmt.Errorf("same-connection state differs: got=%+v want=%+v", got, validState)
		}
		return nil
	}
	if err := readSameConn(); err != nil {
		t.Fatalf("valid same-connection state control: %v", err)
	}
	if _, err := conn.ExecContext(context.Background(), "CREATE TEMP TABLE lifecycle_temp_fixture(value INTEGER)"); err != nil {
		t.Fatal(err)
	}
	if err := readSameConn(); err == nil {
		t.Fatal("temporary schema was accepted")
	}
	if _, err := conn.ExecContext(context.Background(), "DROP TABLE temp.lifecycle_temp_fixture"); err != nil {
		t.Fatal(err)
	}
	var tempObjects int
	if err := conn.QueryRowContext(context.Background(), "SELECT count(*) FROM temp.sqlite_schema").Scan(&tempObjects); err != nil || tempObjects != 0 {
		t.Fatalf("TEMP cleanup left %d objects: %v", tempObjects, err)
	}
	if err := readSameConn(); err != nil {
		t.Fatalf("state after TEMP cleanup: %v", err)
	}
	if _, err := conn.ExecContext(context.Background(), "ATTACH DATABASE ':memory:' AS lifecycle_attached_fixture"); err != nil {
		t.Fatal(err)
	}
	if err := readSameConn(); err == nil {
		t.Fatal("attached database was accepted")
	}
	if _, err := conn.ExecContext(context.Background(), "DETACH DATABASE lifecycle_attached_fixture"); err != nil {
		t.Fatal(err)
	}
	rows, err := conn.QueryContext(context.Background(), "PRAGMA database_list")
	if err != nil {
		t.Fatal(err)
	}
	var dbNames []string
	for rows.Next() {
		var seq int
		var name, file string
		if err := rows.Scan(&seq, &name, &file); err != nil {
			_ = rows.Close()
			t.Fatal(err)
		}
		dbNames = append(dbNames, name)
	}
	rowsErr, closeErr := rows.Err(), rows.Close()
	if rowsErr != nil || closeErr != nil || len(dbNames) != 2 || dbNames[0] != "main" || dbNames[1] != "temp" {
		t.Fatalf("isolation fixture cleanup incomplete: names=%v rows=%v close=%v", dbNames, rowsErr, closeErr)
	}
	if err := readSameConn(); err != nil {
		t.Fatalf("state after ATTACH cleanup: %v", err)
	}
}

func TestAppEncryptionStateRejectsAlteredDefinitionAndView(t *testing.T) {
	for _, tc := range []struct{ name, mutation string }{
		{"extra column", "ALTER TABLE main._benmore_encryption_state ADD COLUMN unexpected TEXT"},
		{"trigger", "CREATE TRIGGER state_extra AFTER UPDATE ON _benmore_encryption_state BEGIN SELECT 1; END"},
		{"wrong-case trigger target", "CREATE TRIGGER state_alias AFTER UPDATE ON _BENMORE_ENCRYPTION_STATE BEGIN SELECT 1; END"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, key, owner := appEncryptionStateFixture(t)
			tx, err := app.DB.Begin()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := initializeEncryptionStateFixture(t, context.Background(), tx, owner, key); err != nil {
				_ = tx.Rollback()
				t.Fatal(err)
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
			if _, err := app.DB.Exec(tc.mutation); err != nil {
				t.Fatal(err)
			}
			tx, err = app.DB.Begin()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := readAppEncryptionState(context.Background(), tx, owner, key); err == nil {
				_ = tx.Rollback()
				t.Fatal("altered state definition was accepted")
			}
			_ = tx.Rollback()
		})
	}
	t.Run("view in reserved name", func(t *testing.T) {
		app, key, owner := appEncryptionStateFixture(t)
		if _, err := app.DB.Exec("CREATE VIEW main._BENMORE_ENCRYPTION_STATE AS SELECT 1 AS singleton"); err != nil {
			t.Fatal(err)
		}
		tx, err := app.DB.Begin()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := readAppEncryptionState(context.Background(), tx, owner, key); err == nil {
			_ = tx.Rollback()
			t.Fatal("view impersonated the marker table")
		}
		_ = tx.Rollback()
	})
}
