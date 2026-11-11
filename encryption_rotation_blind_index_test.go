//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

// blindRotationFixture is an app shaped like the one the 2026-11-05 builder
// round reproduced the key-rotation defects on: INTEGER PRIMARY KEY tables,
// blind-indexed text and integer columns, a Prisma @updatedAt column, same-row
// computed expressions (one over an encrypted column), an aggregate computed
// over a child table with its own encrypted column, and content history.
type blindRotationFixture struct {
	app          *App
	mux          *http.ServeMux
	owner, admin string
	ownerID      int64
}

const blindRotationPast = "2026-01-01 00:00:00"

func newBlindRotationFixture(t *testing.T) blindRotationFixture {
	t.Helper()
	previousKey, previousEphemeral := appEncryptionKey, appEncryptionKeyEphemeral
	previousBlind := appBlindIndexKey.Load()
	t.Cleanup(func() {
		appEncryptionKey, appEncryptionKeyEphemeral = previousKey, previousEphemeral
		appBlindIndexKey.Store(previousBlind)
	})
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, dir, "schema.prisma", `model Patient {
 id Int @id @default(autoincrement())
 user_id Int?
 full_name String
 ssn String?
 salary Int?
 status String @default("open")
 label String?
 ssn_last4 String?
 note_count Int @default(0)
 created_at DateTime @default(now())
 updated_at DateTime @default(now()) @updatedAt
 @@map("patients")
}
model CaseNote {
 id Int @id @default(autoincrement())
 user_id Int?
 patient_id Int
 title String
 private_remark String?
 created_at DateTime @default(now())
 updated_at DateTime @default(now()) @updatedAt
 @@map("case_notes")
}`)
	writeTestFile(t, dir, "app.yaml", `auth: {identifier: email}
access:
 patients: {read: self, write: self, update: self, delete: self}
 case_notes: {read: self, write: self, update: self, delete: self}
versioned: [patients, case_notes]
`)
	writeTestFile(t, dir, "encrypted.yaml", `tables:
 patients:
  fields: [ssn, salary]
  blind_index: [ssn, salary]
  unmask_roles: [owner]
 case_notes:
  fields: [private_remark]
  unmask_roles: [owner]
`)
	writeTestFile(t, dir, "computed.yaml", `fields:
 - table: patients
   column: label
   expr: "upper(full_name) || ' [' || status || ']'"
 - table: patients
   column: ssn_last4
   expr: "substr(ssn, -4)"
 - table: patients
   column: note_count
   sql: "SELECT COUNT(*) FROM case_notes WHERE patient_id = ?"
   triggers:
    - table: case_notes
      on: [insert, update, delete]
      fk: patient_id
`)
	app, err := loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	t.Cleanup(func() { dbCryptoRegistry.Delete(canonicalDBPath(filepath.Join(dir, "data.db"))) })
	f := blindRotationFixture{app: app, mux: buildAppMux(app, true, "https://opaque.example.invalid")}
	f.owner = createCrudScopeSession(t, app, "owner@example.com", "user", "", "")
	f.admin = createCrudScopeSession(t, app, "admin@example.com", "admin", "", "")
	if err := app.DB.QueryRow(`SELECT id FROM _benmore_users WHERE email='owner@example.com'`).Scan(&f.ownerID); err != nil {
		t.Fatal(err)
	}
	return f
}

// seed writes rows through the database triggers (encryption, blind index,
// computed), then backdates them as rows imported long ago and never edited
// since: no history, and created_at = updated_at in the past.
func (f blindRotationFixture) seed(t *testing.T) {
	t.Helper()
	db := f.app.DB
	for i, p := range []struct {
		name, ssn string
		salary    any
	}{
		{"ada", "111-11-1111", 31000},
		{"bob", "222-22-2222", 42000},
		{"cyd", "333-33-3333", nil},
		{"dee", "", 55000},
	} {
		appEncryptionRotationMustExec(t, db, `INSERT INTO patients(id,user_id,full_name,ssn,salary) VALUES(?,?,?,?,?)`, i+1, f.ownerID, p.name, p.ssn, p.salary)
	}
	appEncryptionRotationMustExec(t, db, `INSERT INTO patients(id,user_id,full_name) VALUES(5,?,'eve')`, f.ownerID)
	appEncryptionRotationMustExec(t, db, `INSERT INTO case_notes(id,user_id,patient_id,title,private_remark) VALUES(1,?,1,'intake','remark one'),(2,?,1,'follow-up','remark two')`, f.ownerID, f.ownerID)
	// Child rows first: a child UPDATE recalculates the parent's aggregate,
	// which stamps the parent's updated_at.
	appEncryptionRotationMustExec(t, db, `UPDATE case_notes SET created_at=?, updated_at=?`, blindRotationPast, blindRotationPast)
	appEncryptionRotationMustExec(t, db, `UPDATE patients SET created_at=?, updated_at=?`, blindRotationPast, blindRotationPast)
	appEncryptionRotationMustExec(t, db, `DELETE FROM patients_history`)
	appEncryptionRotationMustExec(t, db, `DELETE FROM case_notes_history`)
}

// rowState is everything a re-encryption must leave alone.
func (f blindRotationFixture) rowState(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, q := range []string{
		`SELECT 'patients/'||id, CAST(updated_at AS TEXT)||'|'||created_at||'|'||COALESCE(label,'')||'|'||COALESCE(ssn_last4,'')||'|'||note_count FROM patients`,
		`SELECT 'case_notes/'||id, CAST(updated_at AS TEXT)||'|'||created_at FROM case_notes`,
		`SELECT 'history', (SELECT COUNT(*) FROM patients_history)||'|'||(SELECT COUNT(*) FROM case_notes_history)`,
	} {
		rows, err := f.app.DB.Query(q)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var k, v string
			if err := rows.Scan(&k, &v); err != nil {
				t.Fatal(err)
			}
			out[k] = v
		}
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return out
}

func (f blindRotationFixture) search(t *testing.T, query string) []float64 {
	t.Helper()
	rec := crudScopeRequest(t, f.mux, http.MethodGet, "/api/patients?"+query+"&fields=id", f.owner, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("search %s: %d %s", query, rec.Code, rec.Body.String())
	}
	var rows []map[string]any
	mustDecodeBody(t, rec, &rows)
	var ids []float64
	for _, row := range rows {
		id, _ := row["id"].(float64)
		ids = append(ids, id)
	}
	return ids
}

func (f blindRotationFixture) expectFound(t *testing.T, when string) {
	t.Helper()
	for query, want := range map[string]float64{
		"ssn=111-11-1111": 1,
		"ssn=222-22-2222": 2,
		"ssn=333-33-3333": 3,
		"salary=31000":    1,
		"salary=55000":    4,
	} {
		if got := f.search(t, query); len(got) != 1 || got[0] != want {
			t.Errorf("%s: ?%s found %v, want [%v]", when, query, got, want)
		}
	}
}

func (f blindRotationFixture) blindValues(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	rows, err := f.app.DB.Query(`SELECT id, COALESCE(ssn_blind,'<null>'), COALESCE(salary_blind,'<null>') FROM patients ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id int
		var ssn, salary string
		if err := rows.Scan(&id, &ssn, &salary); err != nil {
			t.Fatal(err)
		}
		out[fmt.Sprintf("%d/ssn", id)] = ssn
		out[fmt.Sprintf("%d/salary", id)] = salary
	}
	return out
}

func (f blindRotationFixture) lastAudit(t *testing.T, action string) map[string]any {
	t.Helper()
	var raw sql.NullString
	err := f.app.DB.QueryRow(`SELECT new_values FROM _benmore_audit_log WHERE action=? ORDER BY id DESC LIMIT 1`, action).Scan(&raw)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]any{}
	if raw.Valid && raw.String != "" {
		if err := json.Unmarshal([]byte(raw.String), &out); err != nil {
			t.Fatal(err)
		}
	}
	return out
}

func (f blindRotationFixture) post(t *testing.T, path string, body any) map[string]any {
	t.Helper()
	rec := crudScopeRequest(t, f.mux, http.MethodPost, path, f.admin, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST %s: %d %s", path, rec.Code, rec.Body.String())
	}
	out := map[string]any{}
	mustDecodeBody(t, rec, &out)
	return out
}

// After a key rotation, every row written before it must still be found by
// equality search, and the rotation must not look like an edit: updated_at,
// computed values and history stay as they were, so ?as_of= for an instant
// before the rotation and an _expected_updated_at read before it still work.
func TestKeyRotationKeepsEqualitySearchAndRowTimestamps(t *testing.T) {
	f := newBlindRotationFixture(t)
	f.seed(t)
	f.expectFound(t, "before rotation")
	before := f.rowState(t)
	rec := crudScopeRequest(t, f.mux, http.MethodGet, "/api/patients/2", f.owner, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("read before rotation: %d %s", rec.Code, rec.Body.String())
	}
	var read map[string]any
	mustDecodeBody(t, rec, &read)
	token := read["updated_at"]
	if token == nil {
		t.Fatalf("fixture read has no updated_at: %v", read)
	}

	out := f.post(t, "/api/_internal/encryption/rotate", map[string]any{"new_key": strings.Repeat("rotated-key-", 6), "confirm": true})
	if out["status"] != "rotated" {
		t.Fatalf("rotation response: %v", out)
	}
	// ssn on rows 1-3 and salary on rows 1, 2 and 4; the empty ssn has no index.
	if got, _ := out["blind_index_rows_rebuilt"].(float64); got != 6 {
		t.Errorf("rotation reported %v blind-index rows rebuilt, want 6: %v", out["blind_index_rows_rebuilt"], out)
	}
	f.expectFound(t, "after rotation")
	if after := f.rowState(t); fmt.Sprint(after) != fmt.Sprint(before) {
		t.Errorf("rotation changed row state:\nbefore %v\nafter  %v", before, after)
	}
	for _, path := range []string{"/api/patients/1?as_of=2026-02-01T00:00:00Z", "/api/case_notes/2?as_of=2026-02-01T00:00:00Z"} {
		if rec := crudScopeRequest(t, f.mux, http.MethodGet, path, f.owner, nil); rec.Code != http.StatusOK {
			t.Errorf("GET %s after rotation: %d %s", path, rec.Code, rec.Body.String())
		}
	}
	rec = crudScopeRequest(t, f.mux, http.MethodPatch, "/api/patients/2", f.owner, map[string]any{"status": "closed", "_expected_updated_at": token})
	if rec.Code != http.StatusOK {
		t.Errorf("PATCH with the updated_at read before rotation: %d %s", rec.Code, rec.Body.String())
	}
	audit := f.lastAudit(t, "encryption_key_rotated")
	if got, _ := audit["blind_index_rows_rebuilt"].(float64); got != 6 {
		t.Errorf("rotation audit records %v blind-index rows, want 6: %v", audit["blind_index_rows_rebuilt"], audit)
	}
	// A row written after rotation indexes under the new key too.
	appEncryptionRotationMustExec(t, f.app.DB, `INSERT INTO patients(id,user_id,full_name,ssn) VALUES(6,?,'fay','010-10-1010')`, f.ownerID)
	if got := f.search(t, "ssn=010-10-1010"); len(got) != 1 || got[0] != 6 {
		t.Errorf("row written after rotation: found %v", got)
	}
}

// The repair endpoint must index rows of INTEGER PRIMARY KEY tables (every
// Prisma model), where SQLite names `SELECT rowid` after the id column.
func TestBlindIndexBackfillEndpointIndexesEveryRow(t *testing.T) {
	f := newBlindRotationFixture(t)
	f.seed(t)
	want := f.blindValues(t)
	// Rows written with ciphertext (an import, a restore) carry no index.
	appEncryptionRotationMustExec(t, f.app.DB, `UPDATE patients SET ssn_blind=NULL, updated_at=?`, blindRotationPast)
	appEncryptionRotationMustExec(t, f.app.DB, `DELETE FROM patients_history`)
	before := f.rowState(t)
	if got := f.search(t, "ssn=111-11-1111"); len(got) != 0 {
		t.Fatalf("fixture: unindexed row found: %v", got)
	}

	dry := f.post(t, "/api/_internal/blind/backfill", map[string]any{"table": "patients", "column": "ssn"})
	if dry["dry_run"] != true || dry["rows"] != float64(3) {
		t.Errorf("dry run: %v, want 3 rows", dry)
	}
	if got := f.blindValues(t)["1/ssn"]; got != "<null>" {
		t.Errorf("dry run wrote an index: %q", got)
	}
	out := f.post(t, "/api/_internal/blind/backfill", map[string]any{"table": "patients", "column": "ssn", "confirm": true})
	if out["dry_run"] != false || out["rows"] != float64(3) {
		t.Errorf("backfill: %v, want 3 rows", out)
	}
	if got := f.blindValues(t); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("backfilled indexes differ from the write-path ones:\n got %v\nwant %v", got, want)
	}
	f.expectFound(t, "after backfill")
	if after := f.rowState(t); fmt.Sprint(after) != fmt.Sprint(before) {
		t.Errorf("backfill changed row state:\nbefore %v\nafter  %v", before, after)
	}
	if audit := f.lastAudit(t, "blind_index_backfilled"); audit["rows"] != float64(3) {
		t.Errorf("backfill audit: %v", audit)
	}
	// A second run finds every row already indexed and writes nothing.
	if again := f.post(t, "/api/_internal/blind/backfill", map[string]any{"table": "patients", "column": "ssn", "confirm": true}); again["rows"] != float64(3) || again["changed"] != float64(0) {
		t.Errorf("repeat backfill: %v", again)
	}
}

// RebuildAllBlindIndices recomputes every blind column under the current key
// in one transaction, or changes nothing.
func TestRebuildAllBlindIndicesRebuildsStaleRows(t *testing.T) {
	f := newBlindRotationFixture(t)
	f.seed(t)
	want := f.blindValues(t)
	appEncryptionRotationMustExec(t, f.app.DB, `UPDATE patients SET ssn_blind=CASE WHEN ssn_blind<>'' THEN 'stale' ELSE ssn_blind END, salary_blind=CASE WHEN salary IS NOT NULL THEN 'stale' END, updated_at=?`, blindRotationPast)
	appEncryptionRotationMustExec(t, f.app.DB, `DELETE FROM patients_history`)
	before := f.rowState(t)

	n, err := RebuildAllBlindIndices(f.app)
	if err != nil || n != 6 {
		t.Fatalf("RebuildAllBlindIndices = %d, %v; want 6", n, err)
	}
	if got := f.blindValues(t); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("rebuilt indexes differ from the write-path ones:\n got %v\nwant %v", got, want)
	}
	f.expectFound(t, "after rebuild")
	if after := f.rowState(t); fmt.Sprint(after) != fmt.Sprint(before) {
		t.Errorf("rebuild changed row state:\nbefore %v\nafter  %v", before, after)
	}
	if audit := f.lastAudit(t, "blind_index_rebuilt"); audit["rows_rebuilt"] != float64(6) {
		t.Errorf("rebuild audit: %v", audit)
	}

	// A value the key cannot open fails the whole rebuild loudly, instead of
	// indexing the decryption-failure mask, and rolls back the columns it had
	// already rebuilt (ssn is rebuilt before salary).
	appEncryptionRotationMustExec(t, f.app.DB, `UPDATE patients SET ssn_blind='stale', updated_at=? WHERE ssn_blind<>''`, blindRotationPast)
	tx, err := f.app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	versionTriggers, err := suspendVersioningTriggers(tx)
	if err != nil {
		t.Fatal(err)
	}
	encryptionTriggers, err := suspendEncryptionTriggers(tx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`UPDATE patients SET salary='enc:v2:corrupt', updated_at=? WHERE id=4`, blindRotationPast); err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(restoreEncryptionTriggers(tx, encryptionTriggers), restoreVersioningTriggers(tx, versionTriggers), tx.Commit()); err != nil {
		t.Fatal(err)
	}
	n, err = RebuildAllBlindIndices(f.app)
	if err == nil || !strings.Contains(err.Error(), "patients.salary") || !strings.Contains(err.Error(), "row 4") {
		t.Fatalf("rebuild over an unreadable value = %d, %v; want an error naming patients.salary row 4", n, err)
	}
	if got := f.blindValues(t)["1/ssn"]; got != "stale" {
		t.Errorf("failed rebuild kept a partial write: 1/ssn = %q", got)
	}
}

// Rotation drops and recreates triggers in its transaction. On a table the
// MCP connector enrolled for approved writes, the revision triggers must still
// fire first afterwards, or every insert that an encryption or computed
// trigger rewrites fails with "revision ledger row missing".
func TestKeyRotationKeepsConnectorRevisionTriggersFirst(t *testing.T) {
	t.Setenv("BENMORE_CLUSTER", "false")
	previousKey, previousEphemeral := appEncryptionKey, appEncryptionKeyEphemeral
	previousBlind := appBlindIndexKey.Load()
	t.Cleanup(func() {
		appEncryptionKey, appEncryptionKeyEphemeral = previousKey, previousEphemeral
		appBlindIndexKey.Store(previousBlind)
	})
	f := newCanonicalUpdateFixture(t, "", "", "")
	session := GetSessionFromDB(f.app.DB, f.sid)
	if session == nil {
		t.Fatal("fixture session is missing")
	}
	if _, err := f.app.DB.Exec("INSERT INTO main.notes(user_id,title,secret) VALUES(?,?,?)", session.UserID, "Before Rotation", "first-secret"); err != nil {
		t.Fatalf("insert before rotation: %v", err)
	}
	if _, err := RotateEncryptionKey(f.app, strings.Repeat("rotated-key-", 6), false); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	result, err := f.app.DB.Exec("INSERT INTO main.notes(user_id,title,secret) VALUES(?,?,?)", session.UserID, "After Rotation", "second-secret")
	if err != nil {
		t.Fatalf("insert into the enrolled table after rotation: %v", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	assertOneLiveLedgerRow(t, f.app.DB, "notes", id)
	if _, err := verifyTestRevisionEnrollment(t, f.app, snapshotAppMCPGeneration(f.app)); err != nil {
		t.Fatalf("revision enrollment does not verify after rotation: %v", err)
	}
}
