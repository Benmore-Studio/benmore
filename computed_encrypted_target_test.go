//go:build !cli && !windows

package main

import (
	"context"
	"database/sql"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const encTargetSchema = `model Order {
  id        Int     @id @default(autoincrement())
  qty       Int     @default(0)
  price     Int     @default(0)
  total     Int?
  noteTotal Int?    @map("note_total")
  label     String?
  userId    Int?    @map("user_id")
  @@map("orders")
}

model OrderNote {
  id      Int  @id @default(autoincrement())
  orderId Int  @map("order_id")
  amount  Int  @default(0)
  @@map("order_notes")
}
`

const encTargetComputed = `orders:
  total:
    expr: "qty * price"
  note_total:
    sql: "SELECT COALESCE(SUM(amount), 0) FROM order_notes WHERE order_id = ?"
    triggers:
      - table: order_notes
        on: [insert, update, delete]
        fk: order_id
`

const encTargetEncrypted = "tables:\n  orders:\n    fields: [total, note_total]\n    unmask_roles: [admin]\n"

func loadEncTargetApp(t *testing.T, encrypted string) *App {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, dir, "schema.prisma", encTargetSchema)
	writeTestFile(t, dir, "computed.yaml", encTargetComputed)
	writeTestFile(t, dir, "encrypted.yaml", encrypted)
	writeTestFile(t, dir, "app.yaml", "auth:\n  signup: false\n")
	writeTestFile(t, dir, "env.yaml", "ENCRYPTION_KEY: "+strings.Repeat("ab", 32)+"\n")
	app, err := loadAppWithOptions(dir, appLoadOptions{startup: true})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	t.Cleanup(func() {
		app.Shutdown()
		dbCryptoRegistry.Delete(canonicalDBPath(filepath.Join(dir, "data.db")))
	})
	return app
}

// storedText reads a column straight from disk.
func storedText(t *testing.T, db *sql.DB, table, column string, id int64) sql.NullString {
	t.Helper()
	var stored sql.NullString
	if err := db.QueryRow("SELECT CAST("+quoteIdent(column)+" AS TEXT) FROM "+quoteIdent(table)+" WHERE id = ?", id).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	return stored
}

// assertSealed checks a column holds field ciphertext (bound to the field)
// that decrypts to want, and returns that ciphertext.
func assertSealed(t *testing.T, db *sql.DB, table, column string, id int64, want string) string {
	t.Helper()
	stored := storedText(t, db, table, column, id)
	if !stored.Valid || !strings.HasPrefix(stored.String, "enc:v2:") {
		t.Fatalf("%s.%s of row %d is stored as %q, want enc:v2: ciphertext of %q", table, column, id, stored.String, want)
	}
	got, ok := fieldCiphertextOpen(cryptoKeyForQuerier(db), table, column, stored.String)
	if !ok {
		t.Fatalf("%s.%s of row %d is not ciphertext of that field: %q", table, column, id, stored.String)
	}
	if got != want {
		t.Fatalf("%s.%s of row %d decrypts to %q, want %q", table, column, id, got, want)
	}
	return stored.String
}

func insertOrder(t *testing.T, db *sql.DB, query string, args ...any) int64 {
	t.Helper()
	res, err := db.Exec(query, args...)
	if err != nil {
		t.Fatal(err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// A computed column that encrypted.yaml also encrypts is stored as ciphertext
// like every other encrypted column (security.md 26). Its trigger used to
// write the plaintext and leave sealing to the encryption trigger, but the
// computed update trigger fired by the encryption trigger's own write wrote
// the plaintext back while the encryption trigger was still running, so
// SQLite did not run it again: `total` read "21" on disk.
func TestEncryptedComputedColumnIsStoredEncrypted(t *testing.T) {
	app := loadEncTargetApp(t, encTargetEncrypted)

	t.Run("expr", func(t *testing.T) {
		id := insertOrder(t, app.DB, `INSERT INTO orders (qty, price) VALUES (3, 7)`)
		assertSealed(t, app.DB, "orders", "total", id, "21")
		mustExecArgs(t, app.DB, `UPDATE orders SET qty = 5 WHERE id = ?`, id)
		sealed := assertSealed(t, app.DB, "orders", "total", id, "35")

		// An unchanged value is not rewritten (a new nonce would be a new
		// stored value for content history and the connector's revisions).
		mustExecArgs(t, app.DB, `UPDATE orders SET label = 'x' WHERE id = ?`, id)
		if again := assertSealed(t, app.DB, "orders", "total", id, "35"); again != sealed {
			t.Fatalf("an update that leaves total unchanged rewrote its ciphertext")
		}

		// A direct write of the column (SQL in a flow, hook or migration)
		// is recalculated and stays sealed whichever trigger runs first.
		mustExecArgs(t, app.DB, `UPDATE orders SET total = 99 WHERE id = ?`, id)
		assertSealed(t, app.DB, "orders", "total", id, "35")
		mustExecArgs(t, app.DB, `UPDATE orders SET total = NULL WHERE id = ?`, id)
		assertSealed(t, app.DB, "orders", "total", id, "35")
		supplied := insertOrder(t, app.DB, `INSERT INTO orders (qty, price, total) VALUES (2, 3, 50)`)
		assertSealed(t, app.DB, "orders", "total", supplied, "6")
	})

	// Aggregate (sql:) field, recalculated by triggers on the child table.
	t.Run("sql", func(t *testing.T) {
		id := insertOrder(t, app.DB, `INSERT INTO orders (qty, price) VALUES (2, 2)`)
		other := insertOrder(t, app.DB, `INSERT INTO orders (qty, price) VALUES (1, 1)`)
		mustExecArgs(t, app.DB, `INSERT INTO order_notes (order_id, amount) VALUES (?, 4), (?, 6)`, id, id)
		assertSealed(t, app.DB, "orders", "note_total", id, "10")
		mustExecArgs(t, app.DB, `UPDATE order_notes SET amount = 9 WHERE order_id = ? AND amount = 4`, id)
		assertSealed(t, app.DB, "orders", "note_total", id, "15")
		// Moving a note recalculates both parents (the update_old trigger).
		mustExecArgs(t, app.DB, `UPDATE order_notes SET order_id = ? WHERE order_id = ? AND amount = 6`, other, id)
		assertSealed(t, app.DB, "orders", "note_total", id, "9")
		assertSealed(t, app.DB, "orders", "note_total", other, "6")
		mustExecArgs(t, app.DB, `DELETE FROM order_notes WHERE order_id = ?`, other)
		assertSealed(t, app.DB, "orders", "note_total", other, "0")
		// The same-row field is still sealed after the aggregate rewrote the row.
		assertSealed(t, app.DB, "orders", "total", id, "4")
	})

	// Auto-CRUD reads decrypt the sealed computed value for an unmask role.
	t.Run("crud", func(t *testing.T) {
		id := insertOrder(t, app.DB, `INSERT INTO orders (qty, price) VALUES (4, 5)`)
		sid := seedAdminSession(t, app)
		mux := buildAppMux(app, true, "http://localhost")
		patched := crudScopeRequest(t, mux, http.MethodPatch, "/api/orders/"+strconv.FormatInt(id, 10), sid, map[string]any{"qty": 6})
		if patched.Code != http.StatusOK {
			t.Fatalf("PATCH: %d %s", patched.Code, patched.Body.String())
		}
		assertSealed(t, app.DB, "orders", "total", id, "30")
		read := crudScopeRequest(t, mux, http.MethodGet, "/api/orders/"+strconv.FormatInt(id, 10), sid, nil)
		var row map[string]any
		mustDecodeBody(t, read, &row)
		if row["total"] != float64(30) {
			t.Fatalf("GET /api/orders/%d total = %v, want 30: %s", id, row["total"], read.Body.String())
		}
	})

	// A reload installs the same triggers.
	t.Run("reload", func(t *testing.T) {
		if err := reloadAppConfig(app); err != nil {
			t.Fatalf("reload: %v", err)
		}
		id := insertOrder(t, app.DB, `INSERT INTO orders (qty, price) VALUES (7, 7)`)
		assertSealed(t, app.DB, "orders", "total", id, "49")
		mustExecArgs(t, app.DB, `INSERT INTO order_notes (order_id, amount) VALUES (?, 8)`, id)
		assertSealed(t, app.DB, "orders", "note_total", id, "8")
	})
}

// A value stored in plaintext before the fix is sealed by the next write to
// its row, and `UPDATE t SET col = col` seals it at once.
func TestEncryptedComputedColumnPlaintextSealedOnNextWrite(t *testing.T) {
	app := loadEncTargetApp(t, encTargetEncrypted)
	// The triggers as they were before: the plain computed trigger.
	if err := installComputedTriggersChecked(app.DB, app.Computed); err != nil {
		t.Fatal(err)
	}
	touched := insertOrder(t, app.DB, `INSERT INTO orders (qty, price) VALUES (3, 3)`)
	repaired := insertOrder(t, app.DB, `INSERT INTO orders (qty, price) VALUES (4, 4)`)
	if stored := storedText(t, app.DB, "orders", "total", touched); stored.String != "9" {
		t.Fatalf("the old triggers should leave plaintext, got %q", stored.String)
	}
	if err := installComputedTriggersSealed(app.DB, app.Computed, app.Encrypted); err != nil {
		t.Fatal(err)
	}
	mustExecArgs(t, app.DB, `UPDATE orders SET label = 'touched' WHERE id = ?`, touched)
	assertSealed(t, app.DB, "orders", "total", touched, "9")
	mustExec(t, app.DB, `UPDATE orders SET total = total`)
	assertSealed(t, app.DB, "orders", "total", repaired, "16")
}

// A blind index on a computed encrypted column is kept current by the
// computed trigger, so equality search finds the row.
func TestEncryptedComputedColumnBlindIndex(t *testing.T) {
	app := loadEncTargetApp(t, "tables:\n  orders:\n    fields: [total]\n    blind_index: [total]\n    unmask_roles: [admin]\n")
	id := insertOrder(t, app.DB, `INSERT INTO orders (qty, price) VALUES (3, 7)`)
	assertSealed(t, app.DB, "orders", "total", id, "21")
	sid := seedAdminSession(t, app)
	mux := buildAppMux(app, true, "http://localhost")
	find := func(value string) []map[string]any {
		t.Helper()
		rec := crudScopeRequest(t, mux, http.MethodGet, "/api/orders?total="+value, sid, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET ?total=%s: %d %s", value, rec.Code, rec.Body.String())
		}
		var rows []map[string]any
		mustDecodeBody(t, rec, &rows)
		return rows
	}
	if got := find("21"); len(got) != 1 {
		t.Fatalf("?total=21 found %d rows, want 1", len(got))
	}
	mustExecArgs(t, app.DB, `UPDATE orders SET qty = 4 WHERE id = ?`, id)
	if got := find("21"); len(got) != 0 {
		t.Fatalf("?total=21 still finds the row after it became 28")
	}
	if got := find("28"); len(got) != 1 {
		t.Fatalf("?total=28 found %d rows, want 1", len(got))
	}
}

// An approved connector command writes through the same triggers: the
// computed column it fills is sealed, and the connector's trigger check
// accepts the sealed triggers (writes stay on after a reload).
func TestEncryptedComputedColumnThroughConnectorCommand(t *testing.T) {
	t.Setenv("BENMORE_CLUSTER", "false")
	app, sessionID, _ := newUnenrolledCommandProviderTaskFixtureWithManifest(t, commandTaskFlowFixture, "", func(_ *AppMCPManifest, dir string) {
		schema, err := os.ReadFile(filepath.Join(dir, "schema.sql"))
		if err != nil {
			t.Fatal(err)
		}
		withLabel := strings.Replace(string(schema), "event TEXT NOT NULL);", "event TEXT NOT NULL, event_label TEXT);", 1)
		if withLabel == string(schema) {
			t.Fatal("task fixture schema changed shape")
		}
		writeTestFile(t, dir, "schema.sql", withLabel)
		writeTestFile(t, dir, "encrypted.yaml", "tables:\n  activities:\n    fields:\n      - event_label\n")
		writeTestFile(t, dir, "computed.yaml", "fields:\n  - table: activities\n    column: event_label\n    expr: upper(actor_email)\n")
	})
	if _, err := updateAppMCPEpoch(app.Dir, true, false, true); err != nil {
		t.Fatal(err)
	}
	if _, err := initializeAppMCPRevisionEnrollment(context.Background(), app, snapshotAppMCPGeneration(app)); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if err := reloadAppConfig(app); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if _, err := enableAppMCPRevisionEnrolledWrites(context.Background(), app, snapshotAppMCPGeneration(app)); err != nil {
		t.Fatalf("enable writes: %v", err)
	}
	readback, err := runCompleteItemCommand(t, app, sessionID)
	if err != nil {
		t.Fatalf("command: %v", err)
	}
	if readback["status"] != "done" {
		t.Fatalf("command readback = %v", readback)
	}
	var id int64
	if err := app.DB.QueryRow("SELECT id FROM main.activities WHERE task_id=1").Scan(&id); err != nil {
		t.Fatal(err)
	}
	assertSealed(t, app.DB, "activities", "event_label", id, "TASK-ACTOR@EXAMPLE.COM")
	assertOneLiveLedgerRow(t, app.DB, "activities", id)
}

// On a versioned table the sealed recalculation is storage maintenance, as
// for a plain computed column: one version per write, each holding the
// sealed value the row had. Recalculations used to record versions of their
// own (one holding the NULL the row had before its first computation).
func TestEncryptedComputedColumnVersionedOneVersionPerWrite(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, dir, "schema.prisma", encTargetSchema)
	writeTestFile(t, dir, "computed.yaml", "orders:\n  total:\n    expr: \"qty * price\"\n")
	writeTestFile(t, dir, "encrypted.yaml", "tables:\n  orders:\n    fields: [total]\n")
	writeTestFile(t, dir, "app.yaml", "auth:\n  signup: false\nversioned: [orders]\n")
	writeTestFile(t, dir, "env.yaml", "ENCRYPTION_KEY: "+strings.Repeat("ab", 32)+"\n")
	app, err := loadAppWithOptions(dir, appLoadOptions{startup: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		app.Shutdown()
		dbCryptoRegistry.Delete(canonicalDBPath(filepath.Join(dir, "data.db")))
	})
	id := insertOrder(t, app.DB, `INSERT INTO orders (qty, price) VALUES (3, 7)`)
	mustExecArgs(t, app.DB, `UPDATE orders SET qty = 5 WHERE id = ?`, id)
	mustExecArgs(t, app.DB, `UPDATE orders SET price = 2 WHERE id = ?`, id)
	assertSealed(t, app.DB, "orders", "total", id, "10")
	rows, err := app.DB.Query(`SELECT qty, CAST(total AS TEXT) FROM orders_history WHERE id = ? ORDER BY _version`, id)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	type version struct {
		qty   int64
		total string
	}
	var got []version
	for rows.Next() {
		var v version
		if err := rows.Scan(&v.qty, &v.total); err != nil {
			t.Fatal(err)
		}
		plain, ok := fieldCiphertextOpen(cryptoKeyForQuerier(app.DB), "orders", "total", v.total)
		if !ok {
			t.Fatalf("history holds total unsealed: %q", v.total)
		}
		got = append(got, version{v.qty, plain})
	}
	if want := []version{{3, "21"}, {5, "35"}}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("history = %v, want %v", got, want)
	}
}

// Key rotation re-seals a computed encrypted column under the new key. Its
// trigger runs on the rotation's own writes while the old key is still the
// connection's, so it must not run then: it would find the new ciphertext
// unreadable and seal the value again under the old key.
func TestEncryptedComputedColumnSurvivesKeyRotation(t *testing.T) {
	app := loadEncTargetApp(t, encTargetEncrypted)
	id := insertOrder(t, app.DB, `INSERT INTO orders (qty, price) VALUES (3, 7)`)
	mustExecArgs(t, app.DB, `INSERT INTO order_notes (order_id, amount) VALUES (?, 5)`, id)
	oldKey := cryptoKeyForQuerier(app.DB)
	if _, err := RotateEncryptionKey(app, strings.Repeat("e", 64), false); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if string(cryptoKeyForQuerier(app.DB)) == string(oldKey) {
		t.Fatal("the key did not change")
	}
	assertSealed(t, app.DB, "orders", "total", id, "21")
	assertSealed(t, app.DB, "orders", "note_total", id, "5")
	mustExecArgs(t, app.DB, `UPDATE orders SET qty = 4 WHERE id = ?`, id)
	assertSealed(t, app.DB, "orders", "total", id, "28")
	mustExecArgs(t, app.DB, `INSERT INTO order_notes (order_id, amount) VALUES (?, 1)`, id)
	assertSealed(t, app.DB, "orders", "note_total", id, "6")
}
