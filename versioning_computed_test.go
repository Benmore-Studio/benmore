//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

const computedVersionSchema = `model Product {
  id Int @id @default(autoincrement())
  userId Int @map("user_id")
  name String
  onHand Int @default(0) @map("on_hand")
  unitCostCents Int @default(0) @map("unit_cost_cents")
  stockValueCents Int @default(0) @map("stock_value_cents")
  createdAt DateTime @default(now()) @map("created_at")
  updatedAt DateTime @default(now()) @updatedAt @map("updated_at")
  @@map("products")
}`

// computedVersionFixture is a versioned Prisma table with an @updatedAt
// column and (optionally) a same-row computed field, installed in the
// loader's order: schema with its updatedAt trigger, then computed, then
// history.
func computedVersionFixture(t *testing.T, computed bool) (*App, *http.ServeMux, string) {
	t.Helper()
	app, _ := newCrudScopeTestApp(t)
	models, err := ParsePrismaSchema(computedVersionSchema)
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, app.DB, EmitSQL(models))
	refreshTableColumns(t, app, "products")
	app.Access.rules["products"] = map[AccessOp]string{"all": "self"}
	if computed {
		app.Computed = &ComputedFieldConfig{Fields: map[string]map[string]*ComputedField{
			"products": {"stock_value_cents": {Table: "products", Column: "stock_value_cents", Expr: "on_hand * unit_cost_cents"}},
		}}
	}
	if err := installComputedTriggersChecked(app.DB, app.Computed); err != nil {
		t.Fatal(err)
	}
	versioned := &VersionedConfig{Tables: []string{"products"}}
	if err := InstallVersioningTriggers(app.DB, withComputedVersionMaintenance(versioned, app.Computed)); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	RegisterCRUD(mux, app)
	RegisterVersioningAPI(mux, app, versioned)
	sid := createCrudScopeSession(t, app, "stock@example.com", "user", "", "")
	return app, mux, sid
}

type productVersion struct {
	version             int64
	onHand, cost, value int64
	changeType, updated string
	validFrom, validTo  string
}

func productVersions(t *testing.T, app *App, id string) []productVersion {
	t.Helper()
	rows, err := app.DB.Query(`SELECT _version, on_hand, unit_cost_cents, stock_value_cents, _change_type, CAST(updated_at AS TEXT), CAST(_valid_from AS TEXT), CAST(_valid_to AS TEXT) FROM products_history WHERE id=? ORDER BY _version`, id)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []productVersion
	for rows.Next() {
		var v productVersion
		if err := rows.Scan(&v.version, &v.onHand, &v.cost, &v.value, &v.changeType, &v.updated, &v.validFrom, &v.validTo); err != nil {
			t.Fatal(err)
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// backdateProduct moves a row's timestamps into the past without recording
// history, so the next write meets the stale updated_at a real row has (the
// Prisma touch only fires once the row is a second old).
func backdateProduct(t *testing.T, app *App, id string) {
	t.Helper()
	tx, err := app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	ddls, err := suspendVersioningTriggers(tx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`UPDATE products SET created_at='2026-01-01 08:00:00', updated_at='2026-01-01 09:00:00' WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	if err := restoreVersioningTriggers(tx, ddls); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var updated string
	if err := app.DB.QueryRow(`SELECT CAST(updated_at AS TEXT) FROM products WHERE id=?`, id).Scan(&updated); err != nil || updated != "2026-01-01 09:00:00" {
		t.Fatalf("backdate did not hold: %q %v", updated, err)
	}
}

func assertProductState(t *testing.T, app *App, id string, onHand, value int64) {
	t.Helper()
	var gotOnHand, gotValue int64
	if err := app.DB.QueryRow(`SELECT on_hand, stock_value_cents FROM products WHERE id=?`, id).Scan(&gotOnHand, &gotValue); err != nil {
		t.Fatal(err)
	}
	if gotOnHand != onHand || gotValue != value {
		t.Fatalf("current row: on_hand=%d stock_value_cents=%d, want %d/%d", gotOnHand, gotValue, onHand, value)
	}
}

// Each history row is the state one user write replaced. A computed field's
// recalculation and the Prisma @updatedAt touch it set off are maintenance
// writes, so they add no version, and no version holds a stale computed
// value (a state that never committed).
func TestVersioningComputedFieldRecordsOneVersionPerWrite(t *testing.T) {
	app, mux, sid := computedVersionFixture(t, true)
	w := crudScopeRequest(t, mux, http.MethodPost, "/api/products", sid, map[string]any{"name": "bolt", "on_hand": 10, "unit_cost_cents": 25})
	var row map[string]any
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &row) != nil {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	id := fmt.Sprint(row["id"])
	assertProductState(t, app, id, 10, 250)
	if got := productVersions(t, app, id); len(got) != 0 {
		t.Fatalf("an insert recorded history: %+v", got)
	}
	mustExec(t, app.DB, `INSERT INTO products (user_id, name, on_hand, unit_cost_cents) VALUES (1, 'raw', 3, 7)`)
	if got := productVersions(t, app, "2"); len(got) != 0 {
		t.Fatalf("a raw insert recorded history: %+v", got)
	}

	steps := []struct {
		name          string
		write         func()
		onHand, value int64 // current row afterwards
		prior         [2]int64
	}{
		{"canonical PATCH", func() {
			if w := canonicalPatch(app, sid, "products", id, "application/json", `{"on_hand":12}`); w.Code != 200 {
				t.Fatalf("patch: %d %s", w.Code, w.Body.String())
			}
		}, 12, 300, [2]int64{10, 250}},
		{"raw SQL input change", func() { mustExec(t, app.DB, `UPDATE products SET on_hand=276 WHERE id=`+id) }, 276, 6900, [2]int64{12, 300}},
		{"raw SQL other column", func() { mustExec(t, app.DB, `UPDATE products SET name='nut' WHERE id=`+id) }, 276, 6900, [2]int64{276, 6900}},
		{"canonical PATCH other column", func() {
			if w := canonicalPatch(app, sid, "products", id, "application/json", `{"name":"washer"}`); w.Code != 200 {
				t.Fatalf("patch: %d %s", w.Code, w.Body.String())
			}
		}, 276, 6900, [2]int64{276, 6900}},
	}
	for i, step := range steps {
		backdateProduct(t, app, id)
		step.write()
		assertProductState(t, app, id, step.onHand, step.value)
		got := productVersions(t, app, id)
		if len(got) != i+1 {
			t.Fatalf("%s: %d versions after %d writes: %+v", step.name, len(got), i+1, got)
		}
		last := got[len(got)-1]
		if last.changeType != "update" || last.onHand != step.prior[0] || last.value != step.prior[1] {
			t.Fatalf("%s: version holds %+v, want the replaced state %v", step.name, last, step.prior)
		}
	}
	for _, v := range productVersions(t, app, id) {
		if v.value != v.onHand*v.cost {
			t.Fatalf("version %d holds a state that never committed: %+v", v.version, v)
		}
	}
	// The API lists the same versions.
	w = crudScopeRequest(t, mux, http.MethodGet, "/api/products/"+id+"/versions", sid, nil)
	var listed struct{ Versions []map[string]any }
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &listed) != nil || len(listed.Versions) != len(steps) {
		t.Fatalf("versions API: %d %s", w.Code, w.Body.String())
	}
	// A delete still records the final state.
	mustExec(t, app.DB, `DELETE FROM products WHERE id=`+id)
	got := productVersions(t, app, id)
	if last := got[len(got)-1]; len(got) != len(steps)+1 || last.changeType != "delete" || last.value != 6900 {
		t.Fatalf("delete version: %+v", got)
	}
}

// The @updatedAt touch after a raw UPDATE was a second version even without
// computed fields; an explicit timestamp-only write past the recorded
// history is still a version, so its earlier interval keeps its state.
func TestVersioningPrismaTouchIsNotASecondVersion(t *testing.T) {
	app, mux, sid := computedVersionFixture(t, false)
	w := crudScopeRequest(t, mux, http.MethodPost, "/api/products", sid, map[string]any{"name": "bolt", "on_hand": 10, "unit_cost_cents": 25})
	var row map[string]any
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &row) != nil {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	id := fmt.Sprint(row["id"])
	backdateProduct(t, app, id)
	mustExec(t, app.DB, `UPDATE products SET on_hand=11 WHERE id=`+id)
	got := productVersions(t, app, id)
	if len(got) != 1 || got[0].onHand != 10 || got[0].updated != "2026-01-01 09:00:00" {
		t.Fatalf("raw update: %+v", got)
	}
	var updated string
	if err := app.DB.QueryRow(`SELECT CAST(updated_at AS TEXT) FROM products WHERE id=?`, id).Scan(&updated); err != nil || strings.HasPrefix(updated, "2026-01-01") {
		t.Fatalf("raw update did not advance updated_at: %q %v", updated, err)
	}
	// The current state is served from the end of the recorded version on.
	w = crudScopeRequest(t, mux, http.MethodGet, "/api/products/"+id+"?as_of="+strings.ReplaceAll(got[0].validTo, " ", "T")+"Z", sid, nil)
	var current map[string]any
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &current) != nil || fmt.Sprint(current["on_hand"]) != "11" {
		t.Fatalf("as_of at the version boundary: %d %s", w.Code, w.Body.String())
	}

	// An explicit touch past the recorded history keeps the replaced interval.
	mustExec(t, app.DB, `UPDATE products SET updated_at='2099-01-01 00:00:00' WHERE id=`+id)
	if got := productVersions(t, app, id); len(got) != 2 || got[1].onHand != 11 {
		t.Fatalf("explicit touch: %+v", got)
	}
}

// Startup and reload install both trigger sets from one configuration, and
// replace the triggers an older runtime stored.
func TestVersioningComputedTriggersReinstallOnLoad(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, dir, "app.yaml", "auth:\n  signup: false\nversioned: [products]\n")
	writeTestFile(t, dir, "computed.yaml", "products:\n  stock_value_cents:\n    expr: on_hand * unit_cost_cents\n")
	writeTestFile(t, dir, "schema.prisma", computedVersionSchema+"\n")
	app, err := loadAppWithOptions(dir, appLoadOptions{checkOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if app != nil {
			app.Shutdown()
		}
	}()
	// The previous runtime's unconditional recalculation and unconditional
	// history trigger.
	mustExec(t, app.DB, `DROP TRIGGER _benmore_cf_products_stock_value_cents_update`)
	mustExec(t, app.DB, `CREATE TRIGGER _benmore_cf_products_stock_value_cents_update AFTER UPDATE ON products FOR EACH ROW BEGIN UPDATE products SET stock_value_cents = (on_hand * unit_cost_cents) WHERE rowid = NEW.rowid; END`)
	tx, err := app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := suspendVersioningTriggers(tx); err != nil {
		t.Fatal(err)
	}
	if err := reconcileVersionedTable(tx, "products", nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	for transition := 0; transition < 2; transition++ {
		if transition == 0 {
			err = reloadAppConfig(app)
		} else {
			app.Shutdown()
			app, err = loadAppWithOptions(dir, appLoadOptions{startup: true})
		}
		if err != nil {
			t.Fatal(err)
		}
		var computedSQL, historySQL string
		if err := app.DB.QueryRow(`SELECT sql FROM sqlite_schema WHERE name='_benmore_cf_products_stock_value_cents_update'`).Scan(&computedSQL); err != nil {
			t.Fatal(err)
		}
		if err := app.DB.QueryRow(`SELECT sql FROM sqlite_schema WHERE name='_benmore_ver_products_update'`).Scan(&historySQL); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(computedSQL, `stock_value_cents IS NOT (on_hand * unit_cost_cents)`) || !strings.Contains(historySQL, `OLD."stock_value_cents" IS NOT NEW."stock_value_cents"`) {
			t.Fatalf("transition %d kept old triggers:\n%s\n%s", transition, computedSQL, historySQL)
		}
		id := fmt.Sprint(10 + transition)
		mustExec(t, app.DB, `INSERT INTO products (id, user_id, name, on_hand, unit_cost_cents) VALUES (`+id+`, 1, 'p', 2, 5)`)
		mustExec(t, app.DB, `UPDATE products SET on_hand=4 WHERE id=`+id)
		got := productVersions(t, app, id)
		assertProductState(t, app, id, 4, 20)
		if len(got) != 1 || got[0].onHand != 2 || got[0].value != 10 {
			t.Fatalf("transition %d: insert + update recorded %+v", transition, got)
		}
	}
}
