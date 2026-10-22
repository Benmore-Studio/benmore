//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func inventoryTypedUpdateFixture(t *testing.T) (*App, *http.ServeMux, string, string) {
	t.Helper()
	app := newGateApp(t, `CREATE TABLE items (
id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, name TEXT NOT NULL,
quantity INTEGER NOT NULL, unit_price REAL NOT NULL, active BOOLEAN NOT NULL,
received_at DATETIME NOT NULL, note TEXT)`)
	EnsureJobsTable(app.DB)
	EnsureWebhooksTable(app.DB)
	owner, ownerSID := gateUser(t, app, "owner@inventory.invalid")
	outsider, outsiderSID := gateUser(t, app, "outsider@inventory.invalid")
	for id, uid := range map[int]int64{1: owner, 2: owner, 3: outsider} {
		mustExecArgs(t, app.DB, `INSERT INTO items VALUES (?,?,'stock',5,2.5,1,'2026-10-14','original')`, id, uid)
	}
	mux := http.NewServeMux()
	RegisterCRUD(mux, app)
	return app, mux, ownerSID, outsiderSID
}

func inventoryTypedPatch(mux *http.ServeMux, path, body, sid string, cookie bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPatch, "https://app.example.com"+path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if cookie {
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
	} else {
		r.Header.Set("Authorization", "Bearer "+sid)
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

func TestInventoryTypedUpdateJSONValues(t *testing.T) {
	for _, batch := range []bool{false, true} {
		t.Run(fmt.Sprintf("batch=%v", batch), func(t *testing.T) {
			app, mux, sid, _ := inventoryTypedUpdateFixture(t)
			path := "/api/items/1"
			body := `{"quantity":0,"unit_price":1.25,"active":false,"note":null,"received_at":"2026-02-28"}`
			if batch {
				path, body = "/api/items/batch", `{"ids":[1,2,3],"fields":`+body+`}`
			}
			w := inventoryTypedPatch(mux, path, body, sid, false)
			if w.Code != http.StatusOK {
				t.Fatalf("typed update: %d %s", w.Code, w.Body.String())
			}
			var quantity, active int
			var price float64
			var note sql.NullString
			var quantityType, activeType string
			if err := app.DB.QueryRow(`SELECT quantity, unit_price, CAST(active AS INTEGER), note, typeof(quantity), typeof(active) FROM items WHERE id=1`).Scan(&quantity, &price, &active, &note, &quantityType, &activeType); err != nil {
				t.Fatal(err)
			}
			if quantity != 0 || price != 1.25 || active != 0 || note.Valid || quantityType != "integer" || activeType != "integer" {
				t.Errorf("stored values quantity=%d (%s), price=%v, active=%d (%s), note=%+v; want 0,1.25,0,SQL NULL", quantity, quantityType, price, active, activeType, note)
			}
			if batch {
				var receipt map[string]any
				if err := json.Unmarshal(w.Body.Bytes(), &receipt); err != nil || receipt["updated"] != float64(2) {
					t.Fatalf("batch count = %s (%v)", w.Body.String(), err)
				}
				if got := gateScalar(t, app, `SELECT count(*) FROM items WHERE id IN (1,2) AND note IS NULL AND active=0 AND quantity=0`); got != "2" {
					t.Errorf("both owned rows must be updated; got %s", got)
				}
			}
			if got := gateScalar(t, app, `SELECT note FROM items WHERE id=3`); got != "original" {
				t.Errorf("changed an outsider row: %s", got)
			}
			if got := gateScalar(t, app, `SELECT COUNT(*) FROM _benmore_audit_log WHERE table_name='items' AND new_values LIKE '%"note":null%'`); got != map[bool]string{false: "1", true: "2"}[batch] {
				t.Errorf("audit lost null value: %s matching rows", got)
			}
			// An absent field leaves the stored value untouched; an explicit empty
			// string is distinct from JSON null, on both update surfaces.
			for _, update := range []string{`{"name":"renamed"}`, `{"note":""}`} {
				body = update
				if batch {
					body = `{"ids":[1],"fields":` + update + `}`
				}
				w = inventoryTypedPatch(mux, path, body, sid, false)
				if w.Code != 200 {
					t.Fatalf("follow-up: %d %s", w.Code, w.Body.String())
				}
				want := "<nil>"
				if strings.Contains(update, "note") {
					want = ""
				}
				if got := gateScalar(t, app, `SELECT note FROM items WHERE id=1`); got != want {
					t.Errorf("%s: note=%q want %q", update, got, want)
				}
			}
		})
	}
}

func TestInventoryTypedUpdateKeepsGates(t *testing.T) {
	app, mux, owner, outsider := inventoryTypedUpdateFixture(t)
	app.Validators = &ValidatorConfig{Rules: map[string][]ValidatorRule{"items": {{Rule: "quantity >= 0", Error: "nonnegative quantity required"}}}}
	for _, batch := range []bool{false, true} {
		path := "/api/items/1"
		wrap := func(fields string) string { return fields }
		if batch {
			path = "/api/items/batch"
			wrap = func(fields string) string { return `{"ids":[1,2],"fields":` + fields + `}` }
		}
		w := inventoryTypedPatch(mux, path, wrap(`{"quantity":-1,"active":false}`), owner, false)
		if w.Code != http.StatusUnprocessableEntity {
			t.Errorf("batch=%v validator: %d %s", batch, w.Code, w.Body.String())
		}
		w = inventoryTypedPatch(mux, path, wrap(`{"note":null}`), owner, true)
		if w.Code != http.StatusForbidden {
			t.Errorf("batch=%v missing CSRF: %d %s", batch, w.Code, w.Body.String())
		}
		w = inventoryTypedPatch(mux, path, wrap(`{"note":null}`), outsider, false)
		if (!batch && w.Code != 404) || (batch && (w.Code != 200 || !strings.Contains(w.Body.String(), `"updated":0`))) {
			t.Errorf("batch=%v foreign rows: %d %s", batch, w.Code, w.Body.String())
		}
	}
	if got := gateScalar(t, app, `SELECT count(*) FROM items WHERE quantity=5 AND active=1 AND note='original'`); got != "3" {
		t.Fatalf("denied requests changed rows: %s unchanged", got)
	}
	if got := gateScalar(t, app, `SELECT count(*) FROM _benmore_audit_log WHERE table_name='items'`); got != "0" {
		t.Fatalf("denied requests left audit writes: %s", got)
	}
}
