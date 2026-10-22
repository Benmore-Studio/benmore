//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const inventoryPrismaSchema = `model Item {
 id Int @id @default(autoincrement())
 userId Int
 name String
 quantity Int @default(0)
 unitPrice Float @default(0) @map("unit_price")
 active Boolean @default(true)
 receivedAt DateTime @map("received_at")
 note String? @default("fallback")
 optionalCount Int?
 expiresAt DateTime?
}`

func inventorySchemaFixture(t *testing.T, prisma bool) (*App, *http.ServeMux, string) {
	t.Helper()
	app := newGateApp(t)
	EnsureJobsTable(app.DB)
	EnsureWebhooksTable(app.DB)
	dir := t.TempDir()
	name, source := "schema.prisma", inventoryPrismaSchema
	if !prisma {
		models, err := ParsePrismaSchema(source)
		if err != nil {
			t.Fatal(err)
		}
		name, source = "schema.sql", EmitSQL(models)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	tables, deferred, err := LoadSchema(app.DB, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = ApplyDeferredDDL(app.DB, deferred); err != nil {
		t.Fatal(err)
	}
	app.Tables = tables
	_, sid := gateUser(t, app, "schema@inventory.invalid")
	mux := http.NewServeMux()
	RegisterCRUD(mux, app)
	return app, mux, sid
}

func inventorySchemaRequest(mux *http.ServeMux, sid, mode string, fields map[string]any) *httptest.ResponseRecorder {
	payload, _ := json.Marshal(fields)
	method, path, content, body := "POST", "/api/items", "application/json", string(payload)
	switch mode {
	case "batch":
		path += "/batch"
		body = "[" + body + "]"
	case "ingest":
		path += "/ingest"
		content = "application/x-ndjson"
		body += "\n"
	case "transaction":
		path = "/api/_transaction"
		body = `{"operations":[{"table":"items","action":"insert","data":` + body + `}]}`
	case "patch":
		method = "PATCH"
		path += "/1"
	case "batch_patch":
		method = "PATCH"
		path += "/batch"
		body = `{"ids":[1],"fields":` + body + `}`
	case "transaction_patch":
		path = "/api/_transaction"
		body = `{"operations":[{"table":"items","action":"update","id":1,"data":` + body + `}]}`
	}
	r := httptest.NewRequest(method, "https://app.example.com"+path, strings.NewReader(body))
	r.Header.Set("Content-Type", content)
	r.Header.Set("Authorization", "Bearer "+sid)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}
func inventoryValidFields() map[string]any {
	return map[string]any{"name": "stock", "quantity": 3, "unit_price": 2.5, "active": false, "received_at": "2026-02-28T12:15:00Z", "note": nil}
}

func TestInventorySchemaRejectsInvalidScalars(t *testing.T) {
	cases := []struct {
		field string
		value any
	}{
		{"quantity", 1.5}, {"quantity", "several"}, {"quantity", true}, {"quantity", []any{1}},
		{"unit_price", "cheap"}, {"unit_price", "NaN"}, {"unit_price", "Inf"}, {"active", "maybe"}, {"active", 2},
		{"received_at", "2026-02-30"}, {"received_at", 17}, {"name", map[string]any{"a": 1}}, {"name", false},
		{"name", nil}, {"quantity", nil}, {"received_at", nil},
	}
	for _, mode := range []string{"single", "batch", "ingest", "transaction", "patch", "batch_patch", "transaction_patch"} {
		for n, tc := range cases {
			t.Run(fmt.Sprintf("%s/%s/%d", mode, tc.field, n), func(t *testing.T) {
				app, mux, sid := inventorySchemaFixture(t, true)
				initial := 0
				if strings.Contains(mode, "patch") {
					w := inventorySchemaRequest(mux, sid, "single", inventoryValidFields())
					if w.Code != 200 {
						t.Fatalf("seed: %d %s", w.Code, w.Body.String())
					}
					initial = 1
				}
				fields := inventoryValidFields()
				fields[tc.field] = tc.value
				w := inventorySchemaRequest(mux, sid, mode, fields)
				if mode == "ingest" {
					var receipt map[string]any
					json.Unmarshal(w.Body.Bytes(), &receipt)
					if w.Code != 400 || receipt["ingested"] != float64(0) || receipt["errors"] != float64(1) {
						t.Errorf("invalid row receipt: %d %s", w.Code, w.Body.String())
					}
				} else if w.Code != 422 {
					t.Errorf("invalid %s=%#v: %d %s", tc.field, tc.value, w.Code, w.Body.String())
				}
				if got := gateScalar(t, app, "SELECT count(*) FROM items"); got != fmt.Sprint(initial) {
					t.Errorf("invalid write durable count %s want %d", got, initial)
				}
				if initial == 1 {
					if got := gateScalar(t, app, `SELECT count(*) FROM items WHERE name='stock' AND quantity=3 AND unit_price=2.5 AND active=0 AND note IS NULL`); got != "1" {
						t.Errorf("rejected patch changed stored row: %s", got)
					}
				}
			})
		}
	}
}

func TestInventorySchemaValidValuesAndNull(t *testing.T) {
	for _, mode := range []string{"single", "batch", "ingest", "transaction", "patch", "batch_patch", "transaction_patch"} {
		t.Run(mode, func(t *testing.T) {
			app, mux, sid := inventorySchemaFixture(t, true)
			if strings.Contains(mode, "patch") {
				w := inventorySchemaRequest(mux, sid, "single", inventoryValidFields())
				if w.Code != 200 {
					t.Fatal(w.Body.String())
				}
			}
			fields := inventoryValidFields()
			fields["quantity"] = "0"
			fields["unit_price"] = "1.25"
			fields["active"] = "false"
			w := inventorySchemaRequest(mux, sid, mode, fields)
			if w.Code != 200 {
				t.Fatalf("valid values: %d %s", w.Code, w.Body.String())
			}
			if got := gateScalar(t, app, `SELECT count(*) FROM items WHERE quantity=0 AND typeof(quantity)='integer' AND unit_price=1.25 AND typeof(unit_price)='real' AND active=0 AND note IS NULL`); got != "1" {
				t.Errorf("typed values or explicit NULL lost: %s matching rows", got)
			}
		})
	}
}

func TestInventorySchemaBulkRollbackAndIngestCount(t *testing.T) {
	for _, mode := range []string{"batch", "transaction", "ingest"} {
		t.Run(mode, func(t *testing.T) {
			app, mux, sid := inventorySchemaFixture(t, true)
			good, _ := json.Marshal(inventoryValidFields())
			badFields := inventoryValidFields()
			badFields["quantity"] = "several"
			bad, _ := json.Marshal(badFields)
			path, content, body := "/api/items/batch", "application/json", "["+string(good)+","+string(bad)+"]"
			if mode == "transaction" {
				path = "/api/_transaction"
				body = `{"operations":[{"table":"items","action":"insert","data":` + string(good) + `},{"table":"items","action":"insert","data":` + string(bad) + `}]}`
			}
			if mode == "ingest" {
				path = "/api/items/ingest"
				content = "application/x-ndjson"
				body = string(good) + "\n" + string(bad) + "\n" + string(good) + "\n"
			}
			r := httptest.NewRequest("POST", "https://app.example.com"+path, strings.NewReader(body))
			r.Header.Set("Content-Type", content)
			r.Header.Set("Authorization", "Bearer "+sid)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			want := "0"
			if mode == "ingest" {
				want = "2"
				var receipt map[string]any
				json.Unmarshal(w.Body.Bytes(), &receipt)
				if w.Code != 200 || receipt["ingested"] != float64(2) || receipt["errors"] != float64(1) {
					t.Errorf("receipt: %d %s", w.Code, w.Body.String())
				}
			} else if w.Code != 422 {
				t.Errorf("atomic refusal: %d %s", w.Code, w.Body.String())
			}
			if got := gateScalar(t, app, "SELECT count(*) FROM items"); got != want {
				t.Errorf("durable count %s want %s", got, want)
			}
			if mode != "ingest" {
				if got := gateScalar(t, app, "SELECT count(*) FROM _benmore_audit_log WHERE table_name='items'"); got != "0" {
					t.Errorf("rolled-back audit count %s", got)
				}
			}
		})
	}
}

func TestInventorySchemaSQLCompatibility(t *testing.T) {
	for _, mode := range []string{"single", "batch", "ingest", "transaction"} {
		t.Run(mode, func(t *testing.T) {
			app, mux, sid := inventorySchemaFixture(t, false)
			fields := inventoryValidFields()
			fields["quantity"] = "legacy-text"
			fields["active"] = "legacy-flag"
			w := inventorySchemaRequest(mux, sid, mode, fields)
			if w.Code != 200 {
				t.Fatalf("raw SQL schema changed: %d %s", w.Code, w.Body.String())
			}
			if got := gateScalar(t, app, `SELECT count(*) FROM items WHERE quantity='legacy-text' AND active='legacy-flag'`); got != "1" {
				t.Fatalf("raw SQL compatibility durable count=%s", got)
			}
		})
	}
}

func TestInventorySchemaExactIntegersAndDefaults(t *testing.T) {
	for _, mode := range []string{"single", "batch", "ingest", "transaction", "patch", "batch_patch", "transaction_patch"} {
		t.Run(mode, func(t *testing.T) {
			app, mux, sid := inventorySchemaFixture(t, true)
			if strings.Contains(mode, "patch") {
				w := inventorySchemaRequest(mux, sid, "single", inventoryValidFields())
				if w.Code != 200 {
					t.Fatal(w.Body.String())
				}
			}
			fields := inventoryValidFields()
			fields["quantity"] = json.Number("9223372036854775807")
			w := inventorySchemaRequest(mux, sid, mode, fields)
			if w.Code != 200 {
				t.Fatalf("int64: %d %s", w.Code, w.Body.String())
			}
			if got := gateScalar(t, app, `SELECT quantity FROM items WHERE id=1`); got != "9223372036854775807" {
				t.Errorf("int64 rounded: %s", got)
			}
		})
	}
	for _, mode := range []string{"single", "batch", "ingest", "transaction"} {
		t.Run(mode+"/defaults", func(t *testing.T) {
			app, mux, sid := inventorySchemaFixture(t, true)
			fields := map[string]any{"name": "defaults", "received_at": "2026-01-01"}
			w := inventorySchemaRequest(mux, sid, mode, fields)
			if w.Code != 200 {
				t.Fatalf("defaults: %d %s", w.Code, w.Body.String())
			}
			if got := gateScalar(t, app, `SELECT count(*) FROM items WHERE quantity=0 AND active=1 AND note='fallback'`); got != "1" {
				t.Errorf("defaults lost: %s", got)
			}
		})
	}
}

func TestInventorySchemaFormsAndPublishedMetadata(t *testing.T) {
	app, mux, sid := inventorySchemaFixture(t, true)
	// A pending source file cannot change the already published type contract.
	if err := os.WriteFile(filepath.Join(app.Dir, "schema.prisma"), []byte(strings.Replace(inventoryPrismaSchema, "quantity Int", "quantity String", 1)), 0600); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "https://app.example.com/api/items", strings.NewReader("name=false&quantity=2&unit_price=3.50&active=false&received_at=2026-02-28T12%3A30&note="))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Authorization", "Bearer "+sid)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("HTML form: %d %s", w.Code, w.Body.String())
	}
	if got := gateScalar(t, app, `SELECT count(*) FROM items WHERE name='false' AND quantity=2 AND unit_price=3.5 AND active=0 AND note='fallback'`); got != "1" {
		t.Errorf("HTML form values changed: %s", got)
	}
	fields := inventoryValidFields()
	fields["quantity"] = "several"
	w = inventorySchemaRequest(mux, sid, "patch", fields)
	if w.Code != 422 {
		t.Errorf("pending source overrode published metadata: %d %s", w.Code, w.Body.String())
	}
	if got := gateScalar(t, app, "SELECT quantity FROM items WHERE id=1"); got != "2" {
		t.Errorf("invalid pending-schema write changed row: %s", got)
	}
}

func TestInventorySchemaOptionalFormClearsAndJSONEmpty(t *testing.T) {
	app, mux, sid := inventorySchemaFixture(t, true)
	fields := inventoryValidFields()
	fields["optional_count"] = 4
	fields["expires_at"] = "2026-02-28"
	if w := inventorySchemaRequest(mux, sid, "single", fields); w.Code != 200 {
		t.Fatalf("seed: %d %s", w.Code, w.Body.String())
	}
	r := httptest.NewRequest("PATCH", "https://app.example.com/api/items/1", strings.NewReader("optional_count=&expires_at=&note="))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Authorization", "Bearer "+sid)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("clear form: %d %s", w.Code, w.Body.String())
	}
	if got := gateScalar(t, app, `SELECT count(*) FROM items WHERE optional_count IS NULL AND expires_at IS NULL AND note=''`); got != "1" {
		t.Errorf("empty optional controls not cleared: %s", got)
	}
	for _, field := range []string{"optional_count", "expires_at"} {
		w = inventorySchemaRequest(mux, sid, "patch", map[string]any{field: ""})
		if w.Code != 422 {
			t.Errorf("JSON empty %s: %d %s", field, w.Code, w.Body.String())
		}
	}
}

func TestInventorySchemaIngestRejectsTrailingJSON(t *testing.T) {
	app, mux, sid := inventorySchemaFixture(t, true)
	good, _ := json.Marshal(inventoryValidFields())
	body := string(good) + " {}\n" + string(good) + " garbage\n" + string(good) + "\n"
	r := httptest.NewRequest("POST", "https://app.example.com/api/items/ingest", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-ndjson")
	r.Header.Set("Authorization", "Bearer "+sid)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	var receipt map[string]any
	json.Unmarshal(w.Body.Bytes(), &receipt)
	if w.Code != 200 || receipt["ingested"] != float64(1) || receipt["errors"] != float64(2) {
		t.Errorf("receipt: %d %s", w.Code, w.Body.String())
	}
	if got := gateScalar(t, app, "SELECT count(*) FROM items"); got != "1" {
		t.Errorf("trailing input persisted: %s", got)
	}
}

func TestInventorySchemaNumericIDsRemainExactAndCompatible(t *testing.T) {
	for _, mode := range []string{"batch", "transaction"} {
		for _, id := range []string{"1.0", "1e0", "9007199254740993"} {
			t.Run(mode+"/"+id, func(t *testing.T) {
				app, mux, sid := inventorySchemaFixture(t, true)
				if w := inventorySchemaRequest(mux, sid, "single", inventoryValidFields()); w.Code != 200 {
					t.Fatal(w.Body.String())
				}
				storedID := "1"
				if id == "9007199254740993" {
					storedID = id
					mustExec(t, app.DB, "UPDATE items SET id="+id+" WHERE id=1")
				}
				method, path, body := "PATCH", "/api/items/batch", `{"ids":[`+id+`],"fields":{"name":"changed"}}`
				if mode == "transaction" {
					method = "POST"
					path = "/api/_transaction"
					body = `{"operations":[{"table":"items","action":"update","id":` + id + `,"data":{"name":"changed"}}]}`
				}
				r := httptest.NewRequest(method, "https://app.example.com"+path, strings.NewReader(body))
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Authorization", "Bearer "+sid)
				w := httptest.NewRecorder()
				mux.ServeHTTP(w, r)
				if w.Code != 200 {
					t.Fatalf("numeric ID update: %d %s", w.Code, w.Body.String())
				}
				if mode == "transaction" {
					var receipt struct {
						Results []struct {
							ID json.Number `json:"id"`
						} `json:"results"`
					}
					if err := json.Unmarshal(w.Body.Bytes(), &receipt); err != nil || len(receipt.Results) != 1 || string(receipt.Results[0].ID) != storedID {
						t.Errorf("numeric result ID changed: %s (%v)", w.Body.String(), err)
					}
					var raw map[string]any
					json.Unmarshal(w.Body.Bytes(), &raw)
					if rows, ok := raw["results"].([]any); ok && len(rows) == 1 {
						if _, number := rows[0].(map[string]any)["id"].(float64); !number {
							t.Errorf("numeric ID serialized as non-number: %s", w.Body.String())
						}
					}
				}
				if got := gateScalar(t, app, "SELECT name FROM items WHERE id=?", storedID); got != "changed" {
					t.Errorf("numeric ID did not update exact row: %s", got)
				}
			})
		}
	}
}

func TestInventorySchemaRequiredAndProtectedFields(t *testing.T) {
	for _, mode := range []string{"single", "batch", "transaction", "ingest"} {
		t.Run(mode, func(t *testing.T) {
			app, mux, sid := inventorySchemaFixture(t, true)
			fields := inventoryValidFields()
			delete(fields, "name")
			w := inventorySchemaRequest(mux, sid, mode, fields)
			want := 422
			if mode == "ingest" {
				want = 400
			}
			if w.Code != want {
				t.Errorf("missing required field: %d %s", w.Code, w.Body.String())
			}
			if got := gateScalar(t, app, "SELECT count(*) FROM items"); got != "0" {
				t.Errorf("missing required write persisted: %s", got)
			}
			fields = inventoryValidFields()
			fields["user_id"] = "ignored invalid owner"
			w = inventorySchemaRequest(mux, sid, mode, fields)
			if w.Code != 200 {
				t.Fatalf("protected input must be ignored: %d %s", w.Code, w.Body.String())
			}
			if got := gateScalar(t, app, "SELECT user_id FROM items"); got != "1" {
				t.Errorf("owner injection lost: %s", got)
			}
		})
	}
}
