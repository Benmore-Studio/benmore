//go:build !cli

package main

import (
	"fmt"
	"net/http"
	"testing"
	"time"
)

// The planner leaves spent/quantity at its schema default. Cross-field rules
// must compare that value, rather than the missing field's name as text.
func TestCreateCrossFieldValidationUsesDefaults(t *testing.T) {
	for _, mode := range []string{"single", "batch", "transaction", "ingest"} {
		t.Run(mode, func(t *testing.T) {
			app, mux, sid := inventorySchemaFixture(t, true)
			app.Validators = &ValidatorConfig{Rules: map[string][]ValidatorRule{"items": {{Rule: "quantity <= unit_price", Error: "quantity exceeds price"}, {Rule: "note = 'fallback'", Error: "missing default note"}}}}
			fields := map[string]any{"name": "planner", "unit_price": 20, "received_at": "2026-10-16"}
			w := inventorySchemaRequest(mux, sid, mode, fields)
			if w.Code != 200 || gateScalar(t, app, "SELECT COUNT(*) FROM items") != "1" {
				t.Fatalf("omitted defaults: %d %s", w.Code, w.Body.String())
			}
			if got := gateScalar(t, app, "SELECT quantity || ':' || note FROM items"); got != "0:fallback" {
				t.Fatalf("persisted defaults %q", got)
			}
			for _, value := range []any{nil, 21} {
				fields["quantity"] = value
				w = inventorySchemaRequest(mux, sid, mode, fields)
				if (mode != "ingest" && w.Code != 422) || gateScalar(t, app, "SELECT COUNT(*) FROM items") != "1" {
					t.Fatalf("invalid %v changed data: %d %s", value, w.Code, w.Body.String())
				}
			}
			fields["quantity"] = 0
			w = inventorySchemaRequest(mux, sid, mode, fields)
			if w.Code != 200 || gateScalar(t, app, "SELECT COUNT(*) FROM items") != "2" {
				t.Fatalf("explicit zero: %d %s", w.Code, w.Body.String())
			}
			// Invalid defaults still fail instead of skipping a rule on an omitted field.
			app.Validators.Rules["items"] = []ValidatorRule{{Rule: "quantity >= 1", Error: "positive quantity required"}}
			delete(fields, "quantity")
			w = inventorySchemaRequest(mux, sid, mode, fields)
			if (mode != "ingest" && w.Code != 422) || gateScalar(t, app, "SELECT COUNT(*) FROM items") != "2" {
				t.Fatalf("invalid default accepted: %d %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestCreateDefaultsDoNotReplaceExplicitNullableValues(t *testing.T) {
	for _, mode := range []string{"single", "batch", "transaction", "ingest"} {
		for i, value := range []any{nil, ""} {
			t.Run(fmt.Sprintf("%s/%d", mode, i), func(t *testing.T) {
				app, mux, sid := inventorySchemaFixture(t, true)
				app.Validators = &ValidatorConfig{Rules: map[string][]ValidatorRule{"items": {{Rule: "quantity <= unit_price", Error: "too much"}}}}
				w := inventorySchemaRequest(mux, sid, mode, map[string]any{"name": "planner", "unit_price": 20, "received_at": "2026-10-16", "note": value})
				if w.Code != 200 || gateScalar(t, app, "SELECT COUNT(*) FROM items") != "1" {
					t.Fatalf("create %d %s", w.Code, w.Body.String())
				}
				want := ""
				if value == nil {
					want = "<nil>"
				}
				if got := gateScalar(t, app, "SELECT note FROM items"); got != want {
					t.Fatalf("explicit note %q want %q", got, want)
				}
			})
		}
	}
}

func TestCreateEvaluatesValidatedDefaultOnce(t *testing.T) {
	for _, mode := range []string{"single", "batch", "transaction", "ingest"} {
		t.Run(mode, func(t *testing.T) {
			app := newGateApp(t, `CREATE TABLE items(id INTEGER PRIMARY KEY, user_id INTEGER, name TEXT, quantity INTEGER DEFAULT (abs(random()) % 1000000000))`, `CREATE TABLE observed_defaults(value INTEGER, submitted TEXT)`)
			EnsureJobsTable(app.DB)
			EnsureWebhooksTable(app.DB)
			_, sid := gateUser(t, app, "default@example.test")
			app.Validators = &ValidatorConfig{Rules: map[string][]ValidatorRule{"items": {{Rule: "quantity >= 0"}}}}
			app.Hooks = &HookConfig{BeforeInsert: map[string][]Hook{"items": {{SQL: "INSERT INTO observed_defaults(value,submitted) VALUES ({{quantity}}, '{{_submitted}}')"}}}}
			mux := http.NewServeMux()
			RegisterCRUD(mux, app)
			w := inventorySchemaRequest(mux, sid, mode, map[string]any{"name": "once"})
			if w.Code != 200 || gateScalar(t, app, "SELECT COUNT(*) FROM items") != "1" {
				t.Fatalf("create: %d %s", w.Code, w.Body.String())
			}
			if got := gateScalar(t, app, "SELECT count(*) FROM items, observed_defaults WHERE items.quantity = observed_defaults.value AND observed_defaults.submitted=',name,'"); got != "1" {
				t.Fatalf("validated default changed or became submitted: %s", got)
			}
		})
	}
}

func TestGroupBootstrapCrossFieldDefaults(t *testing.T) {
	app, uid, cleanup := newBootstrapTestApp(t, "user_id")
	defer cleanup()
	mustExec(t, app.DB, "ALTER TABLE companies ADD COLUMN used INTEGER NOT NULL DEFAULT 0")
	mustExec(t, app.DB, "ALTER TABLE companies ADD COLUMN capacity INTEGER NOT NULL DEFAULT 10")
	app.Validators = &ValidatorConfig{Rules: map[string][]ValidatorRule{"companies": {{Rule: "used <= capacity", Error: "capacity exceeded"}}}}
	sid := CreateSession(app.DB, uid, "founder@example.com", "", time.Hour)
	w := bootstrapAs(app, sid, `{"name":"Invalid default workspace","capacity":-1}`)
	if w.Code != 422 || countRows(t, app, "companies") != 0 || countRows(t, app, "company_members") != 0 {
		t.Fatalf("invalid bootstrap defaults changed state: %d %s", w.Code, w.Body.String())
	}
	w = bootstrapAs(app, sid, `{"name":"Default workspace"}`)
	if w.Code != 200 {
		t.Fatalf("bootstrap: %d %s", w.Code, w.Body.String())
	}
	if gateScalar(t, app, "SELECT used || ':' || capacity FROM companies") != "0:10" {
		t.Fatal("wrong persisted defaults")
	}
	if countRows(t, app, "company_members") != 1 {
		t.Fatal("missing founding membership")
	}
}
