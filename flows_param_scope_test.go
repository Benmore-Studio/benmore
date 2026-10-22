//go:build !cli

package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A request key that is not a plain identifier must never alter the
// author's SQL text: only `:identifier` tokens found in the template bind.
func TestInterpolateCtxSafeIgnoresNonIdentifierKeys(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	const q = "SELECT id FROM docs WHERE id = :id AND user_id = :user_id"
	ctx := &FlowContext{App: app, Data: map[string]any{}, Params: map[string]string{
		"id":                        "5",
		"user_id":                   "1",
		"id AND user_id = :user_id": "5",
	}}
	for i := 0; i < 50; i++ { // map iteration order must not matter
		query, args := interpolateCtxSafe(q, ctx)
		if query != "SELECT id FROM docs WHERE id = ? AND user_id = ?" {
			t.Fatalf("SQL text changed: %q", query)
		}
		if len(args) != 2 || fmt.Sprint(args[0]) != "5" || fmt.Sprint(args[1]) != "1" {
			t.Fatalf("args = %#v, want [5 1]", args)
		}
	}
}

func TestInterpolateCtxSafeKeepsNonParamColons(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	ctx := &FlowContext{App: app, Data: map[string]any{}, Params: map[string]string{"id": "7", "ss": "x"}}
	query, args := interpolateCtxSafe("SELECT strftime('%H:%M:ss', t)::text FROM x WHERE id = :id", ctx)
	if !strings.Contains(query, "'%H:%M:ss'") || !strings.HasSuffix(query, "id = ?") || len(args) != 1 {
		t.Fatalf("query=%q args=%#v", query, args)
	}
}

// Mixed `{{ }}` refs and `:name` params must bind in placeholder order.
func TestInterpolateCtxSafeBindsMixedStylesInOrder(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	mustExec(t, app.DB, "CREATE TABLE docs (id INTEGER, user_id INTEGER)")
	mustExec(t, app.DB, "INSERT INTO docs VALUES (7, 7), (99, 99)")
	ctx := &FlowContext{App: app, Data: map[string]any{"owner": 7}, Params: map[string]string{"id": "99"}}
	query, args := interpolateCtxSafe("SELECT COUNT(*) FROM docs WHERE user_id = {{owner}} AND id = :id", ctx)
	if len(args) != 2 || fmt.Sprint(args[0]) != "7" || fmt.Sprint(args[1]) != "99" {
		t.Fatalf("args bound out of order: %#v for %q", args, query)
	}
	var n int
	if err := app.DB.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("user 7 matched user 99's doc (count %d): owner check lost to arg reordering", n)
	}
}

func TestSubstituteColonParamsIsTokenScoped(t *testing.T) {
	p := map[string]string{"id": "42", "id x": "EVIL", "name": ":id"}
	got := substituteColonParams("https://api.example.com:8443/items/:id?q=:name&v=:identity&c=a::b", p)
	want := "https://api.example.com:8443/items/42?q=:id&v=:identity&c=a::b"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

// A public flow must never bind a caller-claimed identity: `:user_id` in its
// SQL resolves to the real signed-in user, or NULL for anonymous callers.
func TestPublicFlowIgnoresRequestSuppliedIdentity(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	EnsureUsersTable(app.DB)
	EnsureSessionsTable(app.DB)
	mustExec(t, app.DB, "CREATE TABLE probe (u TEXT, g TEXT)")
	flow := &Flow{
		Name:    "public-probe",
		Trigger: FlowTrigger{Type: "http", Method: http.MethodPost, Path: "/api/public-probe"},
		Steps: []FlowStep{
			{Name: "w", Type: "sql", SQL: "INSERT INTO probe (u, g) VALUES (:user_id, :_group_id)"},
			{Type: "respond", Respond: &FlowRespond{Status: http.StatusOK, JSON: map[string]any{"ok": true}}},
		},
	}
	req := httptest.NewRequest(http.MethodPost, "/api/public-probe?user_id=99&_group_id=tenant-b", strings.NewReader(`{"user_id":99,"_group_id":"tenant-b"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	executeFlowHTTP(app, flow, rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var u, g sql.NullString
	if err := app.DB.QueryRow("SELECT u, g FROM probe").Scan(&u, &g); err != nil {
		t.Fatal(err)
	}
	if u.String == "99" || g.String == "tenant-b" {
		t.Fatalf("public flow bound caller-claimed identity: user_id=%q group=%q", u.String, g.String)
	}
}
