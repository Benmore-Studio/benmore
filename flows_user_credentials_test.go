//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A flow that selects the users table never answers credential columns, but
// keeps everything else, a value computed from them, and other tables'
// columns that only look secret.
func TestFlowSQLDropsUserCredentialColumns(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	mustExec(t, app.DB, `CREATE TABLE IF NOT EXISTS _benmore_users (id INTEGER PRIMARY KEY, email TEXT, first_name TEXT, password_hash TEXT, totp_secret TEXT, backup_codes TEXT, mfa_setup_nonce TEXT)`)
	mustExec(t, app.DB, `INSERT INTO _benmore_users (id, email, first_name, password_hash, totp_secret, backup_codes, mfa_setup_nonce) VALUES (7, 'u@example.com', 'Una', '$2a$12$hash', 'TOTPSECRET', 'codes', 'nonce')`)
	mustExec(t, app.DB, `CREATE TABLE vaults (id INTEGER PRIMARY KEY, user_id INTEGER, api_key TEXT)`)
	mustExec(t, app.DB, `INSERT INTO vaults (id, user_id, api_key) VALUES (1, 7, 'app-key-1')`)
	flow := `on:
  request:
    method: GET
    path: /api/people
jobs:
  main:
    steps:
      - id: everyone
        run: sql
        with:
          query: "SELECT * FROM _benmore_users"
      - id: joined
        run: sql
        with:
          query: "SELECT u.email, v.api_key, CASE WHEN COALESCE(u.totp_secret, '') != '' THEN 1 ELSE 0 END AS mfa FROM vaults v JOIN _benmore_users u ON u.id = v.user_id"
      - id: dyn
        run: sql_dynamic
        with:
          query: "SELECT * FROM main._benmore_users"
      - id: literal
        run: sql
        with:
          query: "SELECT * FROM '_BENMORE_USERS'"
      - run: respond
        with:
          status: 200
          json:
            everyone: ${{ steps.everyone.outputs.rows }}
            joined: ${{ steps.joined.outputs.rows }}
            dyn: ${{ steps.dyn.outputs.rows }}
            literal: ${{ steps.literal.outputs.rows }}
`
	flows, err := parseGHAFlowFile(app.Dir+"/flows/people.yaml", []byte(flow))
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	executeFlowHTTP(app, &flows[0], rr, httptest.NewRequest(http.MethodGet, "/api/people", nil))
	body := rr.Body.String()
	if rr.Code != 200 {
		t.Fatalf("%d %s", rr.Code, body)
	}
	for _, secret := range []string{"$2a$12$hash", "TOTPSECRET", "codes", "nonce", "password_hash", "totp_secret"} {
		if strings.Contains(body, secret) {
			t.Errorf("response carries %q: %s", secret, body)
		}
	}
	var got map[string][]map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["everyone"][0]["email"] != "u@example.com" || got["everyone"][0]["first_name"] != "Una" {
		t.Errorf("ordinary user columns dropped: %v", got["everyone"])
	}
	if got["joined"][0]["api_key"] != "app-key-1" || got["joined"][0]["mfa"] != float64(1) {
		t.Errorf("joined app column or computed value dropped: %v", got["joined"])
	}
	if got["dyn"][0]["email"] != "u@example.com" {
		t.Errorf("sql_dynamic rows: %v", got["dyn"])
	}
	// SQLite reads a string literal in table position as the table name.
	if got["literal"][0]["email"] != "u@example.com" {
		t.Errorf("string-literal table rows: %v", got["literal"])
	}
}

func TestSQLDynamicRefusesRequestParamsAtWrite(t *testing.T) {
	flow := "on:\n  request: {method: GET, path: /api/dyn}\njobs:\n  x:\n    steps:\n      - run: sql_dynamic\n        with:\n          query: \"SELECT * FROM notes ORDER BY ${{ params.col }}\"\n      - run: respond\n        with: {status: 200, json: {ok: true}}\n"
	if msg := ValidateOnWrite("flows/dyn.yaml", flow); !strings.Contains(msg, "params.col") {
		t.Fatalf("sql_dynamic with request input passed the write gate: %q", msg)
	}
	ok := strings.Replace(flow, "${{ params.col }}", "${{ env.SORT_COLUMN }}", 1)
	if msg := ValidateOnWrite("flows/dyn.yaml", ok); strings.Contains(msg, "sql_dynamic") {
		t.Fatalf("server-controlled reference refused: %q", msg)
	}
}

// A table the caller may not reach answers the same 404 as a path that
// matches no table, so the answer does not reveal which tables exist.
func TestCRUDDenialMatchesUnmatchedAPINotFound(t *testing.T) {
	app, mux := auditApp(t)
	sid := createCrudScopeSession(t, app, "plain@example.com", "user", "", "")
	_ = mux
	app.Access.rules["rooms"] = map[AccessOp]string{"all": "admin"}
	full := buildAppMux(app, true, "http://localhost")
	get := func(path string) (int, string, string) {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.Header.Set("Authorization", "Bearer "+sid)
		w := httptest.NewRecorder()
		full.ServeHTTP(w, r)
		return w.Code, w.Header().Get("Content-Type"), w.Body.String()
	}
	dc, dt, db := get("/api/rooms")
	uc, ut, ub := get("/api/no_such_table_here")
	if dc != uc || dt != ut || db != ub {
		t.Fatalf("denied table %d %q %q differs from unmatched %d %q %q", dc, dt, db, uc, ut, ub)
	}
}
