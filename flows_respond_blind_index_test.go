//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// blindRespondApp is an app with one blind-indexed encrypted column
// (patients.ssn) and a table whose own column merely ends in `_blind`
// (shades.color_blind, declared nowhere in the encrypted config).
func blindRespondApp(t *testing.T) *App {
	t.Helper()
	oldKey := appEncryptionKey
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 11)
	}
	appEncryptionKey = key
	if err := SetBlindIndexKey(key); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { appEncryptionKey = oldKey })

	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, db, `CREATE TABLE patients (id INTEGER PRIMARY KEY, name TEXT, ssn TEXT)`)
	mustExec(t, db, `CREATE TABLE shades (id INTEGER PRIMARY KEY, label TEXT, color_blind TEXT)`)
	mustExec(t, db, `CREATE TABLE lookups (id INTEGER PRIMARY KEY, probe TEXT)`)
	cfg := &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{
		"patients": {{Column: "ssn", BlindIndex: true}},
	}}
	if err := EnsureBlindColumns(db, cfg); err != nil {
		t.Fatal(err)
	}
	if err := InstallEncryptionTriggers(db, cfg); err != nil {
		t.Fatal(err)
	}
	if err := InstallBlindIndexTriggers(db, cfg); err != nil {
		t.Fatal(err)
	}
	mustExec(t, db, `INSERT INTO patients (id, name, ssn) VALUES (1, 'Ada', '111-22-3333')`)
	mustExec(t, db, `INSERT INTO patients (id, name, ssn) VALUES (2, 'Bo', '111-22-3333')`)
	mustExec(t, db, `INSERT INTO shades (id, label, color_blind) VALUES (1, 'teal', 'deutan-safe')`)
	app := &App{Dir: dir, DB: db, Encrypted: cfg}
	t.Cleanup(app.Shutdown)
	return app
}

// blindRespondRun runs one flow file's first flow and returns the response.
func blindRespondRun(t *testing.T, app *App, flow string) *httptest.ResponseRecorder {
	t.Helper()
	flows, err := parseGHAFlowFile(app.Dir+"/flows/f.yaml", []byte(flow))
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	executeFlowHTTP(app, &flows[0], rr, httptest.NewRequest(http.MethodGet, "/api/f", nil))
	if rr.Code != 200 {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	return rr
}

// The stored HMAC, read straight from the table.
func blindRespondStored(t *testing.T, app *App) string {
	t.Helper()
	var blind string
	if err := app.DB.QueryRow(`SELECT ssn_blind FROM patients WHERE id = 1`).Scan(&blind); err != nil {
		t.Fatal(err)
	}
	if len(blind) < 16 {
		t.Fatalf("blind index was not written: %q", blind)
	}
	return blind
}

// A flow that selects whole rows of a blind-indexed table and responds with
// them answers every other column and no `<col>_blind` key, at any depth and
// in every response shape; a later step still reads and binds the value.
func TestFlowRespondLeavesOutDeclaredBlindIndexColumns(t *testing.T) {
	app := blindRespondApp(t)
	blind := blindRespondStored(t, app)

	rr := blindRespondRun(t, app, `on:
  request:
    method: GET
    path: /api/f
jobs:
  main:
    steps:
      - id: p
        run: sql
        with:
          query: "SELECT * FROM patients ORDER BY id"
      - id: ret
        run: sql
        with:
          query: "UPDATE patients SET name = name WHERE id = 1 RETURNING *"
      - id: keep
        run: sql
        with:
          query: "INSERT INTO lookups (probe) VALUES (:b)"
          params:
            b: ${{ steps.p.outputs.first.ssn_blind }}
      - id: same
        run: sql
        with:
          query: "SELECT count(*) AS n FROM patients WHERE ssn_blind = :b"
          params:
            b: ${{ steps.p.outputs.first.ssn_blind }}
      - run: respond
        with:
          status: 200
          json:
            rows: ${{ steps.p.outputs.rows }}
            first: ${{ steps.p.outputs.first }}
            outputs: ${{ steps.p.outputs }}
            returned: ${{ steps.ret.outputs.first }}
            nested:
              deep:
                - patient: ${{ steps.p.outputs.rows[1] }}
            same: ${{ steps.same.outputs.first.n }}
`)
	body := rr.Body.String()
	if strings.Contains(body, "ssn_blind") || strings.Contains(body, blind) {
		t.Fatalf("response carries the blind index: %s", body)
	}
	var got struct {
		Rows     []map[string]any `json:"rows"`
		First    map[string]any   `json:"first"`
		Outputs  []map[string]any `json:"outputs"`
		Returned map[string]any   `json:"returned"`
		Nested   struct {
			Deep []struct {
				Patient map[string]any `json:"patient"`
			} `json:"deep"`
		} `json:"nested"`
		Same float64 `json:"same"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("%v: %s", err, body)
	}
	if len(got.Rows) != 2 || got.Rows[0]["name"] != "Ada" || got.Rows[0]["ssn"] != "111-22-3333" || got.Rows[0]["id"] != float64(1) {
		t.Errorf("other columns of the rows changed: %v", got.Rows)
	}
	if got.First["name"] != "Ada" || got.First["ssn"] != "111-22-3333" {
		t.Errorf("first: %v", got.First)
	}
	if got.Returned["name"] != "Ada" || got.Returned["ssn"] != "111-22-3333" {
		t.Errorf("RETURNING * row: %v", got.Returned)
	}
	if len(got.Nested.Deep) != 1 || got.Nested.Deep[0].Patient["name"] != "Bo" {
		t.Errorf("nested row: %v", got.Nested.Deep)
	}
	if len(got.Outputs) != 2 || got.Outputs[1]["name"] != "Bo" {
		t.Errorf("outputs: %v", got.Outputs)
	}
	// The steps before the response read the real value: both patients share
	// an SSN, and the bound value landed in another table unchanged.
	if got.Same != 2 {
		t.Errorf("a later step did not bind the blind value: same = %v", got.Same)
	}
	var probe string
	if err := app.DB.QueryRow(`SELECT probe FROM lookups`).Scan(&probe); err != nil || probe != blind {
		t.Errorf("bound blind value = %q (%v), want the stored one", probe, err)
	}
}

// Every body shape: a json list, a body that is one reference, a text body
// that renders rows through a pipe, and a response header.
func TestFlowRespondBlindIndexEveryBodyShape(t *testing.T) {
	app := blindRespondApp(t)
	blind := blindRespondStored(t, app)
	const head = `on:
  request:
    method: GET
    path: /api/f
jobs:
  main:
    steps:
      - id: p
        run: sql
        with:
          query: "SELECT * FROM patients ORDER BY id"
`
	for name, respond := range map[string]string{
		"json list": `      - run: respond
        with:
          status: 200
          json:
            - ${{ steps.p.outputs.rows }}
            - ${{ steps.p.outputs.first }}
`,
		"bare body": `      - run: respond
        with:
          status: 200
          body: ${{ steps.p.outputs.rows }}
`,
		"bare body, declared type": `      - run: respond
        with:
          status: 200
          content_type: application/json
          body: ${{ steps.p.outputs.first }}
`,
		"text body with a pipe": `      - run: respond
        with:
          status: 200
          content_type: application/json
          body: '{"rows": ${{ steps.p.outputs.rows | json }}, "one": ${{ steps.p.outputs.first | json }}}'
`,
		"text inside a json value": `      - run: respond
        with:
          status: 200
          json:
            note: 'rows ${{ steps.p.outputs.rows | json }}'
`,
		"header": `      - run: respond
        with:
          status: 200
          headers:
            X-Row: ${{ steps.p.outputs.first | json }}
          json:
            ok: true
`,
	} {
		t.Run(name, func(t *testing.T) {
			rr := blindRespondRun(t, app, head+respond)
			sent := rr.Body.String() + " " + rr.Header().Get("X-Row")
			if strings.Contains(sent, "ssn_blind") || strings.Contains(sent, blind) {
				t.Fatalf("response carries the blind index: %s", sent)
			}
			if !strings.Contains(sent, "Ada") || !strings.Contains(sent, "111-22-3333") {
				t.Fatalf("the other columns are missing: %s", sent)
			}
		})
	}
}

// Only declared blind columns are left out: an app column whose name ends in
// `_blind` stays, a blind value the flow selects under another name is the
// author's choice, and so is a single value referenced on its own.
func TestFlowRespondKeepsUndeclaredBlindNamedColumns(t *testing.T) {
	app := blindRespondApp(t)
	blind := blindRespondStored(t, app)
	rr := blindRespondRun(t, app, `on:
  request:
    method: GET
    path: /api/f
jobs:
  main:
    steps:
      - id: s
        run: sql
        with:
          query: "SELECT * FROM shades"
      - id: named
        run: sql
        with:
          query: "SELECT ssn_blind AS match_key, ssn_blind FROM patients WHERE id = 1"
      - run: respond
        with:
          status: 200
          json:
            shade: ${{ steps.s.outputs.first }}
            named: ${{ steps.named.outputs.first }}
            token: ${{ steps.named.outputs.first.ssn_blind }}
            ssn_blind: ${{ steps.named.outputs.first.ssn_blind }}
`)
	var got struct {
		Shade map[string]any `json:"shade"`
		Named map[string]any `json:"named"`
		Token string         `json:"token"`
		Blind *string        `json:"ssn_blind"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("%v: %s", err, rr.Body.String())
	}
	if got.Shade["color_blind"] != "deutan-safe" || got.Shade["label"] != "teal" {
		t.Errorf("an undeclared column ending in _blind was dropped: %v", got.Shade)
	}
	if got.Named["match_key"] != blind {
		t.Errorf("a blind value selected under another name was dropped: %v", got.Named)
	}
	if _, present := got.Named["ssn_blind"]; present {
		t.Errorf("the declared blind column stayed in the row: %v", got.Named)
	}
	if got.Token != blind {
		t.Errorf("a value referenced on its own under another key = %q, want the stored value", got.Token)
	}
	if got.Blind != nil {
		t.Errorf("the response carries a key named like the declared blind column: %s", rr.Body.String())
	}
}

// An app with no blind index declared is untouched, whatever its keys are.
func TestFlowRespondWithoutBlindIndexUnchanged(t *testing.T) {
	app := blindRespondApp(t)
	app.Encrypted = &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{"patients": {{Column: "ssn"}}}}
	rr := blindRespondRun(t, app, `on:
  request:
    method: GET
    path: /api/f
jobs:
  main:
    steps:
      - id: s
        run: sql
        with:
          query: "SELECT id, name, ssn_blind FROM patients WHERE id = 1"
      - run: respond
        with:
          status: 200
          json:
            row: ${{ steps.s.outputs.first }}
`)
	if !strings.Contains(rr.Body.String(), "ssn_blind") {
		t.Errorf("a column no blind index declares was dropped: %s", rr.Body.String())
	}
}
