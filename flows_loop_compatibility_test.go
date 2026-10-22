//go:build !cli

package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParsedLoopAliasReplacementPreservesNestedEffectsAndAccumulators(t *testing.T) {
	const source = `on:
  request: {method: POST, path: /api/loop-compatibility, transaction: true}
jobs:
  loop-compatibility:
    steps:
      - run: set
        with: {trail: '', rowExtra: KEEP}
      - for_each: params.rows
        as: row
        steps:
          - run: set
            with: {trail: "${{ trail }}${{ row.name }};"}
          - run: sql
            query: INSERT INTO recipients(name,email) VALUES (:name,:email)
            params: {name: '${{ row.name }}', email: "${{ row.email | default:'MISSING' }}"}
            expect_rows: '=1'
          - for_each: row.children
            as: child
            steps:
              - run: sql
                query: INSERT INTO children(code) VALUES (:code)
                params: {code: "${{ child.code | default:'MISSING' }}"}
                expect_rows: '=1'
      - for_each: params.empty
        as: row
        steps:
          - run: set
            with: {trail: MUST-NOT-RUN}
      - run: respond
        with:
          status: 200
          body:
            trail: '${{ trail }}'
            last_name: '${{ row.name }}'
            last_email: "${{ row.email | default:'MISSING' }}"
            unrelated: '${{ rowExtra }}'
`
	for _, tc := range []struct {
		name, secondEmail, expectedEmail string
	}{
		{"missing field", "", "MISSING"},
		{"complete rows control", `,"email":"bob@example.test"`, "bob@example.test"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, _ := auditApp(t)
			mustExec(t, app.DB, `CREATE TABLE recipients(name TEXT, email TEXT)`)
			mustExec(t, app.DB, `CREATE TABLE children(code TEXT)`)
			flows, err := parseGHAFlowFile("flows/loop-compatibility.yaml", []byte(source))
			if err != nil || len(flows) != 1 {
				t.Fatalf("parse: flows=%d err=%v", len(flows), err)
			}
			body := `{"rows":[{"name":"Alice","email":"alice@example.test","children":[{"code":"A"},{}]},{"name":"Bob","children":[]` + tc.secondEmail + `}],"empty":[]}`
			req := httptest.NewRequest("POST", "/api/loop-compatibility", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			if err := executeFlowHTTP(app, &flows[0], rec, req); err != nil {
				t.Fatalf("execute: %v; body=%s", err, rec.Body.String())
			}
			var got map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if rec.Code != 200 {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
			for key, want := range map[string]string{"trail": "Alice;Bob;", "last_name": "Bob", "last_email": tc.expectedEmail, "unrelated": "KEEP"} {
				if got[key] != want {
					t.Errorf("%s=%v want=%s", key, got[key], want)
				}
			}
			var email, children string
			if err := app.DB.QueryRow(`SELECT email FROM recipients WHERE name='Bob'`).Scan(&email); err != nil || email != tc.expectedEmail {
				t.Fatalf("stored recipient email=%q err=%v", email, err)
			}
			if err := app.DB.QueryRow(`SELECT group_concat(code, ';') FROM (SELECT code FROM children ORDER BY rowid)`).Scan(&children); err != nil || children != "A;MISSING" {
				t.Fatalf("nested loop effects=%q err=%v", children, err)
			}
		})
	}
}
