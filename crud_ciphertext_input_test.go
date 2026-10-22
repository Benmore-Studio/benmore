//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

// The fixture deliberately gives the peer the owner's stored ciphertext.
// No ordinary API ciphertext disclosure is assumed or demonstrated here.
func TestNativeEncryptedFieldsTreatKnownCiphertextAsPlaintext(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, dir, "schema.prisma", `model Note {
 id Int @id @default(autoincrement())
 user_id Int
 label String
 secret String?
 updated_at DateTime @default(now()) @updatedAt
 @@map("notes")
}
model Receipt {
 id Int @id @default(autoincrement())
 note_id Int
 secret_seen String?
 @@map("receipts")
}`)
	writeTestFile(t, dir, "app.yaml", `auth: {identifier: email}
access:
 notes: {read: everyone, write: self, update: self, delete: self}
 receipts: admin
versioned: [notes]
`)
	writeTestFile(t, dir, "encrypted.yaml", `tables:
 notes:
  fields: [secret]
  blind_index: [secret]
  unmask_roles: [owner]
`)
	writeTestFile(t, dir, "hooks.yaml", `before_update:
 notes:
  - sql: SELECT 'Refused fixture change' AS error
    when: label = 'refused'
on_update:
 notes:
  - sql: INSERT INTO receipts(note_id,secret_seen) VALUES ({{id}},{{secret}})
`)
	app, err := loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	EnsureImportsTable(app)
	mux := buildAppMux(app, true, "https://opaque.example.invalid")
	owner := createCrudScopeSession(t, app, "owner@example.test", "user", "", "")
	peer := createCrudScopeSession(t, app, "peer@example.test", "user", "", "")
	native := func(t *testing.T, method, path, token string, body any) map[string]any {
		t.Helper()
		r := crudScopeRequest(t, mux, method, path, token, body)
		if r.Code != http.StatusOK {
			t.Fatalf("%s %s: %d %s", method, path, r.Code, r.Body.String())
		}
		var row map[string]any
		if err := json.Unmarshal(r.Body.Bytes(), &row); err != nil {
			t.Fatal(err)
		}
		return row
	}
	protected := native(t, http.MethodPost, "/api/notes", owner, map[string]any{"label": "protected", "secret": "owner-private-value"})
	var cipher string
	if err := app.DB.QueryRow("SELECT secret FROM notes WHERE id=?", protected["id"]).Scan(&cipher); err != nil {
		t.Fatal(err)
	}
	if row := native(t, http.MethodGet, fmt.Sprint("/api/notes/", protected["id"]), peer, nil); row["secret"] == "owner-private-value" {
		t.Fatal("fixture is not protected from direct peer reads")
	}
	var peerID int64
	if err := app.DB.QueryRow("SELECT id FROM _benmore_users WHERE email=?", "peer@example.test").Scan(&peerID); err != nil {
		t.Fatal(err)
	}
	key := cryptoKeyForQuerier(app.DB)
	inputs := map[string]string{"v2": cipher, "v1": appMCPTestV1Cipher(t, key, []byte("legacy-owner-private")), "literal": "enc:v2:not-authentic-ciphertext"}
	for name, input := range inputs {
		for _, mode := range []string{"single", "batch", "transaction", "ingest", "import"} {
			t.Run(name+"/"+mode, func(t *testing.T) {
				label := name + "-" + mode
				data := map[string]any{"label": label, "secret": input}
				var id any
				switch mode {
				case "single":
					row := native(t, http.MethodPost, "/api/notes", peer, data)
					id = row["id"]
					if row["secret"] != input {
						t.Errorf("create adopted supplied ciphertext: %#v", row["secret"])
					}
				case "batch":
					row := native(t, http.MethodPost, "/api/notes/batch", peer, []map[string]any{data})
					id = row["ids"].([]any)[0]
				case "transaction":
					row := native(t, http.MethodPost, "/api/_transaction", peer, map[string]any{"operations": []map[string]any{{"table": "notes", "action": "insert", "data": data}}})
					id = row["results"].([]any)[0].(map[string]any)["id"]
				case "ingest":
					raw, _ := json.Marshal(data)
					r := httptest.NewRequest(http.MethodPost, "/api/notes/ingest", strings.NewReader(string(raw)+"\n"))
					r.Header.Set("Content-Type", "application/x-ndjson")
					r.Header.Set("Authorization", "Bearer "+peer)
					w := httptest.NewRecorder()
					mux.ServeHTTP(w, r)
					if w.Code != http.StatusOK {
						t.Fatalf("ingest: %d %s", w.Code, w.Body.String())
					}
				case "import":
					raw, _ := json.Marshal(data)
					content := string(raw) + "\n"
					sessionID := "cipher-" + name
					sum := stageString(t, app, sessionID, content)
					sess := &importSession{ID: sessionID, TableName: "notes", Format: "ndjson", BytesTotal: int64(len(content)), SHA256: sum, CreatedBy: peerID}
					insertSession(t, app, sess)
					if err := runImport(app, sess); err != nil {
						t.Fatalf("import: %v", err)
					}
				}
				if id == nil {
					var n int64
					if err := app.DB.QueryRow("SELECT id FROM notes WHERE label=?", label).Scan(&n); err != nil {
						t.Fatal(err)
					}
					id = float64(n)
				}
				path := fmt.Sprint("/api/notes/", id)
				assertLiteral := func() {
					t.Helper()
					row := native(t, http.MethodGet, path, peer, nil)
					if row["secret"] != input {
						t.Errorf("read adopted supplied ciphertext: %#v", row["secret"])
					}
					var stored string
					if err := app.DB.QueryRow("SELECT secret FROM notes WHERE id=?", id).Scan(&stored); err != nil {
						t.Fatal(err)
					}
					if stored == input {
						t.Error("client ciphertext was adopted as storage")
					}
					if plain, err := fieldDecryptCtx(key, "secret", stored); err != nil || plain != input {
						t.Errorf("storage does not seal literal: %q %v", plain, err)
					}
					filtered := crudScopeRequest(t, mux, http.MethodGet, "/api/notes?secret="+url.QueryEscape(input), peer, nil)
					var hits []map[string]any
					if filtered.Code != http.StatusOK {
						t.Fatalf("blind equality: %d %s", filtered.Code, filtered.Body.String())
					}
					if err := json.Unmarshal(filtered.Body.Bytes(), &hits); err != nil {
						t.Fatal(err)
					}
					found := false
					for _, hit := range hits {
						if hit["id"] == id {
							found = true
						}
					}
					if !found {
						t.Error("literal bytes not blind-indexed")
					}
				}
				assertLiteral()
				for _, update := range []string{"single", "batch", "transaction"} {
					native(t, http.MethodPatch, path, peer, map[string]any{"secret": "ordinary"})
					switch update {
					case "single":
						native(t, http.MethodPatch, path, peer, map[string]any{"secret": input})
					case "batch":
						native(t, http.MethodPatch, "/api/notes/batch", peer, map[string]any{"ids": []any{id}, "fields": map[string]any{"secret": input}})
					case "transaction":
						native(t, http.MethodPost, "/api/_transaction", peer, map[string]any{"operations": []map[string]any{{"table": "notes", "action": "update", "id": id, "data": map[string]any{"secret": input}}}})
					}
					assertLiteral()
					var seen string
					if err := app.DB.QueryRow("SELECT secret_seen FROM receipts WHERE note_id=? ORDER BY id DESC LIMIT 1", id).Scan(&seen); err != nil || seen != input {
						t.Errorf("hook saw different plaintext: %q %v", seen, err)
					}
				}
				// The historical version before the ordinary-value edit keeps the exact
				// supplied text; a rollback must retain it and its derived blind index.
				versions := native(t, http.MethodGet, path+"/versions", peer, nil)
				found := false
				for _, v := range versions["versions"].([]any) {
					version := v.(map[string]any)["_version"]
					snap := native(t, http.MethodGet, fmt.Sprint(path, "/versions/", version), peer, nil)
					if snap["secret"] == input {
						found = true
						break
					}
				}
				if !found {
					t.Error("history lost literal ciphertext")
				}
				failed := crudScopeRequest(t, mux, http.MethodPost, "/api/_transaction", peer, map[string]any{"operations": []map[string]any{{"table": "notes", "action": "update", "id": id, "data": map[string]any{"secret": "rollback"}}, {"table": "notes", "action": "update", "id": id, "data": map[string]any{"label": "refused"}}}})
				if failed.Code < 400 {
					t.Fatal("refused hook committed transaction")
				}
				assertLiteral()
			})
		}
	}
}

func TestGroupBootstrapTreatsKnownCiphertextAsPlaintext(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, dir, "schema.prisma", `model Company {
 id Int @id @default(autoincrement())
 user_id Int
 name String
 @@map("companies")
}
model Member {
 id Int @id @default(autoincrement())
 company_id Int
 user_id Int
 member_role String
 @@map("members")
}`)
	writeTestFile(t, dir, "app.yaml", `auth: {identifier: email}
access: {companies: self, members: self}
groups:
 table: members
 key: company_id
 user_field: user_id
 role_field: member_role
 bootstrap: {org_table: companies, founding_role: builder}
encrypted:
 companies:
  - {column: name, roles: [owner]}
`)
	app, err := loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	key := cryptoKeyForQuerier(app.DB)
	known, err := fieldEncryptCtx(key, "companies", "name", "other-company-private")
	if err != nil {
		t.Fatal(err)
	}
	token := createCrudScopeSession(t, app, "founder@example.test", "user", "", "")
	raw, _ := json.Marshal(map[string]any{"name": known})
	w := bootstrapAs(app, token, string(raw))
	if w.Code != http.StatusOK {
		t.Fatalf("bootstrap: %d %s", w.Code, w.Body.String())
	}
	var result map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	org := result["org"].(map[string]any)
	if org["name"] != known {
		t.Errorf("bootstrap adopted supplied ciphertext: %#v", org["name"])
	}
	var stored string
	if err := app.DB.QueryRow("SELECT name FROM companies WHERE id=?", org["id"]).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if plain, err := fieldDecryptCtx(key, "name", stored); err != nil || plain != known {
		t.Errorf("bootstrap storage did not seal literal: %q %v", plain, err)
	}
	if countRows(t, app, "members") != 1 {
		t.Error("bootstrap membership missing")
	}
}
