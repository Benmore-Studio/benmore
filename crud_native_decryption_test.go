//go:build !cli

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"testing"
)

// The fixture owner supplies known ciphertext. This is not an API disclosure
// of ciphertext: the peer's direct read of the protected source stays masked.
func TestNativeReadsLeaveOrdinaryCiphertextLookingTextLiteral(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, dir, "schema.prisma", `model Note {
 id Int @id @default(autoincrement())
 user_id Int
 label String
 summary String
 secret String
 created_at DateTime @default(now())
 updated_at DateTime @default(now()) @updatedAt
 items Item[]
 @@map("notes")
}
model Item {
 id Int @id @default(autoincrement())
 note_id Int
 user_id Int
 summary String
 secret String
 note Note @relation(fields: [note_id], references: [id])
 @@map("items")
}
model Receipt {
 id Int @id @default(autoincrement())
 note_id Int
 summary_seen String
 @@map("receipts")
}`)
	writeTestFile(t, dir, "app.yaml", `auth: {identifier: email}
access:
 notes: {read: everyone, write: self, update: self, delete: self}
 items: {read: everyone, write: self, update: self, delete: self}
 receipts: admin
versioned: [notes]
encrypted:
 notes:
  - {column: secret, roles: [owner]}
 items:
  - {column: secret, roles: [owner]}
`)
	writeTestFile(t, dir, "hooks.yaml", `on_update:
 notes:
  - sql: INSERT INTO receipts(note_id,summary_seen) VALUES ({{id}},{{summary}})
`)
	app, err := loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	mux := buildAppMux(app, true, "https://source.example.invalid")
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
	protected := native(t, http.MethodPost, "/api/notes", owner, map[string]any{"label": "source", "summary": "public", "secret": "owner-private"})
	var cipher string
	if err := app.DB.QueryRow("SELECT secret FROM notes WHERE id=?", protected["id"]).Scan(&cipher); err != nil {
		t.Fatal(err)
	}
	if direct := native(t, http.MethodGet, fmt.Sprint("/api/notes/", protected["id"]), peer, nil); direct["secret"] == "owner-private" {
		t.Fatal("protected source is readable by peer")
	}
	// Authored SQL remains on its existing compatibility decoder. A direct
	// encrypted-column alias must keep working; arbitrary SQL is not assigned
	// a source policy by guessing its result labels.
	aliases, err := QueryRows(app.DB, "SELECT secret AS encrypted_alias FROM notes WHERE id=?", protected["id"])
	if err != nil || len(aliases) != 1 || aliases[0]["encrypted_alias"] != "owner-private" {
		t.Fatalf("authored encrypted alias changed: %#v %v", aliases, err)
	}
	for name, value := range map[string]string{"known_cipher": cipher, "invalid_literal": "enc:v2:ordinary-literal"} {
		t.Run(name, func(t *testing.T) {
			row := native(t, http.MethodPost, "/api/notes", peer, map[string]any{"label": name, "summary": value, "secret": "peer-private"})
			id, path := row["id"], fmt.Sprint("/api/notes/", row["id"])
			assert := func(label string, row map[string]any) {
				t.Helper()
				if row["summary"] != value || row["secret"] != "peer-private" {
					t.Errorf("%s source policy: summary=%#v secret=%#v", label, row["summary"], row["secret"])
				}
			}
			assert("create", row)
			assert("get", native(t, http.MethodGet, path, peer, nil))
			if name == "known_cipher" && recordReferencesLocalFile(app, "notes", fmt.Sprint(id), "owner-private") {
				t.Error("ordinary ciphertext falsely proved an authorized file reference")
			}
			assert("projection", native(t, http.MethodGet, path+"?fields=summary,secret", peer, nil))
			result := crudScopeRequest(t, mux, http.MethodGet, "/api/notes?label="+name, peer, nil)
			var rows []map[string]any
			if result.Code != 200 || json.Unmarshal(result.Body.Bytes(), &rows) != nil || len(rows) != 1 {
				t.Fatalf("list: %d %s", result.Code, result.Body.String())
			}
			assert("list", rows[0])
			query := native(t, http.MethodPost, "/api/_query", peer, map[string]any{"table": "notes", "select": []string{"summary", "secret"}, "where": map[string]any{"id": id}})
			assert("query", query["rows"].([]any)[0].(map[string]any))
			export := native(t, http.MethodGet, "/api/_my-data", peer, nil)
			var exported bool
			for _, value := range export["tables"].(map[string]any)["notes"].([]any) {
				r := value.(map[string]any)
				if r["id"] == id {
					assert("account export", r)
					exported = true
				}
			}
			if !exported {
				t.Fatal("owned row absent from account export")
			}
			grouped := native(t, http.MethodPost, "/api/_query", peer, map[string]any{"table": "notes", "group_by": []string{"summary"}, "aggregates": []map[string]any{{"fn": "count", "as": "rows_count"}}, "where": map[string]any{"id": id}})
			if got := grouped["rows"].([]any)[0].(map[string]any)["summary"]; got != value {
				t.Errorf("grouped ordinary source interpreted ciphertext: %#v", got)
			}
			child := native(t, http.MethodPost, "/api/items", peer, map[string]any{"note_id": id, "summary": value, "secret": "child-private"})
			withChild := native(t, http.MethodGet, path+"?include=items", peer, nil)
			children, ok := withChild["items"].([]any)
			if !ok || len(children) != 1 {
				t.Fatalf("child include: %#v", withChild)
			}
			included := children[0].(map[string]any)
			if included["summary"] != value || included["secret"] != "child-private" {
				t.Errorf("child include source policy: %#v", included)
			}
			withParent := native(t, http.MethodGet, fmt.Sprint("/api/items/", child["id"], "?include=note"), peer, nil)
			parent, ok := withParent["note"].(map[string]any)
			if !ok {
				t.Fatalf("parent include: %#v", withParent)
			}
			assert("parent include", parent)
			for _, mode := range []string{"single", "batch", "transaction"} {
				switch mode {
				case "single":
					native(t, http.MethodPatch, path, peer, map[string]any{"label": name})
				case "batch":
					native(t, http.MethodPatch, "/api/notes/batch", peer, map[string]any{"ids": []any{id}, "fields": map[string]any{"label": name}})
				case "transaction":
					native(t, http.MethodPost, "/api/_transaction", peer, map[string]any{"operations": []map[string]any{{"table": "notes", "action": "update", "id": id, "data": map[string]any{"label": name}}}})
				}
				var seen string
				if err := app.DB.QueryRow("SELECT summary_seen FROM receipts WHERE note_id=? ORDER BY id DESC LIMIT 1", id).Scan(&seen); err != nil || seen != value {
					t.Errorf("%s hook got %q; err=%v", mode, seen, err)
				}
			}
			var version int64
			if err := app.DB.QueryRow("SELECT _version FROM notes_history WHERE id=? ORDER BY _version LIMIT 1", id).Scan(&version); err != nil {
				t.Fatal(err)
			}
			assert("history", native(t, http.MethodGet, fmt.Sprintf("%s/versions/%d", path, version), peer, nil))
			var from string
			if err := app.DB.QueryRow("SELECT CAST(_valid_from AS TEXT) FROM notes_history WHERE id=? AND _version=?", id, version).Scan(&from); err != nil {
				t.Fatal(err)
			}
			assert("point in time", native(t, http.MethodGet, path+"?as_of="+url.QueryEscape(from), peer, nil))
			native(t, http.MethodPatch, path, peer, map[string]any{"summary": "changed"})
			native(t, http.MethodPost, fmt.Sprintf("%s/revert/%d", path, version), peer, nil)
			assert("revert", native(t, http.MethodGet, path, peer, nil))
		})
	}
}

func TestNativeRowDecoderRequiresConfiguredSourceContext(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	otherKey := bytes.Repeat([]byte{9}, 32)
	seal := func(key []byte, table, column string) string {
		t.Helper()
		value, err := fieldEncryptCtx(key, table, column, "private-value")
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	app := &App{Encrypted: &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{"notes": {{Column: "secret"}}}}}
	valid := seal(key, "notes", "secret")
	for name, input := range map[string]string{
		"correct":            valid,
		"legacy_v1":          appMCPTestV1Cipher(t, key, []byte("private-value")),
		"wrong_table":        seal(key, "other_notes", "secret"),
		"wrong_column":       seal(key, "notes", "other_secret"),
		"wrong_database_key": seal(otherKey, "notes", "secret"),
		"invalid_prefix":     "enc:v2:invalid",
	} {
		t.Run(name, func(t *testing.T) {
			row := map[string]any{"secret": input, "summary": input, "nullable": nil}
			nativeRowDecryptor(app, "notes")(row, key)
			want := decryptFailMask
			if name == "correct" || name == "legacy_v1" {
				want = "private-value"
			}
			if row["secret"] != want || row["summary"] != input || row["nullable"] != nil {
				t.Fatalf("source policy: %#v", row)
			}
		})
	}
	for _, table := range []string{"", "unconfigured"} {
		row := map[string]any{"secret": valid}
		nativeRowDecryptor(app, table)(row, key)
		if row["secret"] != valid {
			t.Fatalf("unproven source %q interpreted a result label", table)
		}
	}
}
