//go:build !cli

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// jobPayloadFixture queues a CRUD hook job and a flow job whose payloads
// carry hidden, encrypted-field and env-derived values, and returns the app,
// an admin session id and the stored payloads by job id.
func jobPayloadFixture(t *testing.T) (*App, string, map[int64]string) {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	app := &App{Dir: dir, DB: db, Encrypted: &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{
		"customers": {{Column: "ssn", Roles: []string{"billing"}}},
	}}}
	t.Cleanup(app.Shutdown)
	// An app with encrypted.yaml always has its key registered; queued
	// rows seal their encrypted values under it.
	withTOTPKey(t, app, testKeyBytes(0x2B), false)
	EnsureUsersTable(db)
	EnsureSessionsTable(db)
	EnsureJobsTable(db)
	mustExec(t, db, `INSERT INTO _benmore_users (id, username, email, role) VALUES (1, 'admin', 'admin@test.com', 'admin')`)
	sid := CreateSession(db, 1, "admin@test.com", "", time.Hour)

	row := map[string]any{"id": 9, "name": "Ada", "stripe_secret": "sk_live_x", "api_token": "tok_x", "old_api_token": "tok_old", "ssn": "123-45-6789", "email_blind": "hmac"}
	EnqueueHookJob(app, Hook{Webhook: "https://hooks.example.com/x"}, "customers", row)
	flowPayload, _ := json.Marshal(map[string]any{"name": "Ada", "api_token": "tok_x", "ssn": "123-45-6789", "creds": map[string]any{"refresh_token": "r"}, "s": "env-secret", flowSecretKeysPayloadField: []string{"s"}})
	mustExec(t, db, `INSERT INTO _benmore_jobs (job_type, flow_name, payload) VALUES ('flow', 'worker', '`+string(flowPayload)+`')`)

	stored := map[int64]string{}
	rows, err := db.Query(`SELECT id, payload FROM _benmore_jobs ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id int64
		var p string
		rows.Scan(&id, &p)
		stored[id] = p
	}
	rows.Close()
	if len(stored) != 2 {
		t.Fatalf("jobs = %d, want 2", len(stored))
	}
	return app, sid, stored
}

// checkJobPayloadRedacted fails when a read payload still holds one of the
// fixture's protected values or lost its ordinary column.
func checkJobPayloadRedacted(t *testing.T, surface, payload string) {
	t.Helper()
	for _, secret := range []string{"sk_live_x", "tok_x", "tok_old", "123-45-6789", "hmac", "env-secret", `"r"`} {
		if strings.Contains(payload, secret) {
			t.Errorf("%s: payload still carries %s: %s", surface, secret, payload)
		}
	}
	if !strings.Contains(payload, "Ada") {
		t.Errorf("%s: ordinary column lost: %s", surface, payload)
	}
}

// Job payloads keep a full copy of the written row (hidden credential
// columns, decrypted encrypted fields) and enqueue values derived from env,
// so a hook, webhook or event flow gets the row it was queued with. Reading a
// job back (GET /api/_jobs/{id}, describe_jobs, read-only SQL) must not hand
// those values to an admin or agent who cannot read them anywhere else; the
// stored payload, and so delivery, stays the same.
func TestJobPayloadReadsRedactHiddenAndDecryptedValues(t *testing.T) {
	app, sid, stored := jobPayloadFixture(t)
	db := app.DB

	mux := http.NewServeMux()
	RegisterJobsAPI(mux, app)
	for id := range stored {
		req := httptest.NewRequest("GET", fmt.Sprintf("/api/_jobs/%d", id), nil)
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		var job map[string]any
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &job) != nil {
			t.Fatalf("GET job %d: %d %s", id, rec.Code, rec.Body.String())
		}
		p, _ := job["payload"].(string)
		checkJobPayloadRedacted(t, fmt.Sprintf("GET /api/_jobs/%d", id), p)
	}

	ro, _, err := queryReadOnlyRows(context.Background(), db, `SELECT payload, json_extract(payload, '$._row.api_token') AS t, json_extract(payload, '$.s') AS s FROM _benmore_jobs`, 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range ro {
		if r["payload"] != nil || r["t"] != nil || r["s"] != nil {
			t.Errorf("read-only SQL sees the job payload: %v", r)
		}
	}

	// Delivery reads the stored payload, which is untouched.
	for id, before := range stored {
		var after string
		db.QueryRow(`SELECT payload FROM _benmore_jobs WHERE id = ?`, id).Scan(&after)
		if after != before {
			t.Fatalf("job %d payload changed on read:\n%s\n%s", id, before, after)
		}
	}
}
