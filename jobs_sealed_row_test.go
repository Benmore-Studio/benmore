//go:build !cli

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

const (
	sealedJobSSN      = "123-45-6789"
	sealedJobSSNNext  = "987-65-4321"
	sealedJobScore    = 774411
	sealedJobHookURL  = "http://93.184.216.34/hook"
	sealedJobSubURL   = "http://93.184.216.34/subscription"
	sealedJobUpdateTp = `{"s":"{{ssn}}","o":"{{old_ssn}}","n":"{{score}}","name":"{{name}}"}`
)

type sealedJobDelivery struct{ path, body string }

// sealedJobApp is an app whose patients table encrypts ssn and score, with an
// insert and an update hook that post a webhook and an admin webhook
// subscription on the table. Outbound posts land on a local receiver.
func sealedJobApp(t *testing.T) (*App, *http.ServeMux, string, []byte, chan sealedJobDelivery) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "data.db")
	key := testKeyBytes(0x3D)
	oldGlobal, oldEphemeral, oldBlind := appEncryptionKey, appEncryptionKeyEphemeral, appBlindIndexKey.Load()
	t.Cleanup(func() {
		appEncryptionKey, appEncryptionKeyEphemeral = oldGlobal, oldEphemeral
		appBlindIndexKey.Store(oldBlind)
		dbCryptoRegistry.Delete(canonicalDBPath(path))
	})
	registerDBEncryptionKey(path, key, false)
	if err := SetBlindIndexKey(key); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(path, dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	mustExec(t, db, `CREATE TABLE patients (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, name TEXT, ssn TEXT, score INTEGER)`)
	config := &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{"patients": {{Column: "ssn"}, {Column: "score"}}}}
	InstallEncryptionTriggers(db, config)
	if err := EnsureUsersTable(db); err != nil {
		t.Fatal(err)
	}
	EnsureSessionsTable(db)
	EnsureAPITokensTable(db)
	EnsurePermissionsTable(db)
	EnsureAuditLogTable(db)
	EnsureIdempotencyTable(db)
	EnsureNotificationsTable(db)
	EnsureWebhooksTable(db)
	EnsureJobsTable(db)
	app := &App{Dir: dir, DB: db, Stop: make(chan struct{}), SessionDuration: time.Hour, Encrypted: config,
		Hooks: &HookConfig{
			OnInsert: map[string][]Hook{"patients": {{Webhook: sealedJobHookURL}}},
			OnUpdate: map[string][]Hook{"patients": {{Webhook: sealedJobHookURL, Body: sealedJobUpdateTp}}},
		},
	}
	t.Cleanup(app.Shutdown)
	cols, err := GetTableColumns(db, "patients")
	if err != nil {
		t.Fatal(err)
	}
	app.Tables = []Table{{Name: "patients", Columns: cols}}
	sid := createCrudScopeSession(t, app, "owner@example.com", "admin", "", "")
	admin := GetSessionFromDB(db, sid).UserID
	if _, err := db.Exec("INSERT INTO _benmore_webhooks (user_id, url, secret, tables, events) VALUES (?, ?, 'whsec-signing', 'patients', '')", admin, sealedJobSubURL); err != nil {
		t.Fatal(err)
	}

	got := make(chan sealedJobDelivery, 32)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got <- sealedJobDelivery{path: r.URL.Path, body: string(b)}
	}))
	t.Cleanup(srv.Close)
	saved := strictOutboundTransport
	strictOutboundTransport = &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", srv.Listener.Addr().String())
	}}
	t.Cleanup(func() { strictOutboundTransport = saved })

	mux := http.NewServeMux()
	RegisterCRUD(mux, app)
	return app, mux, sid, key, got
}

type sealedJobRow struct {
	id              int64
	jobType, status string
	payload         string
}

func sealedJobRows(t *testing.T, db *sql.DB) []sealedJobRow {
	t.Helper()
	rows, err := db.Query("SELECT id, job_type, status, payload FROM _benmore_jobs ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []sealedJobRow
	for rows.Next() {
		var r sealedJobRow
		if err := rows.Scan(&r.id, &r.jobType, &r.status, &r.payload); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

// sealedJobWrite creates a patient and then changes its ssn, queueing an
// insert hook, an update hook and a delivery to the subscription for each.
func sealedJobWrite(t *testing.T, mux *http.ServeMux, sid string) {
	t.Helper()
	rec := crudScopeRequest(t, mux, http.MethodPost, "/api/patients", sid, map[string]any{"name": "Ada", "ssn": sealedJobSSN, "score": sealedJobScore})
	if rec.Code != http.StatusOK {
		t.Fatalf("create = %d %s", rec.Code, rec.Body.String())
	}
	rec = crudScopeRequest(t, mux, http.MethodPatch, "/api/patients/1", sid, map[string]any{"ssn": sealedJobSSNNext})
	if rec.Code != http.StatusOK {
		t.Fatalf("update = %d %s", rec.Code, rec.Body.String())
	}
}

// sealedJobUnsealedTwin returns the payload the runtime stored before job
// rows were sealed: every sealed value replaced by the value it holds,
// opened here with the key directly, and the seal list removed.
func sealedJobUnsealedTwin(t *testing.T, payload, table string, key []byte) string {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(payload), &doc); err != nil {
		t.Fatal(err)
	}
	row, _ := doc["_row"].(map[string]any)
	list, _ := doc[jobSealedRowField].([]any)
	for _, item := range list {
		name := item.(string)
		plain, err := fieldDecryptCtx(key, jobSealedRowColumn(table, name), row[name].(string))
		if err != nil {
			t.Fatalf("open %s: %v", name, err)
		}
		var v any
		if err := json.Unmarshal([]byte(plain), &v); err != nil {
			t.Fatal(err)
		}
		row[name] = v
	}
	delete(doc, jobSealedRowField)
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

var sealedJobTimestampRe = regexp.MustCompile(`"timestamp":"[^"]*"`)

// sealedJobDeliver runs every due job and returns what the receiver got,
// sorted, with the subscription body's timestamp blanked.
func sealedJobDeliver(t *testing.T, app *App, got chan sealedJobDelivery, want int) []string {
	t.Helper()
	FlushJobs(app)
	var out []string
	for i := 0; i < want; i++ {
		select {
		case d := <-got:
			out = append(out, d.path+" "+sealedJobTimestampRe.ReplaceAllString(d.body, `"timestamp":""`))
		case <-time.After(5 * time.Second):
			t.Fatalf("got %d of %d deliveries", i, want)
		}
	}
	select {
	case d := <-got:
		t.Fatalf("unexpected extra delivery %s %s", d.path, d.body)
	default:
	}
	sort.Strings(out)
	return out
}

func sealedJobRequireNoPlaintext(t *testing.T, jobs []sealedJobRow) {
	t.Helper()
	for _, j := range jobs {
		for _, plain := range []string{sealedJobSSN, sealedJobSSNNext, "774411"} {
			if strings.Contains(j.payload, plain) {
				t.Errorf("job %d (%s) stores %s in plaintext: %s", j.id, j.jobType, plain, j.payload)
			}
		}
		if !strings.Contains(j.payload, `"Ada"`) {
			t.Errorf("job %d lost an ordinary column: %s", j.id, j.payload)
		}
	}
}

// A hook or webhook-subscription job carries the written row for delivery.
// Rows are decrypted when read, so the job used to hold the plaintext of
// every encrypted.yaml column (and its old_ delta) in _benmore_jobs for as
// long as jobs are kept. Those values are sealed at enqueue and opened at
// delivery, so the receiver gets exactly what it got before.
func TestHookAndWebhookJobsSealEncryptedColumns(t *testing.T) {
	app, mux, sid, key, got := sealedJobApp(t)
	sealedJobWrite(t, mux, sid)

	jobs := sealedJobRows(t, app.DB)
	if len(jobs) != 4 {
		t.Fatalf("jobs = %d, want an insert and an update hook and two deliveries", len(jobs))
	}
	sealedJobRequireNoPlaintext(t, jobs)

	// The same jobs as the runtime queued them before sealing, delivered
	// side by side: the receiver must see byte-identical bodies.
	for _, j := range jobs {
		twin := sealedJobUnsealedTwin(t, j.payload, "patients", key)
		mustExecArgs(t, app.DB, "INSERT INTO _benmore_jobs (job_type, flow_name, payload, run_at) VALUES (?, ?, ?, datetime('now'))", j.jobType, j.jobType, twin)
	}
	bodies := sealedJobDeliver(t, app, got, 8)
	for i := 0; i < len(bodies); i += 2 {
		if bodies[i] != bodies[i+1] {
			t.Fatalf("sealed delivery differs from the unsealed one:\n%s\n%s", bodies[i], bodies[i+1])
		}
	}
	joined := strings.Join(bodies, "\n")
	for _, want := range []string{
		`"ssn":"` + sealedJobSSN + `"`,
		`"ssn":"` + sealedJobSSNNext + `"`,
		`"old_ssn":"` + sealedJobSSN + `"`,
		`{"s":"` + sealedJobSSNNext + `","o":"` + sealedJobSSN + `","n":"774411","name":"Ada"}`,
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("deliveries lack %s:\n%s", want, joined)
		}
	}
	for _, j := range sealedJobRows(t, app.DB) {
		if j.status != "completed" {
			t.Errorf("job %d (%s) = %s", j.id, j.jobType, j.status)
		}
	}
}

func mustExecArgs(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.Exec(q, args...); err != nil {
		t.Fatalf("exec %q: %v", q, err)
	}
}

// A job queued before rows were sealed holds the plaintext row and no seal
// list; it is delivered as it always was.
func TestLegacyPlaintextHookAndWebhookJobsStillDeliver(t *testing.T) {
	app, _, _, _, got := sealedJobApp(t)
	row := map[string]any{"id": 1, "name": "Ada", "ssn": sealedJobSSN, "score": sealedJobScore}
	hook, _ := json.Marshal(map[string]any{"_hook": map[string]any{"webhook": sealedJobHookURL, "sql": "", "body": "", "table": "patients"}, "_row": row})
	sub, _ := json.Marshal(map[string]any{"_webhook_subscription": map[string]any{"webhook_id": "1", "url": sealedJobSubURL, "event": "insert", "table": "patients"}, "_row": row})
	mustExecArgs(t, app.DB, "INSERT INTO _benmore_jobs (job_type, flow_name, payload, run_at) VALUES ('hook', 'hook', ?, datetime('now'))", string(hook))
	mustExecArgs(t, app.DB, "INSERT INTO _benmore_jobs (job_type, flow_name, payload, run_at) VALUES ('webhook_subscription', 'webhook_subscription', ?, datetime('now'))", string(sub))
	bodies := sealedJobDeliver(t, app, got, 2)
	if !strings.Contains(bodies[0], `/hook {"id":1,"name":"Ada","score":774411,"ssn":"`+sealedJobSSN+`"}`) {
		t.Fatalf("legacy hook delivery = %s", bodies[0])
	}
	if !strings.Contains(bodies[1], `"data":{"id":1,"name":"Ada","score":774411,"ssn":"`+sealedJobSSN+`"}`) {
		t.Fatalf("legacy subscription delivery = %s", bodies[1])
	}
}

// Rotating ENCRYPTION_KEY re-seals the rows of jobs that can still be
// delivered (pending, running, failed) in the rotation's transaction, so
// they deliver unchanged under the new key and the old key opens nothing.
func TestEncryptionKeyRotationResealsJobRows(t *testing.T) {
	app, mux, sid, key, got := sealedJobApp(t)
	sealedJobWrite(t, mux, sid)
	before := sealedJobRows(t, app.DB)
	if len(before) != 4 {
		t.Fatalf("jobs = %d", len(before))
	}
	// One delivery already failed once (retryable by an admin) and one
	// is completed: only the first is re-sealed.
	mustExec(t, app.DB, "UPDATE _benmore_jobs SET status='failed' WHERE id=1")
	mustExec(t, app.DB, "UPDATE _benmore_jobs SET status='completed' WHERE id=2")
	expect := map[int64]string{}
	for _, j := range before {
		expect[j.id] = sealedJobUnsealedTwin(t, j.payload, "patients", key)
	}

	newSource := strings.Repeat("q", 64)
	if _, err := RotateEncryptionKey(app, newSource, false); err != nil {
		t.Fatalf("rotation: %v", err)
	}
	newKey, _ := cryptoDeriveAppKey(newSource)
	after := sealedJobRows(t, app.DB)
	sealedJobRequireNoPlaintext(t, after)
	for i, j := range after {
		if j.id == 2 {
			if j.payload != before[i].payload {
				t.Fatal("completed job was rewritten")
			}
			continue
		}
		if j.payload == before[i].payload {
			t.Fatalf("job %d (%s) not re-sealed", j.id, j.status)
		}
		if got := sealedJobUnsealedTwin(t, j.payload, "patients", newKey); got != expect[j.id] {
			t.Fatalf("job %d re-sealed to a different row:\n%s\n%s", j.id, got, expect[j.id])
		}
		var doc map[string]any
		json.Unmarshal([]byte(j.payload), &doc)
		for _, item := range doc[jobSealedRowField].([]any) {
			name := item.(string)
			if _, err := fieldDecryptCtx(key, jobSealedRowColumn("patients", name), doc["_row"].(map[string]any)[name].(string)); err == nil {
				t.Fatalf("job %d %s still opens under the old key", j.id, name)
			}
		}
	}

	// The failed one is retried by an admin; every deliverable job delivers
	// the row it was queued with.
	mustExec(t, app.DB, "UPDATE _benmore_jobs SET status='pending' WHERE id=1")
	for id, twin := range expect {
		if id == 2 {
			continue
		}
		var jobType string
		app.DB.QueryRow("SELECT job_type FROM _benmore_jobs WHERE id=?", id).Scan(&jobType)
		mustExecArgs(t, app.DB, "INSERT INTO _benmore_jobs (job_type, flow_name, payload, run_at) VALUES (?, ?, ?, datetime('now'))", jobType, jobType, twin)
	}
	bodies := sealedJobDeliver(t, app, got, 6)
	for i := 0; i < len(bodies); i += 2 {
		if bodies[i] != bodies[i+1] {
			t.Fatalf("after rotation the sealed delivery differs:\n%s\n%s", bodies[i], bodies[i+1])
		}
	}
}

// A seal list whose value is not a sealed job value for that table and key -
// plaintext written in, or a value moved from another key - is never
// delivered.
func TestSealedJobRowRefusesTamperedValues(t *testing.T) {
	app, mux, sid, _, got := sealedJobApp(t)
	rec := crudScopeRequest(t, mux, http.MethodPost, "/api/patients", sid, map[string]any{"name": "Ada", "ssn": sealedJobSSN, "score": sealedJobScore})
	if rec.Code != http.StatusOK {
		t.Fatalf("create = %d %s", rec.Code, rec.Body.String())
	}
	jobs := sealedJobRows(t, app.DB)
	var hook sealedJobRow
	for _, j := range jobs {
		if j.jobType == "hook" {
			hook = j
		}
	}
	var doc map[string]any
	json.Unmarshal([]byte(hook.payload), &doc)
	row := doc["_row"].(map[string]any)
	for name, value := range map[string]any{
		"plaintext": `"` + sealedJobSSN + `"`,
		"moved":     row["score"],
	} {
		mutated := map[string]any{}
		json.Unmarshal([]byte(hook.payload), &mutated)
		mutated["_row"].(map[string]any)["ssn"] = value
		if err := executeHookJob(app, mutated); err == nil {
			t.Errorf("%s: hook job with a tampered sealed value ran", name)
		}
	}
	select {
	case d := <-got:
		t.Fatalf("tampered job delivered %s", d.body)
	default:
	}
}
