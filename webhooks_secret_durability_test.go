//go:build !cli

package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	webhookDurableURL    = "http://93.184.216.34/subscription"
	webhookDurableSecret = "whsec-durable-signing-secret-7Q2x"
)

type webhookCapturedDelivery struct {
	signature string
	body      []byte
}

// webhookDurabilityFixture is an app with no configured ENCRYPTION_KEY, run
// as a dedicated app process (isolated=false: the process environment is
// read, the key is also the process global) or a shared host process.
func webhookDurabilityFixture(t *testing.T, isolated bool) string {
	t.Helper()
	t.Setenv("ENCRYPTION_KEY", "")
	os.Unsetenv("ENCRYPTION_KEY")
	oldIsolation := isolateAppEnvironment.Swap(isolated)
	oldKey, oldEphemeral, oldBlind := appEncryptionKey, appEncryptionKeyEphemeral, appBlindIndexKey.Load()
	t.Cleanup(func() {
		isolateAppEnvironment.Store(oldIsolation)
		appEncryptionKey, appEncryptionKeyEphemeral = oldKey, oldEphemeral
		appBlindIndexKey.Store(oldBlind)
	})
	dir := writeApp(t, map[string]string{
		"app.yaml":   "site_name: Webhook secret durability\n",
		"schema.sql": "CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT);\n",
	})
	dir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dbCryptoRegistry.Delete(canonicalDBPath(filepath.Join(dir, "data.db"))) })
	return dir
}

// forgetProcessKeys drops what a process holds in memory, as a restart does.
func forgetProcessKeys(dir string, isolated bool) {
	dbCryptoRegistry.Delete(canonicalDBPath(filepath.Join(dir, "data.db")))
	if !isolated {
		appEncryptionKey, appEncryptionKeyEphemeral = nil, false
	}
}

// webhookReceiver points every strict outbound connection at a local server
// and returns what it receives.
func webhookReceiver(t *testing.T) chan webhookCapturedDelivery {
	t.Helper()
	got := make(chan webhookCapturedDelivery, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got <- webhookCapturedDelivery{signature: r.Header.Get("X-Webhook-Signature"), body: body}
	}))
	t.Cleanup(srv.Close)
	saved := strictOutboundTransport
	strictOutboundTransport = &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", srv.Listener.Addr().String())
	}}
	t.Cleanup(func() { strictOutboundTransport = saved })
	return got
}

func webhookAPI(t *testing.T, mux *http.ServeMux, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(data)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// verifyWebhookSignature checks a delivery the way a receiver does:
// X-Webhook-Signature t=<ts>,v1=hex(HMAC-SHA256(secret, ts + "." + body)).
func checkSubscriptionSignature(t *testing.T, d webhookCapturedDelivery, secret string) {
	t.Helper()
	var ts, v1 string
	for _, part := range strings.Split(d.signature, ",") {
		k, v, _ := strings.Cut(part, "=")
		switch k {
		case "t":
			ts = v
		case "v1":
			v1 = v
		}
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "."))
	mac.Write(d.body)
	if ts == "" || !hmac.Equal([]byte(v1), []byte(hex.EncodeToString(mac.Sum(nil)))) {
		t.Fatalf("delivery signature %q does not verify with the subscription's secret", d.signature)
	}
}

func webhookJobState(t *testing.T, db *sql.DB, webhookID int64) (status, jobErr string, attempts int) {
	t.Helper()
	if err := db.QueryRow(`SELECT status, COALESCE(error,''), attempts FROM _benmore_jobs
		WHERE job_type='webhook_subscription' AND json_extract(payload,'$._webhook_subscription.webhook_id')=?`, fmt.Sprint(webhookID)).Scan(&status, &jobErr, &attempts); err != nil {
		t.Fatal(err)
	}
	return status, jobErr, attempts
}

// An app without a configured ENCRYPTION_KEY runs on a key generated for the
// process. A subscription secret sealed under it was lost at the next
// restart, so every delivery failed "webhook secret decryption failed" and
// the list still showed `****`. Creating the first subscription now saves the
// generated key to env.yaml, and after a restart deliveries still sign with
// the subscription's secret.
func TestWebhookSubscriptionSecretSurvivesRestartWithoutConfiguredKey(t *testing.T) {
	for _, tc := range []struct {
		name     string
		isolated bool
	}{{"app process", false}, {"shared host", true}} {
		t.Run(tc.name, func(t *testing.T) {
			dir := webhookDurabilityFixture(t, tc.isolated)
			dbPath := filepath.Join(dir, "data.db")
			app, err := startServedApp(dir)
			if err != nil {
				t.Fatal(err)
			}
			if keys := cryptoKeysForDBPath(dbPath); keys == nil || !keys.ephemeral {
				t.Fatal("fixture: the app should start on a generated per-process key")
			}
			if _, err := os.Stat(filepath.Join(dir, "env.yaml")); !os.IsNotExist(err) {
				t.Fatalf("fixture: env.yaml exists before any subscription: %v", err)
			}
			_, token, _ := loginTestUser(app, "owner@example.com", "admin")
			mux := http.NewServeMux()
			RegisterWebhookRoutes(mux, app)
			rec := webhookAPI(t, mux, "POST", "/api/_webhooks", token, map[string]any{
				"url": webhookDurableURL, "secret": webhookDurableSecret, "tables": "notes", "events": "insert",
			})
			if rec.Code != http.StatusCreated {
				t.Fatalf("create subscription = %d %s", rec.Code, rec.Body.String())
			}
			var created struct{ ID int64 }
			json.Unmarshal(rec.Body.Bytes(), &created)

			keys := cryptoKeysForDBPath(dbPath)
			if keys == nil || keys.ephemeral {
				t.Error("the key the secret was sealed under is still per-process")
			}
			envYAML, err := os.ReadFile(filepath.Join(dir, "env.yaml"))
			if err != nil || !bytes.Contains(envYAML, []byte("ENCRYPTION_KEY:")) {
				t.Errorf("the generated key was not saved to env.yaml: %v %q", err, envYAML)
			}
			var stored string
			if err := app.DB.QueryRow("SELECT secret FROM _benmore_webhooks WHERE id=?", created.ID).Scan(&stored); err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(stored, encPrefixV2) || strings.Contains(stored, webhookDurableSecret) {
				t.Fatalf("subscription secret is not sealed at rest: %q", stored)
			}
			var before []byte
			if keys != nil {
				before = append(before, keys.aes...)
			}
			app.Shutdown()

			forgetProcessKeys(dir, tc.isolated)
			restarted, err := startServedApp(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer restarted.Shutdown()
			if keys := cryptoKeysForDBPath(dbPath); keys == nil || keys.ephemeral || !bytes.Equal(keys.aes, before) {
				t.Error("the restarted app did not load the saved key")
			}
			mux = http.NewServeMux()
			RegisterWebhookRoutes(mux, restarted)
			rec = webhookAPI(t, mux, "GET", "/api/_webhooks", token, nil)
			if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"active"`) || !strings.Contains(rec.Body.String(), webhookSecretHint(webhookDurableSecret)) {
				t.Errorf("subscription list after restart = %d %s", rec.Code, rec.Body.String())
			}

			got := webhookReceiver(t)
			EnsureJobsTable(restarted.DB)
			_ = enqueueWebhookSubscriptionsTx(restarted.DB, restarted, "insert", "notes", map[string]any{"id": 1, "title": "after restart"}, nil)
			FlushJobs(restarted)
			select {
			case d := <-got:
				checkSubscriptionSignature(t, d, webhookDurableSecret)
				if !bytes.Contains(d.body, []byte(`"after restart"`)) {
					t.Fatalf("delivery body = %s", d.body)
				}
			case <-time.After(5 * time.Second):
				status, jobErr, _ := webhookJobState(t, restarted.DB, created.ID)
				t.Fatalf("no delivery after restart: job %s %q", status, jobErr)
			}
			if status, jobErr, _ := webhookJobState(t, restarted.DB, created.ID); status != "completed" {
				t.Fatalf("delivery job = %s %q, want completed", status, jobErr)
			}
		})
	}
}

// Where the generated key cannot be made durable, a subscription is refused
// with what to do, and nothing is sealed under a key the restart loses.
func TestWebhookSubscriptionRefusedWithoutDurableKey(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, dir string)
		env   bool // ENCRYPTION_KEY set (empty) in the process environment
	}{
		{name: "env.yaml cannot be written", setup: func(t *testing.T, dir string) {
			if err := os.Mkdir(filepath.Join(dir, "env.yaml"), 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		// The next start reads the process environment over env.yaml, so a
		// key saved there would not be loaded.
		{name: "environment overrides env.yaml", env: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := webhookDurabilityFixture(t, false)
			if tc.env {
				t.Setenv("ENCRYPTION_KEY", "")
			}
			app, err := startServedApp(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer app.Shutdown()
			if tc.setup != nil {
				tc.setup(t, dir)
			}
			_, token, _ := loginTestUser(app, "owner@example.com", "admin")
			mux := http.NewServeMux()
			RegisterWebhookRoutes(mux, app)
			rec := webhookAPI(t, mux, "POST", "/api/_webhooks", token, map[string]any{
				"url": webhookDurableURL, "secret": webhookDurableSecret, "tables": "notes",
			})
			var body map[string]any
			json.Unmarshal(rec.Body.Bytes(), &body)
			if rec.Code != http.StatusServiceUnavailable || body["code"] != "encryption_key_not_durable" || !strings.Contains(valueText(body["error"]), "ENCRYPTION_KEY") {
				t.Fatalf("create without a durable key = %d %s; want 503 encryption_key_not_durable", rec.Code, rec.Body.String())
			}
			var n int
			if err := app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_webhooks").Scan(&n); err != nil || n != 0 {
				t.Fatalf("a refused subscription was stored (%d rows, %v)", n, err)
			}
			if keys := cryptoKeysForDBPath(filepath.Join(dir, "data.db")); keys == nil || !keys.ephemeral {
				t.Fatal("a key that could not be saved was marked durable")
			}
		})
	}
}

// A subscription sealed under a key the app no longer has is listed as
// secret_unreadable with how to fix it, reported at startup, and each of its
// deliveries fails once with that reason instead of retrying; a readable
// subscription next to it is unaffected.
func TestWebhookSubscriptionUnreadableSecretIsReportedAndFailsOnce(t *testing.T) {
	app, done := newTestApp(t)
	defer done()
	EnsureUsersTable(app.DB)
	EnsureSessionsTable(app.DB)
	EnsureWebhooksTable(app.DB)
	EnsureJobsTable(app.DB)
	current, lost := testKeyBytes(0x51), testKeyBytes(0x52)
	dbPath := filepath.Join(app.Dir, "data.db")
	registerDBEncryptionKey(dbPath, current, false)
	t.Cleanup(func() { dbCryptoRegistry.Delete(canonicalDBPath(dbPath)) })
	_, token, adminID := loginTestUser(app, "owner@example.com", "admin")

	readable, err := fieldEncryptWithKey(current, webhookDurableSecret)
	if err != nil {
		t.Fatal(err)
	}
	unreadable, err := fieldEncryptWithKey(lost, "whsec-sealed-under-a-lost-key")
	if err != nil {
		t.Fatal(err)
	}
	insert := func(secret string) int64 {
		res, err := app.DB.Exec("INSERT INTO _benmore_webhooks (user_id, url, secret, tables, events) VALUES (?, ?, ?, 'notes', '')", adminID, webhookDurableURL, secret)
		if err != nil {
			t.Fatal(err)
		}
		id, _ := res.LastInsertId()
		return id
	}
	goodID, lostID := insert(readable), insert(unreadable)

	var logs bytes.Buffer
	log.SetOutput(&logs)
	mux := http.NewServeMux()
	RegisterWebhookRoutes(mux, app)
	log.SetOutput(os.Stderr)
	if !strings.Contains(logs.String(), "1 active subscription(s) (#2)") || !strings.Contains(logs.String(), webhookStatusKeyUnreadable) {
		t.Fatalf("startup did not report the unreadable subscription: %q", logs.String())
	}

	rec := webhookAPI(t, mux, "GET", "/api/_webhooks", token, nil)
	var list struct{ Webhooks []map[string]any }
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &list) != nil {
		t.Fatalf("list = %d %s", rec.Code, rec.Body.String())
	}
	for _, row := range list.Webhooks {
		switch toInt64(row["id"]) {
		case goodID:
			if row["status"] != "active" || row["secret"] != webhookSecretHint(webhookDurableSecret) || row["fix"] != nil {
				t.Errorf("readable subscription listed as %v", row)
			}
		case lostID:
			if row["status"] != webhookStatusKeyUnreadable || row["secret"] != "****" || !strings.Contains(valueText(row["fix"]), "create it again") {
				t.Errorf("unreadable subscription listed as %v", row)
			}
		}
	}

	got := webhookReceiver(t)
	_ = enqueueWebhookSubscriptionsTx(app.DB, app, "insert", "notes", map[string]any{"id": 7, "title": "both"}, nil)
	FlushJobs(app)
	select {
	case d := <-got:
		checkSubscriptionSignature(t, d, webhookDurableSecret)
	case <-time.After(5 * time.Second):
		t.Fatal("the readable subscription was not delivered")
	}
	select {
	case d := <-got:
		t.Fatalf("a delivery went out for the unreadable subscription: %s", d.body)
	default:
	}
	if status, jobErr, attempts := webhookJobState(t, app.DB, lostID); status != "failed" || attempts != 1 || !strings.Contains(jobErr, webhookStatusKeyUnreadable) || !strings.Contains(jobErr, "create it again") {
		t.Fatalf("unreadable delivery = %s after %d attempt(s), error %q; want failed once with the reason", status, attempts, jobErr)
	}
	if status, _, _ := webhookJobState(t, app.DB, goodID); status != "completed" {
		t.Fatalf("readable delivery = %s, want completed", status)
	}
}

// OAuth provider tokens are the other framework secret the app reads back:
// stored under a generated key they were empty to every flow after a
// restart. The first stored token now saves the key, and the token opens
// after the restart.
func TestOAuthTokenSealedUnderGeneratedKeySurvivesRestart(t *testing.T) {
	dir := webhookDurabilityFixture(t, true)
	dbPath := filepath.Join(dir, "data.db")
	const source = "5f3c9a0e1b2d4c6e8f0a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6"
	generated, err := cryptoDeriveAppKey(source)
	if err != nil {
		t.Fatal(err)
	}
	registerDBEncryptionKeySource(dbPath, generated, true, source)
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(dbPath, dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := EnsureUsersTable(db); err != nil {
		t.Fatal(err)
	}
	EnsureOAuthTokensTable(db)
	mustExec(t, db, `INSERT INTO _benmore_users (id, username, email, verified) VALUES (1, 'alice', 'alice@example.com', 1)`)

	StoreOAuthToken(db, 1, "google", "provider-access-token", "provider-refresh-token", "Bearer", 3600, "email")
	vars, err := readAppEnv(dir)
	if err != nil || vars["ENCRYPTION_KEY"] != source {
		t.Fatalf("the generated key was not saved before sealing the token: %v", err)
	}
	forgetProcessKeys(dir, true)
	restarted, err := cryptoDeriveAppKey(vars["ENCRYPTION_KEY"])
	if err != nil {
		t.Fatal(err)
	}
	registerDBEncryptionKey(dbPath, restarted, false)
	if got := GetOAuthToken(db, dir, 1, "google"); got != "provider-access-token" {
		t.Fatalf("token after restart = %q", got)
	}
}
