//go:build !cli

package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	sqlite3 "github.com/mattn/go-sqlite3"
)

func appWebhookJobsDB(t *testing.T) (*sql.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "jobs.db")
	db, err := sql.Open("sqlite3", path+"?_busy_timeout=5000&_txlock=immediate")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	EnsureJobsTable(db)
	return db, path
}

var appWebhookUniqueSequence uint64

func appWebhookInsert(t *testing.T, db *sql.DB, kind, flow, payload, status string) int64 {
	t.Helper()
	res, err := db.Exec("INSERT INTO main._benmore_jobs(job_type,flow_name,payload,status,attempts,max_attempts,error,run_at,started_at,completed_at,status_token,lease_expires_at,unique_key) VALUES(?,?,?,?,7,9,'kept-error','2026-10-03','2026-10-02','2026-10-03','kept-token','2026-10-04',?)", kind, flow, payload, status, fmt.Sprintf("kept-unique-%d", atomic.AddUint64(&appWebhookUniqueSequence, 1)))
	if err != nil {
		t.Fatal(err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// appWebhookLegacyEnqueue writes the job the producer queued before the
// signing secret stopped being copied into it. Such jobs can still sit in a
// queue across an upgrade, so rotation must keep resealing them.
func appWebhookLegacyEnqueue(t *testing.T, db *sql.DB, webhookID, webhookURL, secret, event, table string, row map[string]any) {
	t.Helper()
	data, err := json.Marshal(map[string]any{
		"_webhook_subscription": map[string]any{
			"webhook_id": webhookID,
			"url":        webhookURL,
			"secret":     secret,
			"event":      event,
			"table":      table,
		},
		"_row": row,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(
		"INSERT INTO _benmore_jobs (job_type, flow_name, payload, run_at) VALUES ('webhook_subscription', 'webhook_subscription', ?, datetime('now'))",
		string(data),
	); err != nil {
		t.Fatal(err)
	}
}

func appWebhookPayload(secret string) string {
	b, _ := json.Marshal(secret)
	return "{\"_webhook_subscription\":{\"webhook_id\":\"wh1\",\"url\":\"https://example.test/h\",\"event\":\"update\",\"table\":\"notes\",\"secret\":" + string(b) + "},\"_row\":{\"id\":1}}"
}

func appWebhookLegacyV1(t *testing.T, key []byte, plaintext string) string {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return encPrefix + hex.EncodeToString(sealed)
}

func TestAppWebhookJobRotationNativeProducerLosslessAndRollbackCommit(t *testing.T) {
	db, path := appWebhookJobsDB(t)
	oldKey, newKey := []byte(strings.Repeat("o", 32)), []byte(strings.Repeat("n", 32))
	v1 := appWebhookLegacyV1(t, oldKey, "retained-v1")
	v2, err := fieldEncryptWithKey(oldKey, "retained-v2")
	if err != nil {
		t.Fatal(err)
	}
	// Exercise the actual legacy queue producer, then include another row with
	// JSON formatting and number spellings that a whole-object marshal changes.
	appWebhookRestoreRegistryEntry(t, path)
	processKeyBefore := append([]byte(nil), appEncryptionKey...)
	processBlindPtr := appBlindIndexKey.Load()
	processBlindPresent := processBlindPtr != nil
	var processBlindBefore []byte
	if processBlindPresent {
		processBlindBefore = append([]byte(nil), (*processBlindPtr)...)
	}
	unrelatedPath := filepath.Join(t.TempDir(), "unrelated.db")
	appWebhookRestoreRegistryEntry(t, unrelatedPath)
	unrelatedKey := []byte(strings.Repeat("z", 32))
	RegisterDBEncryptionKey(unrelatedPath, unrelatedKey)
	unrelatedEntry := cryptoKeysForDBPath(unrelatedPath)
	RegisterDBEncryptionKey(path, oldKey)
	if !appWebhookRegistryMatches(path, oldKey) {
		t.Fatal("old test key registration incomplete")
	}
	appWebhookLegacyEnqueue(t, db, "wh1", "https://example.test/h", v1, "update", "notes", map[string]any{"id": 1})
	var id1 int64
	if err := db.QueryRow("SELECT id FROM main._benmore_jobs WHERE job_type='webhook_subscription'").Scan(&id1); err != nil {
		t.Fatal(err)
	}
	ts, body := "1730000000", []byte("{\"event\":\"update\",\"data\":{\"id\":1}}")
	sign := func(secret string) []byte {
		mac := hmac.New(sha256.New, []byte(secret))
		_, _ = mac.Write([]byte(ts + "."))
		_, _ = mac.Write(body)
		return mac.Sum(nil)
	}
	var oldConsumerObj map[string]any
	if err := json.Unmarshal([]byte(appWebhookReadPayload(t, db, id1)), &oldConsumerObj); err != nil {
		t.Fatal(err)
	}
	oldConsumerHook := oldConsumerObj["_webhook_subscription"].(map[string]any)
	oldConsumerPlain, err := fieldDecryptForDB(db, oldConsumerHook["secret"].(string))
	if err != nil || oldConsumerPlain != "retained-v1" {
		t.Fatalf("pre-rotation worker decrypt=%q err=%v", oldConsumerPlain, err)
	}
	oldConsumerMAC := sign(oldConsumerPlain)
	escapedKey := "\\u0073ecret"
	ct, _ := json.Marshal(v2)
	quotedText, _ := json.Marshal("brace } and quote \"inside\"")
	formatted := " { \"_webhook_subscription\" : { \"url\":\"https://example.test/h\", \"event\":\"update\", \"table\":\"notes\", \"" + escapedKey + "\" : " + string(ct) + ", \"user_email\":\"a@example.test\" }, \"_row\" : {\"secret\":\"enc:v1:nested\",\"amount\":1.2300e+09,\"text\":" + string(quotedText) + "} } "
	id2 := appWebhookInsert(t, db, "webhook_subscription", "not-flow-name", formatted, "running")
	id3 := appWebhookInsert(t, db, "webhook_subscription", "completed-flow", appWebhookPayload(v2), "completed")
	id4 := appWebhookInsert(t, db, "webhook_subscription", "failed-flow", appWebhookPayload(v1), "failed")
	otherID := appWebhookInsert(t, db, "flow", "webhook_subscription", "malformed unrelated payload", "failed")
	lookalikeExtraID := appWebhookInsert(t, db, "webhook_subscription_extra", "x", "{bad", "failed")
	mixedCaseID := appWebhookInsert(t, db, "Webhook_Subscription", "x", "{mixed-case is not this consumer", "failed")
	plainID := appWebhookInsert(t, db, "webhook_subscription", "x", appWebhookPayload("plain-secret"), "failed")
	emptyID := appWebhookInsert(t, db, "webhook_subscription", "x", "{\"_webhook_subscription\":{\"url\":\"u\",\"event\":\"e\",\"table\":\"t\",\"secret\":\"\"}}", "completed")
	nullID := appWebhookInsert(t, db, "webhook_subscription", "x", "{\"_webhook_subscription\":{\"url\":\"u\",\"event\":\"e\",\"table\":\"t\",\"secret\":null}}", "pending")
	beforeMeta1, beforeMeta2, beforeMeta3, beforeMeta4 := appWebhookQueueMetadata(t, db, id1), appWebhookQueueMetadata(t, db, id2), appWebhookQueueMetadata(t, db, id3), appWebhookQueueMetadata(t, db, id4)
	before1, before2, before3, before4 := appWebhookReadPayload(t, db, id1), appWebhookReadPayload(t, db, id2), appWebhookReadPayload(t, db, id3), appWebhookReadPayload(t, db, id4)
	plainBefore, emptyBefore, nullBefore := appWebhookReadPayload(t, db, plainID), appWebhookReadPayload(t, db, emptyID), appWebhookReadPayload(t, db, nullID)
	otherBefore := appWebhookReadPayload(t, db, otherID)
	lookalikeBefore, mixedCaseBefore := appWebhookReadPayload(t, db, lookalikeExtraID), appWebhookReadPayload(t, db, mixedCaseID)

	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func(tx *sql.Tx) func() { return func() { _ = tx.Rollback() } }(tx))
	rotations, err := collectAppWebhookJobSecretRotations(context.Background(), tx, oldKey, newKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(rotations) != 4 || rotations[0].id != id1 || rotations[1].id != id2 || rotations[2].id != id3 || rotations[3].id != id4 {
		t.Fatalf("inventory ids=%v", appWebhookRotationIDs(rotations))
	}
	prefixAt := strings.Index(before2, string(ct))
	if prefixAt < 0 || !strings.HasPrefix(rotations[1].replacementPayload, before2[:prefixAt]) || !strings.HasSuffix(rotations[1].replacementPayload, before2[prefixAt+len(ct):]) {
		t.Fatal("rotation changed bytes outside the one secret token")
	}
	count, err := applyAppWebhookJobSecretRotations(context.Background(), tx, rotations)
	if err != nil || count != 4 {
		t.Fatalf("apply count=%d err=%v", count, err)
	}
	if got := appWebhookReadPayloadTx(t, tx, id1); got != rotations[0].replacementPayload {
		t.Fatal("producer payload was not replaced exactly")
	}
	if got := appWebhookReadPayloadTx(t, tx, id2); got != rotations[1].replacementPayload {
		t.Fatal("formatted payload replacement was not exact")
	}
	if appWebhookReadPayloadTx(t, tx, id3) != rotations[2].replacementPayload {
		t.Fatal("completed payload replacement was not exact")
	}
	if appWebhookQueueMetadata(t, tx, id1) != beforeMeta1 || appWebhookQueueMetadata(t, tx, id2) != beforeMeta2 || appWebhookQueueMetadata(t, tx, id3) != beforeMeta3 {
		t.Fatal("queue metadata changed")
	}
	if appWebhookReadPayloadTx(t, tx, otherID) != otherBefore {
		t.Fatal("other job type was changed")
	}
	if appWebhookQueueMetadata(t, tx, id4) != beforeMeta4 {
		t.Fatal("failed job metadata changed")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if appWebhookReadPayload(t, db, id1) != before1 || appWebhookReadPayload(t, db, id2) != before2 || appWebhookReadPayload(t, db, id3) != before3 || appWebhookReadPayload(t, db, id4) != before4 {
		t.Fatal("rollback did not restore exact payload preimages")
	}
	if !appWebhookRegistryMatches(path, oldKey) || cryptoKeysForDBPath(unrelatedPath) != unrelatedEntry || !appWebhookRegistryMatches(unrelatedPath, unrelatedKey) || !bytes.Equal(appEncryptionKey, processKeyBefore) || !appWebhookProcessBlindMatches(processBlindPresent, processBlindBefore) {
		t.Fatal("rollback changed registered or process key state")
	}

	// The committed ciphertext remains consumable through the existing DB-key
	// lookup used by the webhook worker. This test never invokes delivery.
	tx, err = db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func(tx *sql.Tx) func() { return func() { _ = tx.Rollback() } }(tx))
	rotations, err = collectAppWebhookJobSecretRotations(context.Background(), tx, oldKey, newKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = applyAppWebhookJobSecretRotations(context.Background(), tx, rotations); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if !appWebhookRegistryMatches(path, oldKey) || cryptoKeysForDBPath(unrelatedPath) != unrelatedEntry || !appWebhookRegistryMatches(unrelatedPath, unrelatedKey) || !bytes.Equal(appEncryptionKey, processKeyBefore) || !appWebhookProcessBlindMatches(processBlindPresent, processBlindBefore) {
		t.Fatal("commit changed key state before test-owned new-key publication")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	RegisterDBEncryptionKey(path, newKey)
	if !appWebhookRegistryMatches(path, newKey) || cryptoKeysForDBPath(unrelatedPath) != unrelatedEntry || !appWebhookRegistryMatches(unrelatedPath, unrelatedKey) || !bytes.Equal(appEncryptionKey, processKeyBefore) || !appWebhookProcessBlindMatches(processBlindPresent, processBlindBefore) {
		t.Fatal("commit changed unrelated process key state")
	}
	reopened, err := sql.Open("sqlite3", path+"?_busy_timeout=5000&_txlock=immediate")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	committed1, committed2, committed3, committed4 := appWebhookReadPayload(t, reopened, id1), appWebhookReadPayload(t, reopened, id2), appWebhookReadPayload(t, reopened, id3), appWebhookReadPayload(t, reopened, id4)
	committedMeta1, committedMeta2, committedMeta3, committedMeta4 := appWebhookQueueMetadata(t, reopened, id1), appWebhookQueueMetadata(t, reopened, id2), appWebhookQueueMetadata(t, reopened, id3), appWebhookQueueMetadata(t, reopened, id4)
	oldRetry, err := reopened.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func(tx *sql.Tx) func() { return func() { _ = tx.Rollback() } }(oldRetry))
	if _, err := collectAppWebhookJobSecretRotations(context.Background(), oldRetry, oldKey, newKey); err == nil {
		t.Fatal("obsolete key retry accepted committed payloads")
	}
	if appWebhookReadPayloadTx(t, oldRetry, id1) != committed1 || appWebhookReadPayloadTx(t, oldRetry, id2) != committed2 || appWebhookReadPayloadTx(t, oldRetry, id3) != committed3 || appWebhookReadPayloadTx(t, oldRetry, id4) != committed4 {
		t.Fatal("obsolete-key refusal changed committed payloads")
	}
	if appWebhookQueueMetadata(t, oldRetry, id1) != committedMeta1 || appWebhookQueueMetadata(t, oldRetry, id2) != committedMeta2 || appWebhookQueueMetadata(t, oldRetry, id3) != committedMeta3 || appWebhookQueueMetadata(t, oldRetry, id4) != committedMeta4 {
		t.Fatal("obsolete-key refusal changed queue metadata")
	}
	_ = oldRetry.Rollback()
	var obj map[string]any
	if err := json.Unmarshal([]byte(appWebhookReadPayload(t, reopened, id1)), &obj); err != nil {
		t.Fatal(err)
	}
	hook := obj["_webhook_subscription"].(map[string]any)
	plain, err := fieldDecryptForDB(reopened, hook["secret"].(string))
	if err != nil || plain != "retained-v1" {
		t.Fatalf("worker decrypt=%q err=%v", plain, err)
	}
	var obj2 map[string]any
	if err := json.Unmarshal([]byte(committed2), &obj2); err != nil {
		t.Fatal(err)
	}
	hook2 := obj2["_webhook_subscription"].(map[string]any)
	plain2, err := fieldDecryptForDB(reopened, hook2["secret"].(string))
	if err != nil || plain2 != "retained-v2" {
		t.Fatalf("second worker decrypt=%q err=%v", plain2, err)
	}
	if _, err := fieldDecryptCtx(oldKey, "", hook["secret"].(string)); err == nil {
		t.Fatal("old key decrypted committed payload")
	}
	if appWebhookReadPayload(t, reopened, otherID) != otherBefore || appWebhookReadPayload(t, reopened, lookalikeExtraID) != lookalikeBefore || appWebhookReadPayload(t, reopened, mixedCaseID) != mixedCaseBefore || appWebhookReadPayload(t, reopened, plainID) != plainBefore || appWebhookReadPayload(t, reopened, emptyID) != emptyBefore || appWebhookReadPayload(t, reopened, nullID) != nullBefore {
		t.Fatal("unselected or nonencrypted job payload changed")
	}
	if plain != oldConsumerPlain || !hmac.Equal(sign(plain), oldConsumerMAC) {
		t.Fatal("worker plaintext or fixed-body HMAC changed across rotation")
	}
}

func TestAppWebhookJobRotationCollectionRefusesMalformedLaterRowBeforeWrites(t *testing.T) {
	db, _ := appWebhookJobsDB(t)
	oldKey, newKey := []byte(strings.Repeat("a", 32)), []byte(strings.Repeat("b", 32))
	ct := appWebhookLegacyV1(t, oldKey, "secret")
	id := appWebhookInsert(t, db, "webhook_subscription", "x", appWebhookPayload(ct), "pending")
	bad := "{\"_webhook_subscription\":{\"url\":\"u\",\"event\":\"e\",\"table\":\"t\",\"secret\":\"plain\"},\"unknown\":{\"a\":1,\"a\":2}}"
	appWebhookInsert(t, db, "webhook_subscription", "x", bad, "failed")
	before := appWebhookReadPayload(t, db, id)
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func(tx *sql.Tx) func() { return func() { _ = tx.Rollback() } }(tx))
	if _, err := collectAppWebhookJobSecretRotations(context.Background(), tx, oldKey, newKey); err == nil {
		t.Fatal("malformed last selected payload was accepted")
	}
	if got := appWebhookReadPayloadTx(t, tx, id); got != before {
		t.Fatal("failed inventory changed earlier row")
	}
	_ = tx.Rollback()
}

func TestAppWebhookJobRotationRejectsNullAndBlobPayloadRowsBeforeWrites(t *testing.T) {
	for _, payloadSQL := range []string{"NULL", "CAST('not text' AS BLOB)"} {
		t.Run(payloadSQL, func(t *testing.T) {
			db, _ := appWebhookJobsDB(t)
			oldKey, newKey := []byte(strings.Repeat("m", 32)), []byte(strings.Repeat("q", 32))
			id := appWebhookInsert(t, db, "webhook_subscription", "x", appWebhookPayload(appWebhookLegacyV1(t, oldKey, "secret")), "pending")
			if _, err := db.Exec("INSERT INTO main._benmore_jobs(job_type,flow_name,payload) VALUES('webhook_subscription','x'," + payloadSQL + ")"); err != nil {
				t.Fatal(err)
			}
			before := appWebhookReadPayload(t, db, id)
			tx, err := db.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func(tx *sql.Tx) func() { return func() { _ = tx.Rollback() } }(tx))
			if _, err := collectAppWebhookJobSecretRotations(context.Background(), tx, oldKey, newKey); err == nil {
				t.Fatal("non-TEXT selected payload was accepted")
			}
			if got := appWebhookReadPayloadTx(t, tx, id); got != before {
				t.Fatal("invalid later payload changed earlier row")
			}
			_ = tx.Rollback()
		})
	}
}

func TestAppWebhookJobRotationCASRejectsEquivalentChangedImage(t *testing.T) {
	db, _ := appWebhookJobsDB(t)
	oldKey, newKey := []byte(strings.Repeat("c", 32)), []byte(strings.Repeat("d", 32))
	ct := appWebhookLegacyV1(t, oldKey, "secret")
	id := appWebhookInsert(t, db, "webhook_subscription", "x", appWebhookPayload(ct), "running")
	before := appWebhookReadPayload(t, db, id)
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func(tx *sql.Tx) func() { return func() { _ = tx.Rollback() } }(tx))
	rows, err := collectAppWebhookJobSecretRotations(context.Background(), tx, oldKey, newKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec("UPDATE main._benmore_jobs SET payload=payload||' ' WHERE id=?", id); err != nil {
		t.Fatal(err)
	}
	if _, err := applyAppWebhookJobSecretRotations(context.Background(), tx, rows); err == nil {
		t.Fatal("stale byte-different JSON image was overwritten")
	}
	_ = tx.Rollback()
	if got := appWebhookReadPayload(t, db, id); got != before {
		t.Fatal("failed CAS changed persisted source")
	}

	for _, mutation := range []string{"UPDATE main._benmore_jobs SET job_type='flow' WHERE id=?", "DELETE FROM main._benmore_jobs WHERE id=?"} {
		tx, err = db.BeginTx(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func(tx *sql.Tx) func() { return func() { _ = tx.Rollback() } }(tx))
		rows, err = collectAppWebhookJobSecretRotations(context.Background(), tx, oldKey, newKey)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(mutation, id); err != nil {
			t.Fatal(err)
		}
		if _, err := applyAppWebhookJobSecretRotations(context.Background(), tx, rows); err == nil {
			t.Fatalf("CAS accepted mutation %q", mutation)
		}
		_ = tx.Rollback()
		if got := appWebhookReadPayload(t, db, id); got != before {
			t.Fatal("failed CAS mutation escaped rollback")
		}
	}
	if _, err := db.Exec("DELETE FROM main._benmore_jobs WHERE id=?", id); err != nil {
		t.Fatal(err)
	}

	// The first real payload write is visible inside the outer transaction;
	// a stale later image fails and rollback restores both persisted preimages.
	firstID := appWebhookInsert(t, db, "webhook_subscription", "x", appWebhookPayload(appWebhookLegacyV1(t, oldKey, "first")), "pending")
	secondID := appWebhookInsert(t, db, "webhook_subscription", "x", appWebhookPayload(appWebhookLegacyV1(t, oldKey, "second")), "pending")
	firstBefore, secondBefore := appWebhookReadPayload(t, db, firstID), appWebhookReadPayload(t, db, secondID)
	tx, err = db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func(tx *sql.Tx) func() { return func() { _ = tx.Rollback() } }(tx))
	rows, err = collectAppWebhookJobSecretRotations(context.Background(), tx, oldKey, newKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("two-row inventory count=%d", len(rows))
	}
	if _, err := tx.Exec("UPDATE main._benmore_jobs SET payload=payload||' ' WHERE id=?", secondID); err != nil {
		t.Fatal(err)
	}
	if count, err := applyAppWebhookJobSecretRotations(context.Background(), tx, rows); err == nil || count != 0 {
		t.Fatalf("stale-later apply count=%d err=%v", count, err)
	}
	if got := appWebhookReadPayloadTx(t, tx, firstID); got != rows[0].replacementPayload {
		t.Fatal("first CAS was not visible in outer transaction")
	}
	if got := appWebhookReadPayloadTx(t, tx, secondID); got == secondBefore {
		t.Fatal("test did not create a changed later source image")
	}
	_ = tx.Rollback()
	if appWebhookReadPayload(t, db, firstID) != firstBefore || appWebhookReadPayload(t, db, secondID) != secondBefore {
		t.Fatal("rollback failed to restore the partially applied transaction")
	}
	tx, err = db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func(tx *sql.Tx) func() { return func() { _ = tx.Rollback() } }(tx))
	rows, err = collectAppWebhookJobSecretRotations(context.Background(), tx, oldKey, newKey)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := casAppWebhookJobSecretRotation(ctx, tx, rows[0]); err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, err := applyAppWebhookJobSecretRotations(ctx, tx, rows[1:]); !errors.Is(err, context.Canceled) {
		t.Fatalf("post-write cancellation error=%v", err)
	}
	if appWebhookReadPayloadTx(t, tx, firstID) != rows[0].replacementPayload {
		t.Fatal("first write not visible before cancellation rollback")
	}
	_ = tx.Rollback()
	if appWebhookReadPayload(t, db, firstID) != firstBefore || appWebhookReadPayload(t, db, secondID) != secondBefore {
		t.Fatal("cancellation rollback did not restore payloads")
	}
}

func TestAppWebhookJobRotationRequiresCleanConnectionAndTriggerFreeMain(t *testing.T) {
	db, _ := appWebhookJobsDB(t)
	oldKey, newKey := []byte(strings.Repeat("e", 32)), []byte(strings.Repeat("f", 32))
	ct := appWebhookLegacyV1(t, oldKey, "secret")
	appWebhookInsert(t, db, "webhook_subscription", "x", appWebhookPayload(ct), "pending")
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := conn.ExecContext(context.Background(), "ATTACH DATABASE ':memory:' AS decoy"); err != nil {
		t.Fatal(err)
	}
	tx, err := conn.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func(tx *sql.Tx) func() { return func() { _ = tx.Rollback() } }(tx))
	if _, err := collectAppWebhookJobSecretRotations(context.Background(), tx, oldKey, newKey); err == nil {
		t.Fatal("attached database was accepted")
	}
	_ = tx.Rollback()
	if _, err := conn.ExecContext(context.Background(), "DETACH DATABASE decoy"); err != nil {
		t.Fatal(err)
	}
	appWebhookAssertCleanFollowup(t, conn, oldKey, newKey)
	if _, err := conn.ExecContext(context.Background(), "CREATE TEMP TABLE tmp_guard(x)"); err != nil {
		t.Fatal(err)
	}
	tx, err = conn.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func(tx *sql.Tx) func() { return func() { _ = tx.Rollback() } }(tx))
	if _, err := collectAppWebhookJobSecretRotations(context.Background(), tx, oldKey, newKey); err == nil {
		t.Fatal("temporary schema was accepted")
	}
	_ = tx.Rollback()
	if _, err := conn.ExecContext(context.Background(), "DROP TABLE temp.tmp_guard"); err != nil {
		t.Fatal(err)
	}
	appWebhookAssertCleanFollowup(t, conn, oldKey, newKey)
	var before string
	if err := conn.QueryRowContext(context.Background(), "SELECT payload FROM main._benmore_jobs WHERE id=1").Scan(&before); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(context.Background(), "CREATE TABLE main.job_observer(id INTEGER)"); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(context.Background(), "CREATE TRIGGER job_guard AFTER UPDATE ON _benmore_jobs BEGIN INSERT INTO job_observer VALUES(new.id); END"); err != nil {
		t.Fatal(err)
	}
	tx, err = conn.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func(tx *sql.Tx) func() { return func() { _ = tx.Rollback() } }(tx))
	if _, err := collectAppWebhookJobSecretRotations(context.Background(), tx, oldKey, newKey); err == nil {
		t.Fatal("main trigger was accepted")
	}
	var observerRows int
	if err := tx.QueryRow("SELECT count(*) FROM main.job_observer").Scan(&observerRows); err != nil || observerRows != 0 {
		t.Fatalf("refused trigger fired observer rows=%d err=%v", observerRows, err)
	}
	if got := appWebhookReadPayloadTx(t, tx, 1); got != before {
		t.Fatal("trigger refusal changed payload before rollback")
	}
	_ = tx.Rollback()
	tx, err = conn.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func(tx *sql.Tx) func() { return func() { _ = tx.Rollback() } }(tx))
	if _, err := tx.Exec("DROP TRIGGER job_guard"); err != nil {
		t.Fatal(err)
	}
	rows, err := collectAppWebhookJobSecretRotations(context.Background(), tx, oldKey, newKey)
	if err != nil {
		t.Fatalf("transaction-local trigger suspension inventory: %v", err)
	}
	if _, err := applyAppWebhookJobSecretRotations(context.Background(), tx, rows); err != nil {
		t.Fatalf("transaction-local trigger suspension apply: %v", err)
	}
	_ = tx.Rollback()
	var triggerCount int
	if err := conn.QueryRowContext(context.Background(), "SELECT count(*) FROM main.sqlite_schema WHERE type='trigger' AND name='job_guard'").Scan(&triggerCount); err != nil || triggerCount != 1 {
		t.Fatalf("rollback did not restore trigger count=%d err=%v", triggerCount, err)
	}
	var observerAfter int
	if err := conn.QueryRowContext(context.Background(), "SELECT count(*) FROM main.job_observer").Scan(&observerAfter); err != nil || observerAfter != 0 {
		t.Fatalf("rollback observer rows=%d err=%v", observerAfter, err)
	}
	var after string
	if err := conn.QueryRowContext(context.Background(), "SELECT payload FROM main._benmore_jobs WHERE id=1").Scan(&after); err != nil || after != before {
		t.Fatalf("trigger suspension rollback payload restored=%v err=%v", after == before, err)
	}
}

func TestAppWebhookJobRotationSQLAuthorizerDenialIsAWriteError(t *testing.T) {
	db, _ := appWebhookJobsDB(t)
	oldKey, newKey := []byte(strings.Repeat("k", 32)), []byte(strings.Repeat("l", 32))
	id := appWebhookInsert(t, db, "webhook_subscription", "x", appWebhookPayload(appWebhookLegacyV1(t, oldKey, "secret")), "pending")
	before := appWebhookReadPayload(t, db, id)
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.Raw(func(raw any) error {
		sqlite, ok := raw.(*sqlite3.SQLiteConn)
		if !ok {
			return errors.New("not a SQLite connection")
		}
		sqlite.RegisterAuthorizer(func(action int, arg1, arg2, database string) int {
			if action == sqlite3.SQLITE_UPDATE && arg1 == "_benmore_jobs" && arg2 == "payload" {
				return sqlite3.SQLITE_DENY
			}
			return sqlite3.SQLITE_OK
		})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := conn.Raw(func(raw any) error {
			sqlite, ok := raw.(*sqlite3.SQLiteConn)
			if !ok {
				return errors.New("not a SQLite connection")
			}
			sqlite.RegisterAuthorizer(nil)
			return nil
		}); err != nil {
			t.Errorf("authorizer cleanup: %v", err)
		}
	})
	tx, err := conn.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func(tx *sql.Tx) func() { return func() { _ = tx.Rollback() } }(tx))
	rows, err := collectAppWebhookJobSecretRotations(context.Background(), tx, oldKey, newKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := applyAppWebhookJobSecretRotations(context.Background(), tx, rows); err == nil || err.Error() != "webhook rotation compare-and-swap failed" {
		t.Fatalf("authorizer failure was not distinguished from zero-row CAS: %v", err)
	}
	_ = tx.Rollback()
	if err := conn.Raw(func(raw any) error { raw.(*sqlite3.SQLiteConn).RegisterAuthorizer(nil); return nil }); err != nil {
		t.Fatal(err)
	}
	var after string
	if err := conn.QueryRowContext(context.Background(), "SELECT payload FROM main._benmore_jobs WHERE id=?", id).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatal("authorizer-refused write changed persisted payload")
	}
	followup, err := conn.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer followup.Rollback()
	rows, err = collectAppWebhookJobSecretRotations(context.Background(), followup, oldKey, newKey)
	if err != nil {
		t.Fatalf("authorizer reset inventory: %v", err)
	}
	if count, err := applyAppWebhookJobSecretRotations(context.Background(), followup, rows); err != nil || count != 1 {
		t.Fatalf("authorizer reset follow-up apply count=%d err=%v", count, err)
	}
}

func TestAppWebhookJobRotationPayloadParserRejectsAliasesBoundsAndInvalidEnvelope(t *testing.T) {
	oldKey, newKey := []byte(strings.Repeat("g", 32)), []byte(strings.Repeat("h", 32))
	encrypted := appWebhookLegacyV1(t, oldKey, "x")
	wrongAAD, err := fieldEncryptCtx(oldKey, "webhooks", "secret", "wrong context")
	if err != nil {
		t.Fatal(err)
	}
	inputs := []string{
		"{\"_webhook_subscription\":{\"url\":\"u\",\"event\":\"e\",\"table\":\"t\",\"secret\":\"plain\"},\"_row\":{\"x\":1,\"x\":2}}",
		"{\"_webhook_subscription\":{\"url\":\"u\",\"event\":\"e\",\"table\":\"t\",\"secret\":\"plain\",\"\\u0073ecret\":\"other\"}}",
		"{\"_webhook_subscription\":{\"url\":\"u\",\"event\":\"e\",\"table\":\"t\",\"secret\":" + mustWebhookJSON(t, wrongAAD) + "}}",
		"{\"_webhook_subscription\":{\"url\":\"u\",\"event\":\"e\",\"table\":\"t\",\"secret\":\"plain\"},\"_webhook_subscription\":{\"url\":\"u\",\"event\":\"e\",\"table\":\"t\",\"secret\":\"plain\"}}",
		"{\"_webhook_subscription\":{\"url\":\"u\",\"event\":\"e\",\"table\":\"t\",\"secret\":\"enc:v9:bad\"}}",
		"{\"_webhook_subscription\":{\"url\":\"u\",\"event\":\"e\",\"table\":\"t\",\"secret\":\"enc:v1:bad\"}}",
		"{\"_webhook_subscription\":{\"url\":\"u\",\"event\":\"e\",\"table\":\"t\",\"secret\":\"plain\"}} trailing",
		"{\"_webhook_subscription\":{\"url\":\"u\",\"event\":\"e\",\"table\":\"t\",\"secret\":\"plain\\ud800\"}}",
		`{"_row":{}}`,
		`{"_webhook_subscription":[]}`,
		`{"_webhook_subscription":{"url":"u","event":"e","table":"t"}}`,
		`{"_webhook_subscription":{"url":"u","event":"e","table":"t","secret":7}}`,
		`{"_webhook_subscription":{"url":"u","event":"e","table":"t","secret":[]}}`,
		`{"_webhook_subscription":{"url":"u","event":"e","table":"t","secret":{}}}`,
	}
	for i, payload := range inputs {
		if _, _, err := appWebhookJobResealPayload(payload, oldKey, newKey); err == nil {
			t.Fatalf("invalid fixture %d accepted", i)
		}
	}
	for _, payload := range []string{appWebhookPayload("plain"), appWebhookPayload(""), `{"_webhook_subscription":{"url":"u","event":"e","table":"t","secret":null}}`, `{"_webhook_subscription":{"url":"u","event":"e","table":"t","secret":"rocket \ud83d\ude80"}}`, `{"_webhook_subscription":{"url":"u","event":"e","table":"t","secret":"plain\\slash\"quote"}}`} {
		got, changed, err := appWebhookJobResealPayload(payload, oldKey, newKey)
		if err != nil || changed || got != payload {
			t.Fatalf("valid fixed path/secret boundary changed=%v err=%v", changed, err)
		}
	}
	valid := " \n" + appWebhookPayload(encrypted) + " \t"
	if _, changed, err := appWebhookJobResealPayload(valid, oldKey, newKey); err != nil || !changed {
		t.Fatalf("leading/trailing whitespace changed=%v err=%v", changed, err)
	}
	if _, _, err := appWebhookJobResealPayload(strings.Repeat(" ", appWebhookJobPayloadLimit+1), oldKey, newKey); err == nil {
		t.Fatal("oversized payload accepted")
	}
}

func TestAppWebhookJobRotationCanceledContextRefusesInventory(t *testing.T) {
	db, _ := appWebhookJobsDB(t)
	oldKey, newKey := []byte(strings.Repeat("i", 32)), []byte(strings.Repeat("j", 32))
	appWebhookInsert(t, db, "webhook_subscription", "x", appWebhookPayload(appWebhookLegacyV1(t, oldKey, "secret")), "pending")
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func(tx *sql.Tx) func() { return func() { _ = tx.Rollback() } }(tx))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := collectAppWebhookJobSecretRotations(ctx, tx, oldKey, newKey); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled inventory error=%v", err)
	}
	_ = tx.Rollback()
}

func TestAppWebhookJobRotationMissingTableIsNoWorkAndViewIsRejected(t *testing.T) {
	oldKey, newKey := []byte(strings.Repeat("r", 32)), []byte(strings.Repeat("s", 32))
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "absent.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(1)
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func(tx *sql.Tx) func() { return func() { _ = tx.Rollback() } }(tx))
	rows, err := collectAppWebhookJobSecretRotations(context.Background(), tx, oldKey, newKey)
	if err != nil || len(rows) != 0 {
		t.Fatalf("absent table result=%d err=%v", len(rows), err)
	}
	_ = tx.Rollback()
	if _, err := db.Exec("CREATE VIEW main._benmore_jobs AS SELECT 1 AS id, 'webhook_subscription' AS job_type, '{}' AS payload"); err != nil {
		t.Fatal(err)
	}
	tx, err = db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func(tx *sql.Tx) func() { return func() { _ = tx.Rollback() } }(tx))
	if _, err := collectAppWebhookJobSecretRotations(context.Background(), tx, oldKey, newKey); err == nil {
		t.Fatal("reserved-name view was accepted as a native queue table")
	}
	_ = tx.Rollback()
	fixtures := map[string]struct {
		statements []string
		wantErr    string
	}{
		"generated":             {[]string{"CREATE TABLE main._benmore_jobs(id INTEGER PRIMARY KEY,job_type TEXT NOT NULL,payload TEXT,computed TEXT GENERATED ALWAYS AS (job_type) VIRTUAL)"}, "unsupported generated job column"},
		"without-rowid":         {[]string{"CREATE TABLE main._benmore_jobs(id TEXT PRIMARY KEY,job_type TEXT NOT NULL,payload TEXT) WITHOUT ROWID"}, "incompatible webhook jobs schema"},
		"incompatible-id":       {[]string{"CREATE TABLE main._benmore_jobs(id TEXT PRIMARY KEY,job_type TEXT NOT NULL,payload TEXT)"}, "incompatible webhook jobs schema"},
		"incompatible-job-type": {[]string{"CREATE TABLE main._benmore_jobs(id INTEGER PRIMARY KEY,job_type INTEGER NOT NULL,payload TEXT)"}, "incompatible webhook jobs schema"},
		"incompatible-payload":  {[]string{"CREATE TABLE main._benmore_jobs(id INTEGER PRIMARY KEY,job_type TEXT NOT NULL,payload BLOB)"}, "incompatible webhook jobs schema"},
		"inbound-payload-fk":    {[]string{"CREATE TABLE main._benmore_jobs(id INTEGER PRIMARY KEY,job_type TEXT NOT NULL,payload TEXT UNIQUE)", "CREATE TABLE main.other_queue_ref(value TEXT REFERENCES _benmore_jobs(payload))"}, "unsupported webhook payload relationship"},
		"outbound-payload-fk":   {[]string{"CREATE TABLE main.parent(id TEXT PRIMARY KEY)", "CREATE TABLE main._benmore_jobs(id INTEGER PRIMARY KEY,job_type TEXT NOT NULL,payload TEXT REFERENCES parent(id))"}, "unsupported webhook payload relationship"},
	}
	for name, fixture := range fixtures {
		for _, populated := range []bool{false, true} {
			label := "empty"
			if populated {
				label = "populated"
			}
			t.Run(name+"/"+label, func(t *testing.T) {
				db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "schema.db"))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = db.Close() })
				db.SetMaxOpenConns(1)
				if _, err := db.Exec("PRAGMA foreign_keys=ON"); err != nil {
					t.Fatal(err)
				}
				for _, statement := range fixture.statements {
					if _, err := db.Exec(statement); err != nil {
						t.Fatal(err)
					}
				}
				key := []byte(strings.Repeat("j", 32))
				payload := appWebhookPayload(appWebhookLegacyV1(t, key, "schema-valid-secret"))
				if populated {
					if name == "outbound-payload-fk" {
						if _, err := db.Exec("INSERT INTO main.parent(id) VALUES(?)", payload); err != nil {
							t.Fatal(err)
						}
					}
					if _, err := db.Exec("INSERT INTO main._benmore_jobs(id,job_type,payload) VALUES(1,'webhook_subscription',?)", payload); err != nil {
						t.Fatal(err)
					}
				}
				tx, err := db.BeginTx(context.Background(), nil)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback()
				if _, err := collectAppWebhookJobSecretRotations(context.Background(), tx, key, []byte(strings.Repeat("k", 32))); err == nil || err.Error() != fixture.wantErr {
					t.Fatalf("schema refusal got=%v want=%q", err, fixture.wantErr)
				}
			})
		}
	}
	// The same encrypted payload is accepted by a supported physical queue.
	positiveDB, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "supported.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = positiveDB.Close() })
	positiveDB.SetMaxOpenConns(1)
	if _, err := positiveDB.Exec(`CREATE TABLE main._benmore_jobs(id INTEGER PRIMARY KEY,job_type TEXT NOT NULL,payload TEXT)`); err != nil {
		t.Fatal(err)
	}
	positiveKey := []byte(strings.Repeat("j", 32))
	positivePayload := appWebhookPayload(appWebhookLegacyV1(t, positiveKey, "schema-valid-secret"))
	if _, err := positiveDB.Exec(`INSERT INTO main._benmore_jobs(job_type,payload) VALUES('webhook_subscription',?)`, positivePayload); err != nil {
		t.Fatal(err)
	}
	positiveTx, err := positiveDB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer positiveTx.Rollback()
	positiveRows, err := collectAppWebhookJobSecretRotations(context.Background(), positiveTx, positiveKey, []byte(strings.Repeat("k", 32)))
	if err != nil || len(positiveRows) != 1 {
		t.Fatalf("supported schema control rows=%d err=%v", len(positiveRows), err)
	}
	if n, err := applyAppWebhookJobSecretRotations(context.Background(), positiveTx, positiveRows); err != nil || n != 1 {
		t.Fatalf("supported schema apply=%d err=%v", n, err)
	}
	// Discover an FTS module from the actual SQLite build instead of assuming one.
	virtualDB, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "virtual.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = virtualDB.Close() })
	virtualDB.SetMaxOpenConns(1)
	modules, err := virtualDB.Query("PRAGMA module_list")
	if err != nil {
		t.Skipf("SQLite module inventory unavailable: %v", err)
	}
	module := ""
	for modules.Next() {
		var candidate string
		if err := modules.Scan(&candidate); err != nil {
			modules.Close()
			t.Fatal(err)
		}
		if candidate == "fts4" || candidate == "fts3" || candidate == "fts5" {
			module = candidate
			break
		}
	}
	if err := modules.Close(); err != nil {
		t.Fatal(err)
	}
	if module == "" {
		t.Skip("native SQLite build exposes no FTS virtual-table module")
	}
	for _, populated := range []bool{false, true} {
		label := "empty"
		if populated {
			label = "populated"
		}
		t.Run("virtual/"+label, func(t *testing.T) {
			db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "virtual.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = db.Close() })
			db.SetMaxOpenConns(1)
			if _, err := db.Exec("CREATE VIRTUAL TABLE main._benmore_jobs USING " + module + "(id,job_type,payload)"); err != nil {
				t.Fatal(err)
			}
			key := []byte(strings.Repeat("j", 32))
			payload := appWebhookPayload(appWebhookLegacyV1(t, key, "schema-valid-secret"))
			if populated {
				if _, err := db.Exec("INSERT INTO main._benmore_jobs(id,job_type,payload) VALUES('1','webhook_subscription',?)", payload); err != nil {
					t.Fatal(err)
				}
			}
			tx, err := db.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if _, err := collectAppWebhookJobSecretRotations(context.Background(), tx, key, []byte(strings.Repeat("k", 32))); err == nil || err.Error() != "incompatible webhook jobs schema" {
				t.Fatalf("virtual schema refusal=%v", err)
			}
		})
	}

}

func TestAppWebhookJobRotationSelectionUsesBinaryJobType(t *testing.T) {
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "nocase.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(1)
	if _, err := db.Exec("CREATE TABLE main._benmore_jobs(id INTEGER PRIMARY KEY,job_type TEXT COLLATE NOCASE NOT NULL,payload TEXT,status TEXT)"); err != nil {
		t.Fatal(err)
	}
	oldKey, newKey := []byte(strings.Repeat("u", 32)), []byte(strings.Repeat("v", 32))
	ciphertext := appWebhookLegacyV1(t, oldKey, "secret")
	if _, err := db.Exec("INSERT INTO main._benmore_jobs(job_type,payload) VALUES('Webhook_Subscription','malformed unrelated case')"); err != nil {
		t.Fatal(err)
	}
	res, err := db.Exec("INSERT INTO main._benmore_jobs(job_type,payload) VALUES('webhook_subscription',?)", appWebhookPayload(ciphertext))
	if err != nil {
		t.Fatal(err)
	}
	wantedID, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func(tx *sql.Tx) func() { return func() { _ = tx.Rollback() } }(tx))
	rows, err := collectAppWebhookJobSecretRotations(context.Background(), tx, oldKey, newKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].id != wantedID {
		t.Fatalf("BINARY-selected inventory=%v", appWebhookRotationIDs(rows))
	}
	if count, err := applyAppWebhookJobSecretRotations(context.Background(), tx, rows); err != nil || count != 1 {
		t.Fatalf("BINARY CAS count=%d err=%v", count, err)
	}
	_ = tx.Rollback()
}

func appWebhookReadPayload(t *testing.T, db *sql.DB, id int64) string {
	t.Helper()
	var s string
	if err := db.QueryRow("SELECT payload FROM main._benmore_jobs WHERE id=?", id).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}
func appWebhookReadPayloadTx(t *testing.T, tx *sql.Tx, id int64) string {
	t.Helper()
	var s string
	if err := tx.QueryRow("SELECT payload FROM main._benmore_jobs WHERE id=?", id).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}
func appWebhookQueueMetadata(t *testing.T, q interface{ QueryRow(string, ...any) *sql.Row }, id int64) string {
	t.Helper()
	var rowID, jobType, flow, status, errorText, runAt, notBefore, started, completed, createdAt, statusToken, lease, unique string
	var attempts, maxAttempts int
	err := q.QueryRow("SELECT CAST(id AS TEXT),job_type,flow_name,status,COALESCE(error,''),COALESCE(run_at,''),COALESCE(not_before,''),COALESCE(started_at,''),COALESCE(completed_at,''),COALESCE(created_at,''),COALESCE(status_token,''),COALESCE(lease_expires_at,''),COALESCE(unique_key,''),attempts,max_attempts FROM main._benmore_jobs WHERE id=?", id).Scan(&rowID, &jobType, &flow, &status, &errorText, &runAt, &notBefore, &started, &completed, &createdAt, &statusToken, &lease, &unique, &attempts, &maxAttempts)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Join([]string{rowID, jobType, flow, status, errorText, runAt, notBefore, started, completed, createdAt, statusToken, lease, unique, strconv.Itoa(attempts), strconv.Itoa(maxAttempts)}, "|")
}
func appWebhookRotationIDs(rows []appWebhookJobSecretRotation) []int64 {
	out := make([]int64, len(rows))
	for i, r := range rows {
		out[i] = r.id
	}
	return out
}
func mustWebhookJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestAppWebhookJobRotationPreservesUnknownLargeNumbersAndRequiresStringFields(t *testing.T) {
	oldKey, newKey := []byte(strings.Repeat("x", 32)), []byte(strings.Repeat("y", 32))
	secret := appWebhookLegacyV1(t, oldKey, "numeric-control")
	payload := `{"_webhook_subscription":{"url":"u","event":"e","table":"t","secret":` + mustWebhookJSON(t, secret) + `},"unknown":1e400,"large":1234567890123456789012345678901234567890}`
	replaced, changed, err := appWebhookJobResealPayload(payload, oldKey, newKey)
	token := mustWebhookJSON(t, secret)
	at := strings.Index(payload, token)
	if err != nil || !changed || at < 0 || !strings.HasPrefix(replaced, payload[:at]) || !strings.HasSuffix(replaced, payload[at+len(token):]) {
		t.Fatalf("large JSON numbers were not preserved: changed=%v err=%v", changed, err)
	}
	for _, field := range []string{"url", "event", "table", "webhook_id"} {
		positive := `{"_webhook_subscription":{"url":"u","event":"e","table":"t","secret":"plain","webhook_id":"wh1"}}`
		bad := positive
		if field == "webhook_id" {
			bad = strings.Replace(positive, `"webhook_id":"wh1"`, `"webhook_id":null`, 1)
		} else {
			value := map[string]string{"url": "u", "event": "e", "table": "t"}[field]
			bad = strings.Replace(positive, `"`+field+`":"`+value+`"`, `"`+field+`":null`, 1)
		}
		if bad == positive {
			t.Fatalf("null fixture did not replace %s", field)
		}
		if _, _, err := appWebhookJobResealPayload(positive, oldKey, newKey); err != nil {
			t.Fatalf("actual string field %s rejected: %v", field, err)
		}
		_, _, err = appWebhookJobResealPayload(bad, oldKey, newKey)
		if field == "webhook_id" {
			if err == nil || err.Error() != "invalid webhook id" {
				t.Fatalf("JSON null webhook_id error=%v", err)
			}
		} else if err == nil || err.Error() != "invalid webhook field" {
			t.Fatalf("JSON null string field %s error=%v", field, err)
		}
	}
	for _, row := range []string{`"scalar"`, `[]`, `1`, `false`} {
		bad := `{"_webhook_subscription":{"url":"u","event":"e","table":"t","secret":"plain"},"_row":` + row + `}`
		if _, _, err := appWebhookJobResealPayload(bad, oldKey, newKey); err == nil {
			t.Fatalf("invalid root _row %s accepted", row)
		}
	}
	for _, row := range []string{"absent", "null", `{\"id\":1}`} {
		bad := `{"_webhook_subscription":{"url":"u","event":"e","table":"t","secret":"plain"}`
		if row != "absent" {
			bad += `,"_row":` + strings.ReplaceAll(row, `\"`, `"`)
		}
		bad += `}`
		if _, _, err := appWebhookJobResealPayload(bad, oldKey, newKey); err != nil {
			t.Fatalf("valid root _row %s rejected: %v", row, err)
		}
	}
	unknownNested := `{"_webhook_subscription":{"url":"u","event":"e","table":"t","secret":"plain","_row":"preserve-me"}}`
	if got, changed, err := appWebhookJobResealPayload(unknownNested, oldKey, newKey); err != nil || changed || got != unknownNested {
		t.Fatalf("nested unknown _row changed=%v err=%v", changed, err)
	}
}

func TestAppWebhookJobRotationCaseVariantPhysicalTableAndImplicitForeignKey(t *testing.T) {
	oldKey, newKey := []byte(strings.Repeat("c", 32)), []byte(strings.Repeat("d", 32))
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "case.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(1)
	if _, err := db.Exec("PRAGMA foreign_keys=ON"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE main."_BENMORE_JOBS"(id INTEGER PRIMARY KEY,job_type TEXT NOT NULL,payload TEXT)`); err != nil {
		t.Fatal(err)
	}
	payload := appWebhookPayload(appWebhookLegacyV1(t, oldKey, "case-table"))
	if _, err := db.Exec(`INSERT INTO main."_BENMORE_JOBS"(job_type,payload) VALUES('webhook_subscription',?)`, payload); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE main.parent(id INTEGER PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE main.unrelated_ref(value INTEGER REFERENCES parent)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO main.parent(id) VALUES(9)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO main.unrelated_ref(value) VALUES(9)`); err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	rows, err := collectAppWebhookJobSecretRotations(context.Background(), tx, oldKey, newKey)
	if err != nil || len(rows) != 1 {
		t.Fatalf("case-variant physical table or unrelated implicit FK rejected: rows=%d err=%v", len(rows), err)
	}
	if _, err := applyAppWebhookJobSecretRotations(context.Background(), tx, rows); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}

	viewDB, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "case-view.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = viewDB.Close() })
	viewDB.SetMaxOpenConns(1)
	if _, err := viewDB.Exec(`CREATE VIEW main."_BENMORE_JOBS" AS SELECT 1 AS id,'webhook_subscription' AS job_type,'{}' AS payload`); err != nil {
		t.Fatal(err)
	}
	viewTx, err := viewDB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer viewTx.Rollback()
	if _, err := collectAppWebhookJobSecretRotations(context.Background(), viewTx, oldKey, newKey); err == nil {
		t.Fatal("case-variant reserved view was treated as absent")
	}
}

func TestAppWebhookJobRotationWriterRejectsUnorderedRowsBeforeFirstWrite(t *testing.T) {
	db, _ := appWebhookJobsDB(t)
	oldKey, newKey := []byte(strings.Repeat("a", 32)), []byte(strings.Repeat("b", 32))
	first := appWebhookInsert(t, db, "webhook_subscription", "x", appWebhookPayload(appWebhookLegacyV1(t, oldKey, "first")), "pending")
	second := appWebhookInsert(t, db, "webhook_subscription", "x", appWebhookPayload(appWebhookLegacyV1(t, oldKey, "second")), "pending")
	beforeFirst, beforeSecond := appWebhookReadPayload(t, db, first), appWebhookReadPayload(t, db, second)
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	rows, err := collectAppWebhookJobSecretRotations(context.Background(), tx, oldKey, newKey)
	if err != nil {
		t.Fatal(err)
	}
	rows[0], rows[1] = rows[1], rows[0]
	if count, err := applyAppWebhookJobSecretRotations(context.Background(), tx, rows); err == nil || count != 0 {
		t.Fatalf("unordered writer input count=%d err=%v", count, err)
	}
	if appWebhookReadPayloadTx(t, tx, first) != beforeFirst || appWebhookReadPayloadTx(t, tx, second) != beforeSecond {
		t.Fatal("unordered refusal followed a partial write")
	}
	rows, err = collectAppWebhookJobSecretRotations(context.Background(), tx, oldKey, newKey)
	if err != nil {
		t.Fatal(err)
	}
	rows[1] = rows[0]
	if count, err := applyAppWebhookJobSecretRotations(context.Background(), tx, rows); err == nil || count != 0 {
		t.Fatalf("duplicate writer input count=%d err=%v", count, err)
	}
	if appWebhookReadPayloadTx(t, tx, first) != beforeFirst || appWebhookReadPayloadTx(t, tx, second) != beforeSecond {
		t.Fatal("duplicate refusal followed a partial write")
	}
}

func TestAppWebhookJobRotationCASUsesBinaryForNocaseAndRTrimPayload(t *testing.T) {
	for _, collation := range []string{"NOCASE", "RTRIM"} {
		t.Run(collation, func(t *testing.T) {
			db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "collation.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = db.Close() })
			db.SetMaxOpenConns(1)
			if _, err := db.Exec(`CREATE TABLE main._benmore_jobs(id INTEGER PRIMARY KEY,job_type TEXT NOT NULL,payload TEXT COLLATE ` + collation + `)`); err != nil {
				t.Fatal(err)
			}
			oldKey, newKey := []byte(strings.Repeat("n", 32)), []byte(strings.Repeat("m", 32))
			original := `{"_webhook_subscription":{"url":"u","event":"e","table":"t","secret":` + mustWebhookJSON(t, appWebhookLegacyV1(t, oldKey, "secret")) + `},"marker":"Aa"}`
			res, err := db.Exec(`INSERT INTO main._benmore_jobs(job_type,payload) VALUES('webhook_subscription',?)`, original)
			if err != nil {
				t.Fatal(err)
			}
			id, err := res.LastInsertId()
			if err != nil {
				t.Fatal(err)
			}
			tx, err := db.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func(tx *sql.Tx) func() { return func() { _ = tx.Rollback() } }(tx))
			rows, err := collectAppWebhookJobSecretRotations(context.Background(), tx, oldKey, newKey)
			if err != nil {
				t.Fatal(err)
			}
			if count, err := applyAppWebhookJobSecretRotations(context.Background(), tx, rows); err != nil || count != 1 {
				t.Fatalf("exact-image positive count=%d err=%v", count, err)
			}
			if err := tx.Rollback(); err != nil {
				t.Fatal(err)
			}
			stale := strings.Replace(original, `"Aa"`, `"aA"`, 1)
			if collation == "RTRIM" {
				stale = original + " "
			}
			var equivalent int
			if err := db.QueryRow(`SELECT payload = ? FROM main._benmore_jobs WHERE id=?`, stale, id).Scan(&equivalent); err != nil || equivalent != 1 {
				t.Fatalf("fixture is not collation-equal equivalent=%d err=%v", equivalent, err)
			}
			tx, err = db.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			rows, err = collectAppWebhookJobSecretRotations(context.Background(), tx, oldKey, newKey)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(`UPDATE main._benmore_jobs SET payload=? WHERE id=?`, stale, id); err != nil {
				t.Fatal(err)
			}
			if count, err := applyAppWebhookJobSecretRotations(context.Background(), tx, rows); err == nil || err.Error() != "webhook rotation source image changed" || count != 0 {
				t.Fatalf("collation-equivalent stale image count=%d err=%v", count, err)
			}
			var got string
			if err := tx.QueryRow(`SELECT payload FROM main._benmore_jobs WHERE id=?`, id).Scan(&got); err != nil || got != stale {
				t.Fatalf("CAS refusal hid changed source gotPreserved=%v err=%v", got == stale, err)
			}
		})
	}
}

func appWebhookPaddedPayload(size int) string {
	prefix := `{"_webhook_subscription":{"url":"u","event":"e","table":"t","secret":"plain"},"padding":"`
	suffix := `"}`
	return prefix + strings.Repeat("x", size-len(prefix)-len(suffix)) + suffix
}

func TestAppWebhookJobRotationParserDepthNodeAndByteBoundaries(t *testing.T) {
	oldKey, newKey := []byte(strings.Repeat("p", 32)), []byte(strings.Repeat("q", 32))
	base := `{"_webhook_subscription":{"url":"u","event":"e","table":"t","secret":"plain"},"x":`
	for _, tc := range []struct {
		name  string
		depth int
		ok    bool
	}{{"depth64", 63, true}, {"depth65", 64, false}} {
		payload := base + strings.Repeat("[", tc.depth) + "0" + strings.Repeat("]", tc.depth) + "}"
		_, _, err := appWebhookJobResealPayload(payload, oldKey, newKey)
		if (err == nil) != tc.ok {
			t.Fatalf("%s accepted=%v err=%v", tc.name, err == nil, err)
		}
	}
	for _, tc := range []struct {
		name  string
		count int
		ok    bool
	}{{"nodes100000", 99993, true}, {"nodes100001", 99994, false}} {
		payload := base + "[" + strings.TrimSuffix(strings.Repeat("0,", tc.count), ",") + "]}"
		_, _, err := appWebhookJobResealPayload(payload, oldKey, newKey)
		if (err == nil) != tc.ok {
			t.Fatalf("%s accepted=%v err=%v", tc.name, err == nil, err)
		}
	}
	for _, tc := range []struct {
		name string
		size int
		ok   bool
	}{{"bytes4MiB", appWebhookJobPayloadLimit, true}, {"bytes4MiBPlusOne", appWebhookJobPayloadLimit + 1, false}} {
		payload := appWebhookPaddedPayload(tc.size)
		_, _, err := appWebhookJobResealPayload(payload, oldKey, newKey)
		if (err == nil) != tc.ok {
			t.Fatalf("%s accepted=%v err=%v", tc.name, err == nil, err)
		}
	}
	for _, payload := range []string{
		`{"_webhook_subscription":{"url":"u","event":"e","table":"t","secret":"plain\ud800"}}`,
		`{"_webhook_subscription":{"url":"u","event":"e","table":"t","secret":"plain\udc00"}}`,
	} {
		if _, _, err := appWebhookJobResealPayload(payload, oldKey, newKey); err == nil {
			t.Fatal("lone surrogate accepted")
		}
	}
	for _, secret := range []string{"pair-🚀", `slash\\quote\"`} {
		payload := appWebhookPayload(secret)
		if _, _, err := appWebhookJobResealPayload(payload, oldKey, newKey); err != nil {
			t.Fatalf("valid escaped string refused: %v", err)
		}
	}
	invalidUTF8 := `{"_webhook_subscription":{"url":"u","event":"e","table":"t","secret":"` + string([]byte{0xff}) + `"}}`
	if _, _, err := appWebhookJobResealPayload(invalidUTF8, oldKey, newKey); err == nil {
		t.Fatal("invalid UTF-8 accepted")
	}
}

func TestAppWebhookJobRotationRowAndAggregateBoundsBeforePayloadFetch(t *testing.T) {
	oldKey, newKey := []byte(strings.Repeat("r", 32)), []byte(strings.Repeat("s", 32))
	makeDB := func(t *testing.T) *sql.DB {
		t.Helper()
		db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "bounds.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		db.SetMaxOpenConns(1)
		if _, err := db.Exec(`CREATE TABLE main._benmore_jobs(id INTEGER PRIMARY KEY,job_type TEXT NOT NULL,payload TEXT)`); err != nil {
			t.Fatal(err)
		}
		return db
	}
	for _, tc := range []struct {
		name string
		rows int
		ok   bool
	}{{"rows10000", 10000, true}, {"rows10001", 10001, false}} {
		t.Run(tc.name, func(t *testing.T) {
			db := makeDB(t)
			payload := appWebhookPayload("plain")
			if _, err := db.Exec(`WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<?) INSERT INTO main._benmore_jobs(job_type,payload) SELECT 'webhook_subscription',? FROM n`, tc.rows, payload); err != nil {
				t.Fatal(err)
			}
			tx, err := db.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			rows, err := collectAppWebhookJobSecretRotations(context.Background(), tx, oldKey, newKey)
			if (err == nil) != tc.ok {
				t.Fatalf("rows=%d expectedOK=%v err=%v", len(rows), tc.ok, err)
			}
			if tc.ok && len(rows) != 0 {
				t.Fatalf("plaintext rows yielded writes: %d", len(rows))
			}
		})
	}
	for _, tc := range []struct {
		name string
		rows int
		ok   bool
	}{{"aggregate64MiB", 16, true}, {"aggregate64MiBPlus", 17, false}} {
		t.Run(tc.name, func(t *testing.T) {
			db := makeDB(t)
			payload := appWebhookPaddedPayload(appWebhookJobPayloadLimit)
			tx, err := db.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			stmt, err := tx.Prepare(`INSERT INTO main._benmore_jobs(job_type,payload) VALUES('webhook_subscription',?)`)
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < tc.rows; i++ {
				if _, err := stmt.Exec(payload); err != nil {
					t.Fatal(err)
				}
			}
			if err := stmt.Close(); err != nil {
				t.Fatal(err)
			}
			rows, err := collectAppWebhookJobSecretRotations(context.Background(), tx, oldKey, newKey)
			if (err == nil) != tc.ok {
				t.Fatalf("aggregate rows=%d expectedOK=%v err=%v", len(rows), tc.ok, err)
			}
		})
	}
}

func TestAppWebhookJobRotationOversizedLaterTextRefusesBeforeAnyPayloadReadOrWrite(t *testing.T) {
	db, _ := appWebhookJobsDB(t)
	oldKey, newKey := []byte(strings.Repeat("v", 32)), []byte(strings.Repeat("w", 32))
	first := appWebhookInsert(t, db, "webhook_subscription", "x", appWebhookPayload(appWebhookLegacyV1(t, oldKey, "first")), "pending")
	before := appWebhookReadPayload(t, db, first)
	if _, err := db.Exec(`INSERT INTO main._benmore_jobs(job_type,payload) VALUES('webhook_subscription',?)`, appWebhookPaddedPayload(appWebhookJobPayloadLimit+1)); err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := collectAppWebhookJobSecretRotations(context.Background(), tx, oldKey, newKey); err == nil {
		t.Fatal("oversized selected SQL TEXT accepted")
	}
	if got := appWebhookReadPayloadTx(t, tx, first); got != before {
		t.Fatal("oversized later row changed earlier source")
	}
}

func appWebhookRestoreRegistryEntry(t *testing.T, path string) {
	t.Helper()
	canonical := canonicalDBPath(path)
	previous, present := dbCryptoRegistry.Load(canonical)
	var copyValue *dbCryptoKeys
	if present {
		k := previous.(*dbCryptoKeys)
		copyValue = &dbCryptoKeys{aes: append([]byte(nil), k.aes...), blind: append([]byte(nil), k.blind...), ephemeral: k.ephemeral}
	}
	t.Cleanup(func() {
		if !present {
			dbCryptoRegistry.Delete(canonical)
			return
		}
		dbCryptoRegistry.Store(canonical, copyValue)
	})
}

func appWebhookRegistryMatches(path string, key []byte) bool {
	got := cryptoKeysForDBPath(path)
	if got == nil || !bytes.Equal(got.aes, key) {
		return false
	}
	want, err := DeriveBlindIndexKey(key)
	return err == nil && bytes.Equal(got.blind, want) && !got.ephemeral
}

func TestAppWebhookJobRotationLastCipherFailuresAreRedactedAndWriteNothing(t *testing.T) {
	for _, kind := range []string{"corrupt-last-cipher", "wrong-key", "wrong-aad", "unknown-version", "truncated"} {
		t.Run(kind, func(t *testing.T) {
			db, _ := appWebhookJobsDB(t)
			oldKey, newKey := []byte(strings.Repeat("f", 32)), []byte(strings.Repeat("g", 32))
			first := appWebhookInsert(t, db, "webhook_subscription", "x", appWebhookPayload(appWebhookLegacyV1(t, oldKey, "first-secret")), "pending")
			var bad string
			switch kind {
			case "corrupt-last-cipher":
				bad = appWebhookPayload("enc:v1:this-secret-ciphertext-is-corrupt-and-must-not-appear-in-errors")
			case "wrong-key":
				bad = appWebhookPayload(appWebhookLegacyV1(t, []byte(strings.Repeat("z", 32)), "wrong-key-secret"))
			case "wrong-aad":
				value, err := fieldEncryptCtx(oldKey, "webhooks", "secret", "wrong-aad-secret")
				if err != nil {
					t.Fatal(err)
				}
				bad = appWebhookPayload(value)
			case "unknown-version":
				bad = appWebhookPayload("enc:v9:unknown-secret")
			case "truncated":
				bad = appWebhookPayload("enc:v1:")
			}
			appWebhookInsert(t, db, "webhook_subscription", "x", bad, "failed")
			before := appWebhookReadPayload(t, db, first)
			tx, err := db.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			_, err = collectAppWebhookJobSecretRotations(context.Background(), tx, oldKey, newKey)
			if err == nil {
				t.Fatal("invalid later ciphertext accepted")
			}
			for _, private := range []string{"first-secret", "wrong-key-secret", "wrong-aad-secret", "unknown-secret", "this-secret-ciphertext", "enc:v1:"} {
				if strings.Contains(err.Error(), private) {
					t.Fatalf("error leaked private payload data: %q", err)
				}
			}
			if got := appWebhookReadPayloadTx(t, tx, first); got != before {
				t.Fatal("bad later ciphertext changed earlier payload")
			}
		})
	}
}

func appWebhookAssertCleanFollowup(t *testing.T, conn *sql.Conn, oldKey, newKey []byte) {
	t.Helper()
	rows, err := conn.QueryContext(context.Background(), "PRAGMA database_list")
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var seq int
		var name, file string
		if err := rows.Scan(&seq, &name, &file); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		if name != "main" && name != "temp" {
			rows.Close()
			t.Fatalf("connection retained attached schema %q", name)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		t.Fatal(err)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	tx, err := conn.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	rotations, err := collectAppWebhookJobSecretRotations(context.Background(), tx, oldKey, newKey)
	if err != nil {
		t.Fatalf("clean connection follow-up inventory: %v", err)
	}
	if _, err := applyAppWebhookJobSecretRotations(context.Background(), tx, rotations); err != nil {
		t.Fatalf("clean connection follow-up apply: %v", err)
	}
}

func appWebhookProcessBlindMatches(present bool, expected []byte) bool {
	got := appBlindIndexKey.Load()
	if (got != nil) != present {
		return false
	}
	return !present || bytes.Equal(*got, expected)
}
