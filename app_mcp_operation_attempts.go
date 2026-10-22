//go:build !cli

package main

// Durable attempt history for approved connector commands (B2, F05).
//
// Every commit attempt is recorded in its own transaction, outside the business
// transaction: a `running` row is committed before any business side effect is
// attempted, and the terminal outcome is written afterwards, so a rolled-back or
// crashed attempt still leaves history. The row is sealed under the app key with
// the same conventions as the approval store (AAD bound to table and column; the
// envelope repeats the row identity). No actor or intent is stored.

import (
	"bytes"
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const appMCPCommandAttemptStorageDDL = `CREATE TABLE _benmore_mcp_command_attempts (
	attempt_id TEXT PRIMARY KEY NOT NULL CHECK(length(attempt_id)=64 AND attempt_id NOT GLOB '*[^0-9a-f]*'),
	operation_id TEXT NOT NULL CHECK(length(operation_id)=64 AND operation_id NOT GLOB '*[^0-9a-f]*'),
	state_ciphertext TEXT NOT NULL
)`

const (
	appMCPAttemptRunning   = "running"
	appMCPAttemptSucceeded = "succeeded"
	appMCPAttemptFailed    = "failed"
	appMCPAttemptConflict  = "conflict"
	appMCPAttemptUnknown   = "unknown"

	appMCPAttemptDomain = "benmore:mcp:command-attempt-state:v1"

	// A running attempt older than this has outlived the coordinator deadline
	// (appMCPCommandTimeout) plus a small grace, so its outcome can no longer be
	// learned from the attempt itself.
	appMCPAttemptStaleAfter = appMCPCommandTimeout + 5*time.Second

	// Bounds the rows one operation can add before its 15-minute expiry.
	appMCPOperationAttemptLimit = 5
)

var (
	errAppMCPOperationInProgress = errors.New("operation has an attempt in progress")
	appMCPAttemptClassPattern    = regexp.MustCompile(`^[a-z_]{0,64}$`)
)

type appMCPAttemptRecord struct {
	Version     int    `json:"version"`
	Domain      string `json:"domain"`
	AttemptID   string `json:"attempt_id"`
	OperationID string `json:"operation_id"`
	AppID       string `json:"app_id"`
	StartedAt   int64  `json:"started_at"`
	State       string `json:"state"`
	ErrorClass  string `json:"error_class"`
	FinishedAt  int64  `json:"finished_at"`
}

type appMCPAttempt struct {
	appMCPAttemptRecord
	Plaintext  []byte
	Ciphertext string
}

func appMCPAttemptAAD(value string) bool {
	if !strings.HasPrefix(value, encPrefixV2) {
		return false
	}
	body := strings.TrimPrefix(value, encPrefixV2)
	sep := strings.IndexByte(body, ':')
	if sep < 0 {
		return false
	}
	aad, err := hex.DecodeString(body[:sep])
	if err != nil {
		return false
	}
	table, column, ok := cryptoParseAAD(aad)
	return ok && table == "_benmore_mcp_command_attempts" && column == "state_ciphertext"
}

func appMCPValidateAttemptRecord(r appMCPAttemptRecord, appID string) error {
	bad := r.Version != 1 || r.Domain != appMCPAttemptDomain || r.AppID != appID || r.StartedAt <= 0 ||
		!appMCPOperationHex(r.AttemptID, 32) || !appMCPOperationHex(r.OperationID, 32) || !appMCPAttemptClassPattern.MatchString(r.ErrorClass)
	switch r.State {
	case appMCPAttemptRunning:
		bad = bad || r.FinishedAt != 0 || r.ErrorClass != ""
	case appMCPAttemptSucceeded:
		bad = bad || r.FinishedAt < r.StartedAt || r.ErrorClass != ""
	case appMCPAttemptFailed, appMCPAttemptConflict:
		bad = bad || r.FinishedAt < r.StartedAt || r.ErrorClass == ""
	case appMCPAttemptUnknown:
		bad = bad || r.FinishedAt < r.StartedAt
	default:
		bad = true
	}
	if bad {
		return errors.New("command attempt record is invalid")
	}
	return nil
}

func appMCPSealAttempt(key []byte, r appMCPAttemptRecord, appID string) ([]byte, string, error) {
	if err := appMCPValidateAttemptRecord(r, appID); err != nil || len(key) != 32 {
		return nil, "", errors.New("command attempt envelope is invalid")
	}
	plain, err := json.Marshal(r)
	if err != nil || !utf8.Valid(plain) {
		return nil, "", errors.New("command attempt envelope is invalid")
	}
	sealed, err := fieldEncryptCtx(key, "_benmore_mcp_command_attempts", "state_ciphertext", string(plain))
	if err != nil || !appMCPAttemptAAD(sealed) {
		return nil, "", errors.New("command attempt encryption failed")
	}
	return plain, sealed, nil
}

func appMCPOpenAttempt(key []byte, appID, attemptID, operationID, sealed string) (*appMCPAttempt, error) {
	if len(key) != 32 || !appMCPAttemptAAD(sealed) {
		return nil, errors.New("command attempt ciphertext context is invalid")
	}
	plain, err := fieldDecryptCtx(key, "state_ciphertext", sealed)
	if err != nil || !utf8.ValidString(plain) {
		return nil, errors.New("command attempt ciphertext authentication failed")
	}
	decoder := json.NewDecoder(strings.NewReader(plain))
	decoder.DisallowUnknownFields()
	var record appMCPAttemptRecord
	if err := decoder.Decode(&record); err != nil || decoder.Decode(new(any)) != io.EOF {
		return nil, errors.New("command attempt envelope is invalid")
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(canonical, []byte(plain)) || appMCPValidateAttemptRecord(record, appID) != nil ||
		subtle.ConstantTimeCompare([]byte(record.AttemptID), []byte(attemptID)) != 1 || subtle.ConstantTimeCompare([]byte(record.OperationID), []byte(operationID)) != 1 {
		return nil, errors.New("command attempt row integrity failed")
	}
	return &appMCPAttempt{appMCPAttemptRecord: record, Plaintext: []byte(plain), Ciphertext: sealed}, nil
}

// verifyAppMCPCommandAttemptStorage checks the exact table, its single primary
// key index and that nothing else hangs off it.
func verifyAppMCPCommandAttemptStorage(ctx context.Context, tx *sql.Tx) error {
	if ctx == nil || tx == nil || ctx.Err() != nil {
		return errors.New("invalid command attempt schema context")
	}
	if err := (appMCPContextTx{tx: tx, ctx: ctx, private: true}).cleanMain(); err != nil {
		return fmt.Errorf("command attempt database isolation failed: %w", err)
	}
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM main.sqlite_schema WHERE lower(name)=lower(?)", "_benmore_mcp_command_attempts").Scan(&count); err != nil || count != 1 {
		return errors.New("command attempt schema is missing")
	}
	var name, kind, ddl string
	if err := tx.QueryRowContext(ctx, "SELECT name,type,sql FROM main.sqlite_schema WHERE lower(name)=lower(?)", "_benmore_mcp_command_attempts").Scan(&name, &kind, &ddl); err != nil ||
		name != "_benmore_mcp_command_attempts" || kind != "table" || ddl != appMCPCommandAttemptStorageDDL {
		return errors.New("command attempt schema definition is altered")
	}
	indexes, err := tx.QueryContext(ctx, "PRAGMA main.index_list('_benmore_mcp_command_attempts')")
	if err != nil {
		return errors.New("command attempt index inspection failed")
	}
	indexCount := 0
	for indexes.Next() {
		var seq, unique, partial int
		var indexName, origin string
		if err := indexes.Scan(&seq, &indexName, &unique, &origin, &partial); err != nil || indexName != "sqlite_autoindex__benmore_mcp_command_attempts_1" || unique != 1 || origin != "pk" || partial != 0 {
			_ = indexes.Close()
			return errors.New("command attempt indexes are altered")
		}
		indexCount++
	}
	if err := errors.Join(indexes.Err(), indexes.Close()); err != nil || indexCount != 1 {
		return errors.New("command attempt indexes are altered")
	}
	var extras int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM main.sqlite_schema WHERE type IN ('trigger','view') AND (lower(name)=lower(?) OR lower(tbl_name)=lower(?))", "_benmore_mcp_command_attempts", "_benmore_mcp_command_attempts").Scan(&extras); err != nil || extras != 0 {
		return errors.New("command attempt triggers or views are refused")
	}
	return nil
}

func initializeAppMCPCommandAttemptStorage(ctx context.Context, tx *sql.Tx) error {
	if ctx == nil || tx == nil || ctx.Err() != nil {
		return errors.New("invalid command attempt bootstrap context")
	}
	if err := (appMCPContextTx{tx: tx, ctx: ctx, private: true}).cleanMain(); err != nil {
		return fmt.Errorf("command attempt database isolation failed: %w", err)
	}
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM main.sqlite_schema WHERE lower(name)=lower(?)", "_benmore_mcp_command_attempts").Scan(&count); err != nil || count != 0 {
		return errors.New("command attempt storage already exists or cannot be inspected")
	}
	if _, err := tx.ExecContext(ctx, appMCPCommandAttemptStorageDDL); err != nil {
		return errors.New("command attempt storage bootstrap failed")
	}
	return verifyAppMCPCommandAttemptStorage(ctx, tx)
}

// appMCPReadAttemptsWithKey authenticates the attempts of one operation (or of
// every operation when operationID is empty), oldest first.
// ponytail: no operation_id index, so this scans the table; the sweep bounds it.
func appMCPReadAttemptsWithKey(ctx context.Context, tx *sql.Tx, appID string, key []byte, operationID string) ([]appMCPAttempt, error) {
	if ctx == nil || tx == nil || ctx.Err() != nil || !appMCPOperationHex(appID, 32) || len(key) != 32 || (operationID != "" && !appMCPOperationHex(operationID, 32)) {
		return nil, errors.New("invalid command attempt read context")
	}
	query, args := "SELECT attempt_id,operation_id,state_ciphertext FROM main._benmore_mcp_command_attempts ORDER BY rowid", []any{}
	if operationID != "" {
		query, args = "SELECT attempt_id,operation_id,state_ciphertext FROM main._benmore_mcp_command_attempts WHERE operation_id=? ORDER BY rowid", []any{operationID}
	}
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, errors.New("command attempt inventory failed")
	}
	type raw struct{ attempt, operation, sealed string }
	var found []raw
	for rows.Next() {
		var r raw
		if err := rows.Scan(&r.attempt, &r.operation, &r.sealed); err != nil {
			_ = rows.Close()
			return nil, errors.New("command attempt inventory is invalid")
		}
		found = append(found, r)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, errors.New("command attempt inventory could not be read completely")
	}
	out := make([]appMCPAttempt, 0, len(found))
	for _, r := range found {
		attempt, err := appMCPOpenAttempt(key, appID, r.attempt, r.operation, r.sealed)
		if err != nil {
			return nil, err
		}
		out = append(out, *attempt)
	}
	return out, nil
}

func insertAppMCPAttemptWithKey(ctx context.Context, tx *sql.Tx, appID string, key []byte, record appMCPAttemptRecord) error {
	_, sealed, err := appMCPSealAttempt(key, record, appID)
	if err != nil || record.State != appMCPAttemptRunning {
		return errors.New("command attempt insert is invalid")
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO main._benmore_mcp_command_attempts(attempt_id,operation_id,state_ciphertext) VALUES(?,?,?)", record.AttemptID, record.OperationID, sealed); err != nil {
		return errors.New("command attempt insert failed")
	}
	return nil
}

// appMCPSwapAttemptCiphertext compares the stored ciphertext, so a concurrent
// change makes the swap fail instead of overwriting it.
func appMCPSwapAttemptCiphertext(ctx context.Context, tx *sql.Tx, attempt appMCPAttempt, replacement string) error {
	if !appMCPAttemptAAD(replacement) || replacement == attempt.Ciphertext {
		return errors.New("invalid command attempt compare-and-swap")
	}
	result, err := tx.ExecContext(ctx, "UPDATE main._benmore_mcp_command_attempts SET state_ciphertext=? WHERE attempt_id=? AND operation_id=? AND state_ciphertext COLLATE BINARY=?",
		replacement, attempt.AttemptID, attempt.OperationID, attempt.Ciphertext)
	if err != nil {
		return errors.New("command attempt update failed")
	}
	if n, err := result.RowsAffected(); err != nil || n != 1 {
		return errors.New("command attempt compare-and-swap failed")
	}
	return nil
}

func rotateAppMCPAttemptsTx(ctx context.Context, tx *sql.Tx, appID string, oldKey, newKey []byte) (int, error) {
	attempts, err := appMCPReadAttemptsWithKey(ctx, tx, appID, oldKey, "")
	if err != nil {
		return 0, err
	}
	for _, attempt := range attempts {
		sealed, err := appMCPSealAttemptPlaintext(newKey, attempt.Plaintext)
		if err != nil {
			return 0, err
		}
		if err := appMCPSwapAttemptCiphertext(ctx, tx, attempt, sealed); err != nil {
			return 0, err
		}
	}
	return len(attempts), nil
}

func appMCPSealAttemptPlaintext(key []byte, plaintext []byte) (string, error) {
	sealed, err := fieldEncryptCtx(key, "_benmore_mcp_command_attempts", "state_ciphertext", string(plaintext))
	if err != nil || len(key) != 32 || !appMCPAttemptAAD(sealed) {
		return "", errors.New("command attempt encryption failed")
	}
	return sealed, nil
}

// appMCPValidateAttempts proves every attempt authenticates and belongs to an
// existing operation, for the union validator that rotation relies on.
func appMCPValidateAttempts(ctx context.Context, tx *sql.Tx, appID string, key []byte, operations map[string]*appMCPStoredOperation) error {
	attempts, err := appMCPReadAttemptsWithKey(ctx, tx, appID, key, "")
	if err != nil {
		return err
	}
	for _, attempt := range attempts {
		if operations[attempt.OperationID] == nil {
			return errors.New("command attempt is orphaned")
		}
	}
	return nil
}

// ---- derived state ---------------------------------------------------------

// appMCPLatestAttempt is the attempt with the greatest sealed StartedAt; rows are
// read in insertion order, so a tie goes to the later row.
func appMCPLatestAttempt(attempts []appMCPAttempt) *appMCPAttempt {
	var latest *appMCPAttempt
	for i := range attempts {
		if latest == nil || attempts[i].StartedAt >= latest.StartedAt {
			latest = &attempts[i]
		}
	}
	return latest
}

// appMCPAttemptStale is true for a running attempt that has outlived the
// coordinator deadline plus grace. The business transaction cannot commit past
// StartedAt+appMCPCommandTimeout (its commit barrier) and refuses to start once
// its own claim is stale, so a stale running attempt with no receipt, checked
// under the write lock, never committed and never will.
func appMCPAttemptStale(a *appMCPAttempt, now time.Time) bool {
	return a.State == appMCPAttemptRunning && now.Unix() >= a.StartedAt+int64(appMCPAttemptStaleAfter/time.Second)
}

// appMCPAttemptState is what an attempt means now. A stale running attempt, or
// one claiming success without a durable receipt, can no longer be trusted, so
// it is unknown.
func appMCPAttemptState(a *appMCPAttempt, now time.Time, hasReceipt bool) string {
	switch {
	case appMCPAttemptStale(a, now):
		return appMCPAttemptUnknown
	case a.State == appMCPAttemptSucceeded && !hasReceipt:
		return appMCPAttemptUnknown
	}
	return a.State
}

// appMCPAttemptView reports the latest attempt; a durable receipt means the
// operation committed, so the attempt reads as succeeded whatever it recorded.
func appMCPAttemptView(a *appMCPAttempt, now time.Time, hasReceipt bool) map[string]any {
	if a == nil {
		return nil
	}
	state, class := appMCPAttemptState(a, now, hasReceipt), a.ErrorClass
	if hasReceipt {
		state, class = appMCPAttemptSucceeded, ""
	}
	return map[string]any{"attempt_id": a.AttemptID, "state": state, "error_class": class, "started_at": a.StartedAt, "finished_at": a.FinishedAt}
}

// appMCPAttemptOutcomeFor maps a commit result to the attempt's terminal state.
func appMCPAttemptOutcomeFor(err error) (state, class string) {
	if err == nil {
		return appMCPAttemptSucceeded, ""
	}
	switch class = appMCPCommandErrorClass(err); class {
	case "unknown_execution":
		return appMCPAttemptUnknown, class
	case "conflict":
		return appMCPAttemptConflict, class
	}
	return appMCPAttemptFailed, class
}

// appMCPAttemptFinisher is the record step; tests replace it to inject faults.
var appMCPAttemptFinisher = appMCPFinishAttempt

// The record step waits for the write-policy lock on its own budget, so a lock
// held for a while cannot starve the transaction that records the outcome.
var (
	appMCPAttemptLockWait     = 35 * time.Second
	appMCPAttemptRecordBudget = 10 * time.Second
)

// appMCPRecordAttemptOutcome writes the terminal state of a claimed attempt in
// its own transaction, after the business transaction has finished (or never
// ran), and writes the audit row for any non-success there, so neither is lost
// to a rollback. An unknown outcome is first reconciled from the durable
// receipt: a receipt proves the business commit happened. It retries up to 3
// times within a 10 s budget and returns the state it recorded, or "" when it
// could not: the attempt then stays running, and once stale a later _commit
// supersedes it (appMCPClaimAttempt).
func appMCPRecordAttemptOutcome(ctx context.Context, app *App, actor Session, operationID, attemptID, state, class string) string {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), appMCPAttemptLockWait+appMCPAttemptRecordBudget)
	defer cancel()
	var err error
	for try := 1; try <= 3; try++ {
		var recorded string
		if recorded, err = appMCPAttemptFinisher(ctx, app, actor, operationID, attemptID, state, class); err == nil {
			return recorded
		}
		log.Printf("mcp-command: ERROR op=%.8s attempt=%s class=attempt_record_failed try=%d err=%v", operationID, attemptID, try, err)
		select {
		case <-ctx.Done():
			return ""
		case <-time.After(time.Duration(try) * 100 * time.Millisecond):
		}
	}
	return ""
}

// appMCPFinishAttempt is one try. It runs under the write-policy lock, so it
// serializes with ENCRYPTION_KEY rotation, and is idempotent: an attempt that
// is already terminal (an earlier try committed but reported an error) returns
// its recorded state.
func appMCPFinishAttempt(ctx context.Context, app *App, actor Session, operationID, attemptID, state, class string) (string, error) {
	lockCtx, cancelWait := context.WithTimeout(ctx, appMCPAttemptLockWait)
	_, release, _, err := acquireAppMCPWritePolicy(lockCtx, app.Dir)
	cancelWait() // only the wait is bounded; the lock is held for the transaction below
	if err != nil {
		return "", err
	}
	defer release()
	ctx, cancel := context.WithTimeout(ctx, appMCPAttemptRecordBudget)
	defer cancel()
	tx, err := app.DB.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	appID, key, err := appMCPReadyOperationStorage(ctx, tx, app)
	if err != nil {
		return "", err
	}
	if _, err := verifyAppMCPCommandStorageWithKey(ctx, tx, appID, key); err != nil {
		return "", err
	}
	attempts, err := appMCPReadAttemptsWithKey(ctx, tx, appID, key, operationID)
	if err != nil {
		return "", err
	}
	var running *appMCPAttempt
	for i := range attempts {
		if attempts[i].AttemptID != attemptID {
			continue
		}
		if attempts[i].State != appMCPAttemptRunning {
			return attempts[i].State, nil
		}
		running = &attempts[i]
	}
	if running == nil {
		return "", errors.New("claimed attempt does not exist")
	}
	if state == appMCPAttemptUnknown {
		stored, err := appMCPReadOperationWithKey(ctx, tx, appID, key, operationID)
		if err != nil {
			return "", err
		}
		if stored.Receipt != nil {
			state, class = appMCPAttemptSucceeded, ""
		}
	}
	if err := appMCPFinishRunningAttempt(ctx, tx, appID, key, *running, state, class, appMCPClock()); err != nil {
		return "", err
	}
	if state != appMCPAttemptSucceeded {
		if err := appMCPAuditAttempt(tx, actor, operationID, attemptID, state, class, ""); err != nil {
			return "", err
		}
	}
	return state, tx.Commit()
}

// appMCPFinishRunningAttempt swaps a running attempt to a terminal state.
func appMCPFinishRunningAttempt(ctx context.Context, tx *sql.Tx, appID string, key []byte, running appMCPAttempt, state, class string, now time.Time) error {
	next := running.appMCPAttemptRecord
	next.State, next.ErrorClass, next.FinishedAt = state, class, now.Unix()
	if next.FinishedAt < next.StartedAt {
		next.FinishedAt = next.StartedAt
	}
	_, sealed, err := appMCPSealAttempt(key, next, appID)
	if err != nil {
		return err
	}
	return appMCPSwapAttemptCiphertext(ctx, tx, running, sealed)
}

// appMCPAuditAttempt writes the attempt audit row: ids and class only.
func appMCPAuditAttempt(exec sqlExecutor, actor Session, operationID, attemptID, state, class, supersededBy string) error {
	details := map[string]any{"attempt_id": attemptID, "error_class": class}
	if supersededBy != "" {
		details["superseded_by"] = supersededBy
	}
	encoded, err := json.Marshal(details)
	if err != nil {
		return err
	}
	return insertAuditRowChecked(exec, "mcp_command_attempt_"+state, "_benmore_mcp_operations", operationID, &actor, "{}", string(encoded))
}
