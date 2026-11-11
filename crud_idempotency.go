//go:build !cli

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Route + credential isolate cache entries. Input and current permissions must
// match before replay. The insert and response cache commit in one transaction.
func createIdempotencyIdentity(r *http.Request, table string, session *Session, key string) (string, string) {
	identity, _ := json.Marshal([]any{"create-v2", table, session.UserID, session.ID, key})
	values := make(url.Values)
	for k, v := range r.Form {
		if k != csrfTokenName {
			values[k] = v
		}
	}
	request, _ := json.Marshal([]any{values.Encode(), isHTMX(r), sessionSecurityFingerprint(session)})
	return fmt.Sprintf("v2:%x", sha256.Sum256(identity)), fmt.Sprintf("%x", sha256.Sum256(request))
}

// batchCreateIdempotencyIdentity is createIdempotencyIdentity for
// POST /api/<table>/batch: the key is scoped like a single create's (route,
// user, credential, key) under its own route tag, and the fingerprint covers
// the exact request body and the caller's current authorization.
func batchCreateIdempotencyIdentity(table string, session *Session, key string, body []byte) (string, string) {
	identity, _ := json.Marshal([]any{"batch-create-v1", table, session.UserID, session.ID, key})
	request, _ := json.Marshal([]any{string(body), sessionSecurityFingerprint(session)})
	return fmt.Sprintf("v2:%x", sha256.Sum256(identity)), fmt.Sprintf("%x", sha256.Sum256(request))
}

type idempotencyStore interface {
	Exec(query string, args ...any) (sql.Result, error)
	QueryRow(query string, args ...any) *sql.Row
}

// answerIdempotentReplay answers a create retried with a key it already used,
// inside the mutation transaction: the stored response when the request is
// the same, 409 when its input or authorization changed or the stored
// response no longer opens. It reports whether it wrote the answer; false
// means the key is new and the create runs. htmx adds the HX-Refresh a
// single create's htmx answer carries.
func answerIdempotentReplay(w http.ResponseWriter, tx idempotencyStore, idempKey, fingerprint string, userID int64, htmx bool) (bool, error) {
	if _, err := tx.Exec("DELETE FROM _benmore_idempotency WHERE key=? AND user_id=? AND created_at < datetime('now', '-1 day')", idempKey, userID); err != nil {
		return false, err
	}
	var cached, previous string
	var status int
	err := tx.QueryRow("SELECT response, status_code, fingerprint FROM _benmore_idempotency WHERE key=? AND user_id=?", idempKey, userID).Scan(&cached, &status, &previous)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !hmac.Equal([]byte(previous), []byte(fingerprint)) {
		httpJSON(w, http.StatusConflict, map[string]any{"error": "idempotency key already used with different input or authorization"})
		return true, nil
	}
	body, err := openIdempotentResponse(tx, idempKey, userID, cached)
	if errors.Is(err, errIdempotentResponseUnreadable) {
		log.Printf("idempotency: a stored response for user %d does not open under the database's key (%v); the retry is refused with 409", userID, err)
		httpJSON(w, http.StatusConflict, map[string]any{"error": "idempotency key already used, but its stored response can no longer be read: verify the original operation before retrying"})
		return true, nil
	}
	if err != nil {
		return false, err
	}
	w.Header().Set("Content-Type", "application/json")
	if htmx {
		w.Header().Set("HX-Refresh", "true")
	}
	w.WriteHeader(status)
	w.Write([]byte(body))
	return true, nil
}

// Sealed stored responses.
//
// A single create stores the response it answered so a retry can answer it
// again: the created row as its creator read it back, each encrypted.yaml
// column decrypted when the creator may unmask it. Kept as text, that put
// SSNs, salaries and diagnoses in plaintext in _benmore_idempotency, and in
// every backup of data.db, for at least the 24 hour replay window.
//
// For a table with encrypted.yaml columns the whole response is now sealed
// under the database's own key (enc:v2, AAD bound to _benmore_idempotency and
// to the entry's user and key, so a sealed response opens only for the entry
// it was written for) and opened on replay, so a retry still answers the
// original bytes. Responses of other tables, empty htmx responses and batch
// responses ({ids, count}) hold no decrypted value and stay as they were.
// RotateEncryptionKey re-seals the live entries in its transaction
// (rotateSealedIdempotencyResponsesTx). A sealed response that does not open
// (the key was replaced outside a rotation, or a per-process key was lost at a
// restart) is never answered and never runs the create again: the retry gets
// 409 and the caller verifies the original operation, as for a legacy entry.

// idempotencySealTable is the AAD table component of a sealed response.
const idempotencySealTable = "_benmore_idempotency"

// errIdempotentResponseUnreadable means a stored response is sealed but does
// not open for its entry under the database's current key.
var errIdempotentResponseUnreadable = errors.New("stored idempotent response does not open")

// idempotencySealColumn is the AAD column component of the response sealed
// for the entry (userID, key).
func idempotencySealColumn(userID int64, key string) string {
	return "response:" + strconv.FormatInt(userID, 10) + ":" + key
}

// idempotencySealsTable reports whether table's stored create responses are
// sealed: the table declares encrypted.yaml columns.
func idempotencySealsTable(app *App, table string) bool {
	if app == nil || app.Encrypted == nil || table == "" {
		return false
	}
	for name, defs := range app.Encrypted.Fields {
		if len(defs) > 0 && strings.EqualFold(name, table) {
			return true
		}
	}
	return false
}

// sealIdempotentResponse returns the text stored for a create's response
// body: sealed for the entry (userID, idempKey) when table has encrypted
// fields, as is otherwise. q is the create's transaction.
func sealIdempotentResponse(q rowQuerier, app *App, table, idempKey string, userID int64, body []byte) (string, error) {
	if len(body) == 0 || !idempotencySealsTable(app, table) {
		return string(body), nil
	}
	// The key that encrypts the table's own columns, per-process or not: a
	// response that outlives it can't be answered, but it never stays readable.
	key, err := jobRowKey(q, false)
	if err != nil {
		return "", fmt.Errorf("resolve encryption key: %w", err)
	}
	return fieldEncryptCtx(key, idempotencySealTable, idempotencySealColumn(userID, idempKey), string(body))
}

// idempotentResponseBound reports whether stored is a v2 envelope whose AAD is
// exactly the one the response sealed for (userID, idempKey) carries.
func idempotentResponseBound(stored, idempKey string, userID int64) bool {
	body, ok := strings.CutPrefix(stored, encPrefixV2)
	if !ok {
		return false
	}
	sep := strings.IndexByte(body, ':')
	if sep < 0 {
		return false
	}
	aad, err := hex.DecodeString(body[:sep])
	return err == nil && string(aad) == string(cryptoBuildAAD(idempotencySealTable, idempotencySealColumn(userID, idempKey)))
}

// openIdempotentResponse returns the response a stored entry answers. A plain
// stored response (a JSON object or empty) is returned as is; a sealed one is
// opened under the database's key, and errIdempotentResponseUnreadable is
// returned when it is not bound to this entry or does not open.
func openIdempotentResponse(q rowQuerier, idempKey string, userID int64, stored string) (string, error) {
	if !cryptoIsEncrypted(stored) {
		return stored, nil
	}
	if !idempotentResponseBound(stored, idempKey, userID) {
		return "", fmt.Errorf("%w: not bound to this entry", errIdempotentResponseUnreadable)
	}
	key, err := jobRowKey(q, false)
	if err != nil {
		return "", fmt.Errorf("resolve encryption key: %w", err)
	}
	plain, err := fieldDecryptCtx(key, idempotencySealColumn(userID, idempKey), stored)
	if err != nil {
		return "", fmt.Errorf("%w: %v", errIdempotentResponseUnreadable, err)
	}
	return plain, nil
}

// idempotencySealedSQL selects the sealed stored responses.
const idempotencySealedSQL = "FROM main._benmore_idempotency WHERE substr(response, 1, 7) = '" + encPrefixV2 + "'"

// idempotencyTablePresent reports whether the database has the table.
func idempotencyTablePresent(q rowQuerier) (bool, error) {
	var n int
	err := q.QueryRow("SELECT count(*) FROM main.sqlite_schema WHERE type = 'table' AND name = '_benmore_idempotency'").Scan(&n)
	return n > 0, err
}

// countSealedIdempotencyResponses counts the sealed stored responses a
// rotation moves.
func countSealedIdempotencyResponses(db *sql.DB) (int, error) {
	present, err := idempotencyTablePresent(db)
	if err != nil || !present {
		return 0, err
	}
	var n int
	err = db.QueryRow("SELECT count(*) " + idempotencySealedSQL).Scan(&n)
	return n, err
}

// rotateSealedIdempotencyResponsesTx re-seals, in the rotation's transaction,
// every sealed stored response still inside the replay window under newKey
// with the same binding; entries past the window are deleted, as a start
// deletes them. A response that does not open under oldKey could not be
// answered before the rotation either: it is left as it is (its retry keeps
// getting 409) and logged.
func rotateSealedIdempotencyResponsesTx(tx *sql.Tx, oldKey, newKey []byte) (int, error) {
	present, err := idempotencyTablePresent(tx)
	if err != nil || !present {
		return 0, err
	}
	if _, err := tx.Exec("DELETE FROM main._benmore_idempotency WHERE created_at < datetime('now', '-1 day')"); err != nil {
		return 0, fmt.Errorf("delete expired idempotency entries: %w", err)
	}
	rows, err := tx.Query("SELECT key, user_id, response " + idempotencySealedSQL + " ORDER BY rowid")
	if err != nil {
		return 0, fmt.Errorf("list sealed idempotency responses: %w", err)
	}
	type entry struct {
		key      string
		userID   int64
		response string
	}
	var entries []entry
	for rows.Next() {
		var e entry
		if err := rows.Scan(&e.key, &e.userID, &e.response); err != nil {
			rows.Close()
			return 0, fmt.Errorf("list sealed idempotency responses: %w", err)
		}
		entries = append(entries, e)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return 0, fmt.Errorf("list sealed idempotency responses: %w", err)
	}
	moved := 0
	for _, e := range entries {
		column := idempotencySealColumn(e.userID, e.key)
		if !idempotentResponseBound(e.response, e.key, e.userID) {
			log.Printf("encryption-rotate: an idempotency entry of user %d is left as it is: its response is not bound to it", e.userID)
			continue
		}
		plain, err := fieldDecryptCtx(oldKey, column, e.response)
		if err != nil {
			log.Printf("encryption-rotate: an idempotency entry of user %d is left as it is: its response does not open under the old key", e.userID)
			continue
		}
		next, err := fieldEncryptCtx(newKey, idempotencySealTable, column, plain)
		if err != nil {
			return 0, err
		}
		res, err := tx.Exec("UPDATE main._benmore_idempotency SET response = ? WHERE key = ? AND user_id = ? AND response IS ?", next, e.key, e.userID, e.response)
		if err != nil {
			return 0, fmt.Errorf("re-seal idempotency response: %w", err)
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			return 0, errors.New("re-seal idempotency response: the entry changed during rotation")
		}
		moved++
	}
	return moved, nil
}
