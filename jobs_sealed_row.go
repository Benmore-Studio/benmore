//go:build !cli

package main

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
)

// Sealed job rows. A hook or webhook-subscription job carries the written row
// in its payload (`_row`) for delivery. Rows are decrypted when read, so that
// copy held the plaintext of every encrypted.yaml column, and of its old_<col>
// change delta, in _benmore_jobs for as long as the job is kept.
//
// sealJobPayloadRow replaces each such value at enqueue with the value's JSON
// encoding sealed under the database's own key (enc:v2, AAD bound to
// _benmore_jobs and "<table>.<key>", so a sealed value can't be moved to
// another key, another table or a source column) and lists the sealed keys in
// jobSealedRowField. openJobPayloadRow restores them at delivery, decoding
// the JSON exactly as the worker decodes the stored payload, so the receiver
// gets the same bytes as before. A payload without the list (queued by an
// earlier runtime) is delivered as stored. RotateEncryptionKey re-seals the
// jobs that can still be delivered (rotateSealedJobRowsTx).

// jobSealedRowField is the payload key listing the sealed `_row` keys.
const jobSealedRowField = "__benmore_sealed_row"

// jobSealedRowTable is the AAD table component of a sealed job value.
const jobSealedRowTable = "_benmore_jobs"

// jobSealedRowColumn is the AAD column component of a sealed job value.
func jobSealedRowColumn(table, key string) string { return table + "." + key }

// jobRowSealedKeys lists the row keys holding an encrypted.yaml column of
// table, or its old_ delta, with a non-null value.
func jobRowSealedKeys(app *App, table string, row map[string]any) []string {
	if app == nil || app.Encrypted == nil || table == "" || len(row) == 0 {
		return nil
	}
	var cols []string
	for name, defs := range app.Encrypted.Fields {
		if !strings.EqualFold(name, table) {
			continue
		}
		for _, def := range defs {
			cols = append(cols, def.Column)
		}
	}
	var keys []string
	for k, v := range row {
		if v == nil {
			continue
		}
		for _, col := range cols {
			if strings.EqualFold(k, col) || strings.EqualFold(k, "old_"+col) {
				keys = append(keys, k)
				break
			}
		}
	}
	sort.Strings(keys)
	return keys
}

// jobRowKey resolves the key of the database q is connected to. With
// sealing set, a per-process (ephemeral) key yields nil: a job sealed under it
// could not be delivered after a restart, so its row is queued as before
// (the rule TOTP secrets follow, totpSealKey).
func jobRowKey(q rowQuerier, sealing bool) ([]byte, error) {
	path, err := mainDatabasePathForQuerier(q)
	if err != nil {
		return nil, err
	}
	if keys := cryptoKeysForDBPath(path); keys != nil {
		if sealing && keys.ephemeral {
			return nil, nil
		}
		if len(keys.aes) == 0 {
			return nil, errors.New("database encryption key is not registered")
		}
		return keys.aes, nil
	}
	if isolateAppEnvironment.Load() || len(appEncryptionKey) == 0 {
		return nil, errors.New("database encryption key is not registered")
	}
	if sealing && appEncryptionKeyEphemeral {
		return nil, nil
	}
	return appEncryptionKey, nil
}

// sealJobPayloadRow seals, in payload, the encrypted.yaml values of the row a
// hook or webhook-subscription job carries. The caller's row map is not
// modified. q is the connection or transaction the job is queued through.
func sealJobPayloadRow(q rowQuerier, app *App, table string, payload map[string]any) error {
	row, _ := payload["_row"].(map[string]any)
	keys := jobRowSealedKeys(app, table, row)
	if len(keys) == 0 {
		return nil
	}
	key, err := jobRowKey(q, true)
	if err != nil {
		return fmt.Errorf("resolve job encryption key: %w", err)
	}
	if key == nil {
		return nil
	}
	sealed := make(map[string]any, len(row))
	for k, v := range row {
		sealed[k] = v
	}
	for _, k := range keys {
		plain, err := json.Marshal(row[k])
		if err != nil {
			return fmt.Errorf("seal job row value: %w", err)
		}
		enc, err := fieldEncryptCtx(key, jobSealedRowTable, jobSealedRowColumn(table, k), string(plain))
		if err != nil {
			return fmt.Errorf("seal job row value: %w", err)
		}
		sealed[k] = enc
	}
	payload["_row"] = sealed
	payload[jobSealedRowField] = keys
	return nil
}

// jobSealedRowList returns the sealed keys a decoded payload lists, and
// whether it has a list at all.
func jobSealedRowList(data map[string]any) ([]string, bool, error) {
	raw, present := data[jobSealedRowField]
	if !present {
		return nil, false, nil
	}
	list, ok := raw.([]any)
	if !ok || len(list) == 0 {
		return nil, true, errors.New("job row seal list is malformed")
	}
	names := make([]string, 0, len(list))
	for _, item := range list {
		name, ok := item.(string)
		if !ok || name == "" {
			return nil, true, errors.New("job row seal list is malformed")
		}
		names = append(names, name)
	}
	return names, true, nil
}

// jobSealedRowValueBound reports whether value is a v2 envelope whose AAD is
// exactly the one a sealed job value of table and key carries.
func jobSealedRowValueBound(value, table, key string) bool {
	body, ok := strings.CutPrefix(value, encPrefixV2)
	if !ok {
		return false
	}
	sep := strings.IndexByte(body, ':')
	if sep < 0 {
		return false
	}
	aad, err := hex.DecodeString(body[:sep])
	return err == nil && string(aad) == string(cryptoBuildAAD(jobSealedRowTable, jobSealedRowColumn(table, key)))
}

// openJobPayloadRow returns the row a hook or webhook-subscription job
// delivers: the stored `_row` with every sealed value opened. A payload with
// no seal list is returned as stored. A list that does not open under the
// database's key (malformed, tampered, moved between keys or tables) is an
// error and nothing is delivered; the error is retryable because a key
// rotation can land between the worker reading the payload and opening it.
func openJobPayloadRow(app *App, data map[string]any, table string) (map[string]any, error) {
	row, _ := data["_row"].(map[string]any)
	names, sealed, err := jobSealedRowList(data)
	if !sealed {
		return row, nil
	}
	if err != nil || row == nil {
		return nil, errors.New("job row seal list is malformed")
	}
	key, err := jobRowKey(app.DB, false)
	if err != nil {
		return nil, fmt.Errorf("resolve job encryption key: %w", err)
	}
	out := make(map[string]any, len(row))
	for k, v := range row {
		out[k] = v
	}
	for _, name := range names {
		value, ok := row[name].(string)
		if !ok || !jobSealedRowValueBound(value, table, name) {
			return nil, fmt.Errorf("sealed job row value %q is not bound to this job", name)
		}
		plain, err := fieldDecryptCtx(key, jobSealedRowColumn(table, name), value)
		if err != nil {
			return nil, fmt.Errorf("sealed job row value %q does not open under the database key", name)
		}
		var v any
		if err := json.Unmarshal([]byte(plain), &v); err != nil {
			return nil, fmt.Errorf("sealed job row value %q is malformed", name)
		}
		out[name] = v
	}
	return out, nil
}

// jobSealedRowTableName returns the event table a hook or webhook
// subscription payload names.
func jobSealedRowTableName(data map[string]any) string {
	for _, field := range []string{"_hook", "_webhook_subscription"} {
		if meta, ok := data[field].(map[string]any); ok {
			if table, ok := meta["table"].(string); ok {
				return table
			}
		}
	}
	return ""
}

// jobSealedRowsDeliverableSQL selects the jobs whose sealed rows a rotation
// must move: hook and webhook-subscription jobs that can still be delivered
// (pending, running, or failed and retryable by an admin) and carry a list.
// Completed jobs are never run again; their values stay under the old key.
const jobSealedRowsDeliverableSQL = "FROM main._benmore_jobs WHERE job_type IN ('hook','webhook_subscription') AND status IN ('pending','running','failed') AND json_valid(payload) AND json_type(payload, '$." + jobSealedRowField + "') = 'array'"

// countSealedJobRows counts the jobs rotateSealedJobRowsTx would visit.
func countSealedJobRows(db *sql.DB) (int, error) {
	present, err := jobsTablePresent(db)
	if err != nil || !present {
		return 0, err
	}
	var n int
	err = db.QueryRow("SELECT count(*) " + jobSealedRowsDeliverableSQL).Scan(&n)
	return n, err
}

// jobsTablePresent reports whether the database has a jobs table.
func jobsTablePresent(q rowQuerier) (bool, error) {
	var n int
	err := q.QueryRow("SELECT count(*) FROM main.sqlite_schema WHERE type = 'table' AND name = '_benmore_jobs'").Scan(&n)
	return n > 0, err
}

// rotateSealedJobRowsTx re-seals, in the rotation's transaction, every sealed
// value of a deliverable job under newKey. Each payload is changed only where
// a sealed value sits and is written back only if it is still byte-for-byte
// the payload read. A job whose values do not open under oldKey could not be
// delivered before the rotation either; it is left as it is and logged.
func rotateSealedJobRowsTx(tx *sql.Tx, oldKey, newKey []byte) (int, error) {
	present, err := jobsTablePresent(tx)
	if err != nil || !present {
		return 0, err
	}
	rows, err := tx.Query("SELECT id, payload " + jobSealedRowsDeliverableSQL + " ORDER BY id")
	if err != nil {
		return 0, fmt.Errorf("list sealed jobs: %w", err)
	}
	type job struct {
		id      int64
		payload string
	}
	var jobs []job
	for rows.Next() {
		var j job
		if err := rows.Scan(&j.id, &j.payload); err != nil {
			rows.Close()
			return 0, fmt.Errorf("list sealed jobs: %w", err)
		}
		jobs = append(jobs, j)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return 0, fmt.Errorf("list sealed jobs: %w", err)
	}
	moved := 0
	for _, j := range jobs {
		next, err := resealJobPayload(j.payload, oldKey, newKey)
		if err != nil {
			log.Printf("encryption-rotate: job #%d left as it is: %s", j.id, err)
			continue
		}
		res, err := tx.Exec("UPDATE main._benmore_jobs SET payload = ? WHERE id = ? AND payload IS ?", next, j.id, j.payload)
		if err != nil {
			return 0, fmt.Errorf("re-seal job #%d: %w", j.id, err)
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			return 0, fmt.Errorf("re-seal job #%d: the payload changed during rotation", j.id)
		}
		moved++
	}
	return moved, nil
}

// resealJobPayload returns payload with each sealed value replaced by the
// same plaintext sealed under newKey with the same binding. Only the sealed
// strings change; every other byte of the payload is kept.
func resealJobPayload(payload string, oldKey, newKey []byte) (string, error) {
	var data map[string]any
	if err := json.Unmarshal([]byte(payload), &data); err != nil {
		return "", errors.New("payload is not a JSON object")
	}
	names, _, err := jobSealedRowList(data)
	if err != nil {
		return "", err
	}
	row, _ := data["_row"].(map[string]any)
	table := jobSealedRowTableName(data)
	if row == nil || table == "" {
		return "", errors.New("sealed job has no row or table")
	}
	out := payload
	for _, name := range names {
		value, ok := row[name].(string)
		if !ok || !jobSealedRowValueBound(value, table, name) {
			return "", fmt.Errorf("sealed value %q is not bound to this job", name)
		}
		column := jobSealedRowColumn(table, name)
		plain, err := fieldDecryptCtx(oldKey, column, value)
		if err != nil {
			return "", fmt.Errorf("sealed value %q does not open under the old key", name)
		}
		next, err := fieldEncryptCtx(newKey, jobSealedRowTable, column, plain)
		if err != nil {
			return "", err
		}
		// A v2 envelope is prefix, hex and colons: its JSON form is the
		// value in quotes, and a random nonce makes it unique.
		quoted := `"` + value + `"`
		if strings.Count(out, quoted) != 1 {
			return "", fmt.Errorf("sealed value %q is not unique in the payload", name)
		}
		out = strings.Replace(out, quoted, `"`+next+`"`, 1)
	}
	return out, nil
}
