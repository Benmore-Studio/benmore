//go:build !cli

package main

// Session ids at rest.
//
// The value a client holds (the session cookie, or a Bearer session token)
// is the credential. _benmore_sessions.id stores only its SHA-256, the same
// treatment reset links and API tokens get, so reading the table (a backup,
// the SQL console, query_db, a copied data.db) yields nothing that signs
// anyone in. In memory, Session.ID is that stored key, so every
// `WHERE id = session.ID` keeps addressing the right row.
//
// sessionKeyPrefix marks the hashed form. A row without it holds a raw id
// written before hashing (or by an older process sharing the database during
// a rolling upgrade). EnsureSessionsTable rekeys all of those at startup in
// one transaction; a straggler written later is still found by its raw value
// and rekeyed on first use, so no one is signed out by the upgrade.
//
// Why a presented value can never match on its stored form: every lookup
// hashes what the client sent, and refuses a value that already carries the
// prefix. The raw fallback compares the presented value to the row id, and
// a hashed row's id always starts with the prefix the presented value may
// not have - so a hashed row matches only its preimage.

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
)

const sessionKeyPrefix = "sha256:"

// sessionLegacyIDSQL selects a column value that is not in hashed form. substr
// rather than LIKE: LIKE is case-insensitive and would treat an id such as
// "SHA256:…" as already hashed.
func sessionLegacyIDSQL(column string) string {
	return fmt.Sprintf("%s <> '' AND substr(%s, 1, %d) <> '%s'", column, column, len(sessionKeyPrefix), sessionKeyPrefix)
}

// sessionStorageKey is the _benmore_sessions.id stored for a session credential.
func sessionStorageKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return sessionKeyPrefix + hex.EncodeToString(sum[:])
}

// isSessionStorageKey reports whether a stored id is in hashed form.
func isSessionStorageKey(id string) bool {
	return strings.HasPrefix(id, sessionKeyPrefix)
}

// presentedSessionKey maps a credential a client presented to its stored key.
// A value already in stored form is refused: it can be read from the
// database, so accepting it would turn the hash back into a credential.
func presentedSessionKey(token string) (string, bool) {
	if token == "" || isSessionStorageKey(token) {
		return "", false
	}
	return sessionStorageKey(token), true
}

// sessionOpaqueID is the short id /api/_auth/sessions lists for a stored
// session: the first 12 hex digits of the credential's SHA-256. It is the
// same value before and after a row is rekeyed, so the ids clients already
// hold keep working for revocation.
func sessionOpaqueID(storedID string) string {
	if isSessionStorageKey(storedID) {
		digest := storedID[len(sessionKeyPrefix):]
		if len(digest) >= 12 {
			return digest[:12]
		}
		return digest
	}
	sum := sha256.Sum256([]byte(storedID))
	return hex.EncodeToString(sum[:])[:12]
}

// revokeSessionByOperatorID deletes a session an operator names (MCP
// revoke_session, the dashboard's revoke): its stored id, as the audit log and
// SQL console show it, or the session token itself.
func revokeSessionByOperatorID(db *sql.DB, id string) (int64, error) {
	candidates := []any{id}
	if !isSessionStorageKey(id) {
		candidates = append(candidates, sessionStorageKey(id))
	}
	res, err := db.Exec("DELETE FROM _benmore_sessions WHERE id IN (?"+strings.Repeat(", ?", len(candidates)-1)+")", candidates...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

type sessionExecer interface {
	Exec(string, ...any) (sql.Result, error)
	QueryRow(string, ...any) *sql.Row
}

// rekeySession moves session oldID to newID everywhere the framework records
// a session id: the row itself, the impersonation sessions it started, and
// the audit rows that name it (act-as start/end). Run inside the caller's
// transaction so the row and its references move together. It reports
// whether the session row itself moved.
func rekeySession(tx sessionExecer, oldID, newID string) (bool, error) {
	res, err := tx.Exec("UPDATE _benmore_sessions SET id = ? WHERE id = ?", newID, oldID)
	if err != nil {
		return false, err
	}
	moved, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if _, err := tx.Exec("UPDATE _benmore_sessions SET impersonator_session_id = ? WHERE impersonator_session_id = ?", newID, oldID); err != nil {
		return false, err
	}
	if ok, err := sessionTableExists(tx, "_benmore_audit_log"); err != nil {
		return false, err
	} else if ok {
		if _, err := tx.Exec("UPDATE _benmore_audit_log SET row_id = ? WHERE table_name = '_benmore_sessions' AND row_id = ?", newID, oldID); err != nil {
			return false, err
		}
	}
	return moved == 1, nil
}

func sessionTableExists(tx sessionExecer, name string) (bool, error) {
	var n int
	if err := tx.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", name).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

// migrateLegacySessionIDs replaces every raw session id at rest with its
// hashed key, in one transaction: session rows, the admin session ids
// recorded on impersonation rows, and session ids in the audit log. Values
// already hashed are left alone, so it is safe to run on every startup.
func migrateLegacySessionIDs(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	collect := func(query string) ([]string, error) {
		rows, err := tx.Query(query)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var ids []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return nil, err
			}
			ids = append(ids, id)
		}
		return ids, rows.Err()
	}
	ids, err := collect("SELECT id FROM _benmore_sessions WHERE " + sessionLegacyIDSQL("id"))
	if err != nil {
		return err
	}
	for _, id := range ids {
		if _, err := rekeySession(tx, id, sessionStorageKey(id)); err != nil {
			return err
		}
	}
	// References to sessions that no longer exist (an expired admin session
	// behind an impersonation row, an act-as audit entry) are dead, but are
	// hashed too so no raw id stays at rest.
	refs, err := collect("SELECT DISTINCT impersonator_session_id FROM _benmore_sessions WHERE " + sessionLegacyIDSQL("COALESCE(impersonator_session_id, '')"))
	if err != nil {
		return err
	}
	for _, id := range refs {
		if _, err := tx.Exec("UPDATE _benmore_sessions SET impersonator_session_id = ? WHERE impersonator_session_id = ?", sessionStorageKey(id), id); err != nil {
			return err
		}
	}
	if ok, err := sessionTableExists(tx, "_benmore_audit_log"); err != nil {
		return err
	} else if ok {
		audit, err := collect("SELECT DISTINCT row_id FROM _benmore_audit_log WHERE table_name = '_benmore_sessions' AND " + sessionLegacyIDSQL("COALESCE(row_id, '')"))
		if err != nil {
			return err
		}
		for _, id := range audit {
			if _, err := tx.Exec("UPDATE _benmore_audit_log SET row_id = ? WHERE table_name = '_benmore_sessions' AND row_id = ?", sessionStorageKey(id), id); err != nil {
				return err
			}
		}
		refs = append(refs, audit...)
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if len(ids)+len(refs) > 0 {
		log.Printf("sessions: stored %d session id(s) and %d reference(s) as SHA-256 keys", len(ids), len(refs))
	}
	return nil
}

// rekeyLegacySession moves one straggler row found by its raw id to the
// hashed key. It returns the id the row now has: the key, or the raw id when
// the rewrite failed (the row still works under its old id this request).
func rekeyLegacySession(db *sql.DB, rawID, key string) string {
	tx, err := db.Begin()
	if err != nil {
		return rawID
	}
	defer tx.Rollback()
	// A row that did not move was rekeyed (or removed) by a concurrent
	// request; either way the key is its id from now on.
	if _, err := rekeySession(tx, rawID, key); err != nil {
		log.Printf("sessions: rekey legacy session failed: %v", err)
		return rawID
	}
	if err := tx.Commit(); err != nil {
		log.Printf("sessions: rekey legacy session failed: %v", err)
		return rawID
	}
	return key
}
