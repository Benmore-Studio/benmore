//go:build !cli

package main

// Audit rows of account security events.
//
// A second factor enrolled or removed, a backup code spent, an address
// changed, an API token minted or revoked, a passkey added or removed and a
// session ended by its owner each changed who can sign in as an account and
// left no row in _benmore_audit_log: only password changes, role changes and
// support sessions did. An admin reading the log after a takeover saw the
// password change and nothing of the token minted just before it.
//
// auditAccountEvent writes the row through the transaction that makes the
// change, so the change and its record commit or roll back together: a failed
// insert refuses the change, it is never written after the commit and never
// dropped. The row names who acted (user_id, user_email, and the admin behind
// a support session) and what was affected (table_name, row_id). Its values
// hold what describes the event and nothing that authenticates: a token's
// name, scopes and expiry, never the token or its hash; a factor's kind,
// never the secret or a code. Addresses are stored as the log stores them
// everywhere else (user_email, the rows platform tooling writes): clear, and
// blanked by account erasure with the rest of the account's rows.
//
// Only completed changes are recorded. A refused attempt (a wrong code or
// password, a request the account may not make) writes nothing here.

import (
	"encoding/json"
	"fmt"
)

const (
	accountAuditMFACodesGenerated  = "mfa_backup_codes_generated"
	accountAuditMFAEnrolled        = "mfa_enrolled"
	accountAuditMFARemoved         = "mfa_removed"
	accountAuditMFABackupCodeUsed  = "mfa_backup_code_used"
	accountAuditEmailChangeRequest = "email_change_requested"
	accountAuditEmailChanged       = "email_changed"
	accountAuditAPITokenCreated    = "api_token_created"
	accountAuditAPITokenRevoked    = "api_token_revoked"
	accountAuditSessionRevoked     = "session_revoked"
	accountAuditPasskeyAdded       = "passkey_added"
	accountAuditPasskeyRemoved     = "passkey_removed"
	accountAuditPasskeysRemovedAll = "passkeys_removed_all"
)

// accountAuditEventTables is every action auditAccountEvent writes and the
// table_name its row carries. A database restore copies the audit rows newer
// than its snapshot by table_name (restoreAuditTables), and account erasure
// drops the values of the rows about an account by table_name and row_id, so
// an event's table decides both; TestAccountAuditEventsAreCarriedByRestore
// fails for an action whose table a restore would leave behind.
var accountAuditEventTables = map[string]string{
	accountAuditMFACodesGenerated:  "_benmore_users",
	accountAuditMFAEnrolled:        "_benmore_users",
	accountAuditMFARemoved:         "_benmore_users",
	accountAuditMFABackupCodeUsed:  "_benmore_users",
	accountAuditEmailChangeRequest: "_benmore_users",
	accountAuditEmailChanged:       "_benmore_users",
	accountAuditAPITokenCreated:    "_benmore_api_tokens",
	accountAuditAPITokenRevoked:    "_benmore_api_tokens",
	accountAuditSessionRevoked:     "_benmore_sessions",
	accountAuditPasskeyAdded:       "_benmore_passkeys",
	accountAuditPasskeyRemoved:     "_benmore_passkeys",
	accountAuditPasskeysRemovedAll: "_benmore_passkeys",
}

// auditAccountEvent writes the audit row of one account security event
// through tx, the transaction that makes the change. rowID is the affected
// row of the action's table: the account id for _benmore_users, the token or
// passkey id, the listed id of a session. Values go through the same
// hidden-column redaction as every other audit row.
func auditAccountEvent(tx sqlExecutor, app *App, action, rowID string, actor *Session, oldRow, newRow map[string]any) error {
	table, known := accountAuditEventTables[action]
	if !known {
		return fmt.Errorf("audit: %q is not an account event", action)
	}
	var oldJSON, newJSON string
	for _, side := range []struct {
		row map[string]any
		out *string
	}{{oldRow, &oldJSON}, {newRow, &newJSON}} {
		if side.row == nil {
			continue
		}
		b, err := json.Marshal(redactAuditHiddenFields(app, table, side.row))
		if err != nil {
			return fmt.Errorf("audit %s: %w", action, err)
		}
		*side.out = string(b)
	}
	if err := insertAuditRowChecked(tx, action, table, rowID, actor, oldJSON, newJSON); err != nil {
		return fmt.Errorf("audit %s: %w", action, err)
	}
	return nil
}

// accountAuditSelf is the actor of an event an account performs on itself
// with no session to name it: a sign-in step, an enrollment held behind a
// setup token, an emailed link confirmed with the account's password.
func accountAuditSelf(q rowQuerier, userID int64) (*Session, error) {
	actor := &Session{UserID: userID}
	if err := q.QueryRow("SELECT COALESCE(email, '') FROM _benmore_users WHERE id = ?", userID).Scan(&actor.Email); err != nil {
		return nil, fmt.Errorf("audit: read account %d: %w", userID, err)
	}
	return actor, nil
}
