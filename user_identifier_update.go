//go:build !cli

package main

// A generic update of a _benmore_users row that changes a sign-in identifier.
//
// The admin panel's inline editor is generic CRUD on the users table, so an
// admin could type a new address into any account. The address is the
// account: it selects the row at sign-in, receives the reset link and the
// emailed sign-in code, and is what an OAuth sign-in is matched on. Two things
// followed:
//
//   - one admin could point a second admin's address at an inbox of their own
//     and reset their way into that account, acting from then on as the other
//     admin. That change is refused: an admin's identifier is changed by that
//     admin (the email-change flow proves the password and the new inbox).
//   - any other account's address could be changed with its sessions, API
//     tokens, connector grants, unused reset links and pending email change
//     left working, so whoever held the old address kept a way in (and a
//     reset link mailed to the old inbox still set the password). The change
//     now ends them in the same transaction, as confirming an email change
//     does (settings_email_change.go).
//
// The same holds for the configured auth.identifier (phone, username) where
// that, not the address, signs the account in.

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strconv"
)

// adminIdentifierProtectedCode is the refusal's stable code.
const adminIdentifierProtectedCode = "admin_identifier_protected"

// userSignInIdentifierColumns are the _benmore_users columns that select or
// recover an account in this app: the address always, and the configured
// sign-in identifier when it is another column.
func userSignInIdentifierColumns(app *App) []string {
	cols := []string{"email"}
	if app != nil {
		if id := authIdentifier(app); id != "email" {
			cols = append(cols, id)
		}
	}
	return cols
}

// userIdentifierUpdate runs before a generic update of table row id writes
// values, in the update's transaction. Other tables, and updates that leave
// the row's identifiers as stored (an edit form sends every field back), pass
// untouched. A change to another admin's identifier is refused; any other
// change first revokes the account's credentials, while the reset links can
// still be matched to the old address.
func userIdentifierUpdate(tx *sql.Tx, q rowQuerier, app *App, actor *Session, table, id string, values map[string]any) error {
	if !identIs(table, "_benmore_users") || tx == nil {
		return nil
	}
	uid, err := strconv.ParseInt(id, 10, 64)
	if err != nil || uid <= 0 {
		return nil
	}
	changed := ""
	for _, col := range userSignInIdentifierColumns(app) {
		submitted, ok := values[col]
		if !ok {
			continue
		}
		next := ""
		if submitted != nil {
			next = valueText(submitted)
		}
		var stored string
		err := q.QueryRow("SELECT COALESCE(CAST("+quoteIdent(col)+" AS TEXT), '') FROM main._benmore_users WHERE id = ?", uid).Scan(&stored)
		if errors.Is(err, sql.ErrNoRows) {
			return nil // the update answers for a missing row
		}
		if err != nil {
			return updateInternalError(err)
		}
		if next != stored {
			changed = col
			break
		}
	}
	if changed == "" {
		return nil
	}
	if actor == nil || actor.UserID != uid {
		admin, err := accountHoldsGlobalAdmin(q, uid)
		if err != nil {
			return updateInternalError(err)
		}
		if admin {
			return &updateRequestError{
				status: http.StatusForbidden,
				code:   adminIdentifierProtectedCode,
				message: fmt.Sprintf("cannot change another admin's %s here: it signs that account in and receives its reset links and sign-in codes. "+
					"That admin changes it from their own account; nothing was saved.", changed),
			}
		}
	}
	if err := revokePasswordCredentials(tx, uid); err != nil {
		return updateInternalError(err)
	}
	return nil
}

// accountHoldsGlobalAdmin reports whether account uid is an admin of the
// whole app: by the role column or an unexpired global grant. A deactivated
// admin counts (the row can be reactivated); a tenant role named admin does
// not (it is no admin of the app).
func accountHoldsGlobalAdmin(q rowQuerier, uid int64) (bool, error) {
	var role sql.NullString
	if err := q.QueryRow("SELECT role FROM main._benmore_users WHERE id = ?", uid).Scan(&role); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	if role.String == "admin" {
		return true, nil
	}
	var grants int
	if err := q.QueryRow("SELECT COUNT(*) FROM main.sqlite_master WHERE type = 'table' AND name = '_benmore_user_roles'").Scan(&grants); err != nil {
		return false, err
	}
	if grants == 0 {
		return false, nil
	}
	return userHasGlobalAdminGrantWithSchema(q, uid, "main")
}
