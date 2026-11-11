//go:build !cli

package main

// Bulk import - row ownership for owner-token imports.
//
// Mode A fills the owner column (user_id) the way an auto-CRUD create does:
// an admin-session import owns its rows. An owner token (`benmore import`)
// is a platform credential with no user in this app, so on its own it can
// only leave rows unowned, and a table whose user_id is NOT NULL (the
// scaffold's own Note) failed every row with a raw constraint error. The
// create request's "owner" (CLI: --owner <email>) names an existing user of
// THIS app; every row is assigned to that user. user_id stays protected:
// the file can never set it, only the owner-token caller's chosen owner.

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// importOwnerColumn returns the table's owner column (user_id), if any.
func importOwnerColumn(db *sql.DB, table string) (Column, bool, error) {
	cols, err := GetTableColumns(db, table)
	if err != nil {
		return Column{}, false, err
	}
	for _, c := range cols {
		if identIs(c.Name, "user_id") {
			return c, true, nil
		}
	}
	return Column{}, false, nil
}

// importOwnerRequired reports whether every row of table must carry an owner:
// its user_id is NOT NULL with no default, so an unowned INSERT always fails.
func importOwnerRequired(c Column) bool {
	d := strings.TrimSpace(c.Default)
	return c.NotNull && (d == "" || strings.EqualFold(d, "NULL"))
}

// errImportOwnerNeeded is the up-front refusal for an owner-token import into
// a table that requires an owner, in place of a NOT NULL error on row 1.
func errImportOwnerNeeded(table string) error {
	return fmt.Errorf("table %s requires an owner for every row (its user_id column is NOT NULL), and an owner-token import has no user in this app to own them. Re-run with --owner <email> (API: \"owner\") naming an existing user of this app; every imported row is assigned to that user", table)
}

// checkImportOwnerPlan validates the owner a Mode A session will write before
// any byte uploads (create) and again before the load (run): a chosen owner
// needs an owner column, and a table that requires one gets a clear refusal
// when the caller has neither a session user nor a chosen owner.
func checkImportOwnerPlan(db *sql.DB, table string, createdBy, ownerUserID int64) error {
	col, ok, err := importOwnerColumn(db, table)
	if err != nil {
		return err
	}
	if ownerUserID != 0 && !ok {
		return fmt.Errorf("--owner applies only to a table with a user_id owner column; %s has none", table)
	}
	if ok && createdBy == 0 && ownerUserID == 0 && importOwnerRequired(col) {
		return errImportOwnerNeeded(table)
	}
	return nil
}

// resolveImportOwner maps an email to an active user of THIS app (app.DB is
// one app instance's database, so another app's or instance's accounts are
// unreachable). It returns the user id and the stored email.
func resolveImportOwner(db *sql.DB, email string) (int64, string, error) {
	email = strings.TrimSpace(email)
	if email == "" || !strings.Contains(email, "@") {
		return 0, "", fmt.Errorf("owner must be the email address of an existing user of this app")
	}
	rows, err := db.Query(`SELECT id, COALESCE(email, ''), deactivated_at IS NOT NULL
		FROM _benmore_users WHERE email = ? COLLATE NOCASE LIMIT 2`, email)
	if err != nil {
		if strings.Contains(err.Error(), "no such table") {
			return 0, "", fmt.Errorf("owner %q: this app has no user accounts", email)
		}
		return 0, "", err
	}
	defer rows.Close()
	type match struct {
		id          int64
		email       string
		deactivated bool
	}
	var found []match
	for rows.Next() {
		var m match
		if err := rows.Scan(&m.id, &m.email, &m.deactivated); err != nil {
			return 0, "", err
		}
		found = append(found, m)
	}
	if err := rows.Err(); err != nil {
		return 0, "", err
	}
	switch {
	case len(found) == 0:
		return 0, "", fmt.Errorf("owner %q is not a user of this app; the owner must already have an account in this app (and in this environment)", email)
	case len(found) > 1:
		return 0, "", fmt.Errorf("owner %q matches more than one user of this app (emails differing only in case); fix the duplicate accounts first", email)
	case found[0].deactivated:
		return 0, "", fmt.Errorf("owner %q is a deactivated account; reactivate it or choose another owner", email)
	}
	return found[0].id, found[0].email, nil
}

// confirmImportOwnerTx re-checks, inside the load transaction, that the chosen
// owner still exists and is active: the account may have been deleted or
// deactivated between create and commit.
func confirmImportOwnerTx(tx *sql.Tx, ownerUserID int64) error {
	var one int
	err := tx.QueryRow(`SELECT 1 FROM _benmore_users WHERE id = ? AND deactivated_at IS NULL`, ownerUserID).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("the import's owner (user %d) no longer exists or was deactivated since the import was created; nothing was imported", ownerUserID)
	}
	return err
}
