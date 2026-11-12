//go:build !cli

package main

// The last-admin guard. An app keeps at least one account that can manage it:
// an admin who can sign in now and will still be an admin tomorrow. Every
// app-facing change that can end an account's admin standing asks
// refuseLastDurableAdmin first, inside the transaction that makes the change:
//
//   - demoting the primary role (/_admin/set-role)
//   - revoking a global admin grant, or giving it an expiry (role API)
//   - deactivating or unverifying the account in the admin panel
//   - deleting the account (/settings/delete-account, the dashboard's
//     Delete account) or purging it (run: purge_current_user)
//
// The guard used to count every unexpired admin grant and every admin row,
// so the only durable admin could step down beside a two-minute grant and
// the app had no admin once it lapsed. Operator paths (delete_app_user,
// benmore users) are not guarded: the operator can always make a new admin.

import (
	"database/sql"
	"errors"
	"strconv"
)

// errLastDurableAdmin is the refusal. Callers add their own wording; the text
// always says what to do instead.
var errLastDurableAdmin = errors.New("this is the app's last active admin: make another account an admin with no expiry first")

// lastAdminRefusal is the 400 body text of the role routes' refusal.
const lastAdminRefusal = "cannot remove admin from the last active admin: make another account an admin (role admin, or a global admin grant with no expiry) first"

// lastAdminAccountRefusal is the refusal for deactivating, unverifying or
// deleting the last admin's account through generic CRUD (the admin panel).
const lastAdminAccountRefusal = "cannot deactivate or delete the last active admin: make another account an admin (role admin, or a global admin grant with no expiry) first"

// adminStandingChange names what a guarded change takes away.
type adminStandingChange int

const (
	// dropsPrimaryAdmin: _benmore_users.role leaves admin.
	dropsPrimaryAdmin adminStandingChange = iota
	// dropsGlobalAdminGrant: the global (group_id IS NULL) admin grant is
	// revoked or gets an expiry.
	dropsGlobalAdminGrant
	// dropsAccount: the account stops being usable (deleted, purged,
	// deactivated, unverified).
	dropsAccount
)

// The queries name main. explicitly: a guard that runs inside a flow's
// transaction must not read a TEMP table an earlier step created under the
// same name.

// durableAdminWhere selects, from _benmore_users u, the accounts that count
// as usable durable admins:
//   - usable: not deactivated, not held at a temporary password (every
//     session lookup refuses such an account), and verified when the app
//     sets auth.require_verified (getSession refuses an unverified one);
//   - durable: admin by the role column, or by a global admin grant with no
//     expiry. A time-bounded grant does not count: when it lapses the account
//     is no longer an admin. Group-scoped admin grants never confer
//     app-wide admin (Session.GlobalAdmin), so they do not count either.
func durableAdminWhere(app *App, grants bool) string {
	where := `COALESCE(CAST(u.deactivated_at AS TEXT), '') = ''
		AND COALESCE(u.password_change_required, 0) = 0`
	if appRequiresVerified(app) {
		where += ` AND COALESCE(u.verified, 0) = 1`
	}
	admin := `COALESCE(u.role, 'user') = 'admin'`
	if grants {
		admin += ` OR EXISTS (SELECT 1 FROM main._benmore_user_roles g
			WHERE g.user_id = u.id AND g.role = 'admin' AND g.group_id IS NULL AND g.expires_at IS NULL)`
	}
	return where + ` AND (` + admin + `)`
}

func appRequiresVerified(app *App) bool {
	return app != nil && app.Design != nil && app.Design.Auth["require_verified"] == "true"
}

// durableAdminCounts reports whether uid is a usable durable admin and how
// many other accounts are.
func durableAdminCounts(app *App, q rowQuerier, uid int64) (self bool, others int, err error) {
	var n int
	if err := q.QueryRow(`SELECT COUNT(*) FROM main.sqlite_master WHERE type = 'table' AND name = '_benmore_user_roles'`).Scan(&n); err != nil {
		return false, 0, err
	}
	var mine int
	err = q.QueryRow(`SELECT
			COALESCE(SUM(CASE WHEN u.id = ? THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN u.id <> ? THEN 1 ELSE 0 END), 0)
		FROM main._benmore_users u WHERE `+durableAdminWhere(app, n > 0), uid, uid).Scan(&mine, &others)
	return mine > 0, others, err
}

// refuseLastDurableAdmin returns errLastDurableAdmin when account uid is a
// usable durable admin, the change would end that standing, and no other
// account is one. Run it in the transaction that makes the change, so two
// admins stepping down at once cannot both pass.
func refuseLastDurableAdmin(app *App, q rowQuerier, uid int64, change adminStandingChange) error {
	if q == nil || uid <= 0 {
		return nil
	}
	if keepsDurableAdmin(q, uid, change) {
		return nil
	}
	self, others, err := durableAdminCounts(app, q, uid)
	if err != nil {
		return err
	}
	if self && others == 0 {
		return errLastDurableAdmin
	}
	return nil
}

// keepsDurableAdmin reports whether account uid stays a durable admin through
// its other standing after change: a durable global grant beside the primary
// role, or the primary role beside the grant.
func keepsDurableAdmin(q rowQuerier, uid int64, change adminStandingChange) bool {
	switch change {
	case dropsPrimaryAdmin:
		var held int
		err := q.QueryRow(`SELECT COUNT(*) FROM main._benmore_user_roles
			WHERE user_id = ? AND role = 'admin' AND group_id IS NULL AND expires_at IS NULL`, uid).Scan(&held)
		return err == nil && held > 0
	case dropsGlobalAdminGrant:
		var role sql.NullString
		err := q.QueryRow(`SELECT role FROM main._benmore_users WHERE id = ?`, uid).Scan(&role)
		return err == nil && role.String == "admin"
	}
	return false
}

// adminDemotionProtectedCode is the stable code of refuseDemotingAnotherAdmin's
// refusal.
const adminDemotionProtectedCode = "admin_demotion_protected"

// adminDemotionRefusal is its message.
const adminDemotionRefusal = "cannot take admin away from another admin: an admin steps down only from their own account. " +
	"To cut another admin off, deactivate the account (deactivated_at); nothing was changed."

// refuseDemotingAnotherAdmin refuses a change by actor that ends, or puts an
// expiry on, another account's global admin standing. An admin's sign-in
// address cannot be changed by another admin (user_identifier_update.go); a
// demotion first would lift that, so no admin demotes another. Run it in the
// change's transaction, beside refuseLastDurableAdmin. A deactivated admin is
// still an admin here: deactivation is how one admin cuts another off.
func refuseDemotingAnotherAdmin(q rowQuerier, actor *Session, uid int64, change adminStandingChange) (refused bool, err error) {
	if q == nil || uid <= 0 || (actor != nil && actor.UserID == uid) {
		return false, nil
	}
	admin, err := accountHoldsGlobalAdmin(q, uid)
	if err != nil || !admin {
		return false, err
	}
	return !keepsDurableAdmin(q, uid, change), nil
}

// lastDurableAdminUpdate guards a generic update of a _benmore_users row (the
// admin panel's inline editor writes deactivated_at and verified). It returns
// a check to run once the row is written: the check refuses when the row was
// the last usable durable admin before the write and no longer is. Edits that
// leave the account an admin (a name, an address) pass. Other tables and rows
// get a check that does nothing.
func lastDurableAdminUpdate(app *App, q rowQuerier, table, id string) (func() error, error) {
	noop := func() error { return nil }
	if !identIs(table, "_benmore_users") {
		return noop, nil
	}
	uid, err := strconv.ParseInt(id, 10, 64)
	if err != nil || uid <= 0 {
		return noop, nil
	}
	if err := refuseLastDurableAdmin(app, q, uid, dropsAccount); err == nil {
		return noop, nil
	} else if !errors.Is(err, errLastDurableAdmin) {
		return nil, err
	}
	return func() error {
		self, _, err := durableAdminCounts(app, q, uid)
		if err != nil {
			return err
		}
		if !self {
			return errLastDurableAdmin
		}
		return nil
	}, nil
}

// refuseLastAdminRowDelete guards a generic CRUD delete of a _benmore_users
// row (the admin panel's delete, batch delete, /api/_transaction): deleting
// the last usable durable admin is a *mutationValidationError naming what to
// do instead. Other tables pass.
func refuseLastAdminRowDelete(app *App, q rowQuerier, table, id string) error {
	if !identIs(table, "_benmore_users") {
		return nil
	}
	uid, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return nil
	}
	err = refuseLastDurableAdmin(app, q, uid, dropsAccount)
	if errors.Is(err, errLastDurableAdmin) {
		return &mutationValidationError{err: errors.New(lastAdminAccountRefusal)}
	}
	return err
}
