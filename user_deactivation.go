//go:build !cli

package main

import (
	"database/sql"
	"strings"
)

// An account is active only while _benmore_users.deactivated_at is NULL.
// Every other stored value is deactivated: a timestamp, and also the empty
// string, which the admin panel's edit form used to write on every save
// (it posts every field, and an active account's field is blank).
//
// That is ONE reading, and these three helpers are its only spelling. Every
// place that asks "may this account act?" uses them: each sign-in method,
// the session and API-token lookups, the stored actors of jobs and scheduled
// tasks, the last-admin guard, the user directory. Spelling it locally is
// how the readings drifted apart: `COALESCE(deactivated_at, '') = ''` took
// the empty string for active while the session lookup, which reads the
// column raw (the driver hands a DATETIME column's unparseable text over as
// a zero time), refused it, so such an account signed in and its new
// session was refused on the next request.
//
// Nothing here rewrites a stored value: a row holding the empty string stays
// deactivated until it is written again (emptying the field in the panel,
// or `benmore users <app> reactivate`, both of which store NULL).

// accountActiveSQL is the SQL condition "this _benmore_users row is active".
// alias is how the query names the table ("u", "main._benmore_users"), or ""
// for a bare column.
func accountActiveSQL(alias string) string {
	return deactivatedAtColumn(alias) + " IS NULL"
}

// accountDeactivatedSQL is its negation.
func accountDeactivatedSQL(alias string) string {
	return deactivatedAtColumn(alias) + " IS NOT NULL"
}

func deactivatedAtColumn(alias string) string {
	if alias == "" {
		return "deactivated_at"
	}
	return alias + ".deactivated_at"
}

// accountDeactivated is the same reading of a scanned deactivated_at.
func accountDeactivated(stored sql.NullString) bool {
	return stored.Valid
}

// normalizeUserDeactivationValue keeps a generic update of the row (the admin
// panel's edit form) from storing the empty string: an empty or blank
// deactivated_at in a _benmore_users update becomes NULL, so emptying the
// field reactivates the account and saving an active account's form leaves
// it active.
func normalizeUserDeactivationValue(table string, values map[string]any) {
	if !identIs(table, "_benmore_users") {
		return
	}
	for key, value := range values {
		if !identIs(key, "deactivated_at") {
			continue
		}
		if text, ok := value.(string); ok && strings.TrimSpace(text) == "" {
			values[key] = nil
		}
	}
}
