//go:build !cli

package main

import "strings"

// An account is active only while _benmore_users.deactivated_at is NULL: the
// session and API-token lookups refuse every other stored value, the empty
// string included. A generic update of the row (the admin panel's edit form,
// which posts every field) wrote an emptied field as the empty string, so
// clearing the timestamp there did not reactivate the account, and saving
// the form of an active account (its field is blank) stored the empty string
// as well and ended its sessions.
//
// normalizeUserDeactivationValue is the one place that write is corrected:
// an empty or blank deactivated_at in a _benmore_users update becomes NULL.
// It changes what is written, never how a stored value is read: a row that
// already holds the empty string stays refused until it is written again
// (the panel, or `benmore users <app> reactivate`).
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
