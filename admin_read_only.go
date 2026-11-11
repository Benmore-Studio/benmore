//go:build !cli

package main

import "net/http"

// Framework tables the admin panel shows but never writes.
//
// The panel's write routes (POST /_admin/api/<table>/create|update|delete) run
// the generic CRUD handlers on whatever table the URL names, framework tables
// included. For most of those that is an admin editing app state. For two
// kinds it forges or destroys what the framework alone may write:
//
//   - the audit tables: a hand-made row says someone changed or read a record
//     they never touched (inserts pass the append-only triggers of a
//     compliance: hipaa app, which stop only changes to existing rows);
//   - the credential tables: sessions, tokens, passkeys, reset and sign-in
//     grants and the connector's stores are minted and revoked by the sign-in
//     code, with hashing, expiry, audit rows and revocation of what depends on
//     them. A row written by hand skips all of it.
//
// The credential set is the restore path's own registry (restore_credentials.go),
// which every credential-bearing framework table must join, so a new one is
// read-only here without another list to keep.

const (
	adminReadOnlyAudit      = "audit"
	adminReadOnlyCredential = "credential"
)

// adminReadOnlyKind reports why the admin panel does not write table: "" for
// a table it does. Names compare as SQLite compares them, so a URL naming
// _BENMORE_AUDIT_LOG is the same table.
func adminReadOnlyKind(table string) string {
	for _, name := range auditAppendOnlyTables {
		if identIs(table, name) {
			return adminReadOnlyAudit
		}
	}
	for _, spec := range restoreGrantTables {
		if identIs(table, spec.name) {
			return adminReadOnlyCredential
		}
	}
	for _, name := range restoreMCPTables {
		if identIs(table, name) {
			return adminReadOnlyCredential
		}
	}
	return ""
}

// adminReadOnlyMessage is the refusal (and the note on the table's page).
func adminReadOnlyMessage(table, kind string) string {
	if kind == adminReadOnlyAudit {
		return table + " is an audit table: the admin panel shows it and never writes it. The framework writes its rows as the events happen; none can be added, edited or deleted here."
	}
	return table + " holds sign-in credentials: the admin panel shows it and never writes it. Sessions, tokens, passkeys and reset grants are created and revoked through the sign-in and account endpoints."
}

// adminRefuseReadOnlyTable answers a panel write to a read-only table and
// reports whether it did.
func adminRefuseReadOnlyTable(w http.ResponseWriter, table string) bool {
	kind := adminReadOnlyKind(table)
	if kind == "" {
		return false
	}
	httpJSON(w, http.StatusForbidden, withRefusalDocs(map[string]any{
		"error":   "admin_table_read_only",
		"table":   table,
		"message": adminReadOnlyMessage(table, kind),
	}, "admin_table_read_only"))
	return true
}
