//go:build !cli

package main

// A restore does not bring back a role that was taken away.
//
// The credential carry-forward (restore_credentials.go) keeps the live
// passwords, factors and deactivations. Authorization went back to the
// snapshot: an account whose admin role or grant was removed after the
// snapshot had it again, while the carried audit rows said it was revoked.
// carryForwardRestoreRoles, in the credential transaction, leaves every
// account with no more than it holds in BOTH databases:
//
//   - Primary role (_benmore_users.role) of an account present in both: the
//     lower of the snapshot's and the live one (lowerPrimaryRole). admin is
//     above every role and the default role below every role; two other
//     roles have no order the database knows, so the live one stands.
//   - Role grant (_benmore_user_roles) of an account present in both: kept
//     only when the live database holds the same grant (account, role, group)
//     and it has not expired there; its expiry is the earlier of the two.
//   - Nothing gained since the snapshot is added: a restore may take
//     privilege away, never hand any out.
//   - An account only in the snapshot that the live database once held
//     (deleted since) comes back with the default role and no grants. The
//     evidence is the live database's own (liveAccountEvidence): the id is
//     at or below the highest account id it ever handed out, or one of its
//     audit rows is about the account. An erased account keeps its row (a
//     tombstone), so it is an account present in both.
//   - An account only in the snapshot that the live database never held (a
//     recreated or different database: the restore is disaster recovery)
//     keeps the snapshot's role and grants. Sessions can be issued again;
//     role assignments are the app's data and cannot be rebuilt. Counted.
//
// The app must keep an admin who can sign in, counted as the last-admin guard
// counts (durableAdminWhere, with the app's auth.require_verified read from
// the app.yaml beside the database: restoreVerifiedSetting). When the rule
// leaves none, accounts that are durable admins NOW keep that standing
// (nobody gets back a role that was taken away); when the snapshot holds no
// such account either, the snapshot's own admin roles and global admin grants
// are kept, revoked ones included. Both are counted, named in the summary's
// warning and logged. An app.yaml that cannot be read leaves the setting
// unknown: only verified admins then count, so an admin who can sign in
// either way is kept, but a revoked admin role comes back only when the app
// has no admin under either reading.
//
// With no readable live database nothing says what was revoked: roles stay as
// the snapshot has them and the summary says why. refresh-dev's copy keeps its
// roles too (dev holds no role state for production's accounts).
//
// Record-level grants (_benmore_permissions) follow the same never-revive
// rule in restore_record_grants.go. Not covered, on purpose: membership-table
// rows and the roles an app keeps in them (groups.role_field) are the app's
// data and roll back with it.

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strconv"
	"strings"
)

// restoreVerifiedUnknown is restoreRoleSummary.RequireVerified when app.yaml
// could not be read.
const restoreVerifiedUnknown = "unknown"

// restoreVerifiedRule is the app's auth.require_verified as a restore knows it.
type restoreVerifiedRule struct {
	required bool
	known    bool
	reason   string // why it is not known
}

// restoreVerifiedSetting reads auth.require_verified from the app.yaml in
// appDir, the way the runtime loads it. Every restore path has the app
// directory (the hosted one runs in the instance's own helper). No app.yaml
// is the runtime's "not required". One that cannot be read or parsed leaves
// the setting unknown.
func restoreVerifiedSetting(appDir string) restoreVerifiedRule {
	if appDir == "" {
		return restoreVerifiedRule{reason: "no app directory"}
	}
	data, err := readOptionalConfig(appDir, "app.yaml")
	if err != nil {
		return restoreVerifiedRule{reason: err.Error()}
	}
	raw, _, err := parseAppConfigDocument(data)
	if err != nil {
		return restoreVerifiedRule{reason: err.Error()}
	}
	rule := restoreVerifiedRule{known: true}
	if raw != nil {
		rule.required = appRequiresVerified(&App{Design: designFromAppYAML(raw)})
	}
	return rule
}

// label is the rule in the summary: "" when verification is not required.
func (v restoreVerifiedRule) label() string {
	switch {
	case !v.known:
		return restoreVerifiedUnknown
	case v.required:
		return "true"
	}
	return ""
}

const (
	restoreRoleGrantsTable = "_benmore_user_roles"
	// restoreRoleColumn is the primary role on the account row.
	restoreRoleColumn  = "role"
	restoreAdminRole   = "admin"
	restoreDefaultRole = "user" // the column default: what a new account holds

	// restoreSequenceTable is where SQLite keeps the highest id an
	// AUTOINCREMENT table ever handed out.
	restoreSequenceTable = "sqlite_sequence"
	// restoreLiveAuditAccounts keys, in the live state, the row ids of the live
	// audit rows about accounts. No table has this name.
	restoreLiveAuditAccounts = "\x00audit rows about accounts"

	// Whose admin standing was kept because the rule left no usable admin.
	restoreAdminsKeptLive     = "live"
	restoreAdminsKeptSnapshot = "snapshot"
)

// restoreRoleSummary reports what a restore did to roles. Counts only.
type restoreRoleSummary struct {
	// Skipped: why roles were left as the snapshot has them
	// (restoreAuditSkippedUnreadable, restoreAuditSkippedNoLive).
	Skipped string `json:"skipped,omitempty"`
	// PrimaryLowered: accounts in both databases whose primary role is now the
	// live, lower one.
	PrimaryLowered int `json:"primary_lowered"`
	// PrimaryReset: accounts deleted since the snapshot, back with the default role.
	PrimaryReset int `json:"primary_reset"`
	// KeptUnknown: snapshot accounts the live database never held, which keep
	// the snapshot's role and grants. Note says so in a sentence.
	KeptUnknown int    `json:"roles_kept_unknown"`
	Note        string `json:"note,omitempty"`
	// GrantsKept / GrantsRemoved: snapshot role grants still held live, and the
	// ones revoked, expired or belonging to an account deleted since.
	GrantsKept    int `json:"grants_kept"`
	GrantsRemoved int `json:"grants_removed"`
	// GrantsShortened: kept grants that took an earlier live expiry.
	GrantsShortened int `json:"grants_expiry_shortened"`
	// AdminsKept: whose admin standing was kept against the rule because it
	// left no admin who can sign in (restoreAdminsKept*), and how many roles
	// and grants that was.
	AdminsKept      string `json:"admins_kept,omitempty"`
	AdminsKeptCount int    `json:"admins_kept_count,omitempty"`
	// UsableAdmins: accounts in the restored database that are admins with no
	// expiry and can sign in.
	UsableAdmins int `json:"usable_admins"`
	// RequireVerified: "true" when the app's auth.require_verified is on (an
	// admin with an unverified email is then no usable admin), "unknown" when
	// app.yaml could not be read (only verified admins are counted).
	RequireVerified string `json:"require_verified,omitempty"`
	Warning         string `json:"warning,omitempty"`
}

// restoreRoleName is a stored primary role as the guards read it: the exact
// text, and the default role when there is none.
func restoreRoleName(v any) string {
	if role := credText(v); role != "" {
		return role
	}
	return restoreDefaultRole
}

// lowerPrimaryRole is the primary role an account present in both databases
// holds after a restore: never one above what it holds live, and never one
// gained since the snapshot where the two can be ordered.
func lowerPrimaryRole(snapshot, live string) string {
	switch {
	case snapshot == live:
		return snapshot
	case snapshot == restoreAdminRole:
		return live // taken away since
	case live == restoreAdminRole:
		return snapshot // gained since
	case snapshot == restoreDefaultRole || live == restoreDefaultRole:
		return restoreDefaultRole
	}
	// Two named roles: which is lower is the app's business, not the
	// database's. The live one is the one the account holds now.
	return live
}

// restoreGrantKey identifies a role grant: account, role and group (NULL is
// the global grant).
func restoreGrantKey(t *credTable, i int, user int64) string {
	return strconv.FormatInt(user, 10) + "\x00" + credText(t.get(i, "role")) + "\x00" + credKey(t.get(i, "group_id"))
}

// restoreGlobalAdminGrant reports whether row i grants admin app-wide.
func restoreGlobalAdminGrant(t *credTable, i int) bool {
	return credText(t.get(i, "role")) == restoreAdminRole && t.get(i, "group_id") == nil
}

// readLiveAccountEvidence adds to the live state what the live database knows
// of accounts it no longer holds: its id sequences and the row ids of its
// audit rows about accounts. Evidence that cannot be read is absent, never a
// reason to treat the whole live database as unreadable (which would leave
// every role as the snapshot has it).
func readLiveAccountEvidence(ctx context.Context, q credQuerier, state map[string]*credTable) {
	if t, err := readCredTable(ctx, q, restoreSequenceTable, false, nil); err != nil {
		log.Printf("restore: the live id sequences could not be read (%v)", err)
	} else if t != nil {
		state[restoreSequenceTable] = t
	}
	audit, err := readCredTable(ctx, q, auditLogTable, false, []string{})
	if err != nil || audit == nil || !audit.has["table_name"] || !audit.has["row_id"] {
		return
	}
	t := &credTable{cols: []string{"row_id"}, has: map[string]bool{"row_id": true}, sel: map[string]int{"row_id": 0}}
	rows, err := q.QueryContext(ctx, "SELECT DISTINCT +row_id FROM "+auditLogTable+" WHERE table_name = '_benmore_users'")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var v any
			if err = rows.Scan(&v); err != nil {
				break
			}
			t.rows = append(t.rows, []any{v})
		}
		if err == nil {
			err = rows.Err()
		}
	}
	if err != nil {
		log.Printf("restore: the live audit rows about accounts could not be read (%v)", err)
		return
	}
	state[restoreLiveAuditAccounts] = t
}

// liveAccountEvidence reports whether the live database ever held an account
// with the given id: the id is at or below the highest account id it handed
// out (the AUTOINCREMENT sequence of _benmore_users, and the highest id it
// holds, which is all there is for a table without one), or one of its audit
// rows is about that account (its deletion or erasure among them).
func liveAccountEvidence(live map[string]*credTable) func(id int64) bool {
	var high int64
	if seq := live[restoreSequenceTable]; seq != nil {
		for i := range seq.rows {
			if n, ok := credInt(seq.get(i, "seq")); ok && credText(seq.get(i, "name")) == "_benmore_users" && n > high {
				high = n
			}
		}
	}
	if lu := live["_benmore_users"]; lu != nil {
		for i := range lu.rows {
			if id, ok := credInt(lu.get(i, "id")); ok && id > high {
				high = id
			}
		}
	}
	audited := map[int64]bool{}
	if rows := live[restoreLiveAuditAccounts]; rows != nil {
		for i := range rows.rows {
			if id, ok := credInt(rows.get(i, "row_id")); ok {
				audited[id] = true
			}
		}
	}
	return func(id int64) bool { return id <= high || audited[id] }
}

// carryForwardRestoreRoles applies the live role state to the candidate.
// skipped names why there is no live state ("" when live is set).
func carryForwardRestoreRoles(ctx context.Context, tx *sql.Tx, live map[string]*credTable, pairs map[int64]int64, skipped string, verified restoreVerifiedRule) (*restoreRoleSummary, error) {
	summary := &restoreRoleSummary{Skipped: skipped}
	if live == nil {
		return summary, nil
	}
	summary.RequireVerified = verified.label()
	users, err := readCredTable(ctx, tx, "_benmore_users", true, []string{"id", restoreRoleColumn})
	if err != nil || users == nil || !users.has["id"] {
		return summary, err
	}
	grants, err := readCredTable(ctx, tx, restoreRoleGrantsTable, true, nil)
	if err != nil {
		return nil, err
	}
	if grants != nil {
		for _, col := range []string{"user_id", "role"} {
			if !grants.has[col] {
				return nil, fmt.Errorf("role grant column %s is missing", col)
			}
		}
	}
	lu, lg := live["_benmore_users"], live[restoreRoleGrantsTable]
	if lg != nil && !(lg.has["user_id"] && lg.has["role"]) {
		lg = nil // no comparable live grant: none survives
	}
	liveRole := map[int64]string{}
	if lu != nil && lu.has["id"] {
		for i := range lu.rows {
			if id, ok := credInt(lu.get(i, "id")); ok {
				liveRole[id] = restoreRoleName(lu.get(i, restoreRoleColumn))
			}
		}
	}
	candidateOf := map[int64]int64{} // live account id -> candidate account id
	for candidateID, liveID := range pairs {
		if prev, dup := candidateOf[liveID]; !dup || candidateID < prev {
			candidateOf[liveID] = candidateID
		}
	}

	// Snapshot accounts the live database never held keep what they have.
	heldLive := liveAccountEvidence(live)
	unknown := map[int64]bool{}
	for i := range users.rows {
		id, ok := credInt(users.get(i, "id"))
		if _, matched := pairs[id]; ok && !matched && !heldLive(id) {
			unknown[id] = true
		}
	}
	if summary.KeptUnknown = len(unknown); summary.KeptUnknown > 0 {
		summary.Note = fmt.Sprintf("%d account(s) of the snapshot were never in the replaced database (their ids are above every account id it handed out and none of its audit rows is about them), so they keep the snapshot's role and role grants.", summary.KeptUnknown)
	}

	// What the two fallbacks need, should the rule leave no usable admin.
	var (
		wasAdmin    []int64           // rowids of accounts the rule took the primary admin role from
		liveAdmins  []int64           // rowids of accounts that are admins live and are not after the rule
		adminGrants [][]any           // the snapshot's global admin grants the rule removed
		shortened   = map[int64]any{} // rowid of a shortened global admin grant -> the snapshot's expiry
	)
	setRole := func(rowid int64, role string) error {
		return updateRow(ctx, tx, "_benmore_users", rowid, []string{restoreRoleColumn}, []any{role})
	}
	if users.has[restoreRoleColumn] {
		for i := range users.rows {
			id, _ := credInt(users.get(i, "id"))
			if unknown[id] {
				continue
			}
			had := restoreRoleName(users.get(i, restoreRoleColumn))
			want := restoreDefaultRole
			lid, matched := pairs[id]
			if matched {
				now, known := liveRole[lid]
				if !known {
					now = restoreDefaultRole
				}
				want = lowerPrimaryRole(had, now)
				if now == restoreAdminRole && want != restoreAdminRole {
					liveAdmins = append(liveAdmins, users.rowid[i])
				}
			}
			if want == had {
				continue
			}
			if err := setRole(users.rowid[i], want); err != nil {
				return nil, err
			}
			if had == restoreAdminRole {
				wasAdmin = append(wasAdmin, users.rowid[i])
			}
			if matched {
				summary.PrimaryLowered++
			} else {
				summary.PrimaryReset++
			}
		}
	}

	liveGrant := map[string]int{}
	if lg != nil {
		for i := range lg.rows {
			if id, ok := credInt(lg.get(i, "user_id")); ok {
				liveGrant[restoreGrantKey(lg, i, id)] = i
			}
		}
	}
	held := map[string]int{} // grants the candidate keeps -> their row
	if grants != nil {
		for i := range grants.rows {
			match := -1
			id, ok := credInt(grants.get(i, "user_id"))
			if ok && unknown[id] {
				summary.GrantsKept++
				continue
			}
			if lid, matched := pairs[id]; ok && matched {
				if j, found := liveGrant[restoreGrantKey(grants, i, lid)]; found {
					match = j
				}
			}
			// The runtime's own test of a grant (LoadSessionRoles), on the live
			// expiry; and whether that expiry is the earlier of the two.
			var current, earlier bool
			if match >= 0 {
				if current, earlier, err = restoreLiveExpiry(ctx, tx, lg.get(match, "expires_at"), grants.get(i, "expires_at")); err != nil {
					return nil, err
				}
			}
			if !current {
				if _, err := tx.ExecContext(ctx, "DELETE FROM "+restoreRoleGrantsTable+" WHERE rowid = ?", grants.rowid[i]); err != nil {
					return nil, err
				}
				if restoreGlobalAdminGrant(grants, i) {
					adminGrants = append(adminGrants, grants.rows[i])
				}
				summary.GrantsRemoved++
				continue
			}
			if earlier && grants.has["expires_at"] {
				if err := updateRow(ctx, tx, restoreRoleGrantsTable, grants.rowid[i], []string{"expires_at"}, []any{lg.get(match, "expires_at")}); err != nil {
					return nil, err
				}
				if restoreGlobalAdminGrant(grants, i) {
					shortened[grants.rowid[i]] = grants.get(i, "expires_at")
				}
				summary.GrantsShortened++
			}
			held[restoreGrantKey(grants, i, id)] = i
			summary.GrantsKept++
		}
	}

	count := func(requireVerified bool) (n int, err error) {
		err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM _benmore_users u WHERE "+restoreUsableAdminWhere(users, grants, requireVerified)).Scan(&n)
		return n, err
	}
	// With the setting unknown only an admin who can sign in either way counts.
	usable := func() (int, error) { return count(verified.required || !verified.known) }
	if summary.UsableAdmins, err = usable(); err != nil || summary.UsableAdmins > 0 {
		return summary, err
	}

	// 1. Accounts that are durable admins now keep that standing: it is theirs
	// today, so nothing that was taken away comes back.
	kept := 0
	for _, rowid := range liveAdmins {
		if err := setRole(rowid, restoreAdminRole); err != nil {
			return nil, err
		}
		kept++
	}
	if lg != nil && grants != nil {
		cols := present(grants.cols, lg)
		for i := range lg.rows {
			lid, ok := credInt(lg.get(i, "user_id"))
			id, matched := candidateOf[lid]
			if !ok || !matched || !restoreGlobalAdminGrant(lg, i) || lg.get(i, "expires_at") != nil {
				continue
			}
			if k, has := held[restoreGrantKey(lg, i, id)]; has {
				if grants.get(k, "expires_at") != nil {
					// The snapshot's grant runs out; the live one does not.
					if err := updateRow(ctx, tx, restoreRoleGrantsTable, grants.rowid[k], []string{"expires_at"}, []any{nil}); err != nil {
						return nil, err
					}
					kept++
				}
				continue
			}
			values := make([]any, len(cols))
			for k, col := range cols {
				values[k] = lg.get(i, col)
				if col == "user_id" {
					values[k] = id
				}
			}
			if err := restoreInsertGrant(ctx, tx, cols, values); err != nil {
				return nil, err
			}
			kept++
		}
	}
	if kept > 0 {
		summary.AdminsKept, summary.AdminsKeptCount = restoreAdminsKeptLive, kept
		if summary.UsableAdmins, err = usable(); err != nil {
			return nil, err
		}
	}

	// The setting is unknown and no admin has a verified email: when the app
	// has an admin under the reading that the setting is off, nothing that was
	// taken away comes back on a guess.
	unverifiedOnly := 0
	if summary.UsableAdmins == 0 && !verified.known {
		if unverifiedOnly, err = count(false); err != nil {
			return nil, err
		}
	}

	// 2. No current admin is in the snapshot: its own admins keep their
	// standing, revoked ones included. Locking the app out is worse.
	if summary.UsableAdmins == 0 && unverifiedOnly == 0 {
		revived := 0
		for _, rowid := range wasAdmin {
			if err := setRole(rowid, restoreAdminRole); err != nil {
				return nil, err
			}
			revived++
		}
		for _, row := range adminGrants {
			if err := restoreInsertGrant(ctx, tx, grants.cols, row); err != nil {
				return nil, err
			}
			revived++
		}
		for rowid, expiry := range shortened {
			if err := updateRow(ctx, tx, restoreRoleGrantsTable, rowid, []string{"expires_at"}, []any{expiry}); err != nil {
				return nil, err
			}
			revived++
		}
		if revived > 0 {
			summary.AdminsKept, summary.AdminsKeptCount = restoreAdminsKeptSnapshot, kept+revived
			if summary.UsableAdmins, err = usable(); err != nil {
				return nil, err
			}
		}
	}
	switch summary.AdminsKept {
	case restoreAdminsKeptLive:
		summary.Warning = fmt.Sprintf("Taking the snapshot's roles would have left the app without an admin who can sign in, so %d admin role(s) or grant(s) held now were kept although the snapshot does not have them. Review who is an admin.", summary.AdminsKeptCount)
	case restoreAdminsKeptSnapshot:
		summary.Warning = fmt.Sprintf("No account that is an admin now exists in the snapshot, so %d admin role(s) or grant(s) of the snapshot were kept, including ones removed since it was taken. Review who is an admin and remove the ones that should not be.", summary.AdminsKeptCount)
	}
	if summary.UsableAdmins == 0 && unverifiedOnly > 0 {
		summary.Warning = strings.TrimSpace(summary.Warning + fmt.Sprintf(" The app's auth.require_verified setting could not be read (%s) and none of its %d admin(s) has a verified email: if the setting is on, no admin can sign in until one verifies their email or a verified account is made an admin.", verified.reason, unverifiedOnly))
	}
	if summary.Warning != "" {
		log.Printf("restore: WARNING: %s (%d usable admin(s) in the restored database)", summary.Warning, summary.UsableAdmins)
	}
	return summary, nil
}

// restoreInsertGrant adds one role grant row to the candidate.
func restoreInsertGrant(ctx context.Context, tx *sql.Tx, cols []string, values []any) error {
	_, err := tx.ExecContext(ctx, "INSERT INTO "+restoreRoleGrantsTable+" ("+strings.Join(quoteIdents(cols), ", ")+") VALUES (?"+strings.Repeat(", ?", len(cols)-1)+")", values...)
	return err
}

// restoreUsableAdminWhere selects, from the candidate's _benmore_users u, the
// accounts the last-admin guard counts. It IS the guard's condition
// (durableAdminWhere) whenever the snapshot has every column that reads; a
// snapshot that predates one gets the same condition without the missing
// column, which then restricts nothing.
func restoreUsableAdminWhere(users, grants *credTable, requireVerified bool) string {
	current := users.has[restoreRoleColumn] && users.has["deactivated_at"] && users.has["password_change_required"] && users.has["verified"] &&
		(grants == nil || (grants.has["group_id"] && grants.has["expires_at"]))
	if current {
		app := &App{Design: &DesignConfig{Auth: map[string]string{"require_verified": strconv.FormatBool(requireVerified)}}}
		return durableAdminWhere(app, grants != nil)
	}
	where := []string{"1"}
	if users.has["deactivated_at"] {
		where = append(where, accountActiveSQL("u"))
	}
	if users.has["password_change_required"] {
		where = append(where, "COALESCE(u.password_change_required, 0) = 0")
	}
	if requireVerified && users.has["verified"] {
		where = append(where, "COALESCE(u.verified, 0) = 1")
	}
	var admin []string
	if users.has[restoreRoleColumn] {
		admin = append(admin, "COALESCE(u.role, '"+restoreDefaultRole+"') = '"+restoreAdminRole+"'")
	}
	if grants != nil {
		grant := "g.user_id = u.id AND g.role = '" + restoreAdminRole + "'"
		for _, col := range []string{"group_id", "expires_at"} {
			if grants.has[col] {
				grant += " AND g." + col + " IS NULL"
			}
		}
		admin = append(admin, "EXISTS (SELECT 1 FROM main."+restoreRoleGrantsTable+" g WHERE "+grant+")")
	}
	if len(admin) == 0 {
		return "0"
	}
	return strings.Join(where, " AND ") + " AND (" + strings.Join(admin, " OR ") + ")"
}

// logLine is the role part of the restore's log line.
func (r *restoreRoleSummary) logLine() string {
	if r.Skipped != "" {
		return "roles left as the snapshot has them (" + r.Skipped + ")"
	}
	parts := []string{
		fmt.Sprintf("%d primary roles lowered to the live one", r.PrimaryLowered),
		fmt.Sprintf("%d reset on accounts deleted since", r.PrimaryReset),
		fmt.Sprintf("role grants: %d kept (%d with an earlier live expiry), %d removed", r.GrantsKept, r.GrantsShortened, r.GrantsRemoved),
		fmt.Sprintf("%d usable admins", r.UsableAdmins),
	}
	if r.KeptUnknown > 0 {
		parts = append(parts, fmt.Sprintf("%d accounts the replaced database never held keep the snapshot's roles", r.KeptUnknown))
	}
	if r.AdminsKept != "" {
		parts = append(parts, fmt.Sprintf("%d admin roles or grants kept from the %s state", r.AdminsKeptCount, r.AdminsKept))
	}
	return strings.Join(parts, "; ")
}
