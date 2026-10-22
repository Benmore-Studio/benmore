//go:build !cli

package main

// Restoring a database snapshot rolls back data, never authentication state.
//
// A snapshot taken last week still holds last week's sessions and API tokens
// (including ones revoked since), last week's password hashes and MFA
// secrets, and reset/verification grants that were used or withdrawn since.
// Installing it as-is would bring all of that back. Before a restored
// database is installed, carryForwardRestoreCredentials rewrites the
// candidate's credential state from the live (pre-restore) database, in one
// transaction on the candidate, so a failure leaves the live database in
// place and the candidate unused:
//
//   - Accounts present in both keep the live password hash, MFA state
//     (sealed TOTP secret, backup codes, replay guard), deactivation,
//     password-change requirement, verification state and login identifiers.
//   - Sessions, API tokens, OAuth provider tokens, OAuth authorization codes
//     and clients, email-change, password-reset/verification and one-time
//     login grants survive only when the same credential exists live for
//     the same account; everything else is deleted. Nothing live-only is
//     added: a credential issued after the snapshot is not restored.
//   - Accounts only in the snapshot (deleted since) come back with no
//     sessions or tokens. A login identifier of theirs that now belongs to a
//     live account is cleared.
//   - Login-attempt lockout state is the live state.
//   - MCP connector grants, their access/refresh credentials and pending
//     authorizations (_benmore_mcp_*) are the live rows, wholesale
//     (carryForwardMCPGrants): a revoked grant stays revoked, a used refresh
//     token stays used, a grant issued after the snapshot survives. Only rows
//     of accounts that exist in the restored database are kept.
//
// Values are compared and copied in their stored form: session ids through
// their stored (hashed) key, TOTP secrets sealed, token hashes as hashes.
// Nothing is decrypted or rehashed from a secret.
//
// If the live database cannot be read (the usual reason for a restore is a
// damaged one) or does not exist, nothing is known to be live: every session,
// token and grant in the snapshot is deleted and account credentials stay as
// the snapshot has them; MCP grants are marked revoked and their credentials
// and authorizations deleted. The summary says which mode ran.
//
// A new credential-bearing framework table must join restoreGrantTables (a
// snapshot row survives only when still live), restoreLiveStateTables (live
// rows replace the snapshot's) or restoreMCPTables (connector stores).

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"slices"
	"strconv"
	"strings"
)

const (
	restoreCredentialsCarried    = "carried_forward"
	restoreCredentialsUnreadable = "live_unreadable_revoked_all"
	restoreCredentialsNoLive     = "no_live_database_revoked_all"
)

// restoreCredentialSummary reports what a restore did to credential state.
// Counts only; it never carries a credential.
type restoreCredentialSummary struct {
	Mode               string `json:"mode"`
	LiveError          string `json:"live_error,omitempty"`
	UsersMatched       int    `json:"users_matched"`
	UsersUpdated       int    `json:"users_updated"`
	UsersSnapshotOnly  int    `json:"users_snapshot_only"`
	IdentifiersCleared int    `json:"identifiers_cleared"`
	// MCPGrantsRevoked counts snapshot connector grants marked revoked because
	// no live grant state was available.
	MCPGrantsRevoked int            `json:"mcp_grants_revoked,omitempty"`
	Kept             map[string]int `json:"kept"`
	Removed          map[string]int `json:"removed"`
}

// restoreUserIdentityColumns are login identifiers: whoever holds one live
// holds it after the restore.
var restoreUserIdentityColumns = []string{"email", "phone", "username"}

// restoreUserCredentialColumns are account credentials and gates, taken from
// the live row for an account present in both databases.
var restoreUserCredentialColumns = []string{
	"password_hash",
	"password_change_required",
	"totp_secret",
	"backup_codes",
	"mfa_last_totp",
	"mfa_last_totp_at",
	"deactivated_at",
	"verified",
	"email_grandfathered",
}

// restoreEmailTrustColumns describe the email address itself and are reset
// when a snapshot-only account loses an email that a live account now holds.
var restoreEmailTrustColumns = []string{"verified", "email_grandfathered"}

// restoreGrantTable is a table of credentials or grants. A snapshot row
// survives only when a live row has the same key for the same account.
type restoreGrantTable struct {
	name    string
	key     []string // the credential's identity, compared in stored form
	userCol string   // the owning account, when the grant belongs to one
	session bool     // key[0] is a session id, compared by its stored key
}

var restoreGrantTables = []restoreGrantTable{
	{name: "_benmore_signin_challenges", key: []string{"token_hash"}, userCol: "user_id"},
	{name: "_benmore_sessions", key: []string{"id"}, userCol: "user_id", session: true},
	{name: "_benmore_api_tokens", key: []string{"token_hash"}, userCol: "user_id"},
	{name: "_benmore_passkeys", key: []string{"credential_id"}, userCol: "user_id"},
	{name: "_benmore_oauth_tokens", key: []string{"provider"}, userCol: "user_id"},
	{name: "_benmore_oauth_codes", key: []string{"code"}, userCol: "user_id"},
	{name: "_benmore_email_changes", key: []string{"token_hash"}, userCol: "user_id"},
	{name: "_benmore_password_resets", key: []string{"token"}},
	{name: "_benmore_otp", key: []string{"email", "code"}},
	{name: "_benmore_oauth_clients", key: []string{"client_id"}},
}

// restoreLiveStateTables are replaced wholesale by their live rows.
var restoreLiveStateTables = []string{"_benmore_login_attempts"}

// credTable is one table: every column it has, and rows holding the selected
// columns in their stored form.
type credTable struct {
	cols  []string
	has   map[string]bool
	sel   map[string]int
	rows  [][]any
	rowid []int64 // candidate rows only
}

// get returns row i's stored value for col (nil when not selected).
func (t *credTable) get(i int, col string) any {
	if j, ok := t.sel[col]; ok {
		return t.rows[i][j]
	}
	return nil
}

// carryForwardRestoreCredentials rewrites the credential state of the restore
// candidate at candidatePath from the live database at livePath. The caller
// has stopped every writer of the live database. actor names who restored,
// for the audit row.
func carryForwardRestoreCredentials(ctx context.Context, livePath, candidatePath, actor string) (*restoreCredentialSummary, error) {
	summary := &restoreCredentialSummary{Mode: restoreCredentialsCarried, Kept: map[string]int{}, Removed: map[string]int{}}
	live, err := readLiveCredentialState(ctx, livePath)
	if err != nil && ctx.Err() != nil {
		// A cancelled restore must stop, not read as a damaged database.
		return nil, ctx.Err()
	}
	switch {
	case errors.Is(err, os.ErrNotExist):
		summary.Mode, live = restoreCredentialsNoLive, nil
	case err != nil:
		summary.Mode, summary.LiveError, live = restoreCredentialsUnreadable, err.Error(), nil
		log.Printf("restore: live database unreadable (%v); revoking every restored session, token and grant", err)
	}

	// The maintenance driver: app triggers still compile, the storage
	// ceiling does not apply, and DELETE journaling keeps every change in
	// the one file that gets installed.
	db, err := sql.Open(sqliteMaintenanceDriver, sqliteRestoreURI(candidatePath, "rw")+"&_journal_mode=DELETE&_txlock=immediate")
	if err != nil {
		return nil, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	// A snapshot old enough to predate the audit table still gets its row.
	if ok, err := credTableExists(ctx, db, "_benmore_audit_log"); err != nil {
		return nil, err
	} else if !ok {
		EnsureAuditLogTable(db)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	pairs, err := carryForwardUsers(ctx, tx, live, summary)
	if err != nil {
		return nil, fmt.Errorf("accounts: %w", err)
	}
	for _, spec := range restoreGrantTables {
		if err := carryForwardGrants(ctx, tx, live, spec, pairs, summary); err != nil {
			return nil, fmt.Errorf("%s: %w", spec.name, err)
		}
	}
	if live != nil {
		for _, name := range restoreLiveStateTables {
			if err := replaceWithLiveRows(ctx, tx, live, name, summary); err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
		}
	}
	if err := carryForwardMCPGrants(ctx, tx, live, pairs, summary); err != nil {
		return nil, fmt.Errorf("connector grants: %w", err)
	}
	if err := carryForwardMCPFileProcessings(ctx, tx, live, livePath, pairs, summary); err != nil {
		return nil, fmt.Errorf("connector file processing: %w", err)
	}
	if err := carryForwardMCPArtifacts(ctx, tx, live, pairs, summary); err != nil {
		return nil, fmt.Errorf("connector artifacts: %w", err)
	}
	values, err := json.Marshal(summary)
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO _benmore_audit_log (action, table_name, row_id, user_id, user_email, old_values, new_values) VALUES ('restore_credentials', '_benmore_users', '', 0, ?, NULL, ?)`, actor, string(values)); err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	if err := db.Close(); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(candidatePath, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	if err := errors.Join(f.Sync(), f.Close()); err != nil {
		return nil, err
	}
	log.Printf("restore: credentials %s: %d accounts matched (%d updated), %d snapshot-only; kept %v; removed %v",
		summary.Mode, summary.UsersMatched, summary.UsersUpdated, summary.UsersSnapshotOnly, summary.Kept, summary.Removed)
	return summary, nil
}

// readLiveCredentialState reads the credential tables of the live database
// read-only, in one read transaction. os.ErrNotExist: no live database.
func readLiveCredentialState(ctx context.Context, livePath string) (map[string]*credTable, error) {
	info, err := os.Lstat(livePath)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("live database is not a regular file")
	}
	db, err := sql.Open("sqlite3", sqliteRestoreURI(livePath, "ro"))
	if err != nil {
		return nil, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "BEGIN"); err != nil {
		return nil, err
	}
	defer conn.ExecContext(context.Background(), "ROLLBACK")
	state := map[string]*credTable{}
	read := func(name string, want []string) error {
		t, err := readCredTable(ctx, conn, name, false, want)
		if err != nil {
			return fmt.Errorf("read %s: %w", name, err)
		}
		if t != nil {
			state[name] = t
		}
		return nil
	}
	if err := read("_benmore_users", restoreUserColumns()); err != nil {
		return nil, err
	}
	for _, spec := range restoreGrantTables {
		if err := read(spec.name, nil); err != nil {
			return nil, err
		}
	}
	for _, name := range restoreLiveStateTables {
		if err := read(name, nil); err != nil {
			return nil, err
		}
	}
	if err := read(mcpFileProcessingsTable, mcpFileProcessingRestoreColumns); err != nil {
		return nil, err
	}
	for _, name := range restoreMCPTables {
		if err := read(name, nil); err != nil {
			return nil, err
		}
	}
	if err := read(mcpArtifactsTable, nil); err != nil {
		return nil, err
	}
	return state, nil
}

// restoreUserColumns are the account columns the carry-forward reads.
func restoreUserColumns() []string {
	cols := []string{"id", "created_at"}
	cols = append(cols, restoreUserIdentityColumns...)
	return append(cols, restoreUserCredentialColumns...)
}

type credQuerier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func credTableExists(ctx context.Context, q credQuerier, name string) (bool, error) {
	rows, err := q.QueryContext(ctx, "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", name)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	found := rows.Next()
	return found, rows.Err()
}

// readCredTable loads a table. want selects columns (nil: all; empty: none,
// only the column list). Each column is selected as `+col`, an expression,
// so the driver returns the stored value and storage class untouched (it
// turns bare DATETIME columns into time.Time). nil table: it does not exist.
func readCredTable(ctx context.Context, q credQuerier, name string, withRowid bool, want []string) (*credTable, error) {
	ok, err := credTableExists(ctx, q, name)
	if err != nil || !ok {
		return nil, err
	}
	rows, err := q.QueryContext(ctx, "SELECT name FROM pragma_table_info(?)", name)
	if err != nil {
		return nil, err
	}
	t := &credTable{has: map[string]bool{}, sel: map[string]int{}}
	for rows.Next() {
		var col string
		if err := rows.Scan(&col); err != nil {
			rows.Close()
			return nil, err
		}
		t.cols = append(t.cols, col)
		t.has[col] = true
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, err
	}
	var selects []string
	if withRowid {
		selects = append(selects, "rowid")
	}
	offset := len(selects)
	for _, col := range t.cols {
		if want != nil && !slices.Contains(want, col) {
			continue
		}
		t.sel[col] = len(selects) - offset
		selects = append(selects, "+"+quoteIdent(col))
	}
	if want != nil && len(want) == 0 && !withRowid {
		return t, nil
	}
	if len(selects) == 0 {
		selects = append(selects, "1")
	}
	rows, err = q.QueryContext(ctx, "SELECT "+strings.Join(selects, ", ")+" FROM "+quoteIdent(name))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		values := make([]any, len(selects))
		ptrs := make([]any, len(selects))
		for i := range values {
			ptrs[i] = &values[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		if withRowid {
			id, ok := credInt(values[0])
			if !ok {
				return nil, fmt.Errorf("unreadable rowid")
			}
			t.rowid = append(t.rowid, id)
			values = values[1:]
		}
		t.rows = append(t.rows, values)
	}
	return t, rows.Err()
}

// credKey renders a stored value for equality: storage class and bytes.
func credKey(v any) string {
	switch x := v.(type) {
	case nil:
		return "n"
	case int64:
		return "i" + strconv.FormatInt(x, 10)
	case float64:
		return "f" + strconv.FormatFloat(x, 'g', -1, 64)
	case []byte:
		return "b" + string(x)
	case string:
		return "s" + x
	}
	return fmt.Sprintf("?%T:%v", v, v)
}

func credInt(v any) (int64, bool) {
	switch x := v.(type) {
	case int64:
		return x, true
	case float64:
		return int64(x), x == float64(int64(x))
	case string:
		n, err := strconv.ParseInt(strings.TrimSpace(x), 10, 64)
		return n, err == nil
	case []byte:
		n, err := strconv.ParseInt(strings.TrimSpace(string(x)), 10, 64)
		return n, err == nil
	}
	return 0, false
}

func credText(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case []byte:
		return string(x)
	case nil:
		return ""
	}
	return fmt.Sprint(v)
}

func credEmail(v any) string { return strings.ToLower(strings.TrimSpace(credText(v))) }

// credSessionKey maps a stored session id to its hashed stored form, the one
// every current row uses. A raw id from before hashing is hashed; an id
// already in stored form is kept.
func credSessionKey(v any) string {
	id := credText(v)
	if isSessionStorageKey(id) {
		return id
	}
	return sessionStorageKey(id)
}

func credRandomSuffix() (string, error) {
	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// present keeps the columns every given table has.
func present(cols []string, tables ...*credTable) []string {
	var out []string
	for _, col := range cols {
		ok := true
		for _, t := range tables {
			ok = ok && t.has[col]
		}
		if ok {
			out = append(out, col)
		}
	}
	return out
}

// updateRow writes values into one candidate row by rowid.
func updateRow(ctx context.Context, tx *sql.Tx, table string, rowid int64, cols []string, values []any) error {
	if len(cols) == 0 {
		return nil
	}
	sets := make([]string, len(cols))
	for i, col := range cols {
		sets[i] = quoteIdent(col) + " = ?"
	}
	_, err := tx.ExecContext(ctx, "UPDATE "+quoteIdent(table)+" SET "+strings.Join(sets, ", ")+" WHERE rowid = ?", append(values, rowid)...)
	return err
}

// carryForwardUsers pairs snapshot accounts with live ones and copies live
// identity and credential columns onto the pairs. It returns candidate user
// id → live user id.
func carryForwardUsers(ctx context.Context, tx *sql.Tx, live map[string]*credTable, summary *restoreCredentialSummary) (map[int64]int64, error) {
	pairs := map[int64]int64{}
	cand, err := readCredTable(ctx, tx, "_benmore_users", true, restoreUserColumns())
	if err != nil || cand == nil {
		return pairs, err
	}
	lu := live["_benmore_users"]
	if lu == nil || !cand.has["id"] || !lu.has["id"] {
		summary.UsersSnapshotOnly = len(cand.rows)
		return pairs, nil
	}
	liveByID := map[int64]int{}
	liveByEmail := map[string]int64{}
	for i := range lu.rows {
		id, ok := credInt(lu.get(i, "id"))
		if !ok {
			continue
		}
		liveByID[id] = i
		if email := credEmail(lu.get(i, "email")); email != "" {
			liveByEmail[email] = id
		}
	}
	checkCreated := cand.has["created_at"] && lu.has["created_at"]
	checkEmail := cand.has["email"] && lu.has["email"]
	liveTaken := map[int64]bool{}
	// Same id and the same account: created_at when both record it (an id
	// reused after an earlier restore is a different account), else email.
	for i := range cand.rows {
		id, ok := credInt(cand.get(i, "id"))
		if !ok {
			continue
		}
		j, ok := liveByID[id]
		if !ok {
			continue
		}
		same := true
		if checkCreated && cand.get(i, "created_at") != nil && lu.get(j, "created_at") != nil {
			same = credKey(cand.get(i, "created_at")) == credKey(lu.get(j, "created_at"))
		} else if checkEmail && credEmail(cand.get(i, "email")) != "" && credEmail(lu.get(j, "email")) != "" {
			same = credEmail(cand.get(i, "email")) == credEmail(lu.get(j, "email"))
		}
		if same {
			pairs[id] = id
			liveTaken[id] = true
		}
	}
	// An account deleted and signed up again under the same email: the live
	// credentials for that email apply to the restored account.
	if checkEmail {
		for i := range cand.rows {
			id, ok := credInt(cand.get(i, "id"))
			if !ok {
				continue
			}
			if _, paired := pairs[id]; paired {
				continue
			}
			if lid, ok := liveByEmail[credEmail(cand.get(i, "email"))]; ok && !liveTaken[lid] {
				pairs[id] = lid
				liveTaken[lid] = true
			}
		}
	}
	summary.UsersMatched = len(pairs)
	summary.UsersSnapshotOnly = len(cand.rows) - len(pairs)

	identity := present(restoreUserIdentityColumns, cand, lu)
	creds := present(restoreUserCredentialColumns, cand, lu)
	identityKey := func(col string, v any) string {
		if col == "email" {
			return credEmail(v)
		}
		return credKey(v)
	}
	type plan struct {
		rowid  int64
		target map[string]any
		change []string
	}
	var plans []plan
	assigned := map[string]map[string]bool{}
	for _, col := range identity {
		assigned[col] = map[string]bool{}
	}
	for i := range cand.rows {
		id, _ := credInt(cand.get(i, "id"))
		lid, ok := pairs[id]
		if !ok {
			continue
		}
		j := liveByID[lid]
		p := plan{rowid: cand.rowid[i], target: map[string]any{}}
		for _, col := range identity {
			v := lu.get(j, col)
			if col == "username" && credText(v) == "" {
				v = cand.get(i, col) // never blank a NOT NULL username
			}
			p.target[col] = v
			if credText(v) != "" {
				assigned[col][identityKey(col, v)] = true
			}
		}
		for _, col := range creds {
			p.target[col] = lu.get(j, col)
		}
		for _, col := range append(slices.Clone(identity), creds...) {
			if credKey(p.target[col]) != credKey(cand.get(i, col)) {
				p.change = append(p.change, col)
			}
		}
		plans = append(plans, p)
	}
	// 1. Move changing identifiers of matched accounts out of the way, so
	// assignments below never collide on a UNIQUE index mid-way.
	for _, p := range plans {
		var cols []string
		var values []any
		for _, col := range p.change {
			if !slices.Contains(identity, col) {
				continue
			}
			suffix, err := credRandomSuffix()
			if err != nil {
				return nil, err
			}
			cols = append(cols, col)
			values = append(values, fmt.Sprintf("restore-pending-%d-%s-%s", p.rowid, col, suffix))
		}
		if err := updateRow(ctx, tx, "_benmore_users", p.rowid, cols, values); err != nil {
			return nil, err
		}
	}
	// 2. A snapshot-only account loses an identifier a live account now holds.
	for i := range cand.rows {
		id, _ := credInt(cand.get(i, "id"))
		if _, ok := pairs[id]; ok {
			continue
		}
		var cols []string
		var values []any
		for _, col := range identity {
			v := cand.get(i, col)
			if credText(v) == "" || !assigned[col][identityKey(col, v)] {
				continue
			}
			cols = append(cols, col)
			if col == "username" {
				suffix, err := credRandomSuffix()
				if err != nil {
					return nil, err
				}
				values = append(values, fmt.Sprintf("restored-%d-%s", id, suffix))
			} else {
				values = append(values, nil)
			}
			if col == "email" {
				for _, trust := range present(restoreEmailTrustColumns, cand) {
					cols = append(cols, trust)
					values = append(values, 0)
				}
			}
			summary.IdentifiersCleared++
		}
		if err := updateRow(ctx, tx, "_benmore_users", cand.rowid[i], cols, values); err != nil {
			return nil, err
		}
	}
	// 3. Matched accounts take the live identifiers and credentials.
	for _, p := range plans {
		if len(p.change) == 0 {
			continue
		}
		values := make([]any, len(p.change))
		for i, col := range p.change {
			values[i] = p.target[col]
		}
		if err := updateRow(ctx, tx, "_benmore_users", p.rowid, p.change, values); err != nil {
			return nil, err
		}
		summary.UsersUpdated++
	}
	return pairs, nil
}

// carryForwardGrants keeps a snapshot credential only when the live database
// holds the same one for the same account, refreshed to its live values.
func carryForwardGrants(ctx context.Context, tx *sql.Tx, live map[string]*credTable, spec restoreGrantTable, pairs map[int64]int64, summary *restoreCredentialSummary) error {
	idCols := slices.Clone(spec.key)
	if spec.userCol != "" {
		idCols = append(idCols, spec.userCol)
	}
	cand, err := readCredTable(ctx, tx, spec.name, true, idCols)
	if err != nil || cand == nil {
		return err
	}
	for _, col := range idCols {
		if !cand.has[col] {
			return fmt.Errorf("credential column %s is missing", col)
		}
	}
	lt := live[spec.name]
	if lt != nil && len(present(idCols, lt)) != len(idCols) {
		lt = nil // no comparable live credential: none survives
	}
	keyOf := func(t *credTable, i int, owner string) string {
		parts := make([]string, 0, len(spec.key)+1)
		for k, col := range spec.key {
			switch {
			case spec.session && k == 0:
				parts = append(parts, credSessionKey(t.get(i, col)))
			case col == "email":
				parts = append(parts, credEmail(t.get(i, col)))
			default:
				parts = append(parts, credKey(t.get(i, col)))
			}
		}
		return strings.Join(append(parts, owner), "\x00")
	}
	index := map[string]int{}
	var refresh []string
	if lt != nil {
		for i := range lt.rows {
			owner := ""
			if spec.userCol != "" {
				id, ok := credInt(lt.get(i, spec.userCol))
				if !ok {
					continue
				}
				owner = strconv.FormatInt(id, 10)
			}
			index[keyOf(lt, i, owner)] = i
		}
		for _, col := range cand.cols {
			if lt.has[col] && col != "id" && !slices.Contains(idCols, col) {
				refresh = append(refresh, col)
			}
		}
	}
	for i := range cand.rows {
		match := -1
		if lt != nil {
			owner, ownerOK := "", true
			if spec.userCol != "" {
				id, ok := credInt(cand.get(i, spec.userCol))
				lid, paired := pairs[id]
				ownerOK = ok && paired
				owner = strconv.FormatInt(lid, 10)
			}
			if j, ok := index[keyOf(cand, i, owner)]; ok && ownerOK {
				match = j
			}
		}
		if match < 0 {
			if _, err := tx.ExecContext(ctx, "DELETE FROM "+quoteIdent(spec.name)+" WHERE rowid = ?", cand.rowid[i]); err != nil {
				return err
			}
			summary.Removed[spec.name]++
			continue
		}
		values := make([]any, len(refresh))
		for k, col := range refresh {
			values[k] = lt.get(match, col)
		}
		if err := updateRow(ctx, tx, spec.name, cand.rowid[i], refresh, values); err != nil {
			return err
		}
		summary.Kept[spec.name]++
	}
	return nil
}

// replaceWithLiveRows makes a candidate table hold exactly the live rows.
func replaceWithLiveRows(ctx context.Context, tx *sql.Tx, live map[string]*credTable, name string, summary *restoreCredentialSummary) error {
	cand, err := readCredTable(ctx, tx, name, false, []string{})
	if err != nil || cand == nil {
		return err
	}
	res, err := tx.ExecContext(ctx, "DELETE FROM "+quoteIdent(name))
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err == nil && n > 0 {
		summary.Removed[name] += int(n)
	}
	lt := live[name]
	if lt == nil {
		return nil
	}
	cols := present(cand.cols, lt)
	if len(cols) == 0 {
		return nil
	}
	quoted := make([]string, len(cols))
	for i, col := range cols {
		quoted[i] = quoteIdent(col)
	}
	stmt, err := tx.PrepareContext(ctx, "INSERT INTO "+quoteIdent(name)+" ("+strings.Join(quoted, ", ")+") VALUES ("+strings.TrimSuffix(strings.Repeat("?, ", len(cols)), ", ")+")")
	if err != nil {
		return err
	}
	defer stmt.Close()
	for i := range lt.rows {
		values := make([]any, len(cols))
		for k, col := range cols {
			values[k] = lt.get(i, col)
		}
		if _, err := stmt.ExecContext(ctx, values...); err != nil {
			return err
		}
		summary.Kept[name]++
	}
	return nil
}
