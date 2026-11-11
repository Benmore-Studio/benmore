//go:build !cli

package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// purgeDeleteSpec describes one framework-owned identity surface. Identifiers
// are compile-time constants; only values are bound. App tables are excluded on
// purpose because the framework cannot infer their retention obligations.
type purgeDeleteSpec struct {
	table         string
	columns       []string
	query         string
	args          func(int64, string) []any
	requiresEmail bool
}

// execStepPurgeCurrentUser irreversibly erases the authenticated user's
// framework-owned credentials and direct identifiers, then leaves the stable
// _benmore_users id as a non-login tombstone. It accepts no target id. The
// caller identity comes exclusively from FlowContext.Session, which the HTTP
// entry point captures before any request data or flow step can mutate context.
func execStepPurgeCurrentUser(ctx *FlowContext, step *FlowStep) error {
	if ctx == nil || ctx.App == nil || ctx.Tx == nil {
		return fmt.Errorf("purge_current_user requires transaction: true")
	}
	if ctx.Request == nil || (ctx.Request.Method != http.MethodPost && ctx.Request.Method != http.MethodDelete) {
		return fmt.Errorf("purge_current_user requires an authenticated POST or DELETE request")
	}
	if ctx.Session == nil || ctx.Session.UserID <= 0 || ctx.Session.ID == "" {
		return purgeCredentialRefused("requires an immutable authenticated session")
	}
	if strings.HasPrefix(ctx.Session.ID, "apitoken:") {
		return purgeCredentialRefused("requires a live user session, not an API token")
	}
	// The rule /settings/delete-account applies (directLoginSession): a
	// credential narrowed to some scopes, or an admin stepped into another
	// tenant, may not erase the account.
	if !accountManagementSession(ctx.Session) {
		return purgeCredentialRefused("requires a full-access sign-in, not a scoped credential")
	}
	if ctx.Session.ActingAsGroup != "" {
		return purgeCredentialRefused("cannot run while the session is stepped into another tenant (act-as): step out first")
	}
	confirm := interpolateCtx(step.PurgeCurrentUserConfirm, ctx)
	if !constantTimeStringEqual(confirm, "DELETE") {
		return &purgeRefusal{status: http.StatusBadRequest, code: "confirmation_required", reason: "confirmation must exactly equal DELETE"}
	}

	userCols, exists, err := purgeTableColumns(ctx.Tx, "_benmore_users")
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("purge_current_user: required table _benmore_users is missing")
	}
	if err := purgeRequireColumns("_benmore_users", userCols,
		"id", "username", "email", "phone", "password_hash", "first_name", "last_name", "avatar_url", "role", "verified", "deactivated_at", "last_login_at"); err != nil {
		return err
	}
	sessionCols, exists, err := purgeTableColumns(ctx.Tx, "_benmore_sessions")
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("purge_current_user: required table _benmore_sessions is missing")
	}
	if err := purgeRequireColumns("_benmore_sessions", sessionCols, "id", "user_id", "email"); err != nil {
		return err
	}

	uid := ctx.Session.UserID
	// Re-resolve the exact live ordinary session inside the same transaction.
	// This rejects persistent tokens, expired/revoked
	// sessions, and support impersonation even if a caller hand-builds context.
	liveSQL := `SELECT COUNT(*) FROM _benmore_sessions WHERE id=? AND user_id=?`
	if sessionCols["expires_at"] {
		liveSQL += ` AND datetime(expires_at) > datetime('now')`
	}
	if sessionCols["is_impersonation"] {
		liveSQL += ` AND COALESCE(is_impersonation,0)=0`
	}
	if sessionCols["scopes"] {
		liveSQL += ` AND COALESCE(scopes,'') IN ('','*')`
	}
	if sessionCols["acting_as_group"] {
		liveSQL += ` AND COALESCE(acting_as_group,'')=''`
	}
	var live int
	if err := ctx.Tx.QueryRow(liveSQL, ctx.Session.ID, uid).Scan(&live); err != nil {
		return fmt.Errorf("purge_current_user: verify session: %w", err)
	}
	if live != 1 {
		return purgeCredentialRefused("requires the account's own live, full-access sign-in session, not an expired, impersonation or delegated one")
	}

	// The app's last usable durable admin cannot erase itself: the app would
	// be left with no admin (last_admin_guard.go). Checked in the flow's own
	// transaction, after the steps before this one.
	if err := refuseLastDurableAdmin(ctx.App, ctx.Tx, uid, dropsAccount); err != nil {
		return &purgeRefusal{status: http.StatusConflict, code: "last_admin", reason: "refused: " + err.Error()}
	}

	var email string
	ctx.Tx.QueryRow(`SELECT COALESCE(email, '') FROM _benmore_users WHERE id = ?`, uid).Scan(&email)
	deleted, artifactRefs, err := purgeAccountTx(ctx.Request.Context(), ctx.App, ctx.Tx, uid, userCols, sessionCols, uid, "")
	if err != nil {
		return err
	}
	// The artifact bytes go once the flow's transaction commits; a rollback
	// keeps them with their manifests. A run with no write log leaves them to
	// the orphan sweep at the next start.
	if ctx.Writes != nil && len(artifactRefs) > 0 {
		app := ctx.App
		ctx.Writes.onCommit(func() { deleteAppMCPArtifactBytes(app, artifactRefs) })
	}
	// On the dashboard app, the control-plane credentials go with the
	// account once it is gone; without a write log, now (fail closed).
	if app := ctx.App; ctx.Writes != nil {
		ctx.Writes.onCommit(func() {
			platformAccountDeleted(app, email)
		})
	} else {
		platformAccountDeleted(ctx.App, email)
	}

	if step.Name != "" {
		ctx.DataMu.Lock()
		ctx.Data[step.Name] = map[string]any{"purged": 1, "user_id": uid, "framework_rows_deleted": deleted}
		ctx.DataMu.Unlock()
	}
	return nil
}

// purgeRefusal is a purge_current_user refusal the caller can act on,
// returned before the step writes anything: a missing or wrong confirmation
// (400) or a credential that may not erase the account (403). An HTTP flow
// answers it with that status, code and reason once its transaction has
// rolled back (answerIfPurgeRefused), instead of the generic 500: a purge
// flow may not declare on_error, so the answer is the only way a client
// learns why. The refusal rules themselves are unchanged by how they answer.
type purgeRefusal struct {
	status int
	code   string
	reason string
}

func (e *purgeRefusal) Error() string { return "purge_current_user " + e.reason }

func purgeCredentialRefused(reason string) error {
	return &purgeRefusal{status: http.StatusForbidden, code: "credential_not_allowed", reason: reason}
}

// answerIfPurgeRefused writes a purge refusal's answer: one JSON object with
// the code, the reason and the request id the failure is logged under.
func answerIfPurgeRefused(w http.ResponseWriter, err error, requestID string) bool {
	var refusal *purgeRefusal
	if !errors.As(err, &refusal) {
		return false
	}
	h := w.Header()
	h.Del("Content-Length")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set(requestIDHeader, requestID)
	httpJSON(w, refusal.status, map[string]any{
		"error":      refusal.code,
		"message":    "account deletion " + refusal.reason,
		"request_id": requestID,
	})
	return true
}

func constantTimeStringEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func purgeUIDArgs(uid int64, _ string) []any     { return []any{uid} }
func purgeEmailArgs(_ int64, email string) []any { return []any{email} }

func purgeTombstoneUsername(uid int64) (string, error) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("purge_current_user: generate tombstone: %w", err)
	}
	return fmt.Sprintf("deleted-user-%d-%s", uid, hex.EncodeToString(random)), nil
}

func purgeOptionalExec(tx *sql.Tx, table string, required []string, query string, args ...any) (int64, error) {
	cols, exists, err := purgeTableColumns(tx, table)
	if err != nil {
		return 0, err
	}
	if !exists {
		return 0, nil
	}
	if err := purgeRequireColumns(table, cols, required...); err != nil {
		return 0, err
	}
	res, err := tx.Exec(query, args...)
	if err != nil {
		return 0, fmt.Errorf("purge_current_user: mutate %s: %w", table, err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

func purgeTableColumns(tx *sql.Tx, table string) (map[string]bool, bool, error) {
	var exists int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&exists); err != nil {
		return nil, false, fmt.Errorf("purge_current_user: inspect %s: %w", table, err)
	}
	if exists == 0 {
		return nil, false, nil
	}
	// table is supplied only by the compile-time registry above. Still reject
	// anything outside SQLite identifiers before placing it in PRAGMA syntax.
	for _, r := range table {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' {
			return nil, false, fmt.Errorf("purge_current_user: invalid internal table identifier")
		}
	}
	rows, err := tx.Query("PRAGMA table_info(" + quoteIdent(table) + ")")
	if err != nil {
		return nil, false, fmt.Errorf("purge_current_user: inspect columns for %s: %w", table, err)
	}
	defer rows.Close()
	cols := map[string]bool{}
	for rows.Next() {
		var cid, notNull, pk int
		var name, kind string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &kind, &notNull, &defaultValue, &pk); err != nil {
			return nil, false, fmt.Errorf("purge_current_user: scan columns for %s: %w", table, err)
		}
		cols[name] = true
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("purge_current_user: scan columns for %s: %w", table, err)
	}
	return cols, true, nil
}

func purgeRequireColumns(table string, have map[string]bool, required ...string) error {
	for _, col := range required {
		if !have[col] {
			return fmt.Errorf("purge_current_user: existing table %s is incompatible: missing required identity column %s", table, col)
		}
	}
	return nil
}

// purgeAuditEmailFields are the keys under which framework audit actions
// record a person by address inside old_values/new_values, outside the
// account's own _benmore_users rows (whose values purgeAuditLogIdentity drops
// whole): the admin and the target of an impersonation (auth.go), the admin
// stepping into or out of a tenant (auth.go act_as), the grantee of a share
// (permissions.go) and the chosen row owner of an import (import_run.go).
// Matching is by action and key, so an app table's own row snapshot (an
// insert into contacts with an email column) is never rewritten: app tables
// and their history are the app's to dispose of.
var purgeAuditEmailFields = []struct {
	key     string
	actions []string
}{
	{"impersonated_by", []string{"impersonate"}},
	{"target_user", []string{"impersonate"}},
	{"admin_email", []string{"act_as_start"}},
	{"user_email", []string{"act_as_end"}},
	{"shared_with", []string{"share", "revoke_share"}},
	{"owner_email", []string{"import"}},
}

// purgeAuditLogIdentity removes account uid's address from the audit log
// while keeping every row, its action, time, stable ids and the other people
// it names. It covers rows the account wrote, rows other actors wrote about
// it (an operator's app_user_created or superuser_password_reset, an admin's
// impersonate or role_changed, which carry the address as user_id 0 or under
// another actor), rows recorded under its address without its id, the
// impersonator columns, and the address-valued keys in
// purgeAuditEmailFields. email is the account's lowercased address ("" when
// it had none: then nothing is matched by address).
func purgeAuditLogIdentity(tx *sql.Tx, uid int64, email string) error {
	cols, exists, err := purgeTableColumns(tx, "_benmore_audit_log")
	if err != nil || !exists {
		return err
	}
	if err := purgeRequireColumns("_benmore_audit_log", cols, "action", "user_id", "user_email", "table_name", "row_id", "old_values", "new_values"); err != nil {
		return err
	}
	exec := func(query string, args ...any) error {
		if _, err := tx.Exec(query, args...); err != nil {
			return fmt.Errorf("purge account: mutate _benmore_audit_log: %w", err)
		}
		return nil
	}
	// Rows the account wrote keep its stable id and lose its address.
	if err := exec(`UPDATE _benmore_audit_log SET user_email='' WHERE user_id=? AND COALESCE(user_email,'')<>''`, uid); err != nil {
		return err
	}
	// Rows about the account, whoever wrote them: their values are a
	// snapshot of its identity (address, role, who reset or impersonated it).
	if err := exec(`UPDATE _benmore_audit_log SET old_values=NULL, new_values=NULL WHERE table_name='_benmore_users' AND row_id=? AND (old_values IS NOT NULL OR new_values IS NOT NULL)`, strconv.FormatInt(uid, 10)); err != nil {
		return err
	}
	if cols["impersonator_user_id"] && cols["impersonator_email"] {
		if err := exec(`UPDATE _benmore_audit_log SET impersonator_email='' WHERE impersonator_user_id=? OR (?<>'' AND lower(trim(impersonator_email))=?)`, uid, email, email); err != nil {
			return err
		}
	}
	if email == "" {
		return nil
	}
	// Rows recorded under the address without the account's id: an
	// owner-token import's subject, a connector switch, a platform operation
	// written as user_id 0.
	if err := exec(`UPDATE _benmore_audit_log SET user_email='' WHERE lower(trim(user_email))=?`, email); err != nil {
		return err
	}
	// The prefilter looks for the address's domain, which JSON encoding never
	// escapes (a local part may hold an & that json.Marshal writes as
	// \u0026); json_extract then compares the decoded value exactly.
	needle := email
	if at := strings.LastIndex(email, "@"); at >= 0 {
		needle = email[at:]
	}
	for _, field := range purgeAuditEmailFields {
		path := "$." + field.key
		in := strings.TrimSuffix(strings.Repeat("?,", len(field.actions)), ",")
		args := []any{path, email, path, path, email, path}
		for _, action := range field.actions {
			args = append(args, action)
		}
		args = append(args, needle, needle)
		// The WHERE prefilter uses no JSON function, so a malformed row is
		// never parsed; CASE evaluates json_extract only on valid JSON.
		if err := exec(`UPDATE _benmore_audit_log SET
			old_values=CASE WHEN json_valid(old_values) AND lower(trim(json_extract(old_values,?)))=? THEN json_replace(old_values,?,'') ELSE old_values END,
			new_values=CASE WHEN json_valid(new_values) AND lower(trim(json_extract(new_values,?)))=? THEN json_replace(new_values,?,'') ELSE new_values END
			WHERE action IN (`+in+`) AND (instr(lower(COALESCE(old_values,'')),?)>0 OR instr(lower(COALESCE(new_values,'')),?)>0)`, args...); err != nil {
			return err
		}
	}
	return nil
}

// purgeAccountTx irreversibly erases account uid's framework-owned
// credentials and direct identifiers inside tx and leaves its _benmore_users
// id as a non-login tombstone, so app tables keep valid foreign keys. App
// tables are left alone: the framework cannot infer their retention rules.
// The audit marker names who asked: the account itself for
// purge_current_user, the operator for delete_app_user. artifactRefs names
// the stored connector artifact bytes whose manifests this deletes; the
// caller removes them with deleteAppMCPArtifactBytes once tx commits.
func purgeAccountTx(c context.Context, app *App, tx *sql.Tx, uid int64, userCols, sessionCols map[string]bool, actorID int64, actorEmail string) (deleted int64, artifactRefs []string, err error) {
	var oldEmail sql.NullString
	claim := `UPDATE _benmore_users SET deactivated_at=datetime('now') WHERE id=? AND (deactivated_at IS NULL OR trim(CAST(deactivated_at AS TEXT))='') RETURNING email`
	if err := tx.QueryRow(claim, uid).Scan(&oldEmail); err != nil {
		if err == sql.ErrNoRows {
			return 0, nil, fmt.Errorf("purge account: account is missing or already deleted")
		}
		return 0, nil, fmt.Errorf("purge account: claim account: %w", err)
	}
	email := strings.ToLower(strings.TrimSpace(oldEmail.String))

	// Read before the manifest rows go: the bytes are deleted after commit.
	artifactRefs, err = appMCPArtifactRefsOwnedBy(tx, uid)
	if err != nil {
		return 0, nil, err
	}
	deleteSpecs := []purgeDeleteSpec{
		{"_benmore_signin_challenges", []string{"user_id"}, `DELETE FROM _benmore_signin_challenges WHERE user_id=?`, purgeUIDArgs, false},
		{"_benmore_mcp_authorizations", []string{"user_id"}, `DELETE FROM _benmore_mcp_authorizations WHERE user_id=?`, purgeUIDArgs, false},
		{"_benmore_mcp_credentials", []string{"grant_id"}, `DELETE FROM _benmore_mcp_credentials WHERE grant_id IN (SELECT id FROM _benmore_mcp_grants WHERE user_id=?)`, purgeUIDArgs, false},
		{"_benmore_mcp_grants", []string{"user_id"}, `DELETE FROM _benmore_mcp_grants WHERE user_id=?`, purgeUIDArgs, false},
		{"_benmore_mcp_connection_credentials", []string{"user_id"}, `DELETE FROM _benmore_mcp_connection_credentials WHERE user_id=?`, purgeUIDArgs, false},
		{appMCPFileProcessingsTable, []string{"created_by"}, `DELETE FROM _benmore_mcp_file_processings WHERE created_by=?`, purgeUIDArgs, false},
		{mcpArtifactsTable, []string{"owner_user_id"}, `DELETE FROM _benmore_mcp_artifacts WHERE owner_user_id=?`, purgeUIDArgs, false},
		{"_benmore_passkeys", []string{"user_id"}, `DELETE FROM _benmore_passkeys WHERE user_id=?`, purgeUIDArgs, false},
		{"_benmore_api_tokens", []string{"user_id"}, `DELETE FROM _benmore_api_tokens WHERE user_id=?`, purgeUIDArgs, false},
		{"_benmore_oauth_tokens", []string{"user_id"}, `DELETE FROM _benmore_oauth_tokens WHERE user_id=?`, purgeUIDArgs, false},
		{"_benmore_oauth_codes", []string{"user_id"}, `DELETE FROM _benmore_oauth_codes WHERE user_id=?`, purgeUIDArgs, false},
		{"_benmore_email_changes", []string{"user_id"}, `DELETE FROM _benmore_email_changes WHERE user_id=?`, purgeUIDArgs, false},
		{"_benmore_password_resets", []string{"email"}, `DELETE FROM _benmore_password_resets WHERE lower(email)=?`, purgeEmailArgs, true},
		{"_benmore_login_attempts", []string{"email"}, `DELETE FROM _benmore_login_attempts WHERE lower(email)=?`, purgeEmailArgs, true},
		{"_benmore_otp", []string{"email"}, `DELETE FROM _benmore_otp WHERE lower(email)=?`, purgeEmailArgs, true},
		{"_benmore_user_roles", []string{"user_id", "granted_by"}, `DELETE FROM _benmore_user_roles WHERE user_id=?`, purgeUIDArgs, false},
		{"_benmore_permissions", []string{"grant_type", "grantee_id", "granted_by"}, `DELETE FROM _benmore_permissions WHERE grant_type='user' AND lower(grantee_id)=?`, purgeEmailArgs, true},
		{"_benmore_devices", []string{"user_id"}, `DELETE FROM _benmore_devices WHERE user_id=?`, purgeUIDArgs, false},
		{"_benmore_presence", []string{"user_id"}, `DELETE FROM _benmore_presence WHERE user_id=?`, purgeUIDArgs, false},
		{"_benmore_webhooks", []string{"user_id"}, `DELETE FROM _benmore_webhooks WHERE user_id=?`, purgeUIDArgs, false},
		{"_benmore_scheduled_tasks", []string{"user_id"}, `DELETE FROM _benmore_scheduled_tasks WHERE user_id=?`, purgeUIDArgs, false},
		{"_benmore_notifications", []string{"user_id"}, `DELETE FROM _benmore_notifications WHERE user_id=?`, purgeUIDArgs, false},
		{"_benmore_saved_views", []string{"user_id"}, `DELETE FROM _benmore_saved_views WHERE user_id=?`, purgeUIDArgs, false},
		{"_benmore_idempotency", []string{"user_id"}, `DELETE FROM _benmore_idempotency WHERE user_id=?`, purgeUIDArgs, false},
		{"_benmore_benchmark_urls", []string{"user_id"}, `DELETE FROM _benmore_benchmark_urls WHERE user_id=?`, purgeUIDArgs, false},
		{"_benmore_benchmarks", []string{"user_id", "is_custom"}, `DELETE FROM _benmore_benchmarks WHERE user_id=?`, purgeUIDArgs, false},
		{"_benmore_events", []string{"user_id"}, `DELETE FROM _benmore_events WHERE user_id=?`, purgeUIDArgs, false},
		{"_benmore_client_errors", []string{"user_id"}, `DELETE FROM _benmore_client_errors WHERE user_id=?`, purgeUIDArgs, false},
		// message and last_request_id come from the latest occurrence too, like the sample.
		{"_benmore_error_groups", []string{"sample", "sample_user_id", "message", "last_request_id"}, `UPDATE _benmore_error_groups SET sample=NULL,sample_user_id=NULL,message=NULL,last_request_id=NULL WHERE sample_user_id=?`, purgeUIDArgs, false},
		{"_benmore_request_log", []string{"user_id"}, `DELETE FROM _benmore_request_log WHERE user_id=? OR (?<>'' AND lower(user_id)=?)`, func(uid int64, email string) []any { return []any{"user:" + strconv.FormatInt(uid, 10), email, email} }, false},
		{"_benmore_usage", []string{"scope"}, `DELETE FROM _benmore_usage WHERE scope=?`, func(uid int64, _ string) []any { return []any{"user:" + strconv.FormatInt(uid, 10)} }, false},
	}
	for _, spec := range deleteSpecs {
		if spec.requiresEmail && email == "" {
			continue
		}
		n, err := purgeOptionalExec(tx, spec.table, spec.columns, spec.query, spec.args(uid, email)...)
		if err != nil {
			return 0, nil, err
		}
		deleted += n
	}

	// Connector operations hold the actor only inside their ciphertext.
	mcpDeleted, err := purgeAppMCPOperations(c, app, tx, uid)
	if err != nil {
		return 0, nil, err
	}
	deleted += mcpDeleted

	// Shared rate-limit buckets are credentials-adjacent transient state. Match
	// only framework-issued, exact subject keys; never use a suffix/substring
	// match that could erase another user's IP, group, or similarly named key.
	n, err := purgeOptionalExec(tx, "_benmore_rate_limits", []string{"key"},
		`DELETE FROM _benmore_rate_limits WHERE key=? OR key=? OR (?<>'' AND key=?)`,
		"u:"+strconv.FormatInt(uid, 10), "user:"+strconv.FormatInt(uid, 10), email, "e:"+email)
	if err != nil {
		return 0, nil, err
	}
	deleted += n

	// Locks carry the email as well as the stable id.
	n, err = purgeOptionalExec(tx, "_benmore_locks", []string{"user_id", "user_email"},
		`DELETE FROM _benmore_locks WHERE user_id=? OR (?<>'' AND lower(user_email)=?)`, uid, email, email)
	if err != nil {
		return 0, nil, err
	}
	deleted += n

	// Analytics has a child-before-parent dependency through visitor_id.
	visitors, visitorsExist, err := purgeTableColumns(tx, "_benmore_visitors")
	if err != nil {
		return 0, nil, err
	}
	analytics, analyticsExist, err := purgeTableColumns(tx, "_benmore_analytics")
	if err != nil {
		return 0, nil, err
	}
	if visitorsExist {
		if err := purgeRequireColumns("_benmore_visitors", visitors, "visitor_id", "user_id"); err != nil {
			return 0, nil, err
		}
		if analyticsExist {
			if err := purgeRequireColumns("_benmore_analytics", analytics, "visitor_id"); err != nil {
				return 0, nil, err
			}
			res, err := tx.Exec(`DELETE FROM _benmore_analytics WHERE visitor_id IN (SELECT visitor_id FROM _benmore_visitors WHERE user_id=?)`, uid)
			if err != nil {
				return 0, nil, fmt.Errorf("purge account: delete _benmore_analytics: %w", err)
			}
			count, _ := res.RowsAffected()
			deleted += count
		}
		res, err := tx.Exec(`DELETE FROM _benmore_visitors WHERE user_id=?`, uid)
		if err != nil {
			return 0, nil, fmt.Errorf("purge account: delete _benmore_visitors: %w", err)
		}
		count, _ := res.RowsAffected()
		deleted += count
	} else if analyticsExist {
		// An analytics table without the identity mapping contains no provable
		// subject link; preserve it rather than guessing from free-form data.
		if err := purgeRequireColumns("_benmore_analytics", analytics, "visitor_id"); err != nil {
			return 0, nil, err
		}
	}

	// Cancel queued work attributable through valid JSON, then erase the
	// copied user object/email from every terminal state as well.
	if _, err := purgeOptionalExec(tx, "_benmore_jobs",
		[]string{"payload", "status", "error", "completed_at", "lease_expires_at"},
		`UPDATE _benmore_jobs SET status=CASE WHEN status IN ('pending','running') THEN 'failed' ELSE status END, error=CASE WHEN status IN ('pending','running') THEN 'cancelled: account deleted' ELSE error END, completed_at=CASE WHEN status IN ('pending','running') THEN datetime('now') ELSE completed_at END, lease_expires_at=NULL, payload='{}' WHERE json_valid(payload) AND CAST(json_extract(payload,'$.user_id') AS INTEGER)=?`, uid); err != nil {
		return 0, nil, err
	}

	// Retain compliance/governance records while removing direct email fields.
	// (the one privileged edit of the append-only audit tables, audit_append_only.go)
	if err := withAuditMutable(tx, func() error {
		if err := purgeAuditLogIdentity(tx, uid, email); err != nil {
			return err
		}
		// client_ip first (a database from before the column skips it): the
		// address would otherwise stay tied to the erased account's user_id.
		if _, err := purgeOptionalExec(tx, "_benmore_read_audit", []string{"user_id", "user_email", "client_ip"},
			`UPDATE _benmore_read_audit SET client_ip=NULL WHERE user_id=? OR (?<>'' AND lower(trim(user_email))=?)`, uid, email, email); err != nil {
			return err
		}
		if _, err := purgeOptionalExec(tx, "_benmore_read_audit", []string{"user_id", "user_email"},
			`UPDATE _benmore_read_audit SET user_email='' WHERE user_id=? OR (?<>'' AND lower(trim(user_email))=?)`, uid, email, email); err != nil {
			return err
		}
		// Reads the account made through support sessions keep its stable id
		// and lose its address and client address, like the audit log's
		// impersonator columns (a database from before them skips it).
		cols, exists, err := purgeTableColumns(tx, "_benmore_read_audit")
		if err != nil || !exists || !cols["impersonator_user_id"] || !cols["impersonator_email"] || !cols["client_ip"] {
			return err
		}
		if _, err := tx.Exec(`UPDATE _benmore_read_audit SET impersonator_email='', client_ip=NULL WHERE impersonator_user_id=? OR (?<>'' AND lower(trim(impersonator_email))=?)`, uid, email, email); err != nil {
			return fmt.Errorf("purge_current_user: mutate _benmore_read_audit: %w", err)
		}
		return nil
	}); err != nil {
		return 0, nil, err
	}
	if _, err := purgeOptionalExec(tx, "_benmore_feedback_comments", []string{"user_id", "user_email"},
		`UPDATE _benmore_feedback_comments SET user_email='' WHERE user_id=? OR (?<>'' AND lower(user_email)=?)`, uid, email, email); err != nil {
		return 0, nil, err
	}
	if email != "" {
		if _, err := purgeOptionalExec(tx, "_benmore_feedback", []string{"visitor_email", "visitor_name"},
			`UPDATE _benmore_feedback SET visitor_email='', visitor_name='' WHERE lower(visitor_email)=?`, email); err != nil {
			return 0, nil, err
		}
	}
	// A request addressed to the erased address can still hold another
	// account's id from when that account had registered it (see
	// approval_assignee.go). With the address blanked the row would read as
	// "approver named by id", so that stale id is cleared with it.
	// The reverse: a row bound to the erased account by id but addressed to
	// another address (the account changed its email, and whoever proved the
	// old address since owns the request) keeps that address and drops the
	// id. Blanking the address there handed the request to the tombstone, so
	// only an admin could decide it.
	if _, err := purgeOptionalExec(tx, "_benmore_approvals", []string{"requested_by", "requested_email", "approver_id", "approver_email"},
		`UPDATE _benmore_approvals SET requested_email=CASE WHEN requested_by=? OR (?<>'' AND lower(requested_email)=?) THEN '' ELSE requested_email END,
			approver_id=CASE
				WHEN approver_id<>? AND ?<>'' AND lower(approver_email)=? THEN NULL
				WHEN approver_id=? AND COALESCE(approver_email,'')<>'' AND NOT (?<>'' AND lower(approver_email)=?) THEN NULL
				ELSE approver_id END,
			approver_email=CASE WHEN ?<>'' AND lower(approver_email)=? THEN '' ELSE approver_email END
		 WHERE requested_by=? OR approver_id=? OR (?<>'' AND lower(requested_email)=?) OR (?<>'' AND lower(approver_email)=?)`,
		uid, email, email,
		uid, email, email,
		uid, email, email,
		email, email,
		uid, uid, email, email, email, email); err != nil {
		return 0, nil, err
	}
	if _, err := purgeOptionalExec(tx, "_benmore_imports", []string{"created_by", "created_by_subject"},
		`UPDATE _benmore_imports SET created_by_subject='' WHERE created_by=? OR (?<>'' AND lower(created_by_subject)=?)`, uid, email, email); err != nil {
		return 0, nil, err
	}
	// Retain grants/roles created for other people, but detach their historical
	// actor pointers from the now-deleted identity.
	if _, err := purgeOptionalExec(tx, "_benmore_user_roles", []string{"user_id", "granted_by"},
		`UPDATE _benmore_user_roles SET granted_by=NULL WHERE granted_by=?`, uid); err != nil {
		return 0, nil, err
	}
	if _, err := purgeOptionalExec(tx, "_benmore_permissions", []string{"grant_type", "grantee_id", "granted_by"},
		`UPDATE _benmore_permissions SET granted_by=NULL WHERE granted_by=?`, uid); err != nil {
		return 0, nil, err

	}

	// Ephemeral broadcast rows may be attributable by either stable user id or
	// one of the subject's sessions. Capture through the still-present session
	// rows before removing them below.
	if sessionCols["impersonator_session_id"] {
		if _, err := purgeOptionalExec(tx, "_benmore_broadcasts", []string{"publisher_user_id", "publisher_session_id"},
			`DELETE FROM _benmore_broadcasts WHERE publisher_user_id=? OR publisher_session_id IN (SELECT id FROM _benmore_sessions WHERE user_id=?)`, uid, uid); err != nil {
			return 0, nil, err
		}
	} else if _, err := purgeOptionalExec(tx, "_benmore_broadcasts", []string{"publisher_user_id", "publisher_session_id"},
		`DELETE FROM _benmore_broadcasts WHERE publisher_user_id=?`, uid); err != nil {
		return 0, nil, err
	}

	// Sessions are the last credentials removed so every earlier operation can
	// use their stable ids for exact matching.
	if sessionCols["impersonator_session_id"] {
		query := `DELETE FROM _benmore_sessions WHERE user_id=? OR impersonator_session_id IN (SELECT id FROM _benmore_sessions WHERE user_id=?)`
		args := []any{uid, uid}
		if sessionCols["impersonator_user_id"] && sessionCols["is_impersonation"] {
			query += ` OR (COALESCE(is_impersonation,0)=1 AND impersonator_user_id=?)`
			args = append(args, uid)
		}
		res, err := tx.Exec(query, args...)
		if err != nil {
			return 0, nil, fmt.Errorf("purge account: delete sessions: %w", err)
		}
		count, _ := res.RowsAffected()
		deleted += count
	} else {
		res, err := tx.Exec(`DELETE FROM _benmore_sessions WHERE user_id=?`, uid)
		if err != nil {
			return 0, nil, fmt.Errorf("purge account: delete sessions: %w", err)
		}
		count, _ := res.RowsAffected()
		deleted += count
	}

	tombstone, err := purgeTombstoneUsername(uid)
	if err != nil {
		return 0, nil, err
	}
	setParts := []string{
		"username=?", "email=NULL", "phone=NULL", "password_hash=NULL",
		"first_name='Deleted'", "last_name=''", "avatar_url=''", "role='user'",
		"verified=0", "last_login_at=NULL",
	}
	for _, col := range []string{"totp_secret", "backup_codes", "mfa_last_totp", "mfa_last_totp_at"} {
		if userCols[col] {
			setParts = append(setParts, col+"=NULL")
		}
	}
	res, err := tx.Exec(`UPDATE _benmore_users SET `+strings.Join(setParts, ", ")+` WHERE id=? AND deactivated_at IS NOT NULL`, tombstone, uid)
	if err != nil {
		return 0, nil, fmt.Errorf("purge account: write tombstone: %w", err)
	}
	if affected, _ := res.RowsAffected(); affected != 1 {
		return 0, nil, fmt.Errorf("purge account: tombstone affected %d rows, expected 1", affected)
	}

	// Audit is optional on legacy/minimal apps. Never create an optional table
	// from an erasure action; if it exists, its shape must be compatible.
	auditCols, auditExists, err := purgeTableColumns(tx, "_benmore_audit_log")
	if err != nil {
		return 0, nil, err
	}
	if auditExists {
		if err := purgeRequireColumns("_benmore_audit_log", auditCols, "action", "table_name", "row_id", "user_id", "user_email", "old_values", "new_values"); err != nil {
			return 0, nil, err
		}
		if _, err := tx.Exec(`INSERT INTO _benmore_audit_log(action,table_name,row_id,user_id,user_email,old_values,new_values) VALUES('account_purge','_benmore_users',?,?,?,NULL,NULL)`, strconv.FormatInt(uid, 10), actorID, actorEmail); err != nil {
			return 0, nil, fmt.Errorf("purge account: write audit marker: %w", err)
		}
	}
	return deleted, artifactRefs, nil
}
