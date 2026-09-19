//go:build !cli

package main

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// flowResponseBuffer is deliberately tiny: purge flow validation permits only
// SQL/readback and respond steps after erasure, so the response is bounded JSON
// rather than a streamed file. It prevents a 200 from escaping before COMMIT.
type flowResponseBuffer struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func newFlowResponseBuffer() *flowResponseBuffer {
	return &flowResponseBuffer{header: make(http.Header)}
}

func (b *flowResponseBuffer) Header() http.Header { return b.header }

func (b *flowResponseBuffer) WriteHeader(status int) {
	if b.status == 0 {
		b.status = status
	}
}

func (b *flowResponseBuffer) Write(p []byte) (int, error) {
	if b.status == 0 {
		b.status = http.StatusOK
	}
	return b.body.Write(p)
}

func (b *flowResponseBuffer) flushTo(w http.ResponseWriter) {
	for key, values := range b.header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	status := b.status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_, _ = w.Write(b.body.Bytes())
}

func flowHasPurgeCurrentUser(steps []FlowStep) bool {
	for _, step := range steps {
		if step.Type == "purge_current_user" || flowHasPurgeCurrentUser(step.Steps) || flowHasPurgeCurrentUser(step.ElseSteps) || flowHasPurgeCurrentUser(step.OnError) {
			return true
		}
	}
	return false
}

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
		return fmt.Errorf("purge_current_user requires an immutable authenticated session")
	}
	if strings.HasPrefix(ctx.Session.ID, "apitoken:") || strings.HasPrefix(ctx.Session.ID, "edge:") {
		return fmt.Errorf("purge_current_user requires a live user session, not an API token or edge identity")
	}
	confirm := interpolateCtx(step.PurgeCurrentUserConfirm, ctx)
	if !constantTimeStringEqual(confirm, "DELETE") {
		return fmt.Errorf("purge_current_user confirmation must exactly equal DELETE")
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
	// This rejects persistent tokens, edge bridge identities, expired/revoked
	// sessions, and support impersonation even if a caller hand-builds context.
	liveSQL := `SELECT COUNT(*) FROM _benmore_sessions WHERE id=? AND user_id=?`
	if sessionCols["expires_at"] {
		liveSQL += ` AND datetime(expires_at) > datetime('now')`
	}
	if sessionCols["is_impersonation"] {
		liveSQL += ` AND COALESCE(is_impersonation,0)=0`
	}
	var live int
	if err := ctx.Tx.QueryRow(liveSQL, ctx.Session.ID, uid).Scan(&live); err != nil {
		return fmt.Errorf("purge_current_user: verify session: %w", err)
	}
	if live != 1 {
		return fmt.Errorf("purge_current_user requires one live, non-impersonated session")
	}

	var oldEmail sql.NullString
	claim := `UPDATE _benmore_users SET deactivated_at=datetime('now') WHERE id=? AND (deactivated_at IS NULL OR trim(CAST(deactivated_at AS TEXT))='') RETURNING email`
	if err := ctx.Tx.QueryRow(claim, uid).Scan(&oldEmail); err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("purge_current_user: account is missing or already deleted")
		}
		return fmt.Errorf("purge_current_user: claim account: %w", err)
	}
	email := strings.ToLower(strings.TrimSpace(oldEmail.String))

	deleted := int64(0)
	deleteSpecs := []purgeDeleteSpec{
		{"_benmore_api_tokens", []string{"user_id"}, `DELETE FROM _benmore_api_tokens WHERE user_id=?`, purgeUIDArgs, false},
		{"_benmore_oauth_tokens", []string{"user_id"}, `DELETE FROM _benmore_oauth_tokens WHERE user_id=?`, purgeUIDArgs, false},
		{"_benmore_oauth_codes", []string{"user_id"}, `DELETE FROM _benmore_oauth_codes WHERE user_id=?`, purgeUIDArgs, false},
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
		{"_benmore_request_log", []string{"user_id"}, `DELETE FROM _benmore_request_log WHERE user_id=? OR (?<>'' AND lower(user_id)=?)`, func(uid int64, email string) []any { return []any{"user:" + strconv.FormatInt(uid, 10), email, email} }, false},
		{"_benmore_usage", []string{"scope"}, `DELETE FROM _benmore_usage WHERE scope=?`, func(uid int64, _ string) []any { return []any{"user:" + strconv.FormatInt(uid, 10)} }, false},
	}
	for _, spec := range deleteSpecs {
		if spec.requiresEmail && email == "" {
			continue
		}
		n, err := purgeOptionalExec(ctx.Tx, spec.table, spec.columns, spec.query, spec.args(uid, email)...)
		if err != nil {
			return err
		}
		deleted += n
	}

	// Shared rate-limit buckets are credentials-adjacent transient state. Match
	// only framework-issued, exact subject keys; never use a suffix/substring
	// match that could erase another user's IP, group, or similarly named key.
	n, err := purgeOptionalExec(ctx.Tx, "_benmore_rate_limits", []string{"key"},
		`DELETE FROM _benmore_rate_limits WHERE key=? OR key=? OR (?<>'' AND key=?)`,
		"u:"+strconv.FormatInt(uid, 10), "user:"+strconv.FormatInt(uid, 10), email, "e:"+email)
	if err != nil {
		return err
	}
	deleted += n

	// Locks carry the email as well as the stable id.
	n, err = purgeOptionalExec(ctx.Tx, "_benmore_locks", []string{"user_id", "user_email"},
		`DELETE FROM _benmore_locks WHERE user_id=? OR (?<>'' AND lower(user_email)=?)`, uid, email, email)
	if err != nil {
		return err
	}
	deleted += n

	// Analytics has a child-before-parent dependency through visitor_id.
	visitors, visitorsExist, err := purgeTableColumns(ctx.Tx, "_benmore_visitors")
	if err != nil {
		return err
	}
	analytics, analyticsExist, err := purgeTableColumns(ctx.Tx, "_benmore_analytics")
	if err != nil {
		return err
	}
	if visitorsExist {
		if err := purgeRequireColumns("_benmore_visitors", visitors, "visitor_id", "user_id"); err != nil {
			return err
		}
		if analyticsExist {
			if err := purgeRequireColumns("_benmore_analytics", analytics, "visitor_id"); err != nil {
				return err
			}
			res, err := ctx.Tx.Exec(`DELETE FROM _benmore_analytics WHERE visitor_id IN (SELECT visitor_id FROM _benmore_visitors WHERE user_id=?)`, uid)
			if err != nil {
				return fmt.Errorf("purge_current_user: delete _benmore_analytics: %w", err)
			}
			count, _ := res.RowsAffected()
			deleted += count
		}
		res, err := ctx.Tx.Exec(`DELETE FROM _benmore_visitors WHERE user_id=?`, uid)
		if err != nil {
			return fmt.Errorf("purge_current_user: delete _benmore_visitors: %w", err)
		}
		count, _ := res.RowsAffected()
		deleted += count
	} else if analyticsExist {
		// An analytics table without the identity mapping contains no provable
		// subject link; preserve it rather than guessing from free-form data.
		if err := purgeRequireColumns("_benmore_analytics", analytics, "visitor_id"); err != nil {
			return err
		}
	}

	// Cancel queued work attributable through valid JSON, then erase the
	// copied user object/email from every terminal state as well.
	if _, err := purgeOptionalExec(ctx.Tx, "_benmore_jobs",
		[]string{"payload", "status", "error", "completed_at", "lease_expires_at"},
		`UPDATE _benmore_jobs SET status=CASE WHEN status IN ('pending','running') THEN 'failed' ELSE status END, error=CASE WHEN status IN ('pending','running') THEN 'cancelled: account deleted' ELSE error END, completed_at=CASE WHEN status IN ('pending','running') THEN datetime('now') ELSE completed_at END, lease_expires_at=NULL, payload='{}' WHERE json_valid(payload) AND CAST(json_extract(payload,'$.user_id') AS INTEGER)=?`, uid); err != nil {
		return err
	}

	// Retain compliance/governance records while removing direct email fields.
	if _, err := purgeOptionalExec(ctx.Tx, "_benmore_audit_log",
		[]string{"user_id", "user_email", "table_name", "row_id", "old_values", "new_values"},
		`UPDATE _benmore_audit_log SET user_email='', old_values=CASE WHEN table_name='_benmore_users' AND row_id=CAST(? AS TEXT) THEN NULL ELSE old_values END, new_values=CASE WHEN table_name='_benmore_users' AND row_id=CAST(? AS TEXT) THEN NULL ELSE new_values END WHERE user_id=?`, uid, uid, uid); err != nil {
		return err
	}
	if _, err := purgeOptionalExec(ctx.Tx, "_benmore_read_audit", []string{"user_id", "user_email"},
		`UPDATE _benmore_read_audit SET user_email='' WHERE user_id=?`, uid); err != nil {
		return err
	}
	if _, err := purgeOptionalExec(ctx.Tx, "_benmore_feedback_comments", []string{"user_id", "user_email"},
		`UPDATE _benmore_feedback_comments SET user_email='' WHERE user_id=? OR (?<>'' AND lower(user_email)=?)`, uid, email, email); err != nil {
		return err
	}
	if email != "" {
		if _, err := purgeOptionalExec(ctx.Tx, "_benmore_feedback", []string{"visitor_email", "visitor_name"},
			`UPDATE _benmore_feedback SET visitor_email='', visitor_name='' WHERE lower(visitor_email)=?`, email); err != nil {
			return err
		}
	}
	if _, err := purgeOptionalExec(ctx.Tx, "_benmore_approvals", []string{"requested_by", "requested_email", "approver_id", "approver_email"},
		`UPDATE _benmore_approvals SET requested_email=CASE WHEN requested_by=? OR (?<>'' AND lower(requested_email)=?) THEN '' ELSE requested_email END, approver_email=CASE WHEN approver_id=? OR (?<>'' AND lower(approver_email)=?) THEN '' ELSE approver_email END WHERE requested_by=? OR approver_id=? OR (?<>'' AND lower(requested_email)=?) OR (?<>'' AND lower(approver_email)=?)`, uid, email, email, uid, email, email, uid, uid, email, email, email, email); err != nil {
		return err
	}
	if _, err := purgeOptionalExec(ctx.Tx, "_benmore_imports", []string{"created_by", "created_by_subject"},
		`UPDATE _benmore_imports SET created_by_subject='' WHERE created_by=? OR (?<>'' AND lower(created_by_subject)=?)`, uid, email, email); err != nil {
		return err
	}
	// Retain grants/roles created for other people, but detach their historical
	// actor pointers from the now-deleted identity.
	if _, err := purgeOptionalExec(ctx.Tx, "_benmore_user_roles", []string{"user_id", "granted_by"},
		`UPDATE _benmore_user_roles SET granted_by=NULL WHERE granted_by=?`, uid); err != nil {
		return err
	}
	if _, err := purgeOptionalExec(ctx.Tx, "_benmore_permissions", []string{"grant_type", "grantee_id", "granted_by"},
		`UPDATE _benmore_permissions SET granted_by=NULL WHERE granted_by=?`, uid); err != nil {
		return err

	}

	// Ephemeral broadcast rows may be attributable by either stable user id or
	// one of the subject's sessions. Capture through the still-present session
	// rows before removing them below.
	if sessionCols["impersonator_session_id"] {
		if _, err := purgeOptionalExec(ctx.Tx, "_benmore_broadcasts", []string{"publisher_user_id", "publisher_session_id"},
			`DELETE FROM _benmore_broadcasts WHERE publisher_user_id=? OR publisher_session_id IN (SELECT id FROM _benmore_sessions WHERE user_id=?)`, uid, uid); err != nil {
			return err
		}
	} else if _, err := purgeOptionalExec(ctx.Tx, "_benmore_broadcasts", []string{"publisher_user_id", "publisher_session_id"},
		`DELETE FROM _benmore_broadcasts WHERE publisher_user_id=?`, uid); err != nil {
		return err
	}

	// Sessions are the last credentials removed so every earlier operation can
	// use their stable ids for exact matching.
	if sessionCols["impersonator_session_id"] {
		res, err := ctx.Tx.Exec(`DELETE FROM _benmore_sessions WHERE user_id=? OR impersonator_session_id IN (SELECT id FROM _benmore_sessions WHERE user_id=?)`, uid, uid)
		if err != nil {
			return fmt.Errorf("purge_current_user: delete sessions: %w", err)
		}
		count, _ := res.RowsAffected()
		deleted += count
	} else {
		res, err := ctx.Tx.Exec(`DELETE FROM _benmore_sessions WHERE user_id=?`, uid)
		if err != nil {
			return fmt.Errorf("purge_current_user: delete sessions: %w", err)
		}
		count, _ := res.RowsAffected()
		deleted += count
	}

	tombstone, err := purgeTombstoneUsername(uid)
	if err != nil {
		return err
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
	res, err := ctx.Tx.Exec(`UPDATE _benmore_users SET `+strings.Join(setParts, ", ")+` WHERE id=? AND deactivated_at IS NOT NULL`, tombstone, uid)
	if err != nil {
		return fmt.Errorf("purge_current_user: write tombstone: %w", err)
	}
	if affected, _ := res.RowsAffected(); affected != 1 {
		return fmt.Errorf("purge_current_user: tombstone affected %d rows, expected 1", affected)
	}

	// Audit is optional on legacy/minimal apps. Never create an optional table
	// from an erasure action; if it exists, its shape must be compatible.
	auditCols, auditExists, err := purgeTableColumns(ctx.Tx, "_benmore_audit_log")
	if err != nil {
		return err
	}
	if auditExists {
		if err := purgeRequireColumns("_benmore_audit_log", auditCols, "action", "table_name", "row_id", "user_id", "user_email", "old_values", "new_values"); err != nil {
			return err
		}
		if _, err := ctx.Tx.Exec(`INSERT INTO _benmore_audit_log(action,table_name,row_id,user_id,user_email,old_values,new_values) VALUES('account_purge','_benmore_users',?,?, '',NULL,NULL)`, strconv.FormatInt(uid, 10), uid); err != nil {
			return fmt.Errorf("purge_current_user: write audit marker: %w", err)
		}
	}

	if step.Name != "" {
		ctx.DataMu.Lock()
		ctx.Data[step.Name] = map[string]any{"purged": 1, "user_id": uid, "framework_rows_deleted": deleted}
		ctx.DataMu.Unlock()
	}
	return nil
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
	rows, err := tx.Query(`PRAGMA table_info("` + table + `")`)
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
