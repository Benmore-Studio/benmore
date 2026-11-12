//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// Known grant names and legacy ranks for hasPermission's admin-sharing check.
// Native CRUD uses aclFilter's action sets: edit and delete each include view,
// but neither includes the other. Only admin includes both and can share.
var permissionLevel = map[string]int{
	"view":   1,
	"edit":   2,
	"delete": 3,
	"admin":  4,
}

// EnsurePermissionsTable creates the resource-level ACL table.
func EnsurePermissionsTable(db *sql.DB) {
	db.Exec(`CREATE TABLE IF NOT EXISTS _benmore_permissions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		resource_type TEXT NOT NULL,
		resource_id TEXT NOT NULL,
		grant_type TEXT NOT NULL,
		grantee_id TEXT NOT NULL,
		permission TEXT NOT NULL,
		granted_by INTEGER,
		granted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		expires_at DATETIME,
		UNIQUE(resource_type, resource_id, grant_type, grantee_id),
		FOREIGN KEY (granted_by) REFERENCES _benmore_users(id)
	)`)
	db.Exec("CREATE INDEX IF NOT EXISTS idx_benmore_perm_resource ON _benmore_permissions(resource_type, resource_id)")
	db.Exec("CREATE INDEX IF NOT EXISTS idx_benmore_perm_grantee ON _benmore_permissions(resource_type, grantee_id)")
}

// hasPermission is the legacy ranked lookup used for the admin-sharing check.
// CRUD action authority comes from rowScopeClause/aclFilter, not these ranks.
func hasPermission(db *sql.DB, resourceType string, resourceID string, email string, requiredPermission string) bool {
	requiredLevel, ok := permissionLevel[requiredPermission]
	if !ok || email == "" {
		return false
	}

	var permission string
	err := db.QueryRow(`
		SELECT permission FROM _benmore_permissions
		WHERE resource_type = ? AND resource_id = ?
		AND grant_type = 'user' AND grantee_id = ?
		AND (expires_at IS NULL OR datetime(expires_at) > datetime('now'))
		LIMIT 1
	`, resourceType, resourceID, email).Scan(&permission)

	if err != nil {
		return false
	}

	grantedLevel, ok := permissionLevel[permission]
	if !ok {
		return false
	}

	return grantedLevel >= requiredLevel
}

// canShareResource checks if the session user can share a resource.
// Owner (user_id), admin permission holder, or platform admin can share.
func canShareResource(app *App, table string, id string, session *Session) bool {
	// Grants are keyed by the id text: only the row's canonical id names it
	// (rowIDCanonical), for admins too.
	if session == nil || !rowIDCanonical(app, table, id) {
		return false
	}
	// IsAdminBypass, not IsAdmin: a stepped-in admin acts AS the tenant, so it
	// can only share rows the tenant could (owner / admin-grant), not anything.
	// IsAdminConsole as well: handing out and revoking access on any row is
	// admin management (security.md 15b), so an admin's scoped API token
	// (delegated access, say notes:write for an integration) gets only what
	// the owner and admin-grant checks below give any other caller.
	if session.IsAdminBypass() && session.IsAdminConsole() {
		return true
	}
	// Sharing hands out access, so the caller must STILL be able to edit the
	// row under the table's access mode and the canonical row scope (tenant,
	// membership, ownership). Owning user_id alone let a creator who left the
	// tenant or lost membership re-grant themselves access.
	if !SessionCanAccessTable(app, table, OpUpdate, session) || !canAccessRowScoped(app, table, id, session, "edit") || membershipRowControlDenied(app, table, id, session) {
		return false
	}
	// Check if user is the owner
	if hasColumn(app, table, "user_id") {
		var ownerID int64
		err := app.DB.QueryRow("SELECT user_id FROM "+quoteIdent(table)+" WHERE id = ?", id).Scan(&ownerID)
		if err == nil && ownerID == session.UserID {
			return true
		}
	}
	// Check if user has admin permission on the resource. With record sharing
	// off for the table no grant is in force, an admin grant included.
	return recordSharingEnabled(app, table) && hasPermission(app.DB, table, id, sessionGrantEmail(session), "admin")
}

// sharingDisabledCode is the stable `error` value of a share refused because
// record sharing is off for the table (features.sharing, access.<table>.share).
const sharingDisabledCode = "sharing_disabled"

// aclFilter returns a parameterized SQL subquery for a required action.
// All grants include view; edit/admin permit edits; delete/admin permit deletes.
// A delete-only grant does not permit edits or restore (which requires update).
func aclFilter(table string, email string, minPermission string) (string, []any) {
	// Shares are addressed to an email; callers pass "" (sessionGrantEmail)
	// until the account has verified it, and "" never matches a grant.
	if email == "" {
		return "0", nil
	}
	var permFilter string
	switch minPermission {
	case "view":
		permFilter = "permission IN ('view','edit','delete','admin')"
	case "edit":
		permFilter = "permission IN ('edit','admin')"
	case "delete":
		permFilter = "permission IN ('delete','admin')"
	default:
		permFilter = "permission = 'admin'"
	}

	sql := fmt.Sprintf(
		`id IN (SELECT resource_id FROM main._benmore_permissions WHERE resource_type = ? AND grant_type = 'user' AND grantee_id = ? AND %s AND (expires_at IS NULL OR datetime(expires_at) > datetime('now')))`,
		permFilter,
	)
	return sql, []any{table, email}
}

// RegisterPermissionRoutes sets up share/permissions/revoke endpoints for all user tables.
func RegisterPermissionRoutes(mux appRouteRegistrar, app *App) {
	EnsurePermissionsTable(app.DB)

	tables, err := GetTableNames(app.DB)
	if err != nil {
		return
	}

	registerPermissionTables(mux, app, tables)
}

func registerPermissionTables(mux appRouteRegistrar, app *App, tables []string) {
	for _, table := range tables {
		if strings.HasPrefix(table, "_benmore_") {
			continue
		}
		t := table

		// POST /api/{table}/{id}/share
		mux.HandleFunc(fmt.Sprintf("POST /api/%s/{id}/share", t), func(w http.ResponseWriter, r *http.Request) {
			handleShare(w, r, app, t)
		})

		// GET /api/{table}/{id}/permissions
		mux.HandleFunc(fmt.Sprintf("GET /api/%s/{id}/permissions", t), func(w http.ResponseWriter, r *http.Request) {
			handleListPermissions(w, r, app, t)
		})

		// DELETE /api/{table}/{id}/share/{permissionId}
		mux.HandleFunc(fmt.Sprintf("DELETE /api/%s/{id}/share/{permissionId}", t), func(w http.ResponseWriter, r *http.Request) {
			handleRevokePermission(w, r, app, t)
		})

		// The browser SDK identifies user grants by email rather than ledger ID.
		mux.HandleFunc(fmt.Sprintf("DELETE /api/%s/{id}/permissions/{email}", t), func(w http.ResponseWriter, r *http.Request) {
			handleRevokePermission(w, r, app, t)
		})
	}

	routeInfof(mux, "  permissions: share/revoke API registered for %d tables", len(tables))
}

// The share, list and revoke handlers answer every refusal through
// writeTableRefusal: a caller who may not read the table gets the
// unmatched-route 404 (security.md 14f), not a 403 that confirmed the table
// exists; a caller who may read it keeps the 403 naming what was refused.
func handleShare(w http.ResponseWriter, r *http.Request, app *App, table string) {
	session := getSession(app, r)
	if session == nil {
		httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return
	}

	if err := checkScope(session, table, "write"); err != nil {
		writeTableRefusal(w, app, table, session, http.StatusForbidden, scopeDeniedBody(err))
		return
	}

	if !isBearerAuth(r) && !validateCSRF(r) {
		httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid CSRF token"})
		return
	}

	// The switch is the app's configuration, read before the row: the answer
	// is the same for every id, so it says nothing about which rows exist.
	if !recordSharingEnabled(app, table) {
		writeTableRefusal(w, app, table, session, http.StatusForbidden, withRefusalDocs(map[string]any{
			"error":   sharingDisabledCode,
			"message": fmt.Sprintf("record sharing is turned off for %s (features.sharing or access.%s.share in app.yaml): nothing was shared", table, table),
		}, sharingDisabledCode))
		return
	}

	id := r.PathValue("id")

	if !canShareResource(app, table, id, session) {
		writeTableRefusal(w, app, table, session, http.StatusForbidden, map[string]any{"error": "only the owner or an admin can share this resource"})
		return
	}

	var body struct {
		Email      string `json:"email"`
		Permission string `json:"permission"`
		ExpiresAt  string `json:"expires_at"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid request"})
		return
	}
	if normalizeEmail(body.Email) == "" || body.Permission == "" {
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": "email and permission required"})
		return
	}
	if _, valid := permissionLevel[body.Permission]; !valid {
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": fmt.Sprintf("invalid permission '%s' (valid: view, edit, delete, admin)", body.Permission)})
		return
	}
	recipient, ambiguous, err := resolveShareRecipient(app.DB, body.Email)
	if err != nil {
		serverErrorJSON(w, r, app, table+" permissions", err, "share failed")
		return
	}
	if ambiguous {
		httpJSON(w, http.StatusConflict, map[string]any{"error": "recipient email is ambiguous; contact the app administrator"})
		return
	}
	body.Email = recipient

	var expiresAt *string
	if body.ExpiresAt != "" {
		// Use the ACL's existing SQLite parser, preserving supported formats
		// and valid past timestamps without normalizing stored values.
		var parsed sql.NullString
		if err := app.DB.QueryRowContext(r.Context(), "SELECT datetime(?)", body.ExpiresAt).Scan(&parsed); err != nil {
			serverErrorJSON(w, r, app, table+" permissions expiry", err, "share failed")
			return
		}
		if !parsed.Valid {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "expires_at must be a valid date or timestamp"})
			return
		}
		expiresAt = &body.ExpiresAt
	}

	_, err = app.DB.Exec(`
		INSERT INTO _benmore_permissions (resource_type, resource_id, grant_type, grantee_id, permission, granted_by, expires_at)
		VALUES (?, ?, 'user', ?, ?, ?, ?)
		ON CONFLICT(resource_type, resource_id, grant_type, grantee_id)
		DO UPDATE SET permission = ?, granted_by = ?, expires_at = ?, granted_at = datetime('now')
	`, table, id, body.Email, body.Permission, session.UserID, expiresAt,
		body.Permission, session.UserID, expiresAt)

	if err != nil {
		serverErrorJSON(w, r, app, table+" permissions", err, "share failed")
		return
	}

	LogAudit(app, "share", table, id, session,
		nil, map[string]any{"shared_with": body.Email, "permission": body.Permission})

	httpJSON(w, http.StatusOK, map[string]any{
		"status":     "shared",
		"email":      body.Email,
		"permission": body.Permission,
	})
}

// Resolve only a new share's recipient, using password login's email predicate.
// Sessions and ACL reads retain the account's exact stored spelling. Legacy
// case-duplicate accounts are ambiguous even if only one is verified or active.
// An absent future recipient keeps the original spelling for compatibility.
func resolveShareRecipient(db *sql.DB, email string) (recipient string, ambiguous bool, err error) {
	rows, err := db.Query("SELECT email FROM _benmore_users WHERE email = ? COLLATE NOCASE LIMIT 2", normalizeEmail(email))
	if err != nil {
		return "", false, err
	}
	defer rows.Close() // release the read cursor before the caller's upsert
	count := 0
	for rows.Next() {
		if err := rows.Scan(&recipient); err != nil {
			return "", false, err
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return "", false, err
	}
	if count == 0 {
		return email, false, nil
	}
	return recipient, count > 1, nil
}

func handleListPermissions(w http.ResponseWriter, r *http.Request, app *App, table string) {
	session := getSession(app, r)
	if session == nil {
		httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return
	}
	// Token scopes apply to ACL management like any other table operation.
	if err := checkScope(session, table, "read"); err != nil {
		writeTableRefusal(w, app, table, session, http.StatusForbidden, scopeDeniedBody(err))
		return
	}

	id := r.PathValue("id")

	// Must be owner, admin, or have admin permission on the resource to view permissions
	if !canShareResource(app, table, id, session) {
		writeTableRefusal(w, app, table, session, http.StatusForbidden, map[string]any{"error": "not authorized to view permissions"})
		return
	}

	rows, err := queryMetadataRows(app.DB, `
		SELECT id, grantee_id, permission, granted_at, expires_at
		FROM _benmore_permissions
		WHERE resource_type = ? AND resource_id = ?
		ORDER BY granted_at DESC
	`, table, id)

	if err != nil {
		serverErrorJSON(w, r, app, table+" permissions", err, "query failed")
		return
	}

	out := map[string]any{
		"resource_type": table,
		"resource_id":   id,
		"permissions":   rows,
	}
	// With sharing off the grants stay stored and give no access: the list
	// says so, and the owner can still revoke them before it is turned on.
	if !recordSharingEnabled(app, table) {
		out["sharing"] = "off"
		for _, row := range rows {
			row["active"] = false
		}
	}
	httpJSON(w, http.StatusOK, out)
}

func handleRevokePermission(w http.ResponseWriter, r *http.Request, app *App, table string) {
	session := getSession(app, r)
	if session == nil {
		httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return
	}
	if err := checkScope(session, table, "write"); err != nil {
		writeTableRefusal(w, app, table, session, http.StatusForbidden, scopeDeniedBody(err))
		return
	}

	if !isBearerAuth(r) && !validateCSRF(r) {
		httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid CSRF token"})
		return
	}

	id := r.PathValue("id")
	permissionId := r.PathValue("permissionId")

	if !canShareResource(app, table, id, session) {
		writeTableRefusal(w, app, table, session, http.StatusForbidden, map[string]any{"error": "not authorized to revoke"})
		return
	}

	query := "DELETE FROM _benmore_permissions WHERE id = ? AND resource_type = ? AND resource_id = ?"
	target := permissionId
	auditTarget := map[string]any{"permission_id": permissionId}
	if email := r.PathValue("email"); email != "" {
		// Keep both routes behind the same scope, CSRF and record authority gates.
		// An email addresses only user grants on this row, never role grants or
		// grants on another row. The SDK URL-encodes the email as one path segment.
		target = strings.TrimSpace(email)
		query = "DELETE FROM _benmore_permissions WHERE grantee_id = ? COLLATE NOCASE AND resource_type = ? AND resource_id = ? AND grant_type = 'user'"
		auditTarget = map[string]any{"shared_with": target}
	}
	result, err := app.DB.Exec(query, target, table, id)
	if err != nil {
		serverErrorJSON(w, r, app, table+" permissions", err, "revoke failed")
		return
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		httpJSON(w, http.StatusNotFound, map[string]any{"error": "permission not found"})
		return
	}

	LogAudit(app, "revoke_share", table, id, session, nil, auditTarget)

	httpJSON(w, http.StatusOK, map[string]any{"status": "revoked"})
}
