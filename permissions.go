//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
)

// Permission hierarchy: admin > delete > edit > view.
// edit implies view. admin implies all + can share.
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

// hasPermission checks if a user has an explicit ACL grant for a resource.
// Returns true if the user's permission level >= the required level.
func hasPermission(db *sql.DB, resourceType string, resourceID string, email string, requiredPermission string) bool {
	requiredLevel, ok := permissionLevel[requiredPermission]
	if !ok {
		return false
	}

	var permission string
	err := db.QueryRow(`
		SELECT permission FROM _benmore_permissions
		WHERE resource_type = ? AND resource_id = ?
		AND grant_type = 'user' AND grantee_id = ?
		AND (expires_at IS NULL OR expires_at > datetime('now'))
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
	if session == nil {
		return false
	}
	// IsAdminBypass, not IsAdmin: a stepped-in admin acts AS the tenant, so it
	// can only share rows the tenant could (owner / admin-grant), not anything.
	if session.IsAdminBypass() {
		return true
	}
	// Check if user is the owner
	if hasColumn(app, table, "user_id") {
		var ownerID int64
		err := app.DB.QueryRow(fmt.Sprintf("SELECT user_id FROM %s WHERE id = ?", table), id).Scan(&ownerID)
		if err == nil && ownerID == session.UserID {
			return true
		}
	}
	// Check if user has admin permission on the resource
	return hasPermission(app.DB, table, id, session.Email, "admin")
}

// aclFilter returns a SQL subquery fragment and args for parameterized ACL checking.
// Returns (sqlFragment, args) where sqlFragment uses ? placeholders.
// Permission hierarchy: view < edit < delete < admin. edit implies view. admin implies all.
func aclFilter(table string, email string, minPermission string) (string, []any) {
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
		`id IN (SELECT resource_id FROM _benmore_permissions WHERE resource_type = ? AND grant_type = 'user' AND grantee_id = ? AND %s AND (expires_at IS NULL OR expires_at > datetime('now')))`,
		permFilter,
	)
	return sql, []any{table, email}
}

// RegisterPermissionRoutes sets up share/permissions/revoke endpoints for all user tables.
func RegisterPermissionRoutes(mux *http.ServeMux, app *App) {
	EnsurePermissionsTable(app.DB)

	tables, err := GetTableNames(app.DB)
	if err != nil {
		return
	}

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
	}

	log.Printf("  permissions: share/revoke API registered for %d tables", len(tables))
}

func handleShare(w http.ResponseWriter, r *http.Request, app *App, table string) {
	session := getSession(app, r)
	if session == nil {
		httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return
	}

	if err := checkScope(session, table, "write"); err != nil {
		httpJSON(w, http.StatusForbidden, map[string]any{"error": err.Error()})
		return
	}

	if !isBearerAuth(r) && !validateCSRF(r) {
		httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid CSRF token"})
		return
	}

	id := r.PathValue("id")

	if !canShareResource(app, table, id, session) {
		httpJSON(w, http.StatusForbidden, map[string]any{"error": "only the owner or an admin can share this resource"})
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
	if body.Email == "" || body.Permission == "" {
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": "email and permission required"})
		return
	}
	if _, valid := permissionLevel[body.Permission]; !valid {
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": fmt.Sprintf("invalid permission '%s' (valid: view, edit, delete, admin)", body.Permission)})
		return
	}

	var expiresAt *string
	if body.ExpiresAt != "" {
		expiresAt = &body.ExpiresAt
	}

	_, err := app.DB.Exec(`
		INSERT INTO _benmore_permissions (resource_type, resource_id, grant_type, grantee_id, permission, granted_by, expires_at)
		VALUES (?, ?, 'user', ?, ?, ?, ?)
		ON CONFLICT(resource_type, resource_id, grant_type, grantee_id)
		DO UPDATE SET permission = ?, granted_by = ?, expires_at = ?, granted_at = datetime('now')
	`, table, id, body.Email, body.Permission, session.UserID, expiresAt,
		body.Permission, session.UserID, expiresAt)

	if err != nil {
		httpJSON(w, http.StatusInternalServerError, map[string]any{"error": "share failed"})
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

func handleListPermissions(w http.ResponseWriter, r *http.Request, app *App, table string) {
	session := getSession(app, r)
	if session == nil {
		httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return
	}

	id := r.PathValue("id")

	// Must be owner, admin, or have admin permission on the resource to view permissions
	if !canShareResource(app, table, id, session) {
		httpJSON(w, http.StatusForbidden, map[string]any{"error": "not authorized to view permissions"})
		return
	}

	rows, err := QueryRows(app.DB, `
		SELECT id, grantee_id, permission, granted_at, expires_at
		FROM _benmore_permissions
		WHERE resource_type = ? AND resource_id = ?
		ORDER BY granted_at DESC
	`, table, id)

	if err != nil {
		httpJSON(w, http.StatusInternalServerError, map[string]any{"error": "query failed"})
		return
	}

	httpJSON(w, http.StatusOK, map[string]any{
		"resource_type": table,
		"resource_id":   id,
		"permissions":   rows,
	})
}

func handleRevokePermission(w http.ResponseWriter, r *http.Request, app *App, table string) {
	session := getSession(app, r)
	if session == nil {
		httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return
	}

	if !isBearerAuth(r) && !validateCSRF(r) {
		httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid CSRF token"})
		return
	}

	id := r.PathValue("id")
	permissionId := r.PathValue("permissionId")

	if !canShareResource(app, table, id, session) {
		httpJSON(w, http.StatusForbidden, map[string]any{"error": "not authorized to revoke"})
		return
	}

	result, err := app.DB.Exec(
		"DELETE FROM _benmore_permissions WHERE id = ? AND resource_type = ? AND resource_id = ?",
		permissionId, table, id,
	)
	if err != nil {
		httpJSON(w, http.StatusInternalServerError, map[string]any{"error": "revoke failed"})
		return
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		httpJSON(w, http.StatusNotFound, map[string]any{"error": "permission not found"})
		return
	}

	LogAudit(app, "revoke_share", table, id, session, nil, map[string]any{"permission_id": permissionId})

	httpJSON(w, http.StatusOK, map[string]any{"status": "revoked"})
}
