//go:build !cli

package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// EnsureRoleColumn adds a role column to _benmore_users if it doesn't exist.
// Now a no-op for new databases (role is in default schema), but kept for
// existing databases that predate EnsureUsersTable's expanded defaults.
func EnsureRoleColumn(db *sql.DB) {
	var count int
	db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('_benmore_users') WHERE name='role'").Scan(&count)
	if count == 0 {
		db.Exec("ALTER TABLE _benmore_users ADD COLUMN role TEXT DEFAULT 'user'")
	}
}

// RoleMiddleware checks if the user has the required role for a page.
// Supports comma-separated roles: role="admin,org" means user needs ANY of them.
// Checks _benmore_users.role - works with both built-in (admin/manager/editor/user)
// and developer-defined roles from app.yaml.
func RoleMiddleware(app *App, page *Page, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requiredRole := extractPageRole(page.RawHTML)
		// role="" and role="public" both mean "anyone can view this page".
		// Previously "public" was treated as a gated role and redirected
		// anonymous visitors to /login - breaking landing / auth / marketing
		// pages that tagged themselves role="public" expecting anonymous access.
		if requiredRole == "" || requiredRole == "public" {
			next(w, r)
			return
		}

		session := getSession(app, r)
		if session == nil {
			http.Redirect(w, r, app.Paths.Login+"?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
			return
		}

		userRole := getUserRole(app.DB, session.UserID)

		// Support comma-separated: role="admin,org" - user needs ANY match
		allowed := false
		for _, role := range strings.Split(requiredRole, ",") {
			role = strings.TrimSpace(role)
			if role == "" {
				continue
			}
			if hasRole(userRole, role) {
				allowed = true
				break
			}
		}

		if !allowed {
			http.Error(w, "Forbidden - insufficient permissions", http.StatusForbidden)
			return
		}

		next(w, r)
	}
}

// getUserRole fetches the role for a user.
func getUserRole(db *sql.DB, userID int64) string {
	var role sql.NullString
	db.QueryRow("SELECT role FROM _benmore_users WHERE id = ?", userID).Scan(&role)
	if role.Valid && role.String != "" {
		return role.String
	}
	return "user"
}

// hasRole checks if a user's platform role satisfies the requirement.
// Built-in hierarchy: admin > manager > editor > user.
// Custom roles (not in hierarchy) use exact match - no implicit escalation.
func hasRole(userRole, requiredRole string) bool {
	hierarchy := map[string]int{
		"admin":   100,
		"manager": 50,
		"editor":  30,
		"user":    10,
	}

	requiredLevel, inHierarchy := hierarchy[strings.ToLower(requiredRole)]
	if !inHierarchy {
		// Custom role: exact match only (e.g., "org", "mgmt", "site")
		return strings.EqualFold(userRole, requiredRole)
	}

	userLevel := hierarchy[strings.ToLower(userRole)]
	if userLevel == 0 {
		userLevel = 10 // default to user
	}

	return userLevel >= requiredLevel
}

// extractPageRole gets the role="..." attribute from the page HTML.
func extractPageRole(html string) string {
	attrs := pageAttrRe.FindStringSubmatch(html)
	if attrs == nil {
		return ""
	}
	parsed := parseAttrs(attrs[1])
	return parsed["role"]
}

// RequireMiddleware checks generic user field requirements from <page require="plan:pro,enterprise verified:1">.
// Each requirement is "field:value1,value2" - the user's field must match one of the values.
func RequireMiddleware(app *App, page *Page, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		require := page.Require
		if require == "" {
			next(w, r)
			return
		}

		session := getSession(app, r)
		if session == nil {
			http.Redirect(w, r, app.Paths.Login+"?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
			return
		}

		// Load user fields
		userMap := LoadUserFields(app.DB, session.UserID)
		if userMap == nil {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		if !checkRequireFields(require, userMap) {
			http.Error(w, "Forbidden - insufficient access", http.StatusForbidden)
			return
		}

		next(w, r)
	}
}

// SetUserRole updates a user's role (admin function).
// Roles are developer-defined - any non-empty string is valid.
func SetUserRole(db *sql.DB, userID int64, role string) error {
	role = strings.TrimSpace(strings.ToLower(role))
	if role == "" {
		return fmt.Errorf("role cannot be empty")
	}
	_, err := db.Exec("UPDATE _benmore_users SET role = ? WHERE id = ?", role, userID)
	return err
}
