//go:build !cli

package main

// A configured role field is authoritative. The historical `role` column is
// supported only when no role_field was configured; missing or empty configured
// values must not revive authority from a stale legacy column.
func workflowMembershipRoleField(app *App) string {
	if app == nil || app.Group == nil {
		return ""
	}
	field := app.Group.RoleField
	if field == "" {
		field = "role"
	}
	if !hasColumn(app, app.Group.Table, field) {
		return ""
	}
	return field
}
