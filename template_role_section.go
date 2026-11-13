//go:build !cli

package main

import "strings"

// roleSectionGlobalAdminKey is the render-data key that says the viewer is the
// app's global admin (Session.IsAdmin), set where a page's data is built. The
// role list a template can print (user_roles) cannot say it: that list also
// carries the tenant membership role and group-scoped grants.
const roleSectionGlobalAdminKey = "_user_global_admin"

// roleSectionOpen reports whether a `{{#role "a,b"}}` section renders for the
// viewer the render data describes: the viewer holds one of the listed roles
// by name (the account's role column, the tenant membership role, any role
// grant), or is the app's global admin, who opens every role section.
//
// `admin` (any letter case) names that global admin and nothing else, as on a
// page's `role=` gate (pageRoleAllowed) and a flow's (flowRoleAllowed): a
// page has no tenant to bound a tenant role named admin, so such a role opens
// neither an `admin` section nor, as it used to, every other role's section.
func roleSectionOpen(requiredRole string, data map[string]any) bool {
	userRole, _ := data["user_role"].(string)
	if userRole == "admin" || data[roleSectionGlobalAdminKey] == true {
		return true
	}
	appRole, _ := data["user_app_role"].(string)
	rolesAll, _ := data["user_roles"].(string)
	held := map[string]bool{userRole: true, appRole: true}
	for _, r := range strings.Split(rolesAll, ",") {
		held[strings.TrimSpace(r)] = true
	}
	for _, want := range strings.Split(requiredRole, ",") {
		want = strings.TrimSpace(want)
		if want != "" && !strings.EqualFold(want, "admin") && held[want] {
			return true
		}
	}
	return false
}
