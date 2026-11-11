//go:build !cli

package main

import "strings"

// flowRoleAllowed reports whether session passes a flow's on.request.role
// gate. Every place that decides it calls this: the request (executeFlow), the
// queued run of an async flow (flowJobActorCheck), scheduling
// (schedulableFlow), the flows.json listing (flowListedFor), the connector
// read tool that calls the flow (appMCPToolAllowed) and the artifact such a
// tool stored (appMCPArtifactAuthorizedFrom).
//
// `role: admin` (any letter case) is the app's global admin: IsAdmin, the
// _benmore_users.role column or a group_id IS NULL admin grant. A session's
// role list also carries the tenant membership role (groups.role_field) and
// group-scoped grants, and with groups.bootstrap.founding_role "admin" every
// account that signs up and founds a tenant holds a role of that name. A flow
// has no tenant column to bound such a role (a table's `role:admin` rule
// does, through the tenant clause), and an admin-gated flow is typically a
// worker whose payload is trusted to come from the app's own producer, so
// matching by name let any founder run it with a payload of their choosing.
//
// Any other role name is matched by HasAnyRole, tenant roles included, so a
// `role: finance` flow keeps admitting a tenant's finance member. A flow the
// tenant's own admins should call checks the membership row in a step.
func flowRoleAllowed(session *Session, role string) bool {
	if session == nil {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(role), "admin") {
		return session.IsAdmin()
	}
	return HasAnyRole(session, []string{role})
}
