//go:build !cli

package main

// A workflow transition's `role:` is an any-of list, like an access
// `role:a,b` mode: one name, a comma-separated string ("owner, manager") or a
// YAML list ([owner, manager]). The list used to be compared as one exact
// string, so `role: "owner,manager"` was held by no one and locked the
// transition for every non-admin while push and `benmore check` accepted it.

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

// workflowRoleYAML is a transition's raw `role:` value. Each accepted form
// decodes to the comma-separated text workflowRoleNames splits.
type workflowRoleYAML string

// UnmarshalYAML accepts a scalar (one role, or a comma-separated list) or a
// sequence of scalars. Anything else, and a list that names no role, is a
// load error rather than a gate that silently means something else.
func (r *workflowRoleYAML) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.AliasNode && node.Alias != nil {
		node = node.Alias
	}
	switch node.Kind {
	case yaml.ScalarNode:
		if node.Tag == "!!null" {
			*r = ""
			return nil
		}
		*r = workflowRoleYAML(node.Value)
		return nil
	case yaml.SequenceNode:
		names := make([]string, 0, len(node.Content))
		for _, item := range node.Content {
			if item.Kind == yaml.AliasNode && item.Alias != nil {
				item = item.Alias
			}
			if item.Kind != yaml.ScalarNode || item.Tag == "!!null" {
				return fmt.Errorf("line %d: a transition role: list holds role names only", item.Line)
			}
			names = append(names, item.Value)
		}
		joined := strings.Join(names, ",")
		if len(workflowRoleNames(joined)) == 0 {
			return fmt.Errorf("line %d: transition role: [] names no role; drop the key to let anyone who may update the row make the transition", node.Line)
		}
		*r = workflowRoleYAML(joined)
		return nil
	}
	return fmt.Errorf("line %d: a transition role: is a role name, a comma-separated list or a YAML list of role names", node.Line)
}

// canonicalWorkflowRole is the stored form of a transition role: its names
// joined with "," ("owner, manager" → "owner,manager"). Text that names no
// role ("," or blanks) is kept as written, so it still gates the transition
// (only an admin passes) instead of becoming "no role"; the write gate refuses
// it.
func canonicalWorkflowRole(raw string) string {
	names := workflowRoleNames(raw)
	if len(names) == 0 {
		return raw
	}
	return strings.Join(names, ",")
}

// workflowRoleNames is the any-of list a transition's `role:` names, split
// like an access `role:a,b` mode (splitCommaList). Empty when it names none.
func workflowRoleNames(required string) []string {
	return splitCommaList(required)
}

// workflowRoleRequired is the refusal message for a transition's `role:`.
func workflowRoleRequired(required string) string {
	names := workflowRoleNames(required)
	if len(names) < 2 {
		return fmt.Sprintf("role '%s' required for this transition", strings.TrimSpace(required))
	}
	return fmt.Sprintf("one of the roles '%s' required for this transition", strings.Join(names, "', '"))
}

// workflowTenantBound reports whether a role held inside one tenant (the
// membership role, a grant scoped to the tenant) counts for a transition on
// table, as tableModeAllowed counts it for a `role:` access rule: the table
// carries the tenant key, or the app lists it in groups.shared. An app with
// no tenant key has no tenants to bound.
func workflowTenantBound(app *App, table string) bool {
	if app == nil {
		return true
	}
	// The published group configuration, read under the reload lock.
	group := app.groupConfig()
	return group == nil || group.Key == "" || hasColumn(app, table, group.Key) || groupSharedTable(app, table)
}

// workflowMembershipRoleAllowed reports whether the caller's membership role
// in the effective tenant (memberRole, "" when there is none) satisfies a
// transition's role list on table: an exact match on a listed name.
//
// `admin` (any letter case) is the exception on a table the tenant does not
// bound (workflowTenantBound): there it is the app's global admin, as a flow's
// `role: admin` is (flowRoleAllowed) and as a `role:admin` access rule on the
// table is (tableModeAllowed). Such a table has no tenant column to keep one
// tenant's admin to its own rows, and with groups.bootstrap.founding_role
// "admin" every account that founds a tenant holds a role of that name. That
// holds for `admin` in a list too. The CRUD transition route (hasWorkflowRole)
// and an approved command (appMCPCommandHasWorkflowRole) both decide here.
func workflowMembershipRoleAllowed(app *App, table string, roles []string, memberRole string) bool {
	if memberRole == "" || !slices.Contains(roles, memberRole) {
		return false
	}
	return !strings.EqualFold(memberRole, "admin") || workflowTenantBound(app, table)
}

// workflowBuiltinRoles are the role names the runtime knows without any
// declaration: admin and the _benmore_users.role hierarchy (hasRole).
var workflowBuiltinRoles = []string{"admin", "manager", "editor", "user"}

// workflowRoleWarnings flags each transition role name that no other part of
// the app names - likely a typo. A misspelled role is held by no one, so the
// transition stays open only to admins. Advisory: an in-tenant role can exist
// only as data in the membership table. Run by the write gate and `benmore
// check` (runCheckWithLive).
func workflowRoleWarnings(dir string) []CheckFinding {
	data, err := os.ReadFile(filepath.Join(dir, "workflows.yaml"))
	if err != nil {
		return nil
	}
	cfg, err := parseWorkflowsYAML(data)
	if err != nil || cfg == nil {
		return nil // the write gate reports the parse error
	}
	type use struct{ where, role string }
	var uses []use
	for _, name := range sortedWhenKeys(cfg.Workflows) {
		wf := cfg.Workflows[name]
		for _, from := range sortedWhenKeys(wf.Transitions) {
			for _, to := range sortedWhenKeys(wf.Transitions[from]) {
				for _, role := range workflowRoleNames(wf.Transitions[from][to].Role) {
					uses = append(uses, use{fmt.Sprintf("%s.transitions.%s -> %s", name, from, to), role})
				}
			}
		}
	}
	if len(uses) == 0 {
		return nil
	}

	known := map[string]bool{}
	add := func(list string) {
		for _, r := range splitCommaList(list) {
			known[strings.ToLower(r)] = true
		}
	}
	for _, r := range workflowBuiltinRoles {
		add(r)
	}
	var group *GroupConfig
	if appYAML, err := os.ReadFile(filepath.Join(dir, "app.yaml")); err == nil {
		if roles := parseRolesConfig(appYAML); roles != nil {
			for name := range roles.Roles {
				add(name)
			}
		}
		if group = parseGroupConfig(appYAML); group != nil && group.Bootstrap != nil {
			add(group.Bootstrap.FoundingRole)
		}
		if access, _ := parseAccessConfig(appYAML); access != nil {
			for _, ops := range access.rules {
				for _, mode := range ops {
					for _, prefix := range []string{"role:", "owner_or_role:"} {
						if rest, ok := strings.CutPrefix(mode, prefix); ok {
							add(rest)
						}
					}
				}
			}
		}
	}
	unknown := func() bool {
		for _, u := range uses {
			if !known[strings.ToLower(u.role)] {
				return true
			}
		}
		return false
	}
	// Flow role: gates name roles too. Parsing every flow is the expensive
	// part, so it runs only when the cheap sources left a name unexplained.
	if unknown() {
		for _, f := range LoadFlowsGHA(dir) {
			add(f.Role)
		}
	}

	dataNote := ""
	if group != nil && group.RoleField != "" {
		dataNote = fmt.Sprintf(" If it is an in-tenant role that exists only as data in %s.%s, ignore this warning.", group.Table, group.RoleField)
	}
	var findings []CheckFinding
	for _, u := range uses {
		if known[strings.ToLower(u.role)] {
			continue
		}
		findings = append(findings, CheckFinding{
			Severity: "warning",
			Source:   "workflows",
			File:     "workflows.yaml",
			Message: fmt.Sprintf("workflows.yaml %s: role %q is not a role the app names anywhere else (app.yaml roles:, groups.bootstrap.founding_role, an access: role: or owner_or_role: mode, a flow's role:) and not a built-in role (%s). If it is a typo, nobody holds it and only an admin can make the transition. List several roles in one comma-separated string or a YAML list.%s See api({at:'workflows'}) → transition_roles.",
				u.where, u.role, strings.Join(workflowBuiltinRoles, ", "), dataNote),
		})
	}
	return findings
}
