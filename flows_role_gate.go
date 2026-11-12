//go:build !cli

package main

import (
	"fmt"
	"strings"

	"go.yaml.in/yaml/v3"
)

// A flow's on.request.role names one role or several, any of which admits
// the caller: `role: finance`, `role: "warehouse, manager"` or
// `role: [warehouse, manager]`. The loaded form (Flow.Role) is the names
// joined with ",".

// flowRoleYAML is the raw `role:` value of on.request. A list decodes to its
// names joined with ","; a scalar is kept as written, so a deployed file with
// an empty name in it still loads (and admits only a global admin).
type flowRoleYAML string

// UnmarshalYAML accepts a scalar or a sequence of role names. A sequence
// never decoded before lists were read, so a malformed one stays a load error.
func (r *flowRoleYAML) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.AliasNode && node.Alias != nil {
		node = node.Alias
	}
	switch node.Kind {
	case yaml.ScalarNode:
		if node.Tag == "!!null" {
			*r = ""
			return nil
		}
		*r = flowRoleYAML(node.Value)
		return nil
	case yaml.SequenceNode:
		names := make([]string, 0, len(node.Content))
		for _, item := range node.Content {
			if item.Kind == yaml.AliasNode && item.Alias != nil {
				item = item.Alias
			}
			if item.Kind != yaml.ScalarNode || item.Tag == "!!null" || strings.TrimSpace(item.Value) == "" {
				return fmt.Errorf("line %d: an on.request.role list holds role names only, none of them empty", item.Line)
			}
			names = append(names, strings.TrimSpace(item.Value))
		}
		if len(names) == 0 {
			return fmt.Errorf("line %d: on.request.role [] names no role; drop the key for a flow without a role gate", node.Line)
		}
		*r = flowRoleYAML(strings.Join(names, ","))
		return nil
	}
	return fmt.Errorf("line %d: on.request.role is a role name, a comma-separated list or a YAML list of role names", node.Line)
}

// flowRoleNames is the any-of list a flow's `role:` names: split at commas,
// spaces around each name dropped. ok is false when the text names no role or
// holds an empty name ("a,,b", "a,", ","): the write gate refuses that, and a
// deployed file that carries it admits only a global admin, as the whole text
// did when it was read as one name.
func flowRoleNames(role string) (names []string, ok bool) {
	parts := strings.Split(role, ",")
	for _, part := range parts {
		name := strings.TrimSpace(part)
		if name == "" {
			return nil, false
		}
		names = append(names, name)
	}
	return names, true
}

// canonicalFlowRole is the loaded form of a `role:`: its names joined with
// ",". Text flowRoleNames does not accept is kept as written, so it still
// gates the flow instead of becoming "no role".
func canonicalFlowRole(raw string) string {
	names, ok := flowRoleNames(raw)
	if !ok {
		return raw
	}
	return strings.Join(names, ",")
}

// flowRoleAllowed reports whether session passes a flow's on.request.role
// gate: it holds one of the roles the gate names. Every place that decides it
// calls this: the request (executeFlow), the queued run of an async flow
// (flowJobActorCheck), scheduling (schedulableFlow), the flows.json listing
// (flowListedFor), the connector read tool that calls the flow
// (appMCPToolAllowed) and the artifact such a tool stored
// (appMCPArtifactAuthorizedFrom).
//
// Each name means what it means alone. `admin` (any letter case) is the app's
// global admin: IsAdmin, the _benmore_users.role column or a group_id IS NULL
// admin grant. A session's role list also carries the tenant membership role
// (groups.role_field) and group-scoped grants, and with
// groups.bootstrap.founding_role "admin" every account that signs up and
// founds a tenant holds a role of that name. A flow has no tenant column to
// bound such a role (a table's `role:admin` rule does, through the tenant
// clause), and an admin-gated flow is typically a worker whose payload is
// trusted to come from the app's own producer, so matching by name let any
// founder run it with a payload of their choosing. That holds for `admin` in
// a list too: `role: [admin, finance]` admits a global admin and a finance
// member, never a tenant admin.
//
// Any other role name is matched by HasAnyRole, tenant roles included, so a
// `role: finance` flow keeps admitting a tenant's finance member. A flow the
// tenant's own admins should call checks the membership row in a step.
func flowRoleAllowed(session *Session, role string) bool {
	if session == nil {
		return false
	}
	if session.IsAdmin() {
		return true
	}
	names, ok := flowRoleNames(role)
	if !ok {
		return false
	}
	for _, name := range names {
		if !strings.EqualFold(name, "admin") && HasAnyRole(session, []string{name}) {
			return true
		}
	}
	return false
}
