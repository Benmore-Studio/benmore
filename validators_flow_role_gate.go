//go:build !cli

package main

// What a flow's `on.request.role` says, checked against what the gate reads.
//
// The gate (flowRoleAllowed, flows_role_gate.go) takes ONE role name and
// matches it exactly. Access modes take `role:a,b` and workflow transitions
// take `role: [a, b]`, so builders write both forms on a flow too:
//
//   - `role: "warehouse,manager"` is one name nobody holds: the flow answers
//     403 to everyone but a global admin, and the write, `benmore check` and
//     the load all accepted it without a word;
//   - `role: [warehouse, manager]` does not decode into the trigger and was
//     refused with the YAML decoder's own error;
//   - with roles: declared, a misspelled name is held by nobody either;
//   - `role: admin` admits only a global admin, which surprises an app whose
//     tenant members hold a role named admin.
//
// The list is refused in words (it never loaded). The other three are
// warnings from the post-write check and `benmore check`
// (flowRoleGateWarnings) and a WARNING line when the app loads the file
// (loadFlowsCheckedFromSourcesSkipping): deployed flow files carry them, and
// making the comma form mean any-of would open flows that are admin-only
// today.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// flowRoleListViolation refuses an `on.request.role` written as a YAML list
// or map, before the typed decode would answer with "cannot unmarshal !!seq
// into string". probe is the file decoded as plain YAML.
func flowRoleListViolation(probe any) string {
	root, _ := probe.(map[string]any)
	on, _ := root["on"].(map[string]any)
	request, _ := on["request"].(map[string]any)
	var names []string
	switch role := request["role"].(type) {
	case []any:
		for _, item := range role {
			if name, ok := item.(string); ok {
				names = append(names, name)
			}
		}
	case map[string]any:
	default:
		return ""
	}
	return "flows.yaml: on.request.role is a YAML list or map, and a flow's role gate takes exactly one role name, matched exactly (`role: warehouse`). It has no any-of form. " + flowSeveralRolesFix(names)
}

// flowRoleNameRe is a role name that can be shown inside a quoted condition.
var flowRoleNameRe = regexp.MustCompile(`^[A-Za-z0-9_.:-]+$`)

// flowSeveralRolesFix says what to write when several roles should pass,
// with the builder's own role names in the example when they can be quoted.
func flowSeveralRolesFix(names []string) string {
	example := []string{"warehouse", "manager"}
	var own []string
	for _, name := range names {
		name = strings.TrimSpace(name)
		if flowRoleNameRe.MatchString(name) && !strings.EqualFold(name, "admin") && !slices.Contains(own, name) {
			own = append(own, name)
		}
	}
	if len(own) > 0 {
		example = own
	}
	conds := make([]string, 0, len(example)+1)
	for _, name := range append(example, "admin") {
		conds = append(conds, "user.role != '"+name+"'")
	}
	single := example[0]
	return fmt.Sprintf("A global admin passes every role gate, so for one role plus admins write that role alone (`role: %s`). For several roles, write `auth: required` and refuse in the first step: `if: ${{ %s }}` with `run: respond` and `with: { status: 403, json: { error: forbidden } }` checks the account's own role; a tenant role or a role grant is checked with a SQL step, and a `mode: async` flow is gated by a synchronous flow that queues it (api(at:\"flows.role_gate\")).",
		single, strings.Join(conds, " && "))
}

// flowRoleGateContext is what the app's other files say about roles, as far
// as a flow's gate depends on it.
type flowRoleGateContext struct {
	rolesDeclared bool
	// named holds every role name another part of the app names, spelled as
	// written: the gate matches exactly.
	named map[string]bool
	group *GroupConfig
	// tenantAdmin says why a tenant member can hold a role named admin, ""
	// when nothing in the source says so.
	tenantAdmin string
}

// newFlowRoleGateContext reads the role names of app.yaml, the membership
// role column's default in schema.prisma and the transition roles of
// workflows.yaml. Each may be nil.
func newFlowRoleGateContext(appYAML, schema, workflows []byte) *flowRoleGateContext {
	c := &flowRoleGateContext{named: map[string]bool{"user": true}}
	add := func(list string) {
		for _, name := range splitCommaList(list) {
			c.named[name] = true
		}
	}
	var because []string
	adminDeclared := false
	if roles := parseRolesConfig(appYAML); roles != nil {
		c.rolesDeclared = true
		for name := range roles.Roles {
			add(name)
			adminDeclared = adminDeclared || strings.EqualFold(strings.TrimSpace(name), "admin")
		}
	}
	c.group = parseGroupConfig(appYAML)
	tenantRoles := c.group != nil && c.group.RoleField != ""
	if c.group != nil && c.group.Bootstrap != nil {
		add(c.group.Bootstrap.FoundingRole)
		if tenantRoles && strings.EqualFold(strings.TrimSpace(c.group.Bootstrap.FoundingRole), "admin") {
			because = append(because, "groups.bootstrap.founding_role gives it to every account that founds one")
		}
	}
	if tenantRoles && len(schema) > 0 {
		models, _ := ParsePrismaSchema(string(schema))
		for _, m := range models {
			if sqliteIdentifierFold(m.Table) != sqliteIdentifierFold(c.group.Table) {
				continue
			}
			for _, f := range m.Fields {
				if sqliteIdentifierFold(f.Column) != sqliteIdentifierFold(c.group.RoleField) || f.Default == "" {
					continue
				}
				def := strings.Trim(f.Default, `'"`)
				add(def)
				if strings.EqualFold(strings.TrimSpace(def), "admin") {
					because = append(because, fmt.Sprintf("it is the default of %s.%s", m.Table, f.Column))
				}
			}
		}
	}
	if tenantRoles && adminDeclared {
		because = append(because, fmt.Sprintf("app.yaml roles: declares admin, and a member whose %s is admin holds it in their tenant", c.group.RoleField))
	}
	c.tenantAdmin = strings.Join(because, "; ")
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
	if len(workflows) > 0 {
		if cfg, err := parseWorkflowsYAML(workflows); err == nil && cfg != nil {
			for _, wf := range cfg.Workflows {
				for _, moves := range wf.Transitions {
					for _, move := range moves {
						add(move.Role)
					}
				}
			}
		}
	}
	return c
}

// flowRoleGateContextFor reads the context from the app's files on disk.
func flowRoleGateContextFor(dir string) *flowRoleGateContext {
	read := func(name string) []byte {
		data, _ := os.ReadFile(filepath.Join(dir, name))
		return data
	}
	return newFlowRoleGateContext(read("app.yaml"), read("schema.prisma"), read("workflows.yaml"))
}

// flowRoleGateProblem is what is wrong with a flow's `role:` as its gate
// reads it, "" when it names one role the app knows. c may be nil: only the
// shape is judged then.
func flowRoleGateProblem(role string, c *flowRoleGateContext) string {
	if problem := flowRoleShapeProblem(role); problem != "" {
		return problem
	}
	return flowRoleNameProblem(role, c)
}

// flowRoleShapeProblem names a `role:` that is not one name. It depends on
// the flow file alone.
func flowRoleShapeProblem(role string) string {
	role = strings.TrimSpace(role)
	names := strings.FieldsFunc(role, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r' })
	if role == "" || (len(names) == 1 && names[0] == role) {
		return ""
	}
	return fmt.Sprintf("on.request.role %q is read as ONE role name: a flow's role gate takes exactly one role, matched exactly, and has no any-of form. Nobody holds a role of that name, so the flow answers 403 to everyone but a global admin. %s",
		role, flowSeveralRolesFix(names))
}

// flowRoleNameProblem names a single-name `role:` that the rest of the app
// makes surprising: `admin` where tenant members hold a role of that name,
// or a name nothing declares when roles: is declared. It depends on app.yaml,
// schema.prisma and workflows.yaml.
func flowRoleNameProblem(role string, c *flowRoleGateContext) string {
	role = strings.TrimSpace(role)
	if role == "" || c == nil || flowRoleShapeProblem(role) != "" {
		return ""
	}
	if strings.EqualFold(role, "admin") {
		if c.tenantAdmin == "" {
			return ""
		}
		g := c.group
		who := ":user_id"
		if emailKeyedColumn(g.UserField) {
			who = ":user_email"
		}
		return fmt.Sprintf("on.request.role is `admin`, which only a global admin passes (the account's own role is admin, or it holds an admin grant for no tenant). A tenant member of this app can hold a role named admin (%s), and a tenant admin does NOT pass this gate. If the tenant's own admins should call this flow, write `auth: required` and check the caller's membership row in the first step: `SELECT id FROM %s WHERE %s = :org AND %s = %s AND %s = 'admin'` with `params: { org: \"${{ user.group_id || 0 }}\" }`, then `if: ${{ !steps.<id>.outputs.rows }}` with `run: respond` and `status: 403`; or give the tenant role a name of its own (org_admin) and gate the flow on that name. If only the app's global admin should call it (a worker flow the queue runs), leave it as it is. See api(at:\"flows.role_gate\").",
			c.tenantAdmin, g.Table, g.Key, g.UserField, who, g.RoleField)
	}
	if !c.rolesDeclared || c.named[role] {
		return ""
	}
	note := ""
	if c.group != nil && c.group.RoleField != "" {
		note = fmt.Sprintf(" If it is an in-tenant role that exists only as data in %s.%s, ignore this warning.", c.group.Table, c.group.RoleField)
	}
	return fmt.Sprintf("on.request.role %q is not a role this app names: app.yaml declares roles: and it is not one of them, and no groups.bootstrap.founding_role, access role: or owner_or_role: mode or workflow transition names it (admin and user are built in). The gate is matched exactly, letter case included, so if it is a typo nobody holds it and the flow answers 403 to everyone but a global admin.%s See api(at:\"flows.role_gate\").",
		role, note)
}

// flowRoleGateWarnings reports flowRoleGateProblem for the flow file just
// written or, on a full check, for every flow file. A write of a file the
// name check depends on (app.yaml, schema.prisma, workflows.yaml) re-reports
// that check for every flow file, and not the shape of gates it did not touch.
func flowRoleGateWarnings(dir, writtenPath string) []CheckFinding {
	files, problemOf := flowFilesFor(dir, writtenPath), flowRoleGateProblem
	switch filepath.ToSlash(filepath.Clean(writtenPath)) {
	case "app.yaml", "schema.prisma", "workflows.yaml":
		files, problemOf = flowFilesFor(dir, ""), flowRoleNameProblem
	}
	var c *flowRoleGateContext
	var findings []CheckFinding
	for _, rel := range files {
		data, err := readFileInRoot(dir, rel)
		if err != nil {
			continue
		}
		var file FlowFileGHA
		if decodeConfigYAML(data, &file) != nil || file.Jobs == nil || file.On.Request == nil || strings.TrimSpace(file.On.Request.Role) == "" {
			continue
		}
		if c == nil {
			c = flowRoleGateContextFor(dir)
		}
		if problem := problemOf(file.On.Request.Role, c); problem != "" {
			name := filepath.ToSlash(rel)
			findings = append(findings, CheckFinding{Severity: "warning", Source: "flows", File: name, Message: name + ": " + problem})
		}
	}
	return findings
}
