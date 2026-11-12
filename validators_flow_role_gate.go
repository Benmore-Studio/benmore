//go:build !cli

package main

// What a flow's `on.request.role` says, checked against what the gate reads.
//
// The gate (flowRoleAllowed, flows_role_gate.go) takes one role name or an
// any-of list of them, as a comma-separated string or a YAML list, like an
// access `role:a,b` mode and a workflow transition's `role:`.
//
//   - A value that names no role or holds an empty name (`role: []`,
//     `role: "warehouse,"`) is refused when the file is written
//     (flowRoleFormViolation). A deployed file that carries one keeps loading
//     and admits only a global admin, with a warning.
//   - `role: warehouse manager` is ONE name with a space in it: names are
//     separated by commas. Nobody holds it; a warning.
//   - With roles: declared, a misspelled name is held by nobody; a warning.
//   - `admin`, alone or in a list, admits only a global admin, which
//     surprises an app whose tenant members hold a role named admin; a
//     warning.
//
// The warnings come from the post-write check and `benmore check`
// (flowRoleGateWarnings) and as a WARNING line when the app loads the file
// (loadFlowsCheckedFromSourcesSkipping).

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// flowRoleFormViolation refuses an `on.request.role` that names no role or
// holds an empty name, and one that is not a name or a list of names, before
// the typed decode would answer in the YAML decoder's words. probe is the
// file decoded as plain YAML.
func flowRoleFormViolation(probe any) string {
	root, _ := probe.(map[string]any)
	on, _ := root["on"].(map[string]any)
	request, _ := on["request"].(map[string]any)
	problem := ""
	switch role := request["role"].(type) {
	case string:
		if _, ok := flowRoleNames(role); role != "" && !ok {
			problem = fmt.Sprintf("%q holds an empty role name", role)
		}
	case []any:
		if len(role) == 0 {
			problem = "is an empty list, which names no role"
		}
		for _, item := range role {
			name, isText := item.(string)
			if _, ok := flowRoleNames(name); !isText || !ok {
				problem = "is a list that holds something other than a role name, or an empty one"
			}
		}
	case map[string]any:
		problem = "is a YAML map"
	}
	if problem == "" {
		return ""
	}
	return "flows.yaml: on.request.role " + problem + ". Write one role name (`role: warehouse`), a comma-separated list (`role: \"warehouse, manager\"`) or a YAML list (`role: [warehouse, manager]`): a caller who holds any of the roles passes, and so does a global admin. Drop the key for a flow without a role gate."
}

// flowRoleNameRe is a role name that can be shown inside a quoted SQL value.
var flowRoleNameRe = regexp.MustCompile(`^[A-Za-z0-9_.:-]+$`)

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
// reads it, "" when every name in it is a role the app knows. c may be nil:
// only the shape is judged then.
func flowRoleGateProblem(role string, c *flowRoleGateContext) string {
	if problem := flowRoleShapeProblem(role); problem != "" {
		return problem
	}
	return flowRoleNameProblem(role, c)
}

// flowRoleShapeProblem names a `role:` the gate cannot read as role names: an
// empty name (refused at write time, so this is a deployed file) or a name
// with a space in it. It depends on the flow file alone.
func flowRoleShapeProblem(role string) string {
	if strings.TrimSpace(role) == "" {
		return ""
	}
	names, ok := flowRoleNames(role)
	if !ok {
		return fmt.Sprintf("on.request.role %q holds an empty role name, so the gate admits only a global admin. Write the roles that may call the flow separated by commas (`role: \"warehouse, manager\"`) or as a YAML list (`role: [warehouse, manager]`): a caller who holds any of them passes. See api(at:\"flows.role_gate\").", role)
	}
	for _, name := range names {
		if words := strings.Fields(name); len(words) > 1 {
			return fmt.Sprintf("on.request.role names %q, ONE role name with a space in it: role names are separated by commas, not spaces. Nobody holds a role of that name, so it admits nobody but a global admin. For any of several roles write `role: \"%s\"`. See api(at:\"flows.role_gate\").", name, strings.Join(words, ", "))
		}
	}
	return ""
}

// flowRoleNameProblem names what the rest of the app makes surprising about
// the role names of a well-formed `role:`: `admin` where tenant members hold
// a role of that name, or a name nothing declares when roles: is declared.
// It depends on app.yaml, schema.prisma and workflows.yaml.
func flowRoleNameProblem(role string, c *flowRoleGateContext) string {
	names, ok := flowRoleNames(role)
	if c == nil || !ok || flowRoleShapeProblem(role) != "" {
		return ""
	}
	var problems, unknown []string
	admin := false
	for _, name := range names {
		switch {
		case strings.EqualFold(name, "admin"):
			admin = true
		case c.rolesDeclared && !c.named[name]:
			unknown = append(unknown, fmt.Sprintf("%q", name))
		}
	}
	if admin && c.tenantAdmin != "" {
		g := c.group
		who := ":user_id"
		if emailKeyedColumn(g.UserField) {
			who = ":user_email"
		}
		is, pass, match := "is", "this gate", "= 'admin'"
		if len(names) > 1 {
			tenantRoles := []string{"'admin'"}
			for _, name := range names {
				if !strings.EqualFold(name, "admin") && flowRoleNameRe.MatchString(name) {
					tenantRoles = append(tenantRoles, "'"+name+"'")
				}
			}
			is, pass, match = "names", "the gate by that role", "IN ("+strings.Join(tenantRoles, ", ")+")"
		}
		problems = append(problems, fmt.Sprintf("on.request.role %s `admin`, which only a global admin passes (the account's own role is admin, or it holds an admin grant for no tenant). A tenant member of this app can hold a role named admin (%s), and a tenant admin does NOT pass %s. If the tenant's own admins should call this flow, write `auth: required` and check the caller's membership row in the first step: `SELECT id FROM %s WHERE %s = :org AND %s = %s AND %s %s` with `params: { org: \"${{ user.group_id || 0 }}\" }`, then `if: ${{ !steps.<id>.outputs.rows }}` with `run: respond` and `status: 403`; or give the tenant role a name of its own (org_admin) and gate the flow on that name. If only the app's global admin should call it (a worker flow the queue runs), leave it as it is. See api(at:\"flows.role_gate\").",
			is, c.tenantAdmin, pass, g.Table, g.Key, g.UserField, who, g.RoleField, match))
	}
	if len(unknown) > 0 {
		note := ""
		if c.group != nil && c.group.RoleField != "" {
			note = fmt.Sprintf(" If it is an in-tenant role that exists only as data in %s.%s, ignore this warning.", c.group.Table, c.group.RoleField)
		}
		if len(names) == 1 {
			problems = append(problems, fmt.Sprintf("on.request.role %s is not a role this app names: app.yaml declares roles: and it is not one of them, and no groups.bootstrap.founding_role, access role: or owner_or_role: mode or workflow transition names it (admin and user are built in). The gate is matched exactly, letter case included, so if it is a typo nobody holds it and the flow answers 403 to everyone but a global admin.%s See api(at:\"flows.role_gate\").",
				unknown[0], note))
		} else {
			problems = append(problems, fmt.Sprintf("on.request.role lists %s, and the app names no such role anywhere else: not under app.yaml roles:, not as groups.bootstrap.founding_role, in an access role: or owner_or_role: mode or on a workflow transition (admin and user are built in). Each name is matched exactly, letter case included, so a misspelled name is held by nobody and admits nobody.%s See api(at:\"flows.role_gate\").",
				strings.Join(unknown, ", "), note))
		}
	}
	return strings.Join(problems, " ")
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
		if decodeConfigYAML(data, &file) != nil || file.Jobs == nil || file.On.Request == nil || strings.TrimSpace(string(file.On.Request.Role)) == "" {
			continue
		}
		if c == nil {
			c = flowRoleGateContextFor(dir)
		}
		if problem := problemOf(string(file.On.Request.Role), c); problem != "" {
			name := filepath.ToSlash(rel)
			findings = append(findings, CheckFinding{Severity: "warning", Source: "flows", File: name, Message: name + ": " + problem})
		}
	}
	return findings
}
