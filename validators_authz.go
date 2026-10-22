//go:build !cli

package main

// Authorization-shape validators for app.yaml access:, groups: and
// ws_rooms:. One write-time ERROR (validateAuthzAppYAML, registered in
// ValidateOnWriteIn) for a declaration that cannot work as written, and
// cross-file WARNINGS (authzWarnings, registered in runCheck) for legal
// declarations whose usual effect is wider access than the author meant.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// validateAuthzAppYAML refuses `perm:` access modes in an app.yaml that has
// no roles: block. Permissions come only from roles' scopes; without roles
// the runtime fails every perm: gate closed (AccessConfig.Allowed), so the
// table would be unreachable - and before that fix every signed-in user
// passed it.
func validateAuthzAppYAML(content string) string {
	access, err := parseAccessConfig([]byte(content))
	if err != nil || access == nil || access.rolesDeclared {
		return ""
	}
	var uses []string
	for table, ops := range access.rules {
		for op, mode := range ops {
			if strings.HasPrefix(mode, "perm:") {
				uses = append(uses, fmt.Sprintf("access.%s.%s: %s", table, op, mode))
			}
		}
	}
	if len(uses) == 0 {
		return ""
	}
	sort.Strings(uses)
	return fmt.Sprintf("%s: perm: access modes need a roles: block - permissions are granted only by roles' scopes, so with no roles every perm: gate refuses everyone. Declare roles: with scopes (e.g. roles: {editor: {scopes: \"posts:publish\"}}), or use role:/admin/self instead.",
		strings.Join(uses, "; "))
}

// validateMemberOfShape refuses a `member-of:` rule on a table that is
// neither a child of the rule (it has the rule's join column) nor the parent
// the membership join column points at. The runtime fails such a table
// closed (memberOfRule.joinTarget): read as the parent, its rows would match
// memberships by unrelated ids and every create would join the creator into
// the membership numbered like the new row. The decision is the runtime's
// own predicate, run over the schema.prisma models; it applies only when
// both the protected and the membership table are models of this schema.
func validateMemberOfShape(appYAML, schema []byte) string {
	if len(appYAML) == 0 || len(schema) == 0 {
		return ""
	}
	access, err := parseAccessConfig(appYAML)
	if err != nil || access == nil {
		return ""
	}
	models, err := ParsePrismaSchema(string(schema))
	if err != nil || len(models) == 0 {
		return ""
	}
	view := &App{Group: parseGroupConfig(appYAML), JoinMap: JoinMap{}}
	modelTable := map[string]string{} // folded name -> declared table name
	for _, m := range models {
		t := Table{Name: m.Table}
		for _, f := range m.Fields {
			t.Columns = append(t.Columns, Column{Name: f.Column})
			if f.FKTable != "" {
				if view.JoinMap[m.Table] == nil {
					view.JoinMap[m.Table] = map[string]ForeignKey{}
				}
				view.JoinMap[m.Table][f.Column] = ForeignKey{Table: f.FKTable, Column: f.FKColumn}
			}
		}
		view.Tables = append(view.Tables, t)
		modelTable[sqliteIdentifierFold(m.Table)] = m.Table
	}
	var problems []string
	for table, ops := range access.rules {
		declared, ok := modelTable[sqliteIdentifierFold(table)]
		if !ok {
			continue
		}
		seen := map[string]bool{}
		for _, mode := range ops {
			rule := parseMemberOf(mode)
			if rule == nil || seen[mode] {
				continue
			}
			seen[mode] = true
			if _, known := modelTable[sqliteIdentifierFold(rule.Table)]; !known {
				continue
			}
			if _, ok := rule.joinTarget(view, declared); !ok {
				problems = append(problems, fmt.Sprintf("access.%s: member-of:%s(%s, %s) - %s has no %s column, and %s.%s does not point at %s (no relation to it, and the name is not %s's). As written the runtime refuses every request on %s. If %s rows belong to a parent, add the %s column to %s; if %s IS the parent, declare the relation in schema.prisma or write member-of:%s(%s=id, %s).",
					table, rule.Table, rule.JoinCol, rule.UserCol, table, rule.JoinCol, rule.Table, rule.JoinCol, table, table, table, table, rule.JoinCol, table, table, rule.Table, rule.JoinCol, rule.UserCol))
			}
		}
	}
	if len(problems) == 0 {
		return ""
	}
	sort.Strings(problems)
	return strings.Join(problems, "\n")
}

// authzWarnings returns the cross-file authorization warnings for the app
// in dir. Each is advisory: the declaration is legal and may be intended.
func authzWarnings(dir string) []CheckFinding {
	appYAML, err := os.ReadFile(filepath.Join(dir, "app.yaml"))
	if err != nil {
		return nil
	}
	access, _ := parseAccessConfig(appYAML)
	group := parseGroupConfig(appYAML)
	var models []PrismaModel
	if schema, err := os.ReadFile(filepath.Join(dir, "schema.prisma")); err == nil {
		models, _ = ParsePrismaSchema(string(schema))
	}

	var findings []CheckFinding
	warn := func(msg string) {
		findings = append(findings, CheckFinding{Severity: "warning", Source: "security", File: "app.yaml", Message: msg})
	}
	for _, msg := range tenantAdminRoleWarnings(access, group) {
		warn(msg)
	}
	for _, msg := range memberOfSelfJoinWarnings(access, group, models) {
		warn(msg)
	}
	for _, msg := range groupKeyedBroadReadWarnings(access, group, models) {
		warn(msg)
	}
	for _, msg := range globalUniqueOnTenantTableWarnings(group, models) {
		findings = append(findings, CheckFinding{Severity: "warning", Source: "security", File: "schema.prisma", Message: msg})
	}
	if msg := rolesWithoutTableScopesWarning(parseRolesConfig(appYAML), models); msg != "" {
		warn(msg)
	}
	if msg := dynamicWSRoomWarning(dir, parseWSRooms(appYAML)); msg != "" {
		findings = append(findings, CheckFinding{Severity: "warning", Source: "security", File: "static/", Message: msg})
	}
	return findings
}

// tenantAdminRoleWarnings flags a tenant (membership) role named "admin".
// Since the HasAnyRole fix it no longer makes a member a platform admin,
// but it still satisfies every literal `role:admin` / `owner_or_role:admin`
// gate - and groups.bootstrap hands founding_role to anyone who signs up
// and creates an organization.
func tenantAdminRoleWarnings(access *AccessConfig, group *GroupConfig) []string {
	if group == nil || group.RoleField == "" {
		return nil
	}
	var out []string
	if group.Bootstrap != nil && strings.EqualFold(strings.TrimSpace(group.Bootstrap.FoundingRole), "admin") {
		out = append(out, `groups.bootstrap.founding_role is "admin": every account that creates an organization holds the tenant role "admin", which satisfies any role:admin access gate. Platform admin is users.role / a global grant; name the tenant role something distinct (e.g. org_admin).`)
	}
	if access == nil {
		return out
	}
	var gates []string
	for table, ops := range access.rules {
		for op, mode := range ops {
			var roles []string
			switch {
			case strings.HasPrefix(mode, "role:"):
				roles = splitCommaList(strings.TrimPrefix(mode, "role:"))
			case strings.HasPrefix(mode, "owner_or_role:"):
				roles = splitCommaList(strings.TrimPrefix(mode, "owner_or_role:"))
			}
			for _, r := range roles {
				if r == "admin" {
					gates = append(gates, fmt.Sprintf("access.%s.%s", table, op))
				}
			}
		}
	}
	if len(gates) > 0 {
		sort.Strings(gates)
		out = append(out, fmt.Sprintf("%s use role \"admin\" while groups.role_field (%s) loads tenant roles: a member whose %s is \"admin\" passes these gates. Use the `admin` mode for platform admins only, or a distinct tenant role name.",
			strings.Join(gates, ", "), group.RoleField, group.RoleField))
	}
	return out
}

// memberOfSelfJoinWarnings flags a member-of membership table whose create
// mode lets an ordinary user insert rows: they can add themselves to any
// parent (POST /api/<membership> {room_id: X}) and read everything the
// member-of rule protects.
func memberOfSelfJoinWarnings(access *AccessConfig, group *GroupConfig, models []PrismaModel) []string {
	if access == nil {
		return nil
	}
	membership := map[string]bool{}
	for _, ops := range access.rules {
		for _, mode := range ops {
			if rule := parseMemberOf(mode); rule != nil {
				membership[rule.Table] = true
			}
		}
	}
	var out []string
	for _, mt := range sortedSetKeys(membership) {
		hasUID, hasGroup := modelShape(models, mt, group)
		mode := access.ModeFor(mt, OpWrite, hasUID, hasGroup)
		if mode == "self" || mode == "everyone" || mode == "anon" {
			out = append(out, fmt.Sprintf("%s is a member-of membership table but its create mode is %q: any user can insert a membership row for any parent and then read what member-of protects. Restrict access.%s.write (admin, a role, or off with a flow that checks the inviter).", mt, mode, mt))
		}
	}
	return out
}

// groupKeyedBroadReadWarnings flags everyone/anon read on a table carrying
// the tenant key: those modes skip row scoping, so every tenant reads every
// other tenant's rows.
func groupKeyedBroadReadWarnings(access *AccessConfig, group *GroupConfig, models []PrismaModel) []string {
	if access == nil || group == nil || group.Key == "" {
		return nil
	}
	var out []string
	for _, m := range models {
		hasUID, hasGroup := modelShape(models, m.Table, group)
		if !hasGroup {
			continue
		}
		if mode := access.ModeFor(m.Table, OpRead, hasUID, hasGroup); mode == "everyone" || mode == "anon" {
			out = append(out, fmt.Sprintf("%s carries the tenant key %s but access.%s.read is %q, which skips tenant scoping: every tenant reads every other tenant's rows. Use group (or owner_or_role:/member-of:) unless the table is deliberately shared.", m.Table, group.Key, m.Table, mode))
		}
	}
	return out
}

// globalUniqueOnTenantTableWarnings flags a unique constraint on a table that
// carries the tenant key but leaves the key out of the constraint. SQLite
// enforces it across every tenant, so a create or update colliding with
// ANOTHER tenant's row is refused: the refusal (identical whether the other
// row is in the caller's tenant or not, see publicConstraintMessage) still
// tells a tenant that the value exists somewhere, and tenants cannot reuse
// each other's values. Only the author can decide the constraint's scope, so
// this is a warning.
func globalUniqueOnTenantTableWarnings(group *GroupConfig, models []PrismaModel) []string {
	if group == nil || group.Key == "" {
		return nil
	}
	var out []string
	for _, m := range models {
		keyField := ""
		for _, f := range m.Fields {
			if strings.EqualFold(f.Column, group.Key) {
				keyField = f.Name
			}
		}
		if keyField == "" {
			continue
		}
		var global []string
		for _, f := range m.Fields {
			if f.IsUnique && !f.IsID && !strings.EqualFold(f.Column, group.Key) {
				global = append(global, "("+f.Column+")")
			}
		}
		for _, u := range m.Uniques {
			hasKey := false
			for _, c := range u.Columns {
				if strings.EqualFold(c, group.Key) {
					hasKey = true
				}
			}
			if !hasKey && len(u.Columns) > 0 {
				global = append(global, "("+strings.Join(u.Columns, ", ")+")")
			}
		}
		if len(global) == 0 {
			continue
		}
		out = append(out, fmt.Sprintf("%s carries the tenant key %s but its unique constraint%s %s %s global: a write that collides with another tenant's row is refused, which tells a tenant the value exists elsewhere and stops tenants reusing each other's values. Scope it to the tenant with @@unique([%s, ...]) unless the value really is unique across all tenants.",
			m.Table, group.Key, map[bool]string{true: "s", false: ""}[len(global) > 1], strings.Join(global, ", "), map[bool]string{true: "are", false: "is"}[len(global) > 1], keyField))
	}
	sort.Strings(out)
	return out
}

// dynamicRoomRe matches a bm.room(...) call whose name is built at run time
// (template literal with ${...}, or string concatenation).
var dynamicRoomRe = regexp.MustCompile("\\broom\\(\\s*(`[^`]*\\$\\{|['\"][^'\"]*['\"]\\s*\\+)")

// dynamicWSRoomWarning flags per-entity WebSocket rooms used with no
// ws_rooms: rule: undeclared rooms are open to any connection that knows
// (or guesses) the name, so `room(\`chat:${id}\`)` is readable by
// non-members.
func dynamicWSRoomWarning(dir string, rules []WSRoomRule) string {
	if len(rules) > 0 {
		return ""
	}
	var hits []string
	root := filepath.Join(dir, "static")
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if d.Name() == "node_modules" || strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".ts", ".tsx", ".js", ".jsx", ".html":
		default:
			return nil
		}
		if info, err := d.Info(); err != nil || info.Size() > 2<<20 {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		if dynamicRoomRe.Match(data) {
			rel, _ := filepath.Rel(dir, path)
			hits = append(hits, rel)
		}
		return nil
	})
	if len(hits) == 0 {
		return ""
	}
	sort.Strings(hits)
	return fmt.Sprintf("%s join WebSocket rooms by a computed name, but app.yaml declares no ws_rooms: rules - any signed-in connection can join an undeclared room and read its messages. Bind the pattern to a membership table, e.g. ws_rooms: {\"chat:*\": \"room_members(room_id, user_id)\"}.",
		strings.Join(hits, ", "))
}

// modelShape reports whether table (per schema.prisma) has user_id and the
// tenant key, the inputs ModeFor's implicit default needs.
func modelShape(models []PrismaModel, table string, group *GroupConfig) (hasUID, hasGroup bool) {
	for _, m := range models {
		if !strings.EqualFold(m.Table, table) {
			continue
		}
		for _, f := range m.Fields {
			c := strings.ToLower(f.Column)
			if c == "user_id" {
				hasUID = true
			}
			if group != nil && group.Key != "" && strings.EqualFold(c, group.Key) {
				hasGroup = true
			}
		}
	}
	return hasUID, hasGroup
}

func sortedSetKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// rolesWithoutTableScopesWarning flags a roles: block that would 403 every
// auto-CRUD call: with roles declared, a session holds only its roles'
// scopes, so when no role scope names a schema table (or `*`), or the default
// `user` role every account starts with is not declared, the CRUD gate refuses
// everyone who is not given a table scope by name.
// `table_scopes: access` makes access: the only table gate.
func rolesWithoutTableScopesWarning(roles *RolesConfig, models []PrismaModel) string {
	if roles == nil || roles.TablesFromAccess || len(models) == 0 {
		return ""
	}
	tables := map[string]bool{}
	for _, m := range models {
		tables[m.Table] = true
	}
	namesTable := false
	for name := range roles.Roles {
		for _, scope := range strings.Fields(roles.ResolveRoleScopes(name)) {
			resource, _ := parseScope(scope)
			if scope == "*" || resource == "*" || tables[resource] {
				namesTable = true
			}
		}
	}
	_, hasUser := roles.Roles["user"]
	switch {
	case !namesTable:
		return "app.yaml: roles: names no table, so every auto-CRUD call (cookie and bearer) gets 403 `scope denied: token does not have <table>:read permission` for every account. If your roles: are capability scopes (flows, MCP tools) and table access should follow access:, add `table_scopes: access` at the top level of app.yaml."
	case !hasUser:
		return "app.yaml: roles: does not declare `user`, the role every new account holds, so those accounts get no scopes and every auto-CRUD call 403s for them. Declare `user` with its table scopes, or add `table_scopes: access` at the top level of app.yaml to let access: alone decide table access."
	}
	return ""
}
