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
	"slices"
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
	if msg := membershipUniqueWarning(group, models, migrationUniqueIndexes(dir)); msg != "" {
		findings = append(findings, CheckFinding{Severity: "warning", Source: "security", File: "schema.prisma", Message: msg})
	}
	roles := parseRolesConfig(appYAML)
	if msg := rolesWithoutTableScopesWarning(roles, models); msg != "" {
		warn(msg)
	}
	for _, msg := range roleModeOwnerRowsWarnings(access, group, roles, models) {
		warn(msg)
	}
	wsRooms := parseWSRooms(appYAML)
	for _, msg := range wsRoomRuleWarnings(dir, wsRooms) {
		warn(msg)
	}
	if msg := dynamicWSRoomWarning(dir, wsRooms); msg != "" {
		findings = append(findings, CheckFinding{Severity: "warning", Source: "security", File: "static/", Message: msg})
	}
	findings = append(findings, unmaskOwnerAliasWarnings(dir)...)
	if msg := mfaSetupPageWarning(dir, appYAML); msg != "" {
		warn(msg)
	}
	return findings
}

// mfaSetupPageWarning flags an app that makes accounts enroll MFA before a
// session is issued (auth.require_mfa_for_roles, which `compliance: hipaa`
// defaults to "*") while no page answers its enrollment redirect
// (auth.mfa_setup_redirect, default /mfa-setup): every listed account,
// under "*" every account, is sent to a 404 and can never sign in. An
// absolute URL is not checked.
func mfaSetupPageWarning(dir string, appYAML []byte) string {
	var doc map[string]any
	if err := decodeConfigYAML(appYAML, &doc); err != nil {
		return ""
	}
	auth, _ := doc["auth"].(map[string]any)
	roles := strings.TrimSpace(anyToString(auth["require_mfa_for_roles"]))
	if auth["require_mfa_for_roles"] == nil {
		roles = ""
	}
	// The hipaa default ("*", mfaRequiredRoles) applies to an app with sign-in;
	// an app.yaml with an auth: block is the static sign of one.
	hipaaDefault := false
	if roles == "" && doc["compliance"] == complianceHIPAA && doc["auth"] != nil {
		roles, hipaaDefault = "*", true
	}
	if roles == "" {
		return ""
	}
	target := "/mfa-setup"
	if v := strings.TrimSpace(anyToString(auth["mfa_setup_redirect"])); auth["mfa_setup_redirect"] != nil && v != "" {
		target = v
	}
	if !strings.HasPrefix(target, "/") || strings.HasPrefix(target, "//") {
		return ""
	}
	page := strings.Trim(strings.SplitN(strings.SplitN(target, "?", 2)[0], "#", 2)[0], "/")
	if page == "" {
		return ""
	}
	candidates := []string{"static/" + page + ".html", "static/" + page + "/index.html", page + ".html"}
	if filepath.Ext(page) != "" {
		candidates = append(candidates, "static/"+page, page)
	}
	for _, c := range candidates {
		if st, err := os.Stat(filepath.Join(dir, filepath.FromSlash(c))); err == nil && st.Mode().IsRegular() {
			return ""
		}
	}
	// Under the hipaa default the builder never wrote the key: name the line
	// that is in their app.yaml.
	who, locked := fmt.Sprintf("auth.require_mfa_for_roles (%s) sends each listed account", roles), "Every such account"
	if hipaaDefault {
		who, locked = "compliance: hipaa makes every account enroll MFA (under it auth.require_mfa_for_roles defaults to \"*\") and sends each one", "Every account"
	}
	return fmt.Sprintf("app.yaml: %s to %s to enroll an authenticator before it gets a session, but no page serves %s (looked for %s). %s is locked out at sign-in. Add the page (the scaffold's static/mfa-setup.html) or point auth.mfa_setup_redirect at the page that enrolls.", who, target, target, strings.Join(candidates, ", "), locked)
}

// unmaskOwnerAliasWarnings flags `owner` or `self` in an encrypted field's
// unmask roles while the app also has a role of that name. In unmask roles
// both words always mean the row's owner (encryptedFieldAccessFor: the row's
// user_id is the viewer), never a role, so the role's holders - typically a
// tenant's founding "owner" - read the field masked unless they own the row.
// The finding is filed under the file that declares the unmask roles.
func unmaskOwnerAliasWarnings(dir string) []CheckFinding {
	appYAML, _ := os.ReadFile(filepath.Join(dir, "app.yaml"))
	if len(appYAML) == 0 {
		return nil
	}
	schema, _ := os.ReadFile(filepath.Join(dir, "schema.prisma"))
	declared := aliasRoleDeclarations(appYAML, schema)
	if len(declared) == 0 {
		return nil
	}
	encYAML, _ := os.ReadFile(filepath.Join(dir, "encrypted.yaml"))
	fromEncFile := parseEncryptedFieldsConfig(encYAML, nil)
	merged := parseEncryptedFieldsConfig(encYAML, appYAML)
	if merged == nil {
		return nil
	}
	// file -> alias -> affected declarations
	hits := map[string]map[string][]string{}
	tables := make([]string, 0, len(merged.Fields))
	for table := range merged.Fields {
		tables = append(tables, table)
	}
	sort.Strings(tables)
	for _, table := range tables {
		inEncFile := fromEncFile != nil && fromEncFile.Fields[table] != nil
		for _, def := range merged.Fields[table] {
			for _, role := range def.Roles {
				role = strings.TrimSpace(role)
				if len(declared[role]) == 0 {
					continue
				}
				file, where := "encrypted.yaml", fmt.Sprintf("tables.%s.unmask_roles", table)
				if !inEncFile {
					file, where = "app.yaml", fmt.Sprintf("encrypted.%s.%s roles", table, def.Column)
				}
				if hits[file] == nil {
					hits[file] = map[string][]string{}
				}
				if !slices.Contains(hits[file][role], where) {
					hits[file][role] = append(hits[file][role], where)
				}
			}
		}
	}
	var findings []CheckFinding
	for _, file := range []string{"encrypted.yaml", "app.yaml"} {
		var parts []string
		for _, alias := range []string{"owner", "self"} {
			where := hits[file][alias]
			if len(where) == 0 {
				continue
			}
			verb := "list"
			if len(where) == 1 {
				verb = "lists"
			}
			parts = append(parts, fmt.Sprintf("%s %s `%s`, which in unmask roles always means the row's owner (`self` and `owner` are aliases: the account whose user_id is on the row), never a role. This app also has a role named %q (%s), and holders of that role read these fields as \"****\" unless they own the row. To let that role unmask, give it a distinct name (e.g. org_%s) everywhere it is assigned and gated, and list the new name in the unmask roles; keep `self` for the row owner.",
				strings.Join(where, ", "), verb, alias, alias, strings.Join(declared[alias], ", "), alias))
		}
		if len(parts) > 0 {
			findings = append(findings, CheckFinding{Severity: "warning", Source: "security", File: file, Message: file + ": " + strings.Join(parts, " ")})
		}
	}
	return findings
}

// aliasRoleDeclarations returns where app.yaml (and the membership table's
// role default in schema.prisma) declares a role named "owner" or "self":
// global roles:, groups.bootstrap.founding_role, the default of the
// groups.role_field column, and role:/owner_or_role: access gates.
func aliasRoleDeclarations(appYAML, schema []byte) map[string][]string {
	out := map[string][]string{}
	add := func(name, where string) {
		name = strings.TrimSpace(name)
		if name != "owner" && name != "self" {
			return
		}
		if !slices.Contains(out[name], where) {
			out[name] = append(out[name], where)
		}
	}
	if roles := parseRolesConfig(appYAML); roles != nil {
		for name := range roles.Roles {
			add(name, "app.yaml roles:")
		}
	}
	group := parseGroupConfig(appYAML)
	if group != nil && group.Bootstrap != nil {
		add(group.Bootstrap.FoundingRole, "groups.bootstrap.founding_role")
	}
	if group != nil && group.Table != "" && group.RoleField != "" && len(schema) > 0 {
		models, _ := ParsePrismaSchema(string(schema))
		for _, m := range models {
			if sqliteIdentifierFold(m.Table) != sqliteIdentifierFold(group.Table) {
				continue
			}
			for _, f := range m.Fields {
				if sqliteIdentifierFold(f.Column) == sqliteIdentifierFold(group.RoleField) && f.Default != "" {
					add(strings.Trim(f.Default, `'"`), fmt.Sprintf("the default of %s.%s", m.Table, f.Column))
				}
			}
		}
	}
	if access, _ := parseAccessConfig(appYAML); access != nil {
		var gates []string
		for table, ops := range access.rules {
			for op, mode := range ops {
				gates = append(gates, table+"\x00"+string(op)+"\x00"+mode)
			}
		}
		sort.Strings(gates)
		for _, gate := range gates {
			parts := strings.SplitN(gate, "\x00", 3)
			mode := parts[2]
			var roles []string
			switch {
			case strings.HasPrefix(mode, "role:"):
				roles = splitCommaList(strings.TrimPrefix(mode, "role:"))
			case strings.HasPrefix(mode, "owner_or_role:"):
				roles = splitCommaList(strings.TrimPrefix(mode, "owner_or_role:"))
			}
			for _, r := range roles {
				add(r, fmt.Sprintf("access.%s.%s", parts[0], parts[1]))
			}
		}
	}
	return out
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
// member-of rule protects. The groups membership table is named only when the
// app declared a create rule on it: left to its default the runtime refuses
// such an insert, and the warning used to send its author to declare a rule
// that replaces that safer default.
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
		// The groups membership table left to its default is not open: its
		// generic creates take a tenant admin (membershipManageGated). A rule
		// declared on the table replaces that default and is judged below.
		if group != nil && identIs(mt, group.Table) {
			if _, declared := access.TableDeclaredModeFor(mt, OpWrite); !declared {
				continue
			}
		}
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

// membershipUniqueWarning flags a groups membership table (groups.table) on
// which nothing makes (groups.key, groups.user_field) unique. Without it a
// repeated invite or create adds a second live row for the same member in the
// same tenant: the member then counts twice in rosters, and only one row's
// groups.role_field can apply (the oldest, oldestMembershipRow). A unique or
// primary key on any subset of the pair is enough, and so is a unique index a
// migration creates (extra, from migrationUniqueIndexes: the partial index an
// app that soft-deletes and re-adds members needs). Warning only: whether a
// member may hold two rows is the author's call.
func membershipUniqueWarning(group *GroupConfig, models []PrismaModel, extra map[string][][]string) string {
	if group == nil || group.Table == "" || group.Key == "" || group.UserField == "" {
		return ""
	}
	var model *PrismaModel
	for i := range models {
		if sqliteIdentifierFold(models[i].Table) == sqliteIdentifierFold(group.Table) {
			model = &models[i]
		}
	}
	if model == nil {
		return ""
	}
	// Block attributes list field names snake-cased; a @map renames the
	// column, so resolve each name to the field it belongs to.
	fieldOf := func(name string) *PrismaField {
		for i := range model.Fields {
			f := &model.Fields[i]
			for _, alias := range []string{f.Column, f.Name, camelToSnake(f.Name)} {
				if sqliteIdentifierFold(alias) == sqliteIdentifierFold(name) {
					return f
				}
			}
		}
		return nil
	}
	keyField, userField := fieldOf(group.Key), fieldOf(group.UserField)
	if keyField == nil || userField == nil {
		return ""
	}
	pair := func(cols []string) bool {
		for _, c := range cols {
			f := fieldOf(c)
			if f == nil || (f != keyField && f != userField) {
				return false
			}
		}
		return len(cols) > 0
	}
	if keyField.IsUnique || userField.IsUnique || (len(model.CompoundID) == 0 && (keyField.IsID || userField.IsID)) || pair(model.CompoundID) {
		return ""
	}
	for _, u := range model.Uniques {
		if pair(u.Columns) {
			return ""
		}
	}
	for _, cols := range extra[sqliteIdentifierFold(model.Table)] {
		if pair(cols) {
			return ""
		}
	}
	return fmt.Sprintf("%s is the groups membership table, but nothing makes (%s, %s) unique: a repeated invite or create adds a second live row for the same member in the same tenant, who then counts twice, and only the oldest row's role applies. Add @@unique([%s, %s]) to the model, or, if removed members are soft-deleted and added again, a migration with CREATE UNIQUE INDEX ... ON %s(%s, %s) WHERE deleted_at IS NULL.",
		model.Table, keyField.Column, userField.Column, keyField.Name, userField.Name, model.Table, keyField.Column, userField.Column)
}

// migrationUniqueIndexRe matches CREATE UNIQUE INDEX ... ON <table> (<cols>).
var migrationUniqueIndexRe = regexp.MustCompile(`(?is)\bcreate\s+unique\s+index\s+(?:if\s+not\s+exists\s+)?[^\s(]+\s+on\s+["\x60\[]?(\w+)["\x60\]]?\s*\(([^)]*)\)`)

// migrationUniqueIndexes returns the unique indexes the app's migrations
// create, by folded table name, each as its column names.
func migrationUniqueIndexes(dir string) map[string][][]string {
	files, _ := filepath.Glob(filepath.Join(dir, "migrations", "*.sql"))
	out := map[string][][]string{}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		for _, m := range migrationUniqueIndexRe.FindAllStringSubmatch(string(data), -1) {
			var cols []string
			for _, part := range strings.Split(m[2], ",") {
				if fields := strings.Fields(part); len(fields) > 0 {
					cols = append(cols, strings.Trim(fields[0], "\"`[]"))
				}
			}
			out[sqliteIdentifierFold(m[1])] = append(out[sqliteIdentifierFold(m[1])], cols)
		}
	}
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
	return fmt.Sprintf("%s join WebSocket rooms by a computed name, but app.yaml declares no ws_rooms: rules - any signed-in connection can join an undeclared room and read its messages. Bind the room names to a membership table, e.g. %s for rooms named like chat:42 (the value after `chat:` is checked as room_members.room_id).",
		strings.Join(hits, ", "), dynamicWSRoomExample)
}

// dynamicWSRoomExample is the rule dynamicWSRoomWarning tells an author to
// write. It is advice an author copies, so a test reads it back out of the
// warning and proves it keeps a non-member out of chat:42
// (TestDynamicRoomWarningAdvisesAPatternThatGates).
const dynamicWSRoomExample = `ws_rooms: {"chat::id": "room_members(room_id, user_id)"}`

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

// roleModeOwnerRowsWarnings flags a role: or perm: mode governing read,
// update or delete on a table that has user_id and no groups: key (the tenant
// root aside). rowScopeClause keeps such a table owner-scoped under those
// modes: the mode decides who may call, and a holder still reaches only the
// rows they own, so `update: role:manager` does not let a manager approve
// another user's request (that row answers 404). owner_or_role: is the mode
// that gives holders every row. Advisory: owner-only may be what is meant.
// On the 2026-11-05 fleet snapshot it flagged one app (prod and dev).
func roleModeOwnerRowsWarnings(access *AccessConfig, group *GroupConfig, roles *RolesConfig, models []PrismaModel) []string {
	if access == nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, m := range models {
		table := m.Table
		if table == "" || seen[sqliteIdentifierFold(table)] {
			continue
		}
		seen[sqliteIdentifierFold(table)] = true
		hasUID, hasGroup := modelShape(models, table, group)
		if !hasUID || hasGroup || tenantRootName(group, table) {
			continue
		}
		ops := map[string][]string{}
		var modes []string
		for _, op := range []AccessOp{OpRead, OpUpdate, OpDelete} {
			mode, ok := access.DeclaredModeFor(table, op)
			if !ok || !ownerScopedRoleMode(mode, roles) {
				continue
			}
			if ops[mode] == nil {
				modes = append(modes, mode)
			}
			ops[mode] = append(ops[mode], string(op))
		}
		for _, mode := range modes {
			out = append(out, fmt.Sprintf("access.%s: %s uses `%s` on a table with user_id and no tenant key. %s",
				table, strings.Join(ops[mode], "/"), mode, roleModeOwnerRowsHint(mode, roles)))
		}
	}
	sort.Strings(out)
	return out
}

// ownerScopedRoleMode reports a role: or perm: mode that an owner-scoped
// table narrows for some holder. A mode only `admin` passes is not: on a
// table without the tenant key only a global admin holds it there, and
// global admins bypass row scope.
func ownerScopedRoleMode(mode string, roles *RolesConfig) bool {
	return len(roleModeHolders(mode, roles)) > 0
}

// roleModeHolders returns the roles other than admin that pass a role: mode
// (its list) or a perm: mode (the roles granting the permission), and nil for
// any other mode.
func roleModeHolders(mode string, roles *RolesConfig) []string {
	var names []string
	switch {
	case strings.HasPrefix(mode, "role:"):
		names = splitCommaList(strings.TrimPrefix(mode, "role:"))
	case strings.HasPrefix(mode, "perm:"):
		names = permGrantingRoles(&App{Roles: roles}, strings.Replace(strings.TrimPrefix(mode, "perm:"), ".", ":", 1))
	}
	var out []string
	for _, name := range names {
		if name != "admin" {
			out = append(out, name)
		}
	}
	return out
}

// tenantRootName reports whether table is groups.bootstrap.org_table, where a
// role: or perm: mode scopes by tenant id rather than user_id.
func tenantRootName(group *GroupConfig, table string) bool {
	return group != nil && group.Key != "" && group.Bootstrap != nil && group.Bootstrap.OrgTable != "" &&
		sqliteIdentifierFold(group.Bootstrap.OrgTable) == sqliteIdentifierFold(table)
}

// roleModeOwnerRowsHint explains a role: or perm: mode on an owner-scoped
// table and names the owner_or_role: mode that widens it (benmore check and
// describe use the same text).
func roleModeOwnerRowsHint(mode string, roles *RolesConfig) string {
	widen := "owner_or_role:<roles>"
	if holders := roleModeHolders(mode, roles); len(holders) > 0 {
		widen = "owner_or_role:" + strings.Join(holders, ",")
	}
	return fmt.Sprintf("The mode only decides who may call: a holder still reaches only rows they own (user_id), and another user's row answers 404 (admins bypass). If holders should reach every row, use `%s` (owners keep their own rows); keep `%s` if owner-only is meant.", widen, mode)
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
		return "app.yaml: roles: names no table, so every auto-CRUD call (cookie and bearer) gets 403 `scope denied: session does not have <table>:read permission` for every account (`token` on an API token). If your roles: are capability scopes (flows, MCP tools) and table access should follow access:, add `table_scopes: access` at the top level of app.yaml."
	case !hasUser:
		return "app.yaml: roles: does not declare `user`, the role every new account holds, so those accounts get no scopes and every auto-CRUD call 403s for them. Declare `user` with its table scopes, or add `table_scopes: access` at the top level of app.yaml to let access: alone decide table access."
	}
	return ""
}
