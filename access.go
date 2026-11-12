package main

// Declarative access control - v2.7.12.
//
// The framework historically inferred access from column names: a
// table with `user_id` got owner-scoped read/write, a table with the
// configured `<group_key>` got group-scoped, and anything else was
// world-readable to any authenticated user. Three escape hatches
// (`scopes.public_read_when`, `database.shared`, `:scope=` page
// attribute) layered on top, none of them unified.
//
// `access:` in app.yaml replaces the implicit, infer-from-columns
// model with an explicit per-operation declaration:
//
//   access:
//     default:                # global defaults - apply to every table
//       read:   admin         # unless that table has its own override
//       write:  self
//       update: self
//       delete: self
//
//     posts:                  # per-table overrides
//       read:   public        # anonymous browsing
//       write:  self          # owner only
//       update: self
//       delete: admin
//
//     messages:               # shorthand: same mode for every op
//       all: everyone
//
//     orders:
//       read:   group         # multi-tenant
//       write:  group
//       update: admin
//       delete: admin
//
//     settings: off           # endpoint disabled entirely
//
//     messages:               # membership-scoped (v2.7.164): visible only
//       all: member-of:room_members(room_id, member_id)
//
// Modes: anon · everyone · self · group · admin · role:<name> ·
// owner_or_role:<roles> · perm:<resource>.<action> ·
// member-of:<table>(<join>,<user>) · off
//
// Defaults - when no access: config exists at all:
//   - Table has `user_id` column           → self everywhere
//   - Table has group_key (groups: set)    → group everywhere
//   - Neither                              → admin everywhere (PRIVATE
//                                            BY DEFAULT - the breaking
//                                            change from v2.7.11)
//
// All defaults are conservative - when ambiguous, fail closed.

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// AccessOp identifies a CRUD operation for the access map.
type AccessOp string

const (
	OpRead   AccessOp = "read"
	OpWrite  AccessOp = "write"
	OpUpdate AccessOp = "update"
	OpDelete AccessOp = "delete"
)

// AccessConfig is the parsed access: block from app.yaml. Keyed first
// by table name (or the literal "default" for global fallbacks), then
// by operation name.
//
// Nil-safe: every read goes through ModeFor / Allowed, which fall back
// to safe defaults when the config is empty or absent.
type AccessConfig struct {
	// table → op → mode. Always lowercased keys.
	rules map[string]map[AccessOp]string
	// rolesDeclared is true when the same app.yaml declares a roles:
	// block (parseRolesConfig != nil, the source of App.Roles). Without
	// one no role grants any permission, so `perm:` modes fail closed
	// instead of reading the unrestricted empty scope set as "granted".
	rolesDeclared bool
	// share is the record-sharing switch a table (or `default`) declares as
	// `share: on|off`. It is a switch, not an access mode, so it is kept out
	// of rules: everything that walks rules reads modes. Lowercased keys.
	share map[string]bool
}

// ModeFor returns the effective access mode for (table, op), applying
// the cascade: per-table per-op → per-table "all" → global per-op →
// global "all" → implicit default.
//
// `tableHasUserID` and `tableHasGroupKey` describe the schema shape
// so we can fall back to "self"/"group" the same way auto-CRUD does
// today, when the developer hasn't declared anything.
func (a *AccessConfig) ModeFor(table string, op AccessOp, tableHasUserID, tableHasGroupKey bool) string {
	if m, ok := a.DeclaredModeFor(table, op); ok {
		return m
	}
	// 3. implicit
	return implicitDefault(tableHasUserID, tableHasGroupKey)
}

// DeclaredModeFor returns the mode the developer DECLARED for (table, op) -
// per-table per-op, per-table "all", then the global `default:` per-op / all
// - and false when only the implicit column-inferred default applies. The
// distinction matters where the implicit default and an explicit declaration
// of the same name behave differently (explicit `self` is owner-only on a
// group-keyed table; the implicit default there stays tenant-wide).
func (a *AccessConfig) DeclaredModeFor(table string, op AccessOp) (string, bool) {
	if a == nil {
		return "", false
	}
	t := strings.ToLower(table)
	// 1. exact per-table per-op
	if tbl, ok := a.rules[t]; ok {
		if m, ok := tbl[op]; ok {
			return m, true
		}
		if m, ok := tbl["all"]; ok {
			return m, true
		}
	}
	// 2. global default per-op / all
	if tbl, ok := a.rules["default"]; ok {
		if m, ok := tbl[op]; ok {
			return m, true
		}
		if m, ok := tbl["all"]; ok {
			return m, true
		}
	}
	return "", false
}

// TableDeclaredModeFor is DeclaredModeFor without the global `default:`
// fallback: the mode declared on this table itself (per-op, then `all`).
func (a *AccessConfig) TableDeclaredModeFor(table string, op AccessOp) (string, bool) {
	if a == nil {
		return "", false
	}
	if tbl, ok := a.rules[strings.ToLower(table)]; ok {
		if m, ok := tbl[op]; ok {
			return m, true
		}
		if m, ok := tbl["all"]; ok {
			return m, true
		}
	}
	return "", false
}

// explicitSelfFor reports whether (table, op) is governed by an explicitly
// declared `self` mode on a table that has the owner column. rowScopeClause
// uses it to keep `self` owner-only even when the table also carries the
// tenant key (where the implicit default is tenant-wide).
func explicitSelfFor(app *App, table string, op AccessOp) bool {
	if app == nil || app.Access == nil {
		return false
	}
	mode, ok := app.Access.DeclaredModeFor(table, op)
	return ok && mode == "self" && hasColumn(app, table, "user_id")
}

// HasExplicitRule reports whether the developer explicitly declared
// an access: rule for this (table, op). Used by the 401 hint to
// decide whether to suggest `access.read: anon` - we only nudge when
// the agent hasn't taken any access:-level position on the table
// yet (so the implicit owner-scoping is what's gating them).
func (a *AccessConfig) HasExplicitRule(table string, op AccessOp) bool {
	if a == nil {
		return false
	}
	t := strings.ToLower(table)
	tbl, ok := a.rules[t]
	if !ok {
		return false
	}
	if _, ok := tbl[op]; ok {
		return true
	}
	if _, ok := tbl["all"]; ok {
		return true
	}
	return false
}

// Allowed evaluates a mode + session against a target user_id (for
// `self` mode) and returns whether the operation is permitted at the
// COARSE layer. Per-row row scoping (does this specific row belong to
// my org) still runs after - Allowed is the gatekeeper that says "can
// you even hit this endpoint."
//
// targetUserID is the row's user_id when meaningful (creates/updates
// against a specific row) or 0 when not applicable (a fresh create
// or a list).
// SessionCanAccessTable reports whether the session passes a table's
// access-MODE gate for op (off/anon/everyone/self/group/admin/role:/perm:/
// member-of:) plus the RBAC scope check - the "is this principal allowed to
// touch this table at all" question, independent of any specific row. Owner/
// group/self/member-of modes return true here (table-level) and rely on the
// caller's per-row scoping to filter rows; off/admin/role:/perm: genuinely
// gate.
//
// This closes a hole on surfaces that historically applied row-scoping ALONE
// (?include= expansion, /versions, record locks): for a table with no user_id
// and no group key, the per-row scope clause is empty, so an admin-only or
// role-gated reference table leaked all rows / full history even though a
// direct GET would 404. Callers still apply rowScopeClause/canAccessRow for
// the per-row decision; this only adds the missing mode gate.
func SessionCanAccessTable(app *App, table string, op AccessOp, session *Session) bool {
	if app == nil || !safeIdent(table) || !appHasTable(app, table) {
		return false
	}
	hasUID := hasColumn(app, table, "user_id")
	hasGroupKey := app.Group != nil && app.Group.Key != "" && hasColumn(app, table, app.Group.Key)
	mode := app.Access.ModeFor(table, op, hasUID, hasGroupKey)
	if !tableModeAllowed(app, table, op, mode, session, 0) {
		return false
	}
	if session != nil {
		action := "read"
		if op != OpRead {
			action = "write"
		}
		if err := checkScope(session, table, action); err != nil {
			return false
		}
	}
	return true
}

func (a *AccessConfig) Allowed(mode string, session *Session, targetUserID int64) bool {
	switch mode {
	case "off":
		return false
	case "anon":
		return true
	case "everyone":
		return session != nil
	case "admin":
		return session != nil && session.IsAdmin()
	case "self":
		if session == nil {
			return false
		}
		// Lists / fresh creates have no specific target row - self
		// gates the operation as "you can act on your own rows."
		// The per-row WHERE clause does the actual filtering.
		if targetUserID == 0 {
			return true
		}
		return targetUserID == session.UserID || session.IsAdmin()
	case "group":
		if session == nil {
			return false
		}
		return session.IsAdmin() || session.HasGroup()
	}
	// role:<name>   OR   role:a,b,c   (any-of)
	//
	// Single-role form is the legacy syntax; multi-role accepts a
	// comma-separated list and grants access when the session holds
	// ANY of the listed roles. Admin always satisfies the check.
	// Membership is evaluated against session.Roles (the full set
	// loaded from _benmore_user_roles + the primary column) - a
	// pre-multi-role session with only `session.Role` set still
	// works because LoadSessionRoles seeds the slice with the
	// primary role.
	if strings.HasPrefix(mode, "role:") {
		want := strings.TrimPrefix(mode, "role:")
		if session == nil {
			return false
		}
		wanted := splitCommaList(want)
		return HasAnyRole(session, wanted)
	}
	// perm:<resource>:<action>  OR  perm:<resource>.<action>
	//
	// Permission-level access. The session's effective scope set
	// (computed at session load from the union of every held role's
	// scopes, including inherited parents) is checked via HasPermission.
	// `.` is accepted as a separator so the user-facing syntax can
	// read `perm:posts.publish` while the underlying scope token is
	// `posts:publish`.
	if strings.HasPrefix(mode, "perm:") {
		want := strings.TrimPrefix(mode, "perm:")
		want = strings.Replace(want, ".", ":", 1)
		if session == nil || a == nil || !a.rolesDeclared {
			return false
		}
		return HasPermission(session, want)
	}
	// member-of:<table>(<join_col>, <user_col>)   (v2.7.164)
	//
	// Membership-scoped access: a row is reachable when the session's
	// user has a row in the membership table pointing at it - the
	// "visible to members of this room/channel/project" shape that
	// collaboration apps previously had to hand-write as EXISTS guards
	// in every flow. This coarse gate only requires authentication;
	// the actual filtering is the EXISTS predicate that rowScopeClause
	// (and handleList's filter builder) emit for every per-row path.
	// A malformed declaration fails closed here, so a typo halts
	// traffic instead of silently widening the policy.
	if strings.HasPrefix(mode, "member-of:") {
		if parseMemberOf(mode) == nil {
			return false
		}
		return session != nil
	}
	// owner_or_role:<roles> - tiered visibility. Coarse gate only requires
	// authentication; rowScopeClause does the per-row owner/role/group/acl
	// filtering. A malformed (empty role list) declaration fails closed.
	if strings.HasPrefix(mode, "owner_or_role:") {
		if strings.TrimSpace(strings.TrimPrefix(mode, "owner_or_role:")) == "" {
			return false
		}
		return session != nil
	}
	// Unknown mode → fail closed.
	return false
}

// globalRoleTier builds the "role-holder sees every row" tier of
// owner_or_role on an UN-GROUPED table, where there is no tenant column to
// bound it. It returns ok=false when the session holds none of roles.
//
// session.Roles mixes provenance: global grants (group_id IS NULL), grants
// scoped to the effective group, and the tenant membership role. Only the
// first kind (or the primary users.role column, or global admin) may widen
// to every row. Without an effective group, only global roles were loaded
// (membership roles and group grants load for an effective group), so the
// tier is plain 1=1; with one, the tier re-checks the global grant in SQL
// so it needs no extra query and works inside a transaction.
func globalRoleTier(session *Session, roles []string) (string, []any, bool) {
	if session == nil || !HasAnyRole(session, roles) {
		return "", nil, false
	}
	if session.IsAdmin() || !session.EffectiveHasGroup() {
		return "1=1", nil, true
	}
	var wanted []string
	for _, r := range roles {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		if r == session.Role {
			return "1=1", nil, true
		}
		wanted = append(wanted, r)
	}
	if len(wanted) == 0 {
		return "", nil, false
	}
	args := []any{session.UserID}
	for _, r := range wanted {
		args = append(args, r)
	}
	return fmt.Sprintf(`EXISTS (SELECT 1 FROM main._benmore_user_roles WHERE user_id = ? AND group_id IS NULL AND role IN (%s) AND (expires_at IS NULL OR datetime(expires_at) > datetime('now')))`,
		strings.TrimSuffix(strings.Repeat("?, ", len(wanted)), ", ")), args, true
}

// sessionHoldsGlobalRole reports whether the session holds one of roles from
// a platform-global source (global admin, the users.role column, or a
// group_id IS NULL grant): globalRoleTier, evaluated.
func sessionHoldsGlobalRole(app *App, session *Session, roles []string) bool {
	tier, args, ok := globalRoleTier(session, roles)
	if !ok {
		return false
	}
	if tier == "1=1" {
		return true
	}
	if app == nil || app.DB == nil {
		return false
	}
	var held bool
	return app.DB.QueryRow("SELECT "+tier, args...).Scan(&held) == nil && held
}

// tenantRootTable reports whether table is the tenant root: the
// groups.bootstrap org_table, whose row id IS the group key value, when it
// lacks the group key column (a root carrying a self-referential key column
// is an ordinary grouped table).
func tenantRootTable(app *App, table string) bool {
	if app == nil || app.Group == nil || app.Group.Key == "" || app.Group.Bootstrap == nil || app.Group.Bootstrap.OrgTable == "" {
		return false
	}
	return sqliteIdentifierFold(app.Group.Bootstrap.OrgTable) == sqliteIdentifierFold(table) && !hasColumn(app, table, app.Group.Key)
}

// groupSharedTable reports a table the app declares in groups.shared.
func groupSharedTable(app *App, table string) bool {
	if app == nil || app.Group == nil {
		return false
	}
	for _, t := range app.Group.Shared {
		if sqliteIdentifierFold(t) == sqliteIdentifierFold(table) {
			return true
		}
	}
	return false
}

// permGrantingRoles returns the roles: entries whose resolved scopes (after
// inherits:) grant perm ("resource:action"), the roles a `perm:` gate is
// satisfied through.
func permGrantingRoles(app *App, perm string) []string {
	if app == nil || app.Roles == nil {
		return nil
	}
	resource, action := parseScope(perm)
	if resource == "" {
		return nil
	}
	var out []string
	for _, name := range app.Roles.KnownRoles() {
		// An empty scope set reads as unrestricted to hasScope; it grants nothing here.
		if scopes := app.Roles.ResolveRoleScopes(name); scopes != "" && hasScope(&Session{Scopes: scopes}, resource, action) {
			out = append(out, name)
		}
	}
	return out
}

// gateRoles returns the roles that satisfy a `role:` mode (its list) or a
// `perm:` mode (the roles granting the permission), and false for any other
// mode.
func gateRoles(app *App, mode string) ([]string, bool) {
	switch {
	case strings.HasPrefix(mode, "role:"):
		return splitCommaList(strings.TrimPrefix(mode, "role:")), true
	case strings.HasPrefix(mode, "perm:"):
		return permGrantingRoles(app, strings.Replace(strings.TrimPrefix(mode, "perm:"), ".", ":", 1)), true
	}
	return nil, false
}

// tableModeAllowed is AccessConfig.Allowed for the mode governing (table, op).
//
// In an app with groups:, a `role:` gate on a table WITHOUT the group key
// column counts only globally held roles (sessionHoldsGlobalRole). The table
// has no tenant column to bound a role held inside one tenant (the membership
// role or a group-scoped grant), so such a role reached every tenant's rows.
// A `perm:` gate there likewise passes only through a permission a globally
// held role grants. The tenant root (tenantRootTable) is the exception: its
// rows ARE the tenants, so a tenant role passes there for read/update/delete
// and rowScopeClause narrows it to the caller's own tenant row. Creating an
// org row acts on no existing tenant, so it needs a global role. A table the
// app lists in groups.shared (a reference catalog with no per-tenant rows)
// keeps counting tenant roles.
//
// An `owner_or_role:<roles>` create on a table with no user_id column has no
// owner tier to create into: it is the role tier alone, so it is judged as
// `role:<roles>` (above), not as "any signed-in user".
func tableModeAllowed(app *App, table string, op AccessOp, mode string, session *Session, targetUserID int64) bool {
	if app == nil {
		return false
	}
	if columnScopedMode(mode) && !appHasTable(app, table) && !session.IsAdminBypass() {
		return false
	}
	// member-of on a table that is neither a child nor the parent of the
	// rule has no rows it could scope correctly (joinTarget).
	if strings.HasPrefix(mode, "member-of:") && memberOfMisdeclared(app, table, mode) && !session.IsAdminBypass() {
		return false
	}
	// `self` scopes rows by user_id and `group` by the tenant key; on a table
	// with neither there is nothing to scope by, and the mode would mean
	// "every signed-in user, every row".
	if (mode == "self" || mode == "group") && !tableHasScopeColumn(app, table) && !session.IsAdminBypass() {
		return false
	}
	if roles := strings.TrimSpace(strings.TrimPrefix(mode, "owner_or_role:")); op == OpWrite && roles != "" && strings.HasPrefix(mode, "owner_or_role:") && !hasColumn(app, table, "user_id") {
		mode = "role:" + roles
	}
	if !app.Access.Allowed(mode, session, targetUserID) {
		return false
	}
	if session == nil || app.Group == nil || app.Group.Key == "" || hasColumn(app, table, app.Group.Key) || groupSharedTable(app, table) {
		return true
	}
	roles, gated := gateRoles(app, mode)
	if !gated || sessionHoldsGlobalRole(app, session, roles) {
		return true
	}
	return op != OpWrite && session.EffectiveHasGroup() && tenantRootTable(app, table)
}

// columnScopedMode reports a mode whose per-row scope is built from columns
// the loaded schema declares: `self` and `owner_or_role:` (user_id), `group`
// (the tenant key) and `member-of:` (the membership join column). A table that
// exists in the database but not in the schema (a model removed from
// schema.prisma, a table a migration created) still gets auto-CRUD routes, but
// hasColumn knows none of its columns, so rowScopeClause would scope nothing
// and the mode would read as "every row". tableModeAllowed refuses these modes
// there for everyone but an admin who bypasses row scope.
func columnScopedMode(mode string) bool {
	return mode == "self" || mode == "group" || strings.HasPrefix(mode, "member-of:") || strings.HasPrefix(mode, "owner_or_role:")
}

// tableHasScopeColumn reports whether the loaded schema gives table an owner
// (user_id) or tenant-key column - what `self` and `group` scope rows by.
func tableHasScopeColumn(app *App, table string) bool {
	return hasColumn(app, table, "user_id") || (app.Group != nil && app.Group.Key != "" && hasColumn(app, table, app.Group.Key))
}

// tenantRootRoleScope narrows a `role:` or `perm:` mode on the un-grouped
// tenant root to the caller's own tenant row unless the caller holds the role
// (or a role granting the permission) globally (see tableModeAllowed). The
// global grant is re-checked in SQL by globalRoleTier. A founder user_id does
// not replace this policy, and act-as stays inside the effective tenant.
func tenantRootRoleScope(app *App, table string, session *Session, op AccessOp) (string, []any, bool) {
	if app == nil || app.Access == nil || session == nil || !tenantRootTable(app, table) {
		return "", nil, false
	}
	roles, gated := gateRoles(app, app.Access.ModeFor(table, op, hasColumn(app, table, "user_id"), false))
	if !gated {
		return "", nil, false
	}
	if session.ActingAsGroup != "" {
		return "id = ?", []any{session.EffectiveGroupID()}, true
	}
	tier, targs, ok := globalRoleTier(session, roles)
	if !ok {
		return "", nil, false
	}
	if tier == "1=1" {
		return tier, targs, true
	}
	return fmt.Sprintf("(id = ? OR %s)", tier), append([]any{session.EffectiveGroupID()}, targs...), true
}

// ownerOrRoleFor returns the role list of an `owner_or_role:<roles>` access
// mode for (table, op), or (nil, false) when the resolved mode is something
// else. The single place rowScopeClause learns it should emit the tiered
// predicate. The mode comes from an explicit per-table rule, or a `default:`
// rule that ModeFor resolves to - either way the tiered predicate is correct.
func ownerOrRoleFor(app *App, table string, op AccessOp) ([]string, bool) {
	if app == nil || app.Access == nil {
		return nil, false
	}
	hasUID := hasColumn(app, table, "user_id")
	hasGroup := app.Group != nil && app.Group.Key != "" && hasColumn(app, table, app.Group.Key)
	mode := app.Access.ModeFor(table, op, hasUID, hasGroup)
	if !strings.HasPrefix(mode, "owner_or_role:") {
		return nil, false
	}
	roles := splitCommaList(strings.TrimPrefix(mode, "owner_or_role:"))
	if len(roles) == 0 {
		return nil, false
	}
	return roles, true
}

// memberOfRule is the parsed form of a `member-of:` access mode:
// member-of:<membership_table>(<join_col>, <user_col>).
//
//   - JoinCol joins the membership table to the protected table: when
//     the protected table has a column of the same name (messages.room_id),
//     rows match on it; otherwise the protected table must BE the parent
//     the join column points at, and rows match on its `id`
//     (rooms.id = room_members.room_id). See joinTarget.
//   - UserCol identifies the member. Columns containing "email" compare
//     against the session email; everything else compares against the
//     session's numeric user id.
//   - Parent is the explicit `<join_col>=id` form: the protected table is
//     the parent, whatever its columns or name.
type memberOfRule struct {
	Table   string // membership table, e.g. room_members
	JoinCol string // FK on the membership table, e.g. room_id
	UserCol string // member identity column, e.g. member_id or email
	Parent  bool   // declared `<join_col>=id`
}

// memberOfRe validates the full mode string. Identifier-shaped names
// only - the three captures are interpolated into SQL, so anything
// outside [a-z0-9_] must never parse. (LoadAccess lowercases modes;
// SQLite identifiers are case-insensitive, so this loses nothing.)
var memberOfRe = regexp.MustCompile(`^member-of:([a-z_][a-z0-9_]*)\(\s*([a-z_][a-z0-9_]*)\s*(=\s*id\s*)?,\s*([a-z_][a-z0-9_]*)\s*\)$`)

// parseMemberOf returns the parsed rule, or nil when the mode string
// is not a well-formed member-of declaration.
func parseMemberOf(mode string) *memberOfRule {
	m := memberOfRe.FindStringSubmatch(strings.TrimSpace(mode))
	if m == nil {
		return nil
	}
	return &memberOfRule{Table: m[1], JoinCol: m[2], Parent: m[3] != "", UserCol: m[4]}
}

// userValue returns the session value the membership table's UserCol
// is compared against.
func (mr *memberOfRule) userValue(session *Session) any {
	if emailKeyedColumn(mr.UserCol) {
		// Email-keyed memberships belong to a verified address; nil
		// compares unequal to every row, so an unverified account is a
		// member of nothing.
		if email := sessionGrantEmail(session); email != "" {
			return email
		}
		return nil
	}
	return session.UserID
}

// joinTarget returns the column on the protected table that the membership
// EXISTS joins on: the rule's JoinCol when the table has it (child tables
// like messages.room_id), else "id" when the table is the parent the
// membership rows point at. ok=false when it is neither: a table without
// the join column that the join column does not point at is a misdeclared
// child (a renamed or missing column), and reading it as the parent would
// match rows to memberships by unrelated ids and auto-join every creator
// into the membership numbered like their new row. Every caller fails
// closed on ok=false.
func (mr *memberOfRule) joinTarget(app *App, table string) (col string, ok bool) {
	if mr.Parent {
		return "id", true
	}
	if hasColumn(app, table, mr.JoinCol) {
		return mr.JoinCol, true
	}
	if memberOfIsParent(app, table, mr) {
		return "id", true
	}
	return "", false
}

// memberOfIsParent reports whether table, which lacks the rule's join
// column, is the parent that column points at. In order: a declared foreign
// key on the membership join column decides; the groups membership table's
// tenant key points at groups.bootstrap.org_table when one is declared;
// otherwise the join column must be named for the table (`room_id` for
// rooms). Anything else needs the explicit `<join_col>=id` form.
func memberOfIsParent(app *App, table string, rule *memberOfRule) bool {
	if app == nil {
		return false
	}
	for mt, fks := range app.joinMapSnapshot() {
		if !identIs(mt, rule.Table) {
			continue
		}
		for col, fk := range fks {
			if identIs(col, rule.JoinCol) {
				return identIs(fk.Table, table) && (fk.Column == "" || identIs(fk.Column, "id"))
			}
		}
	}
	if g := app.Group; g != nil && identIs(rule.Table, g.Table) && identIs(rule.JoinCol, g.Key) && g.Bootstrap != nil && g.Bootstrap.OrgTable != "" {
		return identIs(g.Bootstrap.OrgTable, table)
	}
	return memberOfJoinNamesTable(rule.JoinCol, table)
}

// memberOfJoinNamesTable reports whether joinCol is the conventional foreign
// key name for table: `<singular>_id` (room_id for rooms, company_id for
// companies, box_id for boxes) or `<table>_id`.
func memberOfJoinNamesTable(joinCol, table string) bool {
	stem, ok := strings.CutSuffix(sqliteIdentifierFold(joinCol), "_id")
	t := sqliteIdentifierFold(table)
	if !ok || stem == "" || t == "" {
		return false
	}
	if t == stem || t == stem+"s" || t == stem+"es" {
		return true
	}
	y, endsY := strings.CutSuffix(stem, "y")
	return endsY && t == y+"ies"
}

// memberOfMisdeclared reports a member-of mode on a table that is neither a
// child (it lacks the join column) nor the parent of the rule.
func memberOfMisdeclared(app *App, table, mode string) bool {
	rule := parseMemberOf(mode)
	if rule == nil {
		return false
	}
	_, ok := rule.joinTarget(app, table)
	return !ok
}

// memberOfFor resolves the effective access mode for (table, op) and
// returns the parsed member-of rule when that mode is membership-scoped,
// nil otherwise. The single lookup every enforcement point shares.
func memberOfFor(app *App, table string, op AccessOp) *memberOfRule {
	if app == nil || app.Access == nil {
		return nil
	}
	hasUID := hasColumn(app, table, "user_id")
	hasGroupKey := app.Group != nil && app.Group.Key != "" && hasColumn(app, table, app.Group.Key)
	mode := app.Access.ModeFor(table, op, hasUID, hasGroupKey)
	if !strings.HasPrefix(mode, "member-of:") {
		return nil
	}
	return parseMemberOf(mode)
}

// opForACLAction maps rowScopeClause's aclAction vocabulary back to the
// access op whose declared mode governs it.
func opForACLAction(aclAction string) AccessOp {
	switch aclAction {
	case "edit":
		return OpUpdate
	case "delete":
		return OpDelete
	default:
		return OpRead
	}
}

// memberOfPredicate builds the EXISTS predicate (+args) restricting
// `table` to rows the session is a member of, OR'd with record-level
// ACL grants like every other mode. When the protected table is ALSO
// group-keyed and the session has an effective group, the tenant
// clause is AND'd on top - membership can widen visibility within a
// tenant, never across tenants.
func memberOfPredicate(app *App, table string, rule *memberOfRule, session *Session, aclAction string) (string, []any) {
	local, ok := rule.joinTarget(app, table)
	if !ok {
		return "0", nil // misdeclared: no row is in scope
	}
	aclSQL, aclArgs := recordGrantFilter(app, table, session, aclAction)
	// Only live membership rows count (groups_membership.go). The membership
	// table is aliased: when it is also the protected table (a roster scoped
	// by its own membership), an unaliased inner name would shadow the outer
	// row and any membership anywhere would admit every row. App tables
	// can't be named _benmore_*, so the alias never collides with the outer.
	const membership = "_benmore_membership"
	qualifiedTable := "main." + quoteIdent(table)
	pred := fmt.Sprintf("(EXISTS (SELECT 1 FROM main.%s AS %s WHERE %s.%s = %s.%s AND %s.%s = ?%s) OR %s)",
		quoteIdent(rule.Table), membership, membership, quoteIdent(rule.JoinCol), qualifiedTable, quoteIdent(local), membership, quoteIdent(rule.UserCol),
		membershipLiveConds(app.Group, rule.Table, membership, appColumnChecker(app, rule.Table)), aclSQL)
	args := append([]any{rule.userValue(session)}, aclArgs...)
	if memberOfTenantKeyed(app, table) {
		tenantPred, tenantArgs, tenant := rowTenantClause(app, table, session)
		if !tenant {
			// A caller with no tenant (removed from their company, or never
			// in one) gains nothing on a tenant-keyed table from membership
			// rows, as with group scoping: only an explicit share counts.
			return aclSQL, aclArgs
		}
		pred = fmt.Sprintf("(%s AND %s)", tenantPred, pred)
		args = append(tenantArgs, args...)
	}
	return pred, args
}

// memberOfTenantKeyed reports whether table carries the groups: tenant key,
// so membership on it counts only inside the caller's own tenant.
func memberOfTenantKeyed(app *App, table string) bool {
	return app.Group != nil && app.Group.Key != "" && hasColumn(app, table, app.Group.Key)
}

// memberOfHas reports whether the session is a member of the specific
// parent row identified by joinVal (used for create/update-time checks
// where the row doesn't exist yet, so the EXISTS predicate can't run).
func memberOfHas(app *App, rule *memberOfRule, joinVal any, session *Session) bool {
	return memberOfHasWith(app.DB, app, rule, joinVal, session)
}
func memberOfHasWith(db mutationQuerier, app *App, rule *memberOfRule, joinVal any, session *Session) bool {
	q := fmt.Sprintf("SELECT 1 FROM main.%s WHERE %s = ? AND %s = ?%s LIMIT 1",
		quoteIdent(rule.Table), quoteColumn(rule.Table, rule.JoinCol), quoteColumn(rule.Table, rule.UserCol),
		membershipLiveConds(app.Group, rule.Table, "", appColumnChecker(app, rule.Table)))
	var x int
	return db.QueryRow(q, joinVal, rule.userValue(session)).Scan(&x) == nil
}

// memberOfDenial is the outcome of a pre-write membership check.
// status is the HTTP status to return; msg is the JSON error detail
// (empty → the JSON 404 a read of a missing row gets, one body for a
// missing, non-member or other-tenant parent, so parent existence doesn't
// leak).
type memberOfDenial struct {
	status int
	msg    string
}

// memberOfCreateDenial enforces the member-of create rule for ONE row:
// inserting into a membership-scoped CHILD table (the table carries the
// rule's join column) requires membership in the parent the new row
// points at. Parent-table creates (join column absent → joins on id)
// pass through. val returns the row's value for a column ("" when
// absent) so form-backed (handleCreate) and JSON-item-backed (batch /
// ingest / transaction) callers share ONE implementation - the bulk
// paths skipping this check is exactly the drift the 2026-06-11 audit
// flagged (M5). Returns nil when the write may proceed.
func memberOfCreateDenial(app *App, table string, session *Session, val func(string) string) *memberOfDenial {
	return memberOfCreateDenialWith(app.DB, app, table, session, val)
}
func memberOfCreateDenialWith(db mutationQuerier, app *App, table string, session *Session, val func(string) string) *memberOfDenial {
	rule := memberOfFor(app, table, OpWrite)
	if rule == nil || session == nil || session.IsAdminBypass() {
		return nil
	}
	local, ok := rule.joinTarget(app, table)
	if !ok {
		return &memberOfDenial{
			status: http.StatusUnprocessableEntity,
			msg:    fmt.Sprintf("access.%s is member-of:%s(%s, ...) but %s has no %s column and %s.%s does not point at it: add the column, or declare the parent as member-of:%s(%s=id, %s)", table, rule.Table, rule.JoinCol, table, rule.JoinCol, rule.Table, rule.JoinCol, rule.Table, rule.JoinCol, rule.UserCol),
		}
	}
	if local == "id" {
		return nil
	}
	joinVal := strings.TrimSpace(val(local))
	if joinVal == "" {
		return &memberOfDenial{
			status: http.StatusUnprocessableEntity,
			msg:    fmt.Sprintf("%s is required: %s is membership-scoped (member-of:%s)", local, table, rule.Table),
		}
	}
	if memberOfTenantKeyed(app, table) && !session.EffectiveHasGroup() {
		return &memberOfDenial{status: http.StatusNotFound}
	}
	if !memberOfHasWith(db, app, rule, joinVal, session) {
		return &memberOfDenial{status: http.StatusNotFound}
	}
	return nil
}

// memberOfRepointDenial enforces membership in the NEW parent when an
// update re-points the join column (PATCHing a message's room_id to a
// different room) - the row-scope WHERE only proves membership in the
// row's CURRENT parent. newVal is the submitted value for a column (""
// when not being updated). Returns nil when the update may proceed.
func memberOfRepointDenial(app *App, table string, session *Session, newVal func(string) string) *memberOfDenial {
	return memberOfRepointDenialWith(app.DB, app, table, session, newVal)
}
func memberOfRepointDenialWith(db mutationQuerier, app *App, table string, session *Session, newVal func(string) string) *memberOfDenial {
	rule := memberOfFor(app, table, OpUpdate)
	if rule == nil || session == nil || session.IsAdminBypass() {
		return nil
	}
	local, ok := rule.joinTarget(app, table)
	if !ok {
		return &memberOfDenial{status: http.StatusNotFound}
	}
	if local == "id" {
		return nil
	}
	v := strings.TrimSpace(newVal(local))
	if v == "" {
		return nil
	}
	if memberOfTenantKeyed(app, table) && !session.EffectiveHasGroup() {
		return &memberOfDenial{status: http.StatusNotFound}
	}
	if !memberOfHasWith(db, app, rule, v, session) {
		return &memberOfDenial{status: http.StatusNotFound}
	}
	return nil
}

// writeMemberOfDenial renders a denial onto an HTTP response. A refusal
// without detail is the JSON {"error":"Not found"} every other 404 on the
// table answers; Go's text/plain "404 page not found" broke a client's
// res.json() on this one refusal.
func writeMemberOfDenial(w http.ResponseWriter, r *http.Request, d *memberOfDenial) {
	if d.msg == "" {
		httpError(w, "Not found", http.StatusNotFound)
		return
	}
	httpJSON(w, d.status, map[string]any{"error": d.msg})
}

// WSRoomRule binds a WebSocket room-name pattern to a membership
// check (app.yaml `ws_rooms:`, v2.7.164):
//
//	ws_rooms:
//	  "room-:id": room_members(room_id, member_id)
//
// The pattern holds at most one `:param` placeholder; its matched
// value is the join value checked against the membership table. A
// pattern with no placeholder protects one literal room name.
// parseWSRoomPattern is the one reader of a pattern.
type WSRoomRule struct {
	Pattern string
	Rule    *memberOfRule
}

// wsRoomPattern is a ws_rooms pattern as parseWSRoomPattern read it: the
// literal text before and after the placeholder (prefix alone for a literal
// room name).
type wsRoomPattern struct {
	prefix, suffix string
	param          bool
}

// parseWSRoomPattern reads a ws_rooms pattern. The forms are:
//
//	lobby             one literal room name
//	room-:id          one `:name` placeholder: rooms room-<value>
//	project-:id-chat  text after the placeholder: rooms project-<value>-chat
//	chat::id          a literal ':' directly before the placeholder: rooms chat:<value>
//
// problem is non-empty for a pattern that can't mean what its author wrote:
// `*` is not a wildcard, and one placeholder is all a pattern has. Such a
// pattern used to be matched anyway, with the first ':' as the placeholder
// and everything after its name as literal text ("chat::id" matched only
// chat<value>:id, "chat:*" only chat<value>*), so it matched none of the
// rooms it was written for and left them open to every signed-in user. The
// write gate refuses it (wsRoomPatternRefusal) and a loaded one closes its
// rooms (wsRoomClosedLead). A pattern with one ':' and no '*' reads exactly
// as it always did, unnamed placeholder ("room-:") included.
func parseWSRoomPattern(pattern string) (p wsRoomPattern, problem string) {
	if pattern == "" {
		return p, "the pattern is empty"
	}
	if strings.Contains(pattern, "*") {
		return p, "`*` is not a wildcard"
	}
	i := strings.IndexByte(pattern, ':')
	if i < 0 {
		return wsRoomPattern{prefix: pattern}, ""
	}
	start := i
	if i+1 < len(pattern) && pattern[i+1] == ':' {
		start = i + 1 // "::name": the first ':' is part of the room name
	}
	j := start + 1
	for j < len(pattern) && (pattern[j] == '_' ||
		(pattern[j] >= 'a' && pattern[j] <= 'z') ||
		(pattern[j] >= 'A' && pattern[j] <= 'Z') ||
		(pattern[j] >= '0' && pattern[j] <= '9')) {
		j++
	}
	if strings.Contains(pattern[j:], ":") {
		return p, "a pattern has one `:name` placeholder"
	}
	return wsRoomPattern{prefix: pattern[:start], suffix: pattern[j:], param: true}, ""
}

// matchWSRoomPattern extracts the placeholder value when `room`
// matches `pattern`. ok=false when it doesn't match. Literal patterns
// (no placeholder) return ("", true) on an exact match. An unusable
// pattern matches nothing.
func matchWSRoomPattern(pattern, room string) (val string, ok bool) {
	p, problem := parseWSRoomPattern(pattern)
	if problem != "" {
		return "", false
	}
	if !p.param {
		return "", p.prefix == room
	}
	if len(room) <= len(p.prefix)+len(p.suffix) ||
		!strings.HasPrefix(room, p.prefix) || !strings.HasSuffix(room, p.suffix) {
		return "", false
	}
	return room[len(p.prefix) : len(room)-len(p.suffix)], true
}

// wsRoomClosedLead reports the rooms an unusable pattern closes: every room
// whose name starts with lead, the pattern's text before its first ':' or
// '*'. That text is literal under every reading of the pattern, so the rooms
// the author meant are among them, whichever ':' was meant as the
// placeholder. closed is false for a usable pattern and for an empty one
// (which names no room).
func wsRoomClosedLead(pattern string) (lead string, closed bool) {
	if _, problem := parseWSRoomPattern(pattern); problem == "" || pattern == "" {
		return "", false
	}
	if i := strings.IndexAny(pattern, ":*"); i >= 0 {
		return pattern[:i], true
	}
	return pattern, true
}

// wsRoomPatternRefusal is the write gate's message for an unusable ws_rooms
// pattern ("" for a usable one). It names what is wrong and, when the
// pattern becomes usable by writing its `*` as a placeholder, that pattern
// and a room it restricts.
func wsRoomPatternRefusal(pattern string) string {
	_, problem := parseWSRoomPattern(pattern)
	if problem == "" {
		return ""
	}
	msg := fmt.Sprintf("ws_rooms pattern %q does not restrict the rooms it is written for: %s.", pattern, problem)
	if pattern == "" {
		return msg + " Name the rooms, e.g. \"room-:id\" for rooms named like room-42."
	}
	if lead, closed := wsRoomClosedLead(pattern); closed && lead != "" {
		msg += fmt.Sprintf(" While app.yaml holds it, rooms whose name starts with %q and match no other pattern are closed to everyone but admins.", lead)
	} else if closed {
		msg += " While app.yaml holds it, every room that matches no other pattern is closed to everyone but admins."
	}
	if fixed := strings.Replace(pattern, "*", ":id", 1); fixed != pattern {
		if p, bad := parseWSRoomPattern(fixed); bad == "" && p.prefix+p.suffix != "" {
			return msg + fmt.Sprintf(" Write %q to restrict rooms named like %s42%s: the placeholder's value is the membership join value.", fixed, p.prefix, p.suffix)
		}
	}
	return msg + " A pattern is a literal room name or holds one `:name` placeholder, whose value is the membership join value: \"room-:id\" restricts rooms named like room-42. A literal `:` may come only directly before the placeholder: \"chat::id\" restricts rooms named like chat:42. Use `-` or `.` for any other separator in the room name (`_` works before the placeholder; directly after it a `_` is part of the placeholder's name)."
}

// errMemberOfUnverified: an email-keyed membership can't be founded for an
// address the creator hasn't verified (it would not count anyway).
var errMemberOfUnverified = errors.New("creator email is not verified; email-keyed membership not added")

// memberOfAutoJoins reports whether a create on table founds a membership:
// only when table is the parent the rule's join column points at.
func memberOfAutoJoins(app *App, table string, rule *memberOfRule) bool {
	col, ok := rule.joinTarget(app, table)
	return ok && col == "id"
}

// memberOfAutoJoin inserts the creator's founding membership row after
// a parent-table create (see handleCreate). Best-effort population of
// common membership-table shapes: the join + user columns always, plus
// the app's group key and a user_id column when present - covering the
// `room_members(room_id, member_id, company_id)` shapes multi-tenant
// apps actually declare - and the initial state of a workflow on the
// membership table. Membership tables with other NOT NULL columns
// lacking defaults will error; the caller logs + surfaces it.
func memberOfAutoJoin(app *App, rule *memberOfRule, rowID any, session *Session) error {
	return memberOfAutoJoinWith(app.DB, app, rule, rowID, session)
}
func memberOfAutoJoinWith(db sqlExecutor, app *App, rule *memberOfRule, rowID any, session *Session) error {
	member := rule.userValue(session)
	if member == nil {
		return errMemberOfUnverified
	}
	cols := []string{rule.JoinCol, rule.UserCol}
	vals := []any{rowID, member}
	if app.Group != nil && app.Group.Key != "" && hasColumn(app, rule.Table, app.Group.Key) && session.EffectiveHasGroup() {
		cols = append(cols, app.Group.Key)
		vals = append(vals, session.EffectiveGroupID())
	}
	if rule.UserCol != "user_id" && hasColumn(app, rule.Table, "user_id") {
		cols = append(cols, "user_id")
		vals = append(vals, session.UserID)
	}
	// A workflow on the membership table: the founder's row starts in its
	// initial state, like a membership row created through the API.
	stateCols, stateVals := workflowInitialColumns(app, rule.Table, appColumnChecker(app, rule.Table), cols)
	cols = append(cols, stateCols...)
	vals = append(vals, stateVals...)
	placeholders := strings.TrimSuffix(strings.Repeat("?, ", len(cols)), ", ")
	_, err := db.Exec(fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s) ON CONFLICT DO NOTHING",
		quoteIdent(rule.Table), strings.Join(quoteIdents(cols), ", "), placeholders), vals...)
	return err
}

// splitCommaList splits a "a,b,c" string into trimmed non-empty parts.
func splitCommaList(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// AllowsAnon is a quick predicate: does the mode permit anonymous
// access (no session)? Used by the WS/SSE gate and by routes that
// want to skip session lookups entirely.
func (a *AccessConfig) AllowsAnon(mode string) bool {
	return mode == "anon"
}

// implicitDefault returns the framework's fallback mode for a table
// with no `access:` config. Mirrors the historical CRUD behavior
// EXCEPT for tables with neither user_id nor group_key - those used
// to be world-readable and are now admin-only (default-private).
func implicitDefault(tableHasUserID, tableHasGroupKey bool) string {
	switch {
	case tableHasUserID:
		return "self"
	case tableHasGroupKey:
		return "group"
	default:
		return "admin"
	}
}

// LoadAccess reads the `access:` section of app.yaml into an
// AccessConfig. Returns nil when the section is empty or absent -
// implicitDefault still applies in that case.
//
// Accepted shapes (both work, mixable per table):
//
//	access:
//	  posts:                 # per-op map
//	    read: public
//	    write: self
//	  messages:              # shorthand: same mode for all ops
//	    all: everyone
//	  comments: admin        # tightest shorthand - string-as-mode → all
//	  default:               # global per-op fallback
//	    read: admin
//	    write: admin
//
// Unrecognized modes are kept verbatim - `Allowed` rejects them at
// request time and logs a fail-closed warning, so a typo halts traffic
// rather than silently flapping to a broader policy.
func LoadAccess(dir string) *AccessConfig {
	config, _ := loadAccessChecked(dir)
	return config
}

func loadAccessChecked(dir string) (*AccessConfig, error) {
	data, err := readAppConfigFile(dir, "app.yaml")
	if err != nil {
		return nil, err
	}
	return parseAccessConfig(data)
}

func parseAccessConfig(data []byte) (*AccessConfig, error) {
	if len(data) == 0 {
		return nil, nil
	}
	// We parse loosely so the per-table value can be EITHER a string
	// ("admin") OR a map ({read: x, write: y}). yaml.Node lets us
	// inspect the shape before unmarshaling into the right Go type.
	var raw struct {
		Access yaml.Node `yaml:"access"`
	}
	if err := yamlUnmarshal(data, &raw); err != nil {
		return nil, err
	}
	if raw.Access.Kind == 0 || raw.Access.Kind != yaml.MappingNode {
		return nil, nil
	}
	rules := make(map[string]map[AccessOp]string)
	share := make(map[string]bool)
	for i := 0; i < len(raw.Access.Content); i += 2 {
		keyNode := raw.Access.Content[i]
		valNode := raw.Access.Content[i+1]
		if keyNode.Kind != yaml.ScalarNode {
			continue
		}
		table := strings.ToLower(strings.TrimSpace(keyNode.Value))
		if table == "" {
			continue
		}
		switch valNode.Kind {
		case yaml.ScalarNode:
			// "comments: admin" - apply to every op.
			rules[table] = map[AccessOp]string{
				"all": strings.ToLower(strings.TrimSpace(valNode.Value)),
			}
		case yaml.MappingNode:
			ops := make(map[AccessOp]string)
			for j := 0; j < len(valNode.Content); j += 2 {
				opKey := valNode.Content[j]
				opVal := valNode.Content[j+1]
				if opKey.Kind == yaml.ScalarNode && strings.ToLower(strings.TrimSpace(opKey.Value)) == accessShareKey {
					// A value that is no spelling of on or off (a mapping
					// and a list included) turns sharing off: off is the
					// narrower reading, and the write gate refuses such a
					// value. A key left empty is not set.
					switch {
					case opVal.Kind != yaml.ScalarNode:
						share[table] = false
					case opVal.Tag != "!!null" && strings.TrimSpace(opVal.Value) != "":
						on, _ := accessShareSwitch(opVal.Value)
						share[table] = on
					}
					continue
				}
				if opKey.Kind != yaml.ScalarNode || opVal.Kind != yaml.ScalarNode {
					continue
				}
				ops[AccessOp(strings.ToLower(strings.TrimSpace(opKey.Value)))] =
					strings.ToLower(strings.TrimSpace(opVal.Value))
			}
			if len(ops) > 0 {
				rules[table] = ops
			}
		}
	}
	if len(rules) == 0 && len(share) == 0 {
		return nil, nil
	}
	return &AccessConfig{rules: rules, share: share, rolesDeclared: parseRolesConfig(data) != nil}, nil
}

// accessShareKey is the per-table key of the record-sharing switch under
// access: (`access.<table>.share: off`).
const accessShareKey = "share"

// accessShareSwitch reads a `share:` value: on/off and the spellings every
// app.yaml switch takes (true/false, yes/no, 1/0). ok is false for anything
// else, and on is then false.
func accessShareSwitch(value string) (on, ok bool) {
	if strings.TrimSpace(value) == "" {
		return false, false
	}
	canon, known := canonicalAuthFlag(value)
	return known && canon == "true", known
}

// recordSharingEnabled reports whether record grants (permissions.go) are in
// force on table: the table's own `access.<table>.share`, else
// `access.default.share`, else `features.sharing`, else on. It is the one
// reading of the switch: the share endpoint refuses new grants while it is
// off (handleShare), and recordGrantFilter leaves existing grants out of the
// canonical row scope, so turning the switch back on restores them.
func recordSharingEnabled(app *App, table string) bool {
	if app == nil {
		return true
	}
	if a := app.Access; a != nil {
		if on, declared := a.share[strings.ToLower(table)]; declared {
			return on
		}
		if on, declared := a.share["default"]; declared {
			return on
		}
	}
	return app.FeatureEnabled("sharing")
}

// recordGrantFilter is the grant branch of rowScopeClause and
// memberOfPredicate: aclFilter for the session's proven address, or `0` (no
// row) while record sharing is off for the table. Every per-row surface gets
// its grant predicate here, never from aclFilter directly.
func recordGrantFilter(app *App, table string, session *Session, aclAction string) (string, []any) {
	if !recordSharingEnabled(app, table) {
		return "0", nil
	}
	return aclFilter(table, sessionGrantEmail(session), aclAction)
}

// EnforceCRUDAccess is the coarse gate every auto-CRUD handler calls
// at entry. Returns true when the request may proceed; false after
// writing a 401/404 response (caller bails immediately).
//
// `targetUserID` is the row's user_id when the operation targets a
// specific row (PATCH/DELETE on /api/<table>/{id}, where we've
// already fetched the row's user_id). Pass 0 for fresh creates and
// for list endpoints - `self` mode lets those through with the
// per-row filter applied later by handleList's WHERE builder.
//
// 404 (not 403) on access denial matches the framework's posture:
// don't leak existence of resources the caller can't reach. The one
// exception is a create, update or delete refused on a table the caller
// may read: GET already shows that table exists, so the refusal answers
// 403 and says it is an access rule (writeCRUDOpDenied) instead of the
// unmatched-route 404 that sent developers hunting for a typo.
func EnforceCRUDAccess(w http.ResponseWriter, r *http.Request, app *App, table string, op AccessOp, targetUserID int64) bool {
	if actor, private := appMCPPrivateSession(app, r); private {
		identity, _ := r.Context().Value(appMCPPrivateKey{}).(*appMCPPrivateRead)
		if actor == nil || identity == nil || identity.table != table || op != OpRead {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "connector grant denied"})
			return false
		}
	}
	if app == nil {
		writeUnmatchedAPINotFound(w)
		return false
	}
	hasUID := hasColumn(app, table, "user_id")
	hasGroupKey := app.Group != nil && app.Group.Key != "" && hasColumn(app, table, app.Group.Key)
	mode := app.Access.ModeFor(table, op, hasUID, hasGroupKey)
	if mode == "off" {
		// `off` disables the route itself (route discovery lists it under
		// crud_access_off), so it keeps the unmatched-route answer.
		writeUnmatchedAPINotFound(w)
		return false
	}
	var session *Session
	if mode != "anon" {
		session = getSession(app, r)
		if session == nil {
			// Auth-required mode hit by an anonymous client. 401 - the
			// canonical "log in and try again" signal.
			//
			// On the read path, when the table has user_id (implicit
			// owner-scoping) AND the agent didn't set an explicit
			// access: mode, also include a hint pointing at the
			// `access.read: anon` lever. An earlier app build built a custom
			// /api/feed flow before realizing this; the hint surfaces
			// the right pattern at the moment the 401 fires. Filtered
			// to read-of-owner-default so we don't suggest "make this
			// public" on, say, _benmore_users or admin-only tables.
			body := unauthenticatedAPIBody(app, r, table, op, hasUID)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(body))
			return false
		}
	}
	if !tableModeAllowed(app, table, op, mode, session, targetUserID) {
		// Group-mode LIST for a caller with no resolved group is an empty
		// filtered view, not a missing resource. The endpoint exists, the
		// collection exists, the caller just has no rows in scope yet -
		// REST-correct response is 200 []. Returning 404 here breaks
		// onboarding boots that legitimately list before a group is
		// established (the SPA can't decide where to route the user if
		// list endpoints throw). The per-row scope (rowScopeClause)
		// already handles "no group": only rows shared with the caller
		// and their own rows that carry no tenant, so passing the gate
		// is safe - the empty result emerges naturally.
		//
		// Single-row reads (targetUserID != 0) and writes still fail
		// here: those would either leak existence of rows the caller
		// can't reach or accept orphan rows.
		if op == OpRead && mode == "group" && targetUserID == 0 && session != nil && !session.EffectiveHasGroup() && !session.IsAdminBypass() && (hasUID || hasGroupKey) {
			return true
		}
		if op != OpRead && crudReadGatePasses(app, table, session, hasUID, hasGroupKey) {
			writeCRUDOpDenied(w, app, table, op, mode, session, hasGroupKey)
			return false
		}
		writeUnmatchedAPINotFound(w)
		return false
	}
	return true
}

// crudReadGatePasses reports whether EnforceCRUDAccess would let session list
// table: the read mode is not off, an anonymous caller only on an anon table,
// and the mode admits the caller (including the empty list a tenant-less
// caller gets on a group table). When it passes, GET /api/<table> already
// answers this caller with something other than the unmatched-route 404, so
// naming a refused write as an access refusal reveals nothing new.
func crudReadGatePasses(app *App, table string, session *Session, hasUID, hasGroupKey bool) bool {
	if app == nil {
		return false
	}
	mode := app.Access.ModeFor(table, OpRead, hasUID, hasGroupKey)
	switch {
	case mode == "off":
		return false
	case mode != "anon" && session == nil:
		return false
	case tableModeAllowed(app, table, OpRead, mode, session, 0):
		return true
	}
	return mode == "group" && session != nil && !session.EffectiveHasGroup() && !session.IsAdminBypass() && (hasUID || hasGroupKey)
}

// tableReadGateFor is crudReadGatePasses for a table name that has not been
// checked yet: false for a name that is not a served schema table. Side
// routes (/api/_transaction, share/permissions, revert) use it to answer a
// table the caller may not list exactly like an unmatched /api path before
// any per-row or scope message, so they are no oracle for which tables exist
// (security.md 14f); a refusal on a table that passes keeps its 403.
// It is consulted only once a request is being refused: a write-only table
// (`read: admin`, `write: everyone`) must keep accepting the writes its
// rules allow.
func tableReadGateFor(app *App, table string, session *Session) bool {
	if app == nil || !safeIdent(table) || !appHasTable(app, table) {
		return false
	}
	hasUID := hasColumn(app, table, "user_id")
	hasGroupKey := app.Group != nil && app.Group.Key != "" && hasColumn(app, table, app.Group.Key)
	return crudReadGatePasses(app, table, session, hasUID, hasGroupKey)
}

// writeTableRefusal answers a refused side-route request: the unmatched-route
// 404 when the caller may not read the table (14f), otherwise status + body.
func writeTableRefusal(w http.ResponseWriter, app *App, table string, session *Session, status int, body map[string]any) {
	if !tableReadGateFor(app, table, session) {
		writeUnmatchedAPINotFound(w)
		return
	}
	httpJSON(w, status, body)
}

// writeCRUDOpDenied answers a create, update or delete the access rules refuse
// on a table the caller may read (crudReadGatePasses): 403 with what was
// refused, never which rule or role would allow it. When the op's mode is `group`
// and the caller has no tenant, that is the cause, and the answer says so.
func writeCRUDOpDenied(w http.ResponseWriter, app *App, table string, op AccessOp, mode string, session *Session, hasGroupKey bool) {
	action := map[AccessOp]string{OpWrite: "create rows in", OpUpdate: "change rows in", OpDelete: "delete rows from"}[op]
	if action == "" {
		action = string(op) + " rows in"
	}
	body := map[string]any{
		"error":   "forbidden",
		"message": fmt.Sprintf("the app's access rules do not let you %s %s (its `%s` rule under access: in app.yaml)", action, table, op),
	}
	if mode == "group" && hasGroupKey && app.Group != nil && session != nil && !session.EffectiveHasGroup() && !session.IsAdminBypass() {
		hint := fmt.Sprintf("%s rows belong to a tenant (%s) and your session has none yet: join a tenant as a member", table, app.Group.Key)
		if app.Group.Bootstrap != nil {
			hint += " or create one with POST /api/_groups/create"
		}
		body["hint"] = hint + ", then retry"
	}
	w.Header().Set("Cache-Control", "no-store")
	httpJSON(w, http.StatusForbidden, withRefusalDocs(body, "forbidden"))
}

// ReadAllowsBroaderRows returns true when the read mode permits
// rows the caller doesn't personally own - i.e. handleList should
// SKIP its implicit owner-WHERE filter and rely on `scopes:` /
// per-table read-filter overrides instead. Modes that broaden:
// anon, everyone. Modes that keep per-row filtering: self, group,
// admin (admins already bypass), role:*.
func (a *AccessConfig) ReadAllowsBroaderRows(mode string) bool {
	return mode == "anon" || mode == "everyone"
}

// rowScopeClause is the SINGLE SOURCE OF TRUTH for per-row access scoping.
// It returns a SQL predicate (no leading "AND") + its args that restricts a
// query to rows the session may touch for `aclAction` ("view"/"edit"/"delete"),
// plus a `bypass` flag. Honors the full model, act-as aware:
//
//   - bypass=true  → caller is an admin NOT stepped into a tenant
//     (IsAdminBypass). No row restriction; ignore predicate.
//   - declared `self` on a user_id table   → `(user_id = ? OR <acl>)`.
//   - group-scoped table + EFFECTIVE group → `(group_key = ?)`.
//   - else owner-scoped (user_id)           → `(user_id = ? OR <acl>)`.
//   - On a group-keyed table with an EFFECTIVE group, every predicate
//     (owner, role tier, ACL grant, membership) is AND'd with
//     `group_key = ?`: a record-level share never crosses tenants.
//   - On a group-keyed table WITHOUT an effective group, the owner tier
//     reaches only the caller's rows that carry no tenant
//     (rowCarriesNoTenantSQL): a row with a tenant belongs to that tenant,
//     and a member removed from it does not keep the rows they created.
//     An explicit ACL grant still authorizes a row, and on the groups
//     membership table the caller's own row stays in the owner tier.
//     An action whose rule is DECLARED `self` is the exception: it keeps
//     `(user_id = ? OR <acl>)` for a caller with no tenant.
//   - On the groups membership table, a caller with no effective tenant
//     READS the rows that name them as the member (ownMembershipReadSQL),
//     whatever the row's user_id: `(<the above> OR <user field> = ?)`,
//     under the rules where a live member reads the roster through the
//     tenant (the default tail and member-of). View only.
//   - table has neither + not bypass        → ("", nil, false): no columns to
//     scope by (unscoped table - same as the historical inline behavior).
//   - Every `<acl>` above is recordGrantFilter: with record sharing off for
//     the table (features.sharing, access.<table>.share) it is `0`, so a
//     stored grant reaches no row on any surface until sharing is on again.
//
// Every per-row read/write/delete path (CRUD, batch, versioning, includes,
// workflow transitions, locks, signed-URL authorization) routes through this
// so the policy can't drift. Crucially it uses IsAdminBypass (a STEPPED-IN
// admin does NOT bypass) and EffectiveGroupID (the acted-as tenant), closing
// the act-as escapes that the old per-site copies had (IsAdmin + native group).
func rowScopeClause(app *App, table string, session *Session, aclAction string) (predicate string, args []any, bypass bool) {
	if session != nil && session.IsAdminBypass() {
		return "", nil, true
	}
	if session == nil {
		// Only reachable on anon/everyone-mode tables (the access-mode gate
		// already ran). No owner/group identity → nothing to scope by here.
		return "", nil, false
	}
	// ownRead adds the one read a caller with no tenant keeps on the groups
	// membership table: the rows that name them as the member, live or not
	// (ownMembershipReadSQL). It is a no-op for every other table, caller
	// and action. Only the branches where a LIVE member reads the roster
	// through the tenant call it (member-of and the default tail), so a
	// switched-off member never reads more than a live one: under a declared
	// `self` or `owner_or_role:` the owner tier decides for both.
	ownRead := func(pred string, pargs []any) (string, []any, bool) {
		own, member, ok := ownMembershipReadSQL(app, table, session, aclAction)
		if !ok {
			return pred, pargs, false
		}
		return "(" + pred + " OR " + own + ")", append(append([]any{}, pargs...), member), false
	}
	// member-of mode REPLACES owner/group scoping for the governed op:
	// the whole point is that members see each other's rows. The tenant
	// clause is still AND'd inside memberOfPredicate when the table is
	// group-keyed, so membership never crosses tenants.
	if rule := memberOfFor(app, table, opForACLAction(aclAction)); rule != nil {
		pred, args := memberOfPredicate(app, table, rule, session, aclAction)
		if _, fits := rule.joinTarget(app, table); !fits {
			return pred, args, false // misdeclared: no row is in scope
		}
		return ownRead(pred, args)
	}
	// Tiered mode `owner_or_role:<roles>` - the ONE declaration that expresses
	// "owner sees own, manager sees group, admin sees all" without a hand-rolled
	// secure-read flow. A row is visible when ANY tier matches:
	//   - you OWN it (user_id = you), OR
	//   - you hold one of <roles> and then see your whole GROUP (group-keyed
	//     tables) / ALL rows (un-grouped tables), OR
	//   - an ACL grant covers it.
	// Platform admins (not stepped in) already short-circuited via bypass above,
	// which is the "admin sees all (every tenant)" tier. Built here at the single
	// choke point so every per-row path (list/read/update/delete/batch/tx)
	// inherits it identically.
	// tenant is true when the table carries the groups: key AND the caller has
	// an effective (act-as-aware) tenant. Every branch below then AND's the
	// tenant clause around its WHOLE predicate - owner rows, role tiers and
	// record-level ACL grants alike - so a share (or a stale owner row) from
	// another tenant can never reach this caller.
	tableIsGrouped := memberOfTenantKeyed(app, table)
	tenantPred, tenantArgs, tenant := rowTenantClause(app, table, session)
	withTenant := func(pred string, pargs []any) (string, []any, bool) {
		if !tenant {
			return pred, pargs, false
		}
		return fmt.Sprintf("(%s AND %s)", tenantPred, pred),
			append(append([]any{}, tenantArgs...), pargs...), false
	}
	// ownerTier is the owner predicate with its arguments. A caller with no
	// effective tenant owns, on a group-keyed table, only rows that carry no
	// tenant: there is no tenant clause to AND around the tier for them, and
	// without this bound a member removed from a tenant kept reading (and
	// under the owner-scoped modes editing, deleting and sharing) every
	// tenant row they had created, other members' later edits included.
	// One row with a tenant stays theirs: their own row of the groups
	// membership table (ownMembershipRowSQL), so a member whose membership is
	// switched off still sees it and may leave. What they may change on it is
	// the membership gates' decision (groups_membership_manage.go,
	// membershipActivationDenial), as before.
	ownerTier, ownerArgs := "user_id = ?", []any{session.UserID}
	if tableIsGrouped && !tenant {
		ownerTier = "(user_id = ? AND " + rowCarriesNoTenantSQL(app) + ")"
		if own, member, ok := ownMembershipRowSQL(app, table, session); ok {
			ownerTier = "(user_id = ? AND (" + rowCarriesNoTenantSQL(app) + " OR " + own + "))"
			ownerArgs = append(ownerArgs, member)
		}
	}
	if roles, ok := ownerOrRoleFor(app, table, opForACLAction(aclAction)); ok {
		if tenant && HasAnyRole(session, roles) {
			// Role-holder sees their whole tenant.
			return "(" + tenantPred + ")", tenantArgs, false
		}
		aclSQL, aclArgs := recordGrantFilter(app, table, session, aclAction)
		var parts []string
		var sargs []any
		if hasColumn(app, table, "user_id") {
			parts = append(parts, ownerTier)
			sargs = append(sargs, ownerArgs...)
		}
		// A role-holder on a genuinely un-grouped table sees every row. On a
		// group-keyed table with NO effective group the role tier contributes
		// nothing: `1=1` there would expose EVERY tenant's rows to a group-less
		// role-holder. Fall back to the owner tier, which for that caller
		// holds only their rows that carry no tenant.
		//
		// Only a GLOBALLY held role earns that: an un-grouped table has no
		// tenant column, so a role held inside one tenant (the membership
		// role, or a group-scoped grant) widening to every row would hand
		// one tenant's member every other tenant's rows.
		if !tableIsGrouped {
			if pred, pargs, ok := globalRoleTier(session, roles); ok {
				parts = append(parts, pred)
				sargs = append(sargs, pargs...)
			}
		}
		parts = append(parts, aclSQL)
		sargs = append(sargs, aclArgs...)
		return withTenant("("+strings.Join(parts, " OR ")+")", sargs)
	}
	// Explicitly declared `self` is OWNER-ONLY - including on a table that
	// also carries the tenant key, where the group branch below would
	// otherwise widen it to every row in the caller's tenant. The tenant
	// clause is AND'd on top, so an owner's row in another tenant (created
	// before a move, or while acting as a different group) stays out of
	// scope. The IMPLICIT default for a user_id + tenant-key table is still
	// tenant-wide (the group branch).
	//
	// A caller with NO tenant keeps the plain owner tier here, for the
	// action whose rule is declared `self` (explicitSelfFor: the table's own
	// key for the action, its `all:`, or the global `default:`): the builder
	// wrote "the owner reaches their own row" for it, and apps declare it on
	// a tenant-keyed table for rows a not-yet-member owns (a request to join
	// a tenant that its requester tracks and withdraws). The bound above is
	// for the modes where the tenant, not the builder's rule, decides.
	if explicitSelfFor(app, table, opForACLAction(aclAction)) {
		aclSQL, aclArgs := recordGrantFilter(app, table, session, aclAction)
		return withTenant(fmt.Sprintf("(user_id = ? OR %s)", aclSQL), append([]any{session.UserID}, aclArgs...))
	}
	if tenant {
		// Group mode: every member of the tenant already reaches every tenant
		// row, so a record-level grant adds nothing inside the tenant - and
		// OR-ing it in unguarded let a share reach a user in ANOTHER tenant.
		return "(" + tenantPred + ")", tenantArgs, false
	}
	// A role/permission on the tenant root scopes by tenant id even when
	// bootstrap records its founder in user_id. Ownership of an old tenant
	// must not grant access while holding a role in another tenant.
	if pred, pargs, ok := tenantRootRoleScope(app, table, session, opForACLAction(aclAction)); ok {
		return pred, pargs, false
	}
	if hasColumn(app, table, "user_id") {
		aclSQL, aclArgs := recordGrantFilter(app, table, session, aclAction)
		return ownRead(fmt.Sprintf("(%s OR %s)", ownerTier, aclSQL), append(ownerArgs, aclArgs...))
	}
	if tableIsGrouped {
		// A group-keyed table is still scoped when the caller has no group.
		// Only an explicit ACL grant can authorize a row in that case, and
		// on the membership table the rows that name the caller (read only).
		pred, args := recordGrantFilter(app, table, session, aclAction)
		return ownRead(pred, args)
	}
	return "", nil, false
}

// rowCarriesNoTenantSQL matches a row of a group-keyed table that belongs to
// no tenant: its tenant key is NULL, empty or 0, the values a session without
// a tenant holds (EffectiveHasGroup). Such a row is what a signed-in user
// creates before joining or founding a tenant (the create injects the key
// only from a session that has one), so its owner keeps it while tenant-less.
// The '0' literal takes the column's affinity: it matches 0 in an integer key
// and '0' in a text one.
func rowCarriesNoTenantSQL(app *App) string {
	key := quoteIdent(app.Group.Key)
	return fmt.Sprintf("(%s IS NULL OR %s = '' OR %s = '0')", key, key, key)
}

// ownMembershipRowSQL matches, on the groups membership table, the rows that
// name the session as the member: groups.user_field compared with the value
// membership resolution uses (groupMemberValue: the user id, or the proven
// address for an email-keyed table), the comparison membershipOwnRow makes.
// ok=false on any other table, when the table lacks the column, or when the
// session can hold no membership (an unproven address).
func ownMembershipRowSQL(app *App, table string, session *Session) (pred string, member any, ok bool) {
	g := app.Group
	if g == nil || g.Table == "" || !identIs(table, g.Table) || !membershipIdentRe.MatchString(g.UserField) || !hasColumn(app, table, g.UserField) {
		return "", nil, false
	}
	member, ok = groupMemberValue(g, session)
	if !ok {
		return "", nil, false
	}
	return quoteIdent(g.UserField) + " = ?", member, true
}

// ownMembershipReadSQL is the read a caller with NO effective tenant keeps on
// the groups membership table: the rows whose groups.user_field names them
// (ownMembershipRowSQL), whichever tenant the row names, whether or not it is
// active and whoever created it. A member whose only membership is switched
// off through groups.active_field lists it this way (the row an "your access
// was switched off" screen shows); a roster keyed by its own member column
// has no user_id of theirs for the owner tier to match.
//
// ok is false for every action but "view", on every other table and for a
// caller who has a tenant (a live member, an admin stepped into one): they
// read the roster of that tenant and nothing is added. The read confers
// nothing: tenant resolution and the membership role still count only live
// rows (membershipLiveConds), so the caller stays without a tenant and
// without a tenant role, and no other table's scope looks at this row.
func ownMembershipReadSQL(app *App, table string, session *Session, aclAction string) (pred string, member any, ok bool) {
	if aclAction != "view" || !memberOfTenantKeyed(app, table) || session.EffectiveHasGroup() {
		return "", nil, false
	}
	return ownMembershipRowSQL(app, table, session)
}

// rowTenantClause is the tenant clause of rowScopeClause on its own: on a
// table that carries the groups: key, for a session with an EFFECTIVE
// (act-as-aware) tenant, `<group key> = ?` bound to that tenant. ok is false
// when the table has no tenant key or the session has no tenant; no tenant
// clause applies then (rowScopeClause falls back to ownership and grants).
//
// rowScopeClause and memberOfPredicate AND it around what they return. A
// surface that must stay inside the record's tenant without requiring access
// to the row (who can be named approver of a record, approval_audience.go)
// uses it directly instead of writing the comparison again.
func rowTenantClause(app *App, table string, session *Session) (pred string, args []any, ok bool) {
	if !memberOfTenantKeyed(app, table) || !session.EffectiveHasGroup() {
		return "", nil, false
	}
	return quoteIdent(app.Group.Key) + " = ?", []any{session.EffectiveGroupID()}, true
}

// rowIDCanonical reports whether id is the one spelling of a row id of table
// that the framework accepts from a request. Locks, record shares, audit
// rows and approvals are keyed by the id TEXT, while SQLite compares a
// numeric key column by value: `id = '1.0'`, `'01'`, `' 1'` and `'1e0'` all
// match row 1. A lock held on "1" therefore did not stop PATCH /api/t/1.0,
// and the edit was audited under row "1.0". Every row-addressed route
// (read, update, delete, batch, /api/_transaction, workflow transition,
// lock, share, versions, revert, approvals, signed URLs) refuses a
// non-canonical spelling as "not found".
//
// A key column with TEXT affinity (UUIDs, slugs) is compared as text, so any
// non-empty id is its own canonical form. For every other key column - and
// for a table the schema does not describe - an id that reads as a number
// must be written the way SQLite prints it: a decimal integer with no sign
// prefix, leading zero, fraction, exponent or surrounding space.
func rowIDCanonical(app *App, table, id string) bool {
	if id == "" {
		return false
	}
	if app != nil {
		for _, t := range app.Tables {
			if !identIs(t.Name, table) {
				continue
			}
			for _, c := range t.Columns {
				if identIs(c.Name, "id") && textAffinityType(c.Type) {
					return true
				}
			}
		}
	}
	// SQLite ignores surrounding whitespace when it reads text as a number.
	f, err := strconv.ParseFloat(strings.TrimSpace(id), 64)
	if err != nil {
		return true // not a number: compared as text, it cannot alias a numeric id
	}
	if n, err := strconv.ParseInt(id, 10, 64); err == nil && strconv.FormatInt(n, 10) == id {
		return true
	}
	// A genuinely fractional key (a REAL primary key) in its shortest form.
	return f != math.Trunc(f) && !math.IsInf(f, 0) && strconv.FormatFloat(f, 'f', -1, 64) == id
}

// textAffinityType reports a declared column type with SQLite TEXT affinity
// (it contains CHAR, CLOB or TEXT and not INT).
func textAffinityType(declared string) bool {
	t := strings.ToUpper(declared)
	if strings.Contains(t, "INT") {
		return false
	}
	return strings.Contains(t, "CHAR") || strings.Contains(t, "CLOB") || strings.Contains(t, "TEXT")
}

// canAccessRowScoped reports whether the session may access row id of table
// under rowScopeClause for aclAction. The canonical single-row predicate used
// by every "can this caller touch this specific row" check.
func canAccessRowScoped(app *App, table, id string, session *Session, aclAction string) bool {
	if !rowIDCanonical(app, table, id) {
		return false
	}
	pred, args, bypass := rowScopeClause(app, table, session, aclAction)
	if bypass {
		// Admin (not stepped in): the row is reachable if it exists (+ not soft-deleted).
		q := "SELECT 1 FROM " + quoteIdent(table) + " WHERE id = ?"
		if hasColumn(app, table, "deleted_at") {
			q += " AND deleted_at IS NULL"
		}
		var x int
		return app.DB.QueryRow(q, id).Scan(&x) == nil
	}
	q := "SELECT 1 FROM " + quoteIdent(table) + " WHERE id = ?"
	qargs := []any{id}
	if hasColumn(app, table, "deleted_at") {
		q += " AND deleted_at IS NULL"
	}
	if pred != "" {
		q += " AND " + pred
		qargs = append(qargs, args...)
	}
	var x int
	return app.DB.QueryRow(q, qargs...).Scan(&x) == nil
}

// String returns a human-readable dump (for app validation / docs).
func (a *AccessConfig) String() string {
	if a == nil || len(a.rules) == 0 {
		return "(no access: block - implicit defaults apply)"
	}
	var b strings.Builder
	for table, ops := range a.rules {
		fmt.Fprintf(&b, "%s:\n", table)
		for op, mode := range ops {
			fmt.Fprintf(&b, "  %s: %s\n", op, mode)
		}
	}
	return b.String()
}

// unauthenticatedAPIBody is the 401 body for an auto-CRUD request without a
// valid session. The public-feed hint is for an anonymous read of an
// owner-scoped table with no explicit access rule. A request that did present
// a credential (a session cookie or an Authorization header) that no longer
// resolves - an expired, revoked or restored-away token or session - is told
// that instead: suggesting `read: anon` to it pointed at the wrong fix. One
// refused only because auth.require_verified wants its account's email
// verified gets email_verification_required: signing in again would not help.
func unauthenticatedAPIBody(app *App, r *http.Request, table string, op AccessOp, hasUID bool) string {
	presented := r.Header.Get("Authorization") != ""
	if c, err := requestSessionCookie(r); err == nil && c.Value != "" {
		presented = true
	}
	// Where the rule is documented (refusal_docs.go), closing each body.
	docs := `,"docs":"` + refusalDocsAt(refusalAuthRequired, "") + `"}`
	if presented {
		if presentedCredentialAwaitsVerification(app, r) {
			body, _ := json.Marshal(unverifiedCredentialBody(app))
			return string(body)
		}
		return `{"error":"authentication required","hint":"The session or token this request sent is not valid (expired, revoked or signed out). Sign in again or use a current token."` + docs
	}
	if op == OpRead && hasUID && !app.Access.HasExplicitRule(table, op) {
		return `{"error":"authentication required","hint":"This table is owner-scoped (visitors see 401). For a public feed, declare ` + "`access:\\n  " + table + ":\\n    read: anon`" + ` in app.yaml; that makes EVERY row of the table readable without sign-in, drafts and other owners' rows included (scopes.public_read_when does not narrow it), so to publish only some rows keep the table private and serve them from a public flow. The access modes are listed in api(at:'access') (CLI: benmore api <app> access)."` + docs
	}
	return `{"error":"authentication required"` + docs
}
