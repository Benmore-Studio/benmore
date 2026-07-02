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
// perm:<resource>.<action> · member-of:<table>(<join>,<user>) · off
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
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
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
}

// ModeFor returns the effective access mode for (table, op), applying
// the cascade: per-table per-op → per-table "all" → global per-op →
// global "all" → implicit default.
//
// `tableHasUserID` and `tableHasGroupKey` describe the schema shape
// so we can fall back to "self"/"group" the same way auto-CRUD does
// today, when the developer hasn't declared anything.
func (a *AccessConfig) ModeFor(table string, op AccessOp, tableHasUserID, tableHasGroupKey bool) string {
	if a == nil {
		return implicitDefault(tableHasUserID, tableHasGroupKey)
	}
	t := strings.ToLower(table)
	// 1. exact per-table per-op
	if tbl, ok := a.rules[t]; ok {
		if m, ok := tbl[op]; ok {
			return m
		}
		if m, ok := tbl["all"]; ok {
			return m
		}
	}
	// 2. global default per-op / all
	if tbl, ok := a.rules["default"]; ok {
		if m, ok := tbl[op]; ok {
			return m
		}
		if m, ok := tbl["all"]; ok {
			return m
		}
	}
	// 3. implicit
	return implicitDefault(tableHasUserID, tableHasGroupKey)
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
	if !app.Access.Allowed(mode, session, 0) {
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
		if session == nil {
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
//     rows match on it; otherwise the protected table IS the parent and
//     rows match on its `id` (rooms.id = room_members.room_id).
//   - UserCol identifies the member. Columns containing "email" compare
//     against the session email; everything else compares against the
//     session's numeric user id.
type memberOfRule struct {
	Table   string // membership table, e.g. room_members
	JoinCol string // FK on the membership table, e.g. room_id
	UserCol string // member identity column, e.g. member_id or email
}

// memberOfRe validates the full mode string. Identifier-shaped names
// only - the three captures are interpolated into SQL, so anything
// outside [a-z0-9_] must never parse. (LoadAccess lowercases modes;
// SQLite identifiers are case-insensitive, so this loses nothing.)
var memberOfRe = regexp.MustCompile(`^member-of:([a-z_][a-z0-9_]*)\(\s*([a-z_][a-z0-9_]*)\s*,\s*([a-z_][a-z0-9_]*)\s*\)$`)

// parseMemberOf returns the parsed rule, or nil when the mode string
// is not a well-formed member-of declaration.
func parseMemberOf(mode string) *memberOfRule {
	m := memberOfRe.FindStringSubmatch(strings.TrimSpace(mode))
	if m == nil {
		return nil
	}
	return &memberOfRule{Table: m[1], JoinCol: m[2], UserCol: m[3]}
}

// userValue returns the session value the membership table's UserCol
// is compared against.
func (mr *memberOfRule) userValue(session *Session) any {
	if strings.Contains(mr.UserCol, "email") {
		return session.Email
	}
	return session.UserID
}

// localJoinCol returns the column on the protected table that the
// membership EXISTS joins on: the rule's JoinCol when the table has
// it (child tables like messages.room_id), else "id" (the protected
// table is the parent the membership rows point at).
func (mr *memberOfRule) localJoinCol(app *App, table string) string {
	if hasColumn(app, table, mr.JoinCol) {
		return mr.JoinCol
	}
	return "id"
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
	local := rule.localJoinCol(app, table)
	aclSQL, aclArgs := aclFilter(table, session.Email, aclAction)
	pred := fmt.Sprintf("(EXISTS (SELECT 1 FROM %s WHERE %s.%s = %s.%s AND %s.%s = ?) OR %s)",
		rule.Table, rule.Table, rule.JoinCol, table, local, rule.Table, rule.UserCol, aclSQL)
	args := append([]any{rule.userValue(session)}, aclArgs...)
	if app.Group != nil && app.Group.Key != "" && hasColumn(app, table, app.Group.Key) && session.EffectiveHasGroup() {
		pred = fmt.Sprintf("(%s = ? AND %s)", app.Group.Key, pred)
		args = append([]any{session.EffectiveGroupID()}, args...)
	}
	return pred, args
}

// memberOfHas reports whether the session is a member of the specific
// parent row identified by joinVal (used for create/update-time checks
// where the row doesn't exist yet, so the EXISTS predicate can't run).
func memberOfHas(app *App, rule *memberOfRule, joinVal any, session *Session) bool {
	q := fmt.Sprintf("SELECT 1 FROM %s WHERE %s = ? AND %s = ? LIMIT 1",
		rule.Table, rule.JoinCol, rule.UserCol)
	var x int
	return app.DB.QueryRow(q, joinVal, rule.userValue(session)).Scan(&x) == nil
}

// memberOfDenial is the outcome of a pre-write membership check.
// status is the HTTP status to return; msg is the JSON error detail
// (empty → plain 404 body, so parent existence doesn't leak).
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
	rule := memberOfFor(app, table, OpWrite)
	if rule == nil || session == nil || session.IsAdminBypass() {
		return nil
	}
	local := rule.localJoinCol(app, table)
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
	if !memberOfHas(app, rule, joinVal, session) {
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
	rule := memberOfFor(app, table, OpUpdate)
	if rule == nil || session == nil || session.IsAdminBypass() {
		return nil
	}
	local := rule.localJoinCol(app, table)
	if local == "id" {
		return nil
	}
	v := strings.TrimSpace(newVal(local))
	if v == "" {
		return nil
	}
	if !memberOfHas(app, rule, v, session) {
		return &memberOfDenial{status: http.StatusNotFound}
	}
	return nil
}

// writeMemberOfDenial renders a denial onto an HTTP response.
func writeMemberOfDenial(w http.ResponseWriter, r *http.Request, d *memberOfDenial) {
	if d.msg == "" {
		http.NotFound(w, r)
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
// The pattern holds exactly one `:param` placeholder; its matched
// value is the join value checked against the membership table. A
// pattern with no placeholder protects one literal room name.
type WSRoomRule struct {
	Pattern string
	Rule    *memberOfRule
}

// matchWSRoomPattern extracts the placeholder value when `room`
// matches `pattern`. ok=false when it doesn't match. Literal patterns
// (no placeholder) return ("", true) on an exact match.
func matchWSRoomPattern(pattern, room string) (val string, ok bool) {
	i := strings.IndexByte(pattern, ':')
	if i < 0 {
		return "", pattern == room
	}
	j := i + 1
	for j < len(pattern) && (pattern[j] == '_' ||
		(pattern[j] >= 'a' && pattern[j] <= 'z') ||
		(pattern[j] >= 'A' && pattern[j] <= 'Z') ||
		(pattern[j] >= '0' && pattern[j] <= '9')) {
		j++
	}
	prefix, suffix := pattern[:i], pattern[j:]
	if len(room) <= len(prefix)+len(suffix) ||
		!strings.HasPrefix(room, prefix) || !strings.HasSuffix(room, suffix) {
		return "", false
	}
	return room[len(prefix) : len(room)-len(suffix)], true
}

// memberOfAutoJoin inserts the creator's founding membership row after
// a parent-table create (see handleCreate). Best-effort population of
// common membership-table shapes: the join + user columns always, plus
// the app's group key and a user_id column when present - covering the
// `room_members(room_id, member_id, company_id)` shapes multi-tenant
// apps actually declare. Membership tables with additional NOT NULL
// columns lacking defaults will error; the caller logs + surfaces it.
func memberOfAutoJoin(app *App, rule *memberOfRule, rowID any, session *Session) error {
	cols := []string{rule.JoinCol, rule.UserCol}
	vals := []any{rowID, rule.userValue(session)}
	if app.Group != nil && app.Group.Key != "" && hasColumn(app, rule.Table, app.Group.Key) && session.EffectiveHasGroup() {
		cols = append(cols, app.Group.Key)
		vals = append(vals, session.EffectiveGroupID())
	}
	if rule.UserCol != "user_id" && hasColumn(app, rule.Table, "user_id") {
		cols = append(cols, "user_id")
		vals = append(vals, session.UserID)
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?, ", len(cols)), ", ")
	_, err := app.DB.Exec(fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s) ON CONFLICT DO NOTHING",
		rule.Table, strings.Join(cols, ", "), placeholders), vals...)
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
	path := filepath.Join(dir, "app.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	// We parse loosely so the per-table value can be EITHER a string
	// ("admin") OR a map ({read: x, write: y}). yaml.Node lets us
	// inspect the shape before unmarshaling into the right Go type.
	var raw struct {
		Access yaml.Node `yaml:"access"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil
	}
	if raw.Access.Kind == 0 || raw.Access.Kind != yaml.MappingNode {
		return nil
	}
	rules := make(map[string]map[AccessOp]string)
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
	if len(rules) == 0 {
		return nil
	}
	return &AccessConfig{rules: rules}
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
// don't leak existence of resources the caller can't reach.
func EnforceCRUDAccess(w http.ResponseWriter, r *http.Request, app *App, table string, op AccessOp, targetUserID int64) bool {
	if app == nil {
		http.NotFound(w, r)
		return false
	}
	hasUID := hasColumn(app, table, "user_id")
	hasGroupKey := app.Group != nil && app.Group.Key != "" && hasColumn(app, table, app.Group.Key)
	mode := app.Access.ModeFor(table, op, hasUID, hasGroupKey)
	if mode == "off" {
		http.NotFound(w, r)
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
			body := `{"error":"authentication required"}`
			if op == OpRead && hasUID && !app.Access.HasExplicitRule(table, op) {
				body = `{"error":"authentication required","hint":"This table is owner-scoped (visitors see 401). For a public feed, declare ` + "`access:\\n  " + table + ":\\n    read: anon`" + ` in app.yaml. Run benmore docs for the full access-mode catalogue."}`
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(body))
			return false
		}
	}
	if !app.Access.Allowed(mode, session, targetUserID) {
		// Group-mode LIST for a caller with no resolved group is an empty
		// filtered view, not a missing resource. The endpoint exists, the
		// collection exists, the caller just has no rows in scope yet -
		// REST-correct response is 200 []. Returning 404 here breaks
		// onboarding boots that legitimately list before a group is
		// established (the SPA can't decide where to route the user if
		// list endpoints throw). handleList's per-row WHERE builder
		// already handles "no group" by falling back to user_id scoping
		// (or returning nothing on tables without user_id), so passing
		// the gate is safe - the empty result emerges naturally.
		//
		// Single-row reads (targetUserID != 0) and writes still fail
		// here: those would either leak existence of rows the caller
		// can't reach or accept orphan rows.
		if op == OpRead && mode == "group" && targetUserID == 0 && session != nil && !session.EffectiveHasGroup() && !session.IsAdminBypass() {
			return true
		}
		http.NotFound(w, r)
		return false
	}
	return true
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
//   - group-scoped table + EFFECTIVE group → `(group_key = ? OR <acl>)`.
//   - else owner-scoped (user_id)           → `(user_id = ? OR <acl>)`.
//   - table has neither + not bypass        → ("", nil, false): no columns to
//     scope by (unscoped table - same as the historical inline behavior).
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
	// member-of mode REPLACES owner/group scoping for the governed op:
	// the whole point is that members see each other's rows. The tenant
	// clause is still AND'd inside memberOfPredicate when the table is
	// group-keyed, so membership never crosses tenants.
	if rule := memberOfFor(app, table, opForACLAction(aclAction)); rule != nil {
		pred, args := memberOfPredicate(app, table, rule, session, aclAction)
		return pred, args, false
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
	if roles, ok := ownerOrRoleFor(app, table, opForACLAction(aclAction)); ok {
		aclSQL, aclArgs := aclFilter(table, session.Email, aclAction)
		var parts []string
		var sargs []any
		if hasColumn(app, table, "user_id") {
			parts = append(parts, "user_id = ?")
			sargs = append(sargs, session.UserID)
		}
		if HasAnyRole(session, roles) {
			tableIsGrouped := app.Group != nil && app.Group.Key != "" && hasColumn(app, table, app.Group.Key)
			switch {
			case tableIsGrouped && session.EffectiveHasGroup():
				// Role-holder sees their whole tenant.
				parts = append(parts, app.Group.Key+" = ?")
				sargs = append(sargs, session.EffectiveGroupID())
			case tableIsGrouped:
				// Group-keyed table but the session has NO effective group:
				// the role tier contributes NOTHING. Emitting `1=1` here would
				// expose EVERY tenant's rows to a group-less role-holder - a
				// cross-tenant leak. Fall back to owner-only (the user_id tier).
			default:
				// Genuinely un-grouped table: a role-holder sees every row.
				parts = append(parts, "1=1")
			}
		}
		parts = append(parts, aclSQL)
		sargs = append(sargs, aclArgs...)
		return "(" + strings.Join(parts, " OR ") + ")", sargs, false
	}
	if app.Group != nil && app.Group.Key != "" && session.EffectiveHasGroup() && hasColumn(app, table, app.Group.Key) {
		aclSQL, aclArgs := aclFilter(table, session.Email, aclAction)
		return fmt.Sprintf("(%s = ? OR %s)", app.Group.Key, aclSQL),
			append([]any{session.EffectiveGroupID()}, aclArgs...), false
	}
	if hasColumn(app, table, "user_id") {
		aclSQL, aclArgs := aclFilter(table, session.Email, aclAction)
		return fmt.Sprintf("(user_id = ? OR %s)", aclSQL),
			append([]any{session.UserID}, aclArgs...), false
	}
	return "", nil, false
}

// canAccessRowScoped reports whether the session may access row id of table
// under rowScopeClause for aclAction. The canonical single-row predicate used
// by every "can this caller touch this specific row" check.
func canAccessRowScoped(app *App, table, id string, session *Session, aclAction string) bool {
	pred, args, bypass := rowScopeClause(app, table, session, aclAction)
	if bypass {
		// Admin (not stepped in): the row is reachable if it exists (+ not soft-deleted).
		q := fmt.Sprintf("SELECT 1 FROM %s WHERE id = ?", table)
		if hasColumn(app, table, "deleted_at") {
			q += " AND deleted_at IS NULL"
		}
		var x int
		return app.DB.QueryRow(q, id).Scan(&x) == nil
	}
	q := fmt.Sprintf("SELECT 1 FROM %s WHERE id = ?", table)
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
