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
// Modes: anon · everyone · self · group · admin · role:<name> · off
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
	// Unknown mode → fail closed.
	return false
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
//   access:
//     posts:                 # per-op map
//       read: public
//       write: self
//     messages:              # shorthand: same mode for all ops
//       all: everyone
//     comments: admin        # tightest shorthand - string-as-mode → all
//     default:               # global per-op fallback
//       read: admin
//       write: admin
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
