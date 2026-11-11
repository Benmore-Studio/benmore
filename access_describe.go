//go:build !cli

package main

import (
	"fmt"
	"sort"
	"strings"
)

// Effective access, described. describe(kind=table) and api(at:"<table>")
// used to infer access from column names alone ("user_id means owner
// scoping"), which is wrong for most declared modes: a member-of table that
// also carries user_id is membership-scoped, and a user_id + tenant-key table
// on the implicit default is tenant-wide, so a teammate reads the owner's row.
// These helpers read the same resolution the runtime enforces (ModeFor,
// memberOfFor's parse, ownerOrRoleFor's role list, explicitSelfFor, the
// tenant branch) and follow rowScopeClause's branch order. A change to
// rowScopeClause's branches needs the matching change in accessRowScope.

// describedAccessOps is the order describe reports ops in.
var describedAccessOps = []AccessOp{OpRead, OpWrite, OpUpdate, OpDelete}

// accessRowScopeInfo is what one op's mode means for the rows a signed-in
// caller who is not an admin reaches (admins not stepped into a tenant bypass
// row scope entirely).
type accessRowScopeInfo struct {
	// Rows is one of: none, admin_only, all, member_of, owner_or_role,
	// owner, tenant, tenant_root.
	Rows string
	// Tenant reports that the caller's own tenant (groups.key) bounds the
	// rows, on top of Rows.
	Tenant bool
	Effect string
	// Hint is advice for a shape that likely does not do what it reads as
	// (a role: or perm: mode on an owner-scoped table).
	Hint string
}

// describeTableAccess reports, per CRUD op, the access mode governing table,
// where it was declared (table, default, implicit) and, for read, update and
// delete, which rows a signed-in non-admin caller reaches.
func describeTableAccess(app *App, table string) map[string]map[string]any {
	out := make(map[string]map[string]any, len(describedAccessOps))
	if app == nil {
		return out
	}
	access := app.Access
	hasUID := hasColumn(app, table, "user_id")
	hasGroupKey := app.Group != nil && app.Group.Key != "" && hasColumn(app, table, app.Group.Key)
	for _, op := range describedAccessOps {
		mode := access.ModeFor(table, op, hasUID, hasGroupKey)
		entry := map[string]any{"mode": mode, "declared_by": accessModeSource(access, table, op)}
		if op == OpWrite {
			entry["effect"] = accessCreateEffect(app, table, mode)
		} else {
			info := accessRowScope(app, table, op, mode)
			entry["rows"] = info.Rows
			if info.Tenant {
				entry["tenant_bound"] = true
			}
			entry["effect"] = info.Effect
			if info.Hint != "" {
				entry["hint"] = info.Hint
			}
		}
		out[string(op)] = entry
	}
	return out
}

// accessModeSource names where the mode for (table, op) comes from.
func accessModeSource(access *AccessConfig, table string, op AccessOp) string {
	if _, ok := access.TableDeclaredModeFor(table, op); ok {
		return "table"
	}
	if _, ok := access.DeclaredModeFor(table, op); ok {
		return "default"
	}
	return "implicit"
}

// accessRowScope mirrors rowScopeClause (plus handleList's anon/everyone read
// widening) for a signed-in caller who is not an admin.
func accessRowScope(app *App, table string, op AccessOp, mode string) accessRowScopeInfo {
	grouped := app.Group != nil && app.Group.Key != "" && hasColumn(app, table, app.Group.Key)
	hasUID := hasColumn(app, table, "user_id")
	shares := " (plus rows shared with the caller through record-level grants)"
	inTenant := ""
	if grouped {
		inTenant = fmt.Sprintf(", only inside the caller's own tenant (%s)", app.Group.Key)
	}
	switch {
	case mode == "off":
		return accessRowScopeInfo{Rows: "none", Effect: "this operation is off: the route answers 404 for every caller, admins included"}
	case mode == "admin":
		return accessRowScopeInfo{Rows: "admin_only", Effect: "only global admins pass; other callers are refused"}
	case op == OpRead && (mode == "anon" || mode == "everyone"):
		who := "every signed-in user"
		if mode == "anon" {
			who = "anyone, signed in or not,"
		}
		return accessRowScopeInfo{Rows: "all", Effect: who + " reads every row; no owner or tenant filter applies"}
	case (mode == "self" || mode == "group") && !tableHasScopeColumn(app, table):
		return accessRowScopeInfo{Rows: "none", Effect: fmt.Sprintf("`%s` needs a user_id or tenant-key column to scope by and this table has neither, so every caller but an admin is refused", mode)}
	}
	if strings.HasPrefix(mode, "member-of:") {
		rule := parseMemberOf(mode)
		if rule == nil || memberOfMisdeclared(app, table, mode) {
			return accessRowScopeInfo{Rows: "none", Effect: "the member-of rule is malformed or does not fit this table, so every caller but an admin is refused"}
		}
		local, _ := rule.joinTarget(app, table)
		return accessRowScopeInfo{Rows: "member_of", Tenant: grouped, Effect: fmt.Sprintf(
			"rows whose %s has a %s row (%s = it, %s = the caller)%s%s; user_id ownership plays no part",
			local, rule.Table, rule.JoinCol, rule.UserCol, shares, inTenant)}
	}
	if strings.HasPrefix(mode, "owner_or_role:") {
		roles := splitCommaList(strings.TrimPrefix(mode, "owner_or_role:"))
		if len(roles) == 0 {
			return accessRowScopeInfo{Rows: "none", Effect: "owner_or_role: names no roles, so every caller but an admin is refused"}
		}
		var tiers []string
		if hasUID {
			tiers = append(tiers, "rows the caller owns (user_id)")
		}
		if grouped {
			tiers = append(tiers, fmt.Sprintf("every row of the caller's tenant for holders of %s", strings.Join(roles, "/")))
		} else {
			tiers = append(tiers, fmt.Sprintf("every row for holders of a global %s grant", strings.Join(roles, "/")))
		}
		return accessRowScopeInfo{Rows: "owner_or_role", Tenant: grouped, Effect: strings.Join(tiers, ", ") + shares + inTenant}
	}
	if explicitSelfFor(app, table, op) {
		return accessRowScopeInfo{Rows: "owner", Tenant: grouped, Effect: "rows where user_id is the caller" + shares + inTenant}
	}
	if grouped {
		fallback := "only rows shared with them"
		if hasUID {
			fallback = "only rows they own (user_id)" + shares
		}
		effect := fmt.Sprintf("every row of the caller's tenant (%s), whoever owns it; a caller with no tenant reaches %s", app.Group.Key, fallback)
		if hasUID && mode == "self" {
			effect += ". The implicit default is tenant-wide on a table with the tenant key; declare `self` in access: for owner-only rows"
		}
		return accessRowScopeInfo{Rows: "tenant", Tenant: true, Effect: effect}
	}
	if _, gated := gateRoles(app, mode); gated && tenantRootTable(app, table) {
		return accessRowScopeInfo{Rows: "tenant_root", Effect: "a tenant role reaches only the caller's own tenant row; a global grant reaches every row"}
	}
	if hasUID {
		info := accessRowScopeInfo{Rows: "owner", Effect: "rows where user_id is the caller" + shares}
		// role:/perm: decide who may call; rowScopeClause still falls
		// through to the owner filter here, which reads like role-wide
		// access but is not (owner_or_role: is).
		if ownerScopedRoleMode(mode, app.Roles) {
			info.Effect = fmt.Sprintf("rows where user_id is the caller%s: `%s` only decides who may call", shares, mode)
			info.Hint = roleModeOwnerRowsHint(mode, app.Roles)
		}
		return info
	}
	return accessRowScopeInfo{Rows: "all", Effect: "no owner or tenant column, so a caller who passes the mode reaches every row"}
}

// accessCreateEffect describes what a create (the `write` op) checks beyond
// the mode gate.
func accessCreateEffect(app *App, table, mode string) string {
	switch {
	case mode == "off":
		return "creating rows is off: the route answers 404 for every caller, admins included"
	case mode == "admin":
		return "only global admins may create rows"
	case strings.HasPrefix(mode, "member-of:"):
		rule := parseMemberOf(mode)
		if rule == nil || memberOfMisdeclared(app, table, mode) {
			return "the member-of rule is malformed or does not fit this table, so every caller but an admin is refused"
		}
		if memberOfAutoJoins(app, table, rule) {
			return fmt.Sprintf("any signed-in user may create a row; the creator is added to %s for it", rule.Table)
		}
		return fmt.Sprintf("the caller must be a member (%s) of the %s they write into", rule.Table, rule.JoinCol)
	}
	return fmt.Sprintf("callers who pass `%s` may create rows", mode)
}

// describeTableAccessBehaviors turns describeTableAccess into the behavior entries
// describe(kind=table) lists, one per row-scoping kind that applies to some op.
func describeTableAccessBehaviors(app *App, table string, access map[string]map[string]any) []map[string]any {
	opsWith := func(match func(entry map[string]any) bool) []string {
		var ops []string
		for _, op := range []AccessOp{OpRead, OpUpdate, OpDelete} {
			if entry := access[string(op)]; entry != nil && match(entry) {
				ops = append(ops, string(op))
			}
		}
		return ops
	}
	rowsIs := func(kind string) func(map[string]any) bool {
		return func(e map[string]any) bool { return e["rows"] == kind }
	}
	var out []map[string]any
	if ops := opsWith(rowsIs("owner")); len(ops) > 0 {
		out = append(out, map[string]any{
			"feature":     "owner_scoping",
			"trigger_col": "user_id",
			"ops":         ops,
			"effect":      fmt.Sprintf("%s reach only rows where user_id == the caller (plus record-level shares); admins bypass. See access for each op.", strings.Join(ops, "/")),
		})
	}
	if ops := opsWith(rowsIs("member_of")); len(ops) > 0 {
		out = append(out, map[string]any{
			"feature": "membership_scoping",
			"ops":     ops,
			"effect":  fmt.Sprintf("%s: %s", strings.Join(ops, "/"), access[ops[0]]["effect"]),
		})
	}
	if ops := opsWith(rowsIs("owner_or_role")); len(ops) > 0 {
		out = append(out, map[string]any{
			"feature": "owner_or_role_scoping",
			"ops":     ops,
			"effect":  fmt.Sprintf("%s: %s", strings.Join(ops, "/"), access[ops[0]]["effect"]),
		})
	}
	if ops := opsWith(func(e map[string]any) bool { return e["tenant_bound"] == true }); len(ops) > 0 && app.Group != nil {
		out = append(out, map[string]any{
			"feature":     "org_scoping",
			"trigger_col": app.Group.Key,
			"ops":         ops,
			"effect":      fmt.Sprintf("%s stay inside the caller's tenant (%s from the session group).", strings.Join(ops, "/"), app.Group.Key),
		})
	}
	if read := access[string(OpRead)]; read != nil && read["rows"] == "all" && (read["mode"] == "anon" || read["mode"] == "everyone") {
		out = append(out, map[string]any{
			"feature": "broad_read",
			"effect":  fmt.Sprintf("read is `%v`: %v", read["mode"], read["effect"]),
		})
	}
	if hasColumn(app, table, "user_id") {
		out = append(out, map[string]any{
			"feature":     "owner_column",
			"trigger_col": "user_id",
			"effect":      "POST sets user_id from the session; a client-sent user_id is not accepted. Whether it limits reads depends on access (see owner_scoping).",
		})
	}
	return out
}

// describeTableColumnBehaviors lists encrypted and hidden columns of table.
func describeTableColumnBehaviors(app *App, table string, cols []Column) []map[string]any {
	var out []map[string]any
	if app != nil && app.Encrypted != nil {
		var enc []map[string]any
		for _, def := range app.Encrypted.Fields[table] {
			entry := map[string]any{"column": def.Column, "blind_index": def.BlindIndex}
			if len(def.Roles) > 0 {
				entry["unmask_roles"] = def.Roles
			} else {
				entry["unmask_roles"] = "every reader"
			}
			enc = append(enc, entry)
		}
		if len(enc) > 0 {
			out = append(out, map[string]any{
				"feature": "field_encryption",
				"columns": enc,
				"effect":  "stored AES-GCM encrypted; readers outside unmask_roles get a masked value. Auto-CRUD filters accept only equality (or __in) on a blind_index column, and only from callers who would see it unmasked (403 otherwise); any other operator, sorting, or equality on a column without a blind index answers 400.",
			})
		}
	}
	var hidden []string
	for _, c := range cols {
		if apiHiddenColumn(app, table, c.Name) {
			hidden = append(hidden, c.Name)
		}
	}
	if len(hidden) > 0 {
		sort.Strings(hidden)
		out = append(out, map[string]any{
			"feature": "hidden_columns",
			"columns": hidden,
			"effect":  "never returned by auto-CRUD reads, includes, create read-back or /api/_query, and recorded as [hidden] in audit values; filtering or sorting on them answers 400; a version revert keeps their current value. Select them by name in a flow.",
		})
	}
	return out
}
