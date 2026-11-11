//go:build !cli

package main

// Who sees what in the generated API docs (/api/_docs, /docs, /docs?format=md,
// /api/_openapi + aliases).
//
// The docs switch to public as soon as ONE table is anon/everyone-readable
// (RegisterAPIDocsRoutes), and used to then describe every table, column and
// route in the app - so a single public `posts` table published the payroll
// schema next to it. The docs now describe, per caller:
//
//   - an admin on an unscoped credential (IsAdminConsole; or the developer
//     contract, e.g. `benmore verify`): every table, route and page. A scoped
//     API token an admin minted gets the view its scopes allow;
//   - everyone else: only tables whose READ gate they pass (access mode +
//     RBAC scope, SessionCanAccessTable), only the routes whose own access
//     gate they pass, and only pages they could open.

import "strings"

type docsViewer struct {
	full    bool
	session *Session
}

// fullDocs is the unfiltered developer contract.
var fullDocs = docsViewer{full: true}

func docsViewerFor(session *Session) docsViewer {
	return docsViewer{full: session.IsAdminConsole(), session: session}
}

func (v docsViewer) showsTable(app *App, table string) bool {
	if v.full {
		// A table whose every operation is `off` has no API to describe.
		for _, op := range []AccessOp{OpRead, OpWrite, OpUpdate, OpDelete} {
			if !accessOpOff(app.Access, table, op) {
				return true
			}
		}
		return false
	}
	return SessionCanAccessTable(app, table, OpRead, v.session)
}

// allowsOp: an `off` operation answers 404 to every caller, admins included
// (EnforceCRUDAccess), so even the full developer contract leaves it out.
func (v docsViewer) allowsOp(app *App, table string, op AccessOp) bool {
	if accessOpOff(app.Access, table, op) {
		return false
	}
	return v.full || SessionCanAccessTable(app, table, op, v.session)
}

// accessOpOff reports whether app.yaml declares op `off` for table. Only a
// declaration can be `off`; the implicit column-inferred default never is.
func accessOpOff(access *AccessConfig, table string, op AccessOp) bool {
	mode, ok := access.DeclaredModeFor(table, op)
	return ok && mode == "off"
}

// crudRouteAccessOff reports whether the auto-CRUD route method+path on table
// needs an access op app.yaml turns `off` (restore needs read and update).
// Such a route is registered but unreachable.
func crudRouteAccessOff(access *AccessConfig, table, method, path string) bool {
	ops := []AccessOp{docsRouteOp(method)}
	if method == "POST" && strings.HasSuffix(path, "/restore") {
		ops = []AccessOp{OpRead, OpUpdate}
	}
	for _, op := range ops {
		if accessOpOff(access, table, op) {
			return true
		}
	}
	return false
}

// docsRouteOp maps a documented CRUD route onto the access op that gates it.
func docsRouteOp(method string) AccessOp {
	switch method {
	case "POST":
		return OpWrite
	case "PATCH":
		return OpUpdate
	case "DELETE":
		return OpDelete
	default:
		return OpRead
	}
}

// routes returns the documented CRUD routes of table this viewer may call.
func (v docsViewer) routes(app *App, table string) []docsRoute {
	var out []docsRoute
	for _, rt := range docsCRUDRoutes(table) {
		if v.allowsOp(app, table, docsRouteOp(rt.method)) {
			out = append(out, rt)
		}
	}
	if hasColumn(app, table, "deleted_at") && !restoreRouteOwnedByFlow(app, table) && v.allowsOp(app, table, OpRead) && v.allowsOp(app, table, OpUpdate) {
		out = append(out, docsRoute{"POST", "/api/" + table + "/{id}/restore", "Restore a soft-deleted record; returns the readable row (read and update required)"})
	}
	return out
}

// pruneOpenAPIPaths drops the operations of table's OpenAPI paths that this
// viewer's access gate refuses, and a path left with no operations.
func (v docsViewer) pruneOpenAPIPaths(app *App, table string, paths map[string]any) {
	if !v.allowsOp(app, table, OpRead) || !v.allowsOp(app, table, OpUpdate) {
		delete(paths, "/api/"+table+"/{id}/restore")
	}
	for _, p := range []string{"/api/" + table, "/api/" + table + "/{id}"} {
		ops, _ := paths[p].(map[string]any)
		for method := range ops {
			if !v.allowsOp(app, table, docsRouteOp(strings.ToUpper(method))) {
				delete(ops, method)
			}
		}
		if len(ops) == 0 {
			delete(paths, p)
		}
	}
}

// showsPage mirrors the page gates servePage applies: role= (any-of),
// auth="required" and require= need a signed-in caller.
func (v docsViewer) showsPage(p *Page) bool {
	if v.full {
		return true
	}
	if role := pageRole(p); role != "" && role != "public" {
		return v.session != nil && HasAnyRole(v.session, splitCommaList(role))
	}
	if p.Auth == "required" || p.Require != "" {
		return v.session != nil
	}
	return true
}
