//go:build !cli

package main

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/mattn/go-sqlite3"
)

type appMCPPrivateKey struct{}
type appMCPPrivateRead struct {
	app                                                                    *App
	origin                                                                 *App
	generation                                                             *appMCPRuntimeGeneration
	columns                                                                []Column
	authority                                                              *Session
	grantID, credentialHash, resource, tool, table, operation, path, query string
}

// Only trusted in-process dispatch creates this value. Public headers, cookies
// and supplied identity fields never create connector authority.
func newAppMCPNativeRequest(app *App, source *http.Request, raw, resource, toolName string) (*http.Request, *App, error) {
	generation := snapshotAppMCPGeneration(app)
	if generation == nil {
		return nil, nil, errAppMCPGrantDenied
	}
	policy := generation.view
	tool := appMCPReadTool(policy, toolName)
	if tool == nil {
		return nil, nil, errAppMCPGrantDenied
	}
	columns, err := appMCPReadColumns(source.Context(), policy, tool.Handler.Table)
	if err != nil {
		return nil, nil, err
	}
	request, err := newAppMCPNativeRequestWithGeneration(app, policy, generation, source, raw, resource, toolName, columns)
	return request, policy, err
}

func newAppMCPNativeRequestWithColumns(app *App, source *http.Request, raw, resource, toolName string, columns []Column) (*http.Request, *App, error) {
	generation := snapshotAppMCPGeneration(app)
	if generation == nil {
		return nil, nil, errAppMCPGrantDenied
	}
	request, err := newAppMCPNativeRequestWithGeneration(app, generation.view, generation, source, raw, resource, toolName, columns)
	return request, generation.view, err
}

func newAppMCPNativeRequestWithGeneration(origin, app *App, generation *appMCPRuntimeGeneration, source *http.Request, raw, resource, toolName string, columns []Column) (*http.Request, error) {
	if len(columns) == 0 {
		return nil, errAppMCPGrantDenied
	}

	grant, actor, err := resolveAppMCPAccessForGeneration(source.Context(), origin, generation, raw, resource, time.Now())
	if err != nil {
		return nil, errAppMCPGrantDenied
	}
	tool := appMCPReadTool(app, toolName)
	if tool == nil || tool.Handler.Operation == "flow.call" || source.Method != http.MethodGet || source.URL.Query().Get("include") != "" || !appMCPReadPath(tool, source.URL.Path) || !scopesWithin(actor.Scopes, strings.Join(tool.Permissions, " ")) {
		return nil, errAppMCPGrantDenied
	}
	hash, err := appMCPCredentialHash(raw, "access")
	if err != nil {
		return nil, err
	}
	identity := &appMCPPrivateRead{app: app, origin: origin, generation: generation, columns: append([]Column(nil), columns...), authority: actor, grantID: grant.ID, credentialHash: hash, resource: resource, tool: toolName, table: tool.Handler.Table, operation: tool.Handler.Operation, path: source.URL.Path, query: source.URL.RawQuery}
	request := source.Clone(context.WithValue(source.Context(), appMCPPrivateKey{}, identity))
	request.Header = make(http.Header)
	request.Body, request.GetBody, request.ContentLength = nil, nil, 0
	return request, nil
}

func appMCPManifestSnapshot(app *App) *AppMCPManifest {
	if app == nil {
		return nil
	}
	app.mu.RLock()
	defer app.mu.RUnlock()
	return app.MCP
}
func appMCPReadTool(app *App, name string) *AppMCPTool {
	manifest := appMCPManifestSnapshot(app)
	if manifest == nil {
		return nil
	}
	for i := range manifest.Tools {
		tool := &manifest.Tools[i]
		if tool.Name == name && tool.Handler.Kind == "native" && tool.Effect == "read" && (tool.Handler.Operation == "table.list" || tool.Handler.Operation == "table.read" || tool.Handler.Operation == "flow.call") {
			return tool
		}
	}
	return nil
}
func appMCPReadPath(tool *AppMCPTool, path string) bool {
	base := "/api/" + tool.Handler.Table
	if tool.Handler.Operation == "table.list" {
		return path == base
	}
	return strings.HasPrefix(path, base+"/") && len(path) > len(base)+1 && !strings.Contains(strings.TrimPrefix(path, base+"/"), "/")
}

// Re-resolve the original credential/grant at each canonical authorization
// boundary. Returning present=true on failure prevents ambient-auth fallback.
func appMCPPrivateSession(app *App, r *http.Request) (*Session, bool) {
	if actor, private := appMCPFlowPrivateSession(app, r); private {
		return actor, true
	}
	identity, present := r.Context().Value(appMCPPrivateKey{}).(*appMCPPrivateRead)
	if !present {
		return nil, false
	}
	if identity == nil || identity.app != app || !appMCPGenerationCurrent(identity.origin, identity.generation) || r.Method != http.MethodGet || r.URL.Path != identity.path || r.URL.RawQuery != identity.query {
		return nil, true
	}
	tool := appMCPReadTool(app, identity.tool)
	if tool == nil || tool.Handler.Table != identity.table || tool.Handler.Operation != identity.operation || !appMCPReadPath(tool, r.URL.Path) {
		return nil, true
	}
	now := time.Now()
	grant, err := readAppMCPAccessGrant(r.Context(), identity.origin, identity.credentialHash, identity.resource, now)
	if err != nil || grant.ID != identity.grantID {
		return nil, true
	}
	actor, err := appMCPGrantActorForGeneration(r.Context(), identity.origin, identity.generation, grant, now)
	if err != nil || !appMCPAuthorityUnchanged(identity.authority, actor) || !scopesWithin(actor.Scopes, strings.Join(tool.Permissions, " ")) {
		return nil, true
	}
	return actor, true
}

func appMCPReadOperationAllowed(w http.ResponseWriter, r *http.Request, operation string) bool {
	identity, private := r.Context().Value(appMCPPrivateKey{}).(*appMCPPrivateRead)
	if private && (identity == nil || identity.operation != operation) {
		httpJSON(w, http.StatusForbidden, map[string]any{"error": "connector operation denied"})
		return false
	}
	return true
}

func appMCPReadSessionAvailable(w http.ResponseWriter, r *http.Request, actor *Session) bool {
	if _, private := r.Context().Value(appMCPPrivateKey{}).(*appMCPPrivateRead); private && actor == nil {
		httpJSON(w, http.StatusForbidden, map[string]any{"error": "connector grant denied"})
		return false
	}
	return true
}

// A read must not release rows masked or admitted under authority that changed
// between its canonical gates and result release. Role ordering is immaterial.
func appMCPAuthorityUnchanged(before, after *Session) bool {
	if before == nil || after == nil {
		return false
	}
	left, right := *before, *after
	left.Roles = append([]string(nil), before.Roles...)
	right.Roles = append([]string(nil), after.Roles...)
	left.Permissions = append([]string(nil), before.Permissions...)
	right.Permissions = append([]string(nil), after.Permissions...)
	sort.Strings(left.Roles)
	sort.Strings(right.Roles)
	sort.Strings(left.Permissions)
	sort.Strings(right.Permissions)
	return reflect.DeepEqual(left, right)
}

// Canonical CRUD keeps its SQL and authorization gates. Pin only the actual
// private data query, releasing it before metadata and authority use the pool.
func appMCPReadRows(app *App, r *http.Request, table, query string, args ...any) ([]map[string]any, error) {
	identity, private := r.Context().Value(appMCPPrivateKey{}).(*appMCPPrivateRead)
	if !private {
		// Bound to the request: a disconnecting client cancels its list
		// query, and the default statement deadline applies.
		return queryNativeRowsContext(r.Context(), app.DB, app, table, query, args...)
	}
	if identity == nil || identity.app != app {
		return nil, errAppMCPGrantDenied
	}
	rows, _, truncated, err := queryReadOnlyRowsColsDecrypt(r.Context(), app.DB, query, readOnlyQueryMaxRows, nativeRowDecryptor(app, table), args...)
	if err != nil {
		return nil, err
	}
	if truncated {
		return nil, fmt.Errorf("private read exceeds row limit")
	}
	return rows, nil
}

func appMCPReadCount(app *App, r *http.Request, query string, args []any, target any) error {
	identity, private := r.Context().Value(appMCPPrivateKey{}).(*appMCPPrivateRead)
	if !private {
		// The ?page= / ?count= COUNT(*) walks every matching row; give it
		// the same request binding and deadline as the row query.
		ctx, cancel := withQueryDeadline(r.Context())
		defer cancel()
		return app.DB.QueryRowContext(ctx, query, args...).Scan(target)
	}
	if identity == nil || identity.app != app {
		return errAppMCPGrantDenied
	}
	ctx, cancel := context.WithTimeout(r.Context(), readOnlyQueryTimeout)
	defer cancel()
	conn, _, closeConn, err := openReadOnlyQueryConn(ctx, app.DB)
	if err != nil {
		return err
	}
	defer closeConn()
	return conn.QueryRowContext(ctx, query, args...).Scan(target)
}

// Only framework-owned schema introspection may authorize table_info. The
// user-SQL authorizer remains unchanged, including credential masking.
func authorizeAppMCPMetadata(action int, arg1, arg2, database string) int {
	if action == sqlite3.SQLITE_PRAGMA && strings.EqualFold(arg1, "table_info") && isValidColumnName(arg2) {
		return sqlite3.SQLITE_OK
	}
	return authorizeReadOnlyQuery(action, arg1, arg2, database)
}

func appMCPReadColumns(ctx context.Context, app *App, table string) ([]Column, error) {
	ctx, cancel := context.WithTimeout(ctx, readOnlyQueryTimeout)
	defer cancel()
	conn, _, closeConn, err := openReadOnlyQueryConn(ctx, app.DB)
	if err != nil {
		return nil, err
	}
	defer closeConn()
	if err := conn.Raw(func(raw any) error { raw.(*sqlite3.SQLiteConn).RegisterAuthorizer(authorizeAppMCPMetadata); return nil }); err != nil {
		return nil, err
	}
	return tableColumnsQuery(func(query string, args ...any) (*sql.Rows, error) { return conn.QueryContext(ctx, query, args...) }, table)
}

func crudTableColumns(r *http.Request, app *App, table string) ([]Column, error) {
	identity, private := r.Context().Value(appMCPPrivateKey{}).(*appMCPPrivateRead)
	if !private {
		return cachedTableColumns(app.DB, table)
	}
	if identity == nil || identity.app != app || identity.table != table || identity.columns == nil {
		return nil, errAppMCPGrantDenied
	}
	return identity.columns, nil
}
