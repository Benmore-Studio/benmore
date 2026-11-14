//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"html"
	"math"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// RegisterAPIDocsRoutes adds auto-generated API documentation endpoints.
// Respects features.docs visibility: "public" (default) or "auth" (requires login).
func RegisterAPIDocsRoutes(mux appRouteRegistrar, app *App) {
	requireAuth := app.Design != nil && app.Design.Features != nil && app.Design.Features.DocsRequireAuth()
	// Align the docs default with the data default. Since v2.7.11 table DATA
	// is private-by-default; the docs (full schema: tables/columns/types +
	// page routes) were still public-by-default, so an anon could map the
	// entire data model of a fully-private app. If the app exposes NO
	// anon/everyone-readable table, treat it as private and gate the docs
	// too - unless the developer explicitly opted into public docs.
	if !requireAuth && !docsExplicitlyPublic(app) && !appHasAnonReadableTable(app) {
		requireAuth = true
	}

	// JSON: legacy Benmore docs shape ({endpoints,pages,features}).
	// Every docs surface is filtered to what THIS caller may read
	// (apidocs_audience.go), so the response varies per caller.
	mux.HandleFunc("GET /api/_docs", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if requireAuth && session == nil {
			httpError(w, "authentication required", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "private, no-store")
		json.NewEncoder(w).Encode(generateAPIDocs(app, docsViewerFor(session)))
	})

	// JSON: real OpenAPI 3.1 contract for the app runtime CRUD surface.
	openAPIHandler := func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if requireAuth && session == nil {
			httpError(w, "authentication required", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "private, no-store")
		json.NewEncoder(w).Encode(generateRuntimeOpenAPIFor(app, docsViewerFor(session), registeredFlowOpenAPI(mux)))
	}
	for _, path := range []string{"/api/_openapi", "/openapi.json", "/api/openapi.json"} {
		mux.HandleFunc("GET "+path, openAPIHandler)
	}

	// Rich, per-user schema descriptor - the source the schema-driven
	// component layer renders from. ALWAYS auth-gated: the response
	// reflects THIS caller's allowed ops + which fields are masked for
	// them, so it can't be served anonymously.
	mux.HandleFunc("GET /api/_schema", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil {
			httpError(w, "authentication required", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(generateRichSchema(app, session))
	})

	// HTML: rendered docs page - skip if the app has its own /docs page
	if _, hasDocsPage := app.Pages["/docs"]; !hasDocsPage {
		mux.HandleFunc("GET /docs", func(w http.ResponseWriter, r *http.Request) {
			session := getSession(app, r)
			if requireAuth && session == nil {
				if r.URL.Query().Get("format") == "md" {
					http.Error(w, "authentication required", http.StatusUnauthorized)
					return
				}
				http.Redirect(w, r, app.Paths.Login, http.StatusSeeOther)
				return
			}
			viewer := docsViewerFor(session)
			w.Header().Set("Cache-Control", "private, no-store")
			// Machine/LLM-friendly markdown export from the same docs model -
			// backs the "Copy for LLM" buttons. No second source of truth.
			if r.URL.Query().Get("format") == "md" {
				w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
				fmt.Fprint(w, renderDocsMarkdownFor(app, viewer))
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, WrapLayout(renderDocsHTML(app, viewer), "API Documentation", app, nil))
		})
	}
}

// docsExplicitlyPublic reports whether the developer deliberately set
// `features.docs: public` - in which case we honor it and keep docs open
// even for an otherwise-private app.
func docsExplicitlyPublic(app *App) bool {
	return app.Design != nil && app.Design.Features != nil &&
		app.Design.Features.DocsVisibility == "public"
}

// appHasAnonReadableTable reports whether any table is readable without a
// session (access read mode anon or everyone). Used to decide whether the
// auto-generated docs should default to public or auth-gated.
func appHasAnonReadableTable(app *App) bool {
	for _, t := range app.Tables {
		if strings.HasPrefix(t.Name, "_benmore_") {
			continue
		}
		hasUID := hasColumn(app, t.Name, "user_id")
		hasGroupKey := app.Group != nil && app.Group.Key != "" && hasColumn(app, t.Name, app.Group.Key)
		mode := app.Access.ModeFor(t.Name, OpRead, hasUID, hasGroupKey)
		if mode == "anon" || mode == "everyone" {
			return true
		}
	}
	return false
}

func generateAPIDocs(app *App, viewer docsViewer) map[string]any {
	tables, _ := GetTableNames(app.DB)

	endpoints := make(map[string]any)
	for _, table := range tables {
		if strings.HasPrefix(table, "_benmore_") || !viewer.showsTable(app, table) {
			continue
		}
		cols, _ := GetTableColumns(app.DB, table)

		// Never expose sensitive columns in API docs
		fields := make([]map[string]string, 0)
		for _, col := range cols {
			if docsHiddenColumn(app, table, col.Name) {
				continue
			}
			field := map[string]string{
				"name": col.Name,
				"type": col.Type,
			}
			if col.PK {
				field["primary_key"] = "true"
			}
			if col.NotNull {
				field["required"] = "true"
			}
			if col.Default != "" {
				field["default"] = col.Default
			}
			fields = append(fields, field)
		}

		routes := make([]map[string]string, 0, 8)
		for _, rt := range viewer.routes(app, table) {
			routes = append(routes, map[string]string{"method": rt.method, "path": rt.path, "description": rt.desc})
		}
		tableInfo := map[string]any{
			"fields": fields,
			"routes": routes,
		}
		if app.IsUUIDTable(table) {
			tableInfo["id_format"] = "uuid"
		}
		endpoints[table] = tableInfo
	}

	// Pages
	pages := make([]map[string]string, 0)
	for route, page := range app.Pages {
		if !viewer.showsPage(app, page) {
			continue
		}
		p := map[string]string{"route": route, "file": page.File}
		if page.Auth != "" {
			p["auth"] = page.Auth
		}
		if page.Title != "" {
			p["title"] = page.Title
		}
		pages = append(pages, p)
	}

	return map[string]any{
		"endpoints": endpoints,
		"pages":     pages,
		"features": map[string]any{
			"auth":        "cookie + Bearer token",
			"scoping":     "owner (user_id) + org (configurable key)",
			"soft_delete": "auto if deleted_at column exists",
			"audit_trail": "GET /api/_audit",
			"pagination":  "?page=N&per_page=N or ?limit=N&offset=N (offset); ?cursor=X&limit=N (keyset)",
			"idempotency": "X-Idempotency-Key header on POST",
			"concurrency": "_expected_updated_at field for optimistic locking",
			"cache":       "<query cache=\"5m\"> for query result caching",
		},
	}
}

// generateRuntimeOpenAPI is the full developer contract (every table and
// operation) - `benmore verify` and tests. HTTP callers get
// generateRuntimeOpenAPIFor with their own docsViewer.
func generateRuntimeOpenAPI(app *App) map[string]any {
	if len(app.Flows) == 0 {
		return generateRuntimeOpenAPIFor(app, fullDocs)
	}
	tables := make([]string, 0, len(app.Tables))
	for _, table := range app.Tables {
		tables = append(tables, table.Name)
	}
	if app.DB != nil {
		var err error
		tables, err = GetTableNames(app.DB)
		if err != nil {
			return generateRuntimeOpenAPIFor(app, fullDocs)
		}
	}
	mux := buildAppRouteMux(app, false, "", false, tables)
	return generateRuntimeOpenAPIFor(app, fullDocs, mux.flows)
}

func generateRuntimeOpenAPIFor(app *App, viewer docsViewer, registered ...map[string]string) map[string]any {
	paths := map[string]any{}
	schemas := map[string]any{
		"Problem": map[string]any{
			"type":     "object",
			"required": []string{"error"},
			"properties": map[string]any{
				"error":   map[string]any{"type": "string"},
				"message": map[string]any{"type": "string"},
				"hint":    map[string]any{"type": "string"},
				"fields":  map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}},
			},
		},
	}

	// seenSchema guards against two distinct tables whose singularized,
	// PascalCased names collide (e.g. `note` and `notes`), which would
	// otherwise silently overwrite each other's schema keys and produce
	// duplicate operationIds. On collision we fall back to the raw table
	// name so each table keeps a distinct, stable contract entry.
	seenSchema := map[string]bool{}
	// Custom fields are read once for the whole document; nil (no table, or
	// a read error) lists none, as customFieldTableColumns does.
	var tracked map[string]map[string]bool
	if app != nil && app.DB != nil {
		tracked, _ = customFieldColumns(app.DB)
	}
	for _, table := range sortedTables(app) {
		// Belt-and-suspenders: sortedTables already strips every
		// _benmore_* table, so this guard is normally dead code. Keep it
		// so a future change to sortedTables can't leak an internal table
		// into the public contract.
		if strings.HasPrefix(table.Name, "_benmore_") || !viewer.showsTable(app, table.Name) {
			continue
		}
		schemaName := pascalCase(singularize(table.Name))
		if seenSchema[schemaName] {
			schemaName = pascalCase(table.Name)
		}
		seenSchema[schemaName] = true
		schemas[schemaName] = openAPISchemaForTable(app, table)
		custom := customFieldTableColumnsFrom(app, table, tracked)
		schemas["Create"+schemaName] = openAPIWriteSchemaForTable(app, table, requestCreate, custom)
		schemas["Update"+schemaName] = openAPIWriteSchemaForTable(app, table, requestUpdate, custom)
		paths["/api/"+table.Name] = map[string]any{
			"get": map[string]any{
				"operationId": "list" + schemaName,
				"tags":        []string{table.Name},
				"summary":     "List " + table.Name,
				// Parameters mirror the auto-CRUD list handler (crud_read.go):
				// offset paging is ?page=&per_page= or ?limit=&offset=; keyset
				// paging is ?cursor=&limit=, ?count
				// returns just the total, ?q is full-text, ?include expands
				// relations.
				"parameters": openAPIListParams(schemaName),
				"responses": openAPIResponses(map[string]any{
					// The runtime returns one of: a bare array (default),
					// {data,total,page,per_page} when ?page= is set,
					// {data,next_cursor,limit} when ?cursor= is set, or
					// {count} when ?count is set (crud_read.go list handler).
					"200": openAPIJSONResponse("Rows", openAPIListResponseSchema(schemaName)),
				}),
			},
			"post": map[string]any{
				"operationId": "create" + schemaName,
				"tags":        []string{table.Name},
				"summary":     "Create " + singularize(table.Name),
				"requestBody": openAPIJSONRequest(map[string]any{"$ref": "#/components/schemas/Create" + schemaName}),
				"responses": openAPIResponses(map[string]any{
					// Create echoes the inserted row plus a status envelope:
					// {id, status:"created", ...row} (crud_create.go handleCreate).
					"200": openAPIJSONResponse("Created row", openAPICreateResponseSchema(schemaName)),
				}),
			},
		}
		paths["/api/"+table.Name+"/{id}"] = map[string]any{
			"get": map[string]any{
				"operationId": "get" + schemaName,
				"tags":        []string{table.Name},
				"summary":     "Get " + singularize(table.Name),
				"parameters":  []map[string]any{openAPIIDParam()},
				"responses": openAPIResponses(map[string]any{
					"200": openAPIJSONResponse("Row", map[string]any{"$ref": "#/components/schemas/" + schemaName}),
				}),
			},
			"patch": map[string]any{
				"operationId": "update" + schemaName,
				"tags":        []string{table.Name},
				"summary":     "Update " + singularize(table.Name),
				"parameters":  []map[string]any{openAPIIDParam()},
				"requestBody": openAPIJSONRequest(map[string]any{"$ref": "#/components/schemas/Update" + schemaName}),
				"responses": openAPIResponses(map[string]any{
					// Update does NOT echo the row; it returns {status:"updated"}
					// only (crud_update.go handleUpdate). On an optimistic-concurrency
					// mismatch (_expected_updated_at in the body) it returns 409.
					"200": openAPIJSONResponse("Update status", openAPIWriteStatusSchema("updated")),
					"409": openAPIProblemResponse("Concurrency conflict"),
				}),
			},
			"delete": map[string]any{
				"operationId": "delete" + schemaName,
				"tags":        []string{table.Name},
				"summary":     "Delete " + singularize(table.Name),
				"parameters":  []map[string]any{openAPIIDParam()},
				"responses": openAPIResponses(map[string]any{
					// Delete returns {status:"deleted"} (crud_delete.go handleDelete).
					"200": openAPIJSONResponse("Delete status", openAPIWriteStatusSchema("deleted")),
				}),
			},
		}
		if tableHasColumn(table, "deleted_at") && !restoreRouteOwnedByFlow(app, table.Name) {
			paths["/api/"+table.Name+"/{id}/restore"] = map[string]any{
				"post": map[string]any{
					"operationId": "restore" + schemaName,
					"tags":        []string{table.Name},
					"summary":     "Restore a soft-deleted " + singularize(table.Name),
					"description": "Requires read and update access. Clears deleted_at through update validation, locks, hooks, audit and versioning; returns the sanitized row. Does not restore children. Missing, unreadable or already-live rows return 404.",
					"parameters":  []map[string]any{openAPIIDParam()},
					"responses": openAPIResponses(map[string]any{
						"200": openAPIJSONResponse("Restored row", map[string]any{"$ref": "#/components/schemas/" + schemaName}),
						"409": openAPIProblemResponse("Record is locked"),
						"422": openAPIProblemResponse("Update validation failed"),
					}),
				},
			}
		}
		viewer.pruneOpenAPIPaths(app, table.Name, paths)
	}

	if viewer.full && len(registered) > 0 {
		addFlowOpenAPIPaths(app, paths, registered[0])
	}

	version := "1.0.0+" + tablesFingerprint(app)
	if len(registered) > 0 {
		version += flowOpenAPIFingerprint(app, registered[0])
	}

	return map[string]any{
		"openapi": "3.1.0",
		"info": map[string]any{
			"title": appOpenAPITitle(app),
			// Derive the version from the schema fingerprint so the contract
			// version moves whenever the tables/columns change, letting
			// consumers detect drift instead of seeing a frozen 1.0.0.
			"version": version,
		},
		"paths": paths,
		"components": map[string]any{
			"securitySchemes": map[string]any{
				"cookieSession": map[string]any{"type": "apiKey", "in": "cookie", "name": "benmore_session"},
				"bearerAuth":    map[string]any{"type": "http", "scheme": "bearer"},
			},
			"schemas": schemas,
		},
		"security": []map[string][]string{{"cookieSession": []string{}}, {"bearerAuth": []string{}}},
	}
}

func appOpenAPITitle(app *App) string {
	if app.Design != nil && app.Design.SEO != nil && app.Design.SEO["site_name"] != "" {
		return app.Design.SEO["site_name"] + " API"
	}
	return "Benmore App API"
}

// docsHiddenColumn reports a column every generated description (/api/_docs,
// its HTML and Markdown renderings, the OpenAPI read schema, /api/_schema)
// leaves out: exactly the columns read responses strip (apiHiddenColumn,
// response_columns.go), plus the framework credential names on any table.
// Listing a column the API never returns only advertises where a secret lives.
func docsHiddenColumn(app *App, table, column string) bool {
	return isSensitiveUserColumn(column) || apiHiddenColumn(app, table, column)
}

func openAPISchemaForTable(app *App, table Table) map[string]any {
	props := map[string]any{}
	required := []string{}
	for _, col := range table.Columns {
		if docsHiddenColumn(app, table.Name, col.Name) {
			continue
		}
		props[col.Name] = openAPISchemaForColumn(col)
		if col.NotNull && col.Default == "" && !col.PK {
			required = append(required, col.Name)
		}
	}
	out := map[string]any{
		"type": "object",
		// Read responses allow extra keys: the list/read handlers inject
		// related rows under ?include=<rel> keys (crud_read.go ResolveIncludes),
		// which are not part of the table's own columns. A strict
		// additionalProperties:false would reject those otherwise-valid
		// responses, so reads are open while write schemas stay strict.
		"additionalProperties": true,
		"properties":           props,
	}
	if len(required) > 0 {
		out["required"] = required
	}
	return out
}

// openAPIWriteSchemaForTable is the Create<Model> or Update<Model> request
// schema: the columns a generic create or PATCH may set (requestWritable, the
// predicate /api/_schema uses), custom fields included. The schema refuses
// unknown properties, so a column it lists and the write path drops, or the
// reverse, is a wrong contract either way.
func openAPIWriteSchemaForTable(app *App, table Table, mode requestWriteMode, custom []Column) map[string]any {
	props := map[string]any{}
	required := []string{}
	writable := requestWritableAnyCaller(app, table.Name)
	for _, col := range append(append([]Column(nil), table.Columns...), custom...) {
		if !writable.column(col, mode) || isSensitiveUserColumn(col.Name) {
			continue
		}
		prop := openAPISchemaForColumn(col)
		props[col.Name] = prop
		if writable.tenantKeyColumn(col) {
			// Listed because a platform admin's create keeps it; never
			// required, since every other caller's row takes the session's.
			prop["description"] = "Tenant key. Filled from the caller's session; only a platform admin's explicit value is stored."
			continue
		}
		if mode == requestCreate && col.NotNull && col.Default == "" {
			required = append(required, col.Name)
		}
	}
	// Optimistic concurrency on update is driven by an _expected_updated_at
	// field in the request body (crud_update.go handleUpdate reads r.FormValue), NOT
	// by any header. Model it on the Update schema only, and only when the
	// table actually has an updated_at column for the check to compare against.
	if mode == requestUpdate && tableHasColumn(table, "updated_at") {
		props["_expected_updated_at"] = map[string]any{
			"type":        "string",
			"description": "Optimistic concurrency token: the row's current updated_at. If it no longer matches, the update fails with 409.",
		}
	}
	out := map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"properties":           props,
	}
	if len(required) > 0 {
		out["required"] = required
	}
	return out
}

// tableHasColumn reports whether the (already-loaded) table definition has a
// column with the given name. Unlike hasColumn it works off the in-memory
// Table value without touching the DB.
func tableHasColumn(table Table, name string) bool {
	for _, c := range table.Columns {
		if c.Name == name {
			return true
		}
	}
	return false
}

func openAPISchemaForColumn(col Column) map[string]any {
	t := strings.ToUpper(col.Type)
	schema := map[string]any{}
	switch {
	case strings.Contains(t, "INT"):
		schema["type"] = "integer"
	case strings.Contains(t, "REAL"), strings.Contains(t, "FLOAT"), strings.Contains(t, "DOUBLE"), strings.Contains(t, "DECIMAL"):
		schema["type"] = "number"
	case strings.Contains(t, "BOOL"):
		schema["type"] = "boolean"
	case strings.Contains(t, "DATE"), strings.Contains(t, "TIME"):
		schema["type"] = "string"
		schema["format"] = "date-time"
	case strings.Contains(t, "JSON"):
		schema["type"] = []string{"object", "array", "string", "number", "boolean", "null"}
	default:
		schema["type"] = "string"
	}
	if !col.NotNull {
		if typ, ok := schema["type"].(string); ok {
			schema["type"] = []string{typ, "null"}
		}
	}
	if col.PK {
		schema["readOnly"] = true
	}
	return schema
}

func openAPIResponses(extra map[string]any) map[string]any {
	out := map[string]any{
		"400": openAPIProblemResponse("Bad request"),
		"401": openAPIProblemResponse("Authentication required"),
		"403": openAPIProblemResponse("Forbidden"),
		"404": openAPIProblemResponse("Not found"),
		"422": openAPIProblemResponse("Validation failed"),
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

func openAPIJSONResponse(description string, schema map[string]any) map[string]any {
	return map[string]any{
		"description": description,
		"content": map[string]any{
			"application/json": map[string]any{"schema": schema},
		},
	}
}

func openAPIProblemResponse(description string) map[string]any {
	return openAPIJSONResponse(description, map[string]any{"$ref": "#/components/schemas/Problem"})
}

func openAPIJSONRequest(schema map[string]any) map[string]any {
	return map[string]any{
		"required": true,
		"content": map[string]any{
			"application/json": map[string]any{"schema": schema},
		},
	}
}

func openAPIIDParam() map[string]any {
	return map[string]any{
		"name":     "id",
		"in":       "path",
		"required": true,
		"schema":   map[string]any{"type": "string"},
	}
}

// openAPIListParams describes the query parameters the auto-CRUD list
// handler actually honors (crud_read.go). Offset paging accepts page/per_page
// or the SDK limit/offset aliases; keyset paging uses cursor/limit.
func openAPIListParams(schemaName string) []map[string]any {
	return []map[string]any{
		{"name": "page", "in": "query", "description": "Offset-paging page number (1-based). Triggers the {data,total,page,per_page} response shape.", "schema": map[string]any{"type": "integer", "minimum": 1}},
		{"name": "per_page", "in": "query", "description": "Rows per page for offset paging (default 50, maximum 500). Explicit page/per_page controls take precedence over limit/offset.", "schema": map[string]any{"type": "integer", "minimum": 1}},
		{"name": "cursor", "in": "query", "description": "Keyset-paging cursor (an id). Triggers the {data,next_cursor,limit} response shape.", "schema": map[string]any{"type": "string"}},
		{"name": "limit", "in": "query", "description": "Rows per page, capped at 500; default 20 with cursor, otherwise 50. Explicit page/per_page takes precedence for offset paging.", "schema": map[string]any{"type": "integer", "minimum": 1, "maximum": 500}},
		{"name": "offset", "in": "query", "description": "Rows to skip (default 0, maximum 100000). Used with limit when neither page nor per_page is set; ignored with cursor.", "schema": map[string]any{"type": "integer", "minimum": 0, "maximum": 100000}},
		{"name": "count", "in": "query", "description": "When truthy, return only {count: N} (the filtered total, ignoring paging).", "schema": map[string]any{"type": "boolean"}},
		{"name": "include", "in": "query", "description": "Comma-separated relations to expand inline (e.g. include=contact,tasks): a related table name or a Prisma relation field name (include=notes for `notes CaseNote[]`). Adds extra keys to each row. An entry that names no relation is listed in the X-Ignored-Params response header as include=<entry>.", "schema": map[string]any{"type": "string"}},
		{"name": "sort", "in": "query", "description": "Column to order by (with order=asc|desc, default asc). A sort or order the list does not apply (not a column, a direction other than asc/desc, any sort on a cursor page) is listed in X-Ignored-Params.", "schema": map[string]any{"type": "string"}},
		{"name": "order", "in": "query", "description": "asc or desc, for sort or an orderBy without a direction.", "schema": map[string]any{"type": "string", "enum": []string{"asc", "desc"}}},
		{"name": "orderBy", "in": "query", "description": "col or col:desc; used when sort is absent.", "schema": map[string]any{"type": "string"}},
		{"name": "q", "in": "query", "description": "Full-text search query applied across the table's searchable text columns.", "schema": map[string]any{"type": "string"}},
	}
}

// openAPIListResponseSchema models the four real list response shapes the
// auto-CRUD handler emits (crud_read.go): a bare array (default), a page envelope
// ({data,total,page,per_page}), a cursor envelope ({data,next_cursor,limit}),
// and the count-only shape ({count}).
func openAPIListResponseSchema(schemaName string) map[string]any {
	ref := map[string]any{"$ref": "#/components/schemas/" + schemaName}
	rowArray := map[string]any{"type": "array", "items": ref}
	return map[string]any{
		"oneOf": []any{
			rowArray,
			map[string]any{
				"type":     "object",
				"required": []string{"data", "total", "page", "per_page"},
				"properties": map[string]any{
					"data":     rowArray,
					"total":    map[string]any{"type": "integer"},
					"page":     map[string]any{"type": "integer"},
					"per_page": map[string]any{"type": "integer"},
				},
			},
			map[string]any{
				"type":     "object",
				"required": []string{"data", "limit"},
				"properties": map[string]any{
					"data":        rowArray,
					"next_cursor": map[string]any{"type": []string{"string", "integer", "null"}},
					"limit":       map[string]any{"type": "integer"},
				},
			},
			map[string]any{
				"type":     "object",
				"required": []string{"count"},
				"properties": map[string]any{
					"count": map[string]any{"type": "integer"},
				},
			},
		},
	}
}

// openAPICreateResponseSchema models the create envelope: the inserted row
// plus {id, status:"created"} (crud_create.go handleCreate). additionalProperties is
// open because the full row's columns are merged in alongside the envelope.
func openAPICreateResponseSchema(schemaName string) map[string]any {
	return map[string]any{
		"allOf": []any{
			map[string]any{"$ref": "#/components/schemas/" + schemaName},
			map[string]any{
				"type":     "object",
				"required": []string{"id", "status"},
				"properties": map[string]any{
					"id":     map[string]any{"type": []string{"string", "integer"}},
					"status": map[string]any{"type": "string", "const": "created"},
				},
			},
		},
	}
}

// openAPIWriteStatusSchema models the {status:"<verb>"} envelope returned by
// update and delete (crud_update.go handleUpdate / crud_delete.go handleDelete).
func openAPIWriteStatusSchema(status string) map[string]any {
	return map[string]any{
		"type":     "object",
		"required": []string{"status"},
		"properties": map[string]any{
			"status": map[string]any{"type": "string", "const": status},
		},
	}
}

// richSchemaTableVisible reports whether table is one the schema descriptor
// describes to this caller (SQLite compares table names case-insensitively).
func richSchemaTableVisible(opsFor map[string]map[string]bool, table string) bool {
	if _, ok := opsFor[table]; ok {
		return true
	}
	for name := range opsFor {
		if strings.EqualFold(name, table) {
			return true
		}
	}
	return false
}

// generateRichSchema builds the per-user descriptor served at
// GET /api/_schema - the source the schema-driven component layer
// renders from. Unlike /api/_docs (static, table shape only) this
// reflects THIS session: which ops they may perform per table and
// which fields are masked for them. Components read it to render only
// permitted fields/actions, which is what keeps the rendered UI as
// authoritative as the backend.
func generateRichSchema(app *App, session *Session) map[string]any {
	tables, _ := GetTableNames(app.DB)

	// Pre-pass: forward FKs per table, inverted into a reverse-relation
	// index (parent table → child {table,column}) so a Detail view can
	// embed the child tables whose rows point AT a record (one-to-many).
	fksByTable := map[string]map[string]ForeignKey{}
	childrenOf := map[string][]map[string]string{}
	for _, t := range tables {
		if strings.HasPrefix(t, "_benmore_") {
			continue
		}
		fks, _ := GetForeignKeys(app.DB, t)
		fksByTable[t] = fks
		for col, fk := range fks {
			childrenOf[fk.Table] = append(childrenOf[fk.Table], map[string]string{"table": t, "column": col})
		}
	}

	// Per-user allowed ops - coarse (the server still enforces per row).
	// targetUserID = the caller so `self` mode resolves true for "their
	// own rows" rather than false. A non-admin is only told about tables
	// they can do SOMETHING with (a write-only form table still appears),
	// matching the per-caller filtering of the other docs surfaces. RBAC
	// scopes count too, with the scope action each CRUD handler checks.
	scopeAction := map[AccessOp]string{OpRead: "read", OpWrite: "write", OpUpdate: "write", OpDelete: "delete"}
	opsFor := map[string]map[string]bool{}
	for _, table := range tables {
		if strings.HasPrefix(table, "_benmore_") {
			continue
		}
		hasUID := hasColumn(app, table, "user_id")
		hasGroupKey := app.Group != nil && app.Group.Key != "" && hasColumn(app, table, app.Group.Key)
		ops := map[string]bool{}
		anyOp := false
		for _, op := range []AccessOp{OpRead, OpWrite, OpUpdate, OpDelete} {
			mode := app.Access.ModeFor(table, op, hasUID, hasGroupKey)
			ops[string(op)] = mode != "off" && tableModeAllowed(app, table, op, mode, session, session.UserID) && hasScope(session, table, scopeAction[op])
			anyOp = anyOp || ops[string(op)]
		}
		if anyOp || session.IsAdminConsole() {
			opsFor[table] = ops
		}
	}

	out := make(map[string]any)
	for _, table := range tables {
		ops, ok := opsFor[table]
		if !ok {
			continue
		}
		cols, _ := GetTableColumns(app.DB, table)
		fks := fksByTable[table]
		// writable: what a create by THIS caller stores (request_writable.go).
		writable := requestWritableFor(app, table, session)

		fields := make([]map[string]any, 0, len(cols))
		for _, col := range cols {
			if docsHiddenColumn(app, table, col.Name) {
				continue
			}
			encDef := encryptedDefFor(app, table, col.Name)
			masked := encDef != nil && !sessionCanUnmask(session, encDef)
			f := map[string]any{
				"name":     col.Name,
				"type":     col.Type,
				"control":  schemaControlFor(col),
				"label":    humanizeField(col.Name),
				"required": col.NotNull && col.Default == "" && !col.PK,
				"writable": ops["write"] && writable.column(col, requestCreate) && !masked,
			}
			if def, ok := schemaDefaultValue(col); ok {
				f["default"] = def
			}
			if col.PK {
				f["primary_key"] = true
			}
			if encDef != nil {
				f["encrypted"] = true
				f["masked"] = masked
			}
			// A relation names its target only when the caller may see that
			// table, as children (reverse relations) already do.
			if fk, ok := fks[col.Name]; ok && richSchemaTableVisible(opsFor, fk.Table) {
				f["relation"] = map[string]string{"table": fk.Table, "column": fk.Column}
			}
			fields = append(fields, f)
		}

		td := map[string]any{
			"label":  humanizeField(table),
			"fields": fields,
			"ops":    ops,
			"capabilities": map[string]bool{
				"soft_delete": hasColumn(app, table, "deleted_at"),
				// Always present, so a client can tell "sharing is off" from
				// a descriptor that does not report the switch.
				"sharing": recordSharingEnabled(app, table),
			},
		}
		var children []map[string]string
		for _, c := range childrenOf[table] {
			if _, ok := opsFor[c["table"]]; ok {
				children = append(children, c)
			}
		}
		if len(children) > 0 {
			td["children"] = children // reverse relations (one-to-many)
		}
		if app.IsUUIDTable(table) {
			td["id_format"] = "uuid"
		}
		out[table] = td
	}
	return map[string]any{"tables": out}
}

// isManagedColumn reports columns the framework owns by name; a derived form
// hides them (schemaControlFor). Whether a request may set a column is
// requestWritable's answer (request_writable.go), not this list's.
func isManagedColumn(name string) bool {
	switch name {
	case "id", "user_id", "created_at", "updated_at", "deleted_at", "role", "password_hash":
		return true
	}
	return false
}

// encryptedDefFor returns the encryption def for table.col, or nil.
func encryptedDefFor(app *App, table, col string) *EncryptedFieldDef {
	if app.Encrypted == nil {
		return nil
	}
	defs := app.Encrypted.Fields[table]
	for i := range defs {
		if defs[i].Column == col {
			return &defs[i]
		}
	}
	return nil
}

// sessionCanUnmask is a field-level UI hint that the session may unmask some
// rows. Actual values use MaskEncryptedFields' per-row tenant/owner policy;
// this schema metadata does not assert that every readable row is unmasked.
func sessionCanUnmask(session *Session, def *EncryptedFieldDef) bool {
	if len(def.Roles) == 0 {
		return true
	}
	return session.IsAdmin() || HasAnyRole(session, def.Roles)
}

// schemaControlFor derives the form control / cell kind for a column from
// its name + SQLite type. The single framework-owned home for the
// classify mapping the sdui prototype hand-rolled client-side.
//
// The declared type decides first for values a text box or the wrong
// picker would corrupt: a BOOLEAN is a checkbox (has_file is a flag, not an
// upload), a DATETIME/TIMESTAMP an instant (datetime-local; RecordForm
// converts between the viewer's zone and UTC), a DATE a date and a TIME a
// time. A DATETIME named like a calendar date (date, *_date, dob, birthday,
// birthdate) keeps the date control: those columns hold a day, not a moment.
func schemaControlFor(col Column) string {
	if col.PK || isManagedColumn(col.Name) {
		return "hidden"
	}
	n := strings.ToLower(col.Name)
	t := strings.ToUpper(col.Type)
	switch {
	case strings.Contains(t, "BOOL"):
		return "checkbox"
	case strings.Contains(t, "DATETIME"), strings.Contains(t, "TIMESTAMP"):
		if n == "date" || strings.HasSuffix(n, "_date") || n == "dob" || n == "birthday" || n == "birthdate" {
			return "date"
		}
		return "datetime"
	case strings.Contains(t, "DATE"):
		return "date"
	case strings.Contains(t, "TIME"):
		return "time"
	}
	switch {
	case n == "email":
		return "email"
	case n == "phone" || n == "tel" || strings.HasSuffix(n, "_phone"):
		return "tel"
	// Image/file columns BEFORE the _url rule: avatar_url/image_url/photo/logo/…
	// store a file's URL, so the form must render an UPLOAD (file picker →
	// bm.upload → the stored URL), never a "paste a URL" text box. The cell
	// renders a thumbnail. (avatar_url would otherwise match _url → text input.)
	case n == "avatar_url" || n == "avatar" || n == "image" || n == "image_url" ||
		n == "photo" || n == "photo_url" || n == "logo" || n == "logo_url" ||
		n == "banner" || n == "thumbnail" || n == "cover" || n == "picture" ||
		strings.HasSuffix(n, "_image") || strings.HasSuffix(n, "_photo") ||
		strings.HasSuffix(n, "_avatar") || strings.HasSuffix(n, "_logo"):
		return "image"
	case n == "file" || n == "file_url" || n == "attachment" || n == "document" ||
		strings.HasSuffix(n, "_file") || strings.HasSuffix(n, "_attachment") || strings.HasSuffix(n, "_document"):
		return "file"
	case n == "url" || n == "website" || strings.HasSuffix(n, "_url"):
		return "url"
	case n == "notes" || n == "body" || n == "description" || n == "bio":
		return "textarea"
	}
	switch {
	case strings.Contains(t, "INT"):
		if n == "vip" || n == "active" || n == "done" || n == "enabled" ||
			strings.HasPrefix(n, "is_") || strings.HasPrefix(n, "has_") {
			return "checkbox"
		}
		return "number"
	case strings.Contains(t, "REAL"), strings.Contains(t, "FLOA"),
		strings.Contains(t, "DOUB"), strings.Contains(t, "NUMERIC"),
		strings.Contains(t, "DECIMAL"):
		return "number"
	default:
		return "text"
	}
}

// schemaNumberLiteral matches a SQLite numeric literal as PRAGMA table_info
// reports a column default (sign, decimal, exponent; hex is handled apart).
var schemaNumberLiteral = regexp.MustCompile(`^[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?$`)

// schemaDefaultValue turns a column's SQL default, as PRAGMA table_info
// reports it (an empty string literal, 'draft', 0, TRUE or CURRENT_TIMESTAMP),
// into the value a form starts from. /api/_schema used to hand out the SQL
// text itself, so @default("") reached RecordForm as two apostrophes and was
// saved as such.
//
// A quoted string is unquoted (a doubled quote inside it is one quote), a
// number becomes a number and TRUE/FALSE a boolean, then the value takes the
// column's type the way SQLite stores it: a BOOLEAN's 0/1 is false/true, a
// numeric column's numeric text a number, a TEXT column's number its text. A
// default SQLite computes at insert time (CURRENT_TIMESTAMP, a uuid() or any
// other expression), a blob and NULL have no value to show: ok is false, and
// the insert fills the column in.
func schemaDefaultValue(col Column) (any, bool) {
	raw := strings.TrimSpace(col.Default)
	if raw == "" {
		return nil, false
	}
	var v any
	switch {
	case raw[0] == '\'' || raw[0] == '"':
		s, ok := sqlQuotedLiteral(raw)
		if !ok {
			return nil, false
		}
		v = s
	case strings.EqualFold(raw, "TRUE"):
		v = int64(1)
	case strings.EqualFold(raw, "FALSE"):
		v = int64(0)
	default:
		n, ok := sqlNumberLiteral(raw)
		if !ok {
			return nil, false
		}
		v = n
	}

	t := strings.ToUpper(col.Type)
	switch {
	case strings.Contains(t, "BOOL"):
		switch x := v.(type) {
		case int64:
			return x != 0, true
		case float64:
			return x != 0, true
		case string:
			switch strings.ToLower(strings.TrimSpace(x)) {
			case "1", "true":
				return true, true
			case "0", "false":
				return false, true
			}
		}
		return v, true
	case strings.Contains(t, "INT"), strings.Contains(t, "REAL"), strings.Contains(t, "FLOA"),
		strings.Contains(t, "DOUB"), strings.Contains(t, "NUM"), strings.Contains(t, "DEC"):
		if s, ok := v.(string); ok {
			if n, ok := sqlNumberLiteral(strings.TrimSpace(s)); ok {
				return n, true
			}
		}
		return v, true
	case strings.Contains(t, "CHAR"), strings.Contains(t, "CLOB"), strings.Contains(t, "TEXT"):
		if _, isString := v.(string); !isString {
			return strings.TrimPrefix(raw, "+"), true
		}
	}
	return v, true
}

// sqlQuotedLiteral unquotes one SQL string literal, where a doubled quote
// stands for one. Text that is not exactly one literal ('a' || 'b') reports
// false.
func sqlQuotedLiteral(raw string) (string, bool) {
	q := raw[0]
	if len(raw) < 2 || raw[len(raw)-1] != q {
		return "", false
	}
	inner := raw[1 : len(raw)-1]
	var b strings.Builder
	for i := 0; i < len(inner); i++ {
		if inner[i] == q {
			if i+1 < len(inner) && inner[i+1] == q {
				b.WriteByte(q)
				i++
				continue
			}
			return "", false
		}
		b.WriteByte(inner[i])
	}
	return b.String(), true
}

// sqlNumberLiteral parses a SQLite integer (decimal or 0x hex) or real
// literal: an integer as int64, anything else as float64.
func sqlNumberLiteral(s string) (any, bool) {
	if body := strings.TrimLeft(s, "+-"); strings.HasPrefix(body, "0x") || strings.HasPrefix(body, "0X") {
		i, err := strconv.ParseInt(s, 0, 64)
		if err != nil {
			return nil, false
		}
		return i, true
	}
	if !schemaNumberLiteral.MatchString(s) {
		return nil, false
	}
	if !strings.ContainsAny(s, ".eE") {
		if i, err := strconv.ParseInt(s, 10, 64); err == nil {
			return i, true
		}
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
		return nil, false
	}
	return f, true
}

// humanizeField turns snake_case (or a table name) into a Title-Case label.
func humanizeField(s string) string {
	s = strings.TrimSuffix(s, "_id")
	parts := strings.FieldsFunc(s, func(r rune) bool { return r == '_' || r == '-' })
	for i, p := range parts {
		if p == "" {
			continue
		}
		parts[i] = strings.ToUpper(p[:1]) + p[1:]
	}
	return strings.Join(parts, " ")
}

func renderDocsHTML(app *App, viewer docsViewer) string {
	tables, _ := GetTableNames(app.DB)

	var sb strings.Builder
	sb.WriteString(`<div class="max-w-4xl mx-auto py-8 px-4">`)
	sb.WriteString(`<h1 class="text-3xl font-bold tracking-tight mb-2">API Documentation</h1>`)
	sb.WriteString(`<p class="text-muted-foreground mb-4">Auto-generated from your schema. <a href="/api/_docs" class="text-primary hover:underline">View as JSON</a> &middot; <a href="/docs?format=md" class="text-primary hover:underline">View as Markdown</a></p>`)

	// Copy-for-LLM: fetch the markdown export (?format=md) and copy it to the
	// clipboard, so an agent/LLM can be handed a clean, self-contained copy of
	// the docs. Self-contained inline handler; no external deps.
	sb.WriteString(`<div class="mb-8"><button type="button" data-copy-llm class="inline-flex items-center gap-2 rounded-md border bg-card px-3 py-1.5 text-sm font-medium hover:bg-accent">📋 Copy for LLM</button><span data-copy-llm-status class="ml-2 text-xs text-muted-foreground"></span></div>`)
	sb.WriteString(`<script>(function(){var b=document.querySelector('[data-copy-llm]');if(!b)return;var s=document.querySelector('[data-copy-llm-status]');b.addEventListener('click',function(){fetch('/docs?format=md').then(function(r){return r.text()}).then(function(t){return navigator.clipboard.writeText(t)}).then(function(){if(s){s.textContent='Copied!';setTimeout(function(){s.textContent=''},2000)}}).catch(function(){if(s)s.textContent='Copy failed - open /docs?format=md'})})})();</script>`)

	// Auth section
	sb.WriteString(`<div class="rounded-lg border bg-card p-6 mb-6">`)
	sb.WriteString(`<h2 class="text-lg font-semibold mb-3">Authentication</h2>`)
	sb.WriteString(`<p class="text-sm text-muted-foreground mb-2"><strong>Web:</strong> Cookie-based sessions (automatic via login form)</p>`)
	sb.WriteString(`<p class="text-sm text-muted-foreground mb-2"><strong>API/Native:</strong> POST /api/_auth/token with {"email", "password"} → returns {"token"}</p>`)
	sb.WriteString(`<p class="text-sm text-muted-foreground"><strong>Usage:</strong> Authorization: Bearer {token}</p>`)
	sb.WriteString(`</div>`)

	for _, table := range tables {
		if strings.HasPrefix(table, "_benmore_") || !viewer.showsTable(app, table) {
			continue
		}
		cols, _ := GetTableColumns(app.DB, table)

		sb.WriteString(fmt.Sprintf(`<div class="rounded-lg border bg-card p-6 mb-4">
<h2 class="text-lg font-semibold mb-3">%s</h2>
<div class="overflow-x-auto mb-4"><table class="w-full text-sm">
<thead><tr class="border-b"><th class="text-left py-2 pr-4">Field</th><th class="text-left py-2 pr-4">Type</th><th class="text-left py-2">Notes</th></tr></thead><tbody>`,
			html.EscapeString(table)))

		for _, col := range cols {
			if docsHiddenColumn(app, table, col.Name) {
				continue
			}
			notes := ""
			if col.PK {
				notes = "primary key, auto-increment"
			} else if col.NotNull {
				notes = "required"
			}
			if col.Default != "" {
				if notes != "" {
					notes += ", "
				}
				notes += "default: " + col.Default
			}
			sb.WriteString(fmt.Sprintf(`<tr class="border-b border-border/50"><td class="py-2 pr-4 font-mono text-xs">%s</td><td class="py-2 pr-4 text-muted-foreground">%s</td><td class="py-2 text-muted-foreground">%s</td></tr>`,
				html.EscapeString(col.Name), html.EscapeString(col.Type), notes))
		}

		sb.WriteString(`</tbody></table></div>`)

		// Routes
		sb.WriteString(`<div class="space-y-1 text-sm">`)
		for _, rt := range viewer.routes(app, table) {
			color := "bg-emerald-500/10 text-emerald-500"
			if rt.method == "POST" {
				color = "bg-blue-500/10 text-blue-500"
			} else if rt.method == "PATCH" {
				color = "bg-amber-500/10 text-amber-500"
			} else if rt.method == "DELETE" {
				color = "bg-red-500/10 text-red-500"
			}
			sb.WriteString(fmt.Sprintf(`<div class="flex items-center gap-3"><span class="inline-flex items-center rounded px-2 py-0.5 text-xs font-mono font-semibold %s">%s</span><span class="font-mono text-xs">%s</span><span class="text-muted-foreground">- %s</span></div>`,
				color, rt.method, rt.path, rt.desc))
		}
		sb.WriteString(`</div></div>`)
	}

	sb.WriteString(`</div>`)
	return sb.String()
}

// renderDocsMarkdown emits the docs as clean, self-contained markdown - the
// machine/LLM-friendly export served by `GET /docs?format=md` and copied by the
// "Copy for LLM" button. It walks the SAME tables/columns/routes/features the
// HTML and JSON views do, so there's no second source of truth.
// renderDocsMarkdown is the full developer contract; HTTP callers get
// renderDocsMarkdownFor with their own docsViewer.
func renderDocsMarkdown(app *App) string {
	return renderDocsMarkdownFor(app, fullDocs)
}

func renderDocsMarkdownFor(app *App, viewer docsViewer) string {
	tables, _ := GetTableNames(app.DB)
	var sb strings.Builder

	sb.WriteString("# API Documentation\n\n")
	sb.WriteString("Auto-generated from the app schema. Machine-readable JSON at `/api/_docs`.\n\n")

	sb.WriteString("## Authentication\n\n")
	sb.WriteString("- **Web:** cookie-based sessions (login form).\n")
	sb.WriteString("- **API / native:** `POST /api/_auth/token` with `{\"email\",\"password\"}` returns `{\"token\"}`.\n")
	sb.WriteString("- **Usage:** send header `Authorization: Bearer {token}`.\n\n")

	for _, table := range tables {
		if strings.HasPrefix(table, "_benmore_") || !viewer.showsTable(app, table) {
			continue
		}
		cols, _ := GetTableColumns(app.DB, table)
		fmt.Fprintf(&sb, "## %s\n\n", table)
		if app.IsUUIDTable(table) {
			sb.WriteString("_Primary key: UUID (`String @id @default(uuid())`)._\n\n")
		}
		sb.WriteString("| Field | Type | Notes |\n|---|---|---|\n")
		for _, col := range cols {
			if docsHiddenColumn(app, table, col.Name) {
				continue
			}
			var notes []string
			if col.PK {
				notes = append(notes, "primary key")
			} else if col.NotNull {
				notes = append(notes, "required")
			}
			if col.Default != "" {
				notes = append(notes, "default: "+col.Default)
			}
			fmt.Fprintf(&sb, "| `%s` | %s | %s |\n", col.Name, col.Type, strings.Join(notes, ", "))
		}
		sb.WriteString("\nRoutes:\n\n")
		for _, rt := range viewer.routes(app, table) {
			fmt.Fprintf(&sb, "- `%s %s` - %s\n", rt.method, rt.path, rt.desc)
		}
		sb.WriteString("\n")
	}

	if len(app.Pages) > 0 {
		sb.WriteString("## Pages\n\n")
		routes := make([]string, 0, len(app.Pages))
		for route, page := range app.Pages {
			if viewer.showsPage(app, page) {
				routes = append(routes, route)
			}
		}
		sort.Strings(routes)
		for _, route := range routes {
			page := app.Pages[route]
			line := "- `" + route + "`"
			if page.Title != "" {
				line += " - " + page.Title
			}
			if page.Auth != "" {
				line += " (auth: " + page.Auth + ")"
			}
			sb.WriteString(line + "\n")
		}
		sb.WriteString("\n")
	}

	sb.WriteString("## Platform features\n\n")
	for _, f := range docsPlatformFeatures() {
		fmt.Fprintf(&sb, "- **%s:** %s\n", f.name, f.desc)
	}
	sb.WriteString("\n")
	return sb.String()
}

type docsRoute struct{ method, path, desc string }

type docsFeature struct{ name, desc string }

// docsCRUDRoutes is the auto-CRUD route set documented for a table - the single
// list the HTML, JSON, and markdown docs all render.
func docsCRUDRoutes(table string) []docsRoute {
	return []docsRoute{
		{"GET", fmt.Sprintf("/api/%s", table), "List all records"},
		{"GET", fmt.Sprintf("/api/%s/{id}", table), "Get a single record"},
		{"POST", fmt.Sprintf("/api/%s", table), "Create a record"},
		{"PATCH", fmt.Sprintf("/api/%s/{id}", table), "Update a record"},
		{"DELETE", fmt.Sprintf("/api/%s/{id}", table), "Delete a record"},
		{"POST", fmt.Sprintf("/api/%s/batch", table), "Batch create (JSON array)"},
		{"PATCH", fmt.Sprintf("/api/%s/batch", table), "Batch update ({ids, fields})"},
		{"DELETE", fmt.Sprintf("/api/%s/batch", table), "Batch delete ({ids})"},
	}
}

func docsPlatformFeatures() []docsFeature {
	return []docsFeature{
		{"Auth", "cookie + Bearer token"},
		{"Scoping", "owner (user_id) + org (configurable key)"},
		{"Soft delete", "auto if a deleted_at column exists"},
		{"Audit trail", "GET /api/_audit"},
		{"Pagination", "?page=N&per_page=N or ?limit=N&offset=N (offset); ?cursor=X&limit=N (keyset)"},
		{"Idempotency", "X-Idempotency-Key header on POST"},
		{"Concurrency", "_expected_updated_at field for optimistic locking"},
	}
}
