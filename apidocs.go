//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"strings"
)

// RegisterAPIDocsRoutes adds auto-generated API documentation endpoints.
// Respects features.docs visibility: "public" (default) or "auth" (requires login).
func RegisterAPIDocsRoutes(mux *http.ServeMux, app *App) {
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
	mux.HandleFunc("GET /api/_docs", func(w http.ResponseWriter, r *http.Request) {
		if requireAuth {
			session := getSession(app, r)
			if session == nil {
				http.Error(w, `{"error":"authentication required"}`, http.StatusUnauthorized)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(generateAPIDocs(app))
	})

	// JSON: real OpenAPI 3.1 contract for the app runtime CRUD surface.
	mux.HandleFunc("GET /api/_openapi", func(w http.ResponseWriter, r *http.Request) {
		if requireAuth {
			session := getSession(app, r)
			if session == nil {
				http.Error(w, `{"error":"authentication required"}`, http.StatusUnauthorized)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(generateRuntimeOpenAPI(app))
	})

	// Rich, per-user schema descriptor - the source the schema-driven
	// component layer renders from. ALWAYS auth-gated: the response
	// reflects THIS caller's allowed ops + which fields are masked for
	// them, so it can't be served anonymously.
	mux.HandleFunc("GET /api/_schema", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil {
			http.Error(w, `{"error":"authentication required"}`, http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(generateRichSchema(app, session))
	})

	// HTML: rendered docs page - skip if the app has its own /docs page
	if _, hasDocsPage := app.Pages["/docs"]; !hasDocsPage {
		mux.HandleFunc("GET /docs", func(w http.ResponseWriter, r *http.Request) {
			if requireAuth {
				session := getSession(app, r)
				if session == nil {
					http.Redirect(w, r, app.Paths.Login, http.StatusSeeOther)
					return
				}
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, WrapLayout(renderDocsHTML(app), "API Documentation", app, nil))
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

func generateAPIDocs(app *App) map[string]any {
	tables, _ := GetTableNames(app.DB)

	endpoints := make(map[string]any)
	for _, table := range tables {
		if strings.HasPrefix(table, "_benmore_") {
			continue
		}
		cols, _ := GetTableColumns(app.DB, table)

		// Never expose sensitive columns in API docs
		sensitiveColumns := map[string]bool{
			"password_hash": true, "totp_secret": true, "backup_codes": true,
		}
		fields := make([]map[string]string, 0)
		for _, col := range cols {
			if sensitiveColumns[col.Name] {
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

		tableInfo := map[string]any{
			"fields": fields,
			"routes": []map[string]string{
				{"method": "GET", "path": fmt.Sprintf("/api/%s", table), "description": "List all records"},
				{"method": "GET", "path": fmt.Sprintf("/api/%s/{id}", table), "description": "Get a single record"},
				{"method": "POST", "path": fmt.Sprintf("/api/%s", table), "description": "Create a record"},
				{"method": "PATCH", "path": fmt.Sprintf("/api/%s/{id}", table), "description": "Update a record"},
				{"method": "DELETE", "path": fmt.Sprintf("/api/%s/{id}", table), "description": "Delete a record"},
				{"method": "POST", "path": fmt.Sprintf("/api/%s/batch", table), "description": "Batch create (JSON array)"},
				{"method": "PATCH", "path": fmt.Sprintf("/api/%s/batch", table), "description": "Batch update ({ids, fields})"},
				{"method": "DELETE", "path": fmt.Sprintf("/api/%s/batch", table), "description": "Batch delete ({ids})"},
			},
		}
		if app.IsUUIDTable(table) {
			tableInfo["id_format"] = "uuid"
		}
		endpoints[table] = tableInfo
	}

	// Pages
	pages := make([]map[string]string, 0)
	for route, page := range app.Pages {
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
			"export":      "Export table rows as CSV, JSON, or XLSX",
			"pagination":  "?page=N&per_page=N (offset) or ?cursor=X&limit=N (keyset)",
			"idempotency": "X-Idempotency-Key header on POST",
			"concurrency": "_expected_updated_at field for optimistic locking",
			"cache":       "<query cache=\"5m\"> for query result caching",
		},
	}
}

func generateRuntimeOpenAPI(app *App) map[string]any {
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
	for _, table := range sortedTables(app) {
		// Belt-and-suspenders: sortedTables already strips every
		// _benmore_* table, so this guard is normally dead code. Keep it
		// so a future change to sortedTables can't leak an internal table
		// into the public contract.
		if strings.HasPrefix(table.Name, "_benmore_") {
			continue
		}
		schemaName := pascalCase(singularize(table.Name))
		if seenSchema[schemaName] {
			schemaName = pascalCase(table.Name)
		}
		seenSchema[schemaName] = true
		schemas[schemaName] = openAPISchemaForTable(table)
		schemas["Create"+schemaName] = openAPIWriteSchemaForTable(table, "create")
		schemas["Update"+schemaName] = openAPIWriteSchemaForTable(table, "update")
		paths["/api/"+table.Name] = map[string]any{
			"get": map[string]any{
				"operationId": "list" + schemaName,
				"tags":        []string{table.Name},
				"summary":     "List " + table.Name,
				// Parameters mirror the auto-CRUD list handler (crud.go):
				// offset paging is ?page=&per_page=, keyset paging is
				// ?cursor=&limit= (limit is cursor-scoped only), ?count
				// returns just the total, ?q is full-text, ?include expands
				// relations. There is no ?offset param.
				"parameters": openAPIListParams(schemaName),
				"responses": openAPIResponses(map[string]any{
					// The runtime returns one of: a bare array (default),
					// {data,total,page,per_page} when ?page= is set,
					// {data,next_cursor,limit} when ?cursor= is set, or
					// {count} when ?count is set (crud.go list handler).
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
					// {id, status:"created", ...row} (crud.go handleCreate).
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
					// only (crud.go handleUpdate). On an optimistic-concurrency
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
					// Delete returns {status:"deleted"} (crud.go handleDelete).
					"200": openAPIJSONResponse("Delete status", openAPIWriteStatusSchema("deleted")),
				}),
			},
		}
	}

	return map[string]any{
		"openapi": "3.1.0",
		"info": map[string]any{
			"title": appOpenAPITitle(app),
			// Derive the version from the schema fingerprint so the contract
			// version moves whenever the tables/columns change, letting
			// consumers detect drift instead of seeing a frozen 1.0.0.
			"version": "1.0.0+" + tablesFingerprint(app),
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

func openAPISchemaForTable(table Table) map[string]any {
	props := map[string]any{}
	required := []string{}
	for _, col := range table.Columns {
		if isSensitiveUserColumn(col.Name) {
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
		// related rows under ?include=<rel> keys (crud.go ResolveIncludes),
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

func openAPIWriteSchemaForTable(table Table, mode string) map[string]any {
	props := map[string]any{}
	required := []string{}
	for _, col := range table.Columns {
		if col.PK || isManagedColumn(col.Name) || isSensitiveUserColumn(col.Name) {
			continue
		}
		props[col.Name] = openAPISchemaForColumn(col)
		if mode == "create" && col.NotNull && col.Default == "" {
			required = append(required, col.Name)
		}
	}
	// Optimistic concurrency on update is driven by an _expected_updated_at
	// field in the request body (crud.go handleUpdate reads r.FormValue), NOT
	// by any header. Model it on the Update schema only, and only when the
	// table actually has an updated_at column for the check to compare against.
	if mode == "update" && tableHasColumn(table, "updated_at") {
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
// handler actually honors (crud.go). Offset paging is page/per_page; keyset
// paging is cursor/limit (limit is cursor-scoped only). There is no ?offset.
func openAPIListParams(schemaName string) []map[string]any {
	return []map[string]any{
		{"name": "page", "in": "query", "description": "Offset-paging page number (1-based). Triggers the {data,total,page,per_page} response shape.", "schema": map[string]any{"type": "integer", "minimum": 1}},
		{"name": "per_page", "in": "query", "description": "Rows per page for offset paging (default 20).", "schema": map[string]any{"type": "integer", "minimum": 1}},
		{"name": "cursor", "in": "query", "description": "Keyset-paging cursor (an id). Triggers the {data,next_cursor,limit} response shape.", "schema": map[string]any{"type": "string"}},
		{"name": "limit", "in": "query", "description": "Page size for keyset (cursor) paging only; capped at 500. Ignored for offset paging.", "schema": map[string]any{"type": "integer", "minimum": 1, "maximum": 500}},
		{"name": "count", "in": "query", "description": "When truthy, return only {count: N} (the filtered total, ignoring paging).", "schema": map[string]any{"type": "boolean"}},
		{"name": "include", "in": "query", "description": "Comma-separated relation names to expand inline (e.g. include=contact,tasks). Adds extra keys to each row.", "schema": map[string]any{"type": "string"}},
		{"name": "q", "in": "query", "description": "Full-text search query applied across the table's searchable text columns.", "schema": map[string]any{"type": "string"}},
	}
}

// openAPIListResponseSchema models the four real list response shapes the
// auto-CRUD handler emits (crud.go): a bare array (default), a page envelope
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
// plus {id, status:"created"} (crud.go handleCreate). additionalProperties is
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
// update and delete (crud.go handleUpdate/handleDelete).
func openAPIWriteStatusSchema(status string) map[string]any {
	return map[string]any{
		"type":     "object",
		"required": []string{"status"},
		"properties": map[string]any{
			"status": map[string]any{"type": "string", "const": status},
		},
	}
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
	sensitive := map[string]bool{"password_hash": true, "totp_secret": true, "backup_codes": true}

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

	out := make(map[string]any)
	for _, table := range tables {
		if strings.HasPrefix(table, "_benmore_") {
			continue
		}
		cols, _ := GetTableColumns(app.DB, table)
		fks := fksByTable[table]

		hasUID := hasColumn(app, table, "user_id")
		hasGroupKey := app.Group != nil && app.Group.Key != "" && hasColumn(app, table, app.Group.Key)

		// Per-user allowed ops - coarse (the server still enforces per row).
		// targetUserID = the caller so `self` mode resolves true for "their
		// own rows" rather than false.
		ops := map[string]bool{}
		for _, op := range []AccessOp{OpRead, OpWrite, OpUpdate, OpDelete} {
			mode := app.Access.ModeFor(table, op, hasUID, hasGroupKey)
			ops[string(op)] = mode != "off" && app.Access.Allowed(mode, session, session.UserID)
		}

		fields := make([]map[string]any, 0, len(cols))
		for _, col := range cols {
			if sensitive[col.Name] {
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
				"writable": ops["write"] && !isManagedColumn(col.Name) && !masked,
			}
			if col.Default != "" {
				f["default"] = col.Default
			}
			if col.PK {
				f["primary_key"] = true
			}
			if encDef != nil {
				f["encrypted"] = true
				f["masked"] = masked
			}
			if fk, ok := fks[col.Name]; ok {
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
			},
		}
		if len(childrenOf[table]) > 0 {
			td["children"] = childrenOf[table] // reverse relations (one-to-many)
		}
		if app.IsUUIDTable(table) {
			td["id_format"] = "uuid"
		}
		out[table] = td
	}
	return map[string]any{"tables": out}
}

// isManagedColumn reports columns the framework owns - never user-writable
// through a derived form (they're set server-side or via dedicated routes).
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

// sessionCanUnmask reports whether the session sees the decrypted value.
// Mirrors MaskEncryptedFields' role gate (no roles → everyone with read).
func sessionCanUnmask(session *Session, def *EncryptedFieldDef) bool {
	if len(def.Roles) == 0 {
		return true
	}
	return session.IsAdmin() || HasAnyRole(session, def.Roles)
}

// schemaControlFor derives the form control / cell kind for a column from
// its name + SQLite type. The single framework-owned home for the
// classify mapping the sdui prototype hand-rolled client-side.
func schemaControlFor(col Column) string {
	if col.PK || isManagedColumn(col.Name) {
		return "hidden"
	}
	n := strings.ToLower(col.Name)
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
	t := strings.ToUpper(col.Type)
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
	case strings.Contains(t, "DATE"), strings.Contains(t, "TIME"):
		return "date"
	default:
		return "text"
	}
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

func renderDocsHTML(app *App) string {
	tables, _ := GetTableNames(app.DB)

	var sb strings.Builder
	sb.WriteString(`<div class="max-w-4xl mx-auto py-8 px-4">`)
	sb.WriteString(`<h1 class="text-3xl font-bold tracking-tight mb-2">API Documentation</h1>`)
	sb.WriteString(`<p class="text-muted-foreground mb-8">Auto-generated from your schema. <a href="/api/_docs" class="text-primary hover:underline">View as JSON</a></p>`)

	// Auth section
	sb.WriteString(`<div class="rounded-lg border bg-card p-6 mb-6">`)
	sb.WriteString(`<h2 class="text-lg font-semibold mb-3">Authentication</h2>`)
	sb.WriteString(`<p class="text-sm text-muted-foreground mb-2"><strong>Web:</strong> Cookie-based sessions (automatic via login form)</p>`)
	sb.WriteString(`<p class="text-sm text-muted-foreground mb-2"><strong>API/Native:</strong> POST /api/_auth/token with {"email", "password"} → returns {"token"}</p>`)
	sb.WriteString(`<p class="text-sm text-muted-foreground"><strong>Usage:</strong> Authorization: Bearer {token}</p>`)
	sb.WriteString(`</div>`)

	for _, table := range tables {
		if strings.HasPrefix(table, "_benmore_") {
			continue
		}
		cols, _ := GetTableColumns(app.DB, table)

		sb.WriteString(fmt.Sprintf(`<div class="rounded-lg border bg-card p-6 mb-4">
<h2 class="text-lg font-semibold mb-3">%s</h2>
<div class="overflow-x-auto mb-4"><table class="w-full text-sm">
<thead><tr class="border-b"><th class="text-left py-2 pr-4">Field</th><th class="text-left py-2 pr-4">Type</th><th class="text-left py-2">Notes</th></tr></thead><tbody>`,
			html.EscapeString(table)))

		for _, col := range cols {
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
		routes := []struct{ method, path, desc string }{
			{"GET", "/api/" + table, "List all"},
			{"GET", "/api/" + table + "/{id}", "Get one"},
			{"POST", "/api/" + table, "Create"},
			{"PATCH", "/api/" + table + "/{id}", "Update"},
			{"DELETE", "/api/" + table + "/{id}", "Delete"},
		}
		for _, rt := range routes {
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
