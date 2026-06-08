//go:build !cli

package main

// Context graph extractor.
//
// Walks an app's loaded state (pages, tables, flows, hooks, workflows,
// aggregates, computed fields, encrypted fields, retention policies,
// roles, group scoping, validators, partials, layouts) and writes a
// typed directed graph into the app DB's _benmore_context_nodes and
// _benmore_context_edges tables (created by EnsureContextGraphTables
// in context_graph.go).
//
// The graph is the substrate the MCP server exposes back to LLM
// clients as "perfect memory" context — instead of scanning files
// every turn, the model queries for the subgraph around whatever
// it's touching ("page:/checkout") and gets back every relationship
// (tables queried, partials included, flows triggered, state machine
// it participates in, encrypted fields, retention policies, etc.)
// in one shot. See mcp_tools_context.go for the query side.
//
// Extraction strategy
// -------------------
// Full rebuild. Clear both tables at the start, re-scan the app's
// in-memory state, and insert fresh rows. Simpler than incremental
// updates and fast enough (single-app SQLite, tens of ms for
// typical apps). Triggered from buildAppMux on app load and after
// any MCP write_file tool call (via hot reload).
//
// Node types
// ----------
//   page, table, column, flow, hook, partial, layout, workflow,
//   aggregate, computed_field, encrypted_field, retention, role,
//   group, validator, api_endpoint
//
// Edge types
// ----------
//   queries, writes, includes, uses_layout, triggers_hook,
//   triggers_flow, has_state_machine, aggregates, computes_on,
//   encrypts_in, retains_from, exposes, scoped_by, validates,
//   requires_role

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strings"
)

// RebuildContextGraph wipes and repopulates the context graph tables
// for the given app. Safe to call on any running app. Each extraction
// step is independent and silently skipped if its config is absent.
func RebuildContextGraph(app *App) {
	if app == nil || app.DB == nil {
		return
	}
	EnsureContextGraphTables(app.DB)

	tx, err := app.DB.Begin()
	if err != nil {
		log.Printf("  context graph: begin tx failed: %s", err)
		return
	}
	defer tx.Rollback()

	if _, err := tx.Exec("DELETE FROM _benmore_context_edges"); err != nil {
		log.Printf("  context graph: clear edges failed: %s", err)
		return
	}
	if _, err := tx.Exec("DELETE FROM _benmore_context_nodes"); err != nil {
		log.Printf("  context graph: clear nodes failed: %s", err)
		return
	}

	// Collect every relevant table — user-defined tables plus user-facing
	// system tables like _benmore_users, _benmore_notifications, etc.
	// Internal plumbing tables (sessions, locks, jobs, etc.) are excluded.
	allTables, _ := GetAllTableNames(app.DB)
	var userTables []string
	for _, t := range allTables {
		if strings.HasPrefix(t, "sqlite_") {
			continue
		}
		if isInternalTable(t) {
			continue
		}
		userTables = append(userTables, t)
	}

	extractTables(tx, app, userTables)
	extractPartials(tx, app)
	extractPages(tx, app, userTables)
	extractLayouts(tx, app)
	extractHooks(tx, app)
	extractFlows(tx, app, userTables)
	extractWorkflows(tx, app)
	extractAggregates(tx, app, userTables)
	extractComputedFields(tx, app)
	extractEncryptedFields(tx, app)
	extractRetention(tx, app)
	extractRoles(tx, app)
	extractGroup(tx, app, userTables)
	extractValidators(tx, app)

	if err := tx.Commit(); err != nil {
		log.Printf("  context graph: commit failed: %s", err)
	}
}

// --- Tables ---

func extractTables(tx *sql.Tx, app *App, userTables []string) {
	for _, t := range userTables {
		cols, _ := GetTableColumns(app.DB, t)
		var colNames, pks []string
		for _, c := range cols {
			colNames = append(colNames, c.Name)
			if c.PK {
				pks = append(pks, c.Name)
			}
		}
		var rowCount int64
		app.DB.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %q", t)).Scan(&rowCount)
		meta := map[string]any{
			"columns":     colNames,
			"primary_key": pks,
			"row_count":   rowCount,
			"has_soft_delete": hasColumnInList(cols, "deleted_at"),
			"has_timestamps": hasColumnInList(cols, "created_at"),
			"has_user_id":    hasColumnInList(cols, "user_id"),
		}
		insertNode(tx, "table", "table:"+t, t, meta)
	}
}

// --- Partials ---

func extractPartials(tx *sql.Tx, app *App) {
	for name, body := range app.Partials {
		insertNode(tx, "partial", "partial:"+name, name, map[string]any{"size": len(body)})
	}
}

// --- Pages ---

func extractPages(tx *sql.Tx, app *App, userTables []string) {
	for file, page := range app.Pages {
		route := page.Route
		ref := "page:" + route
		meta := map[string]any{
			"file":        file,
			"route":       route,
			"title":       page.Title,
			"auth":        page.Auth,
			"scope":       page.Scope,
			"require":     page.Require,
			"type":        page.Type,
			"description": page.Description,
			"complexity":  classifyComplexity(page.RawHTML),
			"tokens":      estimateFileTokens(file, page.RawHTML),
			"queries":     countQueries(page.RawHTML),
			"components":  countComponents(page.RawHTML),
			"directives":  countDirectives(page.RawHTML),
		}
		insertNode(tx, "page", ref, route, meta)

		html := page.RawHTML

		for _, t := range extractTablesReferenced(html, userTables) {
			insertEdge(tx, ref, "table:"+t, "queries", nil)
		}
		for _, t := range extractTablesWritten(html) {
			insertEdge(tx, ref, "table:"+t, "writes", nil)
		}
		for _, m := range includeRefRe.FindAllStringSubmatch(html, -1) {
			insertEdge(tx, ref, "partial:"+m[1], "includes", nil)
		}
		if lm := layoutRefRe.FindStringSubmatch(html); lm != nil && lm[1] != "none" {
			insertEdge(tx, ref, "layout:"+lm[1], "uses_layout", nil)
		}
		// Framework-implicit relationships: auth-type pages interact with
		// _benmore_users even though there's no explicit SQL in the HTML.
		switch page.Type {
		case "login":
			insertEdge(tx, ref, "table:_benmore_users", "queries", map[string]any{"implicit": true, "reason": "authenticates against"})
		case "signup":
			insertEdge(tx, ref, "table:_benmore_users", "writes", map[string]any{"implicit": true, "reason": "creates account in"})
		case "settings":
			insertEdge(tx, ref, "table:_benmore_users", "queries", map[string]any{"implicit": true, "reason": "reads profile from"})
			insertEdge(tx, ref, "table:_benmore_users", "writes", map[string]any{"implicit": true, "reason": "updates profile in"})
		case "forgot-password", "reset-password":
			insertEdge(tx, ref, "table:_benmore_users", "queries", map[string]any{"implicit": true, "reason": "looks up account in"})
		}
		// Pages with scope="owner" implicitly filter queries by user_id
		if page.Scope == "owner" {
			insertEdge(tx, ref, "table:_benmore_users", "queries", map[string]any{"implicit": true, "reason": "scoped by user_id"})
		}

		// require="plan:pro,enterprise verified:1" — extract role-ish
		// field names and link them to the page via requires_role.
		if page.Require != "" {
			for _, req := range strings.Fields(page.Require) {
				parts := strings.SplitN(req, ":", 2)
				if len(parts) == 2 {
					insertEdge(tx, ref, "role:"+parts[0]+"="+parts[1], "requires_role", nil)
				}
			}
		}
	}
}

// --- Layouts ---

func extractLayouts(tx *sql.Tx, app *App) {
	layoutNames := map[string]bool{}
	for _, page := range app.Pages {
		if lm := layoutRefRe.FindStringSubmatch(page.RawHTML); lm != nil && lm[1] != "none" {
			layoutNames[lm[1]] = true
		}
	}
	for name := range layoutNames {
		insertNode(tx, "layout", "layout:"+name, name, map[string]any{})
	}
}

// --- Hooks ---

func extractHooks(tx *sql.Tx, app *App) {
	if app.Hooks == nil {
		return
	}
	hookMaps := map[string]map[string][]Hook{
		"on_insert":     app.Hooks.OnInsert,
		"on_update":     app.Hooks.OnUpdate,
		"on_delete":     app.Hooks.OnDelete,
		"before_insert": app.Hooks.BeforeInsert,
		"before_update": app.Hooks.BeforeUpdate,
		"before_delete": app.Hooks.BeforeDelete,
	}
	for kind, m := range hookMaps {
		for table, steps := range m {
			ref := fmt.Sprintf("hook:%s:%s", kind, table)
			stepTypes := make([]string, 0, len(steps))
			for _, s := range steps {
				stepTypes = append(stepTypes, classifyHookStep(s))
			}
			insertNode(tx, "hook", ref, fmt.Sprintf("%s on %s", kind, table),
				map[string]any{
					"table":      table,
					"kind":       kind,
					"step_count": len(steps),
					"step_types": stepTypes,
				},
			)
			insertEdge(tx, "table:"+table, ref, "triggers_hook", nil)
		}
	}
}

// classifyHookStep returns a label for the side-effect kind of a hook
// step — sql, webhook, email, notify, or unknown. Used in metadata so
// the LLM can quickly see "oh this hook fires an email AND writes to
// another table" without re-parsing YAML.
func classifyHookStep(h Hook) string {
	switch {
	case h.SQL != "":
		return "sql"
	case h.Webhook != "":
		return "webhook"
	case h.Email != nil:
		return "email"
	case h.Notify != nil:
		return "notify"
	}
	return "unknown"
}

// --- Flows ---

func extractFlows(tx *sql.Tx, app *App, userTables []string) {
	for _, flow := range app.Flows {
		ref := "flow:" + flow.Name
		meta := map[string]any{
			"name":        flow.Name,
			"step_count":  len(flow.Steps),
			"auth":        flow.Auth,
			"role":        flow.Role,
			"transaction": flow.Transaction,
		}
		if flow.Trigger.Path != "" {
			meta["trigger_path"] = flow.Trigger.Path
			meta["trigger_method"] = flow.Trigger.Method
		}
		if flow.Trigger.Table != "" {
			meta["trigger_table"] = flow.Trigger.Table
		}
		if flow.Trigger.Type != "" {
			meta["trigger_type"] = flow.Trigger.Type
		}
		insertNode(tx, "flow", ref, flow.Name, meta)

		// Table-triggered flows: table → flow
		if flow.Trigger.Table != "" {
			insertEdge(tx, "table:"+flow.Trigger.Table, ref, "triggers_flow", nil)
		}
		// HTTP-triggered flows provide an API endpoint node
		if flow.Trigger.Path != "" {
			epRef := fmt.Sprintf("api:%s %s", flow.Trigger.Method, flow.Trigger.Path)
			insertNode(tx, "api_endpoint", epRef,
				fmt.Sprintf("%s %s", flow.Trigger.Method, flow.Trigger.Path),
				map[string]any{
					"method": flow.Trigger.Method,
					"path":   flow.Trigger.Path,
					"flow":   flow.Name,
					"auth":   flow.Auth,
					"role":   flow.Role,
				},
			)
			insertEdge(tx, ref, epRef, "exposes", nil)
		}

		// Scan step SQL for table references
		for _, step := range flow.Steps {
			if step.SQL == "" {
				continue
			}
			lowered := strings.ToLower(step.SQL)
			for _, t := range userTables {
				if strings.Contains(lowered, strings.ToLower(t)) {
					insertEdge(tx, ref, "table:"+t, "queries", nil)
				}
			}
		}
	}
}

// --- Workflows ---

func extractWorkflows(tx *sql.Tx, app *App) {
	if app.Workflows == nil || app.Workflows.Workflows == nil {
		return
	}
	for name, wf := range app.Workflows.Workflows {
		ref := "workflow:" + name
		meta := map[string]any{
			"table":   wf.Table,
			"field":   wf.Field,
			"initial": wf.Initial,
			"states":  wf.States,
		}
		// Flatten transitions for the metadata — useful summary
		var transitions []string
		for from, targets := range wf.Transitions {
			for to := range targets {
				transitions = append(transitions, from+"→"+to)
			}
		}
		meta["transitions"] = transitions
		insertNode(tx, "workflow", ref, name, meta)
		if wf.Table != "" {
			insertEdge(tx, ref, "table:"+wf.Table, "has_state_machine", nil)
		}
	}
}

// --- Aggregates ---

func extractAggregates(tx *sql.Tx, app *App, userTables []string) {
	// Aggregates live in app.yaml, loaded on demand here (not cached on
	// the App struct). Cheap to re-parse for a graph rebuild.
	configs := LoadAggregateConfig(app.Dir)
	for _, agg := range configs {
		ref := "aggregate:" + agg.Name
		meta := map[string]any{
			"sql":              agg.SQL,
			"refresh_seconds":  int(agg.Refresh.Seconds()),
		}
		insertNode(tx, "aggregate", ref, agg.Name, meta)
		// Heuristic: link the aggregate to every user table whose name
		// appears in its SQL, as an aggregates edge. Not bulletproof
		// but good enough for "what depends on this table".
		lowered := strings.ToLower(agg.SQL)
		for _, t := range userTables {
			if strings.Contains(lowered, strings.ToLower(t)) {
				insertEdge(tx, ref, "table:"+t, "aggregates", nil)
			}
		}
	}
}

// --- Computed fields ---

func extractComputedFields(tx *sql.Tx, app *App) {
	if app.Computed == nil || app.Computed.Fields == nil {
		return
	}
	for table, cols := range app.Computed.Fields {
		for col, def := range cols {
			ref := "computed_field:" + table + "." + col
			meta := map[string]any{
				"table":  table,
				"column": col,
			}
			if def.Expr != "" {
				meta["kind"] = "expression"
				meta["expr"] = def.Expr
			} else if def.SQL != "" {
				meta["kind"] = "aggregate"
				meta["sql"] = def.SQL
			}
			insertNode(tx, "computed_field", ref, table+"."+col, meta)
			insertEdge(tx, ref, "table:"+table, "computes_on", nil)
		}
	}
}

// --- Encrypted fields ---

func extractEncryptedFields(tx *sql.Tx, app *App) {
	if app.Encrypted == nil || app.Encrypted.Fields == nil {
		return
	}
	for table, defs := range app.Encrypted.Fields {
		for _, def := range defs {
			ref := "encrypted_field:" + table + "." + def.Column
			insertNode(tx, "encrypted_field", ref, table+"."+def.Column, map[string]any{
				"table":         table,
				"column":        def.Column,
				"unmask_roles":  def.Roles,
			})
			insertEdge(tx, ref, "table:"+table, "encrypts_in", nil)
		}
	}
}

// --- Retention policies ---

func extractRetention(tx *sql.Tx, app *App) {
	policies := LoadRetentionConfig(app.Dir)
	for _, p := range policies {
		ref := "retention:" + p.Table
		insertNode(tx, "retention", ref, p.Table, map[string]any{
			"table":        p.Table,
			"ttl_seconds":  int(p.TTL.Seconds()),
			"column":       p.Column,
		})
		insertEdge(tx, ref, "table:"+p.Table, "retains_from", nil)
	}
}

// --- Roles ---

func extractRoles(tx *sql.Tx, app *App) {
	if app.Roles == nil || app.Roles.Roles == nil {
		return
	}
	for name, def := range app.Roles.Roles {
		ref := "role:" + name
		insertNode(tx, "role", ref, name, map[string]any{
			"scopes": def.Scopes,
		})
	}
}

// --- Group scoping ---

// extractGroup adds a single group-config node if multi-tenant scoping
// is enabled. All user tables with the configured key column are linked
// via scoped_by edges so the LLM can reason about tenant isolation.
func extractGroup(tx *sql.Tx, app *App, userTables []string) {
	if app.Group == nil || app.Group.Key == "" {
		return
	}
	ref := "group:" + app.Group.Key
	insertNode(tx, "group", ref, app.Group.Key, map[string]any{
		"table":      app.Group.Table,
		"key":        app.Group.Key,
		"user_field": app.Group.UserField,
	})
	for _, t := range userTables {
		cols, _ := GetTableColumns(app.DB, t)
		if hasColumnInList(cols, app.Group.Key) {
			insertEdge(tx, "table:"+t, ref, "scoped_by", nil)
		}
	}
}

// --- Validators ---

func extractValidators(tx *sql.Tx, app *App) {
	if app.Validators == nil || app.Validators.Rules == nil {
		return
	}
	for table, rules := range app.Validators.Rules {
		for i, r := range rules {
			// ValidatorRule is a cross-field expression on the table
			// (e.g. "end_date >= start_date"). One node per rule,
			// indexed so multiple rules on the same table are distinct.
			ref := fmt.Sprintf("validator:%s[%d]", table, i)
			insertNode(tx, "validator", ref, table, map[string]any{
				"table": table,
				"rule":  r.Rule,
				"error": r.Error,
			})
			insertEdge(tx, ref, "table:"+table, "validates", nil)
		}
	}
}

// ===== Node/edge insertion helpers =====

func insertNode(tx *sql.Tx, nodeType, ref, label string, meta map[string]any) {
	metaJSON := "{}"
	if meta != nil {
		if b, err := json.Marshal(meta); err == nil {
			metaJSON = string(b)
		}
	}
	tx.Exec(`
		INSERT INTO _benmore_context_nodes (node_type, ref, label, metadata)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(node_type, ref) DO UPDATE SET label = excluded.label, metadata = excluded.metadata, updated_at = datetime('now')
	`, nodeType, ref, label, metaJSON)
}

func insertEdge(tx *sql.Tx, fromRef, toRef, edgeType string, meta map[string]any) {
	var fromID, toID int64
	if err := tx.QueryRow("SELECT id FROM _benmore_context_nodes WHERE ref = ?", fromRef).Scan(&fromID); err != nil {
		return
	}
	if err := tx.QueryRow("SELECT id FROM _benmore_context_nodes WHERE ref = ?", toRef).Scan(&toID); err != nil {
		return
	}
	metaJSON := "{}"
	if meta != nil {
		if b, err := json.Marshal(meta); err == nil {
			metaJSON = string(b)
		}
	}
	tx.Exec(`
		INSERT INTO _benmore_context_edges (from_node, to_node, edge_type, metadata)
		VALUES (?, ?, ?, ?)
	`, fromID, toID, edgeType, metaJSON)
}
