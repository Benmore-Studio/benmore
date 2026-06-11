//go:build !cli

package main

import (
	"fmt"
	"strings"
)

// ResolveIncludes enriches rows with related records based on the ?include= parameter.
// Supports parent includes (deal → contact via contact_id FK), child includes
// (contact → deals via deals.contact_id), and nested includes (deals.tasks).
//
// Uses batched queries to avoid N+1: for a list of 20 deals, fetches all related
// contacts in a single WHERE id IN (...) query.
//
// Respects soft deletes (deleted_at IS NULL) on included records.
// maxIncludeDepth caps the nesting of `?include=a.b.c…` so a hostile
// (or accidentally cyclic, e.g. self-referential FK) chain can't amplify
// into an unbounded query fan-out. Each level is one batched query; 4 is
// well past any legitimate UI need (deal.contact.account.owner).
const maxIncludeDepth = 4

func ResolveIncludes(app *App, table string, rows []map[string]any, includeSpec string, session *Session) {
	resolveIncludesDepth(app, table, rows, includeSpec, session, 0)
}

func resolveIncludesDepth(app *App, table string, rows []map[string]any, includeSpec string, session *Session, depth int) {
	if includeSpec == "" || len(rows) == 0 || depth >= maxIncludeDepth {
		return
	}

	// Parse include spec: "contact,tasks" or "deals.tasks"
	includes := strings.Split(includeSpec, ",")
	for _, inc := range includes {
		inc = strings.TrimSpace(inc)
		if inc == "" {
			continue
		}

		// Handle nested: "deals.tasks" → resolve "deals" first, then "tasks" on each deal
		parts := strings.SplitN(inc, ".", 2)
		name := parts[0]
		nested := ""
		if len(parts) > 1 {
			nested = parts[1]
		}

		resolveInclude(app, table, rows, name, nested, session, depth)
	}
}

// resolveInclude fetches related records for a single include name and attaches them to rows.
func resolveInclude(app *App, table string, rows []map[string]any, name string, nested string, session *Session, depth int) {
	// Strategy 1: Parent include - this table has a FK column pointing to the included table.
	// Example: deals has contact_id → include "contact" fetches from contacts table.
	if parentFK, parentTable := findParentFK(app, table, name); parentFK != "" {
		resolveParentInclude(app, rows, name, parentFK, parentTable, nested, session, depth)
		return
	}

	// Strategy 2: Child include - another table has a FK pointing to this table.
	// Example: contacts include "deals" → deals table has contact_id pointing to contacts.
	if childTable, childFK := findChildFK(app, table, name); childTable != "" {
		resolveChildInclude(app, rows, name, childTable, childFK, nested, session, depth)
		return
	}
}

// resolveParentInclude fetches parent records and nests them.
// Example: 20 deals each have contact_id → fetch all unique contacts in one query.
func resolveParentInclude(app *App, rows []map[string]any, name string, fkCol string, parentTable string, nested string, session *Session, depth int) {
	// Collect unique parent IDs
	idSet := make(map[string]bool)
	for _, row := range rows {
		if val, ok := row[fkCol]; ok && val != nil {
			idSet[fmt.Sprintf("%v", val)] = true
		}
	}
	if len(idSet) == 0 {
		return
	}

	// Batch fetch parents: SELECT * FROM contacts WHERE id IN (...)
	parentRows := batchFetchByIDs(app, parentTable, idSet, session)

	// Index by ID for O(1) lookup
	parentIndex := make(map[string]map[string]any)
	for _, pr := range parentRows {
		if id, ok := pr["id"]; ok {
			parentIndex[fmt.Sprintf("%v", id)] = pr
		}
	}

	// Attach to each row
	for _, row := range rows {
		if val, ok := row[fkCol]; ok && val != nil {
			key := fmt.Sprintf("%v", val)
			if parent, found := parentIndex[key]; found {
				row[name] = parent
			}
		}
	}

	// Resolve nested includes on the parent records
	if nested != "" && len(parentRows) > 0 {
		resolveIncludesDepth(app, parentTable, parentRows, nested, session, depth+1)
	}
}

// resolveChildInclude fetches child records and nests them as arrays.
// Example: 5 contacts → fetch all deals WHERE contact_id IN (1,2,3,4,5) in one query.
func resolveChildInclude(app *App, rows []map[string]any, name string, childTable string, childFK string, nested string, session *Session, depth int) {
	// Collect parent IDs
	idSet := make(map[string]bool)
	for _, row := range rows {
		if val, ok := row["id"]; ok && val != nil {
			idSet[fmt.Sprintf("%v", val)] = true
		}
	}
	if len(idSet) == 0 {
		return
	}

	// Batch fetch children: SELECT * FROM deals WHERE contact_id IN (...) AND deleted_at IS NULL
	// Scoping: only include children the user has access to
	childRows := batchFetchByFK(app, childTable, childFK, idSet, session)

	// Group by FK value
	childGroups := make(map[string][]map[string]any)
	for _, cr := range childRows {
		if val, ok := cr[childFK]; ok && val != nil {
			key := fmt.Sprintf("%v", val)
			childGroups[key] = append(childGroups[key], cr)
		}
	}

	// Attach to each row
	for _, row := range rows {
		if val, ok := row["id"]; ok && val != nil {
			key := fmt.Sprintf("%v", val)
			if children, found := childGroups[key]; found {
				row[name] = children
			} else {
				row[name] = []map[string]any{}
			}
		}
	}

	// Resolve nested includes on the child records
	if nested != "" && len(childRows) > 0 {
		resolveIncludesDepth(app, childTable, childRows, nested, session, depth+1)
	}
}

// findParentFK checks if `table` has a FK column that points to a table matching `name`.
// Matches: "contact" → contact_id → contacts, "deal" → deal_id → deals
func findParentFK(app *App, table string, name string) (fkCol string, parentTable string) {
	fks, ok := app.JoinMap[table]
	if !ok {
		return "", ""
	}

	// Try exact match: name + "_id" (e.g., "contact" → "contact_id")
	candidateFK := name + "_id"
	if fk, ok := fks[candidateFK]; ok {
		return candidateFK, fk.Table
	}

	// Try matching the FK's target table name directly (e.g., include "contacts" matches contact_id → contacts)
	for col, fk := range fks {
		if fk.Table == name {
			return col, fk.Table
		}
	}

	return "", ""
}

// findChildFK checks if another table has a FK pointing to `table`, matching `name`.
// Matches: "deals" on contacts → deals table has contact_id → contacts
func findChildFK(app *App, table string, name string) (childTable string, childFK string) {
	// Walk all tables in JoinMap looking for FKs pointing to our table
	for candidateTable, fks := range app.JoinMap {
		for col, fk := range fks {
			if fk.Table == table && fk.Column == "id" {
				// Check if the candidate table name matches the include name
				if candidateTable == name || candidateTable == name+"s" || strings.TrimSuffix(candidateTable, "s") == name {
					return candidateTable, col
				}
			}
		}
	}
	return "", ""
}

// batchFetchByIDs fetches rows from a table where id IN (...).
// Respects soft deletes and owner/group scoping.
func batchFetchByIDs(app *App, table string, ids map[string]bool, session *Session) []map[string]any {
	if len(ids) == 0 {
		return nil
	}

	placeholders := make([]string, 0, len(ids))
	args := make([]any, 0, len(ids))
	for id := range ids {
		placeholders = append(placeholders, "?")
		args = append(args, id)
	}

	query := fmt.Sprintf("SELECT * FROM %s WHERE id IN (%s)", table, strings.Join(placeholders, ","))
	if hasColumn(app, table, "deleted_at") {
		query += " AND deleted_at IS NULL"
	}

	// Apply scoping - canonical rowScopeClause (act-as aware + ACL).
	if pred, pargs, bypass := rowScopeClause(app, table, session, "view"); !bypass && pred != "" {
		query += " AND " + pred
		args = append(args, pargs...)
	}

	rows, err := QueryRows(app.DB, query, args...)
	if err != nil {
		return nil
	}
	return rows
}

// batchFetchByFK fetches rows from a table where fkCol IN (...).
// Respects soft deletes.
func batchFetchByFK(app *App, table string, fkCol string, fkValues map[string]bool, session *Session) []map[string]any {
	if len(fkValues) == 0 {
		return nil
	}

	placeholders := make([]string, 0, len(fkValues))
	args := make([]any, 0, len(fkValues))
	for val := range fkValues {
		placeholders = append(placeholders, "?")
		args = append(args, val)
	}

	query := fmt.Sprintf("SELECT * FROM %s WHERE %s IN (%s)", table, fkCol, strings.Join(placeholders, ","))
	if hasColumn(app, table, "deleted_at") {
		query += " AND deleted_at IS NULL"
	}

	// Apply scoping - canonical rowScopeClause (act-as aware + ACL).
	if pred, pargs, bypass := rowScopeClause(app, table, session, "view"); !bypass && pred != "" {
		query += " AND " + pred
		args = append(args, pargs...)
	}

	rows, err := QueryRows(app.DB, query, args...)
	if err != nil {
		return nil
	}
	return rows
}
