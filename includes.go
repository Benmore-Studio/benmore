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

// maxIncludeChildrenPerParent caps a has-many `?include=` per parent row.
// Without it `per_page=500&include=children` returned every child of 500
// parents in one response. The cut is deterministic (lowest ids first).
const maxIncludeChildrenPerParent = 100

// maxIncludeSpecs caps the distinct comma-separated entries of one
// `?include=`. Each entry runs a batched query per nesting level, so an
// unbounded list let one request run thousands of them.
const maxIncludeSpecs = 32

// normalizeIncludeSpec trims every dotted segment of every `?include=` entry,
// drops empty and duplicate entries (a duplicate resolves to exactly the same
// rows), and refuses a spec with more than maxIncludeSpecs distinct entries.
func normalizeIncludeSpec(spec string) (string, error) {
	if spec == "" {
		return "", nil
	}
	seen := map[string]bool{}
	var out []string
	for _, inc := range strings.Split(spec, ",") {
		parts := strings.Split(inc, ".")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		inc = strings.Trim(strings.Join(parts, "."), ".")
		if inc == "" || seen[inc] {
			continue
		}
		seen[inc] = true
		out = append(out, inc)
	}
	if len(out) > maxIncludeSpecs {
		return "", fmt.Errorf("?include= names %d relations; at most %d distinct entries are allowed per request", len(out), maxIncludeSpecs)
	}
	return strings.Join(out, ","), nil
}

// includeTruncatedKey names the parent-row key listing the has-many
// includes that hit maxIncludeChildrenPerParent, e.g.
// "_include_truncated": ["tasks"]. Absent when nothing was cut.
const includeTruncatedKey = "_include_truncated"

// includeRankColumn is the per-parent rank batchFetchByFK computes and
// strips before returning rows.
const includeRankColumn = "_benmore_include_rank"

func markIncludeTruncated(row map[string]any, name string) {
	list, _ := row[includeTruncatedKey].([]string)
	for _, n := range list {
		if n == name {
			return
		}
	}
	row[includeTruncatedKey] = append(list, name)
}

// auditIncludeRead records an `?include=` expansion of an audited table:
// one entry per batched fetch, like a list read, so related rows a caller
// pulled in through an include are not invisible to the read audit.
func auditIncludeRead(app *App, table string, rows []map[string]any, session *Session) {
	if len(rows) > 0 && IsReadAudited(app, table) {
		LogReadAccess(app, table, "", "include", session)
	}
}

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
	// Strip hidden columns (apiHiddenColumn) after nested includes, which
	// read FK values that may themselves carry a hidden name.
	stripHiddenColumns(app, parentTable, parentRows)
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
	// batchFetchByFK returns at most maxIncludeChildrenPerParent+1 rows per
	// parent; the extra one only signals that the list was cut.
	fetched := batchFetchByFK(app, childTable, childFK, idSet, session)

	// Group by FK value, keeping the first maxIncludeChildrenPerParent.
	childGroups := make(map[string][]map[string]any)
	truncated := make(map[string]bool)
	childRows := make([]map[string]any, 0, len(fetched))
	for _, cr := range fetched {
		if val, ok := cr[childFK]; ok && val != nil {
			key := fmt.Sprintf("%v", val)
			if len(childGroups[key]) >= maxIncludeChildrenPerParent {
				truncated[key] = true
				continue
			}
			childGroups[key] = append(childGroups[key], cr)
			childRows = append(childRows, cr)
		}
	}

	// Attach to each row. The children stay a plain array (unchanged
	// shape); a cut list is flagged on the parent under
	// includeTruncatedKey so a client knows to page the child table itself.
	for _, row := range rows {
		if val, ok := row["id"]; ok && val != nil {
			key := fmt.Sprintf("%v", val)
			if children, found := childGroups[key]; found {
				row[name] = children
			} else {
				row[name] = []map[string]any{}
			}
			if truncated[key] {
				markIncludeTruncated(row, name)
			}
		}
	}

	// Resolve nested includes on the child records
	if nested != "" && len(childRows) > 0 {
		resolveIncludesDepth(app, childTable, childRows, nested, session, depth+1)
	}
	// Strip hidden columns only now: grouping and nested includes above
	// read FK values that may themselves carry a hidden name.
	stripHiddenColumns(app, childTable, childRows)
}

// findParentFK checks if `table` has a FK column that points to a table matching `name`.
// Matches: "contact" → contact_id → contacts, "deal" → deal_id → deals
func findParentFK(app *App, table string, name string) (fkCol string, parentTable string) {
	fks, ok := app.joinMapSnapshot()[table]
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
	for candidateTable, fks := range app.joinMapSnapshot() {
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
	// Access-MODE gate (off/admin/role:/perm:). rowScopeClause below handles
	// per-ROW scoping but is empty for a table with no user_id/group key, so
	// without this an `?include=` to an admin-only / role-gated reference
	// table would return every row. A direct GET on it would 404; the include
	// must not be a back door.
	if !SessionCanAccessTable(app, table, OpRead, session) {
		return nil
	}

	placeholders := make([]string, 0, len(ids))
	args := make([]any, 0, len(ids))
	for id := range ids {
		placeholders = append(placeholders, "?")
		args = append(args, id)
	}

	query := fmt.Sprintf("SELECT * FROM %s WHERE id IN (%s)", quoteIdent(table), strings.Join(placeholders, ","))
	if hasColumn(app, table, "deleted_at") {
		query += " AND deleted_at IS NULL"
	}

	// Apply scoping - canonical rowScopeClause (act-as aware + ACL).
	pred, pargs, bypass := rowScopeClause(app, table, session, "view")
	if filter, fargs := readRowFilter(app, table, pred, pargs, bypass); filter != "" {
		query += " AND " + filter
		args = append(args, fargs...)
	}

	rows, err := queryNativeRowsWith(app.DB, app, table, query, args...)
	if err != nil {
		return nil
	}
	auditIncludeRead(app, table, rows, session)
	// Mask encrypted columns on the INCLUDED (parent) rows with the
	// requesting session's role - identical to the primary read path
	// (crud_read.go handleList/handleRead). QueryRows returns DB-trigger-
	// DECRYPTED values; without this, `?include=parent` on a table whose
	// parent has an `encrypted:` column with `unmask_roles:` would hand the
	// caller plaintext the direct GET on that table would have masked. The
	// include must not be a back door around field-level encryption.
	MaskEncryptedFields(app, table, rows, session)
	return rows
}

// batchFetchByFK fetches rows from a table where fkCol IN (...).
// Respects soft deletes.
func batchFetchByFK(app *App, table string, fkCol string, fkValues map[string]bool, session *Session) []map[string]any {
	if len(fkValues) == 0 {
		return nil
	}
	// Access-MODE gate - see batchFetchByIDs. Per-row scoping alone is empty
	// for unscoped tables, so the mode (off/admin/role:/perm:) must be checked
	// before an `?include=` can expand a related table's child rows.
	if !SessionCanAccessTable(app, table, OpRead, session) {
		return nil
	}

	placeholders := make([]string, 0, len(fkValues))
	args := make([]any, 0, len(fkValues))
	for val := range fkValues {
		placeholders = append(placeholders, "?")
		args = append(args, val)
	}

	// fkCol is a column of table (a declared foreign key); the outer query
	// reads it from the subquery's own columns.
	inner := fmt.Sprintf("SELECT %s.*, ROW_NUMBER() OVER (PARTITION BY %s ORDER BY id) AS %s FROM %s WHERE %s IN (%s)",
		quoteIdent(table), quoteColumn(table, fkCol), includeRankColumn, quoteIdent(table), quoteColumn(table, fkCol), strings.Join(placeholders, ","))
	if hasColumn(app, table, "deleted_at") {
		inner += " AND deleted_at IS NULL"
	}

	// Apply scoping - canonical rowScopeClause (act-as aware + ACL). It
	// runs INSIDE the ranking so the per-parent cap counts only rows the
	// caller may see.
	pred, pargs, bypass := rowScopeClause(app, table, session, "view")
	if filter, fargs := readRowFilter(app, table, pred, pargs, bypass); filter != "" {
		inner += " AND " + filter
		args = append(args, fargs...)
	}
	// One past the cap per parent, so resolveChildInclude can tell a list
	// that was cut from one that is exactly full.
	query := fmt.Sprintf("SELECT * FROM (%s) WHERE %s <= ? ORDER BY %s, %s",
		inner, includeRankColumn, quoteIdent(fkCol), includeRankColumn)
	args = append(args, maxIncludeChildrenPerParent+1)

	rows, err := queryNativeRowsWith(app.DB, app, table, query, args...)
	if err != nil {
		return nil
	}
	for _, row := range rows {
		delete(row, includeRankColumn)
	}
	auditIncludeRead(app, table, rows, session)
	// Mask encrypted columns on the INCLUDED (child) rows with the requesting
	// session's role - identical to the primary read path (crud_read.go). Without
	// this, `?include=children` on a table whose child rows carry an
	// `encrypted:` column with `unmask_roles:` would return plaintext the
	// direct GET on that child table masks. See batchFetchByIDs.
	MaskEncryptedFields(app, table, rows, session)
	return rows
}
