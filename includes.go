//go:build !cli

package main

import (
	"fmt"
	"net/http"
	"slices"
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

// maxIncludeRowsPerRequest caps the related rows one request's `?include=`
// expansion fetches in total, across every entry and nesting level. The
// per-parent cap alone multiplied: per_page=327&include=tasks.comments bound
// 32,700 task ids into one IN (...) and could hold ~3.3M comment rows in
// memory, and each of the 32 entries did the same independently.
const maxIncludeRowsPerRequest = 10000

// maxIncludeParentsPerFetch caps the ids bound into one batched IN (...).
// Larger id sets are fetched in chunks: SQLite refuses a statement with more
// than 32,766 bound values, and the fetch helpers answer nil on any query
// error, so an over-wide IN used to drop the whole include silently.
const maxIncludeParentsPerFetch = 2000

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
func auditIncludeRead(app *App, table string, rows []map[string]any, session *Session, ia *includeAudit) {
	if len(rows) > 0 && IsReadAudited(app, table) && ia.err == nil {
		ia.err = LogReadAccess(app, ia.r, table, "", "include", session)
	}
}

// includeAudit carries one expansion's request (for the reader's address),
// its first read-audit failure, which fails the whole read under compliance:
// hipaa, and the related rows fetched so far against maxIncludeRowsPerRequest.
type includeAudit struct {
	r    *http.Request
	err  error
	used int
}

// remaining is what is left of the request's include row budget.
func (ia *includeAudit) remaining() int {
	return max(0, maxIncludeRowsPerRequest-ia.used)
}

// orderedIncludeIDs returns the distinct non-NULL values of col in rows, in
// row order, so a chunked fetch cut by the budget expands the first rows of
// the answer, deterministically.
func orderedIncludeIDs(rows []map[string]any, col string) []string {
	seen := map[string]bool{}
	var out []string
	for _, row := range rows {
		if val, ok := row[col]; ok && val != nil {
			key := valueText(val)
			if !seen[key] {
				seen[key] = true
				out = append(out, key)
			}
		}
	}
	return out
}

func includeIDSet(ids []string) map[string]bool {
	set := make(map[string]bool, len(ids))
	for _, id := range ids {
		set[id] = true
	}
	return set
}

// ResolveIncludes expands includeSpec into rows. The error is a read-audit
// write that failed under compliance: hipaa; the caller must not answer rows.
func ResolveIncludes(app *App, r *http.Request, table string, rows []map[string]any, includeSpec string, session *Session) error {
	ia := &includeAudit{r: r}
	resolveIncludesDepth(app, table, rows, includeSpec, session, ia, 0)
	return ia.err
}

func resolveIncludesDepth(app *App, table string, rows []map[string]any, includeSpec string, session *Session, ia *includeAudit, depth int) {
	if includeSpec == "" || len(rows) == 0 || depth >= maxIncludeDepth {
		return
	}

	// Parse include spec: "contact,tasks" or "deals.tasks". Entries that
	// share a first segment ("tasks,tasks.comments,tasks.owner") resolve that
	// relation ONCE, with the remainders as one nested spec ("comments,owner"):
	// each entry used to fetch "tasks" again and spend the budget again.
	var order []string
	nestedFor := map[string][]string{}
	for _, inc := range strings.Split(includeSpec, ",") {
		inc = strings.TrimSpace(inc)
		if inc == "" {
			continue
		}
		parts := strings.SplitN(inc, ".", 2)
		name := parts[0]
		if _, seen := nestedFor[name]; !seen {
			order = append(order, name)
			nestedFor[name] = nil
		}
		if len(parts) > 1 && parts[1] != "" && !slices.Contains(nestedFor[name], parts[1]) {
			nestedFor[name] = append(nestedFor[name], parts[1])
		}
	}
	for _, name := range order {
		resolveInclude(app, table, rows, name, strings.Join(nestedFor[name], ","), session, ia, depth)
	}
}

// resolveInclude fetches related records for a single include name and attaches them to rows.
func resolveInclude(app *App, table string, rows []map[string]any, name string, nested string, session *Session, ia *includeAudit, depth int) {
	rel, ok := resolveIncludeRelation(app, table, name)
	if !ok {
		return
	}
	if rel.parent {
		resolveParentInclude(app, rows, name, rel.fkCol, rel.table, nested, session, ia, depth)
		return
	}
	resolveChildInclude(app, rows, name, rel.table, rel.fkCol, nested, session, ia, depth)
}

// includeRelation is what one `?include=` name resolves to: a parent (rows
// hold fkCol, pointing at table.id) or children (table.fkCol points at the
// rows' id).
type includeRelation struct {
	parent bool
	table  string
	fkCol  string
}

// resolveIncludeRelation resolves an include name on table. Table-name
// matching comes first, so every include that resolved before resolves the
// same way:
//  1. parent: a `<name>_id` FK, or an FK whose target table is `name`
//     ("contact" or "contacts" on deals → contacts);
//  2. child: a table named `name` (or `name`+"s", or `name` minus a trailing
//     "s") with an FK to this table ("deals" on contacts → deals);
//  3. the model's Prisma relation field named `name`: a pointer through its
//     `fields:` column, a back-relation (`notes CaseNote[]`) through the
//     other model's pointer to this one.
func resolveIncludeRelation(app *App, table, name string) (includeRelation, bool) {
	if parentFK, parentTable := findParentFK(app, table, name); parentFK != "" {
		return includeRelation{parent: true, table: parentTable, fkCol: parentFK}, true
	}
	if childTable, childFK := findChildFK(app, table, name); childTable != "" {
		return includeRelation{table: childTable, fkCol: childFK}, true
	}
	return prismaRelationInclude(app, table, name)
}

// tableRelations returns the Prisma relation fields of table's model.
func tableRelations(app *App, table string) []PrismaRelation {
	for _, t := range app.Tables {
		if t.Name == table {
			return t.Relations
		}
	}
	return nil
}

// prismaRelationInclude resolves `name` as a Prisma relation field of
// table's model. Only relations keyed on the related row's id resolve, the
// same key the include fetches by, and never to a framework or SQLite table
// (a model @@map'd onto one is not an auto-CRUD table).
func prismaRelationInclude(app *App, table, name string) (includeRelation, bool) {
	for _, rel := range tableRelations(app, table) {
		if rel.Name != name {
			continue
		}
		if strings.HasPrefix(rel.Table, "_") || strings.HasPrefix(strings.ToLower(rel.Table), "sqlite_") {
			return includeRelation{}, false
		}
		if rel.Column != "" {
			if rel.References != "id" || !hasColumn(app, table, rel.Column) || !hasColumn(app, rel.Table, "id") {
				return includeRelation{}, false
			}
			return includeRelation{parent: true, table: rel.Table, fkCol: rel.Column}, true
		}
		if fk := backRelationFK(app, table, rel); fk != "" && hasColumn(app, table, "id") {
			return includeRelation{table: rel.Table, fkCol: fk}, true
		}
		return includeRelation{}, false
	}
	return includeRelation{}, false
}

// backRelationFK finds the column on rel.Table that points at table.id for
// the back-relation rel: the related model's pointer to this model with the
// same relation label, else its only pointer to this model, else the only
// declared foreign key from rel.Table to table.id. Ambiguity resolves to "".
func backRelationFK(app *App, table string, rel PrismaRelation) string {
	var labelled, all []string
	for _, other := range tableRelations(app, rel.Table) {
		if other.Table != table || other.Column == "" || other.References != "id" {
			continue
		}
		all = append(all, other.Column)
		if other.Label == rel.Label {
			labelled = append(labelled, other.Column)
		}
	}
	pick := func(cols []string) string {
		if len(cols) == 1 && hasColumn(app, rel.Table, cols[0]) {
			return cols[0]
		}
		return ""
	}
	if len(labelled) > 0 {
		return pick(labelled)
	}
	if len(all) > 0 {
		return pick(all)
	}
	var declared []string
	for col, fk := range app.joinMapSnapshot()[rel.Table] {
		if fk.Table == table && fk.Column == "id" {
			declared = append(declared, col)
		}
	}
	return pick(declared)
}

// ignoredIncludeEntries returns the `?include=` entries (normalized) that
// expand nothing, each as "include=<entry>" for X-Ignored-Params: a segment
// that names no relation of the table it is resolved on, or a segment past
// maxIncludeDepth. Resolution is by schema, not by rows: an include that
// resolves but finds no related row the caller may read is applied (a
// has-many include still answers []).
func ignoredIncludeEntries(app *App, table, spec string) []string {
	if spec == "" {
		return nil
	}
	var ignored []string
	for _, entry := range strings.Split(spec, ",") {
		cur := table
		for i, seg := range strings.Split(entry, ".") {
			rel, ok := includeRelation{}, false
			if i < maxIncludeDepth {
				rel, ok = resolveIncludeRelation(app, cur, seg)
			}
			if !ok {
				ignored = append(ignored, "include="+entry)
				break
			}
			cur = rel.table
		}
	}
	return ignored
}

// allIncludeEntries names every `?include=` entry as ignored, for a read
// that applies no include (a point-in-time read).
func allIncludeEntries(spec string) []string {
	if spec == "" {
		return nil
	}
	var out []string
	for _, entry := range strings.Split(spec, ",") {
		out = append(out, "include="+entry)
	}
	return out
}

// resolveParentInclude fetches parent records and nests them.
// Example: 20 deals each have contact_id → fetch all unique contacts in one query.
func resolveParentInclude(app *App, rows []map[string]any, name string, fkCol string, parentTable string, nested string, session *Session, ia *includeAudit, depth int) {
	// Collect unique parent IDs, in row order
	ids := orderedIncludeIDs(rows, fkCol)
	if len(ids) == 0 {
		return
	}

	// Batch fetch parents: SELECT * FROM contacts WHERE id IN (...), in
	// chunks of at most maxIncludeParentsPerFetch ids, each within what is
	// left of the request's row budget (a parent fetch returns at most one
	// row per id). Ids the budget does not reach are not fetched.
	var parentRows []map[string]any
	fetchedIDs := map[string]bool{}
	for len(ids) > 0 {
		n := min(min(len(ids), maxIncludeParentsPerFetch), ia.remaining())
		if n == 0 {
			break
		}
		got := batchFetchByIDs(app, parentTable, includeIDSet(ids[:n]), session, ia)
		ia.used += len(got)
		parentRows = append(parentRows, got...)
		for _, id := range ids[:n] {
			fetchedIDs[id] = true
		}
		ids = ids[n:]
	}

	// Index by ID for O(1) lookup
	parentIndex := make(map[string]map[string]any)
	for _, pr := range parentRows {
		if id, ok := pr["id"]; ok {
			parentIndex[valueText(id)] = pr
		}
	}

	// Attach to each row. A row whose parent the budget did not reach is
	// flagged under includeTruncatedKey, as a cut has-many list is, so it
	// is not mistaken for a row with no readable parent.
	for _, row := range rows {
		if val, ok := row[fkCol]; ok && val != nil {
			key := valueText(val)
			if parent, found := parentIndex[key]; found {
				row[name] = parent
			} else if !fetchedIDs[key] {
				markIncludeTruncated(row, name)
			}
		}
	}

	// Resolve nested includes on the parent records
	if nested != "" && len(parentRows) > 0 {
		resolveIncludesDepth(app, parentTable, parentRows, nested, session, ia, depth+1)
	}
	// Strip hidden columns (apiHiddenColumn) after nested includes, which
	// read FK values that may themselves carry a hidden name.
	stripHiddenColumns(app, parentTable, parentRows)
}

// resolveChildInclude fetches child records and nests them as arrays.
// Example: 5 contacts → fetch all deals WHERE contact_id IN (1,2,3,4,5) in one query.
func resolveChildInclude(app *App, rows []map[string]any, name string, childTable string, childFK string, nested string, session *Session, ia *includeAudit, depth int) {
	// Collect parent IDs, in row order
	ids := orderedIncludeIDs(rows, "id")
	if len(ids) == 0 {
		return
	}

	// Batch fetch children: SELECT * FROM deals WHERE contact_id IN (...) AND deleted_at IS NULL
	// Scoping: only include children the user has access to
	// batchFetchByFK returns at most maxIncludeChildrenPerParent+1 rows per
	// parent; the extra one only signals that the list was cut. So a chunk
	// of n parents returns at most n*(cap+1) rows, and n is chosen so that
	// stays within what is left of the request's row budget: the total of
	// one request's includes is bounded by maxIncludeRowsPerRequest, not by
	// parents x 101 at every level. Parents the budget does not reach get
	// no list and are flagged under includeTruncatedKey.
	perParent := maxIncludeChildrenPerParent + 1
	var fetched []map[string]any
	fetchedParents := map[string]bool{}
	for len(ids) > 0 {
		n := min(min(len(ids), maxIncludeParentsPerFetch), ia.remaining()/perParent)
		if n == 0 {
			break
		}
		got := batchFetchByFK(app, childTable, childFK, includeIDSet(ids[:n]), session, ia)
		ia.used += len(got)
		fetched = append(fetched, got...)
		for _, id := range ids[:n] {
			fetchedParents[id] = true
		}
		ids = ids[n:]
	}

	// Group by FK value, keeping the first maxIncludeChildrenPerParent.
	childGroups := make(map[string][]map[string]any)
	truncated := make(map[string]bool)
	childRows := make([]map[string]any, 0, len(fetched))
	for _, cr := range fetched {
		if val, ok := cr[childFK]; ok && val != nil {
			key := valueText(val)
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
			key := valueText(val)
			if !fetchedParents[key] {
				markIncludeTruncated(row, name)
				continue
			}
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
		resolveIncludesDepth(app, childTable, childRows, nested, session, ia, depth+1)
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
	var cols []string
	for col, fk := range fks {
		if fk.Table == name {
			cols = append(cols, col)
		}
	}
	if col := pickIncludeFK(cols, name); col != "" {
		return col, fks[col].Table
	}

	return "", ""
}

// pickIncludeFK chooses among several FK columns that point at the same
// table: the conventional `<singular target>_id` when present, else the
// first by name. Map order used to decide, so a table with two FKs to one
// parent (patient_id, referred_by_id) expanded a different one per request.
// A Prisma relation field name (`notes`, `referrals`) names one exactly.
func pickIncludeFK(cols []string, target string) string {
	if len(cols) == 0 {
		return ""
	}
	conventional := singularize(target) + "_id"
	if slices.Contains(cols, conventional) {
		return conventional
	}
	slices.Sort(cols)
	return cols[0]
}

// findChildFK checks if another table has a FK pointing to `table`, matching `name`.
// Matches: "deals" on contacts → deals table has contact_id → contacts
func findChildFK(app *App, table string, name string) (childTable string, childFK string) {
	// Walk all tables in JoinMap looking for FKs pointing to our table,
	// in name order so the answer does not depend on map iteration.
	joins := app.joinMapSnapshot()
	candidates := make([]string, 0, len(joins))
	for candidateTable := range joins {
		// Check if the candidate table name matches the include name
		if candidateTable == name || candidateTable == name+"s" || strings.TrimSuffix(candidateTable, "s") == name {
			candidates = append(candidates, candidateTable)
		}
	}
	slices.Sort(candidates)
	for _, candidateTable := range candidates {
		var cols []string
		for col, fk := range joins[candidateTable] {
			if fk.Table == table && fk.Column == "id" {
				cols = append(cols, col)
			}
		}
		if col := pickIncludeFK(cols, table); col != "" {
			return candidateTable, col
		}
	}
	return "", ""
}

// batchFetchByIDs fetches rows from a table where id IN (...).
// Respects soft deletes and owner/group scoping.
func batchFetchByIDs(app *App, table string, ids map[string]bool, session *Session, ia *includeAudit) []map[string]any {
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
	auditIncludeRead(app, table, rows, session, ia)
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
func batchFetchByFK(app *App, table string, fkCol string, fkValues map[string]bool, session *Session, ia *includeAudit) []map[string]any {
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
	auditIncludeRead(app, table, rows, session, ia)
	// Mask encrypted columns on the INCLUDED (child) rows with the requesting
	// session's role - identical to the primary read path (crud_read.go). Without
	// this, `?include=children` on a table whose child rows carry an
	// `encrypted:` column with `unmask_roles:` would return plaintext the
	// direct GET on that child table masks. See batchFetchByIDs.
	MaskEncryptedFields(app, table, rows, session)
	return rows
}
