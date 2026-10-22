//go:build !cli

package main

import (
	"database/sql"
	"fmt"
	"strings"
)

// JoinMap caches foreign key relationships for fast lookup during shorthand expansion.
// Replaced after successful schema reloads: table → column → ForeignKey.
type JoinMap map[string]map[string]ForeignKey

// Published maps are immutable. Snapshot the pointer under the same lock used
// by reload so in-flight relationship readers never race its replacement.
func (app *App) joinMapSnapshot() JoinMap {
	app.mu.RLock()
	defer app.mu.RUnlock()
	return app.JoinMap
}

// BuildJoinMap creates the FK lookup cache from the live database.
func BuildJoinMap(db *sql.DB) JoinMap {
	jm, _ := buildJoinMapChecked(db)
	return jm
}

func buildJoinMapChecked(db *sql.DB) (JoinMap, error) {
	jm := make(JoinMap)
	tables, err := GetTableNames(db)
	if err != nil {
		return nil, err
	}
	for _, table := range tables {
		fks, err := GetForeignKeys(db, table)
		if err != nil {
			return nil, err
		}
		if len(fks) > 0 {
			jm[table] = fks
		}
	}
	return jm, nil
}

// ExpandShorthand converts shorthand attributes into a valid SQL query.
// Used by <query from="..."> tags and all :model components.
//
// Attributes:
//
//	table  - the base table name (from "from" or ":model")
//	pick   - comma-separated columns, supports dot notation for joins (contact.name)
//	hide   - comma-separated columns to exclude (inverse of pick)
//	where  - WHERE condition (raw SQL expression)
//	owned  - "true" for user_id scoping, or a column name like "assigned_to"
//	sort   - "column [asc|desc]" (default: id DESC)
//	limit  - max rows (default: 100)
//	offset - skip rows
//
// where= arrives with its template values already bound (bindTemplateSQL);
// whereArgs are its ? arguments, in order. Every identifier the builder
// writes into the SQL (table, pick, owned) must name a real column, since a
// page can fill these attributes from template values.
func ExpandShorthand(app *App, table string, attrs map[string]string, userID int64, whereArgs []any) (string, []any, error) {
	if table == "" {
		return "", nil, nil
	}
	tableCols, err := GetTableColumns(app.DB, table)
	if err != nil || len(tableCols) == 0 {
		return "", nil, fmt.Errorf("query from=%q: unknown table", table)
	}
	colSet := make(map[string]bool, len(tableCols))
	for _, c := range tableCols {
		colSet[c.Name] = true
	}

	pick := strings.TrimSpace(attrs["pick"])
	hide := strings.TrimSpace(attrs["hide"])
	where := strings.TrimSpace(attrs["where"])
	owned := strings.TrimSpace(attrs["owned"])
	sortBy := strings.TrimSpace(attrs["sort"])
	limit := strings.TrimSpace(attrs["limit"])
	offset := strings.TrimSpace(attrs["offset"])

	var args []any
	var joins []string
	var selectCols []string
	joinAliases := make(map[string]string) // "contact" → "contact_join"

	// Resolve columns
	if pick != "" {
		for _, col := range strings.Split(pick, ",") {
			col = strings.TrimSpace(col)
			if col == "" {
				continue
			}
			if strings.Contains(col, ".") {
				// Dot notation: contact.name → JOIN + alias
				parts := strings.SplitN(col, ".", 2)
				refName := parts[0]  // "contact"
				refField := parts[1] // "name"

				joinAlias, joinSQL, joinTable := resolveJoin(app, table, refName, joinAliases)
				if joinSQL != "" && joinAlias != "" {
					if !liveTableHasColumn(app, joinTable, refField) {
						return "", nil, fmt.Errorf("query pick=%q: unknown column on %s", col, joinTable)
					}
					// Check if this join is already added
					alreadyJoined := false
					for _, j := range joins {
						if j == joinSQL {
							alreadyJoined = true
							break
						}
					}
					if !alreadyJoined {
						joins = append(joins, joinSQL)
					}
					selectCols = append(selectCols, quoteColumn(joinAlias, refField)+" AS "+quoteIdent(refName+"_"+refField))
				}
			} else {
				if !colSet[col] {
					return "", nil, fmt.Errorf("query pick=%q: unknown column on %s", col, table)
				}
				selectCols = append(selectCols, quoteColumn(table, col))
			}
		}
	} else if hide != "" {
		// Get all columns, exclude hidden ones
		hideCols := make(map[string]bool)
		for _, h := range strings.Split(hide, ",") {
			hideCols[strings.TrimSpace(h)] = true
		}
		for _, c := range tableCols {
			if !hideCols[c.Name] {
				selectCols = append(selectCols, quoteColumn(table, c.Name))
			}
		}
	}

	// Build SELECT
	selectStr := "*"
	if len(selectCols) > 0 {
		selectStr = strings.Join(selectCols, ", ")
	}

	// Build FROM + JOINs. The base table is a real table (GetTableColumns
	// above); the join SQL is built from the FK map (resolveJoin).
	fromStr := quoteIdent(table)
	if len(joins) > 0 {
		fromStr = quoteIdent(table) + " " + strings.Join(joins, " ")
	}

	query := fmt.Sprintf("SELECT %s FROM %s", selectStr, fromStr)

	// Build WHERE. where is the author's expression with any template values
	// already replaced by ? placeholders; their arguments come first.
	args = append(args, whereArgs...)
	// Parenthesized so an OR in the author's where= can't escape the owner
	// condition ANDed after it.
	var conditions []string
	if where != "" {
		conditions = append(conditions, "("+where+"\n)")
	}

	// Owner scoping. Without a signed-in user nothing is owned, so the
	// query matches no rows instead of every owner's.
	if owned != "" {
		ownerCol := "user_id"
		if owned != "true" && owned != "" {
			if !colSet[owned] {
				return "", nil, fmt.Errorf("query owned=%q: unknown column on %s", owned, table)
			}
			ownerCol = owned
		}
		if userID > 0 {
			conditions = append(conditions, quoteColumn(table, ownerCol)+" = ?")
			args = append(args, userID)
		} else {
			conditions = append(conditions, "0")
		}
	}

	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}

	// ORDER BY - validate column exists and direction is ASC/DESC to prevent injection
	if sortBy != "" {
		parts := strings.Fields(sortBy)
		col := parts[0]
		dir := "ASC"
		if len(parts) > 1 {
			d := strings.ToUpper(parts[1])
			if d == "ASC" || d == "DESC" {
				dir = d
			}
		}
		// Validate the column name against the table's actual columns
		sortValid := false
		if strings.Contains(col, ".") {
			// Qualified column (e.g. "orders.created_at") - validate the column part
			dotParts := strings.SplitN(col, ".", 2)
			sortCols, _ := GetTableColumns(app.DB, dotParts[0])
			for _, c := range sortCols {
				if c.Name == dotParts[1] {
					sortValid = true
					col = quoteColumn(dotParts[0], dotParts[1])
					break
				}
			}
		} else {
			sortCols, _ := GetTableColumns(app.DB, table)
			for _, c := range sortCols {
				if c.Name == col {
					sortValid = true
					col = quoteColumn(table, col)
					break
				}
			}
		}
		if sortValid {
			query += fmt.Sprintf(" ORDER BY %s %s", col, dir)
		} else {
			query += " ORDER BY " + quoteColumn(table, "id") + " DESC"
		}
	} else {
		query += " ORDER BY " + quoteColumn(table, "id") + " DESC"
	}

	// LIMIT (validate as integer to prevent injection)
	if limit != "" {
		var limitInt int
		if _, err := fmt.Sscanf(limit, "%d", &limitInt); err == nil && limitInt > 0 {
			query += fmt.Sprintf(" LIMIT %d", limitInt)
		} else {
			query += " LIMIT 100"
		}
	} else {
		query += " LIMIT 100"
	}

	// OFFSET (validate as integer)
	if offset != "" {
		var offsetInt int
		if _, err := fmt.Sscanf(offset, "%d", &offsetInt); err == nil && offsetInt >= 0 {
			query += fmt.Sprintf(" OFFSET %d", offsetInt)
		}
	}

	return query, args, nil
}

// liveTableHasColumn reports whether the live table has a column named col.
func liveTableHasColumn(app *App, table, col string) bool {
	cols, err := GetTableColumns(app.DB, table)
	if err != nil {
		return false
	}
	for _, c := range cols {
		if c.Name == col {
			return true
		}
	}
	return false
}

// resolveJoin figures out the JOIN clause for a dotted reference like "contact.name".
func resolveJoin(app *App, baseTable, refName string, aliases map[string]string) (alias, joinSQL, target string) {
	joins := app.joinMapSnapshot()
	if joins == nil {
		return "", "", ""
	}

	// Look for a FK column that matches: contact → contact_id
	fkCol := refName + "_id"
	fks, ok := joins[baseTable]
	if !ok {
		return "", "", ""
	}

	fk, ok := fks[fkCol]
	if !ok {
		// Try without _id suffix - maybe the column is named exactly like the ref
		fk, ok = fks[refName]
		if !ok {
			return "", "", ""
		}
		fkCol = refName
	}

	// Generate alias
	alias = refName + "_join"
	aliases[refName] = alias

	joinSQL = fmt.Sprintf("LEFT JOIN %s AS %s ON %s = %s", quoteIdent(fk.Table), quoteIdent(alias), quoteColumn(alias, "id"), quoteColumn(baseTable, fkCol))
	return alias, joinSQL, fk.Table
}

// ValidateShorthand checks shorthand attributes against the schema.
// Returns errors for unknown tables, columns, or FK references.
func ValidateShorthand(app *App, table string, attrs map[string]string) []string {
	var errors []string

	// Check table exists
	cols, err := GetTableColumns(app.DB, table)
	if err != nil || len(cols) == 0 {
		errors = append(errors, fmt.Sprintf("unknown table '%s'", table))
		return errors
	}

	colMap := make(map[string]bool)
	for _, c := range cols {
		colMap[c.Name] = true
	}

	// Validate pick columns
	pick := attrs["pick"]
	if pick != "" {
		for _, col := range strings.Split(pick, ",") {
			col = strings.TrimSpace(col)
			if col == "" {
				continue
			}
			if strings.Contains(col, ".") {
				// Dot notation - check FK exists
				parts := strings.SplitN(col, ".", 2)
				fkCol := parts[0] + "_id"
				if !colMap[fkCol] {
					suggestions := suggestColumn(fkCol, cols)
					errors = append(errors, fmt.Sprintf("pick '%s': no FK column '%s' on table '%s' (have: %s)", col, fkCol, table, strings.Join(suggestions, ", ")))
				}
			} else if !colMap[col] {
				suggestions := suggestColumn(col, cols)
				errors = append(errors, fmt.Sprintf("pick '%s': unknown column on table '%s'. Did you mean: %s?", col, table, strings.Join(suggestions, ", ")))
			}
		}
	}

	// Validate hide columns
	hide := attrs["hide"]
	if hide != "" {
		for _, col := range strings.Split(hide, ",") {
			col = strings.TrimSpace(col)
			if col != "" && !colMap[col] {
				errors = append(errors, fmt.Sprintf("hide '%s': unknown column on table '%s'", col, table))
			}
		}
	}

	// Validate owned column
	owned := attrs["owned"]
	if owned != "" && owned != "true" {
		if !colMap[owned] {
			errors = append(errors, fmt.Sprintf("owned='%s': column not found on table '%s'", owned, table))
		}
	}

	return errors
}

func suggestColumn(name string, cols []Column) []string {
	var suggestions []string
	for _, c := range cols {
		if levenshtein(c.Name, name) <= 2 || strings.Contains(c.Name, name) || strings.Contains(name, c.Name) {
			suggestions = append(suggestions, c.Name)
		}
	}
	if len(suggestions) == 0 {
		for _, c := range cols {
			suggestions = append(suggestions, c.Name)
			if len(suggestions) >= 5 {
				break
			}
		}
	}
	return suggestions
}
