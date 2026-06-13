//go:build !cli

package main

import (
	"database/sql"
	"fmt"
	"strings"
)

// JoinMap caches foreign key relationships for fast lookup during shorthand expansion.
// Built once at app startup: table → column → ForeignKey
type JoinMap map[string]map[string]ForeignKey

// BuildJoinMap creates the FK lookup cache from the live database.
func BuildJoinMap(db *sql.DB) JoinMap {
	jm := make(JoinMap)
	tables, _ := GetTableNames(db)
	for _, table := range tables {
		fks, err := GetForeignKeys(db, table)
		if err == nil && len(fks) > 0 {
			jm[table] = fks
		}
	}
	return jm
}

// ExpandShorthand converts shorthand attributes into a valid SQL query.
// Used by <query from="..."> tags and all :model components.
//
// Attributes:
//   table  - the base table name (from "from" or ":model")
//   pick   - comma-separated columns, supports dot notation for joins (contact.name)
//   hide   - comma-separated columns to exclude (inverse of pick)
//   where  - WHERE condition (raw SQL expression)
//   owned  - "true" for user_id scoping, or a column name like "assigned_to"
//   sort   - "column [asc|desc]" (default: id DESC)
//   limit  - max rows (default: 100)
//   offset - skip rows
func ExpandShorthand(app *App, table string, attrs map[string]string, userID int64) (string, []any) {
	if table == "" {
		return "", nil
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

				joinAlias, joinSQL := resolveJoin(app, table, refName, joinAliases)
				if joinSQL != "" && joinAlias != "" {
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
					selectCols = append(selectCols, fmt.Sprintf("%s.%s AS %s_%s", joinAlias, refField, refName, refField))
				}
			} else {
				selectCols = append(selectCols, fmt.Sprintf("%s.%s", table, col))
			}
		}
	} else if hide != "" {
		// Get all columns, exclude hidden ones
		hideCols := make(map[string]bool)
		for _, h := range strings.Split(hide, ",") {
			hideCols[strings.TrimSpace(h)] = true
		}
		cols, _ := GetTableColumns(app.DB, table)
		for _, c := range cols {
			if !hideCols[c.Name] {
				selectCols = append(selectCols, fmt.Sprintf("%s.%s", table, c.Name))
			}
		}
	}

	// Build SELECT
	selectStr := "*"
	if len(selectCols) > 0 {
		selectStr = strings.Join(selectCols, ", ")
	}

	// Build FROM + JOINs
	fromStr := table
	if len(joins) > 0 {
		fromStr = table + " " + strings.Join(joins, " ")
	}

	query := fmt.Sprintf("SELECT %s FROM %s", selectStr, fromStr)

	// Build WHERE
	// NOTE: where is developer-authored SQL from template attributes (not user input).
	// It is NOT parameterized here because it may contain arbitrary expressions.
	// Developers must never pass user input directly into the where attribute.
	var conditions []string
	if where != "" {
		conditions = append(conditions, where)
	}

	// Owner scoping
	if owned != "" {
		ownerCol := "user_id"
		if owned != "true" && owned != "" {
			ownerCol = owned
		}
		if userID > 0 {
			conditions = append(conditions, fmt.Sprintf("%s.%s = ?", table, ownerCol))
			args = append(args, userID)
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
					break
				}
			}
		} else {
			sortCols, _ := GetTableColumns(app.DB, table)
			for _, c := range sortCols {
				if c.Name == col {
					sortValid = true
					break
				}
			}
			if sortValid {
				col = table + "." + col
			}
		}
		if sortValid {
			query += fmt.Sprintf(" ORDER BY %s %s", col, dir)
		} else {
			query += fmt.Sprintf(" ORDER BY %s.id DESC", table)
		}
	} else {
		query += fmt.Sprintf(" ORDER BY %s.id DESC", table)
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

	return query, args
}

// resolveJoin figures out the JOIN clause for a dotted reference like "contact.name".
func resolveJoin(app *App, baseTable, refName string, aliases map[string]string) (alias, joinSQL string) {
	if app.JoinMap == nil {
		return "", ""
	}

	// Look for a FK column that matches: contact → contact_id
	fkCol := refName + "_id"
	fks, ok := app.JoinMap[baseTable]
	if !ok {
		return "", ""
	}

	fk, ok := fks[fkCol]
	if !ok {
		// Try without _id suffix - maybe the column is named exactly like the ref
		fk, ok = fks[refName]
		if !ok {
			return "", ""
		}
		fkCol = refName
	}

	// Generate alias
	alias = refName + "_join"
	aliases[refName] = alias

	joinSQL = fmt.Sprintf("LEFT JOIN %s AS %s ON %s.id = %s.%s", fk.Table, alias, alias, baseTable, fkCol)
	return alias, joinSQL
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
