//go:build !cli

package main

// Schema drift detector. After all migrations have applied, we compare
// the declared schema (the parsed schema.prisma models) against the
// live database's actual tables/columns. Drift = a difference that
// migrations alone can't explain - usually caused by someone running
// ad-hoc SQL directly against data.db, or by a deploy that skipped a
// migration step.
//
// Drift categories:
//   - "missing_table"   model declared, table not in db → declared schema is wrong, or migrations didn't run
//   - "extra_table"     table in db, model not declared → schema doesn't acknowledge it (or it's stale)
//   - "missing_column"  model declares col, db table doesn't have it → ALTER ADD COLUMN never applied
//   - "extra_column"    db has a col model doesn't → manual ALTER somewhere
//   - "type_mismatch"   model says X, db says Y → manual change OR Prisma type maps differently than expected
//
// We surface drift as warnings, not errors: the user might have
// intentionally tweaked the db, OR the schema might be in flight. The
// CLI command the schema-drift check prints the full report. The
// app-load path logs a one-line summary when drift is detected so it's
// visible in production logs.

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// SchemaDrift describes a single inconsistency between the declared
// Prisma models and the live database. Multiple drifts are returned
// as a slice; each is independent.
type SchemaDrift struct {
	Kind    string // "missing_table" | "extra_table" | "missing_column" | "extra_column" | "type_mismatch"
	Table   string
	Column  string // empty for table-level drifts
	Detail  string // human-readable extra context (expected type, etc.)
}

// DetectSchemaDrift compares the declared schema against the live
// database's actual structure. Returns drift items in deterministic
// order (table name, then column name).
//
// `systemTablePrefix` is the prefix used for framework-owned tables -
// they're skipped from the "extra table" check because the agent
// doesn't declare them.
func DetectSchemaDrift(db *sql.DB, models []PrismaModel) ([]SchemaDrift, error) {
	const systemTablePrefix = "_benmore_"
	declaredTables := map[string]PrismaModel{}
	for _, m := range models {
		declaredTables[m.Table] = m
	}

	// Live tables from sqlite_master.
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type='table' ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("query sqlite_master: %w", err)
	}
	defer rows.Close()
	liveTables := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		liveTables[name] = true
	}

	var drifts []SchemaDrift

	// Missing tables (declared in schema, absent from db).
	for table := range declaredTables {
		if !liveTables[table] {
			drifts = append(drifts, SchemaDrift{
				Kind:   "missing_table",
				Table:  table,
				Detail: "declared in schema.prisma but not in the live database - has a migration not been applied? Restart the app or restart the app to apply pending migrations.",
			})
		}
	}

	// Extra tables (in db, not declared). System tables and the
	// special sqlite-internal tables are exempt. So are the SQLite
	// FTS5 shadow tables (<parent>_fts, <parent>_fts_data,
	// <parent>_fts_idx, <parent>_fts_config, <parent>_fts_docsize)
	// auto-created whenever a parent model declares @@fulltext -
	// they're internal implementation detail, not orphans. Pre-2.7.31
	// a real-world audit produced 10 false positives and recommended
	// `prisma_prune`, which would have destroyed the FTS indexes.
	for table := range liveTables {
		if strings.HasPrefix(table, systemTablePrefix) || strings.HasPrefix(table, "sqlite_") {
			continue
		}
		if isFTSShadowTable(table, declaredTables) {
			continue
		}
		if _, ok := declaredTables[table]; !ok {
			drifts = append(drifts, SchemaDrift{
				Kind:   "extra_table",
				Table:  table,
				Detail: "exists in the database but isn't declared in schema.prisma - likely a remnant from a previous schema version (Prisma migrations are additive; tables removed from the model don't get dropped automatically). This can cause confusing route collisions: auto-CRUD still mounts /api/" + table + " against the orphaned table, which can shadow or panic against a flow at the same path. Fix: add a `model` block to schema.prisma to keep it, or call `prisma_prune` (drops orphaned tables + columns in one migration).",
			})
		}
	}

	// Per-table column drift. Only for tables present in BOTH -
	// missing/extra-table cases above cover the table-level case.
	for table, model := range declaredTables {
		if !liveTables[table] {
			continue
		}
		liveCols, err := getLiveColumns(db, table)
		if err != nil {
			return drifts, fmt.Errorf("read live columns for %s: %w", table, err)
		}
		declaredCols := map[string]PrismaField{}
		for _, f := range model.Fields {
			declaredCols[f.Column] = f
		}
		// Missing columns.
		for col, f := range declaredCols {
			live, ok := liveCols[col]
			if !ok {
				drifts = append(drifts, SchemaDrift{
					Kind:   "missing_column",
					Table:  table,
					Column: col,
					Detail: fmt.Sprintf("declared as %s but not present in the live %s table", f.Type, table),
				})
				continue
			}
			// Type drift. SQLite stores affinities loosely - INTEGER
			// might display as INT, etc. We do a loose comparison
			// by upper-casing both and checking prefix.
			if !sqliteTypesMatch(f.Type, live.Type) {
				drifts = append(drifts, SchemaDrift{
					Kind:   "type_mismatch",
					Table:  table,
					Column: col,
					Detail: fmt.Sprintf("declared %s, live %s", f.Type, live.Type),
				})
			}
		}
		// Extra columns.
		for col := range liveCols {
			if _, ok := declaredCols[col]; !ok {
				drifts = append(drifts, SchemaDrift{
					Kind:   "extra_column",
					Table:  table,
					Column: col,
					Detail: "exists in the live DB but not in schema.prisma. INFORMATIONAL - usually harmless: the old column lingers from a previous migration, queries against the new schema work fine without it. To drop the unused column, drop the unused column manually or restore the field to your Prisma model if it was removed accidentally.",
				})
			}
		}
	}

	// Deterministic order: (table, column, kind).
	sort.SliceStable(drifts, func(i, j int) bool {
		if drifts[i].Table != drifts[j].Table {
			return drifts[i].Table < drifts[j].Table
		}
		if drifts[i].Column != drifts[j].Column {
			return drifts[i].Column < drifts[j].Column
		}
		return drifts[i].Kind < drifts[j].Kind
	})
	return drifts, nil
}

// isFTSShadowTable reports whether `name` is one of the auxiliary
// tables SQLite's FTS5 creates around a parent <table>_fts virtual
// table. Five suffixes show up per indexed parent:
//
//	<parent>_fts, <parent>_fts_data, <parent>_fts_idx,
//	<parent>_fts_config, <parent>_fts_docsize
//
// We treat a name as a shadow table only when the parent model
// declared @@fulltext - otherwise a model the developer literally
// named `articles_fts_idx` would be silently exempted from drift.
func isFTSShadowTable(name string, declared map[string]PrismaModel) bool {
	suffixes := []string{"_fts_docsize", "_fts_config", "_fts_idx", "_fts_data", "_fts"}
	for _, suf := range suffixes {
		if !strings.HasSuffix(name, suf) {
			continue
		}
		parent := strings.TrimSuffix(name, suf)
		if parent == "" {
			continue
		}
		if m, ok := declared[parent]; ok && len(m.FullText) > 0 {
			return true
		}
	}
	return false
}

// LiveColumn is one row from PRAGMA table_info.
type LiveColumn struct {
	Name string
	Type string
}

func getLiveColumns(db *sql.DB, table string) (map[string]LiveColumn, error) {
	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]LiveColumn{}
	for rows.Next() {
		var (
			cid       int
			name      string
			ctype     string
			notnull   int
			dfltValue sql.NullString
			pk        int
		)
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk); err != nil {
			return out, err
		}
		out[name] = LiveColumn{Name: name, Type: ctype}
	}
	return out, nil
}

// sqliteTypesMatch is a loose comparison for SQLite types. SQLite
// stores types as strings without strict enforcement (type affinity),
// so a column declared INTEGER might be shown as INT, INTEGER, or
// even bare ''. We accept any of these as matching.
func sqliteTypesMatch(declared, live string) bool {
	d := strings.ToUpper(strings.TrimSpace(declared))
	l := strings.ToUpper(strings.TrimSpace(live))
	if d == l {
		return true
	}
	// Affinity-style fallback.
	affinity := func(s string) string {
		switch {
		case strings.Contains(s, "INT"):
			return "INT"
		case strings.Contains(s, "CHAR") || strings.Contains(s, "TEXT") || strings.Contains(s, "CLOB"):
			return "TEXT"
		case strings.Contains(s, "BLOB"):
			return "BLOB"
		case strings.Contains(s, "REAL") || strings.Contains(s, "FLOA") || strings.Contains(s, "DOUB") || strings.Contains(s, "DECIMAL"):
			return "REAL"
		case strings.Contains(s, "DATE") || strings.Contains(s, "TIME"):
			return "TEXT" // SQLite stores DATETIME as TEXT
		}
		return s
	}
	return affinity(d) == affinity(l) || affinity(l) == affinity(d)
}

// FormatDriftReport renders a list of drifts as a human-readable
// multi-line summary - used by the schema-drift check and the
// app-load warning log.
func FormatDriftReport(drifts []SchemaDrift) string {
	if len(drifts) == 0 {
		return "no schema drift detected - declared schema matches the live database."
	}
	var b strings.Builder
	fmt.Fprintf(&b, "schema drift: %d issue(s)\n", len(drifts))
	for _, d := range drifts {
		loc := d.Table
		if d.Column != "" {
			loc = d.Table + "." + d.Column
		}
		fmt.Fprintf(&b, "  [%s] %s: %s\n", d.Kind, loc, d.Detail)
	}
	return b.String()
}

// LoadSchemaModelsForDrift reparses schema.prisma OR schema.sql back
// into the model shape the drift detector compares against. Exported
// so the CLI command can call it without duplicating the load logic.
func LoadSchemaModelsForDrift(dir string) ([]PrismaModel, error) {
	if data, err := os.ReadFile(filepath.Join(dir, "schema.prisma")); err == nil {
		return ParsePrismaSchema(string(data))
	}
	if data, err := os.ReadFile(filepath.Join(dir, "schema.sql")); err == nil {
		// For schema.sql, we don't have Prisma models per se - but we
		// can parse the CREATE TABLE statements into Table structs
		// and convert. For drift detection what matters is table
		// names + column names + types; the ID/relation/etc metadata
		// is irrelevant.
		tables := ParseCreateTables(string(data))
		models := make([]PrismaModel, len(tables))
		for i, t := range tables {
			models[i].Table = t.Name
			models[i].Name = t.Name
			models[i].Fields = make([]PrismaField, len(t.Columns))
			for j, c := range t.Columns {
				models[i].Fields[j] = PrismaField{
					Name:   c.Name,
					Column: c.Name,
					Type:   strings.ToUpper(c.Type),
				}
			}
		}
		return models, nil
	}
	return nil, nil
}
