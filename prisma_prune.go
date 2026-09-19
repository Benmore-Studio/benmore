//go:build !cli

package main

// PruneDrift drops the columns + tables the live DB has but
// schema.prisma doesn't declare. Used to clean up after the agent
// iterates a schema down to a smaller shape and the old columns
// linger.
//
// Behavior:
//   - For each `extra_column` drift: ALTER TABLE … DROP COLUMN.
//     SQLite supports DROP COLUMN since 3.35.
//   - For each `extra_table` drift: DROP TABLE.
//   - Wrapped in a single transaction. Either every drop succeeds
//     or nothing is touched.
//   - Generates a numbered migration file under migrations/ for
//     the trace.

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// PruneResult summarizes what a prune operation did. Returned to the
// CLI so the user sees exactly what dropped.
type PruneResult struct {
	ColumnsDropped []string // "table.column" pairs
	TablesDropped  []string
	MigrationFile  string // path on disk, or "" if nothing to prune
}

// PrunePrismaDrift drops every drifted column + table from the live
// DB to match schema.prisma. Idempotent - running on a clean schema
// is a no-op.
func PrunePrismaDrift(db *sql.DB, dir string) (PruneResult, error) {
	models, err := LoadSchemaModelsForDrift(dir)
	if err != nil {
		return PruneResult{}, fmt.Errorf("load schema models: %w", err)
	}
	if len(models) == 0 {
		return PruneResult{}, nil
	}
	drifts, err := DetectSchemaDrift(db, models)
	if err != nil {
		return PruneResult{}, fmt.Errorf("detect drift: %w", err)
	}

	var (
		dropColumns [][2]string // [table, column]
		dropTables  []string
	)
	for _, d := range drifts {
		switch d.Kind {
		case "extra_column":
			dropColumns = append(dropColumns, [2]string{d.Table, d.Column})
		case "extra_table":
			dropTables = append(dropTables, d.Table)
		}
	}
	if len(dropColumns) == 0 && len(dropTables) == 0 {
		return PruneResult{}, nil
	}

	// Prune is destructive (DROP COLUMN / DROP TABLE) and its generated
	// migration's DOWN section can't restore the data. Take a fresh consistent
	// backup BEFORE touching anything so `bm db rollback` / auto-restore has a
	// pre-prune snapshot to recover from.
	if bkPath, bkErr := backupDatabase(dir); bkErr != nil {
		log.Printf("WARNING: pre-prune backup failed (dropping %d column(s), %d table(s)): %s",
			len(dropColumns), len(dropTables), bkErr)
	} else if bkPath != "" {
		log.Printf("PRUNE: dropping %d column(s) + %d table(s) - backed up to %s before applying",
			len(dropColumns), len(dropTables), filepath.Base(bkPath))
	}

	// Build the SQL statements + emit a migration file for the trace.
	var stmts []string
	for _, cc := range dropColumns {
		stmts = append(stmts, fmt.Sprintf("ALTER TABLE %s DROP COLUMN %s;", cc[0], cc[1]))
	}
	for _, t := range dropTables {
		stmts = append(stmts, fmt.Sprintf("DROP TABLE IF EXISTS %s;", t))
	}

	timestamp := time.Now().UTC().Format("20060102T150405Z")
	migDir := filepath.Join(dir, "migrations")
	if err := os.MkdirAll(migDir, 0755); err != nil {
		return PruneResult{}, fmt.Errorf("create migrations dir: %w", err)
	}
	next := nextMigrationNumber(migDir)
	filename := fmt.Sprintf("%04d_%s_prune.sql", next, timestamp)
	filePath := filepath.Join(migDir, filename)

	var content strings.Builder
	fmt.Fprintf(&content, "-- Migration: prune (manual drift cleanup)\n")
	fmt.Fprintf(&content, "-- Generated: %s\n--\n-- UP --\n", timestamp)
	for _, s := range stmts {
		content.WriteString(s)
		content.WriteByte('\n')
	}
	content.WriteString("\n" + migrationUpDownMarker + "\n")
	content.WriteString("-- Prune migrations have no automatic DOWN - the original column\n")
	content.WriteString("-- shapes are gone. Restore by editing schema.prisma to re-add\n")
	content.WriteString("-- the columns; the next forward migration will ADD them.\n")
	if err := os.WriteFile(filePath, []byte(content.String()), 0644); err != nil {
		return PruneResult{}, fmt.Errorf("write migration: %w", err)
	}

	// Apply in a single transaction.
	tx, err := db.Begin()
	if err != nil {
		return PruneResult{}, fmt.Errorf("begin tx: %w", err)
	}
	rollback := func(cause error) (PruneResult, error) {
		_ = tx.Rollback()
		_ = os.Remove(filePath)
		return PruneResult{}, fmt.Errorf("prune: %w", cause)
	}
	for _, s := range stmts {
		if _, err := tx.Exec(s); err != nil {
			return rollback(fmt.Errorf("%s: %w", s, err))
		}
	}
	// Record as a pseudo-migration so subsequent boots don't re-warn.
	source, _ := os.ReadFile(filepath.Join(dir, "schema.prisma"))
	if _, err := tx.Exec(
		`INSERT INTO _benmore_migrations (name, source, source_hash) VALUES (?, ?, ?)`,
		filename, string(source), schemaHash(string(source)),
	); err != nil {
		return rollback(fmt.Errorf("record prune: %w", err))
	}
	if err := tx.Commit(); err != nil {
		return rollback(err)
	}

	result := PruneResult{MigrationFile: filename}
	for _, cc := range dropColumns {
		result.ColumnsDropped = append(result.ColumnsDropped, cc[0]+"."+cc[1])
	}
	result.TablesDropped = dropTables
	return result, nil
}
