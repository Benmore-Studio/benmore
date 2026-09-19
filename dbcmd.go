//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DBSchema prints the live database schema to stdout.
func DBSchema(db *sql.DB) {
	tables, _ := GetTableNames(db)
	for _, name := range tables {
		cols, _ := GetTableColumns(db, name)
		fmt.Printf("TABLE %s:\n", name)
		for _, c := range cols {
			extra := ""
			if c.PK {
				extra += " PRIMARY KEY"
			}
			if c.NotNull {
				extra += " NOT NULL"
			}
			if c.Default != "" {
				extra += " DEFAULT " + c.Default
			}
			fmt.Printf("  %-20s %s%s\n", c.Name, c.Type, extra)
		}
		fmt.Println()
	}
}

// DBQuery executes a SQL query and prints results as JSON.
func DBQuery(db *sql.DB, sqlStr string) {
	rows, err := QueryRows(db, sqlStr)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		return
	}
	data, _ := json.MarshalIndent(rows, "", "  ")
	fmt.Println(string(data))
}

// DBCounts prints row counts for all tables.
func DBCounts(db *sql.DB) {
	tables, _ := GetTableNames(db)
	counts := make(map[string]int64)
	for _, name := range tables {
		var count int64
		db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s", name)).Scan(&count)
		counts[name] = count
	}
	data, _ := json.MarshalIndent(counts, "", "  ")
	fmt.Println(string(data))
}

// DBBackup creates a manual backup of data.db.
func DBBackup(dir string) {
	path, err := scheduledBackup(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Backup failed: %s\n", err)
		os.Exit(1)
	}
	if path == "" {
		fmt.Println("No database found to back up.")
		return
	}
	fmt.Printf("Backup created: %s\n", path)
}

// DBRollback restores the database from a backup.
// Supports --list to show available backups.
func DBRollback(dir string) {
	if hasFlag("list") {
		backups := listAllBackups(dir)
		if len(backups) == 0 {
			fmt.Println("No backups found.")
			return
		}
		fmt.Println("Available backups (newest last):")
		for _, b := range backups {
			name := filepath.Base(b)
			// Parse timestamp from filename
			ts := name
			kind := "migrate"
			if strings.HasPrefix(ts, backupPrefix) {
				ts = strings.TrimPrefix(ts, backupPrefix)
				kind = "migrate"
			} else if strings.HasPrefix(ts, scheduledBackupPrefix) {
				ts = strings.TrimPrefix(ts, scheduledBackupPrefix)
				kind = "scheduled"
			}
			ts = strings.TrimSuffix(ts, ".db")
			if t, err := time.Parse("20060102T150405Z", ts); err == nil {
				info, _ := os.Stat(b)
				size := int64(0)
				if info != nil {
					size = info.Size()
				}
				fmt.Printf("  %s  [%s] (%s, %.1f MB)\n", name, kind, t.Local().Format("2006-01-02 15:04:05"), float64(size)/1024/1024)
			} else {
				fmt.Printf("  %s\n", name)
			}
		}
		return
	}

	backups := listAllBackups(dir)
	if len(backups) == 0 {
		fmt.Fprintln(os.Stderr, "No backups available. Run migrations first to create a backup.")
		os.Exit(1)
	}

	// Use most recent backup
	latest := backups[len(backups)-1]
	fmt.Printf("Restoring from: %s\n", filepath.Base(latest))

	if err := restoreDatabase(dir, latest); err != nil {
		fmt.Fprintf(os.Stderr, "Rollback failed: %s\n", err)
		os.Exit(1)
	}

	fmt.Println("Database restored successfully.")
}
