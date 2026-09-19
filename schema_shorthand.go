//go:build !cli

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// SchemaShorthand parses schema.yaml (terse format) and generates SQL.
//
// Format:
//   contacts: name!, email, phone, company, type=lead
//   deals: title!, value:money, stage=new, contact:ref, notes
//   tasks: title!, due_date:date, done:bool, deal:ref
//
// Conventions:
//   name!        → name TEXT NOT NULL
//   email        → email TEXT
//   value:money  → value REAL
//   stage=new    → stage TEXT DEFAULT 'new'
//   contact:ref  → contact_id INTEGER REFERENCES contacts(id) (or TEXT if target is +uuid)
//   done:bool    → done BOOLEAN DEFAULT 0
//   due_date:date → due_date DATETIME
//   count:int    → count INTEGER
//   bio:text     → bio TEXT (explicit, same as default)
//
// Auto-added to every table:
//   id INTEGER PRIMARY KEY AUTOINCREMENT
//   created_at DATETIME DEFAULT CURRENT_TIMESTAMP
//
// Flags (append to table line):
//   +user        → adds user_id INTEGER
//   +timestamps  → adds updated_at DATETIME (created_at already auto-added)
//   +uuid        → uses TEXT PK with auto-generated UUID v4 instead of INTEGER AUTOINCREMENT

// LoadSchemaShorthand reads schema.yaml and returns generated SQL.
func LoadSchemaShorthand(dir string) string {
	path := filepath.Join(dir, "schema.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}

	// Try structured YAML first (models: section in app.yaml)
	var structured struct {
		Models map[string]string `yaml:"models"`
	}
	if err := yaml.Unmarshal(data, &structured); err == nil && len(structured.Models) > 0 {
		return generateSQL(structured.Models)
	}

	// Try flat YAML (just table: columns)
	var flat map[string]string
	if err := yaml.Unmarshal(data, &flat); err == nil && len(flat) > 0 {
		return generateSQL(flat)
	}

	return ""
}

// SQLiteUUID4Default is the SQLite expression that generates a UUID v4 string.
const SQLiteUUID4Default = `(lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-4' || substr(lower(hex(randomblob(2))),2) || '-' || substr('89ab',abs(random()) % 4 + 1, 1) || substr(lower(hex(randomblob(2))),2) || '-' || lower(hex(randomblob(6))))`

// GenerateSQLFromModels converts a models map to SQL CREATE TABLE statements.
func generateSQL(models map[string]string) string {
	// First pass: identify which tables use +uuid
	uuidTables := make(map[string]bool)
	for table, colSpec := range models {
		for _, part := range strings.Split(colSpec, ",") {
			if strings.TrimSpace(part) == "+uuid" {
				uuidTables[table] = true
			}
		}
	}

	var sb strings.Builder
	sb.WriteString("-- Auto-generated from schema.yaml\n\n")

	for table, colSpec := range models {
		sb.WriteString(generateTableSQL(table, colSpec, uuidTables))
		sb.WriteString("\n")
	}

	return sb.String()
}

func generateTableSQL(table, colSpec string, uuidTables map[string]bool) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (\n", table))

	isUUID := uuidTables[table]
	if isUUID {
		sb.WriteString(fmt.Sprintf("  id TEXT PRIMARY KEY DEFAULT %s,\n", SQLiteUUID4Default))
	} else {
		sb.WriteString("  id INTEGER PRIMARY KEY AUTOINCREMENT,\n")
	}

	addUser := false
	addTimestamps := false

	parts := strings.Split(colSpec, ",")
	var colDefs []string

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Check flags
		if part == "+user" {
			addUser = true
			continue
		}
		if part == "+timestamps" {
			addTimestamps = true
			continue
		}
		if part == "+uuid" {
			continue // already handled above
		}

		colDefs = append(colDefs, parseShorthandColumn(part, table, uuidTables))
	}

	for _, def := range colDefs {
		sb.WriteString(fmt.Sprintf("  %s,\n", def))
	}

	if addUser {
		sb.WriteString("  user_id INTEGER,\n")
	}

	if addTimestamps {
		sb.WriteString("  updated_at DATETIME,\n")
	}

	sb.WriteString("  created_at DATETIME DEFAULT CURRENT_TIMESTAMP\n")
	sb.WriteString(");\n")

	return sb.String()
}

func parseShorthandColumn(spec, table string, uuidTables map[string]bool) string {
	notNull := false
	defaultVal := ""
	colName := spec
	colType := "TEXT"

	// Check for NOT NULL: name!
	if strings.HasSuffix(colName, "!") {
		notNull = true
		colName = strings.TrimSuffix(colName, "!")
	}

	// Check for default value: stage=new
	if idx := strings.Index(colName, "="); idx > 0 {
		defaultVal = colName[idx+1:]
		colName = colName[:idx]
	}

	// Check for type annotation: value:money, contact:ref, done:bool
	if idx := strings.Index(colName, ":"); idx > 0 {
		typeHint := colName[idx+1:]
		colName = colName[:idx]

		switch typeHint {
		case "money", "decimal", "float", "real":
			colType = "REAL"
		case "int", "integer", "number":
			colType = "INTEGER"
		case "bool", "boolean":
			colType = "BOOLEAN"
			if defaultVal == "" {
				defaultVal = "0"
			}
		case "date", "datetime", "time":
			colType = "DATETIME"
		case "text":
			colType = "TEXT"
		case "ref":
			// Foreign key: contact:ref → contact_id INTEGER/TEXT REFERENCES contacts(id)
			refTable := colName + "s" // simple pluralization
			colName = colName + "_id"
			if uuidTables[refTable] {
				colType = "TEXT"
			} else {
				colType = "INTEGER"
			}
			def := fmt.Sprintf("%s %s REFERENCES %s(id)", colName, colType, refTable)
			if notNull {
				def += " NOT NULL"
			}
			return def
		default:
			colType = "TEXT" // unknown type hint, default to TEXT
		}
	} else {
		// Infer type from name
		lower := strings.ToLower(colName)
		switch {
		case lower == "email" || strings.HasSuffix(lower, "_email"):
			colType = "TEXT"
		case lower == "phone" || strings.HasSuffix(lower, "_phone"):
			colType = "TEXT"
		case strings.Contains(lower, "amount") || strings.Contains(lower, "price") || strings.Contains(lower, "value") || strings.Contains(lower, "cost") || strings.Contains(lower, "total"):
			colType = "REAL"
		case strings.Contains(lower, "count") || strings.Contains(lower, "quantity"):
			colType = "INTEGER"
		case strings.Contains(lower, "date") || strings.Contains(lower, "time") || lower == "due" || lower == "expires":
			colType = "DATETIME"
		case lower == "done" || lower == "active" || lower == "verified" || strings.HasPrefix(lower, "is_") || strings.HasPrefix(lower, "has_"):
			colType = "BOOLEAN"
			if defaultVal == "" {
				defaultVal = "0"
			}
		}
	}

	// Build column definition
	def := fmt.Sprintf("%s %s", colName, colType)
	if notNull {
		def += " NOT NULL"
	}
	if defaultVal != "" {
		// Quote string defaults, don't quote numeric/boolean
		if colType == "TEXT" {
			def += fmt.Sprintf(" DEFAULT '%s'", defaultVal)
		} else {
			def += fmt.Sprintf(" DEFAULT %s", defaultVal)
		}
	}

	return def
}

// WriteSchemaSQL generates schema.sql from schema.yaml.
func WriteSchemaSQL(dir string) error {
	sql := LoadSchemaShorthand(dir)
	if sql == "" {
		return fmt.Errorf("no schema.yaml found or empty")
	}

	outPath := filepath.Join(dir, "schema.sql")
	// Don't overwrite if schema.sql already exists and is newer
	if info, err := os.Stat(outPath); err == nil {
		yamlInfo, _ := os.Stat(filepath.Join(dir, "schema.yaml"))
		if yamlInfo != nil && info.ModTime().After(yamlInfo.ModTime()) {
			return nil // schema.sql is newer, skip
		}
	}

	return os.WriteFile(outPath, []byte(sql), 0644)
}
