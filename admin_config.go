//go:build !cli

package main

import (
	"log"
	"os"

	"gopkg.in/yaml.v3"
)

// AdminConfig is Django-ModelAdmin-style customisation of the auto-admin
// panel. Per-table you can hide a table, restrict columns, add search
// fields, override the display label, or mark fields as readonly.
//
// admin.yaml example:
//
//	tables:
//	  contacts:
//	    label: "Customers"
//	    columns: [name, email, phone, status, created_at]
//	    search: [name, email]
//	    readonly: [created_at]
//	  _benmore_users:
//	    hidden: true   # don't expose internal user table in admin
//	  audit_log:
//	    columns: [action, table_name, user_email, created_at]
//	    readonly: [action, table_name, user_email, created_at]
//
// Tables not mentioned in admin.yaml fall back to the default behavior
// (all columns shown, all editable, no search). admin.yaml is opt-in —
// if absent, the admin panel works exactly as it did before.
type AdminConfig struct {
	Tables map[string]AdminTableConfig `yaml:"tables"`
}

// AdminTableConfig is per-table admin customisation.
type AdminTableConfig struct {
	Hidden   bool     `yaml:"hidden"`   // omit this table from the admin sidebar entirely
	Label    string   `yaml:"label"`    // display name in the sidebar (default: title-cased table name)
	Columns  []string `yaml:"columns"`  // columns to show in the table view (default: all)
	Search   []string `yaml:"search"`   // columns to search across (default: none — search disabled)
	Readonly []string `yaml:"readonly"` // columns that cannot be edited from admin (default: none)
}

// LoadAdminConfig reads admin.yaml from the app directory. Returns nil
// if the file is absent (which means the admin uses defaults — every
// non-internal table is shown with all columns).
func LoadAdminConfig(dir string) *AdminConfig {
	data, err := os.ReadFile(dir + "/admin.yaml")
	if err != nil {
		return nil
	}
	var cfg AdminConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		log.Printf("WARN: admin.yaml parse error: %s", err)
		return nil
	}
	if len(cfg.Tables) == 0 {
		return nil
	}
	hidden := 0
	for _, t := range cfg.Tables {
		if t.Hidden {
			hidden++
		}
	}
	log.Printf("  admin.yaml: %d table configs (%d hidden)", len(cfg.Tables), hidden)
	return &cfg
}

// IsTableHidden returns true if the table should be omitted from the admin.
// Returns false if AdminConfig is nil or the table has no entry.
func (a *AdminConfig) IsTableHidden(table string) bool {
	if a == nil {
		return false
	}
	cfg, ok := a.Tables[table]
	return ok && cfg.Hidden
}

// VisibleColumns returns the column allowlist for a table, or nil if no
// allowlist is configured (caller should show all columns).
func (a *AdminConfig) VisibleColumns(table string) []string {
	if a == nil {
		return nil
	}
	cfg, ok := a.Tables[table]
	if !ok {
		return nil
	}
	return cfg.Columns
}

// SearchColumns returns columns enabled for search on a table, or nil.
func (a *AdminConfig) SearchColumns(table string) []string {
	if a == nil {
		return nil
	}
	cfg, ok := a.Tables[table]
	if !ok {
		return nil
	}
	return cfg.Search
}

// IsReadonly reports whether a column on a table should be uneditable
// in the admin UI. Useful for fields like created_at, system IDs, etc.
func (a *AdminConfig) IsReadonly(table, column string) bool {
	if a == nil {
		return false
	}
	cfg, ok := a.Tables[table]
	if !ok {
		return false
	}
	for _, ro := range cfg.Readonly {
		if ro == column {
			return true
		}
	}
	return false
}

// TableLabel returns the configured display label, or "" if none.
// Caller falls back to formatColName(table) when empty.
func (a *AdminConfig) TableLabel(table string) string {
	if a == nil {
		return ""
	}
	cfg, ok := a.Tables[table]
	if !ok {
		return ""
	}
	return cfg.Label
}
