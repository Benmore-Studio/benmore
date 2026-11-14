//go:build !cli

package main

import (
	"fmt"
	"log"
	"maps"
	"os"
	"slices"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// AdminConfig is Django-ModelAdmin-style customisation of the auto-admin
// panel. Per table it hides the table, makes it or some of its columns
// read-only, chooses the columns shown and searched, or renames it.
//
// admin.yaml example:
//
//	tables:
//	  contacts:
//	    label: "Customers"
//	    columns: [name, email, phone, status, created_at]
//	    search: [name, email]
//	    readonly: [status]     # shown, never written by the panel
//	  ledger:
//	    readonly: true         # the whole table: shown, never written
//	  _benmore_users:
//	    hidden: true           # not in the panel at all
//
// Tables not mentioned in admin.yaml fall back to the default behavior
// (all columns shown, searched and editable). admin.yaml is opt-in - if
// absent, the admin panel works exactly as it did before. It is a panel
// setting: /api/<table> and the table's access: rule are unaffected.
type AdminConfig struct {
	Tables map[string]AdminTableConfig `yaml:"tables"`
}

// AdminTableConfig is per-table admin customisation.
type AdminTableConfig struct {
	Hidden   bool          `yaml:"hidden"`   // the table is not in the panel at all
	Label    string        `yaml:"label"`    // display name in the sidebar (default: the table name)
	Columns  []string      `yaml:"columns"`  // columns the pages show and the forms offer, in this order (default: all)
	Search   []string      `yaml:"search"`   // columns the list's search matches (default: the columns shown)
	Readonly adminReadonly `yaml:"readonly"` // true: the panel never writes the table; a list: never those columns
}

// adminReadonly is admin.yaml's `readonly:`: `true` for the whole table, or
// the list of columns the panel shows and never writes.
type adminReadonly struct {
	Table   bool
	Columns []string
}

func (a *adminReadonly) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.SequenceNode {
		return node.Decode(&a.Columns)
	}
	if node.Kind == yaml.ScalarNode && (node.Tag == "!!bool" || node.Tag == "!!null") {
		return node.Decode(&a.Table)
	}
	return fmt.Errorf("line %d: readonly takes true (the whole table) or a list of column names", node.Line)
}

// LoadAdminConfig reads admin.yaml from the app directory. Returns nil
// if the file is absent (which means the admin uses defaults - every
// non-internal table is shown with all columns).
func LoadAdminConfig(dir string) *AdminConfig {
	data, err := os.ReadFile(dir + "/admin.yaml")
	if err != nil {
		return nil
	}
	return parseAdminConfig(data)
}

func parseAdminConfig(data []byte) *AdminConfig {
	var cfg AdminConfig
	if err := yamlUnmarshal(data, &cfg); err != nil {
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

// table returns admin.yaml's entry for a table. Names compare as SQLite
// compares them: the table comes from a URL, and /_admin/Vault is the table
// admin.yaml configures as vault. Two entries for one table are refused at
// write time; of two in a deployed file, the first in name order is read.
func (a *AdminConfig) table(table string) AdminTableConfig {
	if a == nil {
		return AdminTableConfig{}
	}
	for _, name := range slices.Sorted(maps.Keys(a.Tables)) {
		if identIs(name, table) {
			return a.Tables[name]
		}
	}
	return AdminTableConfig{}
}

// IsTableHidden returns true if the table should be omitted from the admin.
// Returns false if AdminConfig is nil or the table has no entry.
func (a *AdminConfig) IsTableHidden(table string) bool {
	if a == nil {
		return false
	}
	for name, cfg := range a.Tables {
		if cfg.Hidden && identIs(name, table) {
			return true
		}
	}
	return false
}

// HiddenTables returns the names admin.yaml hides, as written there, for a
// panel read that leaves out the rows about them (the activity list).
func (a *AdminConfig) HiddenTables() []string {
	if a == nil {
		return nil
	}
	var names []string
	for name, cfg := range a.Tables {
		if cfg.Hidden {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// VisibleColumns returns the column allowlist for a table, or nil if no
// allowlist is configured (caller should show all columns).
func (a *AdminConfig) VisibleColumns(table string) []string {
	return a.table(table).Columns
}

// SearchColumns returns the columns the table's search matches, or nil when
// none are configured (the search then matches the columns shown).
func (a *AdminConfig) SearchColumns(table string) []string {
	return a.table(table).Search
}

// TableReadOnly reports `readonly: true`: the panel shows the table and
// never writes it.
func (a *AdminConfig) TableReadOnly(table string) bool {
	return a.table(table).Readonly.Table
}

// IsReadonly reports whether the panel shows a column and never writes it
// (`readonly: [column, ...]`).
func (a *AdminConfig) IsReadonly(table, column string) bool {
	for _, ro := range a.table(table).Readonly.Columns {
		if identIs(ro, column) {
			return true
		}
	}
	return false
}

// TableLabel returns the configured display label, or "" if none.
// Caller falls back to formatColName(table) when empty.
func (a *AdminConfig) TableLabel(table string) string {
	return a.table(table).Label
}

// The keys admin.yaml binds, from the loader's own struct tags.
var (
	adminFileKeys  = yamlStructKeys(AdminConfig{})
	adminTableKeys = yamlStructKeys(AdminTableConfig{})
)

// adminKeyHints names the key an author most likely meant.
var adminKeyHints = map[string]string{
	"read_only": "readonly", "read-only": "readonly", "readonly_fields": "readonly",
	"hide": "hidden", "visible": "hidden", "fields": "columns", "list_display": "columns",
	"search_fields": "search", "searchable": "search", "name": "label", "title": "label",
}

// adminYAMLViolation is the write gate's and `benmore check`'s reading of
// admin.yaml. The loader decodes into structs, which drops a key they do not
// declare: `read_only: true` or `hide: true` loaded clean and did nothing,
// with the table still written or still shown. It refuses such a key, a value
// of the wrong shape and two entries for one table. Table and column names
// are not checked against the schema, which the same write may be changing.
func adminYAMLViolation(content string) string {
	var raw map[string]any
	if err := yamlUnmarshal([]byte(content), &raw); err != nil {
		return "admin.yaml: " + err.Error()
	}
	var lines []string
	unknown := func(where, key string, known map[string]bool) {
		hint := ""
		if meant, ok := adminKeyHints[strings.ToLower(key)]; ok {
			hint = fmt.Sprintf(" Did you mean `%s:`?", meant)
		}
		lines = append(lines, fmt.Sprintf("admin.yaml: unknown key %q %s.%s Valid keys there: %s. The admin panel reads no other key, so this one would do nothing while the file reads as if it did.", key, where, hint, sortedKeyList(known)))
	}
	for _, key := range slices.Sorted(maps.Keys(raw)) {
		if !adminFileKeys[key] {
			unknown("at the top level", key, adminFileKeys)
		}
	}
	tables, isMap := raw["tables"].(map[string]any)
	if raw["tables"] != nil && !isMap {
		lines = append(lines, "admin.yaml: `tables:` takes a map of table name to its settings.")
	}
	stringList := func(v any) bool {
		list, ok := v.([]any)
		for _, item := range list {
			if _, isString := item.(string); !isString {
				return false
			}
		}
		return ok
	}
	seen := map[string]string{}
	for _, name := range slices.Sorted(maps.Keys(tables)) {
		if other, twice := seen[sqliteIdentifierFold(name)]; twice {
			lines = append(lines, fmt.Sprintf("admin.yaml: tables %q and %q are one table (names compare without regard to letter case), configured more than once. Keep one entry.", other, name))
		}
		seen[sqliteIdentifierFold(name)] = name
		if tables[name] == nil {
			continue
		}
		entry, isMap := tables[name].(map[string]any)
		if !isMap {
			lines = append(lines, fmt.Sprintf("admin.yaml: tables.%s takes a map of settings (%s), e.g. `%s: {hidden: true}`.", name, sortedKeyList(adminTableKeys), name))
			continue
		}
		for _, key := range slices.Sorted(maps.Keys(entry)) {
			value, where := entry[key], "tables."+name+"."+key
			_, isBool := value.(bool)
			_, isString := value.(string)
			switch {
			case !adminTableKeys[key]:
				unknown("in tables."+name, key, adminTableKeys)
			case key == "hidden" && !isBool:
				lines = append(lines, "admin.yaml: "+where+" takes true or false.")
			case key == "label" && !isString:
				lines = append(lines, "admin.yaml: "+where+" takes the name to show, as text.")
			case (key == "columns" || key == "search") && !stringList(value):
				lines = append(lines, "admin.yaml: "+where+" takes a list of column names, e.g. `"+key+": [name, email]`.")
			case key == "readonly" && !isBool && !stringList(value):
				lines = append(lines, "admin.yaml: "+where+" takes true (the panel never writes the table) or a list of column names it never writes, e.g. `readonly: [status]`.")
			}
		}
	}
	if len(lines) == 0 {
		// Whatever the checks above do not name, the loader's decode does.
		var config AdminConfig
		if err := decodeConfigYAML([]byte(content), &config); err != nil {
			lines = append(lines, "admin.yaml: "+err.Error())
		}
	}
	return strings.Join(lines, "\n")
}
