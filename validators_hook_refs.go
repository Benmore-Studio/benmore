//go:build !cli

package main

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
)

var (
	hookTemplateRefRe = regexp.MustCompile(`\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}`)
	hookColonRefRe    = regexp.MustCompile(`(^|[^:A-Za-z0-9_]):([A-Za-z_][A-Za-z0-9_]*)`)
)

// hookColumnRefWarnings names the `{{col}}` and `:col` references in
// hooks.yaml that match no column of the hooked table. The hook row holds the
// table's columns (and old_<column> on update hooks); an unknown `{{name}}`
// is left in the text as written and an unknown `:name` binds NULL, so a
// typo stored the wrong value or failed the hook when it ran ("not enough
// args"), visible only in the log while the write it hooked succeeded.
func hookColumnRefWarnings(appDir string) []string {
	data := readAppFileOrNil(appDir, "hooks.yaml")
	columns := loadSchemaColumns(appDir)
	if data == nil || columns == nil {
		return nil
	}
	var top map[string]map[string][]map[string]any
	if yamlUnmarshal(data, &top) != nil {
		return nil
	}
	var out []string
	for _, section := range slices.Sorted(maps.Keys(top)) {
		update := strings.HasSuffix(section, "_update")
		for _, table := range slices.Sorted(maps.Keys(top[section])) {
			cols := columns[table]
			if cols == nil {
				continue // an unknown table is reported by CrossFileWarnings
			}
			known := func(name string) bool {
				switch name {
				case "id", "user_id", "created_at", "updated_at", "deleted_at":
					return true
				}
				// Before-hook rows also carry the caller's session keys.
				if slices.Contains(whenSessionKeys, name) {
					return true
				}
				if cols[name] {
					return true
				}
				old, isOld := strings.CutPrefix(name, "old_")
				return update && isOld && (cols[old] || old == "id" || old == "user_id")
			}
			for i, hook := range top[section][table] {
				unknown := map[string]bool{}
				var walk func(key string, v any)
				walk = func(key string, v any) {
					switch t := v.(type) {
					case string:
						for _, m := range hookTemplateRefRe.FindAllStringSubmatch(t, -1) {
							if !known(m[1]) {
								unknown["{{"+m[1]+"}}"] = true
							}
						}
						if key == "sql" {
							for _, m := range hookColonRefRe.FindAllStringSubmatch(stripSQLLiterals(t), -1) {
								if !known(m[2]) {
									unknown[":"+m[2]] = true
								}
							}
						}
					case map[string]any:
						for k, x := range t {
							walk(k, x)
						}
					case []any:
						for _, x := range t {
							walk(key, x)
						}
					}
				}
				for k, v := range hook {
					if k == "when" {
						continue // SQL over the row's columns by name, checked by its own validator
					}
					walk(k, v)
				}
				if len(unknown) == 0 {
					continue
				}
				out = append(out, fmt.Sprintf("hooks.yaml: %s.%s[%d] references %s, which name no column of %s (columns: %s). An unknown `{{name}}` is left in the text as written and an unknown `:name` binds NULL, so the hook stores the wrong value or fails when it runs, seen only in the log.",
					section, table, i, strings.Join(slices.Sorted(maps.Keys(unknown)), ", "), table, strings.Join(slices.Sorted(maps.Keys(cols)), ", ")))
			}
		}
	}
	return out
}
