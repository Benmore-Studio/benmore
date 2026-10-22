//go:build !cli

package main

import (
	"database/sql"
	"fmt"
	"strings"
)

// materializeValidatorDefaults supplies omitted operands to cross-field rules.
// Evaluate only defaults a rule reads, and bind each evaluated value into the
// eventual INSERT: a volatile SQL default must not change after validation.
// Submitted values (including explicit NULL) and generated identity stay intact.
// Callers retain their original submitted-field set for hooks and field guards.
func materializeValidatorDefaults(tx *sql.Tx, config *ValidatorConfig, table string, cols []Column, fields *[]string, values *[]any) error {
	if config == nil || len(config.Rules[table]) == 0 {
		return nil
	}
	present := make(map[string]bool, len(*fields))
	for _, name := range *fields {
		present[name] = true
	}
	needed := map[string]bool{}
	for _, rule := range config.Rules[table] {
		left, right, comparison := splitCrossFieldRule(rule.Rule)
		if comparison {
			needed[left] = true
			needed[right] = true
		} else {
			needed[strings.TrimSpace(rule.Rule)] = true
		}
	}
	var names, expressions []string
	for _, col := range cols {
		if !needed[col.Name] || present[col.Name] || col.PK || col.Default == "" {
			continue
		}
		names = append(names, col.Name)
		expressions = append(expressions, "("+col.Default+")")
	}
	if len(names) == 0 {
		return nil
	}
	resolved := make([]any, len(names))
	dest := make([]any, len(names))
	for i := range resolved {
		dest[i] = &resolved[i]
	}
	// Expressions come from SQLite's own table metadata, never request text.
	if err := tx.QueryRow("SELECT " + strings.Join(expressions, ", ")).Scan(dest...); err != nil {
		return fmt.Errorf("resolve create defaults: %w", err)
	}
	for i, name := range names {
		*fields = append(*fields, name)
		*values = append(*values, resolved[i])
	}
	return nil
}
