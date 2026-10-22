//go:build !cli

package main

// validators.yaml write gate. The loader (parseValidatorsYAML) keeps every
// rule it can decode and the evaluator (evaluateCrossFieldExpr) reads one
// `<operand> <op> <operand>` comparison, so a rule it can't read does
// nothing visible: a dropped key (`message:`), a misspelled column (`valeu
// >= 0` compares two constants), `value>=0` or `stage == 'won'` (no
// operator it recognizes: the rule is a constant and always passes),
// `a >= 0 AND a <= 9` (the second half is part of a literal) or a table the
// schema doesn't have (its rules never run). The write gate and `benmore
// check` refuse those; a deployed file still loads unchanged.

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

var (
	validatorRuleKeys = yamlStructKeys(ValidatorRule{})
	crossFieldIdentRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

func validatorsYAMLViolation(appDir, content string) string {
	if strings.TrimSpace(content) == "" {
		return ""
	}
	const shape = "\n\nShape: a list of rules per table, each `<column> <op> <column, number or 'quoted string'>` with a space on each side of one of != >= <= = > <:\n  deals:\n    - rule: \"value >= 0\"\n      error: \"Deal value cannot be negative\"\n    - rule: \"end_date > start_date\""
	var typed map[string][]ValidatorRule
	if err := decodeConfigYAML([]byte(content), &typed); err != nil {
		return fmt.Sprintf("validators.yaml: %v%s", err, shape)
	}
	var raw map[string]any
	if err := decodeConfigYAML([]byte(content), &raw); err != nil || len(raw) == 0 {
		return ""
	}
	var tables map[string]bool
	var columns map[string]map[string]bool
	if appDir != "" {
		tables = loadSchemaTableNames(appDir)
		columns = loadSchemaColumns(appDir)
	}
	var problems []string
	for _, table := range slices.Sorted(maps.Keys(raw)) {
		if len(tables) > 0 && !tables[table] {
			problems = append(problems, fmt.Sprintf("validators.yaml: table %q is not in the schema, so its rules never run (tables: %s).", table, sortedKeyList(tables)))
			continue
		}
		entries, _ := raw[table].([]any)
		for i, item := range entries {
			where := fmt.Sprintf("%s[%d]", table, i)
			entry, _ := item.(map[string]any)
			for _, key := range slices.Sorted(maps.Keys(entry)) {
				if !validatorRuleKeys[key] {
					problems = append(problems, fmt.Sprintf("validators.yaml %s: unknown key %q (valid: %s); the loader ignores it.", where, key, sortedKeyList(validatorRuleKeys)))
				}
			}
			rule, _ := entry["rule"].(string)
			if strings.TrimSpace(rule) == "" {
				problems = append(problems, fmt.Sprintf("validators.yaml %s: no `rule:`; an empty rule refuses every write to %s.", where, table))
				continue
			}
			if msg := crossFieldRuleProblem(rule, columns[table]); msg != "" {
				problems = append(problems, fmt.Sprintf("validators.yaml %s: rule %q %s.", where, rule, msg))
			}
		}
	}
	if len(problems) == 0 {
		return ""
	}
	return strings.Join(problems, "\n") + shape
}

// crossFieldRuleProblem says why evaluateCrossFieldExpr would not check
// rule as written, or "". cols is the table's columns (nil when unknown).
func crossFieldRuleProblem(rule string, cols map[string]bool) string {
	isColumn := func(s string) bool {
		if cols == nil {
			return crossFieldIdentRe.MatchString(s)
		}
		return cols[s]
	}
	left, right, found := splitCrossFieldRule(rule)
	if !found {
		s := strings.TrimSpace(rule)
		if !crossFieldIdentRe.MatchString(s) {
			return "has no comparison the validator reads (one of != >= <= = > < with a space on each side; no ==, AND, OR or &&), so it is a constant and always passes"
		}
		if !isColumn(s) {
			return fmt.Sprintf("checks %q, which is not a column of the table, so it is a constant and always passes", s)
		}
		return ""
	}
	for _, side := range []string{left, right} {
		if !crossFieldOperandOK(side) {
			return fmt.Sprintf("compares %q, which the validator reads as one literal value; write one comparison per rule with a column name, a number or a quoted string on each side (no AND/OR, functions or unquoted dates)", side)
		}
	}
	if cols != nil && !cols[left] && !cols[right] {
		return "compares two constants (neither side is a column of the table), so it always gives the same answer; check the column name"
	}
	return ""
}

// splitCrossFieldRule finds the comparison evaluateCrossFieldExpr applies:
// the first of its operators, in its order, written with a space on each
// side. Keep in step with evaluateCrossFieldExpr (validators.go).
func splitCrossFieldRule(expr string) (left, right string, found bool) {
	for _, op := range []string{"!=", ">=", "<=", "=", ">", "<"} {
		if idx := strings.Index(expr, " "+op+" "); idx >= 0 {
			return strings.TrimSpace(expr[:idx]), strings.TrimSpace(expr[idx+len(op)+2:]), true
		}
	}
	return "", "", false
}

// crossFieldOperandOK reports whether the evaluator reads s as one column
// name, number or quoted string (resolveFieldOrLiteral).
func crossFieldOperandOK(s string) bool {
	if len(s) >= 2 && (s[0] == '\'' || s[0] == '"') && s[len(s)-1] == s[0] {
		return true
	}
	if _, err := strconv.ParseFloat(s, 64); err == nil {
		return true
	}
	return crossFieldIdentRe.MatchString(s)
}
