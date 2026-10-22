//go:build !cli

package main

import (
	"cmp"
	"fmt"
	"log"
	"math"
	"os"
	"strconv"
	"strings"
	"time"
)

// Cross-field validators: declarative rules that check relationships between
// fields on INSERT and UPDATE. Defined in validators.yaml per table.
//
//   deals:
//     - rule: "value >= 0"
//       error: "Deal value cannot be negative"
//   events:
//     - rule: "end_date > start_date"
//       error: "End date must be after start date"

// ValidatorRule is a single validation rule for a table.
type ValidatorRule struct {
	Rule  string `yaml:"rule"`
	Error string `yaml:"error"`
}

// ValidatorConfig holds all cross-field validators keyed by table name.
type ValidatorConfig struct {
	Rules map[string][]ValidatorRule // table → rules
}

// LoadValidators reads validators.yaml.
func LoadValidators(dir string) *ValidatorConfig {
	path := dir + "/validators.yaml"
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return parseValidatorsYAML(data)
}

func parseValidatorsYAML(data []byte) *ValidatorConfig {
	var raw map[string][]ValidatorRule
	if err := yamlUnmarshal(data, &raw); err != nil {
		log.Printf("WARN: validators.yaml parse error: %s", err)
		return nil
	}

	if len(raw) == 0 {
		return nil
	}

	config := &ValidatorConfig{Rules: raw}
	total := 0
	for _, rules := range raw {
		total += len(rules)
	}
	log.Printf("  validators: %d rules across %d tables", total, len(raw))
	return config
}

// ValidateCrossField checks all cross-field rules for a table against the given data.
// Returns nil if all rules pass, or the first error message.
func ValidateCrossField(config *ValidatorConfig, table string, data map[string]any) error {
	if config == nil {
		return nil
	}
	rules, ok := config.Rules[table]
	if !ok {
		return nil
	}

	for _, rule := range rules {
		if !evaluateCrossFieldExpr(rule.Rule, data) {
			errMsg := rule.Error
			if errMsg == "" {
				errMsg = "Validation failed: " + rule.Rule
			}
			return fmt.Errorf("%s", errMsg)
		}
	}
	return nil
}

// evaluateCrossFieldExpr evaluates an expression where BOTH sides can be field names.
// "end_date > start_date" resolves both end_date and start_date from data.
// "value >= 0" resolves value from data and treats 0 as a literal.
// The write gate mirrors how it finds the comparison (splitCrossFieldRule).
func evaluateCrossFieldExpr(expr string, data map[string]any) bool {
	for _, op := range []string{"!=", ">=", "<=", "=", ">", "<"} {
		idx := strings.Index(expr, " "+op+" ")
		if idx < 0 {
			continue
		}
		left := strings.TrimSpace(expr[:idx])
		right := strings.TrimSpace(expr[idx+len(op)+2:])

		// Resolve both sides - try as field name first, fall back to literal
		leftVal := resolveFieldOrLiteral(left, data)
		rightVal := resolveFieldOrLiteral(right, data)

		switch op {
		case "=":
			return leftVal == rightVal
		case "!=":
			return leftVal != rightVal
		case ">", ">=", "<", "<=":
			order, ok := crossFieldCompare(leftVal, rightVal)
			if !ok {
				return false
			}
			switch op {
			case ">":
				return order > 0
			case ">=":
				return order >= 0
			case "<":
				return order < 0
			case "<=":
				return order <= 0
			}
		}
	}

	// No operator found - treat as truthy check
	val := resolveFieldOrLiteral(expr, data)
	return val != "" && val != "0" && val != "<nil>"
}

// crossFieldDateLayouts are the ISO-8601 date and date-time shapes an
// ordering rule compares as instants (a zone-less value reads as UTC;
// fractional seconds are accepted after the seconds field), plus the text
// of a scanned DATETIME value (time.Time's String form).
var crossFieldDateLayouts = []string{
	"2006-01-02",
	time.RFC3339,
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05",
	"2006-01-02 15:04:05Z07:00",
	"2006-01-02T15:04",
	"2006-01-02 15:04",
	"2006-01-02 15:04:05.999999999 -0700 MST",
}

func crossFieldInstant(s string) (time.Time, bool) {
	for _, layout := range crossFieldDateLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// crossFieldCompare orders two operands of a `<`/`>`/`<=`/`>=` rule: as
// numbers when each whole operand is one, as instants when each is an
// ISO-8601 date or date-time, otherwise as text. A numeric PREFIX is never
// read as the number ("2024-03-05" is not 2024, "12abc" is not 12). ok is
// false when the numbers can't be ordered (NaN): every comparison fails.
func crossFieldCompare(a, b string) (order int, ok bool) {
	af, aErr := strconv.ParseFloat(strings.TrimSpace(a), 64)
	bf, bErr := strconv.ParseFloat(strings.TrimSpace(b), 64)
	if aErr == nil && bErr == nil {
		if math.IsNaN(af) || math.IsNaN(bf) {
			return 0, false
		}
		return cmp.Compare(af, bf), true
	}
	if at, ok := crossFieldInstant(strings.TrimSpace(a)); ok {
		if bt, ok := crossFieldInstant(strings.TrimSpace(b)); ok {
			return at.Compare(bt), true
		}
	}
	return strings.Compare(a, b), true
}

// resolveFieldOrLiteral tries to look up a value from data by field name.
// If not found, returns the string as a literal (stripping quotes).
func resolveFieldOrLiteral(s string, data map[string]any) string {
	s = strings.TrimSpace(s)
	// Check if it's a quoted literal
	if (strings.HasPrefix(s, `"`) && strings.HasSuffix(s, `"`)) ||
		(strings.HasPrefix(s, `'`) && strings.HasSuffix(s, `'`)) {
		return s[1 : len(s)-1]
	}
	// Try as field name
	if val, ok := data[s]; ok && val != nil {
		return fmt.Sprintf("%v", val)
	}
	// Return as literal (could be a number like "0")
	return s
}
