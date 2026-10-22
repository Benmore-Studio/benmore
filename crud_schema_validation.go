//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// prismaWriteColumns uses the published schema generation, never a source file
// that might contain an unaccepted edit. SQL-only apps keep their legacy SQLite
// affinity semantics. Published columns are immutable; reload swaps the slice.
func prismaWriteColumns(app *App, table string) map[string]Column {
	app.mu.RLock()
	defer app.mu.RUnlock()
	var columns map[string]Column
	for _, t := range app.Tables {
		if !identIs(t.Name, table) {
			continue
		}
		for _, c := range t.Columns {
			if c.prismaScalar {
				if columns == nil {
					columns = make(map[string]Column)
				}
				columns[c.Name] = c
			}
		}
		break
	}
	return columns
}

var prismaNumberPattern = regexp.MustCompile(`^[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?$`)

func prismaNumericString(value any) (string, bool) {
	var s string
	switch v := value.(type) {
	case string:
		s = strings.TrimSpace(v)
	case json.Number:
		s = string(v)
	case float64, float32, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		s = fmt.Sprint(v)
	default:
		return "", false
	}
	return s, prismaNumberPattern.MatchString(s)
}

// normalizePrismaValue checks the original input shape before form conversion
// can turn false into a string, null into an empty value, or an object into text.
// Canonical strings preserve existing validators and hook parameter behavior.
func normalizePrismaValue(column Column, value any) (any, error) {
	invalid := func(want string) (any, error) { return nil, fmt.Errorf("%s must be %s", column.Name, want) }
	if value == nil {
		if column.NotNull {
			return invalid("non-null")
		}
		return nil, nil
	}
	switch strings.ToUpper(column.Type) {
	case "TEXT":
		if v, ok := value.(string); ok {
			return v, nil
		}
		return invalid("a string")
	case "BOOLEAN":
		if v, ok := value.(bool); ok {
			return jsonToFormValue(v), nil
		}
		if v, ok := value.(string); ok {
			switch strings.ToLower(strings.TrimSpace(v)) {
			case "true", "1":
				return "1", nil
			case "false", "0":
				return "0", nil
			}
		}
		if s, ok := prismaNumericString(value); ok {
			if s == "0" || s == "1" {
				return s, nil
			}
		}
		return invalid("a boolean (true/false or 1/0)")
	case "INTEGER":
		s, ok := prismaNumericString(value)
		if !ok {
			return invalid("an integer")
		}
		// Bound rational parsing before allocating for a caller-controlled exponent.
		// Any int64 can be expressed well within these limits, including exponent
		// notation and decimal strings such as 12.0 from number inputs.
		if len(s) > 256 {
			return invalid("a signed 64-bit integer")
		}
		if i := strings.IndexAny(s, "eE"); i >= 0 {
			exp, err := strconv.Atoi(s[i+1:])
			if err != nil || exp > 400 || exp < -400 {
				return invalid("a signed 64-bit integer")
			}
		}
		n, ok := new(big.Rat).SetString(s)
		if !ok || !n.IsInt() || !n.Num().IsInt64() {
			return invalid("a signed 64-bit integer")
		}
		return n.Num().String(), nil
	case "REAL":
		s, ok := prismaNumericString(value)
		if !ok {
			return invalid("a finite number")
		}
		n, err := strconv.ParseFloat(s, 64)
		if err != nil || math.IsNaN(n) || math.IsInf(n, 0) {
			return invalid("a finite number")
		}
		return s, nil
	case "DATETIME":
		if v, ok := value.(time.Time); ok {
			return v.UTC().Format(time.RFC3339Nano), nil
		}
		s, ok := value.(string)
		if !ok {
			return invalid("a valid date or date-time")
		}
		if _, ok := crossFieldInstant(s); !ok {
			return invalid("a valid date or date-time")
		}
		return s, nil
	case "BLOB":
		switch value.(type) {
		case string, []byte:
			return value, nil
		}
		return invalid("a string or bytes")
	}
	return value, nil
}

// prepareJSONCreateData retains Prisma input types for the canonical validator.
// Legacy SQL-schema creates retain null-as-omitted and form normalization.
func prepareJSONCreateData(input map[string]any, columns map[string]Column) map[string]any {
	out := make(map[string]any, len(input))
	for name, value := range input {
		if _, declared := columns[name]; declared {
			out[name] = value
		} else if value != nil {
			out[name] = jsonToFormValue(value)
		}
	}
	return out
}

func normalizePrismaFields(columns map[string]Column, input map[string]any, allowed func(string) bool) (map[string]any, error) {
	out := make(map[string]any, len(input))
	for name, value := range input {
		if column, declared := columns[name]; declared && allowed(name) {
			var err error
			value, err = normalizePrismaValue(column, value)
			if err != nil {
				return nil, err
			}
		}
		out[name] = value
	}
	return out, nil
}

func requirePrismaCreateFields(columns map[string]Column, input map[string]any, allowed func(string) bool) error {
	for name, column := range columns {
		if column.PK || !column.NotNull || column.Default != "" || !allowed(name) {
			continue
		}
		if _, sent := input[name]; !sent {
			return fmt.Errorf("%s is required", name)
		}
	}
	return nil
}

// UseNumber protects large numeric input values from float64 rounding. Row IDs
// retain their existing integral-number semantics: JSON 1.0 and 1e0 mean row 1,
// while string IDs still pass unchanged through the canonical ID checks.
func canonicalJSONNumberID(value any) any {
	if _, ok := value.(json.Number); ok {
		if normalized, err := normalizePrismaValue(Column{Type: "INTEGER", NotNull: true}, value); err == nil {
			return json.Number(normalized.(string))
		}
	}
	return value
}
