//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// Boolean filter values. Reads return a BOOLEAN column as true/false (scanRows)
// and bm.d.ts types it `boolean`, but SQLite stores 1/0, so a filter bound as
// the text "true" matched nothing: `?where[published]=true`, `?published=false`
// and `bm.table(t).list({where: {published: true}})` answered [] and count 0.
// Filters on these columns now accept true/false (any case) and 1/0 and bind
// the stored integer, on every list surface (plain `?col=`, `where[col]=`,
// `__in`, `__ne` and the range operators; count, paged total and cursor share
// applyAPIWhereWithApp) and in /api/_query and report `sources:` where values.

// booleanFilterKind says how a column's filter values are checked.
type booleanFilterKind uint8

const (
	// booleanFilterLoose is a BOOLEAN column of a SQL-only app. Its write path
	// keeps SQLite's permissive affinity (any text is stored), so a value that
	// is no boolean still binds as written.
	booleanFilterLoose booleanFilterKind = iota + 1
	// booleanFilterStrict is a Prisma `Boolean`. Writes accept only
	// true/false/1/0, so any other filter value could match nothing and is
	// refused with 400 instead of an empty answer that reads as "no rows".
	booleanFilterStrict
)

// booleanFilterMessage is the accepted-values text every refusal carries.
const booleanFilterMessage = "true/false or 1/0"

func columnTypeIsBoolean(declared string) bool {
	t := strings.ToUpper(strings.TrimSpace(declared))
	return t == "BOOLEAN" || t == "BOOL"
}

// booleanFilterColumns maps each BOOLEAN-declared column of cols to its kind.
// nil when the table has none.
func booleanFilterColumns(app *App, table string, cols []Column) map[string]booleanFilterKind {
	var out map[string]booleanFilterKind
	var declared map[string]Column
	for _, c := range cols {
		if !columnTypeIsBoolean(c.Type) {
			continue
		}
		if out == nil {
			out = map[string]booleanFilterKind{}
			if app != nil {
				declared = prismaWriteColumns(app, table)
			}
		}
		kind := booleanFilterLoose
		if d, ok := declared[c.Name]; ok && columnTypeIsBoolean(d.Type) {
			kind = booleanFilterStrict
		}
		out[c.Name] = kind
	}
	return out
}

// listBooleanFilterColumns is booleanFilterColumns for the columns the list
// handler reads (crudTableColumns, which honors a connector's private read).
func listBooleanFilterColumns(r *http.Request, app *App, table string) map[string]booleanFilterKind {
	if app == nil {
		return nil
	}
	cols, err := crudTableColumns(r, app, table)
	if err != nil {
		return nil
	}
	return booleanFilterColumns(app, table, cols)
}

// parseBooleanFilterValue reads true/false (any case) and 1/0.
func parseBooleanFilterValue(s string) (int64, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "1":
		return 1, true
	case "false", "0":
		return 0, true
	}
	return 0, false
}

// booleanFilterOperand reports whether a list operator compares the column's
// value (LIKE matches text and is left as written).
func booleanFilterOperand(op string) bool {
	return op != "" && op != "LIKE"
}

// canonicalBooleanFilterText rewrites a list filter value (an `__in` value is
// a comma list) to the stored 1/0 text, which is also the plaintext a
// blind-indexed Boolean was hashed from. Parts that are no boolean are kept
// as written; ok is false when there was one.
func canonicalBooleanFilterText(value string, in bool) (string, bool) {
	parts := []string{value}
	if in {
		parts = strings.Split(value, ",")
	}
	ok := true
	for i, p := range parts {
		n, valid := parseBooleanFilterValue(p)
		if !valid {
			ok = false
			continue
		}
		parts[i] = fmt.Sprint(n)
	}
	return strings.Join(parts, ","), ok
}

// invalidBooleanListParam returns the first list filter (by parameter name)
// on a Prisma Boolean column whose value is no boolean, with the column and
// the offending value. handleList answers 400 for it.
func invalidBooleanListParam(r *http.Request, app *App, table string) (param, col, value string) {
	boolCols := listBooleanFilterColumns(r, app, table)
	if len(boolCols) == 0 {
		return "", "", ""
	}
	q := r.URL.Query()
	keys := make([]string, 0, len(q))
	for key := range q {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if apiFilterReservedParam(key) || len(q[key]) == 0 {
			continue
		}
		c, op := splitAPIFilterKey(key)
		if boolCols[c] != booleanFilterStrict || !booleanFilterOperand(op) {
			continue
		}
		raw := q[key][0]
		parts := []string{raw}
		if op == "IN" {
			parts = strings.Split(raw, ",")
		}
		for _, p := range parts {
			if _, ok := parseBooleanFilterValue(p); !ok {
				return key, c, p
			}
		}
	}
	return "", "", ""
}

func writeInvalidBooleanFilter(w http.ResponseWriter, table, param, col, value string) {
	httpJSON(w, http.StatusBadRequest, map[string]any{
		"error": fmt.Sprintf("%s.%s is a Boolean column: filter it with %s (got %q in %s).", table, col, booleanFilterMessage, value, param),
	})
}

// booleanQueryValue coerces an /api/_query (or report source) where value on
// a Boolean column: JSON/YAML booleans, the strings true/false/1/0 and the
// numbers 1/0 bind as 1/0. Anything else is an error on a Prisma Boolean and
// is passed through unchanged on a SQL-only BOOLEAN column.
func booleanQueryValue(kind booleanFilterKind, col string, v any) (any, error) {
	var n int64
	ok := false
	switch x := v.(type) {
	case bool:
		n, ok = 0, true
		if x {
			n = 1
		}
	case string:
		n, ok = parseBooleanFilterValue(x)
	case json.Number:
		n, ok = parseBooleanFilterValue(string(x))
	case float64, float32, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		n, ok = parseBooleanFilterValue(fmt.Sprint(x))
	}
	if ok {
		return n, nil
	}
	if kind == booleanFilterStrict {
		return nil, fmt.Errorf("where %s: %s is a Boolean column, use %s (got %v)", col, col, booleanFilterMessage, v)
	}
	return v, nil
}

// queryBooleanFilterColumns is booleanFilterColumns for a table of the
// published schema generation (the columns /api/_query validates against).
func queryBooleanFilterColumns(app *App, table string) map[string]booleanFilterKind {
	for _, t := range app.Tables {
		if t.Name == table {
			return booleanFilterColumns(app, table, t.Columns)
		}
	}
	return nil
}
