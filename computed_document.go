//go:build !cli

package main

// computed.yaml checks shared by the load and the write gate.
//
// The write gate used to check only that computed.yaml was YAML (and, with a
// schema, that its tables and columns exist), so a push succeeded with files
// the reload then refused: a list entry without `table`, an `sql:` with two
// `?`, an expression SQLite cannot compile. The checks the load makes are now
// functions the gate calls too:
//
//	checkComputedDocument   the file's shape (the load's stageRuntimeConfig)
//	computedFieldIdentError names that are not plain identifiers (computed.go)
//	computedFieldTextError  expr / sql that are not one expression
//	the trigger install     run against an in-memory copy of the schema
//
// computedFieldTextError is new for both: a field's expr and sql are spliced
// into the trigger that keeps the column, and text that closed the
// expression and went on with statements of its own (`x) WHERE 0; DELETE
// FROM t; END --`) became a trigger that ran them on every write.
//
// A declaration that installs no trigger (no `on:`, `sql:` without
// `triggers:`, neither `expr:` nor `sql:`) still takes the column away from
// every client write, so it can be neither written nor calculated. The load
// keeps accepting a deployed file and logs each such field
// (logComputedProblems); the gate refuses the next write.

import (
	"fmt"
	"log"
	"maps"
	"slices"
	"strings"
)

// computedListFieldYAML is one entry of the `fields:` list form.
type computedListFieldYAML struct {
	Table    string                   `yaml:"table"`
	Column   string                   `yaml:"column"`
	Expr     string                   `yaml:"expr"`
	SQL      string                   `yaml:"sql"`
	Triggers []ComputedTriggerDefYAML `yaml:"triggers"`
}

var (
	computedListFieldKeys = yamlStructKeys(computedListFieldYAML{})
	computedFieldKeys     = yamlStructKeys(ComputedFieldYAML{})
	computedTriggerKeys   = yamlStructKeys(ComputedTriggerDefYAML{})
)

// computedTriggerEvents are the `on:` values a trigger takes.
var computedTriggerEvents = map[string]bool{"insert": true, "update": true, "delete": true}

var computedKeyHints = map[string]string{
	"expression":  "use `expr:`",
	"formula":     "use `expr:`",
	"value":       "use `expr:`",
	"query":       "use `sql:`",
	"select":      "use `sql:`",
	"trigger":     "use `triggers:` (a list)",
	"sources":     "use `triggers:`",
	"events":      "use `on:`",
	"when":        "a trigger takes `on: [insert, update, delete]`; put a condition inside the `sql:`",
	"foreign_key": "use `fk:`",
	"field":       "use `column:`",
	"name":        "use `column:`",
	"model":       "use `table:` with the table name",
	"source":      "use `table:`",
}

// checkComputedDocument is computed.yaml as the load reads it. The config is
// nil for a file that declares nothing. The load (stageRuntimeConfig) and the
// write gate (computedYAMLViolation) both call it.
func checkComputedDocument(data []byte) (*ComputedFieldConfig, error) {
	var document map[string]any
	if err := decodeConfigYAML(data, &document); err != nil {
		return nil, fmt.Errorf("computed.yaml: %w", err)
	}
	emptyList := false
	if fields, present := document["fields"]; present {
		entries, ok := fields.([]any)
		if fields != nil && !ok {
			if _, nested := fields.(map[string]any); !nested {
				return nil, fmt.Errorf("computed.yaml: fields must be a list or nested mapping")
			}
		}
		emptyList = (fields == nil || ok) && len(entries) == 0
		for _, entry := range entries {
			field, ok := entry.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("computed.yaml: field must be a mapping")
			}
			for _, key := range []string{"table", "column"} {
				value, ok := field[key].(string)
				if !ok || strings.TrimSpace(value) == "" {
					return nil, fmt.Errorf("computed.yaml: field requires %s", key)
				}
			}
		}
	}
	if emptyList {
		return nil, nil
	}
	config := parseComputedFieldsYAML(data)
	if len(document) != 0 && config == nil {
		return nil, fmt.Errorf("computed.yaml: invalid computed fields")
	}
	return config, nil
}

// computedFieldTextError refuses a field whose expr or sql is not one SQL
// expression, or carries a parameter the trigger cannot bind. Both are
// written between parentheses into the trigger's UPDATE; one expression (a
// subquery included) cannot leave them.
func computedFieldTextError(cf *ComputedField) error {
	if cf.Expr != "" {
		if problem := computedExpressionProblem(cf.Expr); problem != "" {
			return fmt.Errorf("computed.yaml: %s.%s: expr must be one SQL expression (%s)", cf.Table, cf.Column, problem)
		}
		if params := sqlCodeParameters(cf.Expr); len(params) > 0 {
			return fmt.Errorf("computed.yaml: %s.%s: expr takes no parameter (found %q); name the row's columns", cf.Table, cf.Column, cf.Expr[params[0]:min(params[0]+2, len(cf.Expr))])
		}
	}
	if cf.SQL != "" {
		if problem := computedExpressionProblem(cf.SQL); problem != "" {
			return fmt.Errorf("computed.yaml: %s.%s: sql must be one SQL expression, normally one SELECT (%s)", cf.Table, cf.Column, problem)
		}
		// The trigger replaces the text's first `?` with the changed row's
		// fk (computedAggregateTriggerSQL). SQLite refuses a trigger that
		// still holds a parameter after that.
		params := sqlCodeParameters(cf.SQL)
		first := strings.IndexByte(cf.SQL, '?')
		left := 0
		for _, at := range params {
			if at != first {
				left++
			}
		}
		if left > 0 {
			return fmt.Errorf("computed.yaml: %s.%s: sql takes one `?` (the id of the row being recalculated) and no other parameter; a trigger cannot bind more", cf.Table, cf.Column)
		}
	}
	return nil
}

// computedExpressionProblem says why text cannot sit between parentheses as
// one SQL expression, or "". Judged with the shared lexer, so a `;` or a
// parenthesis inside a quoted string or a comment does not count.
func computedExpressionProblem(text string) string {
	if strings.Contains(strings.ToLower(text), "load_extension") {
		return "load_extension is not allowed"
	}
	kinds := make([]sqlByteKind, 0, len(text))
	_ = scanSQLBytes(text, func(_ byte, k sqlByteKind) error {
		kinds = append(kinds, k)
		return nil
	})
	depth := 0
	for i := 0; i < len(text) && i < len(kinds); i++ {
		if kinds[i] != sqlCode {
			continue
		}
		switch text[i] {
		case ';':
			return "it holds a `;`, which ends a statement"
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return "it closes a parenthesis it did not open"
			}
		}
	}
	if depth != 0 {
		return "a parenthesis is not closed"
	}
	if len(kinds) == 0 {
		return ""
	}
	switch last := kinds[len(kinds)-1]; {
	case last.quoted() && !whenQuotedRegionClosed(text, kinds):
		return "a quoted string or name is not closed"
	case last == sqlInBlockComment && !strings.HasSuffix(text, "*/"):
		return "a comment is not closed"
	case last == sqlInLineComment:
		return "it ends in a `--` comment, which would swallow the rest of the trigger; end the line after the comment or remove it"
	}
	return ""
}

// sqlCodeParameters returns the offset of every bind parameter in s outside
// quotes and comments: `?`, `?NNN`, `:name`, `@name`, `$name`.
func sqlCodeParameters(s string) []int {
	kinds := make([]sqlByteKind, 0, len(s))
	_ = scanSQLBytes(s, func(_ byte, k sqlByteKind) error {
		kinds = append(kinds, k)
		return nil
	})
	code := func(i int) bool { return i >= 0 && i < len(s) && i < len(kinds) && kinds[i] == sqlCode }
	var at []int
	for i := 0; i < len(s); i++ {
		if !code(i) {
			continue
		}
		switch c := s[i]; {
		case c == '?',
			(c == ':' || c == '@') && code(i+1) && (isLetter(s[i+1]) || s[i+1] == '_'),
			c == '$' && (i == 0 || !code(i-1) || !sqlIdentByte(s[i-1])) && code(i+1) && sqlIdentByte(s[i+1]):
			at = append(at, i)
		}
	}
	return at
}

// computedFields lists a config's fields in table, column order.
func computedFields(config *ComputedFieldConfig) []*ComputedField {
	if config == nil {
		return nil
	}
	var out []*ComputedField
	for _, table := range slices.Sorted(maps.Keys(config.Fields)) {
		for _, column := range slices.Sorted(maps.Keys(config.Fields[table])) {
			if cf := config.Fields[table][column]; cf != nil {
				out = append(out, cf)
			}
		}
	}
	return out
}

// computedInertProblems lists the declared fields that are not calculated, or
// not on every change they name: nothing installs a trigger for them, yet
// their column is left out of every client write (computedColumns).
func computedInertProblems(config *ComputedFieldConfig) []string {
	var out []string
	const consequence = "Create and update requests still leave the column out, so it can be neither written nor calculated."
	for _, cf := range computedFields(config) {
		field := cf.Table + "." + cf.Column
		switch {
		case cf.Expr == "" && cf.SQL == "":
			out = append(out, fmt.Sprintf("computed.yaml: %s is not calculated: it has neither `expr:` (a same-row expression) nor `sql:` (a SELECT over another table). %s", field, consequence))
			continue
		case cf.Expr != "":
			continue
		case len(cf.Triggers) == 0:
			out = append(out, fmt.Sprintf("computed.yaml: %s is not calculated: its `sql:` has no `triggers:`, the list of tables whose changes recalculate it (- table: <child>, on: [insert, update, delete], fk: <column>). %s", field, consequence))
			continue
		}
		for _, trigger := range cf.Triggers {
			var known, unknown []string
			for _, event := range trigger.On {
				if computedTriggerEvents[event] {
					known = append(known, event)
				} else {
					unknown = append(unknown, fmt.Sprintf("%q", event))
				}
			}
			switch {
			case len(trigger.On) == 0:
				out = append(out, fmt.Sprintf("computed.yaml: %s is not calculated when %s changes: its trigger has no `on:` events. Add on: [insert, update, delete]. %s", field, trigger.Table, consequence))
			case len(unknown) > 0:
				runs := "none"
				if len(known) > 0 {
					runs = strings.Join(known, ", ")
				}
				out = append(out, fmt.Sprintf("computed.yaml: %s is not calculated on %s of %s: `on:` takes insert, update and delete (events it does recalculate on: %s).", field, strings.Join(unknown, ", "), trigger.Table, runs))
			}
		}
	}
	return out
}

// logComputedProblems logs, at every start and reload, each declared field
// that is not calculated.
func logComputedProblems(config *ComputedFieldConfig) {
	for _, msg := range computedInertProblems(config) {
		log.Printf("COMPUTED NOT RUNNING: %s", msg)
	}
}

// computedUnknownKeyProblems lists the keys in computed.yaml that the load
// drops: yaml decodes into its structs and ignores every key they do not
// bind, so `expression:` for `expr:` reads as a field with no expression.
func computedUnknownKeyProblems(data []byte) []string {
	var raw map[string]any
	if decodeConfigYAML(data, &raw) != nil {
		return nil
	}
	var out []string
	unknown := func(where string, written map[string]any, keys map[string]bool) {
		for _, key := range slices.Sorted(maps.Keys(written)) {
			if keys[key] {
				continue
			}
			hint := ""
			if h := computedKeyHints[strings.ToLower(key)]; h != "" {
				hint = " (" + h + ")"
			}
			out = append(out, fmt.Sprintf("computed.yaml: %s has the key %q, which is not read%s; the keys are %s.", where, key, hint, sortedKeyList(keys)))
		}
	}
	triggers := func(field string, v any) {
		list, _ := v.([]any)
		for i, entry := range list {
			if trigger, ok := entry.(map[string]any); ok {
				unknown(fmt.Sprintf("trigger %d of %s", i+1, field), trigger, computedTriggerKeys)
			}
		}
	}
	if list, ok := raw["fields"].([]any); ok && len(list) > 0 {
		// The list form: the load reads the list and nothing beside it.
		for _, key := range slices.Sorted(maps.Keys(raw)) {
			if key != "fields" {
				out = append(out, fmt.Sprintf("computed.yaml: the top-level key %q is not read: a file with a `fields:` list is read from that list alone. Move its fields into the list (- table: %s, column: ..., expr: ...).", key, key))
			}
		}
		for _, entry := range list {
			field, ok := entry.(map[string]any)
			if !ok {
				continue
			}
			name := fmt.Sprintf("%v.%v", field["table"], field["column"])
			unknown(name, field, computedListFieldKeys)
			triggers(name, field["triggers"])
		}
		return out
	}
	for _, table := range slices.Sorted(maps.Keys(raw)) {
		columns, _ := raw[table].(map[string]any)
		for _, column := range slices.Sorted(maps.Keys(columns)) {
			field, ok := columns[column].(map[string]any)
			if !ok {
				continue
			}
			name := table + "." + column
			unknown(name, field, computedFieldKeys)
			triggers(name, field["triggers"])
		}
	}
	return out
}

// computedYAMLViolation is the write gate for computed.yaml (write_file,
// push, deploy and `benmore check`): the load's own checks, the keys the load
// would drop, the fields that would not be calculated, and the trigger
// install against a copy of the schema. Tables and columns the schema lacks
// are reported by loadRefWriteCheck. "" when the file is clean.
func computedYAMLViolation(appDir, content string) string {
	config, err := checkComputedDocument([]byte(content))
	if err != nil {
		return err.Error()
	}
	lines := computedUnknownKeyProblems([]byte(content))
	// Fields on a framework table and triggers that name one: config drops
	// them, so the checks below never see them (config_framework_tables.go).
	lines = append(lines, computedFrameworkTableProblems([]byte(content))...)
	refused := false
	for _, cf := range computedFields(config) {
		if err := computedFieldIdentError(cf); err != nil {
			lines, refused = append(lines, err.Error()), true
			continue
		}
		if err := computedFieldTextError(cf); err != nil {
			lines, refused = append(lines, err.Error()), true
			continue
		}
		if cf.Expr != "" && cf.SQL != "" {
			lines = append(lines, fmt.Sprintf("computed.yaml: %s.%s has both `expr:` and `sql:`; each installs its own triggers and they overwrite one another. Keep one.", cf.Table, cf.Column))
		}
	}
	lines = append(lines, computedInertProblems(config)...)
	if !refused && appDir != "" {
		lines = append(lines, computedInstallProblems(appDir, content, config)...)
	}
	return strings.Join(lines, "\n")
}

// computedInstallProblems installs each field's triggers, with the load's own
// installer, into an in-memory database holding the schema's tables, and
// reports what the load would refuse: an expression SQLite cannot compile, a
// function that does not exist. A missing table or column is not reported
// here (loadRefWriteCheck judges those, with the migrations in view).
func computedInstallProblems(appDir, content string, config *ComputedFieldConfig) []string {
	schema := readLoadRefSchema(loadRefSource{dir: appDir, written: "computed.yaml", content: content})
	if schema == nil || schema.schemaDDL == "" {
		return nil
	}
	var fields []*ComputedField
	for _, cf := range computedFields(config) {
		judged := (cf.Expr != "" || cf.SQL != "") && schema.judged(cf.Table)
		for _, trigger := range cf.Triggers {
			judged = judged && schema.judged(trigger.Table)
		}
		if judged {
			fields = append(fields, cf)
		}
	}
	errs := computedTriggerInstallErrors(schema, fields)
	var out []string
	for _, cf := range fields {
		err := errs[cf]
		if err == nil || strings.Contains(err.Error(), "no such column") || strings.Contains(err.Error(), "no such table") {
			continue
		}
		out = append(out, fmt.Sprintf("computed.yaml: %s.%s cannot be installed (%v). The app cannot load with it: fix the expression.", cf.Table, cf.Column, err))
	}
	return out
}
