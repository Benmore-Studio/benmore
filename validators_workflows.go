//go:build !cli

package main

// Shape checks for workflows.yaml that the typed parser can't make.
//
// yaml.v3 drops keys the target struct doesn't declare, so a workflow key
// the runtime doesn't read (`timeouts:` for `timeout:`, `roles:` on a
// transition) parsed clean and did nothing - a guard that never applied, a
// timeout that never fired. A name that isn't one of the workflow's states
// (a misspelled `initial`, an on_transition or timeout under a state no
// transition reaches) is equally inert. The write gate and `benmore check`
// refuse these (validateWorkflowsShape); a file that is already deployed
// still loads and each problem is logged (warnWorkflowShape), so an
// upgrade never takes a running app down over one.

import (
	"fmt"
	"log"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

var (
	workflowKeys           = yamlStructKeys(WorkflowYAML{})
	workflowTransitionKeys = yamlStructKeys(TransitionYAML{})
	workflowTimeoutKeys    = yamlStructKeys(TimeoutYAML{})
)

// workflowKeyHints names the key an author most likely meant.
var workflowKeyHints = map[string]string{
	"timeouts":       "timeout",
	"on_transitions": "on_transition",
	"on_enter":       "on_transition",
	"initial_state":  "initial",
	"start":          "initial",
	"column":         "field",
	"state_field":    "field",
	"state":          "field",
	"model":          "table",
	"roles":          "role",
	"condition":      "when",
	"if":             "when",
	"guard":          "when",
	"target":         "to",
	"duration":       "after",
}

func workflowUnknownKey(where, key string, valid map[string]bool) string {
	msg := fmt.Sprintf("workflows.yaml %s: unknown key %q (valid: %s). The runtime ignores it, so it would do nothing.",
		where, key, strings.Join(slices.Sorted(maps.Keys(valid)), ", "))
	if hint := workflowKeyHints[key]; hint != "" && valid[hint] {
		msg += fmt.Sprintf(" Did you mean `%s:`?", hint)
	}
	return msg
}

// workflowShapeProblems lists what a workflows.yaml declares that the
// runtime would ignore or could never act on. column reports whether a
// table has a column; known is false when there is no schema to judge.
func workflowShapeProblems(content string, column func(table, col string) (has, known bool)) []string {
	var shaped map[string]map[string]any
	if err := decodeConfigYAML([]byte(content), &shaped); err != nil {
		return nil // the typed parser reports syntax and shape errors
	}
	var typed map[string]WorkflowYAML
	if err := decodeConfigYAML([]byte(content), &typed); err != nil {
		return nil
	}
	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }
	for _, name := range sortedWhenKeys(shaped) {
		raw, wy := shaped[name], typed[name]
		if name == "workflows" && raw["table"] == nil {
			add("workflows.yaml: there is no `workflows:` wrapper - each top-level key IS a workflow (`orders: { table: orders, field: status, transitions: ... }`). Under the wrapper the parser reads one workflow named \"workflows\" with no table, so nothing is enforced.")
			continue
		}
		// A workflow on a framework table is not loaded at all, so nothing
		// else about it is worth saying (config_framework_tables.go).
		if msg := workflowFrameworkTableProblem(name, wy.Table); msg != "" {
			problems = append(problems, msg)
			continue
		}
		for _, key := range sortedWhenKeys(raw) {
			if !workflowKeys[key] {
				problems = append(problems, workflowUnknownKey(name, key, workflowKeys))
			}
		}
		if strings.TrimSpace(wy.Table) == "" || strings.TrimSpace(wy.Field) == "" {
			add("workflows.yaml %s: `table:` and `field:` are required (the table and the column that holds the state).", name)
		} else {
			// table and field are spliced into the transition SQL (table is
			// also a route pattern); a plain identifier only.
			if !membershipIdentRe.MatchString(strings.TrimSpace(wy.Table)) {
				add("workflows.yaml %s: `table:` %q is not a plain identifier (letters, digits and _ only, not starting with a digit).", name, wy.Table)
			}
			if !membershipIdentRe.MatchString(strings.TrimSpace(wy.Field)) {
				add("workflows.yaml %s: `field:` %q is not a plain identifier (letters, digits and _ only, not starting with a digit).", name, wy.Field)
			}
			// A state column the table lacks guards nothing. Case alone is
			// fine: the loader rewrites it to the schema's spelling.
			if column != nil {
				if has, known := column(strings.TrimSpace(wy.Table), strings.TrimSpace(wy.Field)); known && !has {
					add("workflows.yaml %s: `field:` %q is not a column of table %q, so no state is enforced. Name the column that holds the state.", name, wy.Field, wy.Table)
				}
			}
		}
		if transitions, ok := raw["transitions"].(map[string]any); ok {
			for _, from := range sortedWhenKeys(transitions) {
				targets, _ := transitions[from].(map[string]any)
				for _, to := range sortedWhenKeys(targets) {
					rule, _ := targets[to].(map[string]any)
					for _, key := range sortedWhenKeys(rule) {
						if !workflowTransitionKeys[key] {
							problems = append(problems, workflowUnknownKey(fmt.Sprintf("%s.transitions.%s -> %s", name, from, to), key, workflowTransitionKeys))
						}
					}
					// The runtime keeps such a role as a gate only an admin passes.
					if role := string(wy.Transitions[from][to].Role); role != "" && len(workflowRoleNames(role)) == 0 {
						add("workflows.yaml %s.transitions.%s -> %s: `role: %q` names no role, so only an admin could make the transition. Name the role (`role: manager`) or several (`role: \"owner, manager\"` or `role: [owner, manager]`, any one passes), or drop the key to let anyone who may update the row make it.", name, from, to, role)
					}
				}
			}
		}
		if timeouts, ok := raw["timeout"].(map[string]any); ok {
			for _, state := range sortedWhenKeys(timeouts) {
				rule, _ := timeouts[state].(map[string]any)
				for _, key := range sortedWhenKeys(rule) {
					if !workflowTimeoutKeys[key] {
						problems = append(problems, workflowUnknownKey(fmt.Sprintf("%s.timeout.%s", name, state), key, workflowTimeoutKeys))
					}
				}
			}
		}
		if hooks, ok := raw["on_transition"].(map[string]any); ok {
			for _, state := range sortedWhenKeys(hooks) {
				entries, _ := hooks[state].([]any)
				for i, e := range entries {
					entry, _ := e.(map[string]any)
					for _, key := range sortedWhenKeys(entry) {
						if !hookEntryKeys[key] {
							add("workflows.yaml %s.on_transition.%s[%d]: unknown key %q (valid: %s). The runtime ignores it, so the hook would fire and do nothing.",
								name, state, i, key, strings.Join(hookEntryKeyList, ", "))
						}
					}
					if msg := hookEntrySubKeyViolation(entry, fmt.Sprintf("workflows.yaml: %s.on_transition.%s[%d]", name, state, i)); msg != "" {
						problems = append(problems, msg)
					}
				}
			}
		}

		// The state set: `states:` when declared, else every state a
		// transition names (as a from or a to).
		declared := len(wy.States) > 0
		states := map[string]bool{}
		for i, s := range wy.States {
			s = strings.TrimSpace(s)
			switch {
			case s == "":
				add("workflows.yaml %s.states[%d]: empty state name.", name, i)
			case states[s]:
				add("workflows.yaml %s.states: %q is listed twice.", name, s)
			}
			states[s] = true
		}
		if !declared {
			for from, targets := range wy.Transitions {
				states[from] = true
				for to := range targets {
					states[to] = true
				}
			}
			// A timeout reaches its target too (a terminal state like
			// `delivered` needs no transition out).
			for _, rule := range wy.Timeout {
				if to := strings.TrimSpace(rule.To); to != "" {
					states[to] = true
				}
			}
		}
		stateList := strings.Join(slices.Sorted(maps.Keys(states)), ", ")
		unknownState := func(where, state string) {
			if declared {
				add("workflows.yaml %s: %q is not in `states:` (%s). Add it there or fix the name.", where, state, stateList)
			} else {
				add("workflows.yaml %s: %q is not a state any transition names (%s), so nothing can reach it. Fix the name, or list every state under `states:`.", where, state, stateList)
			}
		}
		if len(states) > 0 {
			if wy.Initial != "" && !states[wy.Initial] {
				unknownState(name+".initial", wy.Initial)
			}
			if declared {
				for _, from := range sortedWhenKeys(wy.Transitions) {
					if !states[from] {
						unknownState(fmt.Sprintf("%s.transitions (from)", name), from)
					}
					for _, to := range sortedWhenKeys(wy.Transitions[from]) {
						if !states[to] {
							unknownState(fmt.Sprintf("%s.transitions.%s (to)", name, from), to)
						}
					}
				}
			}
			for _, state := range sortedWhenKeys(wy.OnTransition) {
				if !states[state] {
					unknownState(name+".on_transition", state)
				}
			}
			for _, state := range sortedWhenKeys(wy.Timeout) {
				if !states[state] {
					unknownState(name+".timeout", state)
				}
			}
		}
		for _, state := range sortedWhenKeys(wy.Timeout) {
			rule := wy.Timeout[state]
			if parseWorkflowDuration(strings.TrimSpace(rule.After)) <= 0 {
				add("workflows.yaml %s.timeout.%s: after %q is not a duration (use 30m, 24h or 7d); the timeout would never fire.", name, state, rule.After)
			}
			switch to := strings.TrimSpace(rule.To); {
			case to == "":
				add("workflows.yaml %s.timeout.%s: `to:` is required (the state to move rows to).", name, state)
			case len(states) > 0 && !states[to]:
				unknownState(fmt.Sprintf("%s.timeout.%s.to", name, state), to)
			}
			if wy.Table != "" && column != nil {
				if has, known := column(wy.Table, "updated_at"); known && !has {
					add("workflows.yaml %s.timeout: table %q has no updated_at column. A timeout measures time since the row's updated_at, so it could never fire; add `updated_at DateTime @updatedAt` to the model.", name, wy.Table)
				}
			}
		}
	}
	return problems
}

// validateWorkflowsShape is the write-time and `benmore check` form.
func validateWorkflowsShape(appDir, content string) string {
	var column func(table, col string) (bool, bool)
	var columnsOf func(table string) []Column
	if db := whenSchemaDB(appDir); db != nil {
		defer db.Close()
		columnsOf = func(table string) []Column {
			cols, _ := tableColumnsWith(db, table)
			return cols
		}
		column = func(table, col string) (bool, bool) {
			cols, err := tableColumnsWith(db, table)
			if err != nil || len(cols) == 0 {
				return false, false
			}
			for _, c := range cols {
				if strings.EqualFold(c.Name, col) {
					return true, true
				}
			}
			return false, true
		}
	}
	problems := workflowShapeProblems(content, column)
	problems = append(problems, workflowDefaultProblems(content, columnsOf, workflowSchemaFile(appDir))...)
	problems = append(problems, workflowEncryptedStateProblems(content,
		parseEncryptedFieldsConfig(readAppFileOrNil(appDir, "encrypted.yaml"), readAppFileOrNil(appDir, "app.yaml")))...)
	if len(problems) == 0 {
		return ""
	}
	return strings.Join(problems, "\n") + "\n\nSee api({at:'workflows'}) → keys."
}

// warnWorkflowShape logs, at load, each problem in the app's workflows.yaml.
// It never refuses the app.
func warnWorkflowShape(app *App) {
	if app == nil || app.Dir == "" || app.Workflows == nil {
		return
	}
	data, err := os.ReadFile(filepath.Join(app.Dir, "workflows.yaml"))
	if err != nil {
		return
	}
	column := func(table, col string) (bool, bool) {
		for _, t := range app.Tables {
			if t.Name == table {
				return hasColumn(app, table, col), true
			}
		}
		return false, false
	}
	problems := workflowShapeProblems(string(data), column)
	problems = append(problems, workflowDefaultProblems(string(data), func(table string) []Column {
		for _, t := range app.Tables {
			if sqliteIdentifierFold(t.Name) == sqliteIdentifierFold(table) {
				return t.Columns
			}
		}
		return nil
	}, workflowSchemaFile(app.Dir))...)
	problems = append(problems, workflowEncryptedStateProblems(string(data), app.Encrypted)...)
	for _, p := range problems {
		log.Printf("WARNING: %s", p)
	}
}

// workflowDefaultProblems names each workflow whose state column has a
// column default other than `initial`. A create through the API starts in
// `initial` regardless, but a flow, hook or SQL insert that leaves the column
// out takes the default, a state the workflow does not start in. A column
// with no default, or an explicit NULL one, stores NULL either way and is not
// named. schemaFile (workflowSchemaFile) words the fix for the file the
// default is declared in. The write gate, `benmore check` and the load
// warning all call this one function.
func workflowDefaultProblems(content string, columnsOf func(table string) []Column, schemaFile string) []string {
	if columnsOf == nil {
		return nil
	}
	var typed map[string]WorkflowYAML
	if err := decodeConfigYAML([]byte(content), &typed); err != nil {
		return nil
	}
	var problems []string
	for _, name := range sortedWhenKeys(typed) {
		wy := typed[name]
		initial := strings.TrimSpace(wy.Initial)
		if initial == "" {
			continue
		}
		for _, c := range columnsOf(strings.TrimSpace(wy.Table)) {
			if !strings.EqualFold(c.Name, strings.TrimSpace(wy.Field)) {
				continue
			}
			state, shown, ok := workflowDefaultState(c.Default)
			if !ok || state == initial {
				continue
			}
			problems = append(problems, fmt.Sprintf("workflows.yaml %s: %s.%s has column default %s but `initial:` is %q. A row inserted by a flow, hook or SQL that leaves the column out would start in %s, not %q. %s",
				name, wy.Table, c.Name, strings.TrimSpace(c.Default), initial, shown, initial, workflowDefaultFix(schemaFile, initial)))
		}
	}
	return problems
}

// workflowDefaultState reads a column default, as the SQL text PRAGMA
// table_info or the schema's DDL gives it, the way SQLite applies it. ok is
// false for a column with no default or an explicit NULL one: both store
// NULL. state is what a row left to the default holds and shown is how a
// message names it. SQLite stores a default written as a name as that text,
// so DEFAULT "draft", DEFAULT `draft` and DEFAULT [draft] are the string
// 'draft', like DEFAULT 'draft' and DEFAULT ('draft'). Stripping parentheses
// and single quotes only refused the first three with "would start in
// "draft", not "draft"", and refused DEFAULT NULL.
func workflowDefaultState(sqlText string) (state, shown string, ok bool) {
	def := strings.TrimSpace(sqlText)
	for len(def) >= 2 && def[0] == '(' && def[len(def)-1] == ')' {
		def = strings.TrimSpace(def[1 : len(def)-1])
	}
	if def == "" || strings.EqualFold(def, "NULL") {
		return "", "", false
	}
	if n := len(def); n >= 2 {
		inner, quote := def[1:n-1], ""
		switch open, end := def[0], def[n-1]; {
		case open == '[' && end == ']':
			if !strings.ContainsAny(inner, "[]") {
				return inner, fmt.Sprintf("%q", inner), true
			}
		case open == end && (open == '\'' || open == '"' || open == '`'):
			quote = def[:1]
		}
		// One quoted value: every quote character inside it is doubled.
		if quote != "" && !strings.Contains(strings.ReplaceAll(inner, quote+quote, ""), quote) {
			state = strings.ReplaceAll(inner, quote+quote, quote)
			return state, fmt.Sprintf("%q", state), true
		}
	}
	// A bare word, a number or an expression: compared as written.
	return def, strings.TrimSpace(sqlText), true
}

// workflowSchemaFile names the file an app declares its column defaults in,
// in the order the schema loader reads them (loadSchemaWithReaderCtx):
// schema.prisma, else schema.sql. Empty when the app has neither.
func workflowSchemaFile(appDir string) string {
	if appDir == "" {
		return ""
	}
	for _, name := range []string{"schema.prisma", "schema.sql"} {
		if _, err := os.Stat(filepath.Join(appDir, name)); err == nil {
			return name
		}
	}
	return ""
}

// workflowDefaultFix is the last sentence of a workflowDefaultProblems
// message: the default to declare, in the syntax of the app's schema file.
func workflowDefaultFix(schemaFile, initial string) string {
	switch schemaFile {
	case "schema.prisma":
		return fmt.Sprintf("In schema.prisma, give the field `@default(%q)` (or drop the default).", initial)
	case "schema.sql":
		return fmt.Sprintf("In schema.sql, give the column `DEFAULT '%s'` (or drop the default).", strings.ReplaceAll(initial, "'", "''"))
	}
	return "Make the column default equal `initial:` (or drop the default)."
}

// workflowEncryptedStateIssue judges the app's on-disk workflows.yaml against
// an encryption config being written (encrypted.yaml or app.yaml `encrypted:`),
// so encrypting a state column that has a timeout is refused when the
// encryption is declared, not only when workflows.yaml is next written.
func workflowEncryptedStateIssue(appDir string, encData, appData []byte) string {
	if appDir == "" {
		return ""
	}
	wf := readAppFileOrNil(appDir, "workflows.yaml")
	if len(wf) == 0 {
		return ""
	}
	return strings.Join(workflowEncryptedStateProblems(string(wf), parseEncryptedFieldsConfig(encData, appData)), "\n")
}

// workflowEncryptedStateProblems names each workflow with a timeout whose state
// column is encrypted. The column stores ciphertext, so the timeout checker's
// `state = ?` select and its conditional UPDATE never match and no timeout
// ever fires; equality on the state is meaningless there.
func workflowEncryptedStateProblems(content string, enc *EncryptedFieldConfig) []string {
	if enc == nil || len(enc.Fields) == 0 {
		return nil
	}
	var typed map[string]WorkflowYAML
	if err := decodeConfigYAML([]byte(content), &typed); err != nil {
		return nil
	}
	var problems []string
	for _, name := range sortedWhenKeys(typed) {
		wy := typed[name]
		if len(wy.Timeout) == 0 {
			continue // transitions read the decrypted state; only timeouts compare the stored one
		}
		for table, defs := range enc.Fields {
			if sqliteIdentifierFold(table) != sqliteIdentifierFold(strings.TrimSpace(wy.Table)) {
				continue
			}
			for _, def := range defs {
				if sqliteIdentifierFold(def.Column) == sqliteIdentifierFold(strings.TrimSpace(wy.Field)) {
					problems = append(problems, fmt.Sprintf("workflows.yaml %s: state column %s.%s is encrypted, so it holds ciphertext and the timeout checker's state comparison can never match: its `timeout:` would never fire. Stop encrypting the state column (encrypted.yaml / app.yaml `encrypted:`); keep the sensitive data in another column.", name, table, def.Column))
				}
			}
		}
	}
	return problems
}
