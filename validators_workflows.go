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
	if db := whenSchemaDB(appDir); db != nil {
		defer db.Close()
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
	for _, p := range workflowShapeProblems(string(data), column) {
		log.Printf("WARNING: %s", p)
	}
}
