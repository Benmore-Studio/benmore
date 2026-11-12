//go:build !cli

package main

// Review-time advice for an approved command whose SQL never names the caller.
//
// An approved command's apply checks the tool's permissions, validators,
// workflow guards, record locks and hooks, but not the written table's
// `access:` rule or row scope: which rows it may change is decided by its SQL
// alone. A command that updates or deletes rows (or inserts rows it selects
// from a table) with no binding from the actor anywhere therefore lets every
// holder of its permission change every row the SQL matches. That can be what
// the author means, so this is a warning and nothing else: `benmore mcp
// review`, `mcp check` and `mcp inspect` list it under `warnings`, `benmore
// check` and the check after a write report it as a warning, and it never
// refuses a file, changes a digest or touches an approval.
//
// The detection is deliberately narrow: a warning on a command that is bound
// to its caller is worse than a missed one. A command is left alone when
//
//   - any dependency param or any SQL binding of its prepare or apply phase
//     names the actor (user.id, user.group_id, user.email, user.role,
//     user.is_admin): the binding may gate a later statement through
//     expect_rows, a refusing prepare branch or a value sealed at prepare, and
//     this check does not try to prove that it doesn't;
//   - the write is a plain INSERT ... VALUES, or an INSERT ... SELECT that
//     reads no table (the insert-unless-exists idiom);
//   - a before-hook of that action on the written table reads a caller key, or
//     the statement names the state column of a workflow whose every
//     transition carries a role or a caller condition: both run inside the
//     command with the actor and can refuse it;
//   - the statement cannot be classified.
//
// Readback bindings are not counted: readback runs after the write.

import (
	"bytes"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// appMCPCommandCallerPredicateDocs is the reference key that states the rule.
const appMCPCommandCallerPredicateDocs = "connector.caller_predicate"

// commandActorRefText matches an authored binding that names the actor.
var commandActorRefText = regexp.MustCompile(`\$\{\{\s*user\.`)

// commandHookCallerKey matches a caller key as hook SQL and `when:` read it.
var commandHookCallerKey = regexp.MustCompile(`\buser_(id|email|role|roles|group_id)\b`)

// commandUnboundWrite is one apply statement that matches rows with no caller
// binding anywhere in its command.
type commandUnboundWrite struct{ Action, Table string }

// commandStepsBindActor reports whether any SQL step, nested steps included,
// binds an actor value.
func commandStepsBindActor(steps []FlowStep) bool {
	for _, step := range steps {
		for _, ref := range step.CommandSQLParams {
			if ref.Kind == "selected_tenant" || strings.HasPrefix(ref.Kind, "actor_") {
				return true
			}
		}
		for _, raw := range step.SQLParams {
			if commandActorRefText.MatchString(raw) {
				return true
			}
		}
		if commandStepsBindActor(step.Steps) || commandStepsBindActor(step.ElseSteps) {
			return true
		}
	}
	return false
}

// commandRowMatchingWrite classifies one apply statement: an UPDATE, a DELETE,
// or an INSERT whose own SELECT reads a table. ok is false for anything else,
// including a statement this cannot classify.
func commandRowMatchingWrite(query string) (write commandUnboundWrite, ok bool) {
	writes, statements := sqlWriteTargets(query)
	if statements != 1 || len(writes) != 1 {
		return commandUnboundWrite{}, false
	}
	write = commandUnboundWrite{Action: writes[0].Action, Table: writes[0].Table}
	if write.Action == "update" || write.Action == "delete" {
		return write, true
	}
	// INSERT: only the form whose SELECT has a FROM of its own and reads a
	// table. `INSERT ... SELECT :a WHERE NOT EXISTS (...)` inserts the bound
	// values and matches no row.
	tokens := sqlTokenize(stripSQLComments(query))
	depth, selected, from := 0, false, false
	for i := sqlStatementVerbIndex(tokens); i < len(tokens); i++ {
		token := tokens[i]
		if token.kind == sqlTokPunct {
			switch token.text {
			case "(":
				depth++
			case ")":
				depth--
			}
			continue
		}
		if depth != 0 || token.kind != sqlTokWord {
			continue
		}
		switch strings.ToUpper(token.text) {
		case "VALUES", "DEFAULT":
			if !selected {
				return commandUnboundWrite{}, false
			}
		case "SELECT":
			selected = true
		case "FROM":
			from = from || selected
		}
	}
	if !from {
		return commandUnboundWrite{}, false
	}
	if relations, err := commandSQLTableInventory(query); err != nil || len(relations) == 0 {
		return commandUnboundWrite{}, false
	}
	return write, true
}

// commandWriteGuardedOutsideSQL reports that a hook or a workflow guard which
// runs inside the command may tie this write to the caller.
func commandWriteGuardedOutsideSQL(write commandUnboundWrite, query string, hooks *HookConfig, workflows *WorkflowConfig) bool {
	fold := sqliteIdentifierFold(write.Table)
	if hooks != nil {
		before := map[string]map[string][]Hook{"insert": hooks.BeforeInsert, "update": hooks.BeforeUpdate, "delete": hooks.BeforeDelete}[write.Action]
		for table, list := range before {
			if sqliteIdentifierFold(table) != fold {
				continue
			}
			for _, hook := range list {
				if commandHookCallerKey.MatchString(hook.SQL) || commandHookCallerKey.MatchString(hook.When) {
					return true
				}
			}
		}
	}
	if workflows == nil || write.Action != "update" {
		return false
	}
	for _, workflow := range workflows.Workflows {
		if workflow == nil || workflow.Field == "" ||
			sqliteIdentifierFold(workflow.Table) != fold && sqliteIdentifierFold(workflow.ConfiguredTable) != fold {
			continue
		}
		// Every transition must carry a guard: one open transition is a state
		// change any holder of the permission can make on any row.
		guarded, transitions := true, 0
		for _, targets := range workflow.Transitions {
			for _, transition := range targets {
				transitions++
				guarded = guarded && (transition.Role != "" || commandHookCallerKey.MatchString(transition.When))
			}
		}
		if !guarded || transitions == 0 {
			continue
		}
		for _, token := range sqlTokenize(stripSQLComments(query)) {
			if (token.kind == sqlTokWord || token.kind == sqlTokIdent) && sqliteIdentifierFold(token.text) == sqliteIdentifierFold(workflow.Field) {
				return true
			}
		}
	}
	return false
}

// appMCPCommandCallerUnboundWrites lists the apply statements of one command
// flow that match rows while nothing in the command is bound to the caller.
// It is empty for every flow the rules at the top of this file leave alone.
func appMCPCommandCallerUnboundWrites(flow Flow, hooks *HookConfig, workflows *WorkflowConfig) []commandUnboundWrite {
	command := flow.Command
	if command == nil {
		return nil
	}
	for _, dependency := range command.Dependencies {
		for _, ref := range dependency.Params {
			if ref.Kind == "actor_id" || ref.Kind == "selected_tenant" {
				return nil
			}
		}
	}
	if commandStepsBindActor(command.Prepare.Steps) || commandStepsBindActor(command.Apply.Steps) {
		return nil
	}
	var found []commandUnboundWrite
	seen := map[commandUnboundWrite]bool{}
	var walk func([]FlowStep)
	walk = func(steps []FlowStep) {
		for _, step := range steps {
			if step.Type == "sql" && step.SQL != "" {
				write, ok := commandRowMatchingWrite(step.SQL)
				if ok && !seen[write] && !commandWriteGuardedOutsideSQL(write, step.SQL, hooks, workflows) {
					seen[write] = true
					found = append(found, write)
				}
			}
			walk(step.Steps)
			walk(step.ElseSteps)
		}
	}
	walk(command.Apply.Steps)
	sort.Slice(found, func(i, j int) bool {
		if found[i].Table != found[j].Table {
			return found[i].Table < found[j].Table
		}
		return found[i].Action < found[j].Action
	})
	return found
}

// appMCPCommandCallerPredicateWarning is the advice for one command flow, or
// "" when there is none. The text says what is missing, what to add and where
// the rule is written.
func appMCPCommandCallerPredicateWarning(flow Flow, hooks *HookConfig, workflows *WorkflowConfig) string {
	writes := appMCPCommandCallerUnboundWrites(flow, hooks, workflows)
	if len(writes) == 0 {
		return ""
	}
	parts := make([]string, 0, len(writes))
	for _, write := range writes {
		verb := map[string]string{"update": "UPDATE", "delete": "DELETE FROM", "insert": "INSERT ... SELECT into"}[write.Action]
		parts = append(parts, verb+" "+write.Table)
	}
	where := fmt.Sprintf("command %q", flow.Name)
	if flow.Source != "" {
		where = flow.Source + ": " + where
	}
	return fmt.Sprintf("%s has no predicate tied to the caller: its apply SQL matches rows (%s) and no dependency, prepare or apply SQL binding names the actor "+
		"(`${{ user.id }}`, `${{ user.group_id }}`, `${{ user.email }}`, `${{ user.role }}` or `${{ user.is_admin }}`). "+
		"A command is not checked against the table's `access:` rule or row scope, so every caller who holds its permission can change every row this SQL matches. "+
		"If that is not what you mean, add the owner or tenant predicate to the prepare SQL and the apply SQL, bound from the actor and never from an argument: "+
		"`AND user_id = :actor` with `params: {actor: '${{ user.id }}'}`, and on a tenant-keyed table `AND <tenant column> = :tenant` with `tenant: '${{ user.group_id }}'`. "+
		"This is advice only: the command loads and review binds it either way. Read `benmore docs %s`.",
		where, strings.Join(parts, ", "), appMCPCommandCallerPredicateDocs)
}

// appMCPCommandCallerPredicateWarnings is the advice for every command flow of
// a loaded configuration, in flow-name order.
func appMCPCommandCallerPredicateWarnings(flows []Flow, hooks *HookConfig, workflows *WorkflowConfig) []string {
	var warnings []string
	for _, flow := range flows {
		if warning := appMCPCommandCallerPredicateWarning(flow, hooks, workflows); warning != "" {
			warnings = append(warnings, warning)
		}
	}
	sort.Strings(warnings)
	return warnings
}

// appMCPCommandCallerPredicateFindings is the same advice for `benmore check`
// / check_app and the check after a write: for the command flow just written,
// or for every command flow on a full check and after a write of a file other
// files depend on (the schema, app.yaml, mcp.yaml). A write of any other file
// reports only its own file's warnings (writeRelevantFindings), so a
// hooks.yaml or workflows.yaml write that lifts or uncovers the warning shows
// at the next of those.
// A file that does not compile is the write gate's to refuse, not this one's.
func appMCPCommandCallerPredicateFindings(dir, writtenPath string, liveDB bool) []CheckFinding {
	files := flowFilesFor(dir, writtenPath)
	if liveDB || writtenPath != "" && writeAffectsOtherFiles(writtenPath) {
		files = flowFilesFor(dir, "")
	}
	var commands []Flow
	var definitions []crudTableDefinition
	for _, rel := range files {
		rel = filepath.ToSlash(rel)
		if !isFlowsSubdirFile(rel) {
			continue
		}
		data, err := readFileInRoot(dir, rel)
		// The cheap test first: most flow files declare no command.
		if err != nil || !bytes.Contains(data, []byte("command:")) || !commandDeclarationPresent(string(data)) {
			continue
		}
		if definitions == nil {
			if definitions, err = appMCPSchemaTableDefinitions(dir); err != nil || definitions == nil {
				return nil
			}
		}
		flow, err := parseFlowCommandFileColumns(rel, data, eligibleCRUDTables(definitions), commandColumnInventory(definitions))
		if err != nil {
			continue
		}
		flow.Source = rel
		commands = append(commands, flow)
	}
	if len(commands) == 0 {
		return nil
	}
	// A hooks.yaml or workflows.yaml that cannot be read or parsed may hold
	// the guard: say nothing rather than guess.
	var hooks *HookConfig
	var workflows *WorkflowConfig
	if data, err := readOptionalConfig(dir, "hooks.yaml"); err != nil {
		return nil
	} else if data != nil {
		if hooks, err = parseHooksYAML(data); err != nil {
			return nil
		}
	}
	if data, err := readOptionalConfig(dir, "workflows.yaml"); err != nil {
		return nil
	} else if data != nil {
		if workflows, err = parseWorkflowsYAML(data); err != nil {
			return nil
		}
	}
	var findings []CheckFinding
	for _, flow := range commands {
		if warning := appMCPCommandCallerPredicateWarning(flow, hooks, workflows); warning != "" {
			findings = append(findings, CheckFinding{Severity: "warning", Source: "mcp_connector", File: flow.Source, Message: warning})
		}
	}
	return findings
}
