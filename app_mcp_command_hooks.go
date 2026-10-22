//go:build !cli

package main

import (
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"

	"github.com/mattn/go-sqlite3"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// Command hook parity.
//
// A command's apply SQL is raw SQL, so the CRUD hook pipeline never sees it.
// For a table whose captured hooks.yaml declares SQL hooks, the owner decision
// is that the command must run them exactly as an ordinary CRUD write would:
// before-hooks against the pre-write state (a refusal aborts the whole
// command), on-hooks after the write, all in the command's own transaction,
// through the same functions CRUD uses (fireBeforeHooksRows, fireAfterHooksTx,
// evaluateWhen, interpolateRowSafeForApp). Only the row derivation is new:
// authored SQL names no row, so the statement is probed inside a SAVEPOINT
// (RETURNING * yields the affected rows), rolled back, the before-hooks run,
// and the statement is then run for real.
//
// The hooks come from cap.generation (the captured, execution-digest-pinned
// hooks.yaml), never from the live app directory.

// appMCPCommandHookProbeSavepoint is the only savepoint a command may open.
const appMCPCommandHookProbeSavepoint = "benmore_command_hook_probe"

// appMCPCommandHookFrameworkTable reports the framework-owned tables a hook
// may write although command SQL may not (and which have no revision ledger).
func appMCPCommandHookFrameworkTable(name string) bool {
	return strings.EqualFold(name, "_benmore_notifications")
}

func appMCPHookSets(hooks *HookConfig, action string) (before, on map[string][]Hook) {
	if hooks == nil {
		return nil, nil
	}
	switch action {
	case "insert":
		return hooks.BeforeInsert, hooks.OnInsert
	case "update":
		return hooks.BeforeUpdate, hooks.OnUpdate
	case "delete":
		return hooks.BeforeDelete, hooks.OnDelete
	}
	return nil, nil
}

// appMCPHookKey reports whether hooks.yaml declares hooks for the physical app
// table and action. Like CRUD (app.Hooks.X[table]) the key must match exactly.
func appMCPHookKey(hooks *HookConfig, table, action string) (string, bool) {
	before, on := appMCPHookSets(hooks, action)
	if len(before[table]) > 0 || len(on[table]) > 0 {
		return table, true
	}
	return "", false
}

// appMCPHookActions are every action a table's hooks can be keyed under.
var appMCPHookActions = []string{"insert", "update", "delete"}

func appMCPTableHasAnyHook(hooks *HookConfig, table string) bool {
	for _, action := range appMCPHookActions {
		if _, ok := appMCPHookKey(hooks, table, action); ok {
			return true
		}
	}
	return false
}

// commandSQLUpsertShape reports statements whose conflict handling can update
// or delete rows beneath an insert (ON CONFLICT, OR REPLACE, REPLACE INTO).
// Their action classification would skip the update/delete hooks.
func commandSQLUpsertShape(query string) bool {
	tokens := sqlTokenize(stripSQLComments(query))
	word := func(i int, text string) bool {
		return i >= 0 && i < len(tokens) && tokens[i].kind == sqlTokWord && strings.EqualFold(tokens[i].text, text)
	}
	if word(0, "REPLACE") {
		return true
	}
	for i := range tokens {
		if word(i, "OR") && word(i+1, "REPLACE") || word(i, "ON") && word(i+1, "CONFLICT") {
			return true
		}
	}
	return false
}

// physicalTable resolves an authored table name to the captured app table's
// exact name.
func (cap *appMCPCommandCapability) physicalTable(name string) (string, bool) {
	for _, candidate := range cap.generation.view.Tables {
		if sqliteIdentifierFold(candidate.Name) == sqliteIdentifierFold(name) {
			return candidate.Name, true
		}
	}
	return "", false
}

// appMCPCommandHooksCompatible refuses, at declaration time, apply SQL whose
// upsert shape would skip the hooks of a table that has any.
func appMCPCommandHooksCompatible(generation *appMCPRuntimeGeneration, command *FlowCommand) error {
	if generation == nil || generation.hooks == nil || command == nil {
		return nil
	}
	var walk func([]FlowStep) error
	walk = func(steps []FlowStep) error {
		for _, step := range steps {
			if step.Type == "sql" && commandSQLUpsertShape(step.SQL) {
				for _, target := range mustCommandWriteTargets(step.SQL) {
					for _, candidate := range generation.view.Tables {
						if sqliteIdentifierFold(candidate.Name) == sqliteIdentifierFold(target.Table) && appMCPTableHasAnyHook(generation.hooks, candidate.Name) {
							return fmt.Errorf("command SQL on %q uses ON CONFLICT / OR REPLACE / REPLACE INTO, which would skip that table's hooks", candidate.Name)
						}
					}
				}
			}
			if err := walk(step.Steps); err != nil {
				return err
			}
			if err := walk(step.ElseSteps); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(command.Apply.Steps)
}

// appMCPCommandHookError is a hook refusal or failure inside a command. The
// coordinator maps it to the hook_refused result code and logs it with the
// operation id; Message is set only for an author-written refusal.
type appMCPCommandHookError struct {
	Table, Action string
	Refused       bool
	Message       string
	cause         error
}

func (e *appMCPCommandHookError) Error() string {
	if e.Refused {
		return fmt.Sprintf("command %s hook refused the write to %s: %s", e.Action, e.Table, e.Message)
	}
	return fmt.Sprintf("command %s hook failed on %s: %v", e.Action, e.Table, e.cause)
}
func (e *appMCPCommandHookError) Unwrap() error { return e.cause }

func newAppMCPCommandHookError(table, action string, err error, before bool) *appMCPCommandHookError {
	var private canonicalPrivateHookFailure
	if !before || errors.As(err, &private) {
		return &appMCPCommandHookError{Table: table, Action: action, cause: err}
	}
	// A before-hook's author-written error text; bounded and printable so it
	// is safe to hand to the connector client.
	message := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, err.Error())
	if len(message) > 200 {
		message = message[:200]
	}
	return &appMCPCommandHookError{Table: table, Action: action, Refused: true, Message: message, cause: err}
}

// appMCPCommandHookRowsRepeat checks that the real run touched exactly the
// rows the savepoint probe did, in the same order.
func appMCPCommandHookRowsRepeat(probe, real []map[string]any) error {
	if len(probe) != len(real) {
		return errors.New("command hooked write was not repeatable")
	}
	for i := range probe {
		a, errA := commandHookRowID(probe[i])
		b, errB := commandHookRowID(real[i])
		if errA != nil || errB != nil || a != b {
			return errors.New("command hooked write was not repeatable")
		}
	}
	return nil
}

// appMCPCommandWrite is one (table, action) the command changed; with the
// tables hooks wrote it feeds the post-commit real-time broadcast.
type appMCPCommandWrite struct{ Table, Action string }

type appMCPWorkflowTransitionState struct {
	Table, Workflow, From string
	RowID                 any
}

type appMCPCommandBroadcast struct {
	Table, Action, GroupID string
	UserID                 int64
}

func (cap *appMCPCommandCapability) noteWrite(table, action string) {
	entry := appMCPCommandWrite{table, action}
	if !slices.Contains(cap.writes, entry) {
		cap.writes = append(cap.writes, entry)
	}
}

func (cap *appMCPCommandCapability) noteStatementWrites(targets []sqlWrite) {
	for _, target := range targets {
		if physical, ok := cap.physicalTable(target.Table); ok {
			cap.noteWrite(physical, target.Action)
		}
	}
}

func (cap *appMCPCommandCapability) noteHookRefresh(tables []string) {
	for _, table := range tables {
		if !slices.Contains(cap.hookRefresh, table) {
			cap.hookRefresh = append(cap.hookRefresh, table)
		}
	}
}

// appMCPCommandBroadcasts derives the post-commit events from the recorded
// effects exactly as the canonical update path does.
func appMCPCommandBroadcasts(view *App, writes []appMCPCommandWrite, hookRefresh []string, actor Session) []appMCPCommandBroadcast {
	var events []appMCPCommandBroadcast
	for _, write := range writes {
		groupID, userID := canonicalUpdateBroadcastScope(view, write.Table, actor)
		events = append(events, appMCPCommandBroadcast{write.Table, write.Action, groupID, userID})
	}
	for _, refresh := range canonicalHookRefreshScopes(view, hookRefresh, "", actor) {
		events = append(events, appMCPCommandBroadcast{refresh.Table, "refresh", refresh.GroupID, refresh.UserID})
	}
	return events
}

// appMCPCommandHookIsSQL is the SQL-only predicate shared with the canonical
// update path and fireAfterHooksTx: any other action kind is delivery work.
func appMCPCommandHookIsSQL(hook Hook) bool {
	return hook.SQL != "" && hook.Webhook == "" && hook.Email == nil && hook.Notify == nil && hook.WS == nil && hook.SMS == nil
}

// appMCPCommandApplyWrites lists the (table, action) pairs the apply steps can
// write, exactly as the SQL steps are classified at run time.
func appMCPCommandApplyWrites(command *FlowCommand) map[string]map[string]bool {
	writes := make(map[string]map[string]bool)
	if command == nil {
		return writes
	}
	var walk func([]FlowStep)
	walk = func(steps []FlowStep) {
		for _, step := range steps {
			if step.Type == "sql" {
				for _, target := range mustCommandWriteTargets(step.SQL) {
					if writes[target.Table] == nil {
						writes[target.Table] = map[string]bool{}
					}
					writes[target.Table][target.Action] = true
				}
			}
			walk(step.Steps)
			walk(step.ElseSteps)
		}
	}
	walk(command.Apply.Steps)
	return writes
}

func appMCPCommandNeedsRowParity(cap *appMCPCommandCapability, table, action string) bool {
	if cap == nil || cap.generation == nil {
		return false
	}
	if appMCPTableHasAnyHook(cap.generation.hooks, table) || cap.anyWebhookSubscribed(table) {
		return true
	}
	if action == "insert" || action == "update" {
		if cap.generation.validators != nil {
			for name, rules := range cap.generation.validators.Rules {
				if sqliteIdentifierFold(name) == sqliteIdentifierFold(table) && len(rules) > 0 {
					return true
				}
			}
		}
		if cap.generation.computed != nil {
			for name, fields := range cap.generation.computed.Fields {
				if sqliteIdentifierFold(name) == sqliteIdentifierFold(table) && len(fields) > 0 {
					return true
				}
			}
		}
		if cap.generation.view.Encrypted != nil {
			for name, fields := range cap.generation.view.Encrypted.Fields {
				if sqliteIdentifierFold(name) == sqliteIdentifierFold(table) && len(fields) > 0 {
					return true
				}
			}
		}
	}
	if cap.generation.workflows != nil {
		for _, workflow := range cap.generation.workflows.Workflows {
			if workflow != nil && sqliteIdentifierFold(workflow.Table) == sqliteIdentifierFold(table) {
				return true
			}
		}
	}
	for _, flow := range cap.generation.flows {
		if sqliteIdentifierFold(flow.Trigger.Table) == sqliteIdentifierFold(table) && flow.Trigger.Type == "on_"+action {
			return true
		}
	}
	return false
}

// appMCPCommandHookEffectsSupported narrows the old blanket hook refusal. A
// before-hook must be read-only SQL. An on-hook is either plain SQL, whose
// writes must be revision-enrolled (or a framework inbox table), or a delivery
// action (email, sms, webhook, notify, ws) that is queued as a durable job; one
// hook may not mix the two, because the SQL half would then run after commit
// outside this transaction. Checked before any command write.
func appMCPCommandHookEffectsSupported(cap *appMCPCommandCapability, table, action string) error {
	before, on := appMCPHookSets(cap.generation.hooks, action)
	enrolled := commandTableSet(cap.effectTables())
	for index, set := range []map[string][]Hook{before, on} {
		for _, hook := range set[table] {
			if !appMCPCommandHookIsSQL(hook) {
				if index == 0 {
					return errors.New("command target has unsupported canonical hooks (before-hooks must be read-only SQL)")
				}
				if hook.SQL != "" {
					return errors.New("command target has unsupported canonical hooks (a hook cannot mix SQL with a delivery action)")
				}
				continue
			}
			if err := appMCPCommandRejectFTSStorageReferences(cap.generation, hook.SQL); err != nil {
				return fmt.Errorf("command target has unsupported canonical hooks: %w", err)
			}
			writes, err := appMCPRevisionHookWrites(hook.SQL)
			if err != nil {
				return fmt.Errorf("command target has unsupported canonical hooks: %w", err)
			}
			if index == 0 && len(writes) > 0 {
				return errors.New("command target has unsupported canonical hooks (before-hooks must be read-only)")
			}
			for _, write := range writes {
				if appMCPCommandHookFrameworkTable(write.Table) {
					continue
				}
				if !enrolled[sqliteIdentifierFold(write.Table)] {
					return fmt.Errorf("command %s hook on %q writes table %q, which is not revision-enrolled", action, table, write.Table)
				}
			}
		}
	}
	return nil
}

func appMCPCommandRejectFTSStorageReferences(generation *appMCPRuntimeGeneration, query string) error {
	if generation == nil {
		return errors.New("command SQL has no captured source generation")
	}
	storage, err := appMCPCommandFullTextStorageTables(generation)
	if err != nil {
		return fmt.Errorf("cannot verify full-text storage references: %w", err)
	}
	for _, token := range sqlTokenize(query) {
		if (token.kind == sqlTokWord || token.kind == sqlTokIdent) && storage[sqliteIdentifierFold(token.text)] {
			return fmt.Errorf("command SQL cannot reference generated full-text storage table %q", token.text)
		}
	}
	return nil
}

// hookedWrite reports the hook key and action when the statement writes a
// table that has hooks, or an active webhook subscription, for that action (the
// key is empty when only a subscription matches). Such a statement must write
// exactly one app table that has a single `id` primary key and no authored
// RETURNING (the runtime appends its own): the probe derives the rows the hooks
// and the subscription payloads need.
func (cap *appMCPCommandCapability) hookedWrite(query string, targets []sqlWrite) (key, table, action string, hooked bool, err error) {
	for _, target := range targets {
		physical, ok := cap.physicalTable(target.Table)
		if !ok {
			continue
		}
		if !appMCPCommandNeedsRowParity(cap, physical, target.Action) {
			locked, err := cap.foreignRowLocks(physical, target.Action)
			if err != nil {
				return "", "", "", false, err
			}
			if !locked {
				continue
			}
		}
		if commandSQLUpsertShape(query) {
			return "", "", "", false, errors.New("command SQL on a table with canonical hooks or webhook subscriptions cannot use ON CONFLICT, OR REPLACE or REPLACE INTO")
		}
		hookKey, ok := appMCPHookKey(cap.generation.hooks, physical, target.Action)
		if !ok {
			hookKey = physical
		}
		if len(targets) != 1 {
			return "", "", "", false, errors.New("command SQL with canonical hooks or webhook subscriptions must write exactly one table")
		}
		if hasReturningClause(strings.ToUpper(query)) {
			return "", "", "", false, errors.New("command SQL on a table with canonical hooks or webhook subscriptions cannot use RETURNING")
		}
		for _, candidate := range cap.generation.view.Tables {
			if candidate.Name != physical {
				continue
			}
			pks, hasID := 0, false
			for _, column := range candidate.Columns {
				if column.PK {
					pks++
					hasID = hasID || column.Name == "id"
				}
			}
			if pks != 1 || !hasID {
				return "", "", "", false, errors.New("command target with canonical hooks or webhook subscriptions needs a single id primary key")
			}
			return hookKey, physical, target.Action, true, nil
		}
	}
	return "", "", "", false, nil
}

// foreignRowLocks reports whether another user holds a live edit lock on a row
// of table. CRUD refuses to update or delete such a row (CheckLock); a command
// statement that could touch one is run through the hook probe, which knows the
// affected rows, so it can refuse the same way.
func (cap *appMCPCommandCapability) foreignRowLocks(table, action string) (bool, error) {
	if action != "update" && action != "delete" {
		return false, nil
	}
	var locked bool
	err := cap.withInternalRead(func() error {
		return cap.tx.QueryRowContext(cap.ctx, `SELECT EXISTS(SELECT 1 FROM main._benmore_locks WHERE table_name = ? AND user_id <> ? AND datetime(expires_at) >= datetime('now'))`, table, cap.actor.UserID).Scan(&locked)
	})
	if err != nil && strings.Contains(err.Error(), "no such table") {
		return false, nil // no lock store: nothing can be locked
	}
	return locked, err
}

// appMCPCommandRowLocked refuses, as a conflict the caller may retry once the
// lock lapses, a probed row another user holds an edit lock on.
func appMCPCommandRowLocked(cap *appMCPCommandCapability, table string, id any) error {
	var holder int64
	err := cap.tx.QueryRowContext(cap.ctx, `SELECT user_id FROM main._benmore_locks WHERE table_name = ? AND row_id = ? AND datetime(expires_at) >= datetime('now')`, table, fmt.Sprint(id)).Scan(&holder)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil
	case err != nil:
		return err
	case holder != cap.actor.UserID:
		return appMCPDependencyConflict("command target row on %s is locked by another user", table)
	}
	return nil
}

func (cap *appMCPCommandCapability) anyWebhookSubscribed(table string) bool {
	for _, action := range appMCPHookActions {
		if cap.webhookSubscribed(table, action) {
			return true
		}
	}
	return false
}

func (cap *appMCPCommandCapability) execSavepoint(statement string) error {
	return cap.withNativeMetadata(appMCPCommandMetadataSavepoint, func() error {
		_, err := cap.tx.ExecContext(cap.ctx, statement)
		return err
	})
}

func commandHookRowID(row map[string]any) (any, error) {
	switch id := row["id"].(type) {
	case int64, string:
		return id, nil
	}
	return nil, errors.New("command hook row has no usable id")
}

func commandHookChangedColumns(before, after map[string]any) []string {
	var changed []string
	for name, value := range after {
		if !reflect.DeepEqual(before[name], value) {
			changed = append(changed, name)
		}
	}
	return changed
}

// executeHookedWrite runs one authored write on a hooked table with CRUD hook
// parity (see the file comment). It returns the real statement's row count.
func (exec *appMCPCommandExecution) executeHookedWrite(step *FlowStep, args []any, key, table, action string) (int64, error) {
	cap := exec.capability
	view := cap.generation.view
	if err := appMCPCommandHookEffectsSupported(cap, table, action); err != nil {
		return 0, err
	}
	before, on := appMCPHookSets(cap.generation.hooks, action)
	hasBefore := len(before[key]) > 0
	hasOn := len(on[key]) > 0
	subscribed := cap.webhookSubscribed(table, action)
	lockCheck, err := cap.foreignRowLocks(table, action)
	if err != nil {
		return 0, err
	}
	ctxTx := appMCPContextTx{tx: cap.tx, ctx: cap.ctx, private: true, cap: cap}
	returning := step.SQL + "\nRETURNING *"

	if err := cap.execSavepoint("SAVEPOINT " + appMCPCommandHookProbeSavepoint); err != nil {
		return 0, err
	}
	probe, err := exec.queryApplyRows(returning, args, table)
	if err != nil {
		return 0, err
	}
	if err := cap.execSavepoint("ROLLBACK TO " + appMCPCommandHookProbeSavepoint); err != nil {
		return 0, err
	}
	if err := cap.execSavepoint("RELEASE " + appMCPCommandHookProbeSavepoint); err != nil {
		return 0, err
	}
	ids := make([]any, len(probe))
	for i, row := range probe {
		id, err := commandHookRowID(row)
		if err != nil {
			return 0, err
		}
		ids[i] = id
	}
	// Pre-write state: the before-image of an update (old_<column>), the
	// deleted row itself for a delete.
	oldRows := make([]map[string]any, len(probe))
	if len(probe) > 0 {
		err := cap.withNativeMetadata(appMCPCommandMetadataHookRead, func() error {
			for i, row := range probe {
				if lockCheck {
					if err := appMCPCommandRowLocked(cap, table, ids[i]); err != nil {
						return err
					}
				}
				switch action {
				case "update":
					found, err := queryNativeRowsWith(ctxTx, view, table, fmt.Sprintf("SELECT * FROM main.%s WHERE id = ?", quoteIdent(table)), ids[i])
					if err != nil || len(found) != 1 {
						return errors.New("command hook could not read the pre-write row")
					}
					oldRows[i] = found[0]
				case "delete":
					oldRows[i] = row
				}
				event := cloneCommandHookRow(row)
				switch action {
				case "update":
					markSubmittedFields(event, commandHookChangedColumns(oldRows[i], row))
				case "insert":
					var names []string
					for name, value := range row {
						if value != nil {
							names = append(names, name)
						}
					}
					markSubmittedFields(event, names)
				}
				injectSessionContext(event, &cap.actor)
				if action == "insert" || action == "update" {
					if err := ValidateCrossField(cap.generation.validators, table, event); err != nil {
						return newAppMCPCommandHookError(table, action, err, true)
					}
				}
				if action == "insert" && cap.generation.workflows != nil {
					for _, workflow := range cap.generation.workflows.Workflows {
						if workflow != nil && sqliteIdentifierFold(workflow.Table) == sqliteIdentifierFold(table) && workflowCreateStateRefused(view, table, workflow.Field, row[workflow.Field]) {
							return newAppMCPCommandHookError(table, action, errors.New("new rows must start in the workflow's initial state"), true)
						}
					}
				}
				if hasBefore {
					// As for a CRUD update, hook SQL placeholders are the
					// columns the command changed; `when:` sees the row.
					sqlRow := event
					if action == "update" {
						sqlRow = submittedHookRow(event, &cap.actor)
					}
					if err := fireBeforeHooksRows(ctxTx, view, action, key, event, sqlRow); err != nil {
						return newAppMCPCommandHookError(table, action, err, true)
					}
				}
				if action == "update" {
					if err := appMCPValidateWorkflowTransition(cap, ctxTx, table, oldRows[i], row); err != nil {
						return newAppMCPCommandHookError(table, action, err, true)
					}
				}
			}
			return nil
		})
		if err != nil {
			return 0, err
		}
	}
	rows, err := exec.queryApplyRows(returning, args, table)
	if err != nil {
		return 0, err
	}
	if err := appMCPCommandHookRowsRepeat(probe, rows); err != nil {
		return 0, err
	}
	affected := int64(len(rows))
	if step.ExpectRows != "" {
		ok, checkErr := evalExpectRows(step.ExpectRows, affected)
		if checkErr != nil {
			return 0, checkErr
		}
		if !ok {
			return 0, &appMCPCommandRowCountConflictError{message: "command SQL mutation cardinality check failed"}
		}
	}
	if action == "update" {
		for i := range rows {
			appMCPTrackWorkflowBeforeImage(cap, table, oldRows[i])
		}
	}
	if len(rows) == 0 || (!hasOn && !subscribed && !appMCPHasEventFlow(cap, table, action) && !appMCPHasWorkflowTransition(cap, table, oldRows, rows)) {
		return affected, nil
	}
	err = cap.withNativeMetadata(appMCPCommandMetadataHookWrite, func() error {
		for i, row := range rows {
			event := cloneCommandHookRow(row)
			if action != "delete" {
				id, err := commandHookRowID(row)
				if err != nil {
					return err
				}
				updated, err := queryNativeRowsWith(ctxTx, view, table, fmt.Sprintf("SELECT * FROM main.%s WHERE id = ?", quoteIdent(table)), id)
				if err != nil {
					return fmt.Errorf("command could not read the mutated row: %w", err)
				}
				if len(updated) != 1 {
					return errors.New("command could not read exactly one mutated row")
				}
				event = cloneCommandHookRow(updated[0])
			}
			switch action {
			case "update":
				for name, value := range oldRows[i] {
					event["old_"+name] = value
				}
			case "delete":
				event = cloneCommandHookRow(oldRows[i])
			}
			injectSessionContext(event, &cap.actor)
			if hasOn {
				refresh, err := fireAfterHooksTx(ctxTx, view, action, key, event)
				if err != nil {
					return newAppMCPCommandHookError(table, action, err, false)
				}
				cap.noteHookRefresh(refresh)
			}
			if subscribed {
				if err := enqueueWebhookSubscriptionsTx(ctxTx, view, action, table, event, &cap.actor); err != nil {
					return newAppMCPCommandHookError(table, action, err, false)
				}
			}
			if action == "update" {
				if err := appMCPEnqueueTransitionHooks(cap, ctxTx, table, oldRows[i], event); err != nil {
					return err
				}
			}
			if err := appMCPEnqueueEventFlows(cap, ctxTx, table, action, event); err != nil {
				return err
			}
		}
		return nil
	})
	return affected, err
}

func appMCPHasEventFlow(cap *appMCPCommandCapability, table, action string) bool {
	for _, flow := range cap.generation.flows {
		if flow.Trigger.Type == "on_"+action && sqliteIdentifierFold(flow.Trigger.Table) == sqliteIdentifierFold(table) {
			return true
		}
	}
	return false
}

func appMCPHasWorkflowTransition(cap *appMCPCommandCapability, table string, before, after []map[string]any) bool {
	if len(before) == 0 || len(after) == 0 || cap.generation.workflows == nil {
		return false
	}
	for i := 0; i < len(before) && i < len(after); i++ {
		for _, workflow := range cap.generation.workflows.Workflows {
			if workflow != nil && sqliteIdentifierFold(workflow.Table) == sqliteIdentifierFold(table) && !reflect.DeepEqual(before[i][workflow.Field], after[i][workflow.Field]) {
				return true
			}
		}
	}
	return false
}

func appMCPTrackWorkflowBeforeImage(cap *appMCPCommandCapability, table string, before map[string]any) {
	if cap == nil || cap.generation == nil || cap.generation.workflows == nil {
		return
	}
	id, err := commandHookRowID(before)
	if err != nil {
		return
	}
	for _, workflow := range cap.generation.workflows.Workflows {
		if workflow == nil || sqliteIdentifierFold(workflow.Table) != sqliteIdentifierFold(table) {
			continue
		}
		if cap.workflowTransitions == nil {
			cap.workflowTransitions = map[string]appMCPWorkflowTransitionState{}
		}
		key := fmt.Sprintf("%s\x00%s\x00%T:%v", table, workflow.Name, id, id)
		if _, exists := cap.workflowTransitions[key]; !exists {
			cap.workflowTransitions[key] = appMCPWorkflowTransitionState{Table: table, Workflow: workflow.Name, From: fmt.Sprint(before[workflow.Field]), RowID: id}
		}
	}
}

func appMCPValidateWorkflowTransition(cap *appMCPCommandCapability, tx appMCPContextTx, table string, before, after map[string]any) error {
	if cap.generation.workflows == nil {
		return nil
	}
	for _, workflow := range cap.generation.workflows.Workflows {
		if workflow == nil || sqliteIdentifierFold(workflow.Table) != sqliteIdentifierFold(table) || reflect.DeepEqual(before[workflow.Field], after[workflow.Field]) {
			continue
		}
		from, to := fmt.Sprint(before[workflow.Field]), fmt.Sprint(after[workflow.Field])
		transition, ok := workflow.Transitions[from][to]
		if !ok {
			return fmt.Errorf("workflow transition %q to %q is not allowed", from, to)
		}
		if transition.Role != "" && !appMCPCommandHasWorkflowRole(cap, tx, transition.Role) {
			return fmt.Errorf("role '%s' required for this transition", transition.Role)
		}
		if transition.When != "" {
			met, err := evaluateWhen(tx, cap.generation.view, table, transition.When, before)
			if err != nil || !met {
				return errors.New("workflow transition condition was not met")
			}
		}
	}
	return nil
}

func appMCPCommandHasWorkflowRole(cap *appMCPCommandCapability, tx appMCPContextTx, requiredRole string) bool {
	actor := &cap.actor
	if requiredRole == "" || actor.IsAdmin() || hasRole(actor.Role, requiredRole) {
		return true
	}
	app := cap.generation.view
	roleField := workflowMembershipRoleField(app)
	if roleField == "" {
		return false
	}
	var lookup any
	if emailKeyedColumn(app.Group.UserField) {
		lookup = sessionGrantEmail(actor)
		if lookup == "" {
			return false
		}
	} else {
		lookup = actor.UserID
	}
	args := []any{lookup}
	tenant := ""
	if app.Group.Key != "" {
		if !actor.EffectiveHasGroup() {
			return false
		}
		tenant = " AND " + quoteColumn(app.Group.Table, app.Group.Key) + " = ?"
		args = append(args, actor.EffectiveGroupID())
	}
	query := "SELECT " + quoteColumn(app.Group.Table, roleField) + " FROM main." + quoteIdent(app.Group.Table) + " WHERE " + quoteColumn(app.Group.Table, app.Group.UserField) + " = ?" + tenant + membershipLiveConds(app.Group, app.Group.Table, "", appColumnChecker(app, app.Group.Table)) + " LIMIT 1"
	var role string
	// Exact, as the CRUD transition route compares (hasWorkflowRole).
	return tx.tx.QueryRowContext(tx.ctx, query, args...).Scan(&role) == nil && role == requiredRole
}

func appMCPEnqueueTransitionHooks(cap *appMCPCommandCapability, tx appMCPContextTx, table string, before, after map[string]any) error {
	if cap.generation.workflows == nil {
		return nil
	}
	for _, workflow := range cap.generation.workflows.Workflows {
		if workflow == nil || sqliteIdentifierFold(workflow.Table) != sqliteIdentifierFold(table) || reflect.DeepEqual(before[workflow.Field], after[workflow.Field]) {
			continue
		}
		for _, hook := range workflow.OnTransition[fmt.Sprint(after[workflow.Field])] {
			if hook.When != "" {
				met, err := evaluateWhen(tx, cap.generation.view, table, hook.When, after)
				if err != nil {
					return err
				}
				if !met {
					continue
				}
			}
			payload := hookJobPayload(hook, table, after)
			if err := sealJobPayloadRow(tx, cap.generation.view, table, payload); err != nil {
				return err
			}
			if err := cap.enqueueEffect(tx, "hook", table, "transition", "hook", "hook", payload); err != nil {
				return err
			}
		}
	}
	return nil
}

func appMCPEnqueueEventFlows(cap *appMCPCommandCapability, tx appMCPContextTx, table, action string, row map[string]any) error {
	for _, flow := range cap.generation.flows {
		if flow.Trigger.Type != "on_"+action || sqliteIdentifierFold(flow.Trigger.Table) != sqliteIdentifierFold(table) {
			continue
		}
		if err := cap.enqueueEffect(tx, "flow", table, action, "flow", flow.Name, appMCPEventFlowPayload(cap.generation.view, row)); err != nil {
			return fmt.Errorf("enqueue event flow %q: %w", flow.Name, err)
		}
	}
	return nil
}

// appMCPEventFlowPayload is the job payload of a queued data-event flow: the
// written row plus its request-taint set, so the worker's sql_dynamic and
// enqueue guards treat the row's columns as request input exactly as CRUD's
// synchronous event path does (flowEventRowTaint). Reserved job keys a column
// could carry are dropped first, so a row can neither forge nor clear them.
func appMCPEventFlowPayload(view *App, row map[string]any) map[string]any {
	payload := make(map[string]any, len(row)+1)
	for name, value := range row {
		if name == flowRequestKeysPayloadField || name == flowJobActorPayloadField || name == appMCPEffectKey {
			continue
		}
		payload[name] = value
	}
	tainted := flowEventRowTaint(view, payload)
	keys := make([]string, 0, len(tainted))
	for name := range tainted {
		keys = append(keys, name)
	}
	if len(keys) > 0 {
		slices.Sort(keys)
		payload[flowRequestKeysPayloadField] = keys
	}
	return payload
}

func cloneCommandHookRow(row map[string]any) map[string]any {
	clone := make(map[string]any, len(row)+8)
	for name, value := range row {
		clone[name] = value
	}
	return clone
}

// authorizeCommandHook is the authorizer for the three hook scopes. Hook SQL
// runs with CRUD-hook reach (it reads framework tables such as users and may
// write the inbox) but never the operation/approval stores, schema, pragmas
// other than the read-only ones the hook engine itself issues, or any table
// that is not revision-enrolled.
func authorizeCommandHook(policy appMCPCommandAuthorizerPolicy, action int, arg1, arg2, database string) int {
	op := policy.metadataOp
	if op == appMCPCommandMetadataSavepoint {
		if action == sqlite3.SQLITE_SAVEPOINT && arg2 == appMCPCommandHookProbeSavepoint {
			return sqlite3.SQLITE_OK
		}
		return sqlite3.SQLITE_DENY
	}
	table := strings.ToLower(arg1)
	db := strings.ToLower(database)
	switch action {
	case sqlite3.SQLITE_SELECT, sqliteRecursiveSelect:
		return sqlite3.SQLITE_OK
	case sqlite3.SQLITE_FUNCTION:
		switch strings.ToLower(arg2) {
		case "load_extension", "fts3_tokenizer", "readfile", "writefile", "edit":
			return sqlite3.SQLITE_DENY
		}
		return sqlite3.SQLITE_OK
	case sqlite3.SQLITE_READ:
		if db == "temp" {
			if slices.Contains([]string{"sqlite_temp_schema", "sqlite_temp_master", "sqlite_schema", "sqlite_master"}, table) {
				return sqlite3.SQLITE_OK
			}
			return sqlite3.SQLITE_DENY
		}
		if db != "main" && !(db == "" && arg2 == "") {
			return sqlite3.SQLITE_DENY
		}
		if table == "pragma_database_list" || commandVerifiedTriggerRead(table) {
			return sqlite3.SQLITE_OK
		}
		// An AUTOINCREMENT insert (the queued job) reads its sequence row.
		if table == "sqlite_sequence" && policy.jobInsert {
			return sqlite3.SQLITE_OK
		}
		if strings.HasPrefix(table, "_benmore_mcp_") || strings.HasPrefix(table, "sqlite_") {
			return sqlite3.SQLITE_DENY
		}
		return sqlite3.SQLITE_OK
	case sqlite3.SQLITE_PRAGMA:
		switch strings.ToLower(arg1) {
		case "database_list":
			if arg2 == "" {
				return sqlite3.SQLITE_OK
			}
		case "query_only", "data_version":
			return sqlite3.SQLITE_OK
		}
		return sqlite3.SQLITE_DENY
	case sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE:
		if op != appMCPCommandMetadataHookWrite || db != "main" {
			return sqlite3.SQLITE_DENY
		}
		if policy.hookWrites[sqliteIdentifierFold(arg1)] || policy.verifiedFTSWrites[sqliteIdentifierFold(arg1)] || appMCPCommandHookFrameworkTable(arg1) || commandVerifiedTriggerWrite(arg1) {
			return sqlite3.SQLITE_OK
		}
		// Framework code, never hook SQL, opens this window around its own
		// enqueue (cap.enqueueEffect): app hook SQL still cannot queue a job.
		if action == sqlite3.SQLITE_INSERT && policy.jobInsert && table == "_benmore_jobs" {
			return sqlite3.SQLITE_OK
		}
	}
	return sqlite3.SQLITE_DENY
}

// appMCPHookRefusedResult is the distinct hook_refused result. Only an
// author-written, bounded refusal message is carried; a hook that could not be
// evaluated reports the code alone.
func appMCPHookRefusedResult(hook *appMCPCommandHookError) *sdk.CallToolResult {
	text := "hook_refused: a data hook on " + hook.Table + " could not allow this change."
	if hook.Refused && hook.Message != "" {
		text = "hook_refused: " + hook.Message
	}
	return &sdk.CallToolResult{Meta: sdk.Meta{"error_code": "hook_refused"}, IsError: true, Content: []sdk.Content{&sdk.TextContent{Text: text}}}
}

// appMCPBroadcastCommitted publishes the recorded effects of a confirmed
// commit. Called only after the connection and owner leases are released (the
// cluster publisher writes to the same database).
func appMCPBroadcastCommitted(app *App, events []appMCPCommandBroadcast) {
	for _, event := range events {
		BroadcastScopedDirect(app, event.Table, event.Action, event.GroupID, event.UserID)
	}
}
