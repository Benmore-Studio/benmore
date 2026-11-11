//go:build !cli

package main

// Config that would act on a framework table.
//
// Four pieces of config install triggers or routes on the table they name:
//
//	app.yaml versioned:              a <table>_history table and history triggers
//	encrypted.yaml, app.yaml encrypted:   encryption triggers on the column
//	workflows.yaml                   transition routes and the timeout sweep
//	computed.yaml                    triggers on the field's table and on each
//	                                 table its `triggers:` list names
//
// Each accepted any table name, the framework's own included. Run on a
// scratch app (November 2026): `versioned: [_benmore_users]` kept a copy of
// every changed account row, password hash included, in _benmore_users_history;
// a workflow on _benmore_users.role with an access: rule let any signed-in
// user make any account an admin through POST /api/_benmore_users/{id}/transition;
// an encrypted _benmore_users.email stored every new account's address as
// ciphertext, so it could never sign in, and encrypted profile columns came
// back from the profile API as ciphertext; a computed _benmore_users.role
// rewrote the role of every account that signed in. And because the
// framework's tables do not exist yet when a new database installs history,
// encryption and computed triggers, each of the three stopped an app from
// starting on a new database at all.
//
// So these four take only the app's own tables, by the name rule retention
// uses (frameworkOwnedTableName, the rule GetTableNames applies). The readers
// every consumer goes through drop an entry that names a framework table
// (parseVersionedSection, parseEncryptedFieldsConfig, parseWorkflowsYAML,
// parseComputedFieldsYAML), so nothing is installed or registered for it and
// a deployed file never takes an app down; the load logs each one
// (logFrameworkTableConfig, warnWorkflowShape), and the write gate and
// `benmore check` refuse it.
//
// Config that only reads a framework table or reacts to it is not this
// file's business and keeps working: `access: _benmore_users: read:` (the
// user directory), hooks.yaml on _benmore_users (sign-up and sign-in events),
// auth.signup_fields / auth.profile_fields (extra profile columns) and SQL in
// flows.

import (
	"errors"
	"fmt"
	"log"
	"maps"
	"slices"
	"strings"
)

// ownTablesOnly is the rule every refusal states, after the thing it applies to.
const ownTablesOnly = "only the app's own tables, never a framework table (_benmore_*) or one of SQLite's own (sqlite_*)"

// versionedFrameworkTableProblems names each framework table app.yaml's
// versioned: lists.
func versionedFrameworkTableProblems(appData []byte) []string {
	var raw map[string]any
	if decodeConfigYAML(appData, &raw) != nil {
		return nil
	}
	items, _ := raw["versioned"].([]any)
	var out []string
	for _, item := range items {
		table, ok := item.(string)
		if !ok || !frameworkOwnedTableName(table) {
			continue
		}
		out = append(out, fmt.Sprintf("app.yaml: versioned lists %q. Version history takes %s: history of a framework table would keep a copy of every changed row, password hashes and sessions included. The entry is ignored and no history is kept for it. Remove it.",
			strings.TrimSpace(table), ownTablesOnly))
	}
	return out
}

// encryptedFrameworkTableProblems names each framework table that file
// ("encrypted.yaml", or "app.yaml" for its encrypted: section) lists for
// field encryption.
func encryptedFrameworkTableProblems(file string, data []byte) []string {
	var raw map[string]any
	if yamlUnmarshal(data, &raw) != nil {
		return nil
	}
	section := "tables"
	if file == "app.yaml" {
		section = "encrypted"
	}
	tables, _ := raw[section].(map[string]any)
	var out []string
	for _, table := range slices.Sorted(maps.Keys(tables)) {
		if !frameworkOwnedTableName(table) {
			continue
		}
		out = append(out, fmt.Sprintf("%s: encrypted fields name the table %q. Field encryption takes %s: the framework reads those columns itself, so an encrypted sign-in identifier could no longer sign in and a profile column would come back as ciphertext. The entry is ignored and nothing is encrypted for it. Remove it, and keep the value in a table of the app.",
			file, strings.TrimSpace(table), ownTablesOnly))
	}
	return out
}

// workflowFrameworkTableProblem is the message for a workflow whose table is
// a framework table, or "".
func workflowFrameworkTableProblem(name, table string) string {
	if !frameworkOwnedTableName(table) {
		return ""
	}
	return fmt.Sprintf("workflows.yaml %s: `table:` %q is a framework table. A workflow takes %s: its transition route and timeouts would change accounts, sessions or other framework rows without the checks the framework makes on them. The workflow is not loaded. Remove it, or keep the state in a table of the app that points at the row (a user_id column).",
		name, strings.TrimSpace(table), ownTablesOnly)
}

// computedFrameworkTableProblems names each computed field declared on a
// framework table, and each trigger of a field that names one.
func computedFrameworkTableProblems(data []byte) []string {
	var out []string
	for _, cf := range computedFields(readComputedFieldsYAML(data)) {
		if frameworkOwnedTableName(cf.Table) {
			out = append(out, fmt.Sprintf("computed.yaml: %s.%s is a computed field on a framework table. A computed field takes %s: it would rewrite that table's rows on every insert and update. The field is not installed. Remove it.",
				cf.Table, cf.Column, ownTablesOnly))
			continue
		}
		for _, trigger := range cf.Triggers {
			if !frameworkOwnedTableName(trigger.Table) {
				continue
			}
			out = append(out, fmt.Sprintf("computed.yaml: %s.%s recalculates on changes to %q, a framework table. A field's `triggers:` take %s: the recalculation would run inside the framework's own writes to that table. That trigger is not installed; the field's other triggers are. Remove it.",
				cf.Table, cf.Column, strings.TrimSpace(trigger.Table), ownTablesOnly))
		}
	}
	return out
}

// withoutComputedFrameworkTables is config without the fields declared on a
// framework table and without the triggers that name one. A file that holds
// nothing else is an empty config, not a nil one: it is a readable file that
// declares nothing the app runs.
func withoutComputedFrameworkTables(config *ComputedFieldConfig) *ComputedFieldConfig {
	if config == nil {
		return nil
	}
	out := &ComputedFieldConfig{Fields: make(map[string]map[string]*ComputedField)}
	for table, columns := range config.Fields {
		if frameworkOwnedTableName(table) {
			continue
		}
		for column, cf := range columns {
			if cf == nil || frameworkOwnedTableName(cf.Table) {
				continue
			}
			kept := *cf
			kept.Triggers = nil
			for _, trigger := range cf.Triggers {
				if !frameworkOwnedTableName(trigger.Table) {
					kept.Triggers = append(kept.Triggers, trigger)
				}
			}
			if out.Fields[table] == nil {
				out.Fields[table] = make(map[string]*ComputedField)
			}
			out.Fields[table][column] = &kept
		}
	}
	return out
}

// dropConfigTriggersOnFrameworkTables removes the encryption and blind-index
// triggers that sit on a framework table: what a load made before this rule
// installed for an entry that is now dropped. The two installers replace
// their set only while some field is still configured, so an app whose
// encrypted config named nothing but framework tables would keep those
// triggers. History and computed triggers need no such step: every load
// drops and recreates all of them from the config it read.
func dropConfigTriggersOnFrameworkTables(tx mutationTx) error {
	rows, err := tx.Query(`SELECT name, tbl_name FROM sqlite_master WHERE type='trigger' AND (substr(name,1,13)='_benmore_enc_' OR substr(name,1,15)='_benmore_blind_')`)
	if err != nil {
		return err
	}
	var names []string
	for rows.Next() {
		var name, table string
		if err := rows.Scan(&name, &table); err != nil {
			rows.Close()
			return err
		}
		if frameworkOwnedTableName(table) {
			names = append(names, name)
		}
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return err
	}
	for _, name := range names {
		if _, err := tx.Exec("DROP TRIGGER IF EXISTS " + quoteIdent(name)); err != nil {
			return err
		}
		log.Printf("ENCRYPTION NOT RUNNING: removed trigger %s, which an earlier configuration installed on a framework table", name)
	}
	return nil
}

// frameworkTableConfigViolation is the write gate (write_file, push, deploy
// and `benmore check`) for app.yaml and encrypted.yaml: every entry of the
// written file that names a framework table, "" when it names none.
// workflows.yaml and computed.yaml are refused by their own gates
// (workflowShapeProblems, computedYAMLViolation).
func frameworkTableConfigViolation(file, content string) string {
	var lines []string
	switch file {
	case "app.yaml":
		lines = append(lines, versionedFrameworkTableProblems([]byte(content))...)
		lines = append(lines, encryptedFrameworkTableProblems("app.yaml", []byte(content))...)
	case "encrypted.yaml":
		lines = append(lines, encryptedFrameworkTableProblems("encrypted.yaml", []byte(content))...)
	}
	return strings.Join(lines, "\n")
}

// logFrameworkTableConfig logs, at every start, each entry of the app's
// config that names a framework table and is therefore ignored. A hosted app
// does not run the source check at start, so this is where the owner of a
// deployed file hears about it. (A workflow on a framework table is logged
// by warnWorkflowShape.)
func logFrameworkTableConfig(app *App) {
	if app == nil {
		return
	}
	read := func(name string) []byte {
		data, err := app.readConfigSource(name)
		if err != nil {
			return nil
		}
		return data
	}
	appData := read("app.yaml")
	for _, msg := range versionedFrameworkTableProblems(appData) {
		log.Printf("VERSIONING NOT RUNNING: %s", msg)
	}
	for _, msg := range encryptedFrameworkTableProblems("encrypted.yaml", read("encrypted.yaml")) {
		log.Printf("ENCRYPTION NOT RUNNING: %s", msg)
	}
	for _, msg := range encryptedFrameworkTableProblems("app.yaml", appData) {
		log.Printf("ENCRYPTION NOT RUNNING: %s", msg)
	}
	for _, msg := range computedFrameworkTableProblems(read("computed.yaml")) {
		log.Printf("COMPUTED NOT RUNNING: %s", msg)
	}
}
