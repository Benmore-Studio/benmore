//go:build !cli

package main

import (
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/mattn/go-sqlite3"
)

// Approved commands on versioned tables.
//
// A table listed in app.yaml `versioned:` carries two framework triggers
// (_benmore_ver_<table>_update/_delete) that copy the row an UPDATE or DELETE
// replaces into <table>_history. A command that writes such a table fires them
// inside its own statement, so three things have to hold:
//
//   - Enrollment recognises the triggers only by their full text: it builds
//     what versionTriggers generates for the table's current columns from the
//     captured app.yaml, encrypted.yaml and computed.yaml and compares the
//     stored definition (appMCPVerifiedHistoryTriggers). A trigger that merely
//     has the name is refused like any other unrecognized trigger, and so is a
//     history table that is missing, not an ordinary table, or has triggers.
//   - The apply authorizer admits what those triggers do and nothing more: an
//     INSERT into, and reads of, the history tables of captured versioned
//     tables in the revision universe, plus the benmore_history_* functions,
//     and only while an apply write statement or a hook-write scope runs.
//     Command and hook SQL still cannot name a history table as a write
//     target: it is not an app table, so it is in no declaration, no
//     enrollment and no hook effect inventory.
//   - The versions a commit records name the user who approved the command,
//     as a CRUD write does through execVersioned. History triggers cannot see
//     the actor, so apply notes each history table's newest row before the
//     apply phase and stamps the rows added since in a scope of its own
//     (appMCPCommandMetadataVersionActor) that may update that one column.
//
// The history table is outside the revision ledger on purpose: it is
// append-only storage no command can read or declare a dependency on.

// appMCPVerifiedHistoryTriggers returns the history triggers a load installs
// for one captured versioned table, after checking the history table they
// write. The caller compares each with the stored trigger text.
func appMCPVerifiedHistoryTriggers(tx *sql.Tx, generation *appMCPRuntimeGeneration, table string) ([]versionTrigger, error) {
	if tx == nil || generation == nil || generation.view == nil || !isValidColumnName(table) {
		return nil, fmt.Errorf("version history of enrolled table %q cannot be verified", table)
	}
	history := table + "_history"
	exists, err := versionHistoryExists(tx, history)
	if err != nil {
		return nil, fmt.Errorf("version history of enrolled table %q: %w", table, err)
	}
	if !exists {
		return nil, fmt.Errorf("version history table %q of enrolled table %q is missing", history, table)
	}
	cols, err := mainTableColumnsWith(tx, table)
	if err != nil || len(cols) == 0 {
		return nil, fmt.Errorf("version history of enrolled table %q: source columns are unavailable", table)
	}
	return versionTriggers(table, cols, generation.view.Encrypted, computedExprColumns(generation.computed, table)), nil
}

// appMCPCommandHistoryTables names the history tables of the captured
// versioned tables among tables, sorted. The enrollment check has verified
// the triggers that write them (it runs again inside every command).
func appMCPCommandHistoryTables(generation *appMCPRuntimeGeneration, tables []string) []string {
	if generation == nil || generation.view == nil || len(tables) == 0 {
		return nil
	}
	versioned := generation.view.versionedConfig()
	if versioned == nil {
		return nil
	}
	inside := commandTableSet(tables)
	var history []string
	for _, table := range versioned.Tables {
		if inside[sqliteIdentifierFold(table)] && isValidColumnName(table) {
			history = append(history, table+"_history")
		}
	}
	sort.Strings(history)
	return history
}

// commandHistoryTriggerFunction reports a function only the generated history
// triggers call. The authorizer admits it while a verified history table is
// writable, and command SQL may never call it by name (commandTriggerOnlyCall):
// benmore_history_normalized compares a sealed value with a plaintext, the
// same key-validity oracle as benmore_ciphertext_matches. Deliberately not
// part of commandVerifiedTriggerFunction, which also admits a function to an
// app-authored trigger.
func commandHistoryTriggerFunction(name string) bool {
	switch strings.ToLower(name) {
	case "benmore_history_start", "benmore_history_end", "benmore_history_covers", "benmore_history_encrypt", "benmore_history_normalized":
		return true
	}
	return false
}

// appMCPVersionMark is a history table's row identity column and its newest
// row before the apply phase.
type appMCPVersionMark struct {
	rowID string
	since int64
}

// versionMarks notes, before any apply write, the newest row of every history
// table the command's writes can reach. Nil when there is nothing to attribute.
func (cap *appMCPCommandCapability) versionMarks() (map[string]appMCPVersionMark, error) {
	if cap == nil || cap.tx == nil || cap.actor.UserID == 0 {
		return nil, nil
	}
	tables := appMCPCommandHistoryTables(cap.generation, cap.effectTables())
	if len(tables) == 0 {
		return nil, nil
	}
	marks := make(map[string]appMCPVersionMark, len(tables))
	err := cap.withInternalRead(func() error {
		for _, history := range tables {
			cols, err := mainTableColumnsWith(cap.tx, history)
			if err != nil {
				return err
			}
			rowID, err := versionHistoryRowID(cols)
			if err != nil {
				return err
			}
			mark := appMCPVersionMark{rowID: rowID}
			// A rowid table numbers a new row above its newest one, so the rows
			// this transaction adds are exactly those past the mark.
			if err := cap.tx.QueryRowContext(cap.ctx, "SELECT COALESCE(MAX("+quoteIdent(rowID)+"), -9223372036854775808) FROM main."+quoteIdent(history)).Scan(&mark.since); err != nil {
				return err
			}
			marks[history] = mark
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read version history before apply: %w", err)
	}
	return marks, nil
}

// appMCPCommandAttributeVersions names the command's actor on every version
// the apply phase recorded (its own statements, their hooks and cascades),
// inside the command transaction: the counterpart of execVersioned.
func appMCPCommandAttributeVersions(cap *appMCPCommandCapability, marks map[string]appMCPVersionMark) error {
	if cap == nil || len(marks) == 0 {
		return nil
	}
	if cap.actor.UserID == 0 {
		return errors.New("command version attribution has no actor")
	}
	tables := make([]string, 0, len(marks))
	for history := range marks {
		tables = append(tables, history)
	}
	sort.Strings(tables)
	return cap.withNativeMetadata(appMCPCommandMetadataVersionActor, func() error {
		for _, history := range tables {
			mark := marks[history]
			if _, err := cap.tx.ExecContext(cap.ctx, "UPDATE main."+quoteIdent(history)+" SET _changed_by = ? WHERE "+quoteIdent(mark.rowID)+" > ? AND _changed_by IS NULL", cap.actor.UserID, mark.since); err != nil {
				return fmt.Errorf("attribute command versions: %w", err)
			}
		}
		return nil
	})
}

// authorizeCommandVersionActor is the authorizer of the attribution scope: the
// one framework statement above. It may read the verified history tables and
// change their _changed_by column; every other table, column and action is
// refused, so the scope cannot rewrite a stored version or touch app data.
func authorizeCommandVersionActor(policy appMCPCommandAuthorizerPolicy, action int, arg1, arg2, database string) int {
	history := strings.EqualFold(database, "main") && policy.verifiedHistoryWrites[sqliteIdentifierFold(arg1)]
	switch action {
	case sqlite3.SQLITE_SELECT:
		return sqlite3.SQLITE_OK
	case sqlite3.SQLITE_READ:
		if history {
			return sqlite3.SQLITE_OK
		}
	case sqlite3.SQLITE_UPDATE:
		if history && strings.EqualFold(arg2, "_changed_by") {
			return sqlite3.SQLITE_OK
		}
	}
	return sqlite3.SQLITE_DENY
}
