//go:build !cli

package main

import "database/sql"

// History triggers cannot see the session, so the versions a write records
// carry no author. A framework write that knows its actor runs its UPDATE or
// DELETE through execVersioned: in the same transaction, it notes the row's
// newest version before the statement and afterwards names the actor on the
// versions that statement recorded. Writes made by flow, hook or other
// authored SQL leave _changed_by NULL.
func execVersioned(tx mutationTx, table, id string, actor *Session, query string, args ...any) (sql.Result, error) {
	since, history, err := versionActorMark(tx, table, id, actor)
	if err != nil {
		return nil, err
	}
	result, err := tx.Exec(query, args...)
	if err != nil || history == "" {
		return result, err
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return result, nil
	}
	if _, err := tx.Exec("UPDATE main."+quoteIdent(history)+" SET _changed_by = ? WHERE id = ? AND _version > ? AND _changed_by IS NULL", actor.UserID, id, since); err != nil {
		return nil, err
	}
	return result, nil
}

// versionActorMark returns the row's newest history version and the history
// table's name, or an empty name when there is nothing to attribute: no
// signed-in actor, or no active history trigger on the table (history kept
// after versioning was turned off records nothing new).
func versionActorMark(q mutationQuerier, table, id string, actor *Session) (int64, string, error) {
	if actor == nil || actor.UserID == 0 {
		return 0, "", nil
	}
	var active int
	if err := q.QueryRow(`SELECT count(*) FROM main.sqlite_schema WHERE type='trigger' AND tbl_name=? COLLATE NOCASE AND (name=? COLLATE NOCASE OR name=? COLLATE NOCASE)`,
		table, "_benmore_ver_"+table+"_update", "_benmore_ver_"+table+"_delete").Scan(&active); err != nil {
		return 0, "", err
	}
	if active == 0 {
		return 0, "", nil
	}
	history := table + "_history"
	var since int64
	if err := q.QueryRow("SELECT COALESCE(MAX(_version), 0) FROM main."+quoteIdent(history)+" WHERE id = ?", id).Scan(&since); err != nil {
		return 0, "", err
	}
	return since, history, nil
}
