//go:build !cli

package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
)

// VersionedConfig holds the list of tables with content versioning enabled.
type VersionedConfig struct {
	Tables []string
}

// LoadVersionedConfig reads the versioned: section from app.yaml.
func LoadVersionedConfig(dir string) *VersionedConfig {
	data, err := os.ReadFile(dir + "/app.yaml")
	if err != nil {
		return nil
	}

	lines := strings.Split(string(data), "\n")
	inVersioned := false
	var tables []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "versioned:" {
			inVersioned = true
			continue
		}
		if inVersioned {
			if trimmed == "" || (!strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t")) {
				break
			}
			if strings.HasPrefix(trimmed, "- ") {
				tables = append(tables, strings.TrimPrefix(trimmed, "- "))
			}
		}
	}

	if len(tables) == 0 {
		return nil
	}
	return &VersionedConfig{Tables: tables}
}

// InstallVersioningTriggers creates history tables and SQLite triggers for versioned tables.
// The history table mirrors the source table's schema plus version metadata.
// Triggers fire BEFORE UPDATE and BEFORE DELETE to capture the outgoing row state.
func InstallVersioningTriggers(db *sql.DB, config *VersionedConfig) {
	if config == nil {
		return
	}

	var installed int
	for _, table := range config.Tables {
		n, err := installVersioningForTable(db, table)
		if err != nil {
			log.Printf("VERSIONING ERROR [%s]: %s", table, err)
			continue
		}
		installed += n
	}

	if installed > 0 {
		log.Printf("  versioning: %d triggers installed across %d tables", installed, len(config.Tables))
	}
}

func installVersioningForTable(db *sql.DB, table string) (int, error) {
	// Get the source table's columns
	cols, err := GetTableColumns(db, table)
	if err != nil {
		return 0, fmt.Errorf("cannot read schema for %s: %w", table, err)
	}

	historyTable := table + "_history"

	// Build CREATE TABLE for history - same columns + version metadata
	var colDefs []string
	var colNames []string
	for _, col := range cols {
		colDefs = append(colDefs, fmt.Sprintf("%s %s", col.Name, col.Type))
		colNames = append(colNames, col.Name)
	}

	// Add version metadata columns
	colDefs = append(colDefs,
		"_version INTEGER NOT NULL",
		"_valid_from DATETIME NOT NULL",
		"_valid_to DATETIME NOT NULL DEFAULT (datetime('now'))",
		"_changed_by INTEGER",
		"_change_type TEXT NOT NULL", // 'update' or 'delete'
	)

	createSQL := fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (%s)", historyTable, strings.Join(colDefs, ", "))
	if _, err := db.Exec(createSQL); err != nil {
		return 0, fmt.Errorf("cannot create %s: %w", historyTable, err)
	}

	// Create index on (id, _version) for efficient lookups
	db.Exec(fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_id_version ON %s (id, _version)", historyTable, historyTable))

	// Drop existing versioning triggers for this table
	db.Exec(fmt.Sprintf("DROP TRIGGER IF EXISTS _benmore_ver_%s_update", table))
	db.Exec(fmt.Sprintf("DROP TRIGGER IF EXISTS _benmore_ver_%s_delete", table))

	// Build column reference list for OLD.col1, OLD.col2, ...
	var oldRefs []string
	for _, name := range colNames {
		oldRefs = append(oldRefs, "OLD."+name)
	}

	// BEFORE UPDATE trigger: copy outgoing row to history
	// _version is auto-incremented: SELECT COALESCE(MAX(_version), 0) + 1
	// _valid_from is the original row's updated_at (or created_at if never updated)
	versionSubquery := fmt.Sprintf("(SELECT COALESCE(MAX(_version), 0) + 1 FROM %s WHERE id = OLD.id)", historyTable)
	validFromExpr := "OLD.updated_at"
	if !hasColumnInList(cols, "updated_at") {
		validFromExpr = "OLD.created_at"
		if !hasColumnInList(cols, "created_at") {
			validFromExpr = "datetime('now')"
		}
	}

	triggerCount := 0

	updateTriggerSQL := fmt.Sprintf(
		"CREATE TRIGGER IF NOT EXISTS _benmore_ver_%s_update BEFORE UPDATE ON %s FOR EACH ROW BEGIN INSERT INTO %s (%s, _version, _valid_from, _valid_to, _change_type) VALUES (%s, %s, %s, datetime('now'), 'update'); END",
		table, table, historyTable,
		strings.Join(colNames, ", "),
		strings.Join(oldRefs, ", "),
		versionSubquery,
		validFromExpr,
	)
	if _, err := db.Exec(updateTriggerSQL); err != nil {
		log.Printf("VERSIONING TRIGGER ERROR [%s update]: %s", table, err)
	} else {
		triggerCount++
	}

	// BEFORE DELETE trigger: same pattern
	deleteTriggerSQL := fmt.Sprintf(
		"CREATE TRIGGER IF NOT EXISTS _benmore_ver_%s_delete BEFORE DELETE ON %s FOR EACH ROW BEGIN INSERT INTO %s (%s, _version, _valid_from, _valid_to, _change_type) VALUES (%s, %s, %s, datetime('now'), 'delete'); END",
		table, table, historyTable,
		strings.Join(colNames, ", "),
		strings.Join(oldRefs, ", "),
		versionSubquery,
		validFromExpr,
	)
	if _, err := db.Exec(deleteTriggerSQL); err != nil {
		log.Printf("VERSIONING TRIGGER ERROR [%s delete]: %s", table, err)
	} else {
		triggerCount++
	}

	return triggerCount, nil
}

// RegisterVersioningAPI sets up version history and revert endpoints.
func RegisterVersioningAPI(mux *http.ServeMux, app *App, config *VersionedConfig) {
	if config == nil {
		return
	}

	for _, table := range config.Tables {
		t := table

		// GET /api/{table}/{id}/versions - list all versions
		mux.HandleFunc(fmt.Sprintf("GET /api/%s/{id}/versions", t), func(w http.ResponseWriter, r *http.Request) {
			handleListVersions(w, r, app, t)
		})

		// GET /api/{table}/{id}/versions/{version} - get a specific version
		mux.HandleFunc(fmt.Sprintf("GET /api/%s/{id}/versions/{version}", t), func(w http.ResponseWriter, r *http.Request) {
			handleGetVersion(w, r, app, t)
		})

		// POST /api/{table}/{id}/revert/{version} - revert to a specific version
		mux.HandleFunc(fmt.Sprintf("POST /api/%s/{id}/revert/{version}", t), func(w http.ResponseWriter, r *http.Request) {
			handleRevert(w, r, app, t)
		})

		log.Printf("  versioning: %s (history + revert API)", t)
	}
}

func handleListVersions(w http.ResponseWriter, r *http.Request, app *App, table string) {
	session := getSession(app, r)
	if session == nil {
		httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return
	}

	id := r.PathValue("id")

	if err := checkScope(session, table, "read"); err != nil {
		httpJSON(w, http.StatusForbidden, map[string]any{"error": err.Error()})
		return
	}

	// Verify the user can access this row (same scoping as handleRead)
	if !canAccessRow(app, table, id, session) {
		httpJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}

	historyTable := table + "_history"

	rows, err := QueryRows(app.DB,
		fmt.Sprintf("SELECT _version, _valid_from, _valid_to, _changed_by, _change_type FROM %s WHERE id = ? ORDER BY _version DESC", historyTable),
		id,
	)
	if err != nil {
		httpJSON(w, http.StatusInternalServerError, map[string]any{"error": "version query failed"})
		return
	}

	httpJSON(w, http.StatusOK, map[string]any{
		"id":       id,
		"versions": rows,
	})
}

func handleGetVersion(w http.ResponseWriter, r *http.Request, app *App, table string) {
	session := getSession(app, r)
	if session == nil {
		httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return
	}

	id := r.PathValue("id")

	if err := checkScope(session, table, "read"); err != nil {
		httpJSON(w, http.StatusForbidden, map[string]any{"error": err.Error()})
		return
	}

	if !canAccessRow(app, table, id, session) {
		httpJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}

	version := r.PathValue("version")
	historyTable := table + "_history"

	// Use history table's actual columns - source table may have columns added after history was created
	historyCols, _ := GetTableColumns(app.DB, historyTable)
	var colNames []string
	for _, col := range historyCols {
		colNames = append(colNames, col.Name)
	}
	if len(colNames) == 0 {
		httpJSON(w, http.StatusNotFound, map[string]any{"error": "version not found"})
		return
	}

	rows, err := QueryRows(app.DB,
		fmt.Sprintf("SELECT %s FROM %s WHERE id = ? AND _version = ?", strings.Join(colNames, ", "), historyTable),
		id, version,
	)
	if err != nil || len(rows) == 0 {
		httpJSON(w, http.StatusNotFound, map[string]any{"error": "version not found"})
		return
	}

	httpJSON(w, http.StatusOK, rows[0])
}

func handleRevert(w http.ResponseWriter, r *http.Request, app *App, table string) {
	session := getSession(app, r)
	if session == nil {
		httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return
	}

	if !isBearerAuth(r) && !validateCSRF(r) {
		httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid CSRF token"})
		return
	}

	id := r.PathValue("id")

	if err := checkScope(session, table, "write"); err != nil {
		httpJSON(w, http.StatusForbidden, map[string]any{"error": err.Error()})
		return
	}

	if !canAccessRow(app, table, id, session) {
		httpJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}
	version := r.PathValue("version")
	historyTable := table + "_history"

	// Get the source table columns (what to restore)
	cols, _ := GetTableColumns(app.DB, table)
	var colNames []string
	for _, col := range cols {
		if col.PK {
			continue // don't overwrite id
		}
		colNames = append(colNames, col.Name)
	}

	// Fetch the historical version
	selectCols := strings.Join(colNames, ", ")
	rows, err := QueryRows(app.DB,
		fmt.Sprintf("SELECT %s FROM %s WHERE id = ? AND _version = ?", selectCols, historyTable),
		id, version,
	)
	if err != nil || len(rows) == 0 {
		httpJSON(w, http.StatusNotFound, map[string]any{"error": "version not found"})
		return
	}

	versionRow := rows[0]

	// Build UPDATE from the historical values
	var sets []string
	var values []any
	for _, col := range colNames {
		sets = append(sets, fmt.Sprintf("%s = ?", col))
		values = append(values, versionRow[col])
	}
	values = append(values, id)

	updateSQL := fmt.Sprintf("UPDATE %s SET %s WHERE id = ?", table, strings.Join(sets, ", "))
	if _, err := app.DB.Exec(updateSQL, values...); err != nil {
		httpJSON(w, http.StatusInternalServerError, map[string]any{"error": fmt.Sprintf("revert failed: %s", err)})
		return
	}

	// The UPDATE itself fires the versioning trigger, creating a new history entry
	// for the pre-revert state. This is correct - the revert is itself a versioned change.

	LogAudit(app, "revert", table, id, session,
		map[string]any{"_reverted_to_version": version},
		nil,
	)

	Broadcast(app, table, "update", session)

	httpJSON(w, http.StatusOK, map[string]any{
		"status":              "reverted",
		"id":                  id,
		"reverted_to_version": version,
	})
}

// hasColumnInList checks if a column name exists in a slice of Column structs.
func hasColumnInList(cols []Column, name string) bool {
	for _, c := range cols {
		if c.Name == name {
			return true
		}
	}
	return false
}

// canAccessRow checks if the session user can READ a specific row. Delegates
// to the canonical rowScopeClause (access.go) so versioning, signed-URL
// authorization, locks, etc. all share ONE policy - act-as aware
// (IsAdminBypass + effective group + ACL). Pre-consolidation this was a
// hand-rolled copy using IsAdmin() + native group, which let a stepped-in
// admin bypass scoping and scoped to the wrong tenant under act-as.
func canAccessRow(app *App, table string, id string, session *Session) bool {
	if session == nil {
		return false
	}
	return canAccessRowScoped(app, table, id, session, "view")
}

// handlePointInTime returns the state of a row at a specific point in time.
// GET /api/{table}/{id}?as_of=2026-03-01T00:00:00Z
// Searches the version history for the version that was active at that timestamp.
func handlePointInTime(app *App, table string, id string, asOf string, session *Session) (map[string]any, error) {
	historyTable := table + "_history"

	// Find the version that was valid at the given time
	rows, err := QueryRows(app.DB,
		fmt.Sprintf("SELECT * FROM %s WHERE id = ? AND _valid_from <= ? AND _valid_to > ? ORDER BY _version DESC LIMIT 1", historyTable),
		id, asOf, asOf,
	)
	if err != nil || len(rows) == 0 {
		// If no history entry, maybe the current row was created before as_of and never updated
		currentRows, err := QueryRows(app.DB,
			fmt.Sprintf("SELECT * FROM %s WHERE id = ? AND created_at <= ?", table),
			id, asOf,
		)
		if err != nil || len(currentRows) == 0 {
			return nil, fmt.Errorf("no version found at %s", asOf)
		}
		return currentRows[0], nil
	}
	return rows[0], nil
}
