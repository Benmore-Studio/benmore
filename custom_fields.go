//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
)

// maxCustomFieldsPerTable prevents abuse by capping the number of custom fields per table.
const maxCustomFieldsPerTable = 50

// allowedColumnTypes is the whitelist of types that can be used for custom fields.
var allowedColumnTypes = map[string]bool{
	"TEXT":     true,
	"INTEGER":  true,
	"REAL":     true,
	"DATETIME": true,
}

// reservedColumnNames are columns that cannot be created as custom fields.
var reservedColumnNames = map[string]bool{
	"id":            true,
	"user_id":       true,
	"created_at":    true,
	"updated_at":    true,
	"deleted_at":    true,
	"password_hash": true,
	"role":          true,
}

// EnsureCustomFieldsTable creates the _benmore_custom_fields tracking table.
func EnsureCustomFieldsTable(db *sql.DB) {
	db.Exec(`CREATE TABLE IF NOT EXISTS _benmore_custom_fields (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		table_name TEXT NOT NULL,
		column_name TEXT NOT NULL,
		column_type TEXT NOT NULL,
		description TEXT DEFAULT '',
		added_by INTEGER,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(table_name, column_name)
	)`)
}

// RegisterCustomFieldRoutes adds the dynamic schema API endpoints.
// All endpoints are admin-only.
func RegisterCustomFieldRoutes(mux appRouteRegistrar, app *App) {
	EnsureCustomFieldsTable(app.DB)
	registerCustomFieldRoutes(mux, app)
}

func registerCustomFieldRoutes(mux appRouteRegistrar, app *App) {
	// List custom fields for a table
	mux.HandleFunc("GET /api/_schema/{table}/fields", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil || !session.IsAdminConsole() {
			http.Error(w, `{"error":"admin required"}`, http.StatusForbidden)
			return
		}

		table := r.PathValue("table")
		if !validColumnNameRe.MatchString(table) {
			http.Error(w, `{"error":"invalid table name"}`, http.StatusBadRequest)
			return
		}

		// Block access to framework tables
		if strings.HasPrefix(table, "_benmore_") {
			http.Error(w, `{"error":"cannot modify framework tables"}`, http.StatusForbidden)
			return
		}

		// Verify table exists
		exists, err := tableExists(app.DB, table)
		if err != nil || !exists {
			http.Error(w, `{"error":"table not found"}`, http.StatusNotFound)
			return
		}

		// Get all live columns
		liveCols, err := GetTableColumns(app.DB, table)
		if err != nil {
			serverErrorJSON(w, r, app, "custom fields "+table, err, "failed to read table schema")
			return
		}

		// Get custom fields from tracking table
		customMap := make(map[string]map[string]any)
		rows, err := queryMetadataRows(app.DB, "SELECT column_name, column_type, description, added_by, created_at FROM _benmore_custom_fields WHERE table_name = ?", table)
		if err == nil {
			for _, row := range rows {
				if name, ok := row["column_name"].(string); ok {
					customMap[name] = row
				}
			}
		}

		// Build response: all columns with a "custom" flag on dynamic ones
		type fieldInfo struct {
			Name        string `json:"name"`
			Type        string `json:"type"`
			Custom      bool   `json:"custom"`
			Description string `json:"description,omitempty"`
			AddedBy     any    `json:"added_by,omitempty"`
			CreatedAt   any    `json:"created_at,omitempty"`
		}

		var fields []fieldInfo
		for _, col := range liveCols {
			f := fieldInfo{
				Name: col.Name,
				Type: col.Type,
			}
			if custom, ok := customMap[col.Name]; ok {
				f.Custom = true
				if desc, ok := custom["description"].(string); ok {
					f.Description = desc
				}
				f.AddedBy = custom["added_by"]
				f.CreatedAt = custom["created_at"]
			}
			fields = append(fields, f)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(fields)
	})

	// Add a custom field to a table
	mux.HandleFunc("POST /api/_schema/{table}/fields", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil || !session.IsAdminConsole() {
			http.Error(w, `{"error":"admin required"}`, http.StatusForbidden)
			return
		}

		// CSRF check (skip for Bearer auth)
		if !isBearerAuth(r) && !validateCSRF(r) {
			http.Error(w, `{"error":"invalid CSRF token"}`, http.StatusForbidden)
			return
		}

		table := r.PathValue("table")
		if !validColumnNameRe.MatchString(table) {
			http.Error(w, `{"error":"invalid table name"}`, http.StatusBadRequest)
			return
		}

		// Block framework tables
		if strings.HasPrefix(table, "_benmore_") {
			http.Error(w, `{"error":"cannot modify framework tables"}`, http.StatusForbidden)
			return
		}

		// Verify table exists
		exists, err := tableExists(app.DB, table)
		if err != nil || !exists {
			http.Error(w, `{"error":"table not found"}`, http.StatusNotFound)
			return
		}

		// Parse request body
		var body struct {
			Name        string `json:"name"`
			Type        string `json:"type"`
			Description string `json:"description"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
			return
		}

		body.Name = strings.TrimSpace(body.Name)
		body.Type = strings.ToUpper(strings.TrimSpace(body.Type))

		// Validate column name
		if !validColumnNameRe.MatchString(body.Name) {
			http.Error(w, `{"error":"invalid column name (must match [a-zA-Z_][a-zA-Z0-9_]*)"}`, http.StatusBadRequest)
			return
		}

		// Block reserved column names
		if reservedColumnNames[strings.ToLower(body.Name)] {
			http.Error(w, fmt.Sprintf(`{"error":"column name '%s' is reserved"}`, body.Name), http.StatusBadRequest)
			return
		}

		// Validate column type
		if !allowedColumnTypes[body.Type] {
			http.Error(w, `{"error":"invalid column type (allowed: TEXT, INTEGER, REAL, DATETIME)"}`, http.StatusBadRequest)
			return
		}

		// Check max custom fields per table
		var count int
		app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_custom_fields WHERE table_name = ?", table).Scan(&count)
		if count >= maxCustomFieldsPerTable {
			http.Error(w, fmt.Sprintf(`{"error":"maximum %d custom fields per table reached"}`, maxCustomFieldsPerTable), http.StatusBadRequest)
			return
		}

		// Check if column already exists
		liveCols, err := GetTableColumns(app.DB, table)
		if err != nil {
			serverErrorJSON(w, r, app, "custom fields "+table, err, "failed to read table schema")
			return
		}
		for _, col := range liveCols {
			if strings.EqualFold(col.Name, body.Name) {
				http.Error(w, fmt.Sprintf(`{"error":"column '%s' already exists"}`, body.Name), http.StatusConflict)
				return
			}
		}

		// The source column, history schema/triggers, and tracking row commit
		// together. A failed history repair must not leave a half-added field.
		key := cryptoKeyForQuerier(app.DB)
		tx, err := app.DB.Begin()
		if err != nil {
			serverErrorJSON(w, r, app, "custom fields "+table, err, "failed to begin schema change")
			return
		}
		defer tx.Rollback()
		alterSQL := fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", quoteIdent(table), quoteIdent(body.Name), body.Type)
		if _, err := tx.Exec(alterSQL); err != nil {
			tx.Rollback()
			serverErrorJSON(w, r, app, "custom fields "+table, err, "failed to add column")
			return
		}
		historyExists, err := versionHistoryExists(tx, table+"_history")
		if err != nil {
			tx.Rollback()
			serverErrorJSON(w, r, app, "custom fields "+table, err, "failed to validate history")
			return
		}
		var activeHistory int
		if historyExists {
			// Retained snapshots alone do not enable capture. Removing a table
			// from versioned: removes its triggers while keeping its old history.
			if err := tx.QueryRow(`SELECT count(*) FROM main.sqlite_schema WHERE type='trigger' AND tbl_name=? COLLATE NOCASE AND (name=? COLLATE NOCASE OR name=? COLLATE NOCASE)`, table, "_benmore_ver_"+table+"_update", "_benmore_ver_"+table+"_delete").Scan(&activeHistory); err != nil {
				tx.Rollback()
				serverErrorJSON(w, r, app, "custom fields "+table, err, "failed to read history policy")
				return
			}
		}
		if activeHistory > 0 {
			if err := installVersioningForTableTx(tx, table, app.Encrypted, key); err != nil {
				tx.Rollback()
				serverErrorJSON(w, r, app, "custom fields "+table, err, "failed to update history")
				return
			}
		}
		if _, err := tx.Exec(
			"INSERT INTO _benmore_custom_fields (table_name, column_name, column_type, description, added_by) VALUES (?, ?, ?, ?, ?)",
			table, body.Name, body.Type, body.Description, session.UserID,
		); err != nil {
			tx.Rollback()
			serverErrorJSON(w, r, app, "custom fields "+table, err, "failed to record custom field")
			return
		}
		if err := tx.Commit(); err != nil {
			tx.Rollback()
			serverErrorJSON(w, r, app, "custom fields "+table, err, "failed to commit custom field")
			return
		}

		// Audit log
		LogAudit(app, "add_field", table, body.Name, session, nil, map[string]any{
			"column_name": body.Name,
			"column_type": body.Type,
			"description": body.Description,
		})

		log.Printf("  custom_fields: added %s.%s %s (by user %d)", table, body.Name, body.Type, session.UserID)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{
			"status": "created",
			"column": body.Name,
			"type":   body.Type,
		})
	})

	// Remove a custom field from a table
	mux.HandleFunc("DELETE /api/_schema/{table}/fields/{name}", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil || !session.IsAdminConsole() {
			http.Error(w, `{"error":"admin required"}`, http.StatusForbidden)
			return
		}

		// CSRF check (skip for Bearer auth)
		if !isBearerAuth(r) && !validateCSRF(r) {
			http.Error(w, `{"error":"invalid CSRF token"}`, http.StatusForbidden)
			return
		}

		table := r.PathValue("table")
		name := r.PathValue("name")

		if !validColumnNameRe.MatchString(table) || !validColumnNameRe.MatchString(name) {
			http.Error(w, `{"error":"invalid table or column name"}`, http.StatusBadRequest)
			return
		}

		// Block framework tables
		if strings.HasPrefix(table, "_benmore_") {
			http.Error(w, `{"error":"cannot modify framework tables"}`, http.StatusForbidden)
			return
		}

		// Verify this is a tracked custom field (not a schema-defined column)
		var trackCount int
		app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_custom_fields WHERE table_name = ? AND column_name = ?", table, name).Scan(&trackCount)
		if trackCount == 0 {
			http.Error(w, `{"error":"field is not a custom field or does not exist"}`, http.StatusNotFound)
			return
		}

		// Execute ALTER TABLE DROP COLUMN
		if err := DropColumn(app.DB, table, name); err != nil {
			serverErrorJSON(w, r, app, "custom fields "+table, err, "failed to remove column")
			return
		}

		// Remove from tracking table
		app.DB.Exec("DELETE FROM _benmore_custom_fields WHERE table_name = ? AND column_name = ?", table, name)

		// Audit log
		LogAudit(app, "remove_field", table, name, session, map[string]any{
			"column_name": name,
		}, nil)

		log.Printf("  custom_fields: removed %s.%s (by user %d)", table, name, session.UserID)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status": "removed",
			"column": name,
		})
	})
}
