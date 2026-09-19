//go:build !cli

package main

// Streaming NDJSON ingestion through the CRUD access and validation gates.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// handleStreamingIngest accepts NDJSON (newline-delimited JSON) for bulk data ingestion.
// Single transaction, no after-hooks (performance), before-hooks fire per row.
// Returns: {"ingested": N, "errors": N, "duration_ms": N, "status": "completed"}
func handleStreamingIngest(w http.ResponseWriter, r *http.Request, app *App, table string) {
	start := time.Now()

	// Same coarse access gate as the single-row create (M5).
	if !EnforceCRUDAccess(w, r, app, table, OpWrite, 0) {
		return
	}

	// CSRF check (Bearer bypass)
	if !validateCSRF(r) && !isBearerAuth(r) {
		httpError(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	// Auth + scope check
	session := getSession(app, r)
	if session == nil {
		httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return
	}
	if err := checkScope(session, table, "write"); err != nil {
		httpJSON(w, http.StatusForbidden, map[string]any{"error": err.Error()})
		return
	}

	// Rate limit: 5 ingestions per minute per user
	rateLimitKey := fmt.Sprintf("ingest:user:%d", session.UserID)
	if !ingestLimiter.Allow(rateLimitKey) {
		http.Error(w, "Rate limit exceeded. Try again later.", http.StatusTooManyRequests)
		return
	}

	// Body size limit: 100MB
	const maxBodySize = 100 * 1024 * 1024
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)

	// Get table columns once for validation
	cols, err := GetTableColumns(app.DB, table)
	if err != nil {
		httpError(w, "Server error", http.StatusInternalServerError)
		return
	}

	// Build column allowlist and detect which columns exist
	validCols := make(map[string]bool)
	colMap := make(map[string]Column)
	for _, col := range cols {
		validCols[col.Name] = true
		colMap[col.Name] = col
	}

	// Protected fields
	protected := map[string]bool{
		"user_id": true, "created_at": true, "updated_at": true,
		"password_hash": true, "role": true,
		"password_change_required": true,
	}
	if app.Group != nil && app.Group.Key != "" {
		protected[app.Group.Key] = true
	}
	// H-10: protect the configurable in-tenant RoleField (e.g. member_role)
	// on the membership table so a member cannot self-elevate via CRUD.
	if app.Group != nil && app.Group.RoleField != "" && app.Group.Table != "" && table == app.Group.Table {
		protected[app.Group.RoleField] = true
	}

	// Extract validation rules once
	validationRules := ExtractValidationRules(app, table)

	// Begin transaction
	tx, err := app.DB.Begin()
	if err != nil {
		httpError(w, "Server error", http.StatusInternalServerError)
		return
	}

	const maxRows = 100000
	const maxLineSize = 1024 * 1024 // 1MB max line length

	scanner := bufio.NewScanner(r.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), maxLineSize)

	var ingested, errCount int
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Bytes()

		// Skip empty lines
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}

		// Enforce max row limit
		if ingested+errCount >= maxRows {
			tx.Rollback()
			httpJSON(w, http.StatusRequestEntityTooLarge, map[string]any{
				"error":    fmt.Sprintf("exceeded maximum of %d rows per request", maxRows),
				"ingested": ingested,
				"errors":   errCount,
				"line":     lineNum,
			})
			return
		}

		// Parse JSON line
		var item map[string]any
		if err := json.Unmarshal(line, &item); err != nil {
			errCount++
			continue
		}

		// member-of: each row must land in a parent the caller is a
		// member of - same gate as single-row create (M5). Ingest's
		// per-row error semantics apply: the row is skipped and counted,
		// the rest of the stream continues.
		if d := memberOfCreateDenial(app, table, session, func(col string) string {
			if v, ok := item[col]; ok && v != nil {
				return fmt.Sprintf("%v", v)
			}
			return ""
		}); d != nil {
			errCount++
			continue
		}

		// Strip protected fields silently (same as handleCreate) and reject truly unknown columns
		for key := range item {
			if protected[key] {
				delete(item, key) // strip, don't reject
				continue
			}
			if !validCols[key] {
				errCount++
				item = nil
				break
			}
		}
		if item == nil {
			continue
		}

		// Build INSERT fields
		var fields []string
		var placeholders []string
		var values []any

		for _, col := range cols {
			if col.PK {
				continue
			}
			if col.Name == "user_id" {
				fields = append(fields, col.Name)
				placeholders = append(placeholders, "?")
				values = append(values, session.UserID)
				continue
			}
			if app.Group != nil && col.Name == app.Group.Key && session.EffectiveHasGroup() {
				fields = append(fields, col.Name)
				placeholders = append(placeholders, "?")
				values = append(values, session.EffectiveGroupID())
				continue
			}
			if protected[col.Name] {
				continue
			}

			if val, ok := item[col.Name]; ok && val != nil {
				fields = append(fields, col.Name)
				placeholders = append(placeholders, "?")
				values = append(values, fmt.Sprintf("%v", val))
			}
		}

		if len(fields) == 0 {
			errCount++
			continue
		}

		// Validate fields against rules
		skipRow := false
		if len(validationRules) > 0 {
			for field, rule := range validationRules {
				if val, ok := item[field]; ok {
					valStr := fmt.Sprintf("%v", val)
					for _, r := range strings.Split(rule, ",") {
						r = strings.TrimSpace(r)
						if r == "required" && valStr == "" {
							skipRow = true
							break
						}
					}
				} else if strings.Contains(rule, "required") {
					skipRow = true
				}
				if skipRow {
					break
				}
			}
		}
		if skipRow {
			errCount++
			continue
		}

		// Fire before-hooks (can abort individual rows)
		beforeRow := make(map[string]any)
		for i, f := range fields {
			beforeRow[f] = values[i]
		}
		injectSessionContext(beforeRow, session)
		if err := FireBeforeHooks(app, "insert", table, beforeRow); err != nil {
			errCount++
			continue
		}

		// Execute parameterized INSERT
		sqlStr := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)",
			table, strings.Join(fields, ", "), strings.Join(placeholders, ", "))
		_, err := tx.Exec(sqlStr, values...)
		if err != nil {
			errCount++
			continue
		}

		ingested++
	}

	// Check for scanner errors (including MaxBytesReader)
	if err := scanner.Err(); err != nil {
		if ingested == 0 {
			tx.Rollback()
			httpJSON(w, http.StatusBadRequest, map[string]any{
				"error":    "read error: " + err.Error(),
				"ingested": 0,
				"errors":   errCount,
			})
			return
		}
		// Partial read - commit what we have
		log.Printf("ingest: scanner error after %d rows: %v", ingested, err)
	}

	if ingested == 0 {
		tx.Rollback()
		httpJSON(w, http.StatusBadRequest, map[string]any{
			"error":    "no rows ingested",
			"ingested": 0,
			"errors":   errCount,
		})
		return
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		httpJSON(w, http.StatusInternalServerError, map[string]any{
			"error":    "commit failed",
			"ingested": 0,
			"errors":   errCount,
		})
		return
	}

	// Single audit log entry for the batch
	LogAudit(app, "ingest", table, fmt.Sprintf("batch:%d", ingested), session, nil, map[string]any{
		"ingested": ingested,
		"errors":   errCount,
	})

	// SSE broadcast
	Broadcast(app, table, "insert", session)
	appendHXTrigger(w, "benmore:changed")

	// Meter the ingestion
	Increment(meterScope(session), "ingest_rows")

	durationMs := time.Since(start).Milliseconds()
	httpJSON(w, http.StatusOK, map[string]any{
		"ingested":    ingested,
		"errors":      errCount,
		"duration_ms": durationMs,
		"status":      "completed",
	})
}
