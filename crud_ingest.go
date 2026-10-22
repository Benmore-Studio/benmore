//go:build !cli

package main

// Streaming NDJSON ingestion through the CRUD access and validation gates.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// handleStreamingIngest accepts NDJSON (newline-delimited JSON) for bulk data ingestion.
// Single transaction, no after-hooks (performance). Each row goes through the
// shared create pipeline (txInsertWithPlan): validators, before-hooks on the
// transaction, protected/computed columns and foreign-key visibility. A
// refused row is skipped and counted; the rest of the stream continues.
// A read failure commits the valid prefix but returns a non-2xx partial result.
// Ingested always counts committed rows; errors includes a terminal read error.
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
	rateLimitKey := appLimiterKey(app, "ingest", fmt.Sprintf("user:%d", session.UserID))
	if !ingestLimiter.Allow(rateLimitKey) {
		http.Error(w, "Rate limit exceeded. Try again later.", http.StatusTooManyRequests)
		return
	}

	// Body size limit: 100MB
	const maxBodySize = 100 * 1024 * 1024
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)

	ownedCheck := ownedFieldChecker(app, table)

	// Begin transaction
	tx, err := app.DB.Begin()
	if err != nil {
		serverError(w, r, app, table+" ingest", err, "Server error")
		return
	}
	defer tx.Rollback()

	// Columns, protected set and :validate rules are resolved once.
	plan, err := newInsertPlan(tx, app, table)
	if err != nil {
		serverError(w, r, app, table+" ingest", err, "Server error")
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
			httpJSON(w, http.StatusRequestEntityTooLarge, map[string]any{
				"error":       fmt.Sprintf("exceeded maximum of %d rows per request", maxRows),
				"ingested":    0, // The deferred rollback discards every row.
				"errors":      errCount + 1,
				"line":        lineNum,
				"duration_ms": time.Since(start).Milliseconds(),
				"status":      "failed",
			})
			return
		}

		// Parse JSON line
		var item map[string]any
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.UseNumber()
		if err := decoder.Decode(&item); err != nil || decoder.Decode(new(any)) != io.EOF {
			errCount++
			continue
		}

		// member-of: each row must land in a parent the caller is a
		// member of - same gate as single-row create (M5). Ingest's
		// per-row error semantics apply: the row is skipped and counted,
		// the rest of the stream continues.
		if d := memberOfCreateDenialWith(tx, app, table, session, func(col string) string {
			if v, ok := item[col]; ok && v != nil {
				return fmt.Sprintf("%v", v)
			}
			return ""
		}); d != nil {
			errCount++
			continue
		}

		// Command-owned columns refuse the whole stream (nothing commits).
		if v := ownedCheck(mapKeys(item)...); v != nil {
			writeOwnedFieldRefusal(w, v)
			return
		}

		// Protected fields are stripped silently (same as handleCreate);
		// a truly unknown column rejects the row.
		data := make(map[string]any, len(item))
		unknown := false
		for key, val := range item {
			if plan.protected.has(key) {
				continue
			}
			if !plan.validCols[key] {
				unknown = true
				break
			}
			if _, declared := plan.schemaCols[key]; declared {
				data[key] = val
			} else if val != nil {
				data[key] = jsonToFormValue(val)
			}
		}
		if unknown {
			errCount++
			continue
		}

		// A savepoint per row: a refusal after the INSERT (the founder
		// membership auto-join) must not leave half a row behind while the
		// stream carries on.
		if _, err := tx.Exec("SAVEPOINT benmore_ingest_row"); err != nil {
			serverError(w, r, app, table+" ingest", err, "Server error")
			return
		}
		if _, err := txInsertWithPlan(tx, app, table, data, session, plan); err != nil {
			// SQLite may end the whole transaction on SQLITE_FULL; any later
			// statement would then commit on its own. Stop and roll back.
			if isStorageFullError(err) {
				respondStorageFull(w, app, err)
				return
			}
			var metadataErr *validationMetadataError
			if errors.As(err, &metadataErr) {
				serverError(w, r, app, table+" ingest", err, "Server error")
				return
			}
			if _, rbErr := tx.Exec("ROLLBACK TO benmore_ingest_row"); rbErr != nil {
				serverError(w, r, app, table+" ingest", rbErr, "Server error")
				return
			}
			tx.Exec("RELEASE benmore_ingest_row")
			errCount++
			continue
		}
		if _, err := tx.Exec("RELEASE benmore_ingest_row"); err != nil {
			serverError(w, r, app, table+" ingest", err, "Server error")
			return
		}

		ingested++
	}

	// A truncated stream must not look complete, even when its valid prefix
	// is committed. Count the terminal failure separately from rejected rows.
	readErr := scanner.Err()
	readStatus := http.StatusBadRequest
	if readErr != nil {
		errCount++
		var sizeErr *http.MaxBytesError
		if errors.Is(readErr, bufio.ErrTooLong) || errors.As(readErr, &sizeErr) {
			readStatus = http.StatusRequestEntityTooLarge
		}
		if ingested == 0 {
			httpJSON(w, readStatus, map[string]any{
				"error":       "read error: " + readErr.Error(),
				"ingested":    0,
				"errors":      errCount,
				"line":        lineNum + 1,
				"duration_ms": time.Since(start).Milliseconds(),
				"status":      "failed",
			})
			return
		}
		// Partial read - commit what we have
		log.Printf("ingest: scanner error after %d rows: %v", ingested, readErr)
	}

	if ingested == 0 {
		httpJSON(w, http.StatusBadRequest, map[string]any{
			"error":    "no rows ingested",
			"ingested": 0,
			"errors":   errCount,
		})
		return
	}

	// Single audit log entry for the batch, committed with the rows.
	if err := LogAuditTx(tx, app, "ingest", table, fmt.Sprintf("batch:%d", ingested), session, nil, map[string]any{
		"ingested": ingested,
		"errors":   errCount,
	}); err != nil {
		if respondStorageFull(w, app, err) {
			return
		}
		serverErrorJSONBody(w, r, app, http.StatusInternalServerError, table+" ingest", err, map[string]any{
			"error":    "audit write failed",
			"ingested": 0,
			"errors":   errCount,
		})
		return
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		if respondStorageFull(w, app, err) {
			return
		}
		serverErrorJSONBody(w, r, app, http.StatusInternalServerError, table+" ingest", err, map[string]any{
			"error":    "commit failed",
			"ingested": 0,
			"errors":   errCount,
		})
		return
	}

	// SSE broadcast
	Broadcast(app, table, "insert", session)
	appendHXTrigger(w, "benmore:changed")

	// Meter the ingestion
	Increment(app, meterScope(session), "ingest_rows")

	durationMs := time.Since(start).Milliseconds()
	result := map[string]any{
		"ingested":    ingested,
		"errors":      errCount,
		"duration_ms": durationMs,
		"status":      "completed",
	}
	status := http.StatusOK
	if readErr != nil {
		status = readStatus
		result["status"] = "partial"
		result["error"] = "read error: " + readErr.Error()
		result["line"] = lineNum + 1
	}
	httpJSON(w, status, result)
}
