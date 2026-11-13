//go:build !cli

package main

// Streaming NDJSON ingestion through the CRUD access and validation gates.

import (
	"bufio"
	"bytes"
	"context"
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
// transaction, protected/computed columns and foreign-key visibility, and
// gets its own "insert" audit entry in the transaction, like batch create. A
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
	if !isBearerAuth(r) && !validateCSRF(r) {
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
		httpJSON(w, http.StatusForbidden, scopeDeniedBody(err))
		return
	}

	// Rate limit: 5 ingestions per minute per user
	rateLimitKey := appLimiterKey(app, "ingest", fmt.Sprintf("user:%d", session.UserID))
	if ok, retry, _ := ingestLimiter.Check(rateLimitKey); !ok {
		setRetryAfter(w, retry)
		httpRefusal(w, rateLimitedMessage, http.StatusTooManyRequests, refusalIngestLimit)
		return
	}

	// The body arrives only as fast as rows are inserted, so the documented
	// 100k rows outlast the server's 15 s read and 30 s write deadlines.
	// Extended only now, for an authenticated, rate-limited writer.
	extendBulkBodyDeadlines(w)

	// Body size limit: 100MB. The global request-body cap does not apply
	// here: serverBodyLimitMiddleware leaves this route to this cap.
	const maxBodySize = 100 * 1024 * 1024
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)

	ownedCheck := ownedFieldChecker(app, table)

	// Begin transaction
	ctx := withWriteTxLabel(context.Background(), "ingest:"+table)
	tx, err := app.DB.BeginTx(ctx, nil)
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
	// Each committed row is read back for its audit entry. The read is
	// queryNativeRowsWith's, with the database's key resolved once instead
	// of once per row (it stats the database path).
	readBackKey := cryptoKeyForQuerier(tx)
	readBackDecrypt := nativeRowDecryptor(app, table)
	readBackSQL := "SELECT * FROM " + quoteIdent(table) + " WHERE id = ?"

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

		// A row naming another member refuses the whole stream too: the strip
		// below would create it for the caller, and a skipped-row count would
		// not say why (membershipNamedIdentityDenial).
		if err := membershipCreateIdentityDenial(app, table, session, item); err != nil {
			httpJSON(w, http.StatusUnprocessableEntity, map[string]any{
				"error":       err.Error(),
				"ingested":    0, // The deferred rollback discards every row.
				"errors":      errCount + 1,
				"line":        lineNum,
				"duration_ms": time.Since(start).Milliseconds(),
				"status":      "failed",
			})
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
		id, err := txInsertWithPlan(tx, app, table, data, session, plan)
		if err != nil {
			// SQLite may end the whole transaction on SQLITE_FULL; any later
			// statement would then commit on its own. Stop and roll back.
			if isStorageFullError(err) {
				respondStorageFull(w, app, err)
				return
			}
			// A row the database was too busy to write is not a bad row:
			// nothing is kept and the whole stream can be sent again.
			if respondDatabaseBusy(w, r, table+" ingest", err) {
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
		// One audit entry per committed row, as batch create writes: the row
		// as stored, under the same "insert" action as a single create. A
		// failure here is the server's, not the row's, so it ends the request
		// and the deferred rollback discards every row.
		stored, err := queryRowsWithKeyContextDecrypt(ctx, tx, readBackKey, readBackDecrypt, readBackSQL, id)
		if err != nil || len(stored) != 1 {
			if err == nil {
				err = fmt.Errorf("inserted row %v read back %d rows", id, len(stored))
			}
			serverErrorJSONBody(w, r, app, http.StatusInternalServerError, table+" ingest", err, map[string]any{
				"error":    "could not read inserted row",
				"ingested": 0,
				"errors":   errCount,
			})
			return
		}
		if err := LogAuditTx(tx, app, "insert", table, valueText(id), session, nil, stored[0]); err != nil {
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
		// Say what committed in the message itself: a caller that reads only
		// the error (or takes any non-2xx to mean nothing happened) must not
		// replay rows that are already in the table.
		status = readStatus
		result["status"] = "partial"
		rows := "rows"
		if ingested == 1 {
			rows = "row"
		}
		result["error"] = fmt.Sprintf("read error: %s; the request body ended before it was complete, and the %d %s accepted before line %d were committed", readErr, ingested, rows, lineNum+1)
		result["line"] = lineNum + 1
	}
	httpJSON(w, status, result)
}
