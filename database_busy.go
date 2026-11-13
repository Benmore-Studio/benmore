//go:build !cli

package main

// A busy database.
//
// SQLite has one writer per database. A write that cannot get the write lock
// within the connection's busy timeout fails with SQLITE_BUSY (or
// SQLITE_LOCKED for a table lock). Nothing is wrong with the request and
// nothing is broken on the server: the database had more writers than it
// could serve in that window, and the same request succeeds a moment later.
//
// The routes used to disagree about it: 500 "Transaction start failed", 500
// "Delete failed", 400 "the write was rejected", 503 with a sentence in
// `error`, a flow's 500 flow_no_response. There is one classifier
// (isDatabaseBusyError, by SQLite's result code, never by message text) and
// one answer:
//
//	503, Retry-After: 1, X-Request-Id
//	{"error":"database_busy","message":"the database is busy, retry shortly",
//	 "request_id":"<id>","docs":"recovery.write_lock"}
//
// Every server error of a route under /api/ passes through serverErrorStatus
// or serverErrorJSONBody (server_error.go), which give this answer for a busy
// error, so a route does not have to remember to. A route that answers a
// write error itself (the 400 of a constraint refusal) asks
// respondDatabaseBusy first, and a failed flow (on any path) gives it in
// place of flow_no_response when nothing the run wrote was kept. Routes
// outside /api/ (pages, form posts, the admin panel, sign-in) keep their own
// answers.
//
// A busy answer is load, not a fault: it writes one DATABASE BUSY line to the
// journal, not a SERVER ERROR or FLOW ERROR line, and a 503 is never reported
// as an error event (reportRequestFailure). The request log row keeps the
// cause under the request id. Who held the lock is in the journal's
// `db: database is locked: ...` line (db_write_lock.go).

import (
	"errors"
	"log"
	"net/http"

	"github.com/mattn/go-sqlite3"
)

const (
	// databaseBusyCode is the stable `error` value of the busy answer.
	databaseBusyCode    = "database_busy"
	databaseBusyMessage = "the database is busy, retry shortly"
	// databaseBusyRetryAfter is the Retry-After of the busy answer, in
	// seconds: the wait was already the busy timeout long, and a write
	// transaction is over in well under a second unless something is wrong.
	databaseBusyRetryAfter = "1"
)

// isDatabaseBusyError reports a statement that could not get a database lock
// in time: SQLITE_BUSY or SQLITE_LOCKED, read from the driver's result code.
// The message text is never consulted: an upstream error, a trigger's RAISE
// or a value quoted in an error can all say "database is locked".
func isDatabaseBusyError(err error) bool {
	var se sqlite3.Error
	return errors.As(err, &se) && (se.Code == sqlite3.ErrBusy || se.Code == sqlite3.ErrLocked)
}

// respondDatabaseBusy answers a busy error (503, Retry-After, database_busy)
// and reports whether it did. where names the table or route, as for
// noteServerError.
func respondDatabaseBusy(w http.ResponseWriter, r *http.Request, where string, err error) bool {
	if !isDatabaseBusyError(err) {
		return false
	}
	writeDatabaseBusy(w, noteDatabaseBusy(r, where, serverErrorDetail(where, err)))
	return true
}

// noteDatabaseBusy records a busy answer and returns the request id: the
// request log row keeps detail (the cause; for a flow, its failed step too),
// the journal gets one line. No stack and no error export are kept, unlike
// noteServerError.
func noteDatabaseBusy(r *http.Request, where, detail string) string {
	id := requestErrorID(r)
	method, path := "", ""
	if r != nil {
		if slot := requestLogSlotFor(r); slot != nil {
			slot.mu.Lock()
			if slot.where == "" {
				slot.where = where
			}
			slot.mu.Unlock()
		}
		setRequestLogError(r, serverErrorText(detail))
		method = r.Method
		if r.URL != nil {
			path = requestLogTruncate(serverErrorOneLine(r.URL.Path), requestLogPathMax)
		}
	}
	log.Printf("DATABASE BUSY [%s] %s %s (request %s): answered 503, retry after %ss", serverErrorOneLine(where), method, path, id, databaseBusyRetryAfter)
	return id
}

// writeDatabaseBusy writes the busy answer for a request already recorded
// under id.
func writeDatabaseBusy(w http.ResponseWriter, id string) {
	h := w.Header()
	h.Del("Content-Length")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Retry-After", databaseBusyRetryAfter)
	h.Set(requestIDHeader, id)
	httpJSON(w, http.StatusServiceUnavailable, withRefusalDocs(map[string]any{
		"error":      databaseBusyCode,
		"message":    databaseBusyMessage,
		"request_id": id,
	}, databaseBusyCode))
}
