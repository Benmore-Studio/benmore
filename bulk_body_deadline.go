//go:build !cli

package main

// Read and write deadlines for the endpoints whose documented request bodies
// cannot arrive within the server's ordinary 15 s ReadTimeout.
//
// Every public listener (the router, `benmore host`, `benmore serve`) reads a
// request under ReadTimeout = 15 s and answers under WriteTimeout (30 s in an
// app process). Streaming ingest documents 100k rows / 100 MB per request,
// but it reads its body only as fast as it inserts rows, so a hosted app
// measured on 2026-10-29 had read 42,489 of 60,000 rows (4.3 MB) when the
// router's 15 s deadline cut the body. The app committed that prefix and its
// JSON partial answer went to a connection the router had already closed, so
// the client saw only the router's "App restarting" page and could not tell
// that rows had committed. File uploads (50 MB) and bulk-import chunks
// (32 MB) have the same shape.
//
// These endpoints move both deadlines for their own request:
// bulkBodyReadTimeout for the body, and bulkBodyAnswerTimeout more for the
// answer once the body is in. The router does it by path before proxying
// (it cannot authenticate), the app inside each handler after its
// authentication and slot checks, so an anonymous caller of an
// authenticated endpoint never holds a connection longer than before.

import (
	"net/http"
	"strings"
	"time"
)

// bulkBodyReadTimeout bounds how long one bulk request may take to deliver
// its body. Five minutes matches the router's WriteTimeout and backend
// ResponseHeaderTimeout: nothing slower could be answered anyway. On the
// hosted platform Cloudflare's own origin timeout (about 100 s for the
// answer) still applies in front of it. Variables so tests can shorten them.
var bulkBodyReadTimeout = 5 * time.Minute

// bulkBodyAnswerTimeout is the time left to write the answer after the body
// deadline: the same 30 s any app request gets for its response.
var bulkBodyAnswerTimeout = 30 * time.Second

// isBulkBodyRequest reports the requests whose body may legitimately take
// longer than the ordinary read deadline: streaming ingest
// (POST /api/<table>/ingest), file uploads (POST /api/_upload and
// /api/_files) and bulk-import chunks (PUT /api/_import/<id>/chunk/<n>).
// Matched by path shape because the router has no route table for apps.
func isBulkBodyRequest(r *http.Request) bool {
	switch r.Method {
	case http.MethodPost:
		return r.URL.Path == "/api/_upload" || r.URL.Path == "/api/_files" || isIngestPath(r.URL.Path)
	case http.MethodPut:
		return isImportChunkUploadPath(r)
	}
	return false
}

// isIngestPath matches /api/<table>/ingest with a single table segment.
func isIngestPath(p string) bool {
	table, ok := strings.CutPrefix(p, "/api/")
	if !ok {
		return false
	}
	table, ok = strings.CutSuffix(table, "/ingest")
	return ok && table != "" && !strings.Contains(table, "/")
}

// extendBulkBodyDeadlines gives the current request bulkBodyReadTimeout to
// deliver its body and bulkBodyAnswerTimeout more for its answer. A writer
// that cannot reach the connection (no deadline support) keeps the server's
// own deadlines.
func extendBulkBodyDeadlines(w http.ResponseWriter) {
	rc := http.NewResponseController(w)
	readBy := time.Now().Add(bulkBodyReadTimeout)
	_ = rc.SetReadDeadline(readBy)
	_ = rc.SetWriteDeadline(readBy.Add(bulkBodyAnswerTimeout))
}
