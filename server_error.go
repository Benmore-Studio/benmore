//go:build !cli

package main

// Server errors from runtime handlers. A handler that fails for a reason the
// caller cannot fix - a query, commit or audit write that broke, a missing
// table, an invariant that did not hold - answers through serverError or
// serverErrorJSON instead of writing the error itself:
//
//   - the full detail is kept server-side: the request log's error column
//     (_benmore_request_log.error, one line, at most serverErrorDetailMax
//     bytes, credential-shaped text redacted) and one `SERVER ERROR` line in
//     the app's journal, both carrying the request id;
//   - the caller keeps the route's status and shape. In dev mode
//     (app.DevMode, the predicate publicConstraintMessage uses) the answer
//     carries the full error text as before. Otherwise it carries only the
//     route's generic text and the request id - text routes answer
//     "<text> (request id: <id>)", JSON routes {"error": <text>,
//     "request_id": <id>} - so raw SQLite text (table and column names, SQL
//     fragments, sometimes values) never reaches a production caller.
//     Both modes set the X-Request-Id response header.
//
// A 4xx answer keeps its text: validation, scope and not-found messages are
// meant for the caller. (A single-record read whose query fails still answers
// its 404 and only records the failure, through noteServerError.) A capacity
// answer (503 busy, 507 storage full) has its own responder
// (storage_limit.go). Flows record their failures through recordRequestError
// next to their own FLOW ERROR lines.

import (
	"context"
	"errors"
	"log"
	"net/http"
	"regexp"
	"strings"
	"unicode"
)

const (
	// serverErrorDetailMax bounds the detail kept in the request log row.
	serverErrorDetailMax = 2048
	// serverErrorScanMax bounds how much of an error's text is redacted and
	// kept at all; nothing past serverErrorDetailMax survives anyway.
	serverErrorScanMax = 16 << 10
	// requestIDHeader names the response header that carries a server
	// error's request id.
	requestIDHeader = "X-Request-Id"
	// requestIDBytes of crypto randomness: 16 hex characters, unique enough
	// to find one row in the requestLogCap-row ring.
	requestIDBytes = 8
)

// requestErrorID returns r's request id, minting it on first use. The id lives
// in the request log slot so the log row carries it. A request the log skips
// (static paths, the platform scanner) gets a fresh id that only the journal
// line and the answer carry.
func requestErrorID(r *http.Request) string {
	if r == nil {
		return generateToken(requestIDBytes)
	}
	slot := requestLogSlotFor(r)
	if slot == nil {
		return generateToken(requestIDBytes)
	}
	slot.mu.Lock()
	defer slot.mu.Unlock()
	if slot.requestID == "" {
		slot.requestID = generateToken(requestIDBytes)
	}
	return slot.requestID
}

// recordRequestError keeps detail as r's request log error (one line, bounded,
// redacted) and returns the request id. It writes no log line: callers with
// their own journal line (FLOW ERROR) use it directly; everything else goes
// through noteServerError.
func recordRequestError(r *http.Request, detail string) string {
	id := requestErrorID(r)
	if r != nil {
		setRequestLogError(r, serverErrorText(detail))
	}
	return id
}

// noteServerError records err as r's server error: the request log slot and
// one `SERVER ERROR [<where>] <method> <path> (request <id>): <detail>` line in
// the journal. where names the table or route. It returns the request id. A
// query cancelled because the caller went away is no server fault: its row
// says so, and the journal gets no line for each abandoned request.
func noteServerError(r *http.Request, where string, err error) string {
	detail := serverErrorDetail(where, err)
	id := recordRequestError(r, detail)
	if r != nil && errors.Is(err, context.Canceled) && r.Context().Err() != nil {
		return id
	}
	method, path := "", ""
	if r != nil {
		method = r.Method
		if r.URL != nil {
			path = requestLogTruncate(serverErrorOneLine(r.URL.Path), requestLogPathMax)
		}
	}
	log.Printf("SERVER ERROR [%s] %s %s (request %s): %s", serverErrorOneLine(where), method, path, id, serverErrorText(errorText(err)))
	return id
}

// serverError answers a text route's server error (500): it records err
// (noteServerError) and writes the answer for the app's mode. public is the
// route's generic text, the whole answer outside dev mode.
func serverError(w http.ResponseWriter, r *http.Request, app *App, where string, err error, public string) {
	serverErrorStatus(w, r, app, http.StatusInternalServerError, where, err, public)
}

// serverErrorStatus is serverError for a route whose server error has another
// 5xx status (a failed upstream call answered 502, a timeout 504).
func serverErrorStatus(w http.ResponseWriter, r *http.Request, app *App, status int, where string, err error, public string) {
	answerServerError(w, app, status, noteServerError(r, where, err), err, public)
}

// answerServerError writes a text server error whose detail is already
// recorded under id (recordRequestError, noteServerError).
func answerServerError(w http.ResponseWriter, app *App, status int, id string, err error, public string) {
	w.Header().Set(requestIDHeader, id)
	http.Error(w, serverErrorAnswerText(app, id, err, public), status)
}

// serverErrorMessage records err (noteServerError), sets X-Request-Id and
// returns the answer text for a route that renders its own error page or
// envelope.
func serverErrorMessage(w http.ResponseWriter, r *http.Request, app *App, where string, err error, public string) string {
	id := noteServerError(r, where, err)
	w.Header().Set(requestIDHeader, id)
	return serverErrorAnswerText(app, id, err, public)
}

// serverErrorAnswerText is the text a caller gets: the full error in dev
// mode, the generic text and the request id otherwise.
func serverErrorAnswerText(app *App, id string, err error, public string) string {
	if serverErrorDevMode(app) {
		return serverErrorDevText(public, err)
	}
	return publicServerErrorText(public, id)
}

// serverErrorJSON answers a JSON route's server error (500) as
// {"error": public, "request_id": id}; in dev mode "error" carries the full
// text instead.
func serverErrorJSON(w http.ResponseWriter, r *http.Request, app *App, where string, err error, public string) {
	serverErrorJSONBody(w, r, app, http.StatusInternalServerError, where, err, map[string]any{"error": public})
}

// serverErrorJSONBody is serverErrorJSON for a route whose error body has more
// keys than "error" (kept as they are) or another 5xx status. body["error"] is
// the generic text; the request id is added as "request_id".
func serverErrorJSONBody(w http.ResponseWriter, r *http.Request, app *App, status int, where string, err error, body map[string]any) {
	answerServerErrorJSON(w, app, status, noteServerError(r, where, err), err, body)
}

// answerServerErrorJSON is answerServerError for a JSON route.
func answerServerErrorJSON(w http.ResponseWriter, app *App, status int, id string, err error, body map[string]any) {
	w.Header().Set(requestIDHeader, id)
	if serverErrorDevMode(app) {
		public, _ := body["error"].(string)
		body["error"] = serverErrorDevText(public, err)
	}
	body["request_id"] = id
	httpJSON(w, status, body)
}

// serverErrorCode answers a JSON route whose "error" is a machine-readable
// code clients branch on (an OAuth error code such as "server_error"): the
// code stays as it is in every mode, the request id is added, and dev mode
// carries the full text as "error_description" (the OAuth field for it).
func serverErrorCode(w http.ResponseWriter, r *http.Request, app *App, where string, err error, code string) {
	id := noteServerError(r, where, err)
	w.Header().Set(requestIDHeader, id)
	body := map[string]any{"error": code, "request_id": id}
	if serverErrorDevMode(app) {
		body["error_description"] = errorText(err)
	}
	httpJSON(w, http.StatusInternalServerError, body)
}

// serverErrorDevMode is the dev-mode predicate of the constraint path
// (publicConstraintMessage): `benmore serve --dev`.
func serverErrorDevMode(app *App) bool {
	return app != nil && app.DevMode
}

// publicServerErrorText is a text route's production answer.
func publicServerErrorText(public, id string) string {
	if public == "" {
		public = "Server error"
	}
	return public + " (request id: " + id + ")"
}

// serverErrorDevText is the dev-mode answer: the route's text and the full
// error, as dev mode showed before.
func serverErrorDevText(public string, err error) string {
	detail := errorText(err)
	switch {
	case detail == "":
		return public
	case public == "" || strings.HasPrefix(detail, public):
		return detail
	}
	return public + ": " + detail
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// serverErrorDetail is the request-log form of err: "[where] text".
func serverErrorDetail(where string, err error) string {
	text := errorText(err)
	if where != "" {
		text = "[" + where + "] " + text
	}
	return text
}

// serverErrorText makes an error text safe to keep in the request log and the
// journal: one line, credential-shaped text redacted, at most
// serverErrorDetailMax bytes. Redaction runs before the cut so a token the cut
// would shorten below its pattern's length is still caught.
func serverErrorText(text string) string {
	text = requestLogTruncate(text, serverErrorScanMax)
	text = redactErrorCredentials(serverErrorOneLine(text))
	return requestLogTruncate(text, serverErrorDetailMax)
}

// serverErrorOneLine replaces control characters (newlines included) with
// spaces, so a detail is one journal line and cannot forge another.
func serverErrorOneLine(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
}

// errorCredentialPatterns match credential-shaped text an error can carry: a
// Go url.Error quotes the request URL (query string and userinfo included), a
// driver Scan error quotes the column value it could not convert (a bcrypt
// hash, a token, ciphertext), and an upstream error can echo an Authorization
// header. SQLite's own constraint messages name tables and columns, not
// values, so they pass unchanged.
var errorCredentialPatterns = []struct {
	re   *regexp.Regexp
	repl string
}{
	{regexp.MustCompile(`(?i)\b(bearer|basic)(\s+)[A-Za-z0-9._~+/=-]{6,}`), "$1$2[redacted]"},
	{regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*://)[^/\s@"'<>]+@`), "$1[redacted]@"},
	{regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*://[^\s"'<>?#]*)\?[^\s"'<>#]*`), "$1?[redacted]"},
	{regexp.MustCompile(`(?i)\b((?:[a-z0-9]+[_-])*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|signature|sig|authorization|credentials?|cookie|session[_-]?id))("?\s*[=:]\s*)("[^"]*"|'[^']*'|[^\s&,;)"']+)`), "$1$2[redacted]"},
	{regexp.MustCompile(`\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}`), "[redacted]"},
	{regexp.MustCompile(`\benc:v\d+:[A-Za-z0-9+/=_:-]+`), "[redacted]"},
	{regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`), "[redacted]"},
	// Session ids, framework tokens (bmr_/bma_/bmca_... + hex) and other hex
	// secrets: no word boundary, so the hex after a token prefix matches.
	{regexp.MustCompile(`[0-9A-Fa-f]{32,}`), "[redacted]"},
}

// redactErrorCredentials replaces credential-shaped text in an error detail
// with [redacted]: the provider key shapes the write gate refuses
// (committedSecretRes) and errorCredentialPatterns.
func redactErrorCredentials(s string) string {
	for _, p := range committedSecretRes {
		s = p.re.ReplaceAllString(s, "[redacted]")
	}
	for _, p := range errorCredentialPatterns {
		s = p.re.ReplaceAllString(s, p.repl)
	}
	return s
}
