//go:build !cli

package main

// Oversized request bodies answer 413 with the limit they exceeded.
//
// A body cap (serverBodyLimitMiddleware's MaxBytesReader, a flow's JSON
// binding limit, net/http's own 10 MB form limit) ends the read with an
// error. Handlers that ignored that error ran with whatever was read before
// the cap: a flow with a 1.1 MB JSON body ran with every field empty and
// answered the app's own "field is required" error, and a form post over
// the cap reached auto-CRUD with no fields. Every body reader on the flow
// and auto-CRUD paths now asks requestBodyTooLarge first and answers with
// writeRequestBodyTooLarge, so an oversized body is never handled as an
// empty one.

import (
	"errors"
	"fmt"
	"mime"
	"net/http"
	"strings"
)

// netHTTPMaxFormBytes is net/http's own cap on an urlencoded form body read
// by ParseForm when the body is not already a MaxBytesReader. ParseForm
// reports it as the plain error "http: POST too large".
const netHTTPMaxFormBytes int64 = 10 << 20

// errRequestBodyTooLarge marks a body that exceeded limit bytes.
type errRequestBodyTooLarge struct{ limit int64 }

func (e *errRequestBodyTooLarge) Error() string {
	return fmt.Sprintf("request body too large: the limit is %s (%d bytes)", humanBytesShort(e.limit), e.limit)
}

// requestBodyTooLarge reports whether err ended a body read because the body
// exceeded a cap, and that cap in bytes.
func requestBodyTooLarge(err error) (int64, bool) {
	if err == nil {
		return 0, false
	}
	var capped *errRequestBodyTooLarge
	if errors.As(err, &capped) {
		return capped.limit, true
	}
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		return tooLarge.Limit, true
	}
	if err.Error() == "http: POST too large" {
		return netHTTPMaxFormBytes, true
	}
	return 0, false
}

// writeRequestBodyTooLarge answers 413 with the limit the body exceeded.
func writeRequestBodyTooLarge(w http.ResponseWriter, limit int64) {
	httpJSON(w, http.StatusRequestEntityTooLarge, withRefusalDocs(map[string]any{
		"error":       (&errRequestBodyTooLarge{limit: limit}).Error(),
		"limit_bytes": limit,
	}, refusalBodyTooLarge))
}

// answerIfRequestBodyTooLarge writes the 413 and reports true when err is an
// oversized-body error; otherwise it writes nothing.
func answerIfRequestBodyTooLarge(w http.ResponseWriter, err error) bool {
	limit, ok := requestBodyTooLarge(err)
	if ok {
		writeRequestBodyTooLarge(w, limit)
	}
	return ok
}

// parseFormBody is r.ParseForm, except that an urlencoded body cut by a cap
// is reported even when the form was already parsed: r.FormValue (which
// validateCSRF uses to read the token) parses the body and drops the error,
// after which ParseForm returns nil with no fields. A capped body leaves a
// trace either way: a MaxBytesReader keeps answering its MaxBytesError, and
// net/http's own 10 MB cap stops reading with bytes left in the body.
func parseFormBody(r *http.Request) error {
	parsed := r.PostForm != nil
	err := r.ParseForm()
	if _, tooLarge := requestBodyTooLarge(err); tooLarge || !parsed || r.Body == nil || !urlEncodedFormRequest(r) {
		return err
	}
	var one [1]byte
	n, readErr := r.Body.Read(one[:])
	if limit, tooLarge := requestBodyTooLarge(readErr); tooLarge {
		return &errRequestBodyTooLarge{limit: limit}
	}
	if n > 0 {
		return &errRequestBodyTooLarge{limit: netHTTPMaxFormBytes}
	}
	return err
}

// urlEncodedFormRequest reports a body ParseForm reads: an
// application/x-www-form-urlencoded POST, PUT or PATCH.
func urlEncodedFormRequest(r *http.Request) bool {
	if r.Method != http.MethodPost && r.Method != http.MethodPut && r.Method != http.MethodPatch {
		return false
	}
	ct := r.Header.Get("Content-Type")
	if ct == "" {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(ct)
	return err == nil && strings.EqualFold(mediaType, "application/x-www-form-urlencoded")
}
