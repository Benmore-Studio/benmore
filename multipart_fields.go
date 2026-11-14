//go:build !cli

package main

// One reading of a multipart body that stores no file.
//
// A handler that ran the CSRF check before it read its fields got the text
// fields of a multipart/form-data body only for a cookie request: the check
// reads its token with r.FormValue, which parses a multipart body as a side
// effect, and a Bearer request skips the check. The same PATCH applied its
// fields with a session cookie and read none with an API token. Such a
// handler calls readMultipartTextFields first, so what it reads does not
// depend on the credential.

import (
	"errors"
	"io"
	"net/http"
)

// multipartMaxParts bounds the parts read from one body, net/http's own
// default for a parsed form.
const multipartMaxParts = 1000

// errMalformedMultipart is a multipart body that could not be read to its
// closing boundary.
var errMalformedMultipart = errors.New("malformed multipart body")

// readMultipartTextFields reads the text fields of a multipart/form-data
// body into r.Form and r.PostForm, after the query's values as
// ParseMultipartForm orders them, and returns the names of its file parts.
// A file part's bytes are read past: nothing of it is kept in memory or
// written to disk, so the caller needs no upload slot and has no temporary
// file to remove. The text fields together are held to net/http's 10 MB form
// limit; over it, or over the body cap, the error is one
// requestBodyTooLarge recognizes. A body already parsed is left as it is.
func readMultipartTextFields(r *http.Request) (fileParts []string, err error) {
	if r.MultipartForm != nil {
		for name := range r.MultipartForm.File {
			fileParts = append(fileParts, name)
		}
		return fileParts, nil
	}
	// The query's values; ParseForm reads nothing of a multipart body. A
	// query that does not parse keeps the values that did, as FormValue does.
	_ = r.ParseForm()
	reader, err := r.MultipartReader()
	if err != nil {
		return nil, errMalformedMultipart
	}
	left := netHTTPMaxFormBytes
	for parts := 0; ; parts++ {
		part, err := reader.NextPart() // discards what is unread of the part before
		if err == io.EOF {
			return fileParts, nil
		}
		if err != nil {
			return nil, multipartReadError(err)
		}
		if parts >= multipartMaxParts {
			return nil, errMalformedMultipart
		}
		name := part.FormName()
		if name == "" {
			continue
		}
		if part.FileName() != "" {
			fileParts = append(fileParts, name)
			continue
		}
		value, err := io.ReadAll(io.LimitReader(part, left+1))
		if err != nil {
			return nil, multipartReadError(err)
		}
		if left -= int64(len(value)); left < 0 {
			return nil, &errRequestBodyTooLarge{limit: netHTTPMaxFormBytes}
		}
		r.Form[name] = append(r.Form[name], string(value))
		r.PostForm[name] = append(r.PostForm[name], string(value))
	}
}

// multipartReadError keeps a body-cap error as it is (the caller answers 413
// with the limit) and reports anything else as a malformed body.
func multipartReadError(err error) error {
	if limit, tooLarge := requestBodyTooLarge(err); tooLarge {
		return &errRequestBodyTooLarge{limit: limit}
	}
	return errMalformedMultipart
}

// answerMultipartReadError writes the answer for a readMultipartTextFields
// error: 413 with the limit, else 400.
func answerMultipartReadError(w http.ResponseWriter, err error) {
	if !answerIfRequestBodyTooLarge(w, err) {
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": errMalformedMultipart.Error()})
	}
}
