//go:build !cli

package main

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A multipart create must be bounded in total, not just per file: parsing
// spills every file part to temporary disk before any per-file check runs.
func TestMultipartCreateBodyHasTotalCap(t *testing.T) {
	app, mux := auditApp(t)
	sid := createCrudScopeSession(t, app, "writer@example.com", "user", "", "")
	handler := serverBodyLimitMiddleware(mux, app)

	post := func(parts int, size int) *httptest.ResponseRecorder {
		var body bytes.Buffer
		mw := multipart.NewWriter(&body)
		mw.WriteField("title", "with files")
		chunk := bytes.Repeat([]byte("x"), size)
		for i := 0; i < parts; i++ {
			fw, _ := mw.CreateFormFile("attachment", "f.bin")
			fw.Write(chunk)
		}
		mw.Close()
		req := httptest.NewRequest("POST", "/api/notes", &body)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		req.Header.Set("Authorization", "Bearer "+auditToken(t, app, sid, "*"))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	// Two 30MB parts: each under the per-file limit, together over the
	// default total.
	if rec := post(2, 30<<20); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized multipart create: %d %s", rec.Code, rec.Body.String())
	}
	if got := serverResolveMaxMultipartBytes(app); got != maxUploadSize+uploadBodyOverhead {
		t.Fatalf("default multipart cap = %d", got)
	}
	SetAppEnv(app.Dir, "MAX_UPLOAD_BODY_BYTES", "999999999999")
	if got := serverResolveMaxMultipartBytes(app); got != serverMaxMultipartBodyCeiling {
		t.Fatalf("multipart cap above the ceiling = %d", got)
	}
}
