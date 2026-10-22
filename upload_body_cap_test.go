//go:build !cli

package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type uploadCountingReader struct {
	r io.Reader
	n int64
}

func (c *uploadCountingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

type uploadFillReader struct{}

func (uploadFillReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'a'
	}
	return len(p), nil
}

// uploadTestBody streams a single-file multipart body without materializing it.
func uploadTestBody(size int64) (io.Reader, string) {
	const boundary = "benmore-upload-cap-boundary"
	head := "--" + boundary + "\r\nContent-Disposition: form-data; name=\"file\"; filename=\"big.txt\"\r\nContent-Type: text/plain\r\n\r\n"
	tail := "\r\n--" + boundary + "--\r\n"
	return io.MultiReader(strings.NewReader(head), io.LimitReader(uploadFillReader{}, size), strings.NewReader(tail)),
		"multipart/form-data; boundary=" + boundary
}

// The upload endpoints parse the multipart body in the CSRF / FormValue step,
// so the size cap has to be in place before that first parse. Otherwise every
// file part spills to temporary disk in full before the per-file check runs.
func TestUploadEndpointsCapBodyBeforeParsing(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	app, cleanup := newTestApp(t)
	defer cleanup()
	mux := http.NewServeMux()
	RegisterUploadRoute(mux, app)
	RegisterFileUploadRoute(mux, app)

	bodyCap := int64(maxUploadSize + 1<<20)
	for _, path := range []string{"/api/_upload", "/api/_files"} {
		body, contentType := uploadTestBody(maxUploadSize + 8<<20)
		counted := &uploadCountingReader{r: body}
		req := httptest.NewRequest(http.MethodPost, path, counted)
		req.Header.Set("Content-Type", contentType)
		req.Header.Set("Authorization", "Bearer upload-cap-test")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("%s oversized upload: status %d, want 413 (%s)", path, rec.Code, strings.TrimSpace(rec.Body.String()))
		}
		if counted.n > bodyCap+64<<10 {
			t.Errorf("%s read %d body bytes before refusing; cap is %d", path, counted.n, bodyCap)
		}
	}

	// A file at exactly the per-file limit still fits under the body cap.
	body, contentType := uploadTestBody(maxUploadSize)
	req := httptest.NewRequest(http.MethodPost, "/api/_upload", body)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "Bearer upload-cap-test")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("upload at the per-file limit: status %d, want 200 (%s)", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
}
