//go:build !cli

package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The TSX handler serves its own pre-gzipped bundle and the response
// middleware compresses everything else. Behind gzipMiddleware the bundle must
// reach the client compressed exactly once: the handler decides first, sets
// Content-Encoding, and the middleware passes those bytes through.
func TestTSXBundleBehindGzipMiddlewareIsCompressedOnce(t *testing.T) {
	app := tsxServeApp(t, "ONCE")
	plain := serveTSX(t, app, "/static/app.js", nil)

	h := gzipMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveTSXIfPresent(w, r, app, "app.js")
	}))
	r := httptest.NewRequest(http.MethodGet, "/static/app.js", nil)
	r.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if got := w.Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", got)
	}
	if !bytes.Equal(gunzipBody(t, w.Body.Bytes()), plain.Body.Bytes()) {
		t.Fatal("bundle behind the middleware was not gzipped exactly once")
	}
}
