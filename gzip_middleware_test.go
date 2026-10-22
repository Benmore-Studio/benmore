//go:build !cli

package main

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func gzipServe(t *testing.T, h http.HandlerFunc, method, acceptEncoding string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, "/api/notes", nil)
	if acceptEncoding != "" {
		req.Header.Set("Accept-Encoding", acceptEncoding)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	gzipMiddleware(h).ServeHTTP(rec, req)
	return rec
}

func gunzipBody(t *testing.T, b []byte) []byte {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("not a gzip stream: %v", err)
	}
	out, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("gunzip: %v", err)
	}
	return out
}

func varyHasAcceptEncoding(h http.Header) bool {
	for _, v := range h.Values("Vary") {
		for _, p := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(p), "Accept-Encoding") {
				return true
			}
		}
	}
	return false
}

func TestGzipCompressesLargeDynamicBodies(t *testing.T) {
	body := benchJSONBody(16 << 10)
	rec := gzipServe(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", "999") // must be dropped
		w.Header().Set("ETag", `"v1"`)
		// Written in several chunks across the buffering threshold.
		for i := 0; i < len(body); i += 300 {
			end := min(i+300, len(body))
			_, _ = w.Write(body[i:end])
		}
	}, http.MethodGet, "gzip, deflate, br", nil)
	if rec.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("large JSON not compressed: %v", rec.Header())
	}
	if rec.Header().Get("Content-Length") != "" {
		t.Fatalf("Content-Length kept on a compressed body: %q", rec.Header().Get("Content-Length"))
	}
	if !varyHasAcceptEncoding(rec.Header()) {
		t.Fatalf("missing Vary: Accept-Encoding: %v", rec.Header())
	}
	if et := rec.Header().Get("ETag"); et != `W/"v1"` {
		t.Fatalf("strong ETag not weakened for the compressed variant: %q", et)
	}
	if got := gunzipBody(t, rec.Body.Bytes()); !bytes.Equal(got, body) {
		t.Fatalf("round trip mismatch: %d vs %d bytes", len(got), len(body))
	}
	if rec.Body.Len() >= len(body) {
		t.Fatalf("compressed %d >= original %d", rec.Body.Len(), len(body))
	}
}

func TestGzipSkipsSmallBodiesButVaries(t *testing.T) {
	rec := gzipServe(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}, http.MethodGet, "gzip", nil)
	if rec.Header().Get("Content-Encoding") != "" {
		t.Fatalf("tiny body compressed")
	}
	if rec.Body.String() != `{"ok":true}` {
		t.Fatalf("body changed: %q", rec.Body.String())
	}
	if !varyHasAcceptEncoding(rec.Header()) {
		t.Fatalf("compressible type must still vary on Accept-Encoding")
	}
}

func TestGzipNeverTouchesBodilessOrPartialStatuses(t *testing.T) {
	big := benchJSONBody(4 << 10)
	for _, code := range []int{http.StatusNoContent, http.StatusNotModified, http.StatusPartialContent} {
		rec := gzipServe(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			if code == http.StatusPartialContent {
				_, _ = w.Write(big)
			}
		}, http.MethodGet, "gzip", nil)
		if rec.Code != code || rec.Header().Get("Content-Encoding") != "" {
			t.Fatalf("status %d: code=%d encoding=%q", code, rec.Code, rec.Header().Get("Content-Encoding"))
		}
		if code == http.StatusPartialContent && !bytes.Equal(rec.Body.Bytes(), big) {
			t.Fatalf("206 body altered")
		}
	}
}

func TestGzipPassesRangeHeadAndIncompressibleThrough(t *testing.T) {
	big := benchJSONBody(8 << 10)
	png := bytes.Repeat([]byte{0x89, 'P', 'N', 'G'}, 4096)
	cases := []struct {
		name   string
		method string
		hdr    map[string]string
		ctype  string
		body   []byte
	}{
		{"range", http.MethodGet, map[string]string{"Range": "bytes=0-99"}, "application/json", big},
		{"head", http.MethodHead, nil, "application/json", nil},
		{"png", http.MethodGet, nil, "image/png", png},
		{"woff2", http.MethodGet, nil, "font/woff2", png},
		{"zip", http.MethodGet, nil, "application/zip", png},
		{"xlsx", http.MethodGet, nil, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", png},
	}
	for _, tc := range cases {
		rec := gzipServe(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", tc.ctype)
			_, _ = w.Write(tc.body)
		}, tc.method, "gzip", tc.hdr)
		if rec.Header().Get("Content-Encoding") != "" {
			t.Errorf("%s: compressed", tc.name)
		}
		if tc.method != http.MethodHead && !bytes.Equal(rec.Body.Bytes(), tc.body) {
			t.Errorf("%s: body altered", tc.name)
		}
	}
}

// A handler serving a pre-compressed bundle sets Content-Encoding itself; the
// middleware must forward its bytes and headers untouched (no double gzip).
func TestGzipPassesPrecompressedResponsesUntouched(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(benchJSONBody(8 << 10))
	_ = zw.Close()
	pre := buf.Bytes()
	rec := gzipServe(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Vary", "Accept-Encoding")
		_, _ = w.Write(pre)
	}, http.MethodGet, "gzip", nil)
	if got := rec.Header().Values("Content-Encoding"); len(got) != 1 || got[0] != "gzip" {
		t.Fatalf("Content-Encoding rewritten: %v", got)
	}
	if !bytes.Equal(rec.Body.Bytes(), pre) {
		t.Fatalf("pre-compressed bytes altered (%d vs %d)", rec.Body.Len(), len(pre))
	}
	if n := len(rec.Header().Values("Vary")); n != 1 {
		t.Fatalf("Vary duplicated: %v", rec.Header().Values("Vary"))
	}
}

func TestGzipRespectsAcceptEncoding(t *testing.T) {
	body := benchJSONBody(4 << 10)
	h := func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(body) }
	for _, ae := range []string{"", "identity", "gzip;q=0", "br"} {
		rec := gzipServe(t, h, http.MethodGet, ae, nil)
		if rec.Header().Get("Content-Encoding") != "" || !bytes.Equal(rec.Body.Bytes(), body) {
			t.Errorf("Accept-Encoding %q: compressed", ae)
		}
	}
	rec := gzipServe(t, h, http.MethodGet, "br;q=1.0, gzip;q=0.8", nil)
	if rec.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("weighted gzip not honored")
	}
}

// Untyped bodies are sniffed from the plain bytes, not the gzip stream (which
// net/http would label application/x-gzip).
func TestGzipSniffsContentTypeBeforeCompressing(t *testing.T) {
	html := []byte("<!DOCTYPE html><html><body>" + strings.Repeat("<p>hello</p>", 400) + "</body></html>")
	rec := gzipServe(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(html) }, http.MethodGet, "gzip", nil)
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("Content-Type = %q, want text/html", ct)
	}
	if !bytes.Equal(gunzipBody(t, rec.Body.Bytes()), html) {
		t.Fatalf("round trip mismatch")
	}
}

func TestGzipFlushStreamsCompressedChunks(t *testing.T) {
	rec := gzipServe(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-ndjson")
		_, _ = w.Write([]byte("{\"n\":1}\n"))
		w.(http.Flusher).Flush()
		_, _ = w.Write([]byte("{\"n\":2}\n"))
	}, http.MethodGet, "gzip", nil)
	if !rec.Flushed {
		t.Fatalf("Flush did not reach the connection")
	}
	if rec.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("flushed stream not compressed")
	}
	if got := string(gunzipBody(t, rec.Body.Bytes())); got != "{\"n\":1}\n{\"n\":2}\n" {
		t.Fatalf("stream = %q", got)
	}
	// Hijack is still not offered underneath a gzip stream.
	_ = gzipServe(t, func(w http.ResponseWriter, r *http.Request) {
		if _, ok := w.(http.Hijacker); ok {
			t.Errorf("gzip writer must not expose Hijacker")
		}
	}, http.MethodGet, "gzip", nil)
}

// Pooled writers are reset per response: concurrent responses never mix.
func TestGzipPooledWritersAreIsolated(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body := bytes.Repeat([]byte{byte('a' + i%26)}, 4096+i)
			rec := gzipServe(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(body) }, http.MethodGet, "gzip", nil)
			if !bytes.Equal(gunzipBody(t, rec.Body.Bytes()), body) {
				t.Errorf("response %d corrupted", i)
			}
		}(i)
	}
	wg.Wait()
}
