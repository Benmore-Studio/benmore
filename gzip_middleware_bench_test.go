//go:build !cli

package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Response-compression benchmarks. Run with
// `go test -tags sqlite_fts5 -run '^$' -bench Gzip -benchmem .`.

func benchGzipHandler(body []byte, contentType string) http.Handler {
	return gzipMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", contentType)
		_, _ = w.Write(body)
	}))
}

func benchGzip(b *testing.B, body []byte, contentType string) {
	h := benchGzipHandler(body, contentType)
	req := httptest.NewRequest(http.MethodGet, "/api/notes", nil)
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
	}
}

func benchJSONBody(n int) []byte {
	var sb strings.Builder
	sb.WriteString("[")
	for i := 0; sb.Len() < n; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, `{"id":%d,"title":"Note number %d","body":"Lorem ipsum dolor sit amet","done":false,"user_id":42}`, i, i)
	}
	sb.WriteString("]")
	return []byte(sb.String())
}

func BenchmarkGzipJSON200B(b *testing.B) {
	benchGzip(b, benchJSONBody(200), "application/json")
}

func BenchmarkGzipJSON8KB(b *testing.B) {
	benchGzip(b, benchJSONBody(8<<10), "application/json")
}

func BenchmarkGzipJSON64KB(b *testing.B) {
	benchGzip(b, benchJSONBody(64<<10), "application/json")
}

func BenchmarkGzipPNG32KB(b *testing.B) {
	body := make([]byte, 32<<10)
	for i := range body {
		body[i] = byte(i * 7919)
	}
	benchGzip(b, body, "image/png")
}
