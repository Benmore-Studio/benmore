//go:build !cli

package main

// Response compression for the per-app server and `benmore host`.
//
// Pre-2026-10 every response from a gzip-accepting client allocated a fresh
// gzip.Writer at DefaultCompression (~800KB of deflate tables, measured at
// ~1MB/op), including 204/304 answers, 100-byte JSON bodies, PNGs and anything
// a handler had already compressed, and sent no Vary header. Under a tenant's
// MemoryHigh that allocation churn is pure GC pressure. This writer:
//
//   - reuses BestSpeed writers from a sync.Pool (dynamic responses: the CPU
//     spent at higher levels buys a few percent on JSON that changes per
//     request);
//   - buffers the first gzipMinSize bytes and only compresses a body that
//     reaches that size (a tiny body gets bigger with gzip framing);
//   - never compresses 1xx/204/206/304, Range requests, HEAD bodies,
//     incompressible types (images, audio/video, fonts, archives), or a
//     response whose handler set Content-Encoding itself (pre-compressed
//     static bundles pass through byte for byte);
//   - adds `Vary: Accept-Encoding` to every response it could have compressed,
//     so a shared cache cannot hand a gzip body to a client that never asked.
//
// Flush support is new and deliberate: Flush emits whatever is buffered
// (compressed when the response is eligible) and flushes the connection.
// Hijack and Unwrap are still NOT exposed, as before: hijacking (or reaching
// the raw writer through http.ResponseController) underneath a gzip stream
// would interleave raw bytes with compressed ones. Upgrade/SSE requests skip
// the wrapper entirely.

import (
	"compress/gzip"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"
)

// gzipMinSize is the body size below which compression is skipped. Gzip adds
// ~18 bytes of framing plus deflate block overhead; below ~1KB the saving is
// a few hundred bytes at most and the CPU and allocation cost dominate.
const gzipMinSize = 1024

var gzipWriterPool = sync.Pool{
	New: func() any {
		gz, _ := gzip.NewWriterLevel(io.Discard, gzip.BestSpeed)
		return gz
	},
}

type gzipResponseWriter struct {
	http.ResponseWriter
	req *http.Request

	status      int  // status the handler asked for (0 = not yet)
	wroteHeader bool // underlying WriteHeader has been called
	decided     bool // compress has been decided
	compress    bool
	buf         []byte
	gz          *gzip.Writer
}

// WriteHeader records the status. 1xx informational headers pass straight
// through (they are not the final response). Statuses that never carry a
// compressible body decide "no" immediately so the header goes out unchanged.
func (w *gzipResponseWriter) WriteHeader(code int) {
	if w.status != 0 || w.wroteHeader {
		return // superfluous call; the first status wins, as in net/http
	}
	if code >= 100 && code < 200 && code != http.StatusSwitchingProtocols {
		w.ResponseWriter.WriteHeader(code)
		return
	}
	w.status = code
	if !statusAllowsGzip(code) {
		w.decide(false, nil)
	}
}

func (w *gzipResponseWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	if w.decided {
		if w.compress {
			return w.gz.Write(b)
		}
		return w.ResponseWriter.Write(b)
	}
	// Still buffering: take as much as fits, decide once the threshold is
	// reached, then pass the remainder through the chosen path.
	if len(w.buf)+len(b) < gzipMinSize {
		if w.buf == nil {
			w.buf = make([]byte, 0, gzipMinSize)
		}
		w.buf = append(w.buf, b...)
		return len(b), nil
	}
	w.decide(true, b)
	if w.compress {
		return w.gz.Write(b)
	}
	return w.ResponseWriter.Write(b)
}

// Flush emits buffered bytes and flushes the connection. A streaming handler
// that flushes before the threshold is decided on headers alone (size is
// unknown for a stream).
func (w *gzipResponseWriter) Flush() {
	if !w.decided {
		if w.status == 0 {
			w.status = http.StatusOK
		}
		w.decide(true, nil)
	}
	if w.compress {
		_ = w.gz.Flush()
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// decide fixes the encoding, writes the real header and drains the buffer.
// sizeReached reports whether the body met gzipMinSize (or is a stream);
// pending is the not-yet-buffered write that triggered the decision, used
// only for content sniffing (the caller writes it after decide returns).
func (w *gzipResponseWriter) decide(sizeReached bool, pending []byte) {
	if w.decided {
		return
	}
	w.decided = true
	h := w.ResponseWriter.Header()
	// Sniff like net/http would have on the uncompressed bytes; once
	// Content-Encoding is gzip the server would otherwise sniff the gzip
	// stream and label every untyped response application/x-gzip.
	if _, typed := h["Content-Type"]; !typed {
		sniff := w.buf
		if len(sniff) == 0 {
			sniff = pending
		}
		if len(sniff) > 0 {
			h.Set("Content-Type", http.DetectContentType(sniff))
		}
	}
	eligible := gzipEligibleResponse(w.req, w.status, h)
	if eligible {
		addVaryAcceptEncoding(h)
	}
	w.compress = eligible && sizeReached
	if w.compress {
		h.Set("Content-Encoding", "gzip")
		h.Del("Content-Length") // length changes after compression
		// A strong validator names exact bytes; the compressed variant has
		// different bytes, so weaken it (RFC 9110 8.8.1).
		if et := h.Get("ETag"); et != "" && !strings.HasPrefix(et, "W/") {
			h.Set("ETag", "W/"+et)
		}
		w.gz = gzipWriterPool.Get().(*gzip.Writer)
		w.gz.Reset(w.ResponseWriter)
	}
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(w.status)
	if len(w.buf) > 0 {
		if w.compress {
			_, _ = w.gz.Write(w.buf)
		} else {
			_, _ = w.ResponseWriter.Write(w.buf)
		}
	}
	w.buf = nil
}

// close finishes the response: an undecided (small or empty) body is written
// uncompressed, a compressing one gets its gzip trailer, and the writer goes
// back to the pool.
func (w *gzipResponseWriter) close() {
	if !w.decided {
		if w.status == 0 {
			// The handler wrote nothing at all; leave the implicit 200 to
			// net/http rather than forcing a header out here.
			if len(w.buf) == 0 {
				w.decided = true
				return
			}
			w.status = http.StatusOK
		}
		w.decide(false, nil)
	}
	if w.gz != nil {
		_ = w.gz.Close()
		w.gz.Reset(io.Discard)
		gzipWriterPool.Put(w.gz)
		w.gz = nil
	}
}

func statusAllowsGzip(code int) bool {
	switch code {
	case http.StatusNoContent, http.StatusNotModified, http.StatusPartialContent, http.StatusSwitchingProtocols:
		return false
	}
	return code >= 200
}

// gzipEligibleResponse reports whether this response may be compressed at
// all (independent of its size).
func gzipEligibleResponse(r *http.Request, status int, h http.Header) bool {
	if !statusAllowsGzip(status) || r.Method == http.MethodHead {
		return false
	}
	if h.Get("Content-Encoding") != "" {
		return false // already encoded by the handler: pass through untouched
	}
	if h.Get("Content-Range") != "" {
		return false
	}
	return gzipCompressibleType(h.Get("Content-Type"))
}

// gzipCompressibleType reports whether a media type benefits from gzip.
// Formats that are already compressed (images except SVG, audio, video,
// fonts other than legacy TTF/OTF, archives, PDFs) only lose CPU to it.
func gzipCompressibleType(contentType string) bool {
	if contentType == "" {
		return true
	}
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		mt = strings.ToLower(strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0]))
	}
	switch {
	case mt == "image/svg+xml":
		return true
	case strings.HasPrefix(mt, "image/"), strings.HasPrefix(mt, "audio/"), strings.HasPrefix(mt, "video/"):
		return false
	case mt == "font/woff", mt == "font/woff2", mt == "application/font-woff", mt == "application/font-woff2":
		return false
	case mt == "text/event-stream":
		return false
	}
	switch mt {
	case "application/zip", "application/gzip", "application/x-gzip", "application/x-bzip2",
		"application/x-xz", "application/zstd", "application/x-7z-compressed",
		"application/x-rar-compressed", "application/vnd.rar", "application/pdf",
		"application/x-brotli", "application/wasm-gzip":
		return false
	}
	// Office Open XML / OpenDocument formats are zip containers.
	if strings.HasPrefix(mt, "application/vnd.openxmlformats-") || strings.HasPrefix(mt, "application/vnd.oasis.opendocument.") {
		return false
	}
	return true
}

// addVaryAcceptEncoding appends Accept-Encoding to Vary unless a value
// already covers it.
func addVaryAcceptEncoding(h http.Header) {
	for _, v := range h.Values("Vary") {
		for _, part := range strings.Split(v, ",") {
			p := strings.TrimSpace(part)
			if p == "*" || strings.EqualFold(p, "Accept-Encoding") {
				return
			}
		}
	}
	h.Add("Vary", "Accept-Encoding")
}

func acceptsGzip(r *http.Request) bool {
	for _, v := range r.Header.Values("Accept-Encoding") {
		for _, part := range strings.Split(v, ",") {
			coding, params, _ := strings.Cut(strings.TrimSpace(part), ";")
			if !strings.EqualFold(strings.TrimSpace(coding), "gzip") {
				continue
			}
			// gzip;q=0 explicitly refuses the coding.
			q := strings.ReplaceAll(strings.ToLower(params), " ", "")
			if q == "q=0" || q == "q=0.0" || q == "q=0.00" || q == "q=0.000" {
				return false
			}
			return true
		}
	}
	return false
}

func gzipMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip gzip for SSE / streaming responses + WebSocket upgrades.
		// WS hijacks the raw TCP connection - a gzip wrapper would
		// (a) make the wrapper lose Hijacker support and (b) corrupt
		// any control frames the framework writes post-upgrade. Range
		// requests are answered with byte offsets into the identity body;
		// compressing a 206 would hand the client the wrong bytes.
		if !acceptsGzip(r) ||
			strings.Contains(r.Header.Get("Accept"), "text/event-stream") ||
			strings.HasPrefix(r.URL.Path, "/sse/") ||
			strings.EqualFold(r.Header.Get("Upgrade"), "websocket") ||
			r.Header.Get("Range") != "" {
			next.ServeHTTP(w, r)
			return
		}
		gw := &gzipResponseWriter{ResponseWriter: w, req: r}
		defer gw.close()
		next.ServeHTTP(gw, r)
	})
}
