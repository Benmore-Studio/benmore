//go:build !cli

package main

// Prometheus-format /metrics endpoint. No external client library -
// Prometheus exposition format is plain text, and the framework only
// needs a small handful of counters + histograms. Keeping it dep-free
// avoids dragging in client_golang's transitive dependencies (procfs,
// gogo-protobuf) for what amounts to ~200 lines of arithmetic.
//
// What's exported:
//   benmore_http_requests_total{status}             counter
//   benmore_http_request_duration_seconds           histogram
//   benmore_db_queries_total                        counter
//   benmore_db_query_duration_seconds               histogram
//   benmore_encryption_ops_total{op}                counter
//   benmore_build_info{version}                     gauge (constant 1)
//
// Hooked at the HTTP middleware layer (every request through the mux),
// the QueryRows wrapper (every DB read), and fieldEncrypt / fieldDecrypt
// (every crypto operation). All counters/histograms are sync/atomic;
// no mutexes on the hot path.
//
// Access control: the /metrics endpoint requires `Authorization: Bearer
// <BENMORE_METRICS_TOKEN>`. When BENMORE_METRICS_TOKEN is unset, the
// endpoint returns 404 - no scrapeable surface unless the operator opts
// in. Standard pattern: set the token via systemd EnvironmentFile and
// configure Prometheus to scrape with bearer_token_file.

import (
	"bufio"
	"crypto/hmac"
	"fmt"
	"math"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ===== Counters =====

var (
	metricHTTPRequests     sync.Map // map[string]*atomic.Int64 keyed by status bucket "2xx", "3xx", "4xx", "5xx"
	metricDBQueries        atomic.Int64
	metricEncryptionEncOps atomic.Int64
	metricEncryptionDecOps atomic.Int64
)

func incHTTPRequest(status int) {
	bucket := httpStatusBucket(status)
	v, _ := metricHTTPRequests.LoadOrStore(bucket, new(atomic.Int64))
	v.(*atomic.Int64).Add(1)
}

func httpStatusBucket(code int) string {
	switch {
	case code >= 500:
		return "5xx"
	case code >= 400:
		return "4xx"
	case code >= 300:
		return "3xx"
	case code >= 200:
		return "2xx"
	default:
		return "1xx"
	}
}

func incDBQuery()       { metricDBQueries.Add(1) }
func incEncryptionEnc() { metricEncryptionEncOps.Add(1) }
func incEncryptionDec() { metricEncryptionDecOps.Add(1) }

// ===== Histograms =====

// Standard Prometheus latency buckets in seconds. Picked to cover
// "fast page" (10ms) through "slow flow" (5s) with reasonable bucket
// granularity for p50/p95/p99.
var latencyBucketsSec = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

type histogram struct {
	buckets []atomic.Int64 // one counter per bucket boundary, plus +Inf
	sum     atomic.Uint64  // sum stored as bits of float64 via math.Float64bits
	count   atomic.Int64
}

func newHistogram() *histogram {
	return &histogram{buckets: make([]atomic.Int64, len(latencyBucketsSec)+1)}
}

func (h *histogram) Observe(sec float64) {
	for i, ub := range latencyBucketsSec {
		if sec <= ub {
			h.buckets[i].Add(1)
		}
	}
	// +Inf bucket - always incremented
	h.buckets[len(latencyBucketsSec)].Add(1)
	// Atomic float-add via CAS on the uint64 bits.
	for {
		old := h.sum.Load()
		oldF := float64FromBits(old)
		newF := oldF + sec
		newBits := bitsFromFloat64(newF)
		if h.sum.CompareAndSwap(old, newBits) {
			break
		}
	}
	h.count.Add(1)
}

var (
	metricHTTPLatency = newHistogram()
	metricDBLatency   = newHistogram()
)

// ===== HTTP middleware =====

// MetricsMiddleware wraps a handler to count requests + measure latency.
// Mounted once at the top of the per-app mux. Status code captured via
// a small ResponseWriter wrapper.
func MetricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// /metrics itself isn't counted - keeps scrape traffic from
		// inflating its own numbers.
		if r.URL.Path == "/metrics" {
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		rw := &statusCapturingWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(rw, r)
		elapsed := time.Since(start).Seconds()
		incHTTPRequest(rw.status)
		metricHTTPLatency.Observe(elapsed)
	})
}

type statusCapturingWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (s *statusCapturingWriter) WriteHeader(code int) {
	if !s.wroteHeader {
		s.status = code
		s.wroteHeader = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusCapturingWriter) Write(b []byte) (int, error) {
	if !s.wroteHeader {
		s.status = 200
		s.wroteHeader = true
	}
	return s.ResponseWriter.Write(b)
}

// Flush passes Flusher through to the underlying writer. Required for
// SSE (/sse/events) - the SSE handler type-asserts `w.(http.Flusher)`
// and 500s with "SSE not supported" when the assertion fails.
// Pre-v2.7.60: this metrics middleware (added in v2.7.53) wrapped the
// response writer without implementing Flusher, so every SSE
// connection in every app in the deployment died at handshake time. The
// framework's own responseWriter wrapper (server.go) had this fix
// - the metrics wrapper didn't, and now does.
func (s *statusCapturingWriter) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack passes Hijacker through to the underlying writer. Required
// for WebSocket (/ws) - the upgrade handshake hijacks the raw TCP
// connection. Same failure mode as Flush but for WS: type-assert
// fails, upgrade returns 400, every bm.room()/bm.broadcast()/bm.ws
// subscription is dead. The framework's responseWriter wrapper
// already had this; this metrics wrapper now too.
func (s *statusCapturingWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := s.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

// Unwrap exposes the underlying ResponseWriter so
// http.NewResponseController can walk down to the conn for
// SetWriteDeadline (used by SSE to clear the 30s server WriteTimeout
// so its long-lived stream survives past 30s). Without Unwrap the
// stdlib refuses to walk past this wrapper and the deadline call
// silently fails - Chrome then closes the stream with
// ERR_INCOMPLETE_CHUNKED_ENCODING at exactly the 30s mark.
func (s *statusCapturingWriter) Unwrap() http.ResponseWriter {
	return s.ResponseWriter
}

// ===== /metrics handler =====

// RegisterMetricsRoute mounts /metrics if BENMORE_METRICS_TOKEN is set.
// Without the token the endpoint is dark - no scrape surface at all.
// Mount BEFORE other routes so /metrics resolves first.
func RegisterMetricsRoute(mux *http.ServeMux) {
	token := strings.TrimSpace(os.Getenv("BENMORE_METRICS_TOKEN"))
	if token == "" {
		return
	}
	expected := []byte("Bearer " + token)
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !hmac.Equal([]byte(auth), expected) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		writePrometheusMetrics(w)
	})
}

func writePrometheusMetrics(w http.ResponseWriter) {
	appName := strings.TrimSpace(os.Getenv("BENMORE_APP_NAME"))
	if appName == "" {
		appName = "router"
	}

	// build info - version is hard-coded in main.go; expose for label
	fmt.Fprintf(w, "# HELP benmore_build_info Build/version info (constant 1, labels carry the data)\n")
	fmt.Fprintf(w, "# TYPE benmore_build_info gauge\n")
	fmt.Fprintf(w, "benmore_build_info{version=%q,app=%q} 1\n", version, appName)

	// http requests counter (by status bucket)
	fmt.Fprintf(w, "# HELP benmore_http_requests_total HTTP request count by status bucket\n")
	fmt.Fprintf(w, "# TYPE benmore_http_requests_total counter\n")
	for _, b := range []string{"1xx", "2xx", "3xx", "4xx", "5xx"} {
		v := int64(0)
		if x, ok := metricHTTPRequests.Load(b); ok {
			v = x.(*atomic.Int64).Load()
		}
		fmt.Fprintf(w, "benmore_http_requests_total{app=%q,status=%q} %d\n", appName, b, v)
	}

	// http request duration histogram
	fmt.Fprintf(w, "# HELP benmore_http_request_duration_seconds HTTP request latency\n")
	fmt.Fprintf(w, "# TYPE benmore_http_request_duration_seconds histogram\n")
	writeHistogram(w, "benmore_http_request_duration_seconds", appName, metricHTTPLatency)

	// db queries counter
	fmt.Fprintf(w, "# HELP benmore_db_queries_total Total DB queries executed through QueryRows\n")
	fmt.Fprintf(w, "# TYPE benmore_db_queries_total counter\n")
	fmt.Fprintf(w, "benmore_db_queries_total{app=%q} %d\n", appName, metricDBQueries.Load())

	// db query duration histogram
	fmt.Fprintf(w, "# HELP benmore_db_query_duration_seconds DB query latency\n")
	fmt.Fprintf(w, "# TYPE benmore_db_query_duration_seconds histogram\n")
	writeHistogram(w, "benmore_db_query_duration_seconds", appName, metricDBLatency)

	// encryption op counters
	fmt.Fprintf(w, "# HELP benmore_encryption_ops_total Field-level encrypt/decrypt operations\n")
	fmt.Fprintf(w, "# TYPE benmore_encryption_ops_total counter\n")
	fmt.Fprintf(w, "benmore_encryption_ops_total{app=%q,op=%q} %d\n", appName, "encrypt", metricEncryptionEncOps.Load())
	fmt.Fprintf(w, "benmore_encryption_ops_total{app=%q,op=%q} %d\n", appName, "decrypt", metricEncryptionDecOps.Load())
}

func writeHistogram(w http.ResponseWriter, name, appName string, h *histogram) {
	// Each bucket stores the cumulative count of observations <= its
	// upper bound (Observe increments every bucket whose ub matches),
	// so we emit each bucket value directly - Prometheus expects
	// monotonically-increasing _bucket samples.
	for i, ub := range latencyBucketsSec {
		fmt.Fprintf(w, "%s_bucket{app=%q,le=%q} %d\n", name, appName, formatFloat(ub), h.buckets[i].Load())
	}
	fmt.Fprintf(w, "%s_bucket{app=%q,le=\"+Inf\"} %d\n", name, appName, h.buckets[len(latencyBucketsSec)].Load())
	fmt.Fprintf(w, "%s_sum{app=%q} %g\n", name, appName, float64FromBits(h.sum.Load()))
	fmt.Fprintf(w, "%s_count{app=%q} %d\n", name, appName, h.count.Load())
}

func formatFloat(f float64) string {
	// Prometheus bucket label format. %g handles both "0.005" and "10"
	// correctly without us needing to strip trailing zeros (the bug we
	// fixed: TrimRight("10", "0") returns "1", which mis-labels every
	// histogram bucket whose ub ends in 0).
	return fmt.Sprintf("%g", f)
}

// ===== float64 atomic helpers =====

// Standard library doesn't expose atomic float64 directly; bit-cast
// via math.Float64bits / math.Float64frombits so the histogram's sum
// can use atomic.Uint64 + CAS without unsafe.
func float64FromBits(b uint64) float64 { return math.Float64frombits(b) }
func bitsFromFloat64(f float64) uint64 { return math.Float64bits(f) }
