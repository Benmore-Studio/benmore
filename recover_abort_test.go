//go:build !cli

package main

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// http.ErrAbortHandler is a deliberate abort (httputil.ReverseProxy uses it
// when the client goes away mid-stream). recoverMiddleware passes it on: no
// PANIC line with a stack, no 500 page.
func TestRecoverMiddlewarePassesAbortHandlerThrough(t *testing.T) {
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)

	h := recoverMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "data: first\n\n")
		panic(http.ErrAbortHandler)
	}))
	w := httptest.NewRecorder()
	var got any
	func() {
		defer func() { got = recover() }()
		h.ServeHTTP(w, httptest.NewRequest("GET", "https://app.example.com/sse/events", nil))
	}()
	if got != http.ErrAbortHandler {
		t.Fatalf("recoverMiddleware did not pass ErrAbortHandler on: recovered %v", got)
	}
	if strings.Contains(buf.String(), "PANIC") {
		t.Fatalf("an abort was logged as a panic: %q", buf.String())
	}
	if strings.Contains(w.Body.String(), "Something went wrong") || w.Code == http.StatusInternalServerError && w.Body.Len() > len("data: first\n\n") {
		t.Fatalf("an abort got the 500 page: %d %q", w.Code, w.Body.String())
	}

	// Any other panic is still recovered, logged with its stack and answered 500.
	buf.Reset()
	w = httptest.NewRecorder()
	recoverMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") })).
		ServeHTTP(w, httptest.NewRequest("GET", "https://app.example.com/x", nil))
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("error cache policy = %q", w.Header().Get("Cache-Control"))
	}
	if w.Code != http.StatusInternalServerError || !strings.Contains(buf.String(), "PANIC GET /x - boom") {
		t.Fatalf("ordinary panic: %d, log %q", w.Code, buf.String())
	}
}

// Over a real connection the client sees the stream cut off (an error reading
// the body), not a short body that ends as if it were complete.
func TestRecoverMiddlewareAbortCutsTheConnection(t *testing.T) {
	prev := log.Writer()
	log.SetOutput(io.Discard)
	defer log.SetOutput(prev)
	srv := httptest.NewServer(recoverMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		panic(http.ErrAbortHandler)
	})))
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err == nil {
		t.Fatalf("the aborted stream ended cleanly with %q; want a read error", body)
	}
	if !strings.HasPrefix(string(body), "data: first") {
		t.Fatalf("the part written before the abort is missing: %q", body)
	}
}
