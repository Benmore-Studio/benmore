//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The recording beacon is anonymous, so it must not let one caller grow an
// app's in-memory buffer without bound.
func TestRecordingBeaconIsBounded(t *testing.T) {
	app := &App{DevMode: true}
	mux := http.NewServeMux()
	RegisterRecordingRoutes(mux, app)
	post := func(body string) int {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/_internal/recording", strings.NewReader(body)))
		return rec.Code
	}
	ev := strings.Repeat(`{"type":"click","timestamp":1,"data":1},`, 1000) + `{"type":"click","timestamp":1,"data":1}`
	for i := 0; i < 80; i++ {
		post(`{"id":"s1","events":[` + ev + `]}`)
	}
	if n := len(app.recordingStore().sessions["s1"].Events); n > 60000 {
		t.Fatalf("session buffer grew to %d events", n)
	}
	if code := post(`{"id":"` + strings.Repeat("x", 500) + `","events":[]}`); code != 400 {
		t.Fatalf("oversized id accepted: %d", code)
	}
	// The event-count cap alone allows 50000 events of ~4 MiB each: the
	// buffer is also bounded in bytes.
	big := `{"id":"fat","events":[{"type":"snapshot","timestamp":1,"data":"` + strings.Repeat("a", 3<<20) + `"}]}`
	for i := 0; i < 40; i++ {
		post(big)
	}
	if n := len(app.recordingStore().sessions["fat"].Events); n > 10 {
		t.Fatalf("session buffered %d MiB-sized events; byte cap missing", n)
	}
	if code := post(`{"id":"big","events":[{"type":"snapshot","timestamp":1,"data":"` + strings.Repeat("a", 5<<20) + `"}]}`); code != 400 {
		t.Fatalf("oversized batch accepted: %d", code)
	}
}
