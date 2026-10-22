//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func recordingBeacon(mux *http.ServeMux, ip, body string) int {
	r := httptest.NewRequest(http.MethodPost, "/_internal/recording", strings.NewReader(body))
	r.RemoteAddr = ip + ":40000"
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w.Code
}

// The recording beacon is anonymous and /_internal/ is exempt from the app's
// general rate limiter, so nothing bounded how often one client could make
// the app decode a 4 MiB batch. One address now gets a fixed budget per
// minute; other addresses are unaffected.
func TestRecordingBeaconIsRateLimitedPerClient(t *testing.T) {
	app := &App{DevMode: true}
	mux := http.NewServeMux()
	RegisterRecordingRoutes(mux, app)
	beacon := `{"id":"rate","events":[{"type":"click","timestamp":1,"data":1}]}`
	for i := 0; i < recordingBeaconsPerMinute; i++ {
		if code := recordingBeacon(mux, "198.51.100.7", beacon); code != http.StatusNoContent {
			t.Fatalf("beacon %d within the budget refused: %d", i+1, code)
		}
	}
	if code := recordingBeacon(mux, "198.51.100.7", beacon); code != http.StatusTooManyRequests {
		t.Fatalf("beacon past the per-client budget: status %d, want 429", code)
	}
	if code := recordingBeacon(mux, "198.51.100.8", beacon); code != http.StatusNoContent {
		t.Fatalf("another client's beacon refused: %d", code)
	}
	if n := len(app.recordingStore().sessions["rate"].Events); n != recordingBeaconsPerMinute+1 {
		t.Fatalf("buffered %d events, want %d (refused beacon must not be stored)", n, recordingBeaconsPerMinute+1)
	}
}

// Decoding a batch can take many times its 4 MiB wire size; the number of
// batches decoded at once is capped so concurrent beacons from many
// addresses can't multiply that.
func TestRecordingBeaconDecodesAreBounded(t *testing.T) {
	app := &App{DevMode: true}
	mux := http.NewServeMux()
	RegisterRecordingRoutes(mux, app)
	store := app.recordingStore()
	for i := 0; i < cap(store.decodeSlots); i++ {
		store.decodeSlots <- struct{}{}
	}
	if code := recordingBeacon(mux, "198.51.100.9", `{"id":"busy","events":[]}`); code != http.StatusServiceUnavailable {
		t.Fatalf("beacon decoded with every decode slot busy: %d", code)
	}
	for i := 0; i < cap(store.decodeSlots); i++ {
		<-store.decodeSlots
	}
	if code := recordingBeacon(mux, "198.51.100.9", `{"id":"busy","events":[]}`); code != http.StatusNoContent {
		t.Fatalf("beacon refused once a slot freed: %d", code)
	}
}
