//go:build !cli

package main

import (
	"net/http"
	"testing"
	"time"
)

func TestErrorReportingStatusTracksCurrentDelivery(t *testing.T) {
	m := &sentryMuteState{}
	if got := m.status(); got != "configured" {
		t.Fatal(got)
	}
	m.apply(deliveryResult{OK: true, Status: http.StatusOK})
	if got := m.status(); got != "connected" {
		t.Fatal(got)
	}
	m.apply(deliveryResult{Status: http.StatusTooManyRequests, limits: map[string]time.Time{"error": time.Now().Add(time.Hour)}})
	if got := m.status(); got != "rate_limited" {
		t.Fatal(got)
	}
	m.apply(deliveryResult{Rejected: true, Status: http.StatusForbidden, limits: map[string]time.Time{"": time.Now().Add(time.Minute)}})
	if got := m.status(); got != "rejected" {
		t.Fatal(got)
	}
	m.mu.Lock()
	m.until = map[string]time.Time{}
	m.mu.Unlock()
	m.apply(deliveryResult{OK: true, Status: http.StatusOK})
	if got := m.status(); got != "connected" {
		t.Fatal(got)
	}
	app := errorGroupsFixture(t)
	state := appErrorReportingState(app)
	if state.Sentry != "not_configured" || app.errorReporter != nil {
		t.Fatalf("read started reporter: %+v", state)
	}
}
