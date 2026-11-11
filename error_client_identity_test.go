//go:build !cli

package main

import (
	"strings"
	"testing"
)

func TestErrorClientMetadataDistinct(t *testing.T) {
	app := &App{Dir: t.TempDir()}
	event := func(name, published string) map[string]any {
		storeAppEnv(app.Dir, map[string]string{"BENMORE_APP_NAME": name, "BENMORE_PUBLISHED_AT": published, "SENTRY_ENVIRONMENT": "production"})
		return clientSentryEvent(app, clientErrorBody{Message: "example"})
	}
	one := event("customer-one", "2026-10-27T12:00:00Z")
	two := event("customer-two", "2026-10-27T12:00:00Z")
	next := event("customer-one", "2026-10-27T13:00:00Z")
	if one["tags"].(map[string]string)["app"] == two["tags"].(map[string]string)["app"] || one["release"] == next["release"] {
		t.Fatal("client metadata identities collapsed")
	}
	if one["environment"] != "production" {
		t.Fatalf("configured environment hashed: %v", one["environment"])
	}
	for _, value := range []string{one["tags"].(map[string]string)["app"], one["release"].(string)} {
		if strings.Contains(value, "customer-one") || strings.Contains(value, "[redacted:env]") {
			t.Fatalf("expected distinct opaque identity: %q", value)
		}
	}
}
