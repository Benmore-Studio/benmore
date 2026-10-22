//go:build !cli

package main

import (
	"encoding/json"
	"testing"
)

// One shared URL cannot identify which copy recipient asks to unsubscribe.
func TestEmailOneClickMultipleRecipientsRejectedUserStory(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	receipt := captureSMTP(t, app)
	input, _ := json.Marshal(map[string]any{
		"to": "reader@fixturemail.net", "cc": "colleague@fixturemail.net",
		"bcc": "private@fixturemail.net", "one_click": true,
		"unsubscribe_url": "https://app.fixturemail.net/u?token=reader-token",
	})
	rr := runProbeGHAFlow(t, app, copiesFlow, string(input))
	if rr.Code < 400 {
		t.Fatalf("multi-recipient one-click flow sent: %d %s", rr.Code, rr.Body.String())
	}
	select {
	case got := <-receipt:
		t.Fatalf("rejected send reached SMTP: %v", got.recipients)
	default:
	}
}
