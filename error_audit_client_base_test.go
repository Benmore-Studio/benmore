//go:build !cli

package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestErrorAuditClientRedactionBoundaries(t *testing.T) {
	app := &App{Dir: t.TempDir()}
	secret := "opaque-private-value-abcdef"
	storeAppEnv(app.Dir, map[string]string{"OPAQUE": secret, "MULTILINE": "private\nmultiline-value"})
	for _, input := range []string{strings.Repeat("x", 2035) + secret, "private\nmultiline-value", "private multiline-value"} {
		if got := scrubForExport(app, input); strings.Contains(got, "opaque-priv") || strings.Contains(got, "multiline-value") {
			t.Fatalf("secret survived export: %q", got)
		}
	}
	body := clientErrorBody{Message: strings.Repeat("x", 990) + secret}
	scrubClientErrorContext(app, &body)
	data, err := json.Marshal(clientSentryEvent(app, body))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "opaque-pr") {
		t.Fatalf("partial secret in client event: %s", data)
	}
}
