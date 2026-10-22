//go:build !cli

package main

import "testing"

// A hosted app with no seo.url pinned its connector resource to
// http://localhost:<port>, which is refused, so /api/_mcp never mounted.
func TestAppMCPBaseURLUsesHostedInstanceOrigin(t *testing.T) {
	app := &App{}
	local := "http://localhost:18001"
	t.Setenv(instanceOriginEnv, "https://notes-dev.benmore.test")
	t.Setenv("BENMORE_BIND_LOOPBACK", "")
	if got := appMCPBaseURL(app, local); got != local {
		t.Fatalf("self-hosted serve must keep its base: %q", got)
	}
	t.Setenv("BENMORE_BIND_LOOPBACK", "1")
	if got := appMCPResourceAt(app, local); got != "https://notes-dev.benmore.test/api/_mcp" {
		t.Fatalf("hosted resource = %q", got)
	}
	app.Design = &DesignConfig{SEO: map[string]string{"url": "https://www.example.com"}}
	if got := appMCPBaseURL(app, "https://www.example.com"); got != "https://www.example.com" {
		t.Fatalf("seo.url must win: %q", got)
	}
	app.Design = nil
	t.Setenv(instanceOriginEnv, "http://evil.example")
	if got := appMCPBaseURL(app, local); got != local {
		t.Fatalf("a non-https origin must be ignored: %q", got)
	}
	app.MCPLocal = true
	t.Setenv(instanceOriginEnv, "https://notes-dev.benmore.test")
	if got := appMCPBaseURL(app, local); got != local {
		t.Fatalf("--mcp-local keeps localhost: %q", got)
	}
}
