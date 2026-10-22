//go:build !cli

package main

import (
	"os"
	"strings"
)

// instanceOriginEnv is the instance's public https origin, written by the
// router into every hosted instance's environment (platform_instance_origin.go)
// and reserved, so an app's own env can never set it.
const instanceOriginEnv = "BENMORE_INSTANCE_ORIGIN"

// appMCPBaseURL is the origin the connector resource (/api/_mcp) is pinned to.
// app.yaml seo.url wins, as before. A hosted tenant without one used to get
// http://localhost:<port>, which validAppMCPResource refuses, so the connector
// never mounted on such apps; it now uses the router's origin for the instance
// (its verified custom domain on prod, else <instance>.<platform domain>).
// Self-hosted serve and --mcp-local keep baseURL.
func appMCPBaseURL(app *App, baseURL string) string {
	if app == nil || app.MCPLocal || !hostedTenantProcess() {
		return baseURL
	}
	if app.Design != nil && strings.TrimSpace(app.Design.SEO["url"]) != "" {
		return baseURL
	}
	if origin := strings.TrimSpace(os.Getenv(instanceOriginEnv)); strings.HasPrefix(origin, "https://") {
		return origin
	}
	return baseURL
}
