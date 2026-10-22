//go:build !cli && !windows

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// A real MCP client lists and calls the external tool over the streamable
// transport; the result satisfies the advertised wire schema, which carries no
// source_revisions, and the connector token is never forwarded.
func TestAppMCPExternalSDKRoundTrip(t *testing.T) {
	f := newExternalFixture(t)
	f.setCredential(t, "items", externalSecret)
	upstream := newExternalUpstream(t, externalJSONOK(`{"name":"widget","internal":"hidden"}`))
	var resource string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { serveAppMCP(w, r, f.app, resource) }))
	t.Cleanup(server.Close)
	resource = server.URL + "/api/_mcp"
	pair, err := createAppMCPGrant(f.app, f.uid, "17", "client-fixture", resource, "rates:read", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	httpClient := server.Client()
	httpClient.Transport = appMCPBearerRoundTripper{base: httpClient.Transport, token: pair.AccessToken}
	client := sdk.NewClient(&sdk.Implementation{Name: "fixture-client", Version: "1"}, nil)
	session, err := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: resource, HTTPClient: httpClient, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	listed, err := session.ListTools(ctx, nil)
	if err != nil || len(listed.Tools) != 2 {
		t.Fatalf("listed tools: %+v %v", listed, err)
	}
	var tool *sdk.Tool
	for _, candidate := range listed.Tools {
		if candidate.Name == "get_item" {
			tool = candidate
		}
	}
	args := map[string]any{"path": map[string]any{"id": 7}}
	result, err := session.CallTool(ctx, &sdk.CallToolParams{Name: "get_item", Arguments: args})
	if err != nil || result.IsError || result.StructuredContent == nil {
		t.Fatalf("external call: %+v %v", result, err)
	}
	if got := upstream.last().Header.Get("Authorization"); got != "Bearer "+externalSecret {
		t.Fatalf("provider saw %q", got)
	}
	schemaJSON, _ := json.Marshal(tool.OutputSchema)
	var schema jsonschema.Schema
	if err := json.Unmarshal(schemaJSON, &schema); err != nil {
		t.Fatal(err)
	}
	resolved, err := schema.Resolve(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := resolved.Validate(result.StructuredContent); err != nil {
		t.Fatalf("output schema rejected the result: %v", err)
	}
	if encoded, _ := json.Marshal(result.StructuredContent); strings.Contains(string(encoded), "source_revisions") || strings.Contains(string(encoded), "hidden") {
		t.Fatalf("unexpected envelope: %s", encoded)
	}
	// A call without a stored credential reports it plainly through the tool result.
	auditExec(t, f.app.DB, `DELETE FROM _benmore_mcp_connection_credentials`)
	missing, err := session.CallTool(ctx, &sdk.CallToolParams{Name: "get_item", Arguments: args})
	if err != nil || !missing.IsError || !strings.Contains(missing.Content[0].(*sdk.TextContent).Text, "No credential is stored") {
		t.Fatalf("missing credential result: %+v %v", missing, err)
	}
}
