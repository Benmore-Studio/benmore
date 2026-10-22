package legacyacceptance

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"sort"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const legacyVersion = "2025-11-25"

type bearerTransport struct {
	base  http.RoundTripper
	token string
}

func (t bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	request := r.Clone(r.Context())
	request.Header = r.Header.Clone()
	request.Header.Set("Authorization", "Bearer "+t.token)
	return t.base.RoundTrip(request)
}

func clientSession(t *testing.T, endpoint, token string, tlsClient *http.Client) *sdk.ClientSession {
	t.Helper()
	client := &http.Client{Transport: bearerTransport{base: tlsClient.Transport, token: token}, Timeout: 10 * time.Second}
	transport := &sdk.StreamableClientTransport{Endpoint: endpoint, HTTPClient: client, DisableStandaloneSSE: true}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	session, err := sdk.NewClient(&sdk.Implementation{Name: "legacy-sdk-acceptance", Version: "1.6.1"}, nil).Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("SDK v1.6.1 default initialize: %v", err)
	}
	if got := session.InitializeResult().ProtocolVersion; got != legacyVersion {
		t.Fatalf("server negotiated %q, want %q", got, legacyVersion)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

func TestLegacyClientProtocolAndTenantRevocation(t *testing.T) {
	endpoint := requiredEnv(t, "MCP_LEGACY_ENDPOINT")
	resource := requiredEnv(t, "MCP_LEGACY_RESOURCE")
	if endpoint != resource {
		t.Fatalf("endpoint/resource mismatch: %q != %q", endpoint, resource)
	}
	certPEM := []byte(requiredEnv(t, "MCP_LEGACY_CA_CERT"))
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("test TLS certificate is malformed")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		t.Fatalf("parse TLS certificate: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("could not trust supplied test TLS certificate")
	}
	tlsClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}, Timeout: 10 * time.Second}
	t.Cleanup(func() { tlsClient.CloseIdleConnections() })
	token17 := requiredEnv(t, "MCP_LEGACY_TOKEN_17")
	token29 := requiredEnv(t, "MCP_LEGACY_TOKEN_29")
	if token17 == token29 {
		t.Fatal("tenant grants unexpectedly share a bearer token")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	session17List := clientSession(t, endpoint, token17, tlsClient)
	session17Call := clientSession(t, endpoint, token17, tlsClient)
	session29 := clientSession(t, endpoint, token29, tlsClient)
	assertToolInventory(t, ctx, session17List, []string{"list_notes"})
	assertToolInventory(t, ctx, session29, []string{"list_notes", "list_projects"})
	assertRows(t, ctx, session17List, "list_notes", requiredEnv(t, "MCP_LEGACY_EXPECTED_ID_17"))
	assertRows(t, ctx, session17Call, "list_notes", requiredEnv(t, "MCP_LEGACY_EXPECTED_ID_17"))
	assertRows(t, ctx, session29, "list_notes", requiredEnv(t, "MCP_LEGACY_EXPECTED_ID_29"))
	assertRows(t, ctx, session29, "list_projects", "29")

	revoke := requiredEnv(t, "MCP_LEGACY_REVOKE_ENDPOINT")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, revoke, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+requiredEnv(t, "MCP_LEGACY_REVOKE_SECRET"))
	response, err := tlsClient.Do(req)
	if err != nil {
		t.Fatalf("revoke tenant 17 grant: %v", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke control returned %s", response.Status)
	}
	if _, err := session17List.ListTools(ctx, nil); err == nil {
		t.Fatal("same legacy SDK session listed tools after its grant was revoked")
	}
	if result, err := session17Call.CallTool(ctx, &sdk.CallToolParams{Name: "list_notes", Arguments: map[string]any{}}); err == nil {
		t.Fatalf("same legacy SDK session call did not return a protocol error after revocation: result=%+v", result)
	}
	// Revocation is grant-scoped; tenant 29's independent live grant still works.
	assertRows(t, ctx, session29, "list_notes", requiredEnv(t, "MCP_LEGACY_EXPECTED_ID_29"))
}

func assertToolInventory(t *testing.T, ctx context.Context, session *sdk.ClientSession, want []string) {
	t.Helper()
	got, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	names := make([]string, 0, len(got.Tools))
	for _, tool := range got.Tools {
		names = append(names, tool.Name)
	}
	sort.Strings(names)
	sort.Strings(want)
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("tools/list = %v, want %v", names, want)
	}
}

func assertRows(t *testing.T, ctx context.Context, session *sdk.ClientSession, tool, wantID string) {
	t.Helper()
	result, err := session.CallTool(ctx, &sdk.CallToolParams{Name: tool, Arguments: map[string]any{}})
	if err != nil || result == nil || result.IsError {
		t.Fatalf("tools/call %s: result=%+v err=%v", tool, result, err)
	}
	data, ok := result.StructuredContent.(map[string]any)
	if !ok {
		t.Fatalf("%s structured content type %T", tool, result.StructuredContent)
	}
	rows, ok := data["data"].([]any)
	if !ok {
		t.Fatalf("%s data type %T", tool, data["data"])
	}
	ids := make([]string, 0, len(rows))
	for _, item := range rows {
		row, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("%s row type %T", tool, item)
		}
		ids = append(ids, fmt.Sprint(row["id"]))
	}
	sort.Strings(ids)
	want := []string{wantID}
	if !reflect.DeepEqual(ids, want) {
		t.Fatalf("%s returned row IDs %v, want only %v", tool, ids, want)
	}
}

func requiredEnv(t *testing.T, key string) string {
	t.Helper()
	value := os.Getenv(key)
	if value == "" {
		t.Fatalf("missing required fixture environment variable %s", key)
	}
	return value
}
