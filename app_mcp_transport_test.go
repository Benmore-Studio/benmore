//go:build !cli && !windows

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

type appMCPBearerRoundTripper struct {
	base  http.RoundTripper
	token string
}

func (rt appMCPBearerRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	request = request.Clone(request.Context())
	request.Header.Set("Authorization", "Bearer "+rt.token)
	return rt.base.RoundTrip(request)
}

func TestAppMCPSDKStreamableTLSRoundTrip(t *testing.T) {
	for _, read := range []bool{false, true} {
		name := "list"
		if read {
			name = "read"
		}
		t.Run(name, func(t *testing.T) {
			app, _, uid := appMCPResultFixture(t, read)
			if read {
				enrollNotesRevisions(t, app) // the enrolled shape must also satisfy the wire schema
			}
			var resource string
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				serveAppMCP(w, r, app, resource)
			}))
			t.Cleanup(server.Close)
			resource = server.URL + "/api/_mcp"

			now := time.Now()
			pair, err := createAppMCPGrant(app, uid, "17", "client-fixture", resource, "notes:read", now)
			if err != nil {
				t.Fatal(err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			httpClient := server.Client()
			httpClient.Transport = appMCPBearerRoundTripper{base: httpClient.Transport, token: pair.AccessToken}
			transport := &sdk.StreamableClientTransport{
				Endpoint: resource, HTTPClient: httpClient, DisableStandaloneSSE: true,
			}
			client := sdk.NewClient(&sdk.Implementation{Name: "fixture-client", Version: "1"}, nil)
			session, err := client.Connect(ctx, transport, nil)
			if err != nil {
				t.Fatalf("connect SDK client: %v", err)
			}
			defer func() {
				if err := session.Close(); err != nil {
					t.Errorf("close SDK session: %v", err)
				}
			}()

			listed, err := session.ListTools(ctx, nil)
			if err != nil || len(listed.Tools) != 1 || listed.Tools[0].Name != "list_notes" || listed.Tools[0].OutputSchema == nil {
				t.Fatalf("listed tools: %+v, %v", listed, err)
			}
			tool := listed.Tools[0]

			args := map[string]any{}
			if read {
				args = map[string]any{"id": 1}
			}
			result, err := session.CallTool(ctx, &sdk.CallToolParams{Name: "list_notes", Arguments: args})
			if err != nil || result.IsError || result.StructuredContent == nil {
				t.Fatalf("authorized call: %+v, %v", result, err)
			}
			if len(result.Content) != 1 {
				t.Fatalf("content count: %+v", result.Content)
			}
			text, ok := result.Content[0].(*sdk.TextContent)
			if !ok {
				t.Fatalf("content type: %T", result.Content[0])
			}
			structuredJSON, err := json.Marshal(result.StructuredContent)
			if err != nil {
				t.Fatal(err)
			}
			var textValue, structuredValue any
			if err := json.Unmarshal([]byte(text.Text), &textValue); err != nil {
				t.Fatalf("text content is not JSON: %v", err)
			}
			if err := json.Unmarshal(structuredJSON, &structuredValue); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(textValue, structuredValue) {
				t.Fatalf("text and structured content differ: %s != %s", text.Text, structuredJSON)
			}

			// The text mirror carries every required envelope field and _meta
			// repeats the provenance.
			envelope, _ := textValue.(map[string]any)
			for _, field := range []string{"data", "observed_at", "source_revisions", "completeness", "pagination", "freshness", "warnings"} {
				if _, present := envelope[field]; !present {
					t.Fatalf("text content lacks %q: %s", field, text.Text)
				}
			}
			metaJSON, err := json.Marshal(result.Meta["source_revisions"])
			if err != nil || result.Meta["observed_at"] != envelope["observed_at"] {
				t.Fatalf("_meta observed_at: %v", result.Meta)
			}
			wantRevisions, _ := json.Marshal(envelope["source_revisions"])
			if string(metaJSON) != string(wantRevisions) {
				t.Fatalf("_meta source_revisions %s != %s", metaJSON, wantRevisions)
			}
			if revisions, _ := envelope["source_revisions"].(map[string]any); read && revisions["row:notes/1"] != "1" {
				t.Fatalf("enrolled read lacks its row revision: %v", revisions)
			}

			schemaJSON, err := json.Marshal(tool.OutputSchema)
			if err != nil {
				t.Fatal(err)
			}
			var schema jsonschema.Schema
			if err := json.Unmarshal(schemaJSON, &schema); err != nil {
				t.Fatalf("decode output schema: %v", err)
			}
			resolved, err := schema.Resolve(nil)
			if err != nil {
				t.Fatalf("resolve output schema: %v", err)
			}
			if err := resolved.Validate(result.StructuredContent); err != nil {
				t.Fatalf("output schema rejected result: %v", err)
			}

			var output struct {
				Data json.RawMessage `json:"data"`
			}
			if err := json.Unmarshal(structuredJSON, &output); err != nil {
				t.Fatal(err)
			}
			wantIDs := []int{1, 2}
			var gotIDs []int
			idFromRow := func(row map[string]json.RawMessage) int {
				if len(row) != 1 || row["id"] == nil {
					t.Fatalf("projected keys: got %v, want exactly [id]", reflect.ValueOf(row).MapKeys())
				}
				var id int
				if err := json.Unmarshal(row["id"], &id); err != nil {
					t.Fatalf("projected id: %v", err)
				}
				return id
			}
			if read {
				wantIDs = []int{1}
				var row map[string]json.RawMessage
				if err := json.Unmarshal(output.Data, &row); err != nil {
					t.Fatal(err)
				}
				gotIDs = []int{idFromRow(row)}
			} else {
				var rows []map[string]json.RawMessage
				if err := json.Unmarshal(output.Data, &rows); err != nil {
					t.Fatal(err)
				}
				gotIDs = make([]int, len(rows))
				for i, row := range rows {
					gotIDs[i] = idFromRow(row)
				}
			}
			slices.Sort(gotIDs)
			if !reflect.DeepEqual(gotIDs, wantIDs) {
				t.Fatalf("authorized projected IDs: got %v, want %v", gotIDs, wantIDs)
			}

			invalidArgs := map[string]any{"per_page": 501}
			if read {
				invalidArgs = map[string]any{"id": 0}
			}
			invalid, err := session.CallTool(ctx, &sdk.CallToolParams{Name: "list_notes", Arguments: invalidArgs})
			if err != nil || !invalid.IsError || invalid.StructuredContent != nil {
				t.Fatalf("invalid arguments returned success data: %+v, %v", invalid, err)
			}
		})
	}
}
