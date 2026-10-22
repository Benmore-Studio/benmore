//go:build !cli && !windows

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAppMCPSDKProtocolAndRequestAuthority(t *testing.T) {
	app, pair, _ := appMCPResultFixture(t, false)
	meta := func(version string) map[string]any {
		return map[string]any{"io.modelcontextprotocol/protocolVersion": version, "io.modelcontextprotocol/clientInfo": map[string]any{"name": "fixture", "version": "1"}, "io.modelcontextprotocol/clientCapabilities": map[string]any{}}
	}
	wire := func(method string, params map[string]any) string {
		b, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	request := func(method, version, body, token, origin string, overrides ...map[string]string) *httptest.ResponseRecorder {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		r := httptest.NewRequest(method, grantFixtureResource, strings.NewReader(body)).WithContext(ctx)
		var frame struct {
			Method string `json:"method"`
		}
		if json.Unmarshal([]byte(body), &frame) == nil {
			r.Header.Set("Mcp-Method", frame.Method)
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		if version != "" {
			r.Header.Set("Mcp-Protocol-Version", version)
		}
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		for _, headers := range overrides {
			for key, value := range headers {
				r.Header.Set(key, value)
			}
		}
		w := httptest.NewRecorder()
		serveAppMCP(w, r, app, grantFixtureResource)
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("cache policy: %v", w.Header())
		}
		if w.Header().Get("Mcp-Session-Id") != "" {
			t.Fatal("stateless endpoint issued a session")
		}
		return w
	}
	modern := "2026-07-28"
	for _, version := range []string{"2025-06-18", "2025-11-25"} {
		w := request("POST", version, wire("initialize", map[string]any{"protocolVersion": version, "clientInfo": map[string]any{"name": "legacy", "version": "1"}, "capabilities": map[string]any{}}), pair.AccessToken, "")
		var response struct {
			Result struct {
				ProtocolVersion string `json:"protocolVersion"`
			} `json:"result"`
		}
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &response) != nil || response.Result.ProtocolVersion != version {
			t.Fatalf("legacy negotiation %s: %d %s", version, w.Code, w.Body.String())
		}
		w = request("POST", version, wire("tools/list", map[string]any{}), pair.AccessToken, "")
		if w.Code != 200 || !strings.Contains(w.Body.String(), "list_notes") {
			t.Fatalf("legacy tools: %d %s", w.Code, w.Body.String())
		}
	}
	for _, tc := range []struct {
		name, version, body string
		status              int
		code                string
	}{
		{"discovery", modern, wire("server/discover", map[string]any{"_meta": meta(modern)}), 200, ""},
		{"invalid cursor", modern, wire("tools/list", map[string]any{"_meta": meta(modern), "cursor": "not-a-valid-cursor"}), 400, "-32602"},
		{"missing metadata", modern, wire("tools/list", map[string]any{}), 400, "-32602"},
		{"mismatch", modern, wire("tools/list", map[string]any{"_meta": meta("2025-11-25")}), 400, "-32020"},
		{"missing header", "", wire("tools/list", map[string]any{"_meta": meta(modern)}), 400, "-32020"},
		{"subscription denied", modern, wire("subscriptions/listen", map[string]any{"_meta": meta(modern), "notifications": map[string]any{"toolsListChanged": true}}), 404, "-32601"},
		{"body limit", modern, strings.Repeat("x", appMCPInputLimit+(8<<10)+1), 413, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := request("POST", tc.version, tc.body, pair.AccessToken, "")
			if w.Code != tc.status || (tc.code != "" && !strings.Contains(w.Body.String(), tc.code)) {
				t.Fatalf("wire response: %d %s", w.Code, w.Body.String())
			}
		})
	}
	for _, headers := range []map[string]string{{"Mcp-Method": "tools/call"}, {"Mcp-Method": ""}} {
		w := request("POST", modern, wire("tools/list", map[string]any{"_meta": meta(modern)}), pair.AccessToken, "", headers)
		if w.Code != 400 || !strings.Contains(w.Body.String(), "-32020") {
			t.Fatalf("method/header mismatch: %d %s", w.Code, w.Body.String())
		}
	}
	for _, method := range []string{"GET", "DELETE"} {
		w := request(method, modern, "", pair.AccessToken, "")
		if w.Code != 405 || w.Header().Get("Allow") != "POST" {
			t.Fatalf("stateless method: %d %v", w.Code, w.Header())
		}
	}
	body := wire("tools/list", map[string]any{"_meta": meta(modern)})
	for _, token := range []string{"", pair.RefreshToken, "ordinary-api-token"} {
		w := request("POST", modern, body, token, "")
		if w.Code != 401 || !strings.Contains(w.Header().Get("WWW-Authenticate"), "https://fixture.example/.well-known/oauth-protected-resource/api/_mcp") {
			t.Fatalf("ambient credentials: %d %v", w.Code, w.Header())
		}
	}
	if w := request("POST", modern, body, pair.AccessToken, "https://attacker.example"); w.Code != 403 {
		t.Fatalf("cross-origin: %d", w.Code)
	}
	// Canonical access modes filter discovery even when the token has table scope.
	app.Access.rules["notes"] = map[AccessOp]string{OpRead: "admin"}
	w := request("POST", modern, body, pair.AccessToken, "")
	if w.Code != 200 || strings.Contains(w.Body.String(), "list_notes") {
		t.Fatalf("role-gated discovery: %d %s", w.Code, w.Body.String())
	}
	auditExec(t, app.DB, "UPDATE _benmore_mcp_grants SET revoked=1")
	if w := request("POST", modern, body, pair.AccessToken, ""); w.Code != 401 {
		t.Fatalf("revoked grant: %d %s", w.Code, w.Body.String())
	}
}

// JSON-RPC batches left MCP in 2025-06-18, but the SDK still accepts them from
// a request without a protocol header and runs every element concurrently,
// each with its own authority checks. One HTTP request carries one message.
func TestAppMCPSDKRejectsJSONRPCBatches(t *testing.T) {
	app, pair, _ := appMCPResultFixture(t, false)
	elements := make([]string, 0, 40)
	for i := range 40 {
		elements = append(elements, fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/list","params":{}}`, i+1))
	}
	for _, version := range []string{"", "2025-03-26"} {
		for _, body := range []string{"[" + strings.Join(elements, ",") + "]", " \n\t[" + elements[0] + "]"} {
			r := httptest.NewRequest("POST", grantFixtureResource, strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Accept", "application/json, text/event-stream")
			r.Header.Set("Authorization", "Bearer "+pair.AccessToken)
			if version != "" {
				r.Header.Set("Mcp-Protocol-Version", version)
			}
			w := httptest.NewRecorder()
			serveAppMCP(w, r, app, grantFixtureResource)
			if w.Code != 400 || strings.Contains(w.Body.String(), "list_notes") {
				t.Fatalf("batch (version %q) answered: %d %.200s", version, w.Code, w.Body.String())
			}
		}
	}
	// A single message without a protocol header still works.
	r := httptest.NewRequest("POST", grantFixtureResource, strings.NewReader(elements[0]))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	r.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	w := httptest.NewRecorder()
	serveAppMCP(w, r, app, grantFixtureResource)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "list_notes") {
		t.Fatalf("single legacy message: %d %s", w.Code, w.Body.String())
	}
}
