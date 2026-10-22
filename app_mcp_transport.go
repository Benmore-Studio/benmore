//go:build !cli

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerAppMCPTransport(mux appRouteRegistrar, app *App, resource string) {
	for _, method := range []string{"GET", "POST", "DELETE"} {
		mux.HandleFunc(method+" /api/_mcp", func(w http.ResponseWriter, r *http.Request) { serveAppMCP(w, r, app, resource) })
	}
	registerAppMCPOperationRoutes(mux, app, resource)
	registerAppMCPConnectionRoutes(mux, app, resource)
	registerAppMCPGrantRoutes(mux, app)
	registerAppMCPArtifactRoutes(mux, app)
	registerAppMCPTelemetryRoute(mux, app)
}
func serveAppMCP(w http.ResponseWriter, r *http.Request, app *App, resource string) {
	w.Header().Set("Cache-Control", "no-store")
	generation := snapshotAppMCPGeneration(app)
	manifest := (*AppMCPManifest)(nil)
	if generation != nil {
		manifest = generation.manifest
	}
	if manifest == nil || !appMCPOAuthHost(r, app, resource) {
		http.NotFound(w, r)
		return
	}
	if origin := r.Header.Get("Origin"); origin != "" && origin != appMCPOAuthOrigin(resource) {
		http.Error(w, "connector origin denied", 403)
		return
	}
	authorization := r.Header.Values("Authorization")
	raw := ""
	if len(authorization) == 1 && strings.HasPrefix(authorization[0], "Bearer ") {
		raw = strings.TrimPrefix(authorization[0], "Bearer ")
	}
	grant, actor, err := resolveAppMCPAccessForGeneration(r.Context(), app, generation, raw, resource, time.Now())
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+appMCPOAuthOrigin(resource)+`/.well-known/oauth-protected-resource/api/_mcp"`)
		http.Error(w, "connector authorization required", 401)
		return
	}
	if r.Method == http.MethodPost {
		// JSON-RPC batches left MCP in 2025-06-18, but the SDK still runs one
		// from a request without that protocol header, every element
		// concurrently and each with its own authority checks. One request
		// carries one message.
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, appMCPInputLimit+(8<<10)))
		if err != nil {
			http.Error(w, "connector request body is too large", http.StatusRequestEntityTooLarge)
			return
		}
		if trimmed := bytes.TrimLeft(body, " \t\r\n"); len(trimmed) > 0 && trimmed[0] == '[' {
			http.Error(w, "connector batch requests are unsupported", http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
	}
	// Every request gets a fresh inventory; no administrator's server is cached.
	capabilities := &sdk.ServerCapabilities{Tools: &sdk.ToolCapabilities{}}
	if len(appMCPComponents(manifest)) > 0 {
		// Resources are advertised only when the reviewed manifest declares components.
		capabilities.Resources = &sdk.ResourceCapabilities{}
	}
	server := sdk.NewServer(&sdk.Implementation{Name: manifest.Connector.ID, Version: manifest.Connector.Version}, &sdk.ServerOptions{Capabilities: capabilities})
	widgets := appMCPGenerationWidgets(r.Context(), generation)
	authorized := func(ctx context.Context) bool {
		if ctx.Err() != nil || !appMCPGenerationCurrent(app, generation) {
			return false
		}
		current, identity, err := resolveAppMCPAccessForGeneration(ctx, app, generation, raw, resource, time.Now())
		return err == nil && current.ID == grant.ID && appMCPAuthorityUnchanged(actor, identity)
	}
	server.AddReceivingMiddleware(func(next sdk.MethodHandler) sdk.MethodHandler {
		return func(ctx context.Context, method string, request sdk.Request) (sdk.Result, error) {
			call, isToolCall := request.GetParams().(*sdk.CallToolParamsRaw)
			started := time.Now()
			record := func(result sdk.Result, err error, forced string) {
				if method != "tools/call" || !isToolCall || call == nil || !appMCPTelemetryKnownTool(manifest, call.Name) {
					return
				}
				appMCPRecordToolCall(app, call, manifest, started, result, err, forced)
			}
			if method == "subscriptions/listen" {
				return nil, &jsonrpc.Error{Code: jsonrpc.CodeMethodNotFound, Message: "Connector subscriptions are unavailable."}
			}
			if !authorized(ctx) {
				record(nil, errors.New("connector authorization denied"), "denied")
				return nil, errors.New("connector authorization denied")
			}
			started = time.Now()
			result, err := next(ctx, method, request)
			// Authorization-dependent discovery is immediately stale and private.
			switch inventory := result.(type) {
			case *sdk.DiscoverResult:
				if inventory != nil {
					inventory.TTLMs, inventory.CacheScope = 0, "private"
				}
			case *sdk.ListToolsResult:
				if inventory != nil {
					inventory.TTLMs, inventory.CacheScope = 0, "private"
					appMCPApplyToolVisibility(manifest, inventory.Tools)
				}
			case *sdk.ListResourcesResult:
				if inventory != nil {
					inventory.TTLMs, inventory.CacheScope = 0, "private"
				}
			case *sdk.ListResourceTemplatesResult:
				if inventory != nil {
					inventory.TTLMs, inventory.CacheScope = 0, "private"
				}
			case *sdk.ReadResourceResult:
				// The bytes are caller-identical, but whether this caller may
				// read them is not, so no shared cache may answer for it.
				if inventory != nil {
					inventory.TTLMs, inventory.CacheScope = 0, "private"
				}
			}
			if !authorized(ctx) {
				record(result, errors.New("connector authorization changed"), "unknown")
				return nil, errors.New("connector authorization denied")
			}
			record(result, err, "")
			return result, err
		}
	})
	for _, declared := range manifest.Tools {
		tool := declared
		if !appMCPToolAllowed(generation.view, &tool, actor) {
			continue
		}
		server.AddTool(&sdk.Tool{Name: tool.Name, Description: tool.Description, Meta: appMCPToolUIMeta(generation, widgets, &tool), InputSchema: tool.InputSchema, OutputSchema: appMCPEnvelopeSchema(&tool), Annotations: &sdk.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true}}, func(ctx context.Context, request *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			input, ok := appMCPDecodeToolArguments(request.Params.Arguments)
			if !ok {
				return appMCPSDKFailure(appMCPResultFailure("invalid_input")), nil
			}
			result, err := runAppMCPNativeReadGeneration(ctx, app, generation, raw, resource, tool.Name, input)
			if err != nil {
				return appMCPSDKFailure(err), nil
			}
			text, err := json.Marshal(result)
			if err != nil {
				return appMCPSDKFailure(err), nil
			}
			// The text content is the whole envelope (data, observed_at, source
			// revisions, warnings), so a client without structured content loses
			// nothing; _meta repeats the provenance for clients that skip the body.
			meta := sdk.Meta{"observed_at": result.ObservedAt, "source_revisions": result.SourceRevisions}
			if link := appMCPDeepLink(manifest, &tool, result.Data, appMCPOAuthOrigin(resource)); link != "" {
				meta["deep_link"] = link
			}
			return &sdk.CallToolResult{Meta: meta, StructuredContent: result, Content: []sdk.Content{&sdk.TextContent{Text: string(text)}}}, nil
		})
	}
	addAppMCPCommandTools(server, app, generation, grant, actor, raw, resource)
	appMCPRegisterArtifactTools(server, app, generation, grant, actor)
	appMCPRegisterReadArtifactTool(server, app, generation, grant, actor, raw, resource)
	appMCPRegisterResourceTools(server, app, generation, grant, actor, raw, resource)
	appMCPRegisterFileTools(server, app, generation, grant, actor, raw, resource)
	appMCPRegisterExternalTools(server, app, generation, grant, actor, raw, resource)
	// Hosted runtimes receive loopback proxy connections with a public Host.
	// The pinned Host/Origin checks above replace the SDK's localhost heuristic
	// only for a server-configured HTTPS origin; public input cannot disable it.
	handler := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return server }, &sdk.StreamableHTTPOptions{Stateless: true, JSONResponse: true, MaxRequestBodyBytes: appMCPInputLimit + (8 << 10), PropagateRequestCancellation: true, DisableLocalhostProtection: strings.HasPrefix(resource, "https://")})
	capture := &appMCPReadCapture{header: make(http.Header)}
	handler.ServeHTTP(capture, r)
	if capture.overflow {
		serverError(w, r, app, "_mcp", errors.New("connector result exceeded the response limit"), "connector result limit exceeded")
		return
	}
	if !authorized(r.Context()) {
		http.Error(w, "connector authorization denied", 403)
		return
	}
	for key, values := range capture.Header() {
		w.Header()[key] = values
	}
	w.Header().Set("Cache-Control", "no-store")
	status := capture.status
	if status == 0 {
		status = 200
	}
	w.WriteHeader(status)
	_, _ = w.Write(capture.Bytes())
}

// Extension points for later connector packets (external tools register in
// app_mcp_external.go). Each runs once per request after the native read and command tools, receives the same pinned request
// authority, and must register nothing until its packet lands: the server
// advertises no file or external capability yet. Resources live in
// app_mcp_resources.go.
func appMCPSDKFailure(err error) *sdk.CallToolResult {
	code, message := "incomplete_result", "Connector operation could not produce an authorized, validated result."
	var failure *appMCPResultError
	if errors.As(err, &failure) {
		if slices.Contains(appMCPErrorCodes, failure.Code) {
			code, message = failure.Code, failure.Message
		}
	}
	return &sdk.CallToolResult{Meta: sdk.Meta{"error_code": code, "observed_at": time.Now().UTC().Format(time.RFC3339Nano)}, IsError: true, Content: []sdk.Content{&sdk.TextContent{Text: code + ": " + message}}}
}

// The reviewed schema describes rows; the wire schema describes the complete
// shared envelope, including array data for lists and nullable pagination.
func appMCPEnvelopeSchema(tool *AppMCPTool) map[string]any {
	object := func(properties map[string]any, required ...string) map[string]any {
		return map[string]any{"type": "object", "additionalProperties": false, "properties": properties, "required": required}
	}
	stringType := map[string]any{"type": "string"}
	integerType := map[string]any{"type": "integer", "minimum": 0}
	data := any(tool.OutputSchema)
	if tool.Handler.Operation == "table.list" {
		data = map[string]any{"type": "array", "items": tool.OutputSchema}
	}
	pagination := object(map[string]any{"page": map[string]any{"type": "integer", "minimum": 1}, "per_page": map[string]any{"type": "integer", "minimum": 1, "maximum": 500}, "total": integerType, "has_next": map[string]any{"type": "boolean"}}, "page", "per_page", "total", "has_next")
	pagination["type"] = []string{"object", "null"}
	// contract/execution are always present; row:/rows: data revisions are added
	// only when the read could prove them (see app_mcp_read_revisions.go).
	sourceRevisions := object(map[string]any{"contract": stringType, "execution": stringType}, "contract", "execution")
	sourceRevisions["additionalProperties"] = stringType
	return object(map[string]any{
		"data": data, "processing_id": stringType, "observed_at": stringType,
		"source_revisions": sourceRevisions,
		"completeness":     object(map[string]any{"state": map[string]any{"type": "string", "enum": []string{"complete", "partial", "indeterminate"}}, "basis": map[string]any{"type": "string", "enum": []string{"authorized_row", "reported_total", "declared_output"}}, "snapshot_consistent": map[string]any{"type": "boolean", "const": false}}, "state", "basis", "snapshot_consistent"),
		"pagination":       pagination, "freshness": map[string]any{"type": "string", "const": "observed"}, "warnings": map[string]any{"type": "array", "items": stringType},
	}, "data", "observed_at", "source_revisions", "completeness", "pagination", "freshness", "warnings")
}
