//go:build !cli

package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

func parseFlowOpenAPIContract(request *FlowRequestTrigger) (map[string]any, error) {
	node := request.Contract
	if node.Kind == 0 {
		return nil, nil
	}
	if request.Verify != nil {
		return nil, fmt.Errorf("contract does not support signature-verified requests")
	}
	method := strings.ToUpper(request.Method)
	if method == "" {
		method = "POST"
	}
	if !map[string]bool{"GET": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true, "OPTIONS": true}[method] || strings.EqualFold(strings.TrimSpace(request.Mode), "async") {
		return nil, fmt.Errorf("contract requires a synchronous standard HTTP method")
	}
	if !strings.HasPrefix(request.Path, "/") || strings.ContainsAny(request.Path, "{}?#") || strings.HasSuffix(request.Path, "/") || !routePatternValid(flowMuxPattern(method, request.Path)) {
		return nil, fmt.Errorf("contract requires an exact route using :name parameters")
	}
	var contract map[string]any
	if err := node.Decode(&contract); err != nil {
		return nil, fmt.Errorf("on.request.contract: %w", err)
	}
	if contract == nil {
		return nil, fmt.Errorf("on.request.contract must be an object")
	}
	for key, value := range contract {
		switch key {
		case "request_body", "query", "headers":
			if key == "request_body" && (method == "GET" || method == "HEAD") {
				return nil, fmt.Errorf("contract body is unsupported on GET or HEAD")
			}
			if err := validateFlowOpenAPISchema(value, 0); err != nil {
				return nil, fmt.Errorf("on.request.contract.%s: %w", key, err)
			}
			if key != "request_body" && (value.(map[string]any)["type"] != "object" || value.(map[string]any)["additionalProperties"] != false) {
				return nil, fmt.Errorf("on.request.contract.%s must be a closed object schema", key)
			}
			if key == "headers" {
				properties := value.(map[string]any)["properties"].(map[string]any)
				if len(properties) > 32 {
					return nil, fmt.Errorf("contract headers supports at most 32 names")
				}
				seen := map[string]bool{}
				for name, raw := range properties {
					lower := strings.ToLower(name)
					if len(name) == 0 || len(name) > 64 || seen[lower] {
						return nil, fmt.Errorf("contract header names must be bounded and unique ignoring case")
					}
					for _, ch := range name {
						if !strings.ContainsRune("!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", ch) {
							return nil, fmt.Errorf("invalid contract header name")
						}
					}
					switch lower {
					case "authorization", "cookie", "set-cookie", "host", "connection", "content-length", "content-type", "accept":
						return nil, fmt.Errorf("reserved contract header %q", name)
					}
					property := raw.(map[string]any)
					if property["type"] != "string" || property["enum"] != nil {
						return nil, fmt.Errorf("contract headers require string schemas without values or metadata")
					}
					seen[lower] = true
				}
			}

		case "request_body_required":
			if _, ok := value.(bool); !ok || contract["request_body"] == nil {
				return nil, fmt.Errorf("contract request_body_required requires a boolean and request_body")
			}
		case "request_body_media_types":
			types, ok := value.([]any)
			if !ok || len(types) == 0 || len(types) > 2 || contract["request_body"] == nil {
				return nil, fmt.Errorf("contract request_body_media_types requires one or two supported media types and request_body")
			}
			seen := map[string]bool{}
			for _, raw := range types {
				media, ok := raw.(string)
				if !ok || seen[media] || (media != "application/json" && media != "application/x-www-form-urlencoded") {
					return nil, fmt.Errorf("contract has unsupported or duplicate request body media type")
				}
				if media == "application/x-www-form-urlencoded" {
					if method != "POST" {
						return nil, fmt.Errorf("contract form request bodies require POST")
					}
					body, ok := contract["request_body"].(map[string]any)
					if !ok || body["type"] != "object" {
						return nil, fmt.Errorf("contract form request body requires an object schema")
					}
				}
				seen[media] = true
			}
		case "responses":
		default:
			return nil, fmt.Errorf("unknown on.request.contract key %q", key)
		}
	}
	responses, ok := contract["responses"].(map[string]any)
	if !ok || len(responses) == 0 {
		return nil, fmt.Errorf("on.request.contract.responses requires quoted HTTP status keys and schemas")
	}
	success := false
	for status, value := range responses {
		code, err := strconv.Atoi(status)
		if err != nil || len(status) != 3 || code < 200 || code > 599 || code == 204 || code == 205 || code == 304 {
			return nil, fmt.Errorf("invalid contract response status %q", status)
		}
		success = success || code < 300
		if err := validateFlowOpenAPIResponse(value); err != nil {
			return nil, fmt.Errorf("on.request.contract.responses.%s: %w", status, err)
		}
	}
	if !success {
		return nil, fmt.Errorf("on.request.contract.responses requires a success status")
	}
	return contract, nil
}

func registerPrivateFlowOpenAPI(mux appRouteRegistrar, app *App) {
	mux.HandleFunc("GET /api/_openapi", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		w.Header().Set("Cache-Control", "private, no-store")
		if session == nil {
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		if !session.IsAdminConsole() {
			http.Error(w, "developer access required", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(generateRuntimeOpenAPIFor(app, fullDocs, registeredFlowOpenAPI(mux)))
	})
}

func registeredFlowOpenAPI(mux appRouteRegistrar) map[string]string {
	if recorder, ok := mux.(*appRouteMux); ok {
		return recorder.flows
	}
	return nil
}

// flowOpenAPIFingerprint moves info.version when a served flow contract
// changes. It hashes the contracts themselves, not the viewer's pruned paths,
// so every audience sees the same version for one deploy.
func flowOpenAPIFingerprint(app *App, registered map[string]string) string {
	served := map[string]any{}
	for _, flow := range app.Flows {
		pattern := flowMuxPattern(flow.Trigger.Method, flow.Trigger.Path)
		if flow.Trigger.Type == "http" && flow.Trigger.Contract != nil && registered[flow.Name] == pattern {
			served[flow.Name] = []any{pattern, flow.Auth, flow.Role, flow.Permissions, flow.Trigger.Contract}
		}
	}
	if len(served) == 0 {
		return ""
	}
	data, _ := json.Marshal(served) // map keys marshal sorted
	sum := sha256.Sum256(data)
	return fmt.Sprintf(".%x", sum[:6])
}

func addFlowOpenAPIPaths(app *App, paths map[string]any, registered map[string]string) {
	flows := append([]Flow(nil), app.Flows...)
	sort.Slice(flows, func(i, j int) bool { return flows[i].Name < flows[j].Name })
	for _, flow := range flows {
		contract := flow.Trigger.Contract
		if flow.Trigger.Type != "http" || contract == nil || registered[flow.Name] != flowMuxPattern(flow.Trigger.Method, flow.Trigger.Path) {
			continue
		}
		parts := strings.Split(flow.Trigger.Path, "/")
		parameters := []map[string]any{}
		for i, part := range parts {
			if strings.HasPrefix(part, ":") {
				name := strings.TrimPrefix(part, ":")
				parts[i] = "{" + name + "}"
				parameters = append(parameters, map[string]any{"in": "path", "name": name, "required": true, "schema": map[string]any{"type": "string"}})
			}
		}
		for _, location := range []string{"query", "header"} {
			key := location
			if key == "header" {
				key = "headers"
			}
			query, ok := contract[key].(map[string]any)
			if !ok {
				continue
			}
			required := map[string]bool{}
			if names, ok := query["required"].([]any); ok {
				for _, name := range names {
					required[name.(string)] = true
				}
			}
			properties := query["properties"].(map[string]any)
			names := make([]string, 0, len(properties))
			for name := range properties {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				parameters = append(parameters, map[string]any{"in": location, "name": name, "required": required[name], "schema": properties[name]})
			}
		}
		responses := map[string]any{}
		for status, schema := range contract["responses"].(map[string]any) {
			response := schema.(map[string]any)
			if media, ok := response["content"].(map[string]any); ok {
				content := map[string]any{}
				for name, value := range media {
					content[name] = map[string]any{"schema": value}
				}
				responses[status] = map[string]any{"description": "HTTP " + status, "content": content}
			} else {
				responses[status] = openAPIJSONResponse("HTTP "+status, response)
			}
		}
		operation := map[string]any{"operationId": "flow_" + flow.Name, "parameters": parameters, "responses": responses}
		if flow.Auth != "required" && flow.Role == "" && len(flow.Permissions) == 0 {
			operation["security"] = []any{}
		}
		if body, ok := contract["request_body"].(map[string]any); ok {
			requestBody := openAPIJSONRequest(body)
			if required, ok := contract["request_body_required"].(bool); ok {
				requestBody["required"] = required
			}
			if types, ok := contract["request_body_media_types"].([]any); ok {
				content := map[string]any{}
				for _, media := range types {
					content[media.(string)] = map[string]any{"schema": body}
				}
				requestBody["content"] = content
			}
			operation["requestBody"] = requestBody
		}
		path := strings.Join(parts, "/")
		existing := make([]string, 0, len(paths))
		for key := range paths {
			existing = append(existing, key)
		}
		sort.Strings(existing)
		for _, candidate := range existing {
			other := strings.Split(candidate, "/")
			if len(other) != len(parts) {
				continue
			}
			matches := true
			for i := range parts {
				if parts[i] != other[i] && !(strings.HasPrefix(parts[i], "{") && strings.HasPrefix(other[i], "{")) {
					matches = false
					break
				}
			}
			if !matches {
				continue
			}
			for i := range parts {
				if strings.HasPrefix(parts[i], "{") {
					old := strings.Trim(parts[i], "{}")
					for _, parameter := range parameters {
						if parameter["in"] == "path" && parameter["name"] == old {
							parameter["name"] = strings.Trim(other[i], "{}")
							break
						}
					}
				}
			}
			path = candidate
			break
		}
		item, ok := paths[path].(map[string]any)
		if !ok {
			item = map[string]any{}
			paths[path] = item
		}
		if _, exists := item[strings.ToLower(flow.Trigger.Method)]; !exists {
			item[strings.ToLower(flow.Trigger.Method)] = operation
		}
	}
}
