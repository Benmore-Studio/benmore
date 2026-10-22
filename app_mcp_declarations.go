//go:build !cli

package main

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// Reviewed component declarations and external connection grammar. Both are
// declarations only: nothing here serves a resource or dials an upstream.

var (
	appMCPConnectionEnv    = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
	appMCPConnectionHeader = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,63}$`)
	appMCPDeepLinkField    = regexp.MustCompile(`\{([^{}]*)\}`)
)

func validateAppMCPConnections(connections []AppMCPConnection) (map[string]bool, error) {
	names := map[string]bool{}
	for _, c := range connections {
		if !appMCPName.MatchString(c.Name) || names[c.Name] {
			return nil, fmt.Errorf("invalid or duplicate connection %q", c.Name)
		}
		names[c.Name] = true
		base, err := url.Parse(c.BaseURL)
		// Credentials never ride in the URL: no userinfo, no query (api_key=...), no fragment.
		if err != nil || base.Scheme != "https" || base.Hostname() == "" || base.User != nil || base.RawQuery != "" || base.ForceQuery || base.Fragment != "" || strings.ContainsAny(c.BaseURL, " \t\r\n\\") {
			return nil, fmt.Errorf("connection %q base_url must be a credential-free https URL", c.Name)
		}
		// Syntax only: isPrivateURL resolves DNS and fails closed offline, which
		// would make a manifest unloadable without network. Resolved addresses are
		// refused at dial time by publicOnlyDialer (app_mcp_external.go).
		if appMCPLiteralPrivateHost(base.Hostname()) {
			return nil, fmt.Errorf("connection %q base_url must not name a private or local host", c.Name)
		}
		switch c.Auth.Kind {
		case "none":
			if c.Auth.Env != "" || c.Auth.Header != "" {
				return nil, fmt.Errorf("connection %q auth kind none takes no env or header", c.Name)
			}
		case "bearer", "header":
			if !appMCPConnectionEnv.MatchString(c.Auth.Env) {
				return nil, fmt.Errorf("connection %q auth env must name an environment variable, never hold a credential", c.Name)
			}
			if c.Auth.Kind == "bearer" && c.Auth.Header != "" {
				return nil, fmt.Errorf("connection %q bearer auth takes no header", c.Name)
			}
			switch strings.ToLower(c.Auth.Header) {
			case "host", "cookie", "content-length", "transfer-encoding":
				return nil, fmt.Errorf("connection %q auth header is reserved", c.Name)
			}
			if c.Auth.Kind == "header" && !appMCPConnectionHeader.MatchString(c.Auth.Header) {
				return nil, fmt.Errorf("connection %q auth header is invalid", c.Name)
			}
		default:
			return nil, fmt.Errorf("connection %q has unsupported auth kind", c.Name)
		}
		ext := strings.ToLower(filepath.Ext(c.OpenAPI))
		if c.OpenAPI == "" || strings.ContainsAny(c.OpenAPI, "\\\x00") || path.Clean(c.OpenAPI) != c.OpenAPI || !filepath.IsLocal(filepath.FromSlash(c.OpenAPI)) || ext != ".json" && ext != ".yaml" && ext != ".yml" {
			return nil, fmt.Errorf("connection %q must pin a local OpenAPI JSON/YAML file", c.Name)
		}
	}
	return names, nil
}

// appMCPLiteralPrivateHost refuses names and address literals that are private
// without any lookup. A name that resolves privately is caught at connect time.
func appMCPLiteralPrivateHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && blockedOutboundIP(ip)
}

// appMCPDeclaresExternal reports whether the manifest uses the external grammar at all.
func appMCPDeclaresExternal(m *AppMCPManifest) bool {
	if len(m.Connections) > 0 {
		return true
	}
	for _, tool := range m.Tools {
		if tool.Handler.Kind == "external" {
			return true
		}
	}
	return false
}

func validateAppMCPExternalGate(m *AppMCPManifest, enabled bool) error {
	if !enabled && appMCPDeclaresExternal(m) {
		return fmt.Errorf("external connections are not enabled in this runtime")
	}
	return nil
}

func validateAppMCPResourceDeclaration(r AppMCPResource) error {
	if r.Entrypoint == "" && len(r.Tools) == 0 && r.DataSchema == nil && r.SchemaVersion == 0 && r.DeepLink == "" {
		return nil
	}
	ext := strings.ToLower(filepath.Ext(r.Entrypoint))
	if !strings.HasPrefix(r.Entrypoint, "static/") || strings.ContainsAny(r.Entrypoint, "\\\x00") || path.Clean(r.Entrypoint) != r.Entrypoint || !filepath.IsLocal(filepath.FromSlash(r.Entrypoint)) || ext != ".tsx" && ext != ".ts" && ext != ".jsx" && ext != ".js" && ext != ".html" {
		return fmt.Errorf("entrypoint must be a source file under static/")
	}
	if r.SchemaVersion < 1 || r.DataSchema == nil || r.DataSchema.Type != "object" {
		return fmt.Errorf("a component requires schema_version >= 1 and an object data_schema")
	}
	if err := validateAppMCPSchema(r.DataSchema, 0); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, name := range r.Tools {
		if !appMCPName.MatchString(name) || seen[name] {
			return fmt.Errorf("invalid or duplicate permitted tool %q", name)
		}
		seen[name] = true
	}
	if r.DeepLink != "" {
		return validateAppMCPDeepLink(r.DeepLink, r.DataSchema)
	}
	return nil
}

// A deep link is a path on the app's own host. It never carries a credential,
// so token/code/secret anywhere in the template (placeholder names included) is refused.
func validateAppMCPDeepLink(link string, data *AppMCPSchema) error {
	if !strings.HasPrefix(link, "/") || strings.HasPrefix(link, "//") || strings.ContainsAny(link, "\\%\x00 \t\r\n") {
		return fmt.Errorf("deep_link must be a plain path relative to the app host")
	}
	lower := strings.ToLower(link)
	for _, word := range []string{"token", "code", "secret"} {
		if strings.Contains(lower, word) {
			return fmt.Errorf("deep_link must not carry %s material", word)
		}
	}
	for _, match := range appMCPDeepLinkField.FindAllStringSubmatch(link, -1) {
		property := data.Properties[match[1]]
		if property == nil || property.Nullable || property.Type != "string" && property.Type != "integer" && property.Type != "number" && property.Type != "boolean" {
			return fmt.Errorf("deep_link placeholder %q is not a declared scalar data field", match[1])
		}
	}
	rest := appMCPDeepLinkField.ReplaceAllString(link, "x")
	if strings.ContainsAny(rest, "{}") {
		return fmt.Errorf("deep_link has an unbalanced placeholder")
	}
	parsed, err := url.Parse(rest)
	if err != nil || parsed.Scheme != "" || parsed.Host != "" || parsed.User != nil || parsed.Opaque != "" {
		return fmt.Errorf("deep_link must not name a scheme or host")
	}
	for _, segment := range strings.Split(parsed.Path, "/") {
		if segment == "." || segment == ".." {
			return fmt.Errorf("deep_link must not contain dot segments")
		}
	}
	return nil
}

// validateAppMCPDeclaredSources checks the declarations that need source bytes:
// component entrypoints exist, and every external operation is in its pinned
// OpenAPI document. The execution digest already binds the bytes.
func validateAppMCPDeclaredSources(dir string, m *AppMCPManifest) error {
	if m == nil {
		return nil
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("mcp.yaml: cannot open declared sources")
	}
	defer root.Close()
	for _, resource := range m.Resources {
		if resource.Entrypoint == "" {
			continue
		}
		present := false
		if m.sourceHashes != nil {
			_, present = m.sourceHashes[resource.Entrypoint]
		} else if info, err := root.Lstat(filepath.FromSlash(resource.Entrypoint)); err == nil && info.Mode().IsRegular() {
			present = true
		}
		if !present {
			return fmt.Errorf("mcp.yaml: component %q entrypoint %q is absent from source", resource.Name, resource.Entrypoint)
		}
	}
	if !appMCPDeclaresExternal(m) && !appMCPDeclaresTransfer(m) {
		return nil
	}
	// Each pinned document is read once, from the bytes the execution digest
	// bound (a swap between hashing and here is refused). One reader serves the
	// whole manifest, so the file and byte budgets bound every connection
	// together and a document pinned by many connections is parsed and resolved
	// once; only the expansion budget is per pinned document.
	reader := &appMCPOpenAPIReader{root: root, documents: map[string]map[string]any{}, sources: map[string]SourceManifestFile{}}
	generatedByDocument := map[string]*appMCPOpenAPICandidates{}
	candidates := map[string]map[string]appMCPOpenAPICandidate{}
	for _, connection := range m.Connections {
		generated := generatedByDocument[connection.OpenAPI]
		if generated == nil {
			reader.nodes, reader.expandedBytes = 0, 0
			var err error
			if generated, err = reader.generate(connection.OpenAPI); err != nil {
				return fmt.Errorf("mcp.yaml: connection %q: %w", connection.Name, err)
			}
			generatedByDocument[connection.OpenAPI] = generated
		}
		if m.sourceHashes != nil {
			for file, source := range reader.sources {
				if _, bound := m.sourceHashes[file]; !bound {
					return fmt.Errorf("mcp.yaml: connection %q: pinned OpenAPI file %q is not bound by the execution digest; keep referenced documents in the pinned document's directory", connection.Name, file)
				}
				if m.sourceHashes[file] != source.SHA256 {
					return fmt.Errorf("mcp.yaml: connection %q: pinned OpenAPI file %q differs from the reviewed source", connection.Name, file)
				}
			}
		}
		candidates[connection.Name] = map[string]appMCPOpenAPICandidate{}
		for _, operation := range generated.Operations {
			candidates[connection.Name][operation.OperationID] = operation
		}
	}
	external := map[string]*appMCPExternalOperation{}
	for _, tool := range m.Tools {
		if tool.Handler.Kind != "external" && tool.Transfer != nil {
			transfer := tool.Transfer
			candidate, ok := candidates[transfer.Connection][transfer.OperationID]
			if !ok {
				return fmt.Errorf("mcp.yaml: transfer operation %q is absent from its pinned OpenAPI document", transfer.OperationID)
			}
			operation, err := newAppMCPExternalOperation(m, transfer.Connection, candidate)
			want := "GET"
			if transfer.Kind == "push" {
				want = "POST"
			}
			if transfer.Kind == "pull" && appMCPTransferExtension(transfer.ExpectedMIME) == "" {
				return fmt.Errorf("mcp.yaml: tool %q pull transfer must pin a supported expected_mime", tool.Name)
			}
			if err != nil || operation.Method != want {
				return fmt.Errorf("mcp.yaml: tool %q transfer operation must be a pinned %s", tool.Name, want)
			}
			if err := validateAppMCPTransferOperation(transfer, operation, false); err != nil {
				return fmt.Errorf("mcp.yaml: tool %q transfer: %w", tool.Name, err)
			}
			set := &appMCPTransferOperations{Operation: operation}
			if transfer.Kind == "push" {
				candidate, ok = candidates[transfer.Connection][transfer.ReconcileOperationID]
				if !ok {
					return fmt.Errorf("mcp.yaml: reconciliation operation %q is absent from its pinned OpenAPI document", transfer.ReconcileOperationID)
				}
				set.Reconcile, err = newAppMCPExternalOperation(m, transfer.Connection, candidate)
				if err != nil || set.Reconcile.Method != "GET" {
					return fmt.Errorf("mcp.yaml: tool %q reconciliation must be a pinned GET", tool.Name)
				}
				if err := validateAppMCPTransferOperation(transfer, set.Reconcile, true); err != nil {
					return fmt.Errorf("mcp.yaml: tool %q reconciliation: %w", tool.Name, err)
				}
			}
			if m.transfers == nil {
				m.transfers = map[string]*appMCPTransferOperations{}
			}
			m.transfers[tool.Name] = set
			continue
		}
		if tool.Handler.Kind != "external" {
			continue
		}
		operation, ok := candidates[tool.Handler.Connection][tool.Handler.OperationID]
		if !ok {
			return fmt.Errorf("mcp.yaml: tool %q operation %q is absent from the pinned OpenAPI document", tool.Name, tool.Handler.OperationID)
		}
		pinned, err := newAppMCPExternalOperation(m, tool.Handler.Connection, operation)
		if err != nil {
			return fmt.Errorf("mcp.yaml: tool %q: %w", tool.Name, err)
		}
		external[tool.Name] = pinned
	}
	m.external = external
	return nil
}

func appMCPDeclaresTransfer(m *AppMCPManifest) bool {
	if m == nil {
		return false
	}
	for _, tool := range m.Tools {
		if tool.Transfer != nil {
			return true
		}
	}
	return false
}

// A flow-backed tool's input_schema must match what the flow enforces at
// runtime (flows.go validateFlowInputValues) plus its path parameters, which
// the dispatcher fills from the arguments. Anything else would be dropped
// silently by the flow, or required by the flow but never asked of the caller.
func validateAppMCPFlowInputContract(tool AppMCPTool, flow *Flow) error {
	accepted := map[string]FlowInput{}
	for name, input := range flow.Trigger.Inputs {
		accepted[name] = input
	}
	pathParams := map[string]bool{}
	for _, part := range strings.Split(flow.Trigger.Path, "/") {
		name := ""
		if strings.HasPrefix(part, ":") {
			name = strings.TrimPrefix(part, ":")
		} else if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
			name = strings.TrimSuffix(strings.TrimPrefix(part, "{"), "}")
		}
		if name != "" {
			pathParams[name] = true
		}
	}
	for name, property := range tool.InputSchema.Properties {
		// Identity keys are stripped from every request before a flow reads its
		// inputs, so advertising one would promise a value the flow never receives.
		if slices.Contains(flowIdentityKeys, name) || name == "env" || strings.HasPrefix(name, "env.") || strings.HasPrefix(name, "user.") {
			return fmt.Errorf("input_schema property %q is a server-owned identity key", name)
		}
		input, declared := accepted[name]
		if !declared && !pathParams[name] {
			return fmt.Errorf("input_schema property %q is not accepted by flow %q", name, flow.Name)
		}
		want := ""
		switch input.Type {
		case "text", "textarea", "email", "date", "enum":
			want = "string"
		case "number":
			want = "number"
		case "bool":
			want = "boolean"
		}
		compatible := !property.Nullable && (property.Type == want || want == "number" && property.Type == "integer")
		if !declared { // a path segment carries any scalar
			compatible = !property.Nullable && (property.Type == "string" || property.Type == "integer" || property.Type == "number" || property.Type == "boolean")
		}
		if !compatible {
			return fmt.Errorf("input_schema property %q has type %q, incompatible with flow input type %q", name, property.Type, input.Type)
		}
		if declared && input.Type == "enum" {
			for _, value := range property.Enum {
				if text, ok := value.(string); !ok || !slices.Contains(input.Values, text) {
					return fmt.Errorf("input_schema property %q allows an enum value the flow rejects", name)
				}
			}
		}
	}
	for name, input := range accepted {
		if input.Required && !appMCPHasRequiredField(tool.InputSchema, name) {
			return fmt.Errorf("input_schema omits required flow input %q", name)
		}
	}
	for name := range pathParams {
		if !appMCPHasRequiredField(tool.InputSchema, name) {
			return fmt.Errorf("input_schema omits flow path parameter %q", name)
		}
	}
	return nil
}
