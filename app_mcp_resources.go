//go:build !cli

package main

// MCP Apps resources: reviewed components served as ui:// HTML resources.
//
// A component is a reviewed mcp.yaml resource with an entrypoint. Its
// resource is built from the digest-bound generation only (never model-written
// code), published under ui://<declared host>/<name>@<closure hash>, and is the
// same bytes for every caller: nothing per user, per session or per row is in
// it. Whether a caller may LIST or READ it is decided per request, like the
// tools: the caller must be allowed at least one tool bound to the component.
//
// A build failure leaves the component unpublished (logged once per
// generation); its tools keep working with their text envelope.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net/url"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	appMCPWidgetMIME = "text/html;profile=mcp-app"
	// No network, frame, object, base or form access; scripts only by hash of
	// the one inline module. Inline styles stay allowed for host-injected theming.
	appMCPWidgetCSPTemplate = "default-src 'none'; script-src 'sha256-%s'; style-src 'unsafe-inline'; img-src data:; font-src data:; connect-src 'none'; frame-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'"
	appMCPWidgetCacheLimit  = 64
)

// appMCPWidget is one published component. Immutable after construction.
type appMCPWidget struct {
	URI     string
	Closure string
	HTML    string
	Tools   []string
	Meta    sdk.Meta
}

type appMCPWidgetConfig struct {
	Component     string        `json:"component"`
	SchemaVersion int           `json:"schema_version"`
	DataSchema    *AppMCPSchema `json:"data_schema"`
	Tools         []string      `json:"tools"`
	RefreshTool   string        `json:"refresh_tool,omitempty"`
	MaxCalls      int           `json:"max_calls_per_minute"`
	BridgeVersion int           `json:"bridge_version"`
}

// appMCPWidgetMemo holds a generation's published set; the generation is
// immutable, so it is built once.
type appMCPWidgetMemo struct {
	once    sync.Once
	widgets map[string]*appMCPWidget // declared uri -> published widget
}

// The global cache holds reviewed static code only, keyed by everything that
// can change the bytes: a changed source, bundle, bridge, schema or policy
// gives another key, so a stale build is never served.
var appMCPWidgetCache = struct {
	sync.Mutex
	entries map[string]*appMCPWidget
}{entries: map[string]*appMCPWidget{}}

// appMCPComponents returns the manifest's reviewed components in declared order.
func appMCPComponents(m *AppMCPManifest) []AppMCPResource {
	if m == nil {
		return nil
	}
	var out []AppMCPResource
	for _, resource := range m.Resources {
		if resource.Entrypoint != "" {
			out = append(out, resource)
		}
	}
	return out
}

// appMCPComponentTools is every tool a component may call: its declared
// permitted tools plus the tools bound to it, sorted.
func appMCPComponentTools(m *AppMCPManifest, resource AppMCPResource) (all []string, linked []string) {
	set := map[string]bool{}
	for _, name := range resource.Tools {
		set[name] = true
	}
	for _, tool := range m.Tools {
		if tool.Component == resource.URI {
			set[tool.Name] = true
			linked = append(linked, tool.Name)
		}
		// A widget may poll the durable status of an approved write.
		if tool.Handler.Operation == "command" {
			set[appMCPStatusTool] = true
		}
	}
	for name := range set {
		all = append(all, name)
	}
	sort.Strings(all)
	sort.Strings(linked)
	return all, linked
}

func appMCPGenerationWidgets(ctx context.Context, generation *appMCPRuntimeGeneration) map[string]*appMCPWidget {
	if generation == nil || len(appMCPComponents(generation.manifest)) == 0 {
		return nil
	}
	memo := generation.widgets
	if memo == nil {
		memo = new(appMCPWidgetMemo)
	}
	memo.once.Do(func() {
		memo.widgets = map[string]*appMCPWidget{}
		for _, resource := range appMCPComponents(generation.manifest) {
			widget, err := buildAppMCPWidget(context.WithoutCancel(ctx), generation, resource)
			if err != nil {
				log.Printf("mcp-resources: component %q is not published: %v", resource.Name, err)
				continue
			}
			memo.widgets[resource.URI] = widget
		}
	})
	return memo.widgets
}

func buildAppMCPWidget(ctx context.Context, generation *appMCPRuntimeGeneration, resource AppMCPResource) (*appMCPWidget, error) {
	manifest := generation.manifest
	hashes := manifest.sourceHashes
	switch strings.ToLower(filepath.Ext(resource.Entrypoint)) {
	case ".tsx", ".ts", ".jsx", ".js":
	default:
		return nil, fmt.Errorf("entrypoint %q is not a script; only .tsx, .ts, .jsx and .js components are published", resource.Entrypoint)
	}
	if len(hashes) == 0 || generation.sourceFiles == nil {
		return nil, fmt.Errorf("no captured source generation")
	}
	tools, linked := appMCPComponentTools(manifest, resource)
	config := appMCPWidgetConfig{Component: resource.Name, SchemaVersion: resource.SchemaVersion, DataSchema: resource.DataSchema, Tools: tools, MaxCalls: appMCPWidgetMaxCalls, BridgeVersion: appMCPWidgetBridgeVersion}
	if len(linked) > 0 {
		config.RefreshTool = linked[0]
	}
	configJSON, err := json.Marshal(config) // escapes <, > and &: safe inside a script element
	if err != nil {
		return nil, err
	}
	_, bundleSHA := mcpAppsBundle()
	policy := strings.Join([]string{"mcp-widget/1", manifest.Connector.ID, resource.URI, resource.Entrypoint, resource.DeepLink,
		"bundle=" + bundleSHA, "shim=" + mcpAppsShimSHA(), "bridge=" + strconv.Itoa(appMCPWidgetBridgeVersion), "policy=" + strconv.Itoa(appMCPWidgetPolicyVersion), appMCPWidgetCSPTemplate, string(configJSON)}, "\n")

	// Cache key: the policy plus every captured file the build can read. That
	// is the whole generation: the resolver reads tsconfig extends targets and
	// package.json files outside static/.
	key := sha256.New()
	key.Write([]byte(policy))
	names := make([]string, 0, len(hashes))
	for name := range hashes {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintf(key, "\n%s\x00%s", name, hashes[name])
	}
	cacheKey := hex.EncodeToString(key.Sum(nil))
	appMCPWidgetCache.Lock()
	cached := appMCPWidgetCache.entries[cacheKey]
	appMCPWidgetCache.Unlock()
	if cached != nil {
		return cached, nil
	}

	root, cleanup, err := stageAppCompilerSources(ctx, generation.sourceFiles, hashes)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	response, err := compileCapturedAppSourceDetailed(ctx, "widget", root, filepath.Join(root, filepath.FromSlash(resource.Entrypoint)), hashes)
	if err != nil {
		return nil, fmt.Errorf("build failed: %w", err)
	}

	// The closure: policy, exactly the files that were bundled and the output.
	inputs := append([]string(nil), response.Inputs...)
	sort.Strings(inputs)
	closure := sha256.New()
	closure.Write([]byte(policy))
	for _, name := range inputs {
		digest, reviewed := hashes[name]
		if !reviewed || digest == "" {
			return nil, fmt.Errorf("bundled input %q is not a reviewed source", name)
		}
		fmt.Fprintf(closure, "\n%s\x00%s", name, digest)
	}
	output := sha256.Sum256(response.Body)
	closure.Write(output[:])
	closureHash := hex.EncodeToString(closure.Sum(nil))

	script := string(response.Body)
	scriptHash := sha256.Sum256([]byte(script))
	csp := fmt.Sprintf(appMCPWidgetCSPTemplate, base64.StdEncoding.EncodeToString(scriptHash[:]))
	page := `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">` +
		`<meta http-equiv="Content-Security-Policy" content="` + csp + `">` +
		`<meta name="mcp-apps-bundle" content="sha256-` + bundleSHA + `"><meta name="benmore-closure" content="sha256-` + closureHash + `">` +
		`<title>` + html.EscapeString(resource.Name) + `</title></head><body><div id="root"></div>` +
		`<script type="application/json" id="benmore-widget-config">` + string(configJSON) + `</script>` +
		`<script type="module">` + script + `</script></body></html>`
	widget := &appMCPWidget{
		URI: resource.URI + "@" + closureHash, Closure: closureHash, HTML: page, Tools: tools,
		// An empty csp declares no network, resource or frame domains to the host.
		Meta: sdk.Meta{"ui": map[string]any{"csp": map[string]any{}, "prefersBorder": false}},
	}
	appMCPWidgetCache.Lock()
	if len(appMCPWidgetCache.entries) >= appMCPWidgetCacheLimit {
		for k := range appMCPWidgetCache.entries { // ponytail: arbitrary eviction; LRU if rebuild cost is measured
			delete(appMCPWidgetCache.entries, k)
			break
		}
	}
	appMCPWidgetCache.entries[cacheKey] = widget
	appMCPWidgetCache.Unlock()
	return widget, nil
}

// appMCPWidgetVisible applies the tool grant rules to a component: the caller
// must be allowed at least one read tool the component binds or permits.
func appMCPWidgetVisible(generation *appMCPRuntimeGeneration, widget *appMCPWidget, actor *Session) bool {
	for i := range generation.manifest.Tools {
		tool := &generation.manifest.Tools[i]
		if slices.Contains(widget.Tools, tool.Name) && appMCPToolAllowed(generation.view, tool, actor) {
			return true
		}
	}
	return false
}

func appMCPRegisterResourceTools(server *sdk.Server, app *App, generation *appMCPRuntimeGeneration, grant *appMCPGrant, actor *Session, raw, resource string) {
	widgets := appMCPGenerationWidgets(context.Background(), generation)
	for _, component := range appMCPComponents(generation.manifest) {
		widget := widgets[component.URI]
		if widget == nil || !appMCPWidgetVisible(generation, widget, actor) {
			continue
		}
		contents := &sdk.ResourceContents{URI: widget.URI, MIMEType: appMCPWidgetMIME, Text: widget.HTML, Meta: widget.Meta}
		server.AddResource(&sdk.Resource{URI: widget.URI, Name: component.Name, Title: component.Name, MIMEType: appMCPWidgetMIME, Size: int64(len(widget.HTML)), Meta: widget.Meta,
			Description: "Reviewed interactive view. The same content for every caller; data arrives through authorized tool calls."},
			func(ctx context.Context, request *sdk.ReadResourceRequest) (*sdk.ReadResourceResult, error) {
				return &sdk.ReadResourceResult{Contents: []*sdk.ResourceContents{contents}}, nil
			})
	}
}

// appMCPToolUIMeta is the MCP Apps link on a tool: the published component's
// URI, and who may call it. With components declared a tool is callable by an
// app only if some component permits or binds it, so a widget cannot reach a
// tool nobody reviewed for it. Apps with no components keep plain tools.
func appMCPToolUIMeta(generation *appMCPRuntimeGeneration, widgets map[string]*appMCPWidget, tool *AppMCPTool) sdk.Meta {
	components := appMCPComponents(generation.manifest)
	if len(components) == 0 {
		return nil
	}
	visibility := []string{"model"}
	for _, component := range components {
		if all, _ := appMCPComponentTools(generation.manifest, component); slices.Contains(all, tool.Name) {
			visibility = []string{"model", "app"}
			break
		}
	}
	ui := map[string]any{"visibility": visibility}
	meta := sdk.Meta{"ui": ui}
	if widget := widgets[tool.Component]; widget != nil && tool.Component != "none" {
		ui["resourceUri"] = widget.URI
		meta["ui/resourceUri"] = widget.URI // the deprecated flat key, for hosts that predate _meta.ui
	}
	return meta
}

// appMCPApplyToolVisibility gives every listed tool that carries no MCP Apps
// visibility (command prepare, _commit, _status, artifact.export, file and
// external tools) the rule appMCPToolUIMeta gives reads: with components
// declared it is callable by an app only if some component permits or binds
// it. Hosts read an absent visibility as ["model","app"].
func appMCPApplyToolVisibility(manifest *AppMCPManifest, tools []*sdk.Tool) {
	components := appMCPComponents(manifest)
	if len(components) == 0 {
		return
	}
	permitted := map[string]bool{}
	for _, component := range components {
		all, _ := appMCPComponentTools(manifest, component)
		for _, name := range all {
			permitted[name] = true
		}
	}
	for _, tool := range tools {
		if tool == nil {
			continue
		}
		existing, _ := tool.Meta["ui"].(map[string]any)
		if existing != nil && existing["visibility"] != nil {
			continue
		}
		ui := map[string]any{}
		for key, value := range existing {
			ui[key] = value
		}
		ui["visibility"] = []string{"model"}
		if permitted[tool.Name] {
			ui["visibility"] = []string{"model", "app"}
		}
		meta := sdk.Meta{}
		for key, value := range tool.Meta {
			meta[key] = value
		}
		meta["ui"] = ui
		tool.Meta = meta
	}
}

// appMCPDeepLink renders a component's deep link from declared data fields
// only. It returns "" when the tool has no component, the template or data
// does not fit, or a field is not the declared scalar type; the link never
// carries anything but those fields (the template itself is token-free).
func appMCPDeepLink(manifest *AppMCPManifest, tool *AppMCPTool, data any, origin string) string {
	var component *AppMCPResource
	for i := range manifest.Resources {
		if tool.Component != "none" && manifest.Resources[i].URI == tool.Component {
			component = &manifest.Resources[i]
		}
	}
	if component == nil || component.DeepLink == "" || component.DataSchema == nil {
		return ""
	}
	encoded, err := json.Marshal(data)
	if err != nil {
		return ""
	}
	var row map[string]any
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.UseNumber()
	if decoder.Decode(&row) != nil || row == nil {
		return ""
	}
	path, query, _ := strings.Cut(component.DeepLink, "?")
	ok := true
	render := func(part string, escape func(string) string) string {
		return appMCPDeepLinkField.ReplaceAllStringFunc(part, func(placeholder string) string {
			name := placeholder[1 : len(placeholder)-1]
			property := component.DataSchema.Properties[name]
			var text string
			switch value := row[name].(type) {
			case string:
				ok = ok && property != nil && property.Type == "string" && !property.Nullable && value != "." && value != ".."
				text = value
			case json.Number:
				ok = ok && property != nil && (property.Type == "integer" || property.Type == "number") && !property.Nullable
				text = value.String()
			case bool:
				ok = ok && property != nil && property.Type == "boolean" && !property.Nullable
				text = strconv.FormatBool(value)
			default:
				ok = false
			}
			return escape(text)
		})
	}
	rendered := render(path, url.PathEscape)
	if strings.Contains(component.DeepLink, "?") {
		rendered += "?" + render(query, url.QueryEscape)
	}
	if !ok || len(rendered) > 2048 {
		return ""
	}
	return origin + rendered
}
