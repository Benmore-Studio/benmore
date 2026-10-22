//go:build !cli

package main

// Widget publication build for MCP Apps components (app_mcp_resources.go).
//
// A reviewed component entrypoint is bundled by the embedded esbuild into ONE
// self-contained ES module: no externals, no source map, no CSS side file. The
// build runs in the captured-compiler child (app_source_compiler_child.go) over
// the digest-bound generation, behind the same static/ containment plugin as
// browser bundles (bundle_containment.go). Any error fails the whole build; no
// build text is ever returned, so nothing outside static/ can leak through one.
//
// The vendored MCP Apps bundle is not an external: an import of
// "@modelcontextprotocol/ext-apps" resolves to mcpAppsWidgetShim, a small
// module in a virtual namespace that re-exports the vendored bundle
// (mcp_apps_bundle.go) and wraps its App with the bounded bridge the policy
// requires. Virtual namespaces are skipped by the containment plugin because
// they hold no file.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"

	esbuild "github.com/benmore-studio/benmore/third_party/esbuild/pkg/api"
)

const (
	mcpAppsWidgetNamespace = "mcp-widget"
	mcpAppsSpecifier       = "@modelcontextprotocol/ext-apps"
	mcpAppsVendorSpecifier = "mcp-apps-vendor"
	// appMCPWidgetBridgeVersion changes with the shim's observable behaviour and
	// appMCPWidgetPolicyVersion with the CSP or the visibility policy; both enter
	// every closure hash, next to the shim's own bytes.
	appMCPWidgetBridgeVersion = 1
	appMCPWidgetPolicyVersion = 1
	appMCPWidgetMaxCalls      = 30 // tool calls a widget may make per minute
)

// mcpAppsWidgetShim is the bridge. It holds no storage access and no tenant
// data: the only input is the static JSON configuration the resource inlines.
// Its client-side limits (permitted tools, call budget, argument size) are a
// guard for honest components; the server still authorizes every call per
// caller, and tool visibility (_meta.ui.visibility) is what bounds the app.
const mcpAppsWidgetShim = `import { App as VendorApp } from "` + mcpAppsVendorSpecifier + `";
export * from "` + mcpAppsVendorSpecifier + `";

const config = JSON.parse(document.getElementById("benmore-widget-config").textContent);
const permitted = new Set(config.tools);
const WINDOW_MS = 60000;
const MAX_ARGUMENT_CHARS = 65536;
const MIN_REFRESH_MS = 5000;

export class App extends VendorApp {
  constructor(...args) {
    super(...args);
    this._calls = [];
    this._arguments = {};
    this._lastRefresh = 0;
    this.onrefresh = null;
    const refresh = () => { void this.refresh(false); };
    document.addEventListener("visibilitychange", () => { if (document.visibilityState === "visible") refresh(); });
    window.addEventListener("focus", refresh);
    window.addEventListener("online", refresh);
  }
  get ontoolinput() { return super.ontoolinput; }
  set ontoolinput(handler) {
    super.ontoolinput = (params) => {
      this._arguments = (params && params.arguments) || {};
      return handler ? handler(params) : undefined;
    };
  }
  async callServerTool(params, options) {
    const name = params && params.name;
    if (!permitted.has(name)) throw new Error("benmore: tool is not permitted for this component");
    const args = params.arguments || {};
    if (JSON.stringify(args).length > MAX_ARGUMENT_CHARS) throw new Error("benmore: tool arguments are too large");
    const now = Date.now();
    this._calls = this._calls.filter((at) => now - at < WINDOW_MS);
    if (this._calls.length >= config.max_calls_per_minute) throw new Error("benmore: tool call budget exhausted");
    this._calls.push(now);
    if (name === config.refresh_tool) this._arguments = args;
    const result = await super.callServerTool(params, options);
    const content = result && result.structuredContent;
    if (name === "_status" && content && content.state === "succeeded" && content.business === "committed") void this.refresh(true);
    return result;
  }
  // Re-reads the linked tool with the arguments it last ran with, so the
  // widget never shows more than a call by this caller returns. A failure keeps
  // the data already shown.
  async refresh(force) {
    const now = Date.now();
    if (!config.refresh_tool || (!force && now - this._lastRefresh < MIN_REFRESH_MS)) return null;
    this._lastRefresh = now;
    try {
      const result = await this.callServerTool({ name: config.refresh_tool, arguments: this._arguments });
      if (typeof this.onrefresh === "function") this.onrefresh(result);
      return result;
    } catch (error) {
      return null;
    }
  }
}

// The deep link a tool result carries (built from declared data fields only).
export function deepLinkOf(result) {
  return (result && result._meta && typeof result._meta.deep_link === "string") ? result._meta.deep_link : "";
}
`

func mcpAppsShimSHA() string {
	sum := sha256.Sum256([]byte(mcpAppsWidgetShim))
	return hex.EncodeToString(sum[:])
}

// mcpAppsWidgetPlugin serves the two virtual modules above.
func mcpAppsWidgetPlugin() esbuild.Plugin {
	return esbuild.Plugin{
		Name: "benmore-mcp-apps-widget",
		Setup: func(build esbuild.PluginBuild) {
			build.OnResolve(esbuild.OnResolveOptions{Filter: "^(" + regexp.QuoteMeta(mcpAppsSpecifier) + "|" + regexp.QuoteMeta(mcpAppsVendorSpecifier) + ")$"}, func(args esbuild.OnResolveArgs) (esbuild.OnResolveResult, error) {
				return esbuild.OnResolveResult{Path: args.Path, Namespace: mcpAppsWidgetNamespace}, nil
			})
			build.OnLoad(esbuild.OnLoadOptions{Filter: ".*", Namespace: mcpAppsWidgetNamespace}, func(args esbuild.OnLoadArgs) (esbuild.OnLoadResult, error) {
				source := mcpAppsWidgetShim
				if args.Path == mcpAppsVendorSpecifier {
					bundle, _ := mcpAppsBundle()
					source = string(bundle)
				}
				return esbuild.OnLoadResult{Contents: &source, Loader: esbuild.LoaderJS}, nil
			})
		},
	}
}

// compileWidgetBundle builds one component entrypoint. It returns the bundle
// and the absolute path of every file it bundled (all inside staticRoot).
func compileWidgetBundle(srcPath, staticRoot string) ([]byte, []string, error) {
	absWorkingDir := filepath.Dir(srcPath)
	result, err := buildAppSources(context.Background(), esbuild.BuildOptions{
		EntryPoints:   []string{srcPath},
		AbsWorkingDir: absWorkingDir,
		Metafile:      true,
		Bundle:        true,
		Format:        esbuild.FormatESModule,
		Target:        esbuild.ES2020,
		JSX:           esbuild.JSXAutomatic,
		Loader:        map[string]esbuild.Loader{".tsx": esbuild.LoaderTSX, ".ts": esbuild.LoaderTS, ".jsx": esbuild.LoaderJSX, ".js": esbuild.LoaderJS},
		Write:         false,
		Sourcemap:     esbuild.SourceMapNone,
		LegalComments: esbuild.LegalCommentsNone,
		Platform:      esbuild.PlatformBrowser,
		LogLevel:      esbuild.LogLevelSilent,
		Plugins:       []esbuild.Plugin{mcpAppsWidgetPlugin(), staticContainmentPlugin(staticRoot)},
	})
	if err != nil {
		return nil, nil, err
	}
	if len(result.Errors) > 0 {
		return nil, nil, fmt.Errorf("widget build failed with %d error(s)", len(result.Errors))
	}
	if len(result.OutputFiles) != 1 {
		return nil, nil, fmt.Errorf("widget build produced %d outputs, want 1", len(result.OutputFiles))
	}
	// esbuild leaves http(s):// imports external by itself; the page must be
	// one self-contained module, so any external import refuses the build.
	if widgetBundleHasExternalImport(result.Metafile) {
		return nil, nil, fmt.Errorf("widget bundle imports an external module")
	}
	files := bundleInputMtimes(result.Metafile, absWorkingDir)
	if len(files) == 0 {
		return nil, nil, fmt.Errorf("widget build reported no inputs")
	}
	if bundleInputOutside(files, staticRoot) != "" {
		return nil, nil, errOutsideStatic
	}
	inputs := make([]string, 0, len(files))
	for path := range files {
		inputs = append(inputs, path)
	}
	body := result.OutputFiles[0].Contents
	// The body is inlined in a <script>; a literal terminator would end it.
	lower := bytes.ToLower(body)
	if bytes.Contains(lower, []byte("</script")) || bytes.Contains(lower, []byte("<!--")) {
		return nil, nil, fmt.Errorf("widget bundle contains an HTML script terminator")
	}
	return body, inputs, nil
}

// widgetBundleHasExternalImport reports whether the output keeps any import
// (static or dynamic) for the browser to fetch; an unreadable metafile counts
// as one. Input-side entries are not consulted: esbuild lists its own inlined
// "<runtime>" helpers there as external.
func widgetBundleHasExternalImport(metafile string) bool {
	var meta struct {
		Outputs map[string]struct {
			Imports []json.RawMessage `json:"imports"`
		} `json:"outputs"`
	}
	if json.Unmarshal([]byte(metafile), &meta) != nil || len(meta.Outputs) == 0 {
		return true
	}
	for _, output := range meta.Outputs {
		if len(output.Imports) > 0 {
			return true
		}
	}
	return false
}
