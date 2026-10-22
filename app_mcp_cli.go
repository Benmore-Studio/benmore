//go:build !cli

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	iofs "io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type appMCPInventoryEntry struct {
	Kind     string               `json:"kind"`
	Name     string               `json:"name"`
	Binding  string               `json:"binding"`
	Source   string               `json:"source"`
	State    string               `json:"state"`
	Reason   string               `json:"reason"`
	Tools    []string             `json:"tools,omitempty"`
	Modes    []string             `json:"modes,omitempty"`
	Inputs   map[string]FlowInput `json:"inputs,omitempty"`
	Effect   string               `json:"effect,omitempty"`
	Approval string               `json:"approval,omitempty"`
}
type appMCPInspection struct {
	ValidationScope  string                 `json:"validation_scope"`
	Version          int                    `json:"version"`
	ConnectorEnabled bool                   `json:"connector_enabled"`
	SourceValid      bool                   `json:"source_valid"`
	ContractDigest   string                 `json:"contract_digest,omitempty"`
	ExecutionDigest  string                 `json:"execution_digest,omitempty"`
	Inventory        []appMCPInventoryEntry `json:"inventory"`
	ReviewedTools    []map[string]any       `json:"reviewed_tools,omitempty"`
	Unmeasured       []string               `json:"unmeasured"`
}

func runAppMCPCLI(args []string, out io.Writer) error {
	if len(args) == 0 || len(args) == 1 && (args[0] == "--help" || args[0] == "-h" || args[0] == "help") {
		return writeAppMCPCLIHelp(out, "")
	}
	for _, arg := range args[1:] {
		if arg == "--help" || arg == "-h" {
			return writeAppMCPCLIHelp(out, args[0])
		}
	}
	if len(args) < 2 {
		return appMCPCLIUsageError("usage: benmore mcp {inspect <appdir> --json|check <appdir>|review <appdir> --reviewed|generate <appdir> --openapi <file> --out <file>}")
	}
	switch args[0] {
	case "review":
		if len(args) != 3 || args[2] != "--reviewed" {
			return appMCPCLIUsageError("usage: benmore mcp review <appdir> --reviewed (bind a manifest to source you have reviewed; does not enable access)")
		}
		report, err := reviewAppMCPSource(args[1])
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(report)
	case "generate":
		flags := flag.NewFlagSet("mcp generate", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		document := flags.String("openapi", "", "pinned local OpenAPI file")
		output := flags.String("out", "", "explicit new candidate output")
		if flags.Parse(args[2:]) != nil || flags.NArg() != 0 || *document == "" || *output == "" {
			return appMCPCLIUsageError("usage: benmore mcp generate <appdir> --openapi <file> --out <file>")
		}
		if err := generateAppMCPCandidates(args[1], *document, *output); err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(map[string]any{"candidate_output": *output, "enabled": false})
	case "inspect":
		if len(args) != 3 || args[2] != "--json" {
			return appMCPCLIUsageError("usage: benmore mcp inspect <appdir> --json")
		}
	case "check":
		if len(args) != 2 {
			return appMCPCLIUsageError("usage: benmore mcp check <appdir>")
		}
	default:
		return appMCPCLIUsageError(fmt.Sprintf("unknown local connector command %q", args[0]))
	}
	report, err := inspectAppMCPSource(args[1])
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func writeAppMCPCLIHelp(out io.Writer, command string) error {
	usage := map[string]string{
		"":         "App-facing MCP source commands (no framework source checkout needed):\n  benmore mcp review <appdir> --reviewed\n  benmore mcp inspect <appdir> --json\n  benmore mcp check <appdir>\n  benmore mcp generate <appdir> --openapi <file> --out <file>\n\nRead benmore docs connector for the complete native manifest and hosted setup.\nReview accepts authored manifests without digests; runtime/upload checks require generated top-level digests. Review again after source edits. Source checks do not enable access.\nCloud/platform owner controls: benmore mcp status|enable|disable <app> --env dev|prod\n",
		"review":   "Usage: benmore mcp review <appdir> --reviewed\nAfter you review the app source and manifest, bind their digests. This does not enable access.\n",
		"inspect":  "Usage: benmore mcp inspect <appdir> --json\nRead-only inventory of reviewed source bindings and unmeasured runtime gates.\n",
		"check":    "Usage: benmore mcp check <appdir>\nRead-only check of the reviewed manifest and source bindings.\n",
		"generate": "Usage: benmore mcp generate <appdir> --openapi <file> --out <file>\nWrite disabled OpenAPI candidates to a new output file; candidates are not deployable manifests.\n",
	}
	help, ok := usage[command]
	if !ok {
		return appMCPCLIUsageError(fmt.Sprintf("no local help for %q", command))
	}
	_, err := io.WriteString(out, help)
	return err
}

// Explicit source attestation only: owner switches and user grants are unchanged.
func reviewAppMCPSource(dir string) (*appMCPInspection, error) {
	if err := validateAppMCPDeployableSources(dir); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	info, err := root.Lstat("mcp.yaml")
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("review requires an existing regular mcp.yaml")
	}
	data, err := root.ReadFile("mcp.yaml")
	if err != nil {
		return nil, err
	}
	manifest, err := parseAppMCPManifestForReview(data)
	if err != nil {
		return nil, err
	}
	manifest.ExecutionSources = appMCPExecutionSourcesRuntime // review always writes the runtime-source form
	// Bind the representation that will be written and loaded. YAML emits omitted
	// optional slices as []; hashing the pre-serialization nil slices would seal
	// JSON null instead and make our own output fail its strict source check.
	serialized, err := yaml.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	manifest, err = parseAppMCPManifestForReview(serialized)
	if err != nil {
		return nil, err
	}
	manifest.ContractDigest, manifest.ExecutionDigest, err = appMCPDigests(dir, manifest)
	if err != nil {
		return nil, err
	}
	updated, err := yaml.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	config, err := loadRuntimeConfigWithManifest(dir, updated)
	if err != nil {
		return nil, err
	}
	report, err := inspectAppMCPSourceStaged(dir, config)
	if err != nil {
		return nil, err
	}
	// Refuse a concurrently replaced manifest before publishing the reviewed copy.
	current, err := root.ReadFile("mcp.yaml")
	if err != nil || string(current) != string(data) {
		return nil, fmt.Errorf("mcp.yaml changed during review")
	}
	name := ".mcp-review-" + generateToken(16)
	tmp, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, info.Mode().Perm())
	if err != nil {
		return nil, err
	}
	defer root.Remove(name)
	if err := tmp.Chmod(info.Mode().Perm()); err != nil {
		tmp.Close()
		return nil, err
	}
	_, writeErr := tmp.Write(updated)
	closeErr := tmp.Close()
	if writeErr != nil {
		return nil, writeErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	current, err = root.ReadFile("mcp.yaml")
	if err != nil || string(current) != string(data) {
		return nil, fmt.Errorf("mcp.yaml changed during review")
	}
	if err := root.Rename(name, "mcp.yaml"); err != nil {
		return nil, err
	}
	return report, nil
}

// This stages the actual route registrar, never loadApp: no DB opening,
// migrations, handlers, scheduler, provider calls or environment publication.
func inspectAppMCPSource(dir string) (report *appMCPInspection, err error) {
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return nil, fmt.Errorf("appdir must be an existing directory")
	}
	if err := validateAppMCPDeployableSources(dir); err != nil {
		return nil, err
	}
	config, err := loadRuntimeConfig(dir)
	if err != nil {
		return nil, err
	}
	return inspectAppMCPSourceStaged(dir, config)
}

func validateAppMCPDeployableSources(dir string) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("cannot open app source: %w", err)
	}
	defer root.Close()
	for _, tree := range []string{"static", "flows"} {
		info, err := root.Lstat(tree)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("cannot inspect %s: %w", tree, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("MCP execution tree %s must be a regular directory", tree)
		}
		err = iofs.WalkDir(root.FS(), tree, func(path string, entry iofs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return fmt.Errorf("cannot inspect MCP source %s: %w", path, walkErr)
			}
			if isMetadataSidecar(path) { // never deployed nor loaded; the digest skips it too
				if entry.IsDir() {
					return iofs.SkipDir
				}
				return nil
			}
			info, err := entry.Info()
			if err != nil {
				return fmt.Errorf("cannot inspect MCP source %s: %w", path, err)
			}
			for _, segment := range strings.Split(filepath.ToSlash(path), "/") {
				if sourceManifestExcluded(segment, true) || sourceManifestExcluded(segment, false) {
					return fmt.Errorf("MCP execution source %s is excluded from deployment; remove or rename it outside static/ and flows/ before review", path)
				}
			}
			if sourceManifestExcluded(filepath.ToSlash(path), entry.IsDir()) {
				return fmt.Errorf("MCP execution source %s is excluded from deployment; remove or rename it outside static/ and flows/ before review", path)
			}
			if entry.Type()&os.ModeSymlink != 0 || (!entry.IsDir() && !info.Mode().IsRegular()) {
				return fmt.Errorf("MCP execution source %s is not a regular deployable file; remove or replace it before review", path)
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func inspectAppMCPSourceStaged(dir string, config *runtimeConfig) (report *appMCPInspection, err error) {
	definitions, err := appMCPSchemaTableDefinitionsWithReader(func(name string) ([]byte, error) { return config.schemaSource(dir, name) })
	if err != nil {
		return nil, err
	}
	tables := eligibleCRUDTables(definitions)
	pages := config.pages
	if pages == nil {
		pages, _, err = LoadPages(dir)
		if err != nil {
			return nil, fmt.Errorf("cannot inspect app pages")
		}
	}
	report = &appMCPInspection{ValidationScope: "checked source configuration and reviewed native bindings", Version: 1, SourceValid: true, ConnectorEnabled: config.mcp != nil, Inventory: []appMCPInventoryEntry{}, Unmeasured: []string{"physical_database_and_pending_migrations", "environment_dependent_routes", "current_grant_role_tenant_authority", "host_client_acceptance"}}
	if config.mcp != nil {
		report.ContractDigest = config.mcp.ContractDigest
		report.ExecutionDigest = config.mcp.ExecutionDigest
		for _, tool := range config.mcp.Tools {
			handler := map[string]string{"kind": tool.Handler.Kind, "operation": tool.Handler.Operation, "table": tool.Handler.Table, "flow": tool.Handler.Flow}
			if tool.Handler.FileColumn != "" {
				handler["file_column"] = tool.Handler.FileColumn
			}
			report.ReviewedTools = append(report.ReviewedTools, map[string]any{"name": tool.Name, "description": tool.Description, "handler": handler, "input_schema": tool.InputSchema, "output_schema": tool.OutputSchema, "permissions": tool.Permissions, "effect": tool.Effect, "approval": tool.Approval, "idempotency": tool.Idempotency, "reconciliation": tool.Reconciliation, "output_projection": tool.Output.Include, "component": tool.Component})
		}
	}
	names := make([]string, 0, len(tables))
	for name := range tables {
		names = append(names, name)
	}
	sort.Strings(names)
	app := &App{Dir: dir, Pages: pages, Paths: DiscoverAuthPaths(pages), Design: config.design, Flows: config.flows, Workflows: config.workflows, Hooks: config.hooks, MCP: config.mcp, sourceFiles: config.sourceFiles, Group: config.group, Access: config.access, routeEnv: map[string]string{}}
	defer func() {
		if recover() != nil {
			report = nil
			err = fmt.Errorf("cannot register canonical source routes")
		}
	}()
	entries := make(map[string]*appMCPInventoryEntry)
	if config.mcp != nil {
		for _, tool := range config.mcp.Tools {
			if tool.Effect == "write" && tool.Handler.Operation == "table.update" {
				entries["private_write:"+tool.Name] = &appMCPInventoryEntry{Kind: "native_write_tool", Name: tool.Name, Binding: "native:table.update:" + tool.Handler.Table, Source: "mcp.yaml", State: "disabled", Reason: "v1 exposes writes only through approved commands"}
			}
		}
	}
	for _, dev := range []bool{false, true} {
		app.DevMode = dev
		mux := buildAppRouteMux(app, dev, "", false, names)
		if config.mcp != nil {
			if err := validateAppMCPRegisteredBindings(config.mcp, config.flows, mux.ServeMux, mux.flows, mux.patterns); err != nil {
				return nil, err
			}
		}
		mode := "production"
		if dev {
			mode = "development"
		}
		for _, pattern := range mux.patterns {
			entry := entries[pattern]
			if entry == nil {
				source := mux.sources[pattern]
				entry = &appMCPInventoryEntry{Kind: "command_route", Name: pattern, Binding: pattern, Source: source, State: "command-only", Reason: "canonical HTTP route has no reviewed native connector binding"}
				if strings.HasPrefix(source, "crud.go:") {
					entry.Kind = "crud"
				}
				if strings.HasPrefix(source, "flows.go:") {
					entry.Kind = "request_flow"
				}
				if strings.HasPrefix(source, "upload") || strings.HasPrefix(source, "pdf.go:") || strings.HasPrefix(source, "image_transform.go:") || pattern == "GET /uploads/" {
					entry.Kind = "artifact_route"
					entry.State = "disabled"
					entry.Reason = "connector artifact authorization is not enabled"
				}
				if config.mcp != nil {
					for _, tool := range config.mcp.Tools {
						binding := ""
						switch tool.Handler.Operation {
						case "table.list":
							binding = "GET /api/" + tool.Handler.Table
						case "table.read":
							binding = "GET /api/" + tool.Handler.Table + "/"
						case "flow.call":
							binding = mux.flows[tool.Handler.Flow]
						}
						if binding == pattern {
							entry.State = "exposed"
							entry.Reason = "reviewed native declaration; live caller authority remains required"
							entry.Tools = append(entry.Tools, tool.Name)
						}
					}
				}
				entries[pattern] = entry
			}
			entry.Modes = append(entry.Modes, mode)
		}
		for _, flow := range config.flows {
			key := "flow:" + flow.Name
			if entries[key] != nil {
				continue
			}
			entry := &appMCPInventoryEntry{Kind: flow.Trigger.Type + "_flow", Name: flow.Name, Source: flow.Source, Inputs: flow.Trigger.Inputs, State: "disabled", Reason: "non-HTTP triggers are outside native connector dispatch", Binding: flow.Trigger.Type + ":" + flow.Trigger.Table + flow.Trigger.Cron}
			if flow.Command != nil && flow.Trigger.Type == "command" {
				entry.Binding = "command:" + flow.Name
				if flow.Command.Request != nil {
					entry.Binding = flow.Command.Request.Method + " " + flow.Command.Request.Path
				}
				entry.Reason = "command declaration has no reviewed connector tool"
				if config.mcp != nil {
					for _, tool := range config.mcp.Tools {
						if tool.Handler.Operation == "command" && tool.Handler.Flow == flow.Name {
							entry.State, entry.Effect, entry.Approval = "command", tool.Effect, tool.Approval
							entry.Reason = "reviewed command tool; execution requires an owner-approved prepared operation and live caller authority"
							entry.Tools = append(entry.Tools, tool.Name)
						}
					}
				}
			}
			if flow.Trigger.Type == "http" {
				entry.Kind = "request_flow"
				entry.Binding = mux.flows[flow.Name]
				entry.State = "unresolved"
				entry.Reason = "canonical flow registration was skipped"
				if bound := entries[entry.Binding]; bound != nil {
					entry.State = bound.State
					entry.Reason = bound.Reason
					entry.Tools = bound.Tools
				}
			}
			entries[key] = entry
		}
	}
	for route, page := range pages {
		entries["ui:"+route] = &appMCPInventoryEntry{Kind: "ui_entrypoint", Name: route, Binding: route, Source: page.File, State: "disabled", Reason: "app page is not an approved reusable connector component"}
	}
	addUISource := func(relative string) error {
		if len(entries) >= 10000 {
			return fmt.Errorf("source inventory exceeds 10000 entries")
		}
		ext := filepath.Ext(relative)
		if ext == ".tsx" || ext == ".ts" || ext == ".jsx" || ext == ".js" || ext == ".html" {
			entries["ui_source:"+relative] = &appMCPInventoryEntry{Kind: "ui_source", Name: relative, Source: relative, Binding: "GET /static/", State: "unresolved", Reason: "source file inventoried; reusable component and dependency closure not reviewed"}
		}
		return nil
	}
	if config.mcp != nil {
		for path := range config.sourceFiles {
			if strings.HasPrefix(path, "static/") {
				if err := addUISource(path); err != nil {
					return nil, err
				}
			}
		}
	} else if err := filepath.WalkDir(filepath.Join(dir, "static"), func(path string, entry os.DirEntry, walkErr error) error {
		if os.IsNotExist(walkErr) && path == filepath.Join(dir, "static") {
			return nil
		}
		if walkErr != nil {
			return fmt.Errorf("cannot inspect static source")
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		return addUISource(filepath.ToSlash(relative))
	}); err != nil {
		return nil, err
	}
	if config.cron != nil {
		for _, job := range config.cron.Jobs {
			entries["cron:"+job.ID] = &appMCPInventoryEntry{Kind: "scheduled_job", Name: job.ID, Binding: job.Flow, Source: "cron.yaml", State: "disabled", Reason: "scheduler is outside native connector dispatch"}
		}
	}
	if config.hooks != nil {
		for event, tables := range map[string]map[string][]Hook{"on_insert": config.hooks.OnInsert, "on_update": config.hooks.OnUpdate, "on_delete": config.hooks.OnDelete, "before_insert": config.hooks.BeforeInsert, "before_update": config.hooks.BeforeUpdate, "before_delete": config.hooks.BeforeDelete} {
			for table, hooks := range tables {
				for index := range hooks {
					name := fmt.Sprintf("%s:%s:%d", event, table, index)
					entries["hook:"+name] = &appMCPInventoryEntry{Kind: "event_hook", Name: name, Binding: event + ":" + table, Source: "hooks.yaml", State: "disabled", Reason: "data hooks execute through canonical mutations, not standalone connector tools"}
				}
			}
		}
	}
	if len(entries) > 10000 {
		return nil, fmt.Errorf("source inventory exceeds 10000 entries")
	}
	keys := make([]string, 0, len(entries))
	for key := range entries {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		report.Inventory = append(report.Inventory, *entries[key])
	}
	// Paths identify source inside the app/framework, never absolute host paths.
	for i := range report.Inventory {
		report.Inventory[i].Source = filepath.ToSlash(report.Inventory[i].Source)
	}
	return report, nil
}
