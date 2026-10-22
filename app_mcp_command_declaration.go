//go:build !cli

package main

import (
	"fmt"
	"slices"
	"strings"
)

func validateAppMCPBindingsForTables(m *AppMCPManifest, flows []Flow, tables map[string]bool, roles *RolesConfig) error {
	commandBindings := map[string]int{}
	toolsByName := make(map[string]*AppMCPTool, len(m.Tools))
	for i := range m.Tools {
		toolsByName[m.Tools[i].Name] = &m.Tools[i]
	}
	for _, tool := range m.Tools {
		if tool.Handler.Kind == "external" {
			continue // bound to a pinned OpenAPI operation, not a table or flow (validateAppMCPDeclaredSources)
		}
		if tool.Handler.Table != "" {
			if strings.HasPrefix(tool.Handler.Table, "_") || strings.HasPrefix(strings.ToLower(tool.Handler.Table), "sqlite_") {
				return fmt.Errorf("mcp.yaml: tool %q targets a reserved framework table", tool.Name)
			}
			if !tables[tool.Handler.Table] {
				return fmt.Errorf("mcp.yaml: tool %q has unresolved table %q", tool.Name, tool.Handler.Table)
			}
			if tool.Handler.Operation == "table.update" {
				if len(tool.Permissions) != 1 || tool.Permissions[0] != tool.Handler.Table+":write" {
					return fmt.Errorf("mcp.yaml: tool %q lacks canonical table write permission", tool.Name)
				}
			} else if !scopesWithin(strings.Join(tool.Permissions, " "), tool.Handler.Table+":read") {
				return fmt.Errorf("mcp.yaml: tool %q lacks canonical table read permission", tool.Name)
			}
		} else {
			found := false
			for _, flow := range flows {
				if flow.Name != tool.Handler.Flow {
					continue
				}
				found = true
				if tool.Handler.Operation == "command" {
					commandBindings[flow.Name]++
					if flow.Command == nil || flow.Trigger.Type != "command" {
						return fmt.Errorf("mcp.yaml: tool %q is not bound to a command declaration", tool.Name)
					}
					if err := validateAppMCPCommandDescriptor(tool, flow.Command, m.sourceHashes, tables, roles); err != nil {
						return fmt.Errorf("mcp.yaml: tool %q: %w", tool.Name, err)
					}
					if tool.Transfer != nil {
						if err := validateAppMCPCommandTransfer(tool, toolsByName, tables); err != nil {
							return fmt.Errorf("mcp.yaml: tool %q transfer: %w", tool.Name, err)
						}
					}
				} else {
					if flow.Command != nil {
						return fmt.Errorf("mcp.yaml: tool %q cannot bind a command through flow.call", tool.Name)
					}
					if err := appMCPReadFlowPolicy(&flow); err != nil {
						return fmt.Errorf("mcp.yaml: tool %q: %w", tool.Name, err)
					}
					if flow.Trigger.Type != "http" || len(flow.Permissions) == 0 || !scopesWithin(strings.Join(tool.Permissions, " "), strings.Join(flow.Permissions, " ")) {
						return fmt.Errorf("mcp.yaml: tool %q lacks reviewed canonical flow permissions", tool.Name)
					}
					if err := validateAppMCPFlowInputContract(tool, &flow); err != nil {
						return fmt.Errorf("mcp.yaml: tool %q: %w", tool.Name, err)
					}
				}
			}
			if !found {
				return fmt.Errorf("mcp.yaml: tool %q has unresolved flow %q", tool.Name, tool.Handler.Flow)
			}
		}
	}
	for _, flow := range flows {
		if flow.Command != nil && commandBindings[flow.Name] != 1 {
			return fmt.Errorf("mcp.yaml: command %q requires exactly one declaration binding", flow.Name)
		}
	}
	return validateAppMCPRouteBindings(m, flows, tables)
}

func validateAppMCPCommandTransfer(tool AppMCPTool, tools map[string]*AppMCPTool, tables map[string]bool) error {
	transfer := tool.Transfer
	if transfer == nil {
		return nil
	}
	for _, path := range []string{transfer.SelectorIntentPath, transfer.RecordIDIntentPath, transfer.ArtifactIntentPath} {
		if path == "" {
			continue
		}
		schema, ok := appMCPCommandRequiredSchemaPath(tool.InputSchema, path)
		if !ok || schema.Type != "string" || schema.Nullable {
			return fmt.Errorf("transfer path %q must name a required string input", path)
		}
	}
	if transfer.Kind != "pull" {
		return nil
	}
	attach := tools[transfer.AttachTool]
	if attach == nil || attach.Handler.Operation != "table.update" || attach.Handler.Table == "" || !tables[attach.Handler.Table] {
		return fmt.Errorf("pull requires an existing canonical table.update attach tool")
	}
	if !slices.Contains(tool.Permissions, attach.Handler.Table+":write") || !slices.Contains(attach.Permissions, attach.Handler.Table+":write") {
		return fmt.Errorf("pull command and attach tool must both declare target table write permission")
	}
	if !isValidColumnName(transfer.FileColumn) || attach.InputSchema.Properties["data"] == nil || attach.InputSchema.Properties["data"].Properties[transfer.FileColumn] == nil {
		return fmt.Errorf("pull file_column must be a declared canonical update field")
	}
	return nil
}

func validateAppMCPCommandDescriptor(tool AppMCPTool, command *FlowCommand, captured map[string]string, tables map[string]bool, roles *RolesConfig) error {
	if tool.Handler.Kind != "flow" || tool.Handler.Operation != "command" || command == nil {
		return fmt.Errorf("invalid command binding")
	}
	if err := validateCommandSchemaNames(tool.InputSchema); err != nil {
		return err
	}
	if err := validateAppMCPReviewBindings(tool, command); err != nil {
		return err
	}
	if len(command.Generated) > 0 && tool.InputSchema.Properties[commandGeneratedKey] != nil {
		return fmt.Errorf("command input schema cannot declare a property named generated when the command declares generated values")
	}
	writes := map[string]bool{}
	for _, table := range command.Writes {
		writes[table] = true
		if !tables[table] {
			return fmt.Errorf("command write table %q is unresolved", table)
		}
	}
	for _, dep := range command.Dependencies {
		if !tables[dep.Table] {
			return fmt.Errorf("dependency table %q is unresolved", dep.Table)
		}
		for _, ref := range dep.Params {
			if ref.Kind == "intent_path" {
				schema, ok := appMCPCommandRequiredSchemaPath(tool.InputSchema, ref.Path)
				if !ok || schema.Nullable || schema.Type != "string" && schema.Type != "integer" {
					return fmt.Errorf("dependency %q has an unresolved or incompatible intent path", dep.Name)
				}
			}
		}
	}
	// A permission is a table scope (read/write) or a capability scope: a
	// resource some role in app.yaml roles: names (so a typo is refused) with
	// any identifier action. A table name always takes the table rules.
	covered := false
	for _, scope := range tool.Permissions {
		resource, action, _ := strings.Cut(scope, ":")
		if tables[resource] {
			if action != "read" && action != "write" {
				return fmt.Errorf("command permission has unsupported action")
			}
			covered = covered || action == "write" && writes[resource]
			continue
		}
		if !appMCPCapabilityResource(roles, resource) {
			return fmt.Errorf("command permission resource %q is unresolved", resource)
		}
		if !isScopeIdentifier(action) || action == "*" {
			return fmt.Errorf("command permission has unsupported action")
		}
		// `*` actions never reach here (validateFlowPermissions refuses them).
		covered = covered || action == "write"
	}
	if !covered {
		return fmt.Errorf("command requires a write permission for a declared table or capability")
	}
	for _, field := range tool.Output.Include {
		if _, ok := appMCPCommandSchemaPath(tool.OutputSchema, field); !ok {
			return fmt.Errorf("command output field %q is unresolved", field)
		}
	}
	for phaseName, phase := range map[string]FlowCommandPhase{"prepare": command.Prepare, "apply": command.Apply, "readback": command.Readback} {
		schema := tool.InputSchema
		if phaseName != "prepare" {
			schema = command.PreparedSchema
		}
		if err := validateAppMCPCommandIntentBindings(phase.Steps, schema, phaseName); err != nil {
			return err
		}
		if err := validateAppMCPCommandComputeSources(phase.Steps, captured); err != nil {
			return err
		}
	}
	return nil
}
func validateCommandSchemaNames(schema *AppMCPSchema) error {
	if schema == nil {
		return fmt.Errorf("missing command input schema")
	}
	for name, child := range schema.Properties {
		if !commandLocalName(name) {
			return fmt.Errorf("command schema has unsafe property name %q", name)
		}
		if err := validateCommandSchemaNames(child); err != nil {
			return err
		}
	}
	if schema.Items != nil {
		if err := validateCommandSchemaNames(schema.Items); err != nil {
			return err
		}
	}
	return nil
}
func validateAppMCPCommandIntentBindings(steps []FlowStep, input *AppMCPSchema, phase string) error {
	for _, step := range steps {
		if step.Type == "sql" {
			if len(step.SQLParams) != len(step.CommandSQLParams) {
				return fmt.Errorf("SQL bindings lost their raw typed references")
			}
			for name, ref := range step.CommandSQLParams {
				raw := step.SQLParams[name]
				if commandActorEmailRef.MatchString(raw) != (ref.Kind == "actor_email") {
					return fmt.Errorf("SQL binding %q lost its exact typed source reference", name)
				}
				if ref.Kind == "actor_email" && (phase != "apply" || ref.Path != "") {
					return fmt.Errorf("trusted actor email is an apply-SQL-only empty-path binding")
				}
				if ref.Kind == "phase_path" {
					// A declared scalar path binds even when optional or nullable:
					// a missing or null value binds SQL NULL (appMCPResolveCommandRefs).
					schema, ok := appMCPCommandSchemaPath(input, ref.Path)
					if !ok || !appMCPCommandBindableType(schema.Type) {
						return fmt.Errorf("SQL binding %q has an unresolved or incompatible phase path", name)
					}
				}
			}
		}
		if step.Type == "revoke_user_sessions" {
			if phase != "apply" || step.CommandRevokeRef.Kind != "phase_path" {
				return fmt.Errorf("revoke_user_sessions is an apply-phase step bound to a captured intent value")
			}
			schema, ok := appMCPCommandRequiredSchemaPath(input, step.CommandRevokeRef.Path)
			if !ok || schema.Type != "integer" || schema.Nullable {
				return fmt.Errorf("revoke_user_sessions user_id must name a required, non-nullable integer in prepared_schema")
			}
		}
		if step.Type == "for_each" && strings.HasPrefix(step.ForEach, "params.") {
			schema, ok := appMCPCommandRequiredSchemaPath(input, strings.TrimPrefix(step.ForEach, "params."))
			if !ok || schema.Type != "array" || schema.Nullable || schema.MaxItems == nil || schema.Items != nil && schema.Items.Nullable {
				return fmt.Errorf("for_each intent source must be a required, non-nullable bounded array")
			}
		}
		for _, nested := range [][]FlowStep{step.Steps, step.ElseSteps} {
			if err := validateAppMCPCommandIntentBindings(nested, input, phase); err != nil {
				return err
			}
		}
	}
	return nil
}
func appMCPCommandBindableType(schemaType string) bool {
	switch schemaType {
	case "string", "integer", "number", "boolean":
		return true
	}
	return false
}
func appMCPCommandSchemaPath(schema *AppMCPSchema, dotted string) (*AppMCPSchema, bool) {
	if schema == nil || dotted == "" {
		return nil, false
	}
	parts := strings.Split(dotted, ".")
	current := schema
	for _, part := range parts {
		if current == nil || current.Type != "object" {
			return nil, false
		}
		current = current.Properties[part]
		if current == nil {
			return nil, false
		}
	}
	return current, true
}
func appMCPCommandRequiredSchemaPath(schema *AppMCPSchema, dotted string) (*AppMCPSchema, bool) {
	if schema == nil || dotted == "" {
		return nil, false
	}
	parts := strings.Split(dotted, ".")
	current := schema
	for _, part := range parts {
		if current == nil || current.Type != "object" || !appMCPHasRequiredField(current, part) {
			return nil, false
		}
		current = current.Properties[part]
		if current == nil {
			return nil, false
		}
	}
	return current, true
}
func appMCPHasRequiredField(schema *AppMCPSchema, field string) bool {
	for _, required := range schema.Required {
		if required == field {
			return true
		}
	}
	return false
}
func validateAppMCPCommandComputeSources(steps []FlowStep, captured map[string]string) error {
	for _, step := range steps {
		if step.Type == "compute" && step.Compute != nil {
			module := strings.TrimSpace(step.Compute.Module)
			if module == "" || strings.Contains(module, "..") || strings.HasPrefix(module, "/") || strings.ContainsAny(module, "\\\x00") {
				return fmt.Errorf("unsafe command compute module")
			}
			found := false
			for _, ext := range []string{"", ".ts", ".js", ".tsx", ".jsx"} {
				if _, ok := captured["static/"+module+ext]; ok {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("command compute module %q is absent from captured source", module)
			}
		}
		for _, nested := range [][]FlowStep{step.Steps, step.ElseSteps} {
			if err := validateAppMCPCommandComputeSources(nested, captured); err != nil {
				return err
			}
		}
	}
	return nil
}

// Inspect values before typed decoding discards null presence or truncates floats.

// appMCPCapabilityResource reports whether some role, directly or through
// inherits, grants a scope on resource. A role holding only "*" names nothing,
// so a mistyped capability still fails.
func appMCPCapabilityResource(roles *RolesConfig, resource string) bool {
	if roles == nil || resource == "" || resource == "*" || !isScopeIdentifier(resource) {
		return false
	}
	for name := range roles.Roles {
		for _, scope := range strings.Fields(roles.ResolveRoleScopes(name)) {
			if r, _ := parseScope(scope); r == resource {
				return true
			}
		}
	}
	return false
}
