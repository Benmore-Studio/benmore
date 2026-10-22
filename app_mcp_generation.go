//go:build !cli

package main

import "sync"

// appMCPRuntimeGeneration is the immutable policy/configuration view for one
// connector request. Its view deliberately omits App synchronization and worker
// state; DB and directory remain shared with the live owner.
type appMCPRuntimeGeneration struct {
	origin            *App
	view              *App
	manifest          *AppMCPManifest
	hooks             *HookConfig
	validators        *ValidatorConfig
	computed          *ComputedFieldConfig
	workflows         *WorkflowConfig
	pages             map[string]*Page
	flows             []Flow
	environment       map[string]string
	sourceFiles       map[string][]byte
	templateEnvSource []byte
	// declarations already reported as not live, so the log names each broken
	// command once per generation instead of once per request.
	reportedUnlive *sync.Map
	// published MCP Apps components, built once per generation.
	widgets *appMCPWidgetMemo
}

func newAppMCPRuntimeGeneration(origin *App, manifest *AppMCPManifest, group *GroupConfig, roles *RolesConfig, access *AccessConfig, scopes map[string]ScopeConfig, design *DesignConfig, tables []Table, uuidTables map[string]bool, encrypted *EncryptedFieldConfig, flows []Flow, sourceFiles map[string][]byte, environment map[string]string, templateEnvSource []byte, hooks *HookConfig, validators *ValidatorConfig, computed *ComputedFieldConfig, workflows *WorkflowConfig, pages map[string]*Page) *appMCPRuntimeGeneration {
	flowCopy := append([]Flow(nil), flows...)
	for i := range flowCopy {
		flowCopy[i].Command = cloneFlowCommand(flows[i].Command)
	}
	tableCopy := append([]Table(nil), tables...)
	scopeCopy := make(map[string]ScopeConfig, len(scopes))
	for key, value := range scopes {
		scopeCopy[key] = value
	}
	uuidCopy := make(map[string]bool, len(uuidTables))
	for key, value := range uuidTables {
		uuidCopy[key] = value
	}
	envCopy := make(map[string]string, len(environment))
	for key, value := range environment {
		envCopy[key] = value
	}
	sourceCopy := make(map[string][]byte, len(sourceFiles))
	for key, value := range sourceFiles {
		sourceCopy[key] = append([]byte(nil), value...)
	}
	templateCopy := append([]byte(nil), templateEnvSource...)
	hooksCopy := cloneHookConfig(hooks)
	validatorsCopy := cloneValidatorConfig(validators)
	computedCopy := cloneComputedConfig(computed)
	workflowsCopy := cloneWorkflowConfig(workflows)
	pagesCopy := clonePages(pages)
	view := &App{Dir: origin.Dir, DB: origin.DB, JoinMap: origin.JoinMap, MCP: manifest, Group: group, Roles: roles, Access: access, Scopes: scopeCopy, Design: design, Tables: tableCopy, UUIDTables: uuidCopy, Encrypted: encrypted, Flows: flowCopy, Hooks: hooksCopy, Validators: validatorsCopy, Computed: computedCopy, Workflows: workflowsCopy, Pages: pagesCopy, sourceFiles: sourceCopy, environment: envCopy, templateEnvSource: templateCopy, auditOwner: origin}
	return &appMCPRuntimeGeneration{origin: origin, view: view, manifest: manifest, hooks: hooksCopy, validators: validatorsCopy, computed: computedCopy, workflows: workflowsCopy, pages: pagesCopy, flows: flowCopy, environment: envCopy, sourceFiles: sourceCopy, templateEnvSource: templateCopy, reportedUnlive: new(sync.Map), widgets: new(appMCPWidgetMemo)}
}

func cloneFlowCommand(src *FlowCommand) *FlowCommand {
	if src == nil {
		return nil
	}
	out := *src
	out.PreparedSchema = cloneAppMCPSchema(src.PreparedSchema)
	out.PreviewSchema = cloneAppMCPSchema(src.PreviewSchema)
	out.Writes = append([]string(nil), src.Writes...)
	out.Owns = append([]FlowCommandOwn(nil), src.Owns...)
	out.Generated = append([]FlowCommandGenerated(nil), src.Generated...)
	out.AppTriggers = append([]FlowCommandAppTrigger(nil), src.AppTriggers...)
	out.Dependencies = append([]FlowCommandDependency(nil), src.Dependencies...)
	for i := range out.Dependencies {
		in := src.Dependencies[i]
		out.Dependencies[i].Params = make(map[string]FlowCommandParamRef, len(in.Params))
		for k, v := range in.Params {
			out.Dependencies[i].Params[k] = v
		}
	}
	out.Prepare = cloneFlowCommandPhase(src.Prepare)
	out.Apply = cloneFlowCommandPhase(src.Apply)
	out.Readback = cloneFlowCommandPhase(src.Readback)
	if src.Request != nil {
		r := *src.Request
		if src.Request.RateLimit != nil {
			limit := *src.Request.RateLimit
			r.RateLimit = &limit
		}
		out.Request = &r
	}
	return &out
}
func cloneFlowCommandPhase(src FlowCommandPhase) FlowCommandPhase {
	out := src
	out.Steps = cloneCommandSteps(src.Steps)
	out.ReadTables = append([]string(nil), src.ReadTables...)
	out.WriteTables = append([]string(nil), src.WriteTables...)
	out.ComputeModules = append([]string(nil), src.ComputeModules...)
	return out
}
func cloneCommandSteps(src []FlowStep) []FlowStep {
	if src == nil {
		return nil
	}
	out := append([]FlowStep(nil), src...)
	for i := range out {
		step := &out[i]
		step.SQLParams = cloneStringMap(step.SQLParams)
		if step.CommandSQLParams != nil {
			commandParams := step.CommandSQLParams
			step.CommandSQLParams = make(map[string]FlowCommandParamRef, len(commandParams))
			for k, v := range commandParams {
				step.CommandSQLParams[k] = v
			}
		}
		step.Set = cloneStringMap(step.Set)
		step.Steps = cloneCommandSteps(step.Steps)
		step.ElseSteps = cloneCommandSteps(step.ElseSteps)
		step.OnError = cloneCommandSteps(step.OnError)
		if step.Compute != nil {
			c := *step.Compute
			c.Args = cloneCommandValue(c.Args)
			step.Compute = &c
		}
		if step.Respond != nil {
			r := *step.Respond
			if r.JSON != nil {
				r.JSON = cloneCommandValue(r.JSON).(map[string]any)
			}
			if r.JSONArray != nil {
				r.JSONArray = cloneCommandValue(r.JSONArray).([]any)
			}
			step.Respond = &r
		}
	}
	return out
}
func cloneStringMap(src map[string]string) map[string]string {
	if src == nil {
		return nil
	}
	out := make(map[string]string, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}
func cloneCommandValue(src any) any {
	switch value := src.(type) {
	case map[string]any:
		out := make(map[string]any, len(value))
		for k, v := range value {
			out[k] = cloneCommandValue(v)
		}
		return out
	case []any:
		out := make([]any, len(value))
		for i, v := range value {
			out[i] = cloneCommandValue(v)
		}
		return out
	default:
		return src
	}
}
func cloneAppMCPSchema(src *AppMCPSchema) *AppMCPSchema {
	if src == nil {
		return nil
	}
	out := *src
	if src.Properties != nil {
		out.Properties = make(map[string]*AppMCPSchema, len(src.Properties))
		for k, v := range src.Properties {
			out.Properties[k] = cloneAppMCPSchema(v)
		}
	}
	out.Required = append([]string(nil), src.Required...)
	if src.AdditionalProperties != nil {
		v := *src.AdditionalProperties
		out.AdditionalProperties = &v
	}
	out.Items = cloneAppMCPSchema(src.Items)
	out.Enum = make([]any, len(src.Enum))
	for i, v := range src.Enum {
		out.Enum[i] = cloneCommandValue(v)
	}
	if src.Minimum != nil {
		v := *src.Minimum
		out.Minimum = &v
	}
	if src.Maximum != nil {
		v := *src.Maximum
		out.Maximum = &v
	}
	if src.MinLength != nil {
		v := *src.MinLength
		out.MinLength = &v
	}
	if src.MaxLength != nil {
		v := *src.MaxLength
		out.MaxLength = &v
	}
	if src.MinItems != nil {
		v := *src.MinItems
		out.MinItems = &v
	}
	if src.MaxItems != nil {
		v := *src.MaxItems
		out.MaxItems = &v
	}
	return &out
}

func cloneHookConfig(src *HookConfig) *HookConfig {
	if src == nil {
		return nil
	}
	out := &HookConfig{}
	clone := func(in map[string][]Hook) map[string][]Hook {
		if in == nil {
			return nil
		}
		m := make(map[string][]Hook, len(in))
		for table, hooks := range in {
			items := append([]Hook(nil), hooks...)
			for i := range items {
				if items[i].Email != nil {
					value := *items[i].Email
					items[i].Email = &value
				}
				if items[i].Notify != nil {
					value := *items[i].Notify
					items[i].Notify = &value
				}
				if items[i].WS != nil {
					value := *items[i].WS
					items[i].WS = &value
				}
				if items[i].SMS != nil {
					value := *items[i].SMS
					items[i].SMS = &value
				}
			}
			m[table] = items
		}
		return m
	}
	out.OnInsert, out.OnUpdate, out.OnDelete = clone(src.OnInsert), clone(src.OnUpdate), clone(src.OnDelete)
	out.BeforeInsert, out.BeforeUpdate, out.BeforeDelete = clone(src.BeforeInsert), clone(src.BeforeUpdate), clone(src.BeforeDelete)
	return out
}

func cloneValidatorConfig(src *ValidatorConfig) *ValidatorConfig {
	if src == nil {
		return nil
	}
	out := &ValidatorConfig{Rules: make(map[string][]ValidatorRule, len(src.Rules))}
	for table, rules := range src.Rules {
		out.Rules[table] = append([]ValidatorRule(nil), rules...)
	}
	return out
}

func cloneComputedConfig(src *ComputedFieldConfig) *ComputedFieldConfig {
	if src == nil {
		return nil
	}
	out := &ComputedFieldConfig{Fields: make(map[string]map[string]*ComputedField, len(src.Fields))}
	for table, fields := range src.Fields {
		copyFields := make(map[string]*ComputedField, len(fields))
		for name, field := range fields {
			if field == nil {
				copyFields[name] = nil
				continue
			}
			copyField := *field
			copyField.Triggers = append([]ComputedTriggerDef(nil), field.Triggers...)
			for i := range copyField.Triggers {
				copyField.Triggers[i].On = append([]string(nil), copyField.Triggers[i].On...)
			}
			copyFields[name] = &copyField
		}
		out.Fields[table] = copyFields
	}
	return out
}

func cloneWorkflowConfig(src *WorkflowConfig) *WorkflowConfig {
	if src == nil {
		return nil
	}
	out := &WorkflowConfig{Workflows: make(map[string]*Workflow, len(src.Workflows))}
	for name, workflow := range src.Workflows {
		if workflow == nil {
			out.Workflows[name] = nil
			continue
		}
		copyWorkflow := *workflow
		copyWorkflow.States = append([]string(nil), workflow.States...)
		copyWorkflow.Transitions = make(map[string]map[string]Transition, len(workflow.Transitions))
		for from, transitions := range workflow.Transitions {
			inner := make(map[string]Transition, len(transitions))
			for to, transition := range transitions {
				inner[to] = transition
			}
			copyWorkflow.Transitions[from] = inner
		}
		copyWorkflow.OnTransition = cloneHookConfig(&HookConfig{OnUpdate: workflow.OnTransition}).OnUpdate
		copyWorkflow.Timeouts = make(map[string]WorkflowTimeout, len(workflow.Timeouts))
		for state, timeout := range workflow.Timeouts {
			copyWorkflow.Timeouts[state] = timeout
		}
		out.Workflows[name] = &copyWorkflow
	}
	return out
}

func clonePages(src map[string]*Page) map[string]*Page {
	if src == nil {
		return nil
	}
	out := make(map[string]*Page, len(src))
	for route, page := range src {
		if page == nil {
			out[route] = nil
			continue
		}
		copyPage := *page
		out[route] = &copyPage
	}
	return out
}

// snapshotAppMCPGeneration captures the published identity under the owner lock.
// The fallback supports tests and short-lived, directly assembled App fixtures.
func snapshotAppMCPGeneration(app *App) *appMCPRuntimeGeneration {
	if app == nil {
		return nil
	}
	app.mu.RLock()
	defer app.mu.RUnlock()
	if app.mcpGeneration != nil {
		return app.mcpGeneration
	}
	return appMCPGenerationFromAppLocked(app)
}

func appMCPGenerationCurrent(origin *App, generation *appMCPRuntimeGeneration) bool {
	if origin == nil || generation == nil || generation.origin != origin {
		return false
	}
	origin.mu.RLock()
	defer origin.mu.RUnlock()
	if origin.mcpGeneration != nil {
		return origin.mcpGeneration == generation
	}
	return origin.MCP == generation.manifest
}

func appMCPGenerationFromAppLocked(app *App) *appMCPRuntimeGeneration {
	return newAppMCPRuntimeGeneration(app, app.MCP, app.Group, app.Roles, app.Access, app.Scopes, app.Design, app.Tables, app.UUIDTables, app.Encrypted, app.Flows, app.sourceFiles, app.environment, app.templateEnvSource, app.Hooks, app.Validators, app.Computed, app.Workflows, app.Pages)
}
