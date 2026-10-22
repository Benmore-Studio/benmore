//go:build !cli

package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// appMCPCommandCapability is the only value accepted by the phase provider.
// It is created by the private owner coordinator after locking, native
// authority verification, and revision-enrollment verification. Authored flow
// steps never receive the connection, transaction, or capability itself.
type appMCPCommandCapability struct {
	ctx          context.Context
	app          *App
	generation   *appMCPRuntimeGeneration
	tool         *AppMCPTool
	flow         *Flow
	command      *FlowCommand
	actor        Session
	actorCreated string
	origin       appMCPCommandOriginKind
	originPin    *appMCPWriteAuthorityPin
	sessionID    string
	tenant       string
	epoch        string
	writeEpoch   string
	exportEpoch  string
	// Grant-consented auto-approval as this transaction saw it (connector
	// origin only): the grant's ticked tools and whether the owner switch is
	// on with the pin's epoch. Flags only; they never authorize by themselves.
	autoApproveTools        []string
	autoApproveLive         bool
	autoApproveOwnerOn      bool // the owner switch alone; only explains why a prepare was not auto-approved
	readOnlyStatus          bool
	conn                    *sql.Conn
	tx                      *sql.Tx
	lease                   *appMCPAuthorityLease
	enrollment              *appMCPVerifiedRevisionEnrollment
	dependencies            *appMCPRevisionDependencySnapshot
	budget                  *appMCPCommandBudget
	guard                   *appMCPCommandExecution
	currentPhase            string
	sourceVerificationScope bool
	closed                  bool
	// Effects recorded for the post-commit real-time broadcast.
	writes              []appMCPCommandWrite
	hookRefresh         []string
	workflowTransitions map[string]appMCPWorkflowTransitionState
	// Durable effects queued in the command transaction, the operation they
	// belong to (set by the commit coordinator) and the webhook subscriptions
	// read when the effect policy was checked.
	effects       []appMCPEffectIntent
	operationID   string
	subscriptions []map[string]any
	// run: revoke_user_sessions (app_mcp_command_revoke.go): which targets
	// held a live membership in the tenant when the apply began, and the
	// users whose credentials the apply ended (edge grants follow the commit).
	revokeMembers map[int64]bool
	revokedUsers  []int64
}

type appMCPCommandComputeKey struct{}

func (cap *appMCPCommandCapability) currentPhaseName() string {
	if cap == nil {
		return ""
	}
	return cap.currentPhase
}

func commandPhaseAllowsCompute(command *FlowCommand, phase, module string) bool {
	if command == nil || module == "" {
		return false
	}
	var current FlowCommandPhase
	switch phase {
	case "prepare":
		current = command.Prepare
	case "apply":
		current = command.Apply
	case "readback":
		current = command.Readback
	default:
		return false
	}
	for _, declared := range current.ComputeModules {
		if declared == module {
			return true
		}
	}
	return false
}

type appMCPCommandBudget struct {
	steps int
	loops int
}

type appMCPCommandPhaseResult struct {
	Arguments map[string]any `json:"arguments,omitempty"`
	Preview   map[string]any `json:"preview,omitempty"`
	Readback  map[string]any `json:"readback,omitempty"`
}

// appMCPCommandPrepared is an immutable in-process value for the native
// coordinator/test seam. Durable approval persistence belongs to the later
// operation store and is intentionally absent here.
type appMCPCommandPrepared struct {
	ToolName        string
	ContractDigest  string
	ExecutionDigest string
	OwnerEpoch      string
	WriteEpoch      string
	EnrollmentID    string
	ActorUserID     int64
	ActorEmail      string
	ActorCreated    string
	Tenant          string
	Origin          appMCPCommandOriginKind
	Intent          map[string]any
	Arguments       map[string]any
	Preview         map[string]any
	Dependencies    *appMCPRevisionDependencySnapshot
}

// appMCPRunCommandPhase only consumes a previously verified private
// capability. The operation is borrowed-Tx: it cannot commit or publish an
// externally visible success result.
func appMCPRunCommandPhase(cap *appMCPCommandCapability, phase string, values map[string]any) (map[string]any, error) {
	if err := cap.validateLifetime(); err != nil {
		return nil, err
	}
	var declaration FlowCommandPhase
	var responseSchema *AppMCPSchema
	switch phase {
	case "prepare":
		declaration, responseSchema = cap.command.Prepare, appMCPCommandPrepareResponseSchema(cap.command)
	case "apply":
		declaration, responseSchema = cap.command.Apply, appMCPCommandApplyResponseSchema()
	case "readback":
		declaration, responseSchema = cap.command.Readback, cap.tool.OutputSchema
	default:
		return nil, errors.New("unknown private command phase")
	}
	if err := validateAppMCPCommandRuntimePhase(declaration, phase, cap.command.Writes); err != nil {
		return nil, err
	}
	if values == nil {
		values = map[string]any{}
	}
	// Prepare draws the declared generated values once. The caller's intent map
	// is left alone: it is stored as the sealed intent, which never holds them.
	var generated map[string]any
	if phase == "prepare" && len(cap.command.Generated) > 0 {
		if _, taken := values[commandGeneratedKey]; taken {
			return nil, appMCPResultFailure("invalid_input")
		}
		var err error
		if generated, err = appMCPGenerateCommandValues(cap.command.Generated); err != nil {
			return nil, err
		}
		withGenerated := make(map[string]any, len(values)+1)
		for key, value := range values {
			withGenerated[key] = value
		}
		withGenerated[commandGeneratedKey] = generated
		values = withGenerated
	}
	previousPhase := cap.currentPhase
	cap.currentPhase = phase
	defer func() { cap.currentPhase = previousPhase }()
	data := map[string]any{"params": values, "user": map[string]any{"id": cap.actor.UserID, "group_id": cap.tenant}, "env": cloneCommandStringMap(cap.generation.environment)}
	exec := &appMCPCommandExecution{capability: cap, phase: phase, values: values, responseSchema: responseSchema, budget: cap.budget, results: map[string]any{}, generated: generated}
	ctx := &FlowContext{App: cap.generation.view, Session: &cap.actor, Data: data, Params: map[string]string{}, Tx: cap.tx, command: exec}
	if phase == "apply" {
		if err := exec.snapshotRevokeTargets(declaration.Steps); err != nil {
			return nil, err
		}
	}
	executeSteps(ctx, declaration.Steps)
	if ctx.Error != nil {
		return nil, ctx.Error
	}
	if !ctx.Stopped || exec.responses != 1 || exec.result == nil {
		return nil, errors.New("command phase did not produce exactly one terminal result")
	}
	if err := cap.validateLifetime(); err != nil {
		return nil, err
	}
	return cloneCommandObject(exec.result)
}

func (cap *appMCPCommandCapability) validateLifetime() error {
	if cap == nil || cap.closed || cap.ctx == nil || cap.conn == nil || cap.tx == nil || cap.lease == nil || cap.generation == nil || cap.app == nil || cap.command == nil {
		return errors.New("command capability is unavailable")
	}
	if err := cap.ctx.Err(); err != nil {
		return err
	}
	if !appMCPGenerationCurrent(cap.app, cap.generation) || cap.generation.origin != cap.app {
		return errors.New("command source generation changed")
	}
	if err := validateAuthorityLockPath(cap.lease.root, cap.lease.file); err != nil {
		return err
	}
	state, err := cap.lease.read()
	if err != nil || state.App != cap.lease.key || state.Epoch != cap.epoch || state.ApprovedWrites == nil || !*state.ApprovedWrites || state.ApprovedWriteEpoch != cap.writeEpoch {
		if err == nil {
			err = errors.New("command owner/write epoch changed")
		}
		return err
	}
	if !cap.readOnlyStatus && cap.tool != nil && cap.tool.Transfer != nil && cap.tool.Transfer.Kind == "push" && (!state.ExternalExport || state.ExternalExportEpoch != cap.exportEpoch || cap.exportEpoch == "") {
		return errors.New("command external export authority changed")
	}
	if cap.enrollment == nil || cap.enrollment.tx != cap.tx || cap.enrollment.generation != cap.generation || cap.enrollment.lease != cap.lease {
		return errors.New("command enrollment capability is stale")
	}
	if err := cap.withInternalRead(func() error {
		if err := cap.reverifyOrigin(); err != nil {
			return err
		}
		_, err := reverifyAppMCPRevisionCapability(cap.enrollment)
		return err
	}); err != nil {
		return err
	}
	return nil
}

// withFullSourceVerificationPhase fingerprints the complete on-disk source at
// phase entry and exit. During the phase, validateLifetime still rechecks the
// owner, grant, database, schema, trigger, and enrollment boundaries but skips
// repeating the same filesystem walk for each SQL statement. The scoped flag
// is restored on every return and panic.
func (cap *appMCPCommandCapability) withFullSourceVerificationPhase(run func() error) (err error) {
	if cap == nil || run == nil {
		return errors.New("source verification phase is unavailable")
	}
	if err := cap.validateLifetimeWithSource(); err != nil {
		return err
	}
	previous := cap.sourceVerificationScope
	cap.sourceVerificationScope = true
	defer func() { cap.sourceVerificationScope = previous }()

	phaseErr := run()
	cap.sourceVerificationScope = false
	verifyErr := cap.validateLifetime()
	cap.sourceVerificationScope = previous
	return errors.Join(phaseErr, verifyErr)
}

func (cap *appMCPCommandCapability) validateLifetimeWithSource() error {
	if cap == nil {
		return errors.New("command capability is unavailable")
	}
	previous := cap.sourceVerificationScope
	cap.sourceVerificationScope = false
	defer func() { cap.sourceVerificationScope = previous }()
	return cap.validateLifetime()
}

func (cap *appMCPCommandCapability) reverifyOrigin() error {
	if cap == nil || cap.tx == nil || cap.generation == nil || cap.tool == nil {
		return errors.New("command origin is unavailable")
	}
	var actor Session
	var tenant, actorCreated string
	switch cap.origin {
	case appMCPCommandConnectorOrigin:
		if cap.originPin == nil {
			return errAppMCPGrantDenied
		}
		verifySource := !cap.sourceVerificationScope
		snapshot, err := appMCPWriteAuthorityForTxMode(cap.ctx, cap.tx, *cap.originPin, time.Now().UTC(), verifySource)
		if err != nil {
			return err
		}
		actor, tenant, actorCreated = snapshot.Actor, snapshot.Tenant, snapshot.UserCreated
	case appMCPCommandSessionOrigin:
		var err error
		actor, tenant, actorCreated, err = appMCPCommandSessionAuthority(cap.ctx, cap.generation, cap.tx, cap.sessionID, cap.tool)
		if err != nil {
			return err
		}
	default:
		return errAppMCPGrantDenied
	}
	if actor.UserID != cap.actor.UserID || actor.Email != cap.actor.Email || actorCreated != cap.actorCreated || tenant != cap.tenant ||
		actor.Scopes != cap.actor.Scopes || actor.Role != cap.actor.Role || !sameStrings(actor.Roles, cap.actor.Roles) || actor.GlobalAdmin != cap.actor.GlobalAdmin {
		return errors.New("command native authority changed during the borrowed transaction")
	}
	return nil
}

func (cap *appMCPCommandCapability) withInternalRead(check func() error) error {
	if cap == nil || check == nil {
		return errors.New("command internal verification is unavailable")
	}
	if cap.guard != nil {
		wasInternal := cap.guard.swapInternal(true)
		defer cap.guard.swapInternal(wasInternal)
	}
	err := check()
	return err
}

func (cap *appMCPCommandCapability) prepare(intent map[string]any) (*appMCPCommandPrepared, error) {
	var prepared *appMCPCommandPrepared
	err := cap.withFullSourceVerificationPhase(func() error {
		var err error
		prepared, err = cap.prepareWithinSourcePhase(intent)
		return err
	})
	return prepared, err
}

func (cap *appMCPCommandCapability) prepareWithinSourcePhase(intent map[string]any) (*appMCPCommandPrepared, error) {
	if err := cap.validateLifetime(); err != nil {
		return nil, err
	}
	canonicalIntent, err := cloneCommandObject(intent)
	if err != nil || validateAppMCPSchemaValue(cap.tool.InputSchema, canonicalIntent) != nil {
		return nil, appMCPResultFailure("invalid_input")
	}
	inputBytes, err := json.Marshal(canonicalIntent)
	if err != nil || len(inputBytes) > appMCPInputLimit {
		return nil, appMCPResultFailure("invalid_input")
	}
	dependencies, err := appMCPCaptureCommandDependencies(cap, canonicalIntent)
	if err != nil {
		return nil, err
	}
	cap.dependencies = dependencies
	prepareResult, err := appMCPRunCommandPhase(cap, "prepare", canonicalIntent)
	if err != nil {
		return nil, err
	}
	args, ok := prepareResult["arguments"].(map[string]any)
	if !ok || validateAppMCPSchemaValue(cap.command.PreparedSchema, args) != nil {
		return nil, appMCPResultFailure("incomplete_result")
	}
	argsBytes, err := json.Marshal(args)
	if err != nil || len(argsBytes) > appMCPInputLimit {
		return nil, appMCPResultFailure("incomplete_result")
	}
	preview, ok := prepareResult["preview"].(map[string]any)
	if !ok || validateAppMCPSchemaValue(cap.command.PreviewSchema, preview) != nil {
		return nil, appMCPResultFailure("incomplete_result")
	}
	args, err = cloneCommandObject(args)
	if err != nil {
		return nil, err
	}
	preview, err = cloneCommandObject(preview)
	if err != nil {
		return nil, err
	}
	if cap.tool.Transfer != nil {
		if err := appMCPAddTransferPreview(cap, canonicalIntent, preview); err != nil {
			return nil, err
		}
	}
	return &appMCPCommandPrepared{ToolName: cap.tool.Name, ContractDigest: cap.generation.manifest.ContractDigest,
		ExecutionDigest: cap.generation.manifest.ExecutionDigest, OwnerEpoch: dependencies.OwnerEpoch,
		WriteEpoch: cap.writeEpoch, EnrollmentID: dependencies.EnrollmentID, ActorUserID: cap.actor.UserID, ActorEmail: cap.actor.Email,
		ActorCreated: cap.actorCreated, Tenant: cap.tenant, Origin: cap.origin, Intent: canonicalIntent,
		Arguments: args, Preview: preview, Dependencies: cloneAppMCPCommandDependencySnapshot(dependencies)}, nil
}

func (cap *appMCPCommandCapability) apply(prepared *appMCPCommandPrepared) (map[string]any, map[string]any, error) {
	if err := cap.validateLifetime(); err != nil {
		return nil, nil, err
	}
	if prepared == nil || prepared.ToolName != cap.tool.Name || prepared.ContractDigest != cap.generation.manifest.ContractDigest ||
		prepared.ExecutionDigest != cap.generation.manifest.ExecutionDigest || prepared.OwnerEpoch != cap.enrollment.record.OwnerEpoch ||
		prepared.WriteEpoch != cap.writeEpoch || prepared.EnrollmentID != cap.enrollment.record.EnrollmentID ||
		prepared.ActorUserID != cap.actor.UserID || prepared.ActorEmail != cap.actor.Email || prepared.ActorCreated != cap.actorCreated || prepared.Tenant != cap.tenant || prepared.Origin != cap.origin ||
		prepared.Dependencies == nil || prepared.Intent == nil {
		return nil, nil, errors.New("prepared command does not match the current source and owner")
	}
	if err := appMCPCompareCommandDependencies(cap, prepared.Intent, prepared.Dependencies); err != nil {
		return nil, nil, err
	}
	if cap.tool.Transfer != nil && cap.tool.Transfer.Kind == "pull" {
		if err := appMCPValidateTransferTargetSnapshot(cap, prepared); err != nil {
			return nil, nil, err
		}
	}
	arguments, err := cloneCommandObject(prepared.Arguments)
	if err != nil || validateAppMCPSchemaValue(cap.command.PreparedSchema, arguments) != nil {
		return nil, nil, appMCPResultFailure("invalid_input")
	}
	argumentsBytes, err := json.Marshal(arguments)
	if err != nil || len(argumentsBytes) > appMCPInputLimit {
		return nil, nil, appMCPResultFailure("invalid_input")
	}
	if err := appMCPCommandEffectsSupported(cap); err != nil {
		return nil, nil, err
	}
	var result map[string]any
	err = cap.withFullSourceVerificationPhase(func() error {
		var phaseErr error
		result, phaseErr = appMCPRunCommandPhase(cap, "apply", arguments)
		return phaseErr
	})
	if err != nil {
		return nil, nil, err
	}
	if len(result) != 1 || result["ok"] != true {
		return nil, nil, appMCPResultFailure("incomplete_result")
	}
	var readback map[string]any
	err = cap.withFullSourceVerificationPhase(func() error {
		var phaseErr error
		readback, phaseErr = appMCPRunCommandPhase(cap, "readback", arguments)
		return phaseErr
	})
	if err != nil {
		return nil, nil, err
	}
	readback, err = appMCPProjectCommandResult(cap.tool, readback)
	if err != nil || validateAppMCPSchemaValue(cap.tool.OutputSchema, readback) != nil {
		return nil, nil, appMCPResultFailure("incomplete_result")
	}
	if cap.tool.Transfer != nil {
		if err := cap.withNativeMetadata(appMCPCommandMetadataHookWrite, func() error { return appMCPQueueTransfer(cap, prepared) }); err != nil {
			return nil, nil, err
		}
	}
	return result, readback, nil
}

func appMCPCommandEffectsSupported(cap *appMCPCommandCapability) error {
	if cap == nil || cap.generation == nil || cap.tx == nil {
		return errors.New("command effect policy is unavailable")
	}
	writes := appMCPCommandApplyWrites(cap.command)
	for authored, actions := range writes {
		table := authored
		if physical, ok := cap.physicalTable(authored); ok {
			table = physical
		}
		// SQL hooks run in the command transaction and every other action is a
		// durable job queued in it (app_mcp_command_hooks.go, ..._effects.go).
		for action := range actions {
			if _, hooked := appMCPHookKey(cap.generation.hooks, table, action); hooked {
				if err := appMCPCommandHookEffectsSupported(cap, table, action); err != nil {
					return err
				}
			}
		}
	}
	// Matching webhook subscriptions are queued as durable jobs in this
	// transaction (executeHookedWrite); the read stays so a missing table fails
	// closed rather than reading as "no subscriptions".
	subscriptions, err := cap.webhookSubscriptions()
	if err != nil {
		return fmt.Errorf("check command webhook effects: %w", err)
	}
	cap.subscriptions = subscriptions
	return nil
}

func mustCommandWriteTargets(query string) []sqlWrite {
	writes, _ := sqlWriteTargets(query)
	return writes
}

func appMCPProjectCommandResult(tool *AppMCPTool, value map[string]any) (map[string]any, error) {
	if tool == nil || value == nil || len(tool.Output.Include) == 0 {
		return nil, errors.New("command readback projection is unavailable")
	}
	projected := make(map[string]any, len(tool.Output.Include))
	for _, field := range tool.Output.Include {
		item, ok := value[field]
		if !ok || !isValidColumnName(field) {
			return nil, errors.New("command readback omitted a projected field")
		}
		projected[field] = item
	}
	for field := range value {
		if !slices.Contains(tool.Output.Include, field) {
			return nil, errors.New("command readback included an unprojected field")
		}
	}
	return projected, nil
}

func cloneCommandObject(value map[string]any) (map[string]any, error) {
	if value == nil {
		return nil, errors.New("command object is unavailable")
	}
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > appMCPResultLimit {
		return nil, errors.New("command value exceeds its bounded JSON representation")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var clone map[string]any
	if err := decoder.Decode(&clone); err != nil || clone == nil {
		return nil, errors.New("command value is not a JSON object")
	}
	return clone, nil
}

func cloneCommandStringMap(values map[string]string) map[string]any {
	copy := make(map[string]any, len(values))
	for name, value := range values {
		copy[name] = value
	}
	return copy
}

func appMCPFindCommandDeclaration(generation *appMCPRuntimeGeneration, name string) (*AppMCPTool, *Flow, error) {
	if generation == nil || generation.manifest == nil || generation.view == nil || name == "" {
		return nil, nil, errors.New("captured command declaration is unavailable")
	}
	var tool *AppMCPTool
	for i := range generation.manifest.Tools {
		candidate := &generation.manifest.Tools[i]
		if candidate.Name == name {
			if tool != nil {
				return nil, nil, errors.New("duplicate captured command binding")
			}
			tool = candidate
		}
	}
	if tool == nil || tool.Effect != "write" || tool.Handler.Kind != "flow" || tool.Handler.Operation != "command" || tool.Handler.Flow == "" {
		// A pending operation whose tool a reload removed is a refusal, not an infrastructure fault.
		return nil, nil, fmt.Errorf("%w: named command is not an admitted source declaration", errAppMCPOperationDenied)
	}
	var flow *Flow
	for i := range generation.flows {
		candidate := &generation.flows[i]
		if candidate.Name == tool.Handler.Flow {
			if flow != nil {
				return nil, nil, errors.New("duplicate captured command flow")
			}
			flow = candidate
		}
	}
	if flow == nil || flow.Command == nil || flow.Trigger.Type != "command" || flow.Source != "flows/"+flow.Name+".yaml" || flow.sourceHash == "" {
		return nil, nil, errors.New("command flow is not part of the captured source generation")
	}
	data, ok := generation.sourceFiles[flow.Source]
	if !ok || hashBytesSHA256(data) != flow.sourceHash || !appMCPName.MatchString(flow.Name) || flow.Name != tool.Handler.Flow {
		return nil, nil, errors.New("command flow source identity is stale")
	}
	if err := validateAppMCPCommandDeclaration(tool, flow.Command); err != nil {
		return nil, nil, err
	}
	if err := appMCPCommandHooksCompatible(generation, flow.Command); err != nil {
		return nil, nil, err
	}
	tables := make(map[string]bool, len(generation.view.Tables))
	for _, table := range generation.view.Tables {
		tables[table.Name] = true
	}
	if err := validateAppMCPCommandDescriptor(*tool, flow.Command, generation.manifest.sourceHashes, tables, generation.view.Roles); err != nil {
		return nil, nil, err
	}
	return tool, flow, nil
}

func appMCPCommandDependencyTables(command *FlowCommand) []string {
	if command == nil {
		return nil
	}
	seen := make(map[string]bool, len(command.Dependencies))
	var tables []string
	for _, dependency := range command.Dependencies {
		if dependency.Table != "" && !seen[dependency.Table] {
			seen[dependency.Table] = true
			tables = append(tables, dependency.Table)
		}
	}
	return tables
}

func appMCPCommandFlowByName(generation *appMCPRuntimeGeneration, name string) *Flow {
	if generation == nil || name == "" {
		return nil
	}
	var match *Flow
	for i := range generation.flows {
		flow := &generation.flows[i]
		if flow.Name == name && flow.Trigger.Type == "command" && flow.Command != nil {
			if match != nil {
				return nil
			}
			match = flow
		}
	}
	return match
}

func appMCPCommandReadTables(command *FlowCommand, phase string) []string {
	if command == nil {
		return nil
	}
	var selected FlowCommandPhase
	switch phase {
	case "prepare":
		selected = command.Prepare
	case "apply":
		selected = command.Apply
	case "readback":
		selected = command.Readback
	default:
		return nil
	}
	return append([]string(nil), selected.ReadTables...)
}

func (cap *appMCPCommandCapability) effectTables() []string {
	if cap == nil || cap.enrollment == nil || cap.enrollment.record == nil {
		return nil
	}
	return append([]string(nil), cap.enrollment.record.TableNames...)
}

func validateAppMCPCommandDeclaration(tool *AppMCPTool, command *FlowCommand) error {
	if tool == nil || command == nil || command.Version != 1 || command.PreparedSchema == nil || command.PreviewSchema == nil || len(command.Writes) == 0 ||
		len(command.Prepare.Steps) == 0 || len(command.Apply.Steps) == 0 || len(command.Readback.Steps) == 0 {
		return errors.New("captured command contract is incomplete")
	}
	for _, schema := range []*AppMCPSchema{tool.InputSchema, tool.OutputSchema, command.PreparedSchema, command.PreviewSchema} {
		if schema == nil || schema.Type != "object" || validateAppMCPSchema(schema, 0) != nil || validateBoundedUpdateSchema(schema, 0) != nil {
			return errors.New("captured command schema is not closed and bounded")
		}
	}
	if command.Request != nil || tool.Approval != "first_party" && tool.Approval != "grant" || tool.Approval == "grant" && tool.Transfer != nil || tool.Idempotency != "operation" || tool.Reconciliation != "authoritative_readback" {
		return errors.New("publicly dispatchable command contract is unsupported")
	}
	return nil
}

func appMCPCommandPrepareResponseSchema(command *FlowCommand) *AppMCPSchema {
	if command == nil {
		return nil
	}
	return &AppMCPSchema{Type: "object", Properties: map[string]*AppMCPSchema{"arguments": command.PreparedSchema, "preview": command.PreviewSchema}, Required: []string{"arguments", "preview"}, AdditionalProperties: commandBoolPtr(false)}
}

func appMCPCommandApplyResponseSchema() *AppMCPSchema {
	return &AppMCPSchema{Type: "object", Properties: map[string]*AppMCPSchema{"ok": {Type: "boolean"}}, Required: []string{"ok"}, AdditionalProperties: commandBoolPtr(false)}
}

func commandBoolPtr(value bool) *bool { return &value }

// appMCPCommandTimeout bounds one coordinator call; a running attempt older
// than this (plus grace) is reported unknown.
const appMCPCommandTimeout = 30 * time.Second

func appMCPCommandDeadline(ctx context.Context) (context.Context, context.CancelFunc) {
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) <= appMCPCommandTimeout {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, appMCPCommandTimeout)
}

func appMCPCommandScopes(actor Session, tool *AppMCPTool) error {
	if tool == nil || len(tool.Permissions) == 0 || !scopesWithin(actor.Scopes, strings.Join(tool.Permissions, " ")) {
		return errAppMCPGrantDenied
	}
	return nil
}
