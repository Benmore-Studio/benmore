//go:build !cli

package main

// Exposure of approved command writes (B2).
//
// Connector surface (/api/_mcp, per request, only while the owner approved-
// writes switch is live and both the grant and the current role carry the
// declared permissions):
//   - <command tool> prepares: persists an immutable operation and returns
//     {operation_id, preview, expires_at, review_url}. It never writes
//     business data and never approves.
//   - _commit {operation_id} applies an operation its intended person already
//     approved; a replay returns the stored receipt and never re-applies. It runs
//     in three transactions: claim (a durable `running` attempt, before any side
//     effect), apply (the business transaction, receipt included) and record
//     (the attempt's terminal state and, for a non-success, its audit row, outside
//     any rollback).
//   - _status {operation_id} reads the durable state of one operation: prepared,
//     approved, running, succeeded, failed, conflict, unknown or expired.
// The framework tools start with "_", which the manifest name grammar forbids
// for app tools, so they cannot collide. There is no approve tool.
//
// First-party browser surface (reserved /api/_mcp/operations/ namespace):
//   - GET  {id}          review page with the exact preview
//   - POST {id}/approve  approval; session-bound CSRF, same user as the preparer
// Every durable write goes through appMCPWithCommandOutcome, the sole commit
// point, except the attempt's terminal record (appMCPFinishAttempt): it must
// survive the rollback of the business transaction, so it runs after it.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	sqlite3 "github.com/mattn/go-sqlite3"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	appMCPCommitTool        = "_commit"
	appMCPStatusTool        = "_status"
	appMCPOperationRoute    = "/api/_mcp/operations/"
	appMCPDisclosureVersion = "benmore:mcp:disclosure:v2"
)

var (
	errAppMCPOperationNotApproved = errors.New("operation is not approved")
	errAppMCPOperationExpired     = errors.New("operation is expired")
	errAppMCPOperationDenied      = errors.New("operation is unavailable to this caller")
	errAppMCPOperationApproved    = errors.New("operation is already approved")
	errAppMCPOperationLimit       = errors.New("too many open operations")
)

const (
	appMCPOperationActorLimit = 20 // live, unexpired, unfinished operations per actor
	appMCPOperationSweepGrace = time.Hour
	appMCPOperationSweepBatch = 100
)

// appMCPCommandErrorClass separates authorization outcomes (expected, never
// logged) from infrastructure failures, which are logged and reported as
// unavailable_provider so an operator can tell a broken store from a refusal.
type appMCPCommandRowCountConflictError struct{ message string }

func (e *appMCPCommandRowCountConflictError) Error() string {
	if e.message != "" {
		return e.message
	}
	return "command SQL row-count assertion failed"
}

func appMCPCommandRowCountConflictOnly(err error) bool {
	if err == nil {
		return false
	}
	pending := []error{err}
	found := false
	for visited := 0; len(pending) > 0; visited++ {
		if visited == 256 {
			return false
		}
		current := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if current == nil {
			continue
		}
		if _, ok := current.(*appMCPCommandRowCountConflictError); ok {
			found = true
			continue
		}
		if joined, ok := current.(interface{ Unwrap() []error }); ok {
			children := joined.Unwrap()
			if len(children) == 0 {
				return false
			}
			pending = append(pending, children...)
			continue
		}
		if wrapped, ok := current.(interface{ Unwrap() error }); ok {
			child := wrapped.Unwrap()
			if child == nil {
				return false
			}
			pending = append(pending, child)
			continue
		}
		return false
	}
	return found
}

func appMCPCommandErrorClass(err error) string {
	var unknown *appMCPCommandOutcomeUnknownError
	var failure *appMCPResultError
	var hook *appMCPCommandHookError
	var refusal *appMCPCommandRefusal
	switch {
	case errors.As(err, &refusal):
		return refusal.Code
	case errors.As(err, &hook):
		return "hook_refused"
	case errors.As(err, &unknown):
		return "unknown_execution"
	case appMCPCommandRowCountConflictOnly(err):
		return "conflict"
	case errors.Is(err, errAppMCPOperationExpired):
		return "expired_intent"
	case errors.Is(err, errAppMCPOperationNotApproved):
		return "approval_required"
	case errors.Is(err, errAppMCPOperationApproved):
		return "already_approved"
	case errors.Is(err, errAppMCPOperationLimit):
		return "operation_limit"
	case errors.Is(err, errAppMCPOperationInProgress):
		return "in_progress"
	case errors.Is(err, errAppMCPOperationDenied), errors.Is(err, errAppMCPGrantDenied):
		return "denied"
	case errors.As(err, &failure):
		return failure.Code
	}
	return "unavailable_provider"
}

// appMCPCommandRefusal is a prepare phase that refused the request with the
// author's literal message (a `respond` with a 4xx status, see
// commandRefusalStatus). Code is one of the stable codes; Message was checked
// at compile and again at run time to be bounded printable text with no
// template, so it is safe to hand to the client.
type appMCPCommandRefusal struct{ Code, Message string }

func (e *appMCPCommandRefusal) Error() string { return "command refused: " + e.Message }

// appMCPLogCommandError logs every non-authorization error with the tool, the
// operation id prefix and the class, and returns the class.
func appMCPLogCommandError(tool, id string, err error) string {
	class := appMCPCommandErrorClass(err)
	switch class {
	case "unavailable_provider", "unknown_execution", "incomplete_result":
		if len(id) > 8 {
			id = id[:8]
		}
		log.Printf("mcp-command: tool=%s op=%s class=%s err=%v", tool, id, class, err)
	case "hook_refused":
		if len(id) > 8 {
			id = id[:8]
		}
		var hook *appMCPCommandHookError
		errors.As(err, &hook)
		log.Printf("mcp-command: tool=%s op=%s class=%s table=%s action=%s refused=%t err=%v", tool, id, class, hook.Table, hook.Action, hook.Refused, hook.cause)
	}
	return class
}

// appMCPCommandOutcomeUnknownError means the outer COMMIT may or may not have
// happened. Callers must reconcile from the durable row via _status.
type appMCPCommandOutcomeUnknownError struct{ cause error }

func (e *appMCPCommandOutcomeUnknownError) Error() string { return "command outcome is unknown" }
func (e *appMCPCommandOutcomeUnknownError) Unwrap() error { return e.cause }

// appMCPClock is the operation clock (creation, approval, expiry, consumption).
// Tests move it to prove expiry; coordinator deadlines keep the real clock.
var appMCPClock = func() time.Time { return time.Now().UTC() }

// appMCPWritesLive reads the owner switch; anything unreadable is off.
func appMCPWritesLive(app *App) (*appMCPEpochState, bool) {
	if app == nil {
		return nil, false
	}
	state, err := currentAppMCPEpoch(app.Dir)
	if err != nil || !state.Exposed || state.Version != 2 || state.ApprovedWrites == nil || !*state.ApprovedWrites || state.ApprovedWriteEpoch == "" {
		return nil, false
	}
	return state, true
}

type appMCPLiveCommand struct {
	tool *AppMCPTool
	flow *Flow
}

// appMCPLiveCommands returns the admitted command bindings while writes are
// live. The coordinator re-verifies enrollment and authority on every call.
func appMCPLiveCommands(app *App, generation *appMCPRuntimeGeneration) []appMCPLiveCommand {
	if generation == nil || generation.manifest == nil || generation.origin != app {
		return nil
	}
	if _, live := appMCPWritesLive(app); !live {
		return nil
	}
	var out []appMCPLiveCommand
	for i := range generation.manifest.Tools {
		if generation.manifest.Tools[i].Handler.Operation != "command" {
			continue
		}
		name := generation.manifest.Tools[i].Name
		tool, flow, err := appMCPFindCommandDeclaration(generation, name)
		if err != nil {
			if generation.reportedUnlive == nil {
				log.Printf("mcp-command: declaration %q is not live: %v", name, err)
			} else if _, reported := generation.reportedUnlive.LoadOrStore(name, true); !reported {
				log.Printf("mcp-command: declaration %q is not live: %v", name, err)
			}
			continue
		}
		out = append(out, appMCPLiveCommand{tool: tool, flow: flow})
	}
	return out
}

// appMCPLiveScopes is the connector scope set: reviewed read permissions, plus
// admitted command permissions only while writes are live. With writes off it
// equals appMCPSupportedScopes exactly, so no write scope is advertised or
// grantable.
func appMCPLiveScopes(app *App, manifest *AppMCPManifest, generation *appMCPRuntimeGeneration) string {
	read := appMCPSupportedScopes(manifest)
	if manifest == nil || generation == nil || generation.manifest != manifest {
		return read
	}
	commands := appMCPLiveCommands(app, generation)
	if len(commands) == 0 {
		return read
	}
	known := map[string]bool{}
	if read != "_none_:read" {
		for _, scope := range strings.Fields(read) {
			known[scope] = true
		}
	}
	for _, command := range commands {
		for _, scope := range command.tool.Permissions {
			known[scope] = true
		}
	}
	values := make([]string, 0, len(known))
	for scope := range known {
		values = append(values, scope)
	}
	sort.Strings(values)
	return strings.Join(values, " ")
}

// appMCPConnectorOrigin builds evidence from the grant the transport already
// resolved. The coordinator re-verifies credential, grant, account, role and
// both epochs in its own transaction; permissions come from the declaration.
func appMCPConnectorOrigin(app *App, generation *appMCPRuntimeGeneration, grant *appMCPGrant, tool *AppMCPTool, raw, resource string) (appMCPCommandOrigin, error) {
	state, live := appMCPWritesLive(app)
	hash, err := appMCPCredentialHash(raw, "access")
	if !live || err != nil || grant == nil || tool == nil {
		return appMCPCommandOrigin{}, denyAppMCPWriteAuthority(errors.New("owner approved writes are off or the grant is unavailable"))
	}
	if tool.Transfer != nil && tool.Transfer.Kind == "push" && (!state.ExternalExport || state.ExternalExportEpoch == "") {
		return appMCPCommandOrigin{}, denyAppMCPWriteAuthority(errors.New("external export is disabled"))
	}
	return appMCPCommandOrigin{kind: appMCPCommandConnectorOrigin, connector: &appMCPWriteAuthorityPin{
		Origin: app, Generation: generation, CredentialHash: hash, GrantID: grant.ID, AppID: grant.App, Epoch: grant.Epoch,
		WriteEpoch: state.ApprovedWriteEpoch, ExternalExportEpoch: state.ExternalExportEpoch, AutoApproveEpoch: state.AutoApproveEpoch, Resource: resource, Client: grant.Client, Tenant: grant.Tenant,
		UserID: grant.UserID, UserCreated: grant.UserCreated, Permissions: append([]string(nil), tool.Permissions...),
	}}, nil
}

// Status may reconcile an already-approved transfer using GET only. It keeps
// the same live grant and role checks but does not require export to remain on.
func appMCPConnectorStatusOrigin(app *App, generation *appMCPRuntimeGeneration, grant *appMCPGrant, tool *AppMCPTool, raw, resource string) (appMCPCommandOrigin, error) {
	state, live := appMCPWritesLive(app)
	hash, err := appMCPCredentialHash(raw, "access")
	if !live || err != nil || grant == nil || tool == nil {
		return appMCPCommandOrigin{}, denyAppMCPWriteAuthority(errors.New("owner approved writes are off or the grant is unavailable"))
	}
	return appMCPCommandOrigin{kind: appMCPCommandConnectorOrigin, connector: &appMCPWriteAuthorityPin{
		Origin: app, Generation: generation, CredentialHash: hash, GrantID: grant.ID, AppID: grant.App, Epoch: grant.Epoch,
		WriteEpoch: state.ApprovedWriteEpoch, ExternalExportEpoch: state.ExternalExportEpoch, AutoApproveEpoch: state.AutoApproveEpoch, Resource: resource, Client: grant.Client, Tenant: grant.Tenant,
		UserID: grant.UserID, UserCreated: grant.UserCreated, Permissions: append([]string(nil), tool.Permissions...),
	}}, nil
}

// appMCPCanonicalJSON is the sorted-key form the operation store demands.
func appMCPCanonicalJSON(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	decoded, err := appMCPDecodeJSON(raw)
	if err != nil {
		return nil, err
	}
	return json.Marshal(decoded)
}

func appMCPDecodeJSON(raw []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil || decoder.Decode(new(any)) != io.EOF {
		return nil, errors.New("invalid stored JSON")
	}
	return value, nil
}

func appMCPDecodeObject(raw []byte) (map[string]any, error) {
	value, err := appMCPDecodeJSON(raw)
	object, ok := value.(map[string]any)
	if err != nil || !ok {
		return nil, errors.New("stored JSON is not an object")
	}
	return object, nil
}

// appMCPDecodeToolArguments is the shared bounded, exact-number decoder.
func appMCPDecodeToolArguments(args json.RawMessage) (map[string]any, bool) {
	input := map[string]any{}
	if len(args) > appMCPInputLimit || !utf8.Valid(args) {
		return nil, false
	}
	if len(args) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(args))
		decoder.UseNumber()
		if decoder.Decode(&input) != nil || input == nil || decoder.Decode(new(any)) != io.EOF {
			return nil, false
		}
	}
	return input, true
}

func appMCPOperationIDArgument(args json.RawMessage) (string, bool) {
	input, ok := appMCPDecodeToolArguments(args)
	id, _ := input["operation_id"].(string)
	return id, ok && len(input) == 1 && appMCPIsHex(id, 32)
}

// appMCPOperationCommand names the command an operation was prepared for, so
// the coordinator can be started for it. It confers no authority: the same
// operation is re-read and fully bound to the caller inside the coordinator.
func appMCPOperationCommand(ctx context.Context, app *App, id string) (string, error) {
	command, _, err := appMCPOperationCommandOwner(ctx, app, id)
	return command, err
}

// appMCPOperationCommandOwner is appMCPOperationCommand plus the id of the
// user who prepared the operation.
func appMCPOperationCommandOwner(ctx context.Context, app *App, id string) (string, int64, error) {
	tx, err := app.DB.BeginTx(ctx, nil)
	if err != nil {
		return "", 0, err // infrastructure: logged and reported as unavailable
	}
	defer tx.Rollback()
	stored, err := readAppMCPStoredOperation(ctx, tx, app, id)
	if err != nil {
		return "", 0, errAppMCPOperationDenied // unknown id or unreadable row: opaque by design
	}
	return stored.Prepared.Command, stored.Prepared.Origin.ActorID, nil
}

// appMCPReadOperation reads the operation and its approval (nil when none)
// through the native metadata scope, verifying both storage schemas first.
func appMCPReadOperation(cap *appMCPCommandCapability, id string) (stored *appMCPStoredOperation, approval *appMCPCommandApprovalState, err error) {
	err = cap.withNativeMetadata(appMCPCommandMetadataRead, func() error {
		appID, key, err := appMCPReadyOperationStorage(cap.ctx, cap.tx, cap.app)
		if err != nil {
			return err
		}
		if _, err := verifyAppMCPCommandStorageWithKey(cap.ctx, cap.tx, appID, key); err != nil {
			return err
		}
		if stored, err = appMCPReadOperationWithKey(cap.ctx, cap.tx, appID, key, id); err != nil {
			return errAppMCPOperationDenied
		}
		approval, err = appMCPReadCommandApprovalWithKey(cap.ctx, cap.tx, appID, key, stored)
		return err
	})
	return stored, approval, err
}

// appMCPBindOperation proves the caller is the person and connection that
// prepared the operation, on the same source and tenant. Stale epochs are
// reported separately (expired), never as a binding success.
func appMCPBindOperation(cap *appMCPCommandCapability, stored *appMCPStoredOperation) error {
	p := stored.Prepared
	if p.Command != cap.tool.Name || p.Origin.Kind != "connector" ||
		p.Origin.ActorID != cap.actor.UserID || p.Origin.ActorCreated != cap.actorCreated || p.Origin.Tenant != cap.tenant {
		return errAppMCPOperationDenied
	}
	if cap.origin == appMCPCommandConnectorOrigin {
		if cap.originPin == nil || !SecureCompare(p.Origin.GrantID, cap.originPin.GrantID) || p.Origin.Client != cap.originPin.Client {
			return errAppMCPOperationDenied
		}
	}
	return nil
}

// appMCPBindSource additionally pins the operation to the live reviewed source.
// Only an unfinished operation needs it. A receipt replay or a status read
// skips this digest check, but still runs inside the coordinator, which needs
// the current generation, revision enrollment and command declaration: they
// survive a source change only while those remain current, not a removal.
func appMCPBindSource(cap *appMCPCommandCapability, stored *appMCPStoredOperation) error {
	p := stored.Prepared
	if p.DisclosureVersion != appMCPDisclosureVersion ||
		!SecureCompare(p.ContractDigest, cap.generation.manifest.ContractDigest) || !SecureCompare(p.ExecutionDigest, cap.generation.manifest.ExecutionDigest) {
		return errAppMCPOperationDenied
	}
	// ${{ user.role }} / ${{ user.is_admin }} are read live at each phase, so a
	// role change after prepare would run SQL the approved preview never showed.
	if p.Origin.ActorRole != "" && (p.Origin.ActorRole != cap.actor.Role || p.Origin.ActorAdmin != cap.actor.IsAdmin()) {
		return errAppMCPOperationDenied
	}
	return nil
}

// appMCPApproverSessionLive proves the approving browser session still exists,
// is unexpired and is still a direct unscoped non-impersonated non-act-as
// login of the approver, so revoking that session kills its approval.
// A database failure is returned, never folded into "not live".
func appMCPApproverSessionLive(cap *appMCPCommandCapability, sessionID string, userID int64) (bool, error) {
	var one int
	err := cap.tx.QueryRowContext(cap.ctx, `SELECT 1 FROM main._benmore_sessions WHERE id=? AND user_id=? AND datetime(expires_at) > datetime('now')
		AND COALESCE(is_impersonation,0)=0 AND COALESCE(acting_as_group,'')='' AND COALESCE(scopes,'') IN ('','*')`, sessionID, userID).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// appMCPAutoApproveEligible is whether this connector call may stand in for a
// browser approval: the current declaration says approval: grant, the owner
// switch is on with the epoch the call was admitted under and the grant was
// consented under (autoApproveLive), and the grant's consented list names the
// tool at the current manifest contract digest. All four come from this transaction. A
// transfer tool is never eligible, whatever its declaration says.
func appMCPAutoApproveEligible(cap *appMCPCommandCapability) bool {
	return cap.origin == appMCPCommandConnectorOrigin && cap.originPin != nil && appMCPOperationHex(cap.originPin.AutoApproveEpoch, 32) &&
		cap.tool != nil && cap.tool.Approval == "grant" && cap.tool.Transfer == nil && cap.autoApproveLive &&
		cap.generation != nil && cap.generation.manifest != nil && cap.generation.manifest.ContractDigest != "" &&
		slices.ContainsFunc(cap.autoApproveTools, func(entry string) bool {
			return SecureCompare(entry, appMCPAutoApproveEntry(cap.tool.Name, cap.generation.manifest.ContractDigest, cap.generation.manifest.ExecutionDigest))
		})
}

// appMCPGrantApprovalLive re-checks a grant-domain approval at commit: it must
// be this grant's consent under the current auto-approve epoch, and the call
// must still be eligible. Revoking the grant, turning auto-approval or writes
// off, re-enabling it (new epoch), a manifest change back to first_party or a
// role downgrade therefore stops even a retried _commit; the coordinator has
// already re-verified grant, credential, account and roles∩scopes.
func appMCPGrantApprovalLive(cap *appMCPCommandCapability, approval *appMCPCommandApprovalState) bool {
	record := approval.Approval
	return appMCPAutoApproveEligible(cap) && record.Basis == appMCPGrantConsentBasis+cap.originPin.GrantID &&
		SecureCompare(record.AutoApproveEpoch, cap.originPin.AutoApproveEpoch)
}

func appMCPOperationExpired(cap *appMCPCommandCapability, stored *appMCPStoredOperation, now time.Time) bool {
	p := stored.Prepared
	if now.Unix() >= p.ExpiresAt || !SecureCompare(p.RuntimeAuthority.OwnerEpoch, cap.epoch) || !SecureCompare(p.RuntimeAuthority.WriteEpoch, cap.writeEpoch) {
		return true
	}
	if cap.tool.Transfer != nil && cap.tool.Transfer.Kind == "push" {
		return p.RuntimeAuthority.ExternalExportEpoch == "" || !SecureCompare(p.RuntimeAuthority.ExternalExportEpoch, cap.exportEpoch)
	}
	return false
}

// appMCPOperationState is derived only from durable rows and the clock; business
// is committed (receipt), not_committed, or undetermined (running or unknown). The
// receipt wins over everything; an expired operation can no longer be retried
// whatever its last attempt did; otherwise the latest attempt decides (a stale
// running attempt reads as unknown, see appMCPAttemptState).
func appMCPOperationState(cap *appMCPCommandCapability, stored *appMCPStoredOperation, approval *appMCPCommandApprovalState, attempts []appMCPAttempt, now time.Time) (state, business string) {
	switch latest := appMCPLatestAttempt(attempts); {
	case stored.Receipt != nil:
		return "succeeded", "committed"
	case appMCPOperationExpired(cap, stored, now):
		return "expired", "not_committed"
	case latest != nil:
		state = appMCPAttemptState(latest, now, false)
		if state == appMCPAttemptRunning || state == appMCPAttemptUnknown {
			return state, "undetermined" // the business transaction may still be in flight, or its outcome is unknown
		}
		return state, "not_committed"
	case approval != nil:
		return "approved", "not_committed"
	}
	return "prepared", "not_committed"
}

// appMCPAttemptRetryable is whether _commit may claim another attempt after the
// latest one: after failed or conflict, or after a stale running claim (reported
// unknown) that a retry supersedes; never after an unknown COMMIT outcome.
func appMCPAttemptRetryable(state string, latest *appMCPAttempt, attempts int, now time.Time) bool {
	if latest == nil || attempts >= appMCPOperationAttemptLimit {
		return false
	}
	return state == appMCPAttemptFailed || state == appMCPAttemptConflict || state == appMCPAttemptUnknown && appMCPAttemptStale(latest, now)
}

// appMCPReadAttempts reads the attempt history of one operation through the
// native metadata scope.
func appMCPReadAttempts(cap *appMCPCommandCapability, id string) (attempts []appMCPAttempt, err error) {
	err = cap.withNativeMetadata(appMCPCommandMetadataRead, func() error {
		appID, key, err := appMCPReadyOperationStorage(cap.ctx, cap.tx, cap.app)
		if err != nil {
			return err
		}
		attempts, err = appMCPReadAttemptsWithKey(cap.ctx, cap.tx, appID, key, id)
		return err
	})
	return attempts, err
}

// appMCPFinishOutcome maps the coordinator result. A confirmed commit is a
// success even if only connection cleanup failed afterwards.
func appMCPFinishOutcome(outcome appMCPCommandTxOutcome, err error) error {
	switch {
	case outcome.State == appMCPCommandCommitConfirmed:
		return nil
	case outcome.State == appMCPCommandCommitUnknown:
		return &appMCPCommandOutcomeUnknownError{cause: err}
	}
	return err
}

func appMCPBarrier(expiresAt *int64) appMCPCommandFinalize {
	return func(*appMCPCommandCapability, time.Time) (appMCPCommandCommitBarrier, error) {
		if expiresAt == nil || *expiresAt == 0 {
			return appMCPCommandCommitBarrier{}, nil
		}
		return appMCPCommandCommitBarrier{ValidUntil: time.Unix(*expiresAt, 0)}, nil
	}
}

func appMCPAudit(cap *appMCPCommandCapability, action, id string, details map[string]any) error {
	encoded, err := json.Marshal(details)
	if err != nil {
		return err
	}
	return cap.withNativeMetadata(appMCPCommandMetadataAudit, func() error {
		return insertAuditRowChecked(cap.tx, action, "_benmore_mcp_operations", id, &cap.actor, "{}", string(encoded))
	})
}

// ---- prepare ---------------------------------------------------------------

type appMCPPreparedView struct {
	ID        string
	Preview   map[string]any
	ExpiresAt int64
	// AutoApproved: a grant-domain approval was stored with the operation.
	AutoApproved bool
	// ApprovalReason says why the call was only prepared (empty when applied).
	ApprovalReason string
}

// appMCPInsertGrantApproval writes the grant-domain approval for an operation
// this connector call just prepared, and its approve audit row.
func appMCPInsertGrantApproval(cap *appMCPCommandCapability, stored *appMCPStoredOperation, now time.Time) error {
	p := stored.Prepared
	if !appMCPAutoApproveEligible(cap) || !SecureCompare(p.Origin.GrantID, cap.originPin.GrantID) {
		return errAppMCPOperationDenied
	}
	approvalID, err := appMCPRandomHex(32)
	if err != nil {
		return err
	}
	epoch := cap.originPin.AutoApproveEpoch
	record := appMCPCommandApprovalRecord{
		Version: 1, Domain: appMCPGrantApprovalDomain, ApprovalID: approvalID, AppID: p.AppID, OperationID: p.OperationID,
		PreparedDigest: stored.PreparedDigest, DisclosureVersion: p.DisclosureVersion,
		OwnerEpoch: p.RuntimeAuthority.OwnerEpoch, WriteEpoch: p.RuntimeAuthority.WriteEpoch,
		ApproverUserID: p.Origin.ActorID, ApproverCreated: p.Origin.ActorCreated, Tenant: p.Origin.Tenant,
		ApprovedAt: now.Unix(), ExpiresAt: p.ExpiresAt,
		ReviewChallengeDigest: appMCPGrantApprovalChallenge(stored.PreparedDigest, p.Origin.GrantID, epoch),
		Basis:                 appMCPGrantConsentBasis + p.Origin.GrantID, AutoApproveEpoch: epoch,
	}
	if err := cap.withNativeMetadata(appMCPCommandMetadataApprove, func() error {
		_, err := insertAppMCPCommandApproval(cap.ctx, cap.tx, cap.app, stored, record)
		return err
	}); err != nil {
		return err
	}
	return appMCPAudit(cap, "mcp_command_approve", p.OperationID, map[string]any{"command": cap.tool.Name, "approval_id": approvalID, "prepared_digest": stored.PreparedDigest, "basis": record.Basis})
}

func appMCPOperationRecordFor(cap *appMCPCommandCapability, prepared *appMCPCommandPrepared, now time.Time) (appMCPPreparedOperationRecord, error) {
	pin := cap.originPin
	if cap.origin != appMCPCommandConnectorOrigin || pin == nil {
		return appMCPPreparedOperationRecord{}, errAppMCPOperationDenied
	}
	id, err := appMCPRandomHex(32)
	if err != nil {
		return appMCPPreparedOperationRecord{}, err
	}
	permissions := append([]string(nil), pin.Permissions...)
	sort.Strings(permissions)
	record := appMCPPreparedOperationRecord{
		Version: 1, OperationID: id, Command: cap.tool.Name, DisclosureVersion: appMCPDisclosureVersion,
		ContractDigest: prepared.ContractDigest, ExecutionDigest: prepared.ExecutionDigest,
		RuntimeAuthority: appMCPOperationRuntimeAuthority{Version: 1, OwnerEpoch: cap.epoch, WriteEpoch: cap.writeEpoch},
		Origin: appMCPOperationOriginRecord{Kind: "connector", ActorID: prepared.ActorUserID, ActorCreated: prepared.ActorCreated, Tenant: prepared.Tenant,
			Permissions: permissions, GrantID: pin.GrantID, Client: pin.Client, Resource: pin.Resource, CredentialHash: pin.CredentialHash,
			ActorRole: cap.actor.Role, ActorAdmin: cap.actor.IsAdmin()},
		CreatedAt: now.Unix(), ExpiresAt: now.Unix() + 15*60, ApprovalReason: appMCPApprovalReason(cap),
	}
	if record.AppID, err = appMCPOperationOwnerID(cap.app.Dir); err != nil {
		return record, err
	}
	if cap.tool.Transfer != nil && cap.tool.Transfer.Kind == "push" {
		if cap.exportEpoch == "" {
			return record, errAppMCPOperationDenied
		}
		record.RuntimeAuthority.ExternalExportEpoch = cap.exportEpoch
	}
	for _, field := range []struct {
		dst   *json.RawMessage
		value any
	}{{&record.Intent, prepared.Intent}, {&record.Arguments, prepared.Arguments}, {&record.Dependencies, prepared.Dependencies}, {&record.Preview, prepared.Preview}} {
		if *field.dst, err = appMCPCanonicalJSON(field.value); err != nil {
			return record, err
		}
	}
	return record, nil
}

// appMCPScanOperations authenticates every unfinished stored operation to count
// the actor's open ones and to pick expired ones to sweep. A finished operation
// (receipt attached) is neither open nor swept, so it is not read: receipts are
// kept forever and must not make every prepare slower under the write lock.
// An unreadable row is logged and skipped, so one bad row cannot block every
// prepare.
// ponytail: O(unfinished operations) decrypt per prepare, bounded by the actor
// cap and the sweep; a plaintext actor/expiry column (a storage migration)
// would make it O(actor).
func appMCPScanOperations(cap *appMCPCommandCapability, actorID int64, now time.Time) (open int, sweep []string, err error) {
	err = cap.withNativeMetadata(appMCPCommandMetadataRead, func() error {
		appID, key, err := appMCPReadyOperationStorage(cap.ctx, cap.tx, cap.app)
		if err != nil {
			return err
		}
		rows, err := cap.tx.QueryContext(cap.ctx, "SELECT operation_id FROM main._benmore_mcp_operations WHERE receipt_digest IS NULL")
		if err != nil {
			return err
		}
		var ids []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				_ = rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			return err
		}
		for _, id := range ids {
			operation, err := appMCPReadOperationWithKey(cap.ctx, cap.tx, appID, key, id)
			if err != nil {
				log.Printf("mcp-command: tool=%s op=%.8s class=unreadable_operation err=%v", cap.tool.Name, id, err)
				continue
			}
			p := operation.Prepared
			switch {
			case operation.Receipt != nil: // finished: kept as the replay receipt
			case now.Unix() >= p.ExpiresAt+int64(appMCPOperationSweepGrace/time.Second):
				if len(sweep) < appMCPOperationSweepBatch {
					sweep = append(sweep, id)
				}
			case now.Unix() < p.ExpiresAt && p.Origin.ActorID == actorID:
				open++
			}
		}
		return nil
	})
	return open, sweep, err
}

// appMCPSweepOperations deletes unfinished operations past expiry plus grace,
// each with its approval row and attempts, through the narrowly scoped Sweep authorizer.
func appMCPSweepOperations(cap *appMCPCommandCapability, ids []string) error {
	return cap.withNativeMetadata(appMCPCommandMetadataSweep, func() error {
		for _, id := range ids {
			if _, err := cap.tx.ExecContext(cap.ctx, "DELETE FROM main._benmore_mcp_command_approvals WHERE operation_id=?", id); err != nil {
				return err
			}
			if _, err := cap.tx.ExecContext(cap.ctx, "DELETE FROM main._benmore_mcp_command_attempts WHERE operation_id=?", id); err != nil {
				return err
			}
			result, err := cap.tx.ExecContext(cap.ctx, "DELETE FROM main._benmore_mcp_operations WHERE operation_id=? AND receipt_digest IS NULL", id)
			if err != nil {
				return err
			}
			if n, err := result.RowsAffected(); err != nil || n != 1 {
				return errors.New("operation sweep removed an unexpected number of rows")
			}
		}
		return nil
	})
}

func appMCPPrepareOperation(ctx context.Context, request appMCPCommandRequest, input map[string]any) (*appMCPPreparedView, error) {
	var view *appMCPPreparedView
	refused := false
	outcome, err := appMCPWithCommandOutcome(ctx, request, func(cap *appMCPCommandCapability) (bool, error) {
		now := appMCPClock()
		open, expired, err := appMCPScanOperations(cap, cap.actor.UserID, now)
		if err != nil {
			return false, err
		}
		if len(expired) > 0 {
			if err := appMCPSweepOperations(cap, expired); err != nil {
				return false, err
			}
			prefixes := make([]string, len(expired))
			for i, id := range expired {
				prefixes[i] = id[:8]
			}
			if err := appMCPAudit(cap, "mcp_command_sweep", "", map[string]any{"deleted": len(expired), "operations": prefixes}); err != nil {
				return false, err
			}
		}
		if open >= appMCPOperationActorLimit {
			refused = true // still commit the sweep
			return true, nil
		}
		prepared, err := cap.prepare(input)
		if err != nil {
			return false, err
		}
		record, err := appMCPOperationRecordFor(cap, prepared, now)
		if err != nil {
			return false, err
		}
		var stored *appMCPStoredOperation
		if err := cap.withNativeMetadata(appMCPCommandMetadataPrepare, func() error {
			stored, err = insertAppMCPPreparedOperation(cap.ctx, cap.tx, cap.app, record)
			return err
		}); err != nil {
			return false, err
		}
		details := map[string]any{"command": cap.tool.Name, "prepared_digest": stored.PreparedDigest}
		if digests := appMCPGeneratedDigests(prepared.Arguments); len(cap.command.Generated) > 0 && len(digests) > 0 {
			details["generated_digests"] = digests // a digest per value, never the value
		}
		if err := appMCPAudit(cap, "mcp_command_prepare", record.OperationID, details); err != nil {
			return false, err
		}
		view = &appMCPPreparedView{ID: record.OperationID, Preview: prepared.Preview, ExpiresAt: record.ExpiresAt, ApprovalReason: record.ApprovalReason}
		if appMCPAutoApproveEligible(cap) {
			// The user's consent on this grant stands in for the browser review.
			// Same transaction as the operation, same only writer; the commit
			// re-checks every condition before anything applies.
			if err := appMCPInsertGrantApproval(cap, stored, now); err != nil {
				return false, err
			}
			view.AutoApproved = true
		}
		return true, nil
	}, appMCPBarrier(nil))
	if err := appMCPFinishOutcome(outcome, err); err != nil {
		return nil, err
	}
	if refused {
		return nil, errAppMCPOperationLimit
	}
	return view, nil
}

// ---- review / approve ------------------------------------------------------

type appMCPReview struct {
	Tool, Description, Preview, State string
	ExpiresAt                         int64
	Effects                           []string
	// Human-facing review text (#770). Title and Summary come from the
	// manifest's title/review_summary, never from the model-facing
	// description; empty means the manifest declares none. Changes is the
	// labelled preview (Before is empty for a create). AutoApprove says why
	// this change was not applied without review, empty when not applicable.
	Title, Summary, AutoApprove string
	Changes                     []appMCPReviewChange
}

// appMCPReviewChange is one labelled argument of a prepared change. Values are
// display text already escaped like appMCPReviewPreviewText.
type appMCPReviewChange struct {
	Label, Before, After string
	Changed              bool
}

// appMCPReviewPreviewText renders the stored preview as indented JSON for the
// review page. A character that renders invisibly or reorders the text around
// it (bidi controls, zero-width and other format characters, variation
// selectors, fillers, control and non-ASCII space characters) is written as
// its JSON \u escape, so a value the assistant chose cannot make the reviewed
// text read as something else. The escaped text decodes to the same JSON:
// outside strings MarshalIndent emits only ASCII.
func appMCPReviewPreviewText(preview map[string]any) (string, error) {
	pretty, err := json.MarshalIndent(preview, "", "  ")
	if err != nil {
		return "", err
	}
	var out strings.Builder
	for _, r := range string(pretty) {
		if r == '\n' || !appMCPHiddenRune(r) {
			out.WriteRune(r)
			continue
		}
		appMCPWriteEscaped(&out, r)
	}
	return out.String(), nil
}

// appMCPReviewOperation runs as the first-party session. With challenge != ""
// it also writes the approval row, the audit row and commits both together.
func appMCPReviewOperation(ctx context.Context, request appMCPCommandRequest, id, challenge string) (*appMCPReview, error) {
	var review *appMCPReview
	var expiresAt int64
	outcome, err := appMCPWithCommandOutcome(ctx, request, func(cap *appMCPCommandCapability) (bool, error) {
		stored, approval, err := appMCPReadOperation(cap, id)
		if err != nil {
			return false, err
		}
		now := appMCPClock()
		if err := appMCPBindOperation(cap, stored); err != nil {
			return false, err
		}
		if stored.Receipt == nil {
			if err := appMCPBindSource(cap, stored); err != nil {
				return false, err
			}
		}
		state, _ := appMCPOperationState(cap, stored, approval, nil, now)
		preview, err := appMCPDecodeObject(stored.Prepared.Preview)
		if err != nil {
			return false, err
		}
		pretty, err := appMCPReviewPreviewText(preview)
		if err != nil {
			return false, err
		}
		effects, err := appMCPEffectDisclosure(cap)
		if err != nil {
			return false, err
		}
		review = &appMCPReview{Tool: cap.tool.Name, Description: cap.tool.Description, Preview: pretty, State: state, ExpiresAt: stored.Prepared.ExpiresAt, Effects: effects,
			Title: cap.tool.Title, Summary: cap.tool.ReviewSummary, AutoApprove: stored.Prepared.ApprovalReason,
			Changes: appMCPReviewChanges(cap.tool, cap.command.PreviewSchema, preview)}
		if challenge == "" {
			return false, nil
		}
		if state == "expired" {
			return false, errAppMCPOperationExpired
		}
		if state == "approved" {
			return false, errAppMCPOperationApproved
		}
		if state != "prepared" {
			return false, errAppMCPOperationDenied // already committed
		}
		// The transaction's own view of the session: a direct unscoped
		// non-impersonated non-act-as login (not just the request's copy).
		direct, err := directLoginSessionErr(cap.tx, &cap.actor, true)
		if err != nil {
			return false, fmt.Errorf("verify approving session: %w", err)
		}
		if cap.origin != appMCPCommandSessionOrigin || !direct {
			return false, errAppMCPOperationDenied
		}
		expiresAt = stored.Prepared.ExpiresAt
		approvalID, err := appMCPRandomHex(32)
		if err != nil {
			return false, err
		}
		record := appMCPCommandApprovalRecord{
			Version: 1, Domain: appMCPHumanApprovalDomain, ApprovalID: approvalID, AppID: stored.Prepared.AppID, OperationID: id,
			PreparedDigest: stored.PreparedDigest, DisclosureVersion: stored.Prepared.DisclosureVersion,
			OwnerEpoch: stored.Prepared.RuntimeAuthority.OwnerEpoch, WriteEpoch: stored.Prepared.RuntimeAuthority.WriteEpoch,
			ApproverUserID: cap.actor.UserID, ApproverCreated: cap.actorCreated, ApproverSessionID: cap.sessionID, Tenant: cap.tenant,
			ApprovedAt: now.Unix(), ExpiresAt: stored.Prepared.ExpiresAt,
			ReviewChallengeDigest: appMCPOperationDigest("benmore:mcp:review-challenge:v1", []byte(stored.PreparedDigest+"|"+challenge)),
		}
		if err := cap.withNativeMetadata(appMCPCommandMetadataApprove, func() error {
			_, err := insertAppMCPCommandApproval(cap.ctx, cap.tx, cap.app, stored, record)
			return err
		}); err != nil {
			return false, err
		}
		if err := appMCPAudit(cap, "mcp_command_approve", id, map[string]any{"command": cap.tool.Name, "approval_id": approvalID, "prepared_digest": stored.PreparedDigest}); err != nil {
			return false, err
		}
		review.State = "approved"
		return true, nil
	}, appMCPBarrier(&expiresAt))
	if err := appMCPFinishOutcome(outcome, err); err != nil {
		return nil, err
	}
	return review, nil
}

// insertAppMCPCommandApproval is the only production writer of an approval
// row. It stores the exact shape the storage fixtures and the union validator
// define: an "approved" state sealed under the app key, bound to the prepared
// operation. The primary key makes a second approval fail.
func insertAppMCPCommandApproval(ctx context.Context, tx *sql.Tx, app *App, operation *appMCPStoredOperation, record appMCPCommandApprovalRecord) (*appMCPCommandApprovalState, error) {
	appID, key, err := appMCPReadyOperationStorage(ctx, tx, app)
	if err != nil {
		return nil, err
	}
	if _, err := verifyAppMCPCommandStorageWithKey(ctx, tx, appID, key); err != nil {
		return nil, err
	}
	if err := appMCPValidateCommandApprovalRecord(record, operation, appID); err != nil {
		return nil, err
	}
	_, digest, err := appMCPEncodeCommandApproval(record)
	if err != nil {
		return nil, err
	}
	plaintext, err := appMCPEncodeCommandApprovalState(appMCPCommandApprovalState{Approval: record, ApprovalDigest: digest, State: "approved"})
	if err != nil {
		return nil, err
	}
	sealed, err := appMCPSealCommandApproval(key, plaintext)
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO main._benmore_mcp_command_approvals(operation_id,approval_digest,state_ciphertext) VALUES(?,?,?)", record.OperationID, digest, sealed); err != nil {
		var sqliteErr sqlite3.Error
		if errors.As(err, &sqliteErr) && sqliteErr.ExtendedCode == sqlite3.ErrConstraintPrimaryKey {
			return nil, errAppMCPOperationApproved
		}
		return nil, errors.New("command approval insert failed")
	}
	return appMCPReadCommandApprovalWithKey(ctx, tx, appID, key, operation)
}

// consumeAppMCPCommandApproval flips approved -> consumed exactly once through
// the existing compare-and-swap; a concurrent consumer changes zero rows.
func consumeAppMCPCommandApproval(ctx context.Context, tx *sql.Tx, app *App, approval *appMCPCommandApprovalState, attemptID string, consumedAt int64) error {
	_, key, err := appMCPReadyOperationStorage(ctx, tx, app)
	if err != nil {
		return err
	}
	consumed := *approval
	consumed.State, consumed.AttemptID, consumed.ConsumedAt = "consumed", attemptID, consumedAt
	plaintext, err := appMCPEncodeCommandApprovalState(consumed)
	if err != nil {
		return err
	}
	sealed, err := appMCPSealCommandApproval(key, plaintext)
	if err != nil {
		return err
	}
	return appMCPResealCommandApprovalCAS(ctx, tx, appMCPCommandApprovalMaintenanceRow{
		operationID: approval.Approval.OperationID, approvalDigest: approval.ApprovalDigest, ciphertext: approval.Ciphertext}, sealed)
}

// ---- commit ----------------------------------------------------------------

type appMCPCommitView struct {
	OperationID, Outcome string
	Receipt              map[string]any
}

func appMCPPreparedFromRecord(cap *appMCPCommandCapability, record appMCPPreparedOperationRecord) (*appMCPCommandPrepared, error) {
	intent, err1 := appMCPDecodeObject(record.Intent)
	arguments, err2 := appMCPDecodeObject(record.Arguments)
	preview, err3 := appMCPDecodeObject(record.Preview)
	var dependencies appMCPRevisionDependencySnapshot
	decoder := json.NewDecoder(bytes.NewReader(record.Dependencies))
	decoder.DisallowUnknownFields()
	if err := errors.Join(err1, err2, err3, decoder.Decode(&dependencies)); err != nil {
		return nil, errAppMCPOperationDenied
	}
	return &appMCPCommandPrepared{ToolName: record.Command, ContractDigest: record.ContractDigest, ExecutionDigest: record.ExecutionDigest,
		OwnerEpoch: dependencies.OwnerEpoch, WriteEpoch: record.RuntimeAuthority.WriteEpoch, EnrollmentID: dependencies.EnrollmentID,
		ActorUserID: record.Origin.ActorID, ActorEmail: cap.actor.Email, ActorCreated: record.Origin.ActorCreated, Tenant: record.Origin.Tenant,
		Origin: cap.origin, Intent: intent, Arguments: arguments, Preview: preview, Dependencies: &dependencies}, nil
}

// appMCPReceiptView is the receipt a tool returns. approval_basis says what
// stood in for the approval: "human" (the browser review) or
// grant_consent:<grant id>. It is read from the sealed approval the receipt is
// bound to, so the sealed receipt itself is unchanged.
func appMCPReceiptView(cap *appMCPCommandCapability, receipt *appMCPCommandReceiptRecord, approval *appMCPCommandApprovalState) (map[string]any, error) {
	if approval == nil || approval.Approval.ApprovalID != receipt.ApprovalID {
		return nil, errors.New("command receipt approval is unavailable")
	}
	basis := "human"
	if approval.Approval.Domain == appMCPGrantApprovalDomain {
		basis = approval.Approval.Basis
	}
	result, err := appMCPDecodeObject(receipt.Result)
	if err != nil {
		return nil, err
	}
	effects, err := appMCPEffectsView(cap, receipt.OperationID, receipt.Effects)
	if err != nil {
		return nil, err
	}
	return map[string]any{"version": 1, "operation_id": receipt.OperationID, "approval_id": receipt.ApprovalID, "attempt_id": receipt.AttemptID,
		"committed_at": receipt.CommittedAt, "result": result, "effects": effects, "approval_basis": basis}, nil
}

// appMCPCommitChecks is the read-and-verify prefix shared by both commit
// phases. A stored receipt is returned as is (replay); otherwise the operation
// must be bound to the caller and source, unexpired, approved by its own actor
// from a still-live session.
func appMCPCommitChecks(cap *appMCPCommandCapability, id string, now time.Time) (*appMCPStoredOperation, *appMCPCommandApprovalState, []appMCPAttempt, error) {
	stored, approval, err := appMCPReadOperation(cap, id)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := appMCPBindOperation(cap, stored); err != nil {
		return nil, nil, nil, err
	}
	if stored.Receipt != nil { // replay: same receipt, no second apply; identity only
		return stored, approval, nil, nil
	}
	if err := appMCPBindSource(cap, stored); err != nil {
		return nil, nil, nil, err
	}
	if appMCPOperationExpired(cap, stored, now) {
		return nil, nil, nil, errAppMCPOperationExpired
	}
	if approval == nil {
		return nil, nil, nil, errAppMCPOperationNotApproved
	}
	if approval.State != "approved" || approval.Approval.ApproverUserID != stored.Prepared.Origin.ActorID {
		return nil, nil, nil, errAppMCPOperationDenied
	}
	switch approval.Approval.Domain {
	case appMCPGrantApprovalDomain:
		if !appMCPGrantApprovalLive(cap, approval) {
			return nil, nil, nil, errAppMCPOperationDenied // consent, switch or declaration no longer allow it
		}
	case appMCPHumanApprovalDomain:
		live, err := appMCPApproverSessionLive(cap, approval.Approval.ApproverSessionID, approval.Approval.ApproverUserID)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("verify approving session: %w", err)
		}
		if !live {
			return nil, nil, nil, errAppMCPOperationDenied // a revoked, expired or narrowed approving session
		}
	default:
		return nil, nil, nil, errAppMCPOperationDenied
	}
	attempts, err := appMCPReadAttempts(cap, id)
	return stored, approval, attempts, err
}

func appMCPReplayView(cap *appMCPCommandCapability, id string, stored *appMCPStoredOperation, approval *appMCPCommandApprovalState) (*appMCPCommitView, error) {
	receipt, err := decodeAppMCPCommandReceipt(stored, approval)
	if err != nil {
		return nil, err
	}
	receiptView, err := appMCPReceiptView(cap, receipt, approval)
	if err != nil {
		return nil, err
	}
	return &appMCPCommitView{OperationID: id, Outcome: "already_applied", Receipt: receiptView}, nil
}

// appMCPClaimAttempt is commit phase one: in its own transaction it verifies
// the operation and durably records one `running` attempt before any business
// side effect. Only failed or conflicted attempts may be retried; a running one
// is in progress. A terminal unknown one is never replayed: the receipt
// (checked first, in appMCPCommitChecks) is the only reconciliation, so without
// one it stays unknown until the operation expires. A running attempt past the
// coordinator deadline with no receipt is superseded: it is marked unknown
// (audited) and a fresh attempt is claimed in the same transaction.
func appMCPClaimAttempt(ctx context.Context, request appMCPCommandRequest, id string) (view *appMCPCommitView, attemptID string, actor Session, err error) {
	var expiresAt int64
	retry := false
	outcome, err := appMCPWithCommandOutcome(ctx, request, func(cap *appMCPCommandCapability) (bool, error) {
		now := appMCPClock()
		stored, approval, attempts, err := appMCPCommitChecks(cap, id, now)
		if err != nil {
			return false, err
		}
		retry = len(attempts) > 0
		if stored.Receipt != nil {
			view, err = appMCPReplayView(cap, id, stored, approval)
			return false, err
		}
		// A stale running attempt with no receipt (checked above, under the write
		// lock) never committed and can no longer commit: it is superseded below.
		var superseded *appMCPAttempt
		latest := appMCPLatestAttempt(attempts)
		if latest != nil {
			switch appMCPAttemptState(latest, now, false) {
			case appMCPAttemptRunning:
				return false, errAppMCPOperationInProgress
			case appMCPAttemptUnknown, appMCPAttemptSucceeded:
				if !appMCPAttemptStale(latest, now) {
					return false, &appMCPCommandOutcomeUnknownError{cause: errors.New("the previous attempt has no durable receipt")}
				}
				superseded = latest
			}
		}
		if len(attempts) >= appMCPOperationAttemptLimit {
			return false, fmt.Errorf("too many commit attempts: %w", errAppMCPOperationLimit)
		}
		if attemptID, err = appMCPRandomHex(32); err != nil {
			return false, err
		}
		if err := cap.withNativeMetadata(appMCPCommandMetadataAttempt, func() error {
			appID, key, err := appMCPOperationContext(cap.ctx, cap.tx, cap.app)
			if err != nil {
				return err
			}
			if superseded != nil {
				if err := appMCPFinishRunningAttempt(cap.ctx, cap.tx, appID, key, *superseded, appMCPAttemptUnknown, "stale_claim", now); err != nil {
					return err
				}
			}
			// Ordering is by sealed StartedAt, so a clock that stepped back must not
			// sort a new claim before the attempt it follows.
			started := now.Unix()
			if latest != nil && started <= latest.StartedAt {
				started = latest.StartedAt + 1
			}
			return insertAppMCPAttemptWithKey(cap.ctx, cap.tx, appID, key, appMCPAttemptRecord{Version: 1, Domain: appMCPAttemptDomain,
				AttemptID: attemptID, OperationID: id, AppID: appID, StartedAt: started, State: appMCPAttemptRunning})
		}); err != nil {
			return false, err
		}
		if superseded != nil {
			if err := appMCPAudit(cap, "mcp_command_attempt_unknown", id, map[string]any{"attempt_id": superseded.AttemptID, "error_class": "stale_claim", "superseded_by": attemptID}); err != nil {
				return false, err
			}
		}
		actor, expiresAt = cap.actor, stored.Prepared.ExpiresAt
		return true, nil
	}, appMCPBarrier(&expiresAt))
	if err := appMCPFinishOutcome(outcome, err); err != nil {
		return nil, "", actor, err
	}
	if attemptID != "" && request.generation != nil && request.generation.manifest != nil {
		appMCPRecordAttemptTelemetry(request.app, request.toolName, request.generation.manifest.ContractDigest, request.generation.manifest.ExecutionDigest, appMCPTelemetrySchemaRevision(request.generation.manifest, request.generation.manifest.ExecutionDigest), retry)
	}
	return view, attemptID, actor, nil
}

// appMCPCommitOperation applies an approved operation in three steps, each its
// own transaction: claim (record `running`), apply (the business transaction,
// which consumes the approval and writes the receipt under the claimed attempt
// id) and record (terminal attempt state and audit, outside any rollback).
func appMCPCommitOperation(ctx context.Context, request appMCPCommandRequest, id string) (*appMCPCommitView, error) {
	view, attemptID, actor, err := appMCPClaimAttempt(ctx, request, id)
	if err != nil || view != nil {
		return view, err
	}
	var validUntil int64
	var events []appMCPCommandBroadcast
	var revokedUsers []int64
	var workflowCompletions int64
	outcome, err := appMCPWithCommandOutcome(ctx, request, func(cap *appMCPCommandCapability) (bool, error) {
		now := appMCPClock()
		stored, approval, attempts, err := appMCPCommitChecks(cap, id, now)
		if err != nil {
			return false, err
		}
		// Refuse once our own claim is stale: a later _commit may supersede it.
		latest := appMCPLatestAttempt(attempts)
		if stored.Receipt != nil || latest == nil || latest.AttemptID != attemptID || appMCPAttemptState(latest, now, false) != appMCPAttemptRunning {
			return false, errAppMCPOperationDenied // the claim is no longer ours
		}
		// The COMMIT may not happen after the claim's coordinator deadline, which
		// is what makes a stale claim without a receipt safe to supersede.
		validUntil = latest.StartedAt + int64(appMCPCommandTimeout/time.Second)
		if stored.Prepared.ExpiresAt < validUntil {
			validUntil = stored.Prepared.ExpiresAt
		}
		if now.Unix() >= validUntil {
			return false, errAppMCPOperationDenied // no time left to commit: do no apply work
		}
		prepared, err := appMCPPreparedFromRecord(cap, stored.Prepared)
		if err != nil {
			return false, err
		}
		cap.operationID = id
		_, readback, err := cap.apply(prepared)
		if err != nil {
			return false, err
		}
		workflowCompletions = appMCPWorkflowCompletionCount(cap)
		result, err := json.Marshal(readback)
		if err != nil {
			return false, err
		}
		effects, err := appMCPEffectReceipt(cap.effects)
		if err != nil {
			return false, err
		}
		consumedAt := appMCPClock().Unix()
		if consumedAt >= stored.Prepared.ExpiresAt {
			return false, errAppMCPOperationExpired
		}
		receiptBytes, err := json.Marshal(appMCPCommandReceiptRecord{Version: 1, Kind: "command_receipt", State: "committed", AppID: stored.Prepared.AppID,
			OperationID: id, PreparedDigest: stored.PreparedDigest, ApprovalID: approval.Approval.ApprovalID, ApprovalDigest: approval.ApprovalDigest,
			AttemptID: attemptID, CommittedAt: consumedAt, Result: result, Effects: effects})
		if err != nil {
			return false, err
		}
		if err := cap.withNativeMetadata(appMCPCommandMetadataConsume, func() error {
			return consumeAppMCPCommandApproval(cap.ctx, cap.tx, cap.app, approval, attemptID, consumedAt)
		}); err != nil {
			return false, err
		}
		if err := cap.withNativeMetadata(appMCPCommandMetadataReceipt, func() error {
			_, err := storeAppMCPCommittedReceipt(cap.ctx, cap.tx, cap.app, id, stored.PreparedDigest, receiptBytes)
			return err
		}); err != nil {
			return false, err
		}
		if err := appMCPAudit(cap, "mcp_command_commit", id, map[string]any{"command": cap.tool.Name, "approval_id": approval.Approval.ApprovalID, "attempt_id": attemptID, "prepared_digest": stored.PreparedDigest}); err != nil {
			return false, err
		}
		// Read back what will commit: the receipt must be coherent with the
		// consumed approval before the coordinator is allowed to COMMIT.
		after, afterApproval, err := appMCPReadOperation(cap, id)
		if err != nil {
			return false, err
		}
		if view, err = appMCPReplayView(cap, id, after, afterApproval); err != nil {
			return false, err
		}
		view.Outcome = "applied"
		events = appMCPCommandBroadcasts(request.generation.view, cap.writes, cap.hookRefresh, cap.actor)
		revokedUsers = append([]int64(nil), cap.revokedUsers...)
		return true, nil
	}, appMCPBarrier(&validUntil))
	view, err = appMCPSettleCommit(ctx, request, actor, id, attemptID, appMCPFinishOutcome(outcome, err), view, events)
	if err == nil && view != nil && view.Outcome == "applied" {
		appMCPAfterCommitRevocations(request.app, revokedUsers)
	}
	if err == nil && view != nil && view.Outcome == "applied" && workflowCompletions > 0 {
		appMCPRecordWorkflowCompletions(request.app, request.toolName, request.generation.manifest.ContractDigest, request.generation.manifest.ExecutionDigest, appMCPTelemetrySchemaRevision(request.generation.manifest, request.generation.manifest.ExecutionDigest), workflowCompletions)
	}
	return view, err
}

// appMCPSettleCommit is commit phase three: it records the attempt outcome and
// returns the result. An unknown COMMIT whose receipt turns out to exist is a
// success: the applied view is returned and the events broadcast like any other
// confirmed commit.
func appMCPSettleCommit(ctx context.Context, request appMCPCommandRequest, actor Session, id, attemptID string, err error, view *appMCPCommitView, events []appMCPCommandBroadcast) (*appMCPCommitView, error) {
	state, class := appMCPAttemptOutcomeFor(err)
	recorded := appMCPRecordAttemptOutcome(ctx, request.app, actor, id, attemptID, state, class)
	if err != nil && state == appMCPAttemptUnknown && recorded == appMCPAttemptSucceeded && view != nil {
		err = nil
	}
	if err != nil {
		return nil, err
	}
	if attemptID != "" && view != nil && request.generation != nil && request.generation.manifest != nil {
		appMCPRecordQueuedEffects(request.app, request.toolName, request.generation.manifest.ContractDigest, request.generation.manifest.ExecutionDigest, appMCPTelemetrySchemaRevision(request.generation.manifest, request.generation.manifest.ExecutionDigest), view.Receipt)
	}
	// The connection and leases are released: broadcast only a confirmed commit.
	appMCPBroadcastCommitted(request.app, events)
	return view, nil
}

// ---- status ----------------------------------------------------------------

type appMCPStatusView struct {
	OperationID, State, Business string
	Receipt, Attempt, Effects    map[string]any
	Retryable                    bool
}

// appMCPStatusOperation reports durable state only. After an unknown commit it
// is the reconciliation read: a receipt row exists iff the commit happened, and
// it wins over any attempt record.
func appMCPStatusOperation(ctx context.Context, request appMCPCommandRequest, id string) (*appMCPStatusView, error) {
	if request.readOnlyStatus {
		appMCPReconcileTransferEffects(ctx, request, id)
	}
	var view *appMCPStatusView
	outcome, err := appMCPWithCommandOutcome(ctx, request, func(cap *appMCPCommandCapability) (bool, error) {
		stored, approval, err := appMCPReadOperation(cap, id)
		if err != nil {
			return false, err
		}
		now := appMCPClock()
		if err := appMCPBindOperation(cap, stored); err != nil {
			return false, err
		}
		attempts, err := appMCPReadAttempts(cap, id)
		if err != nil {
			return false, err
		}
		state, business := appMCPOperationState(cap, stored, approval, attempts, now)
		latest := appMCPLatestAttempt(attempts)
		view = &appMCPStatusView{OperationID: id, State: state, Business: business, Attempt: appMCPAttemptView(latest, now, stored.Receipt != nil),
			Retryable: appMCPAttemptRetryable(state, latest, len(attempts), now), Effects: map[string]any{"status": appMCPEffectNone, "items": []any{}}}
		if stored.Receipt != nil {
			receipt, err := decodeAppMCPCommandReceipt(stored, approval)
			if err != nil {
				return false, err
			}
			if view.Receipt, err = appMCPReceiptView(cap, receipt, approval); err != nil {
				return false, err
			}
			view.Effects, _ = view.Receipt["effects"].(map[string]any)
		}
		return false, nil
	}, appMCPBarrier(nil))
	if err := appMCPFinishOutcome(outcome, err); err != nil {
		return nil, err
	}
	return view, nil
}

// ---- connector tools -------------------------------------------------------

func appMCPCommandFailure(tool, id string, err error) *sdk.CallToolResult {
	code := appMCPLogCommandError(tool, id, err)
	var hook *appMCPCommandHookError
	if code == "hook_refused" && errors.As(err, &hook) {
		return appMCPHookRefusedResult(hook)
	}
	var refusal *appMCPCommandRefusal
	if errors.As(err, &refusal) {
		return appMCPSDKFailure(&appMCPResultError{Code: refusal.Code, Message: refusal.Message})
	}
	switch code {
	case "unknown_execution", "expired_intent", "approval_required", "operation_limit", "in_progress", "invalid_input", "incomplete_result", "unavailable_provider", "conflict":
	default:
		code = "denied" // authorization, and a duplicate approval, look alike to a tool
	}
	return appMCPSDKFailure(appMCPResultFailure(code))
}

func appMCPCommandResult(result map[string]any) *sdk.CallToolResult {
	text, err := json.Marshal(result)
	if err != nil || len(text) > appMCPResultLimit {
		return appMCPSDKFailure(appMCPResultFailure("incomplete_result"))
	}
	return &sdk.CallToolResult{StructuredContent: result, Content: []sdk.Content{&sdk.TextContent{Text: string(text)}}}
}

func appMCPClosedObject(properties map[string]any) map[string]any {
	required := make([]string, 0, len(properties))
	for name := range properties {
		required = append(required, name)
	}
	sort.Strings(required)
	return map[string]any{"type": "object", "additionalProperties": false, "properties": properties, "required": required}
}

func appMCPCommandPreviewOutputSchema(schema *AppMCPSchema, transfer *AppMCPTransfer) map[string]any {
	encoded, _ := json.Marshal(schema)
	var output map[string]any
	_ = json.Unmarshal(encoded, &output)
	if output == nil {
		return map[string]any{}
	}
	if transfer == nil {
		return output
	}
	properties, _ := output["properties"].(map[string]any)
	if properties == nil {
		properties = map[string]any{}
		output["properties"] = properties
	}
	stringSchema := func(max int) map[string]any { return map[string]any{"type": "string", "maxLength": max} }
	transferProperties := map[string]any{
		"kind":       map[string]any{"type": "string", "enum": []string{transfer.Kind}},
		"connection": stringSchema(64), "operation_id": stringSchema(128),
	}
	if transfer.Kind == "pull" {
		transferProperties["selected_source_id"] = stringSchema(512)
		transferProperties["target_table"] = stringSchema(64)
		transferProperties["target_record_id"] = stringSchema(256)
		transferProperties["target_file_column"] = stringSchema(64)
		transferProperties["private_destination"] = stringSchema(512)
		transferProperties["target_row_digest"] = map[string]any{"type": "string", "pattern": "^[0-9a-f]{64}$"}
	} else {
		transferProperties["artifact_id"] = stringSchema(128)
		transferProperties["artifact_sha256"] = map[string]any{"type": "string", "pattern": "^[0-9a-f]{64}$"}
		transferProperties["artifact_size"] = map[string]any{"type": "integer", "minimum": 1, "maximum": mcpArtifactMaxBytes}
	}
	properties["external_transfer"] = appMCPClosedObject(transferProperties)
	requiredRoot, _ := output["required"].([]any)
	requiredRoot = append(requiredRoot, "external_transfer")
	output["required"] = requiredRoot
	return output
}

// addAppMCPCommandTools registers the write surface for one connector request.
// A command is listed only when writes are live and both the grant and the
// current role-intersected actor carry every declared permission; a read-only
// grant never sees or reaches a write tool.
func addAppMCPCommandTools(server *sdk.Server, app *App, generation *appMCPRuntimeGeneration, grant *appMCPGrant, actor *Session, raw, resource string) {
	if grant == nil || actor == nil {
		return
	}
	var listed []appMCPLiveCommand
	for _, command := range appMCPLiveCommands(app, generation) {
		permissions := strings.Join(command.tool.Permissions, " ")
		if scopesWithin(grant.Scopes, permissions) && scopesWithin(actor.Scopes, permissions) {
			listed = append(listed, command)
		}
	}
	if len(listed) == 0 {
		return
	}
	no, yes := false, true
	operationID := map[string]any{"type": "string", "pattern": "^[0-9a-f]{64}$"}
	idInput := appMCPClosedObject(map[string]any{"operation_id": operationID})
	unixTime := map[string]any{"type": "integer", "minimum": 0}
	request := func(name string, tool *AppMCPTool, statusOnly bool) (appMCPCommandRequest, error) {
		originFunc := appMCPConnectorOrigin
		if statusOnly {
			originFunc = appMCPConnectorStatusOrigin
		}
		origin, err := originFunc(app, generation, grant, tool, raw, resource)
		return appMCPCommandRequest{app: app, generation: generation, toolName: name, origin: origin, readOnlyStatus: statusOnly}, err
	}
	effects := appMCPEffectsSchema()
	receiptFor := func(readback any) map[string]any {
		return appMCPClosedObject(map[string]any{
			"version": map[string]any{"type": "integer", "enum": []any{1}}, "operation_id": operationID,
			"approval_id": operationID, "attempt_id": operationID, "committed_at": unixTime, "result": readback,
			"effects": effects, "approval_basis": map[string]any{"type": "string", "maxLength": 128},
		})
	}
	commitOutput := func(receipt map[string]any) map[string]any {
		return appMCPClosedObject(map[string]any{"operation_id": operationID, "outcome": map[string]any{"type": "string", "enum": []any{"applied", "already_applied"}}, "receipt": receipt})
	}
	readbacks := make([]any, 0, len(listed))
	for _, command := range listed {
		tool := command.tool
		readbacks = append(readbacks, tool.OutputSchema)
		output := appMCPClosedObject(map[string]any{
			"operation_id": operationID, "preview": appMCPCommandPreviewOutputSchema(command.flow.Command.PreviewSchema, tool.Transfer), "expires_at": unixTime,
			"review_url": map[string]any{"type": "string", "maxLength": 2048}, "batch_review_url": map[string]any{"type": "string", "maxLength": 2048},
			"approval_reason": map[string]any{"type": "string", "maxLength": 256},
		})
		description := tool.Description + " Prepares the change only: a person must approve it at review_url (or every pending change of this connection at once at batch_review_url) before " + appMCPCommitTool + " applies it."
		if tool.Approval == "grant" {
			// Either shape: applied in this call (the commit result) when the
			// user allowed it at connection and the owner switch is on, else a
			// prepared operation to approve.
			output = map[string]any{"type": "object", "anyOf": []any{output, commitOutput(receiptFor(tool.OutputSchema))}}
			description = tool.Description + " When this connection was allowed to apply it without asking, it is applied in this call and the result is the " + appMCPCommitTool + " receipt; otherwise it is only prepared and a person must approve it at review_url before " + appMCPCommitTool + " applies it. If applying fails, the error carries operation_id: use " + appMCPStatusTool + " and " + appMCPCommitTool + " with it."
		}
		server.AddTool(&sdk.Tool{Name: tool.Name, Description: description,
			InputSchema: tool.InputSchema, OutputSchema: output, Annotations: &sdk.ToolAnnotations{DestructiveHint: &no, OpenWorldHint: &no}},
			func(ctx context.Context, call *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
				input, ok := appMCPDecodeToolArguments(call.Params.Arguments)
				if !ok || validateAppMCPSchemaValue(tool.InputSchema, input) != nil {
					return appMCPSDKFailure(appMCPResultFailure("invalid_input")), nil
				}
				req, err := request(tool.Name, tool, false)
				if err != nil {
					return appMCPCommandFailure(tool.Name, "", err), nil
				}
				prepared, err := appMCPPrepareOperation(ctx, req, input)
				if err != nil {
					return appMCPCommandFailure(tool.Name, "", err), nil
				}
				if prepared.AutoApproved {
					// The approval is durable with the operation, so a failure here is
					// reconciled exactly like a failed _commit: by _status and _commit.
					view, err := appMCPCommitOperation(ctx, req, prepared.ID)
					if err != nil {
						result := appMCPCommandFailure(tool.Name, prepared.ID, err)
						result.Meta["operation_id"] = prepared.ID
						return result, nil
					}
					return appMCPCommandResult(map[string]any{"operation_id": view.OperationID, "outcome": view.Outcome, "receipt": view.Receipt}), nil
				}
				return appMCPCommandResult(map[string]any{"operation_id": prepared.ID, "preview": prepared.Preview, "expires_at": prepared.ExpiresAt,
					"review_url": appMCPOAuthOrigin(resource) + appMCPOperationRoute + prepared.ID, "batch_review_url": appMCPBatchReviewURL(resource, grant.ID),
					"approval_reason": prepared.ApprovalReason}), nil
			})
	}
	readback := readbacks[0]
	if len(readbacks) > 1 {
		readback = map[string]any{"anyOf": readbacks}
	}
	attemptStates := []any{"running", "succeeded", "failed", "conflict", "unknown"}
	attempt := appMCPClosedObject(map[string]any{
		"attempt_id": operationID, "state": map[string]any{"type": "string", "enum": attemptStates},
		"error_class": map[string]any{"type": "string", "maxLength": 64}, "started_at": unixTime, "finished_at": unixTime,
	})
	receipt := receiptFor(readback)
	// run resolves the command an operation belongs to, then runs one verb of
	// the coordinator for that command with this request's connector origin.
	run := func(ctx context.Context, args json.RawMessage, statusOnly bool, verb func(context.Context, appMCPCommandRequest, string) (map[string]any, error)) *sdk.CallToolResult {
		id, ok := appMCPOperationIDArgument(args)
		if !ok {
			return appMCPSDKFailure(appMCPResultFailure("invalid_input"))
		}
		name, err := appMCPOperationCommand(ctx, app, id)
		var tool *AppMCPTool
		if err == nil {
			tool, _, err = appMCPFindCommandDeclaration(generation, name)
		}
		var req appMCPCommandRequest
		if err == nil {
			req, err = request(name, tool, statusOnly)
		}
		if err != nil {
			return appMCPCommandFailure(name, id, err)
		}
		result, err := verb(ctx, req, id)
		if err != nil {
			return appMCPCommandFailure(name, id, err)
		}
		return appMCPCommandResult(result)
	}
	server.AddTool(&sdk.Tool{Name: appMCPCommitTool, Description: "Apply one operation that its intended person already approved on the review page. Repeating returns the same receipt; it never applies twice.",
		InputSchema: idInput, OutputSchema: commitOutput(receipt),
		Annotations: &sdk.ToolAnnotations{IdempotentHint: true, DestructiveHint: &yes, OpenWorldHint: &no}},
		func(ctx context.Context, call *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			return run(ctx, call.Params.Arguments, false, func(ctx context.Context, req appMCPCommandRequest, id string) (map[string]any, error) {
				view, err := appMCPCommitOperation(ctx, req, id)
				if err != nil {
					return nil, err
				}
				return map[string]any{"operation_id": view.OperationID, "outcome": view.Outcome, "receipt": view.Receipt}, nil
			}), nil
		})
	server.AddTool(&sdk.Tool{Name: appMCPStatusTool, Description: "Read the durable state of one operation this connection prepared: prepared, approved, running, succeeded, failed, conflict, unknown or expired. Business commit and effect delivery are reported separately. For an unknown external push, this read may perform a bounded GET by the server-derived idempotency key and record a confirmed receipt; it never repeats the POST. Transfer effects include a durable phase and recovery reference when available. retryable says whether _commit may claim another attempt; an unknown COMMIT outcome is never committed again, and a receipt proves an operation succeeded.",
		InputSchema: idInput, OutputSchema: appMCPClosedObject(map[string]any{"operation_id": operationID,
			"state":     map[string]any{"type": "string", "enum": []any{"prepared", "approved", "running", "succeeded", "failed", "conflict", "unknown", "expired"}},
			"business":  map[string]any{"type": "string", "enum": []any{"committed", "not_committed", "undetermined"}},
			"effects":   effects,
			"retryable": map[string]any{"type": "boolean"},
			"attempt":   map[string]any{"anyOf": []any{attempt, map[string]any{"type": "null"}}},
			"receipt":   map[string]any{"anyOf": []any{receipt, map[string]any{"type": "null"}}}}),
		Annotations: &sdk.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: &no}},
		func(ctx context.Context, call *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			return run(ctx, call.Params.Arguments, true, func(ctx context.Context, req appMCPCommandRequest, id string) (map[string]any, error) {
				view, err := appMCPStatusOperation(ctx, req, id)
				if err != nil {
					return nil, err
				}
				var receipt, attempt any
				if view.Receipt != nil {
					receipt = view.Receipt
				}
				if view.Attempt != nil {
					attempt = view.Attempt
				}
				return map[string]any{"operation_id": view.OperationID, "state": view.State, "business": view.Business, "effects": view.Effects, "retryable": view.Retryable, "attempt": attempt, "receipt": receipt}, nil
			}), nil
		})
}

// ---- first-party review/approve routes -------------------------------------

// appMCPOperationLimits are the review/approve budgets. The per-IP limiter runs
// before authentication as a coarse flood guard and is deliberately roomy: a
// shared NAT or office must not lose its approvals to one anonymous caller, so
// the tight budget is per signed-in user.
//
// The user budgets are charged only for an operation that exists and belongs
// to the caller, so a page that sends someone's browser to random operation
// URLs cannot spend it. Approvals have the tight budget; review pages, which
// are read-only, have a roomier one of their own.
type appMCPOperationLimits struct{ ip, approve, review *RateLimiter }

const (
	appMCPOperationIPRate     = 120
	appMCPOperationUserRate   = 30
	appMCPOperationReviewRate = 120
)

func newAppMCPOperationLimits(app *App, stop <-chan struct{}) *appMCPOperationLimits {
	mk := func(rate int) *RateLimiter {
		if IsClusterMode() { // same selection as the request limiter in server.go
			return NewSharedRateLimiter(app.DB, rate, time.Minute, stop)
		}
		return NewRateLimiterStoppable(rate, time.Minute, stop)
	}
	return &appMCPOperationLimits{ip: mk(appMCPOperationIPRate), approve: mk(appMCPOperationUserRate), review: mk(appMCPOperationReviewRate)}
}

// refuse answers 429 with Retry-After when key is out of budget.
func (l *RateLimiter) refuse(w http.ResponseWriter, app *App, key string) bool {
	allowed, retryAfter, _ := l.Check(key)
	if allowed {
		return false
	}
	setRetryAfter(w, retryAfter)
	writeAppMCPTooManyRequests(w, app)
	return true
}

// registerAppMCPOperationRoutes registers the first-party review/approve pair.
func registerAppMCPOperationRoutes(mux appRouteRegistrar, app *App, resource string) {
	// Keep lazy cleanup bound to this handler, even if its first request
	// arrives after reload has published a different stop generation.
	stop := app.workerStopGeneration()
	limits := sync.OnceValue(func() *appMCPOperationLimits { return newAppMCPOperationLimits(app, stop) })
	mux.HandleFunc("GET "+appMCPOperationRoute+"{id}", func(w http.ResponseWriter, r *http.Request) {
		serveAppMCPOperation(w, r, app, resource, limits(), false)
	})
	mux.HandleFunc("POST "+appMCPOperationRoute+"{id}/approve", func(w http.ResponseWriter, r *http.Request) {
		serveAppMCPOperation(w, r, app, resource, limits(), true)
	})
	registerAppMCPBatchRoutes(mux, app, resource, limits)
}

// registerAppMCPWithheldRoutes answers the review and batch URLs of an app whose connector is withheld
// (mcp.yaml present, review stale). Same disclosure rule as the live pages: signed out, the visitor is sent
// to sign in exactly as for a connector app that is on, so a stranger learns nothing more; only a signed-in
// direct browser session is told the connector is off.
func registerAppMCPWithheldRoutes(mux appRouteRegistrar, app *App) {
	serve := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		hasAuthorization := len(r.Header.Values("Authorization")) > 0
		cookie, cookieErr := requestSessionCookie(r)
		var session *Session
		if cookieErr == nil && !hasAuthorization {
			session = GetSessionFromDB(app.DB, cookie.Value)
		}
		if session == nil && r.Method == http.MethodGet && !hasAuthorization {
			http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
			return
		}
		if session == nil || session.ImpersonatorUserID != 0 || session.ActingAsGroup != "" || !directLoginSession(app, session) {
			if r.Method == http.MethodPost {
				writeAppMCPCannotApprove(w, app)
			} else {
				writeAppMCPCannotShow(w, app)
			}
			return
		}
		writeAppMCPConnectorOff(w, app)
	}
	for _, pattern := range []string{
		"GET " + appMCPOperationRoute + "{id}", "POST " + appMCPOperationRoute + "{id}/approve",
		"GET " + appMCPBatchRoute, "POST " + appMCPBatchRoute + "/approve",
	} {
		mux.HandleFunc(pattern, serve)
	}
}

// appMCPCSRFBinding ties an approval token to one session AND one operation.
func appMCPCSRFBinding(sessionCookie, operationID string) string {
	return sessionCookie + "|op:" + operationID
}

// appMCPBoundCSRF accepts only a token minted for exactly this binding. The
// generic validator also accepts the unbound /api/_csrf token and a token for
// any other operation of the same session; approval never may. The browser
// origin gate is csrfOriginReason, as in validateCSRFReason, and the token lives 15 minutes.
func appMCPBoundCSRF(r *http.Request, binding string) bool {
	token := r.FormValue(csrfTokenName)
	if token == "" {
		token = r.Header.Get("X-CSRF-Token")
	}
	parts := strings.SplitN(token, "|", 3)
	if len(parts) != 3 {
		return false
	}
	// The shared origin gate: a literal "Origin: null" (what a browser sends on
	// a same-origin form POST) counts only with Sec-Fetch-Site: same-origin.
	if _, ok := csrfOriginReason(r); !ok {
		return false
	}
	if !hmac.Equal([]byte(parts[2]), []byte(authCSRFSign(parts[0]+"|"+parts[1], binding))) {
		return false
	}
	issued, err := strconv.ParseInt(parts[1], 10, 64)
	age := time.Now().Unix() - issued
	return err == nil && age >= -60 && age <= 15*60
}

// appMCPReviewPageOpts: the review pages carry an operation or grant id in
// their URL and post a form, so the Referrer-Policy is same-origin (never
// no-referrer, security.md 5b): under no-referrer a browser sends
// "Origin: null" on the approve POST and appMCPBoundCSRF would refuse it.
var appMCPReviewPageOpts = appMCPPageOpts{Title: "Review requested change", Referrer: "same-origin"}

func serveAppMCPOperation(w http.ResponseWriter, r *http.Request, app *App, resource string, limits *appMCPOperationLimits, approve bool) {
	w.Header().Set("Cache-Control", "no-store")
	id := r.PathValue("id")
	generation := snapshotAppMCPGeneration(app)
	// Order matters for what a stranger can learn: a wrong host or a missing
	// connector says nothing; "writes off" is not secret (the tool list shows
	// it) and gets its own message; a malformed id waits until the viewer is
	// signed in, so a signed-out probe is sent to /login, never a bare 404.
	if generation == nil || generation.manifest == nil || !appMCPOAuthHost(r, app, resource) || (approve && !appMCPIsHex(id, 32)) {
		writeAppMCPCannotShow(w, app)
		return
	}
	_, writesLive := appMCPWritesLive(app)
	if limits.ip.refuse(w, app, "mcp-operation-ip:"+clientIP(r)) {
		return
	}
	// Only a browser cookie session may review or approve: a bearer/connector
	// credential, API token or edge identity is refused outright.
	hasAuthorization := len(r.Header.Values("Authorization")) > 0
	cookie, cookieErr := requestSessionCookie(r)
	var session *Session
	if cookieErr == nil && !hasAuthorization {
		session = GetSessionFromDB(app.DB, cookie.Value)
	}
	if session == nil && !approve && !hasAuthorization {
		// Signed out: send the person to sign in, then back here.
		http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.Path), http.StatusSeeOther)
		return
	}
	if session == nil || session.ImpersonatorUserID != 0 || session.ActingAsGroup != "" || !directLoginSession(app, session) {
		if approve {
			writeAppMCPCannotApprove(w, app)
		} else {
			writeAppMCPCannotShow(w, app)
		}
		return
	}
	// Writes off is said only to a signed-in direct session: signed out, every
	// connector app answers the same redirect, so a stranger cannot map which
	// apps have approved writes switched on.
	if !writesLive {
		writeAppMCPApprovalsOff(w, app)
		return
	}
	if !appMCPIsHex(id, 32) {
		writeAppMCPCannotShow(w, app)
		return
	}
	command, owner, err := appMCPOperationCommandOwner(r.Context(), app, id)
	if err == nil && owner != session.UserID {
		err = errAppMCPOperationDenied
	}
	if err == nil {
		// Only a real operation of this user is charged. A cross-site
		// navigation (a link from another origin) is never charged to the
		// user, so it cannot spend a person's budget; the IP guard covers it.
		uid := strconv.FormatInt(session.UserID, 10)
		switch {
		case approve:
			if limits.approve.refuse(w, app, "mcp-operation:"+uid) {
				return
			}
		case r.Header.Get("Sec-Fetch-Site") != "cross-site":
			if limits.review.refuse(w, app, "mcp-operation-review:"+uid) {
				return
			}
		}
	}
	request := appMCPCommandRequest{app: app, generation: generation, toolName: command,
		origin: appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: session.ID}}
	challenge := ""
	if approve {
		r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
		if err == nil && !appMCPBoundCSRF(r, appMCPCSRFBinding(cookie.Value, id)) {
			err = errAppMCPOperationDenied
		}
		challenge = r.FormValue(csrfTokenName) + r.Header.Get("X-CSRF-Token")
		if challenge == "" {
			err = errAppMCPOperationDenied
		}
	}
	var review *appMCPReview
	if err == nil {
		review, err = appMCPReviewOperation(r.Context(), request, id, challenge)
	}
	if err != nil {
		// A server-side failure keeps only its class in the request log; the
		// journal line (appMCPLogCommandError) has the rest.
		serverSide := func(class string) {
			w.Header().Set(requestIDHeader, recordRequestError(r, "[mcp review] "+class))
		}
		switch class := appMCPLogCommandError("review", id, err); {
		case approve && class == "unknown_execution":
			serverSide(class)
			writeAppMCPError(w, app, http.StatusInternalServerError, "We couldn't confirm the approval",
				"The approval outcome is unknown. Reload the review page to see the current state.")
		case approve && class == "already_approved":
			writeAppMCPError(w, app, http.StatusConflict, "Already approved",
				"This change was already approved. Reload the review page to see its current state.")
		case class == "unavailable_provider" || class == "incomplete_result":
			serverSide(class)
			writeAppMCPUnavailable(w, app)
		case approve:
			writeAppMCPCannotApprove(w, app)
		default:
			writeAppMCPCannotShow(w, app) // unknown, foreign and refused operations look the same
		}
		return
	}
	if approve {
		http.Redirect(w, r, appMCPOperationRoute+id, http.StatusSeeOther)
		return
	}
	view := newAppMCPReviewView(review, id, appMCPClock())
	view.Approvable = review.State == "prepared"
	view.StateKind, view.StateText = appMCPReviewStateNote(review.State)
	if view.Approvable {
		view.CSRF = authMintCSRFToken(appMCPCSRFBinding(cookie.Value, id)) // this session and this operation only
		view.Action = appMCPOperationRoute + id + "/approve"
	}
	writeAppMCPPage(w, app, http.StatusOK, appMCPReviewPage, appMCPReviewPageOpts, view)
}
