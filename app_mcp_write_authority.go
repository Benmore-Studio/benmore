//go:build !cli

package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// appMCPWriteAuthorityPin is request-local evidence already resolved by the
// connector adapter. No bearer token or caller-selected permissions enter here.
type appMCPWriteAuthorityPin struct {
	Origin              *App
	Generation          *appMCPRuntimeGeneration
	CredentialHash      string
	GrantID             string
	AppID               string
	Epoch               string
	WriteEpoch          string
	ExternalExportEpoch string
	// AutoApproveEpoch is the owner auto-approve epoch seen when the request
	// was admitted; it only decides AutoApproveLive and never denies.
	AutoApproveEpoch  string
	Resource          string
	Client            string
	Tenant            string
	UserID            int64
	UserCreated       string
	Permissions       []string
	Effect            *appMCPWriteEffectAuthority
	ExpectedRowDigest string
}

type appMCPWriteEffectAuthority struct {
	OperationID         string
	JobID               int64
	PayloadDigest       string
	ExternalExportEpoch string
	Grant               appMCPEffectGrant
	Transfer            appMCPTransferJob
}

type appMCPWriteTxQuerier struct {
	ctx context.Context
	tx  *sql.Tx
}

// appMCPWriteAuthoritySnapshot contains only validated bindings, never a raw
// bearer or credential hash. It is a prerequisite snapshot, not commit proof.
type appMCPWriteAuthoritySnapshot struct {
	Actor               Session
	AppID, GrantID      string
	Tenant, Client      string
	Resource, Epoch     string
	UserCreated         string
	UserID              int64
	CredentialExpiresAt int64
	GrantExpiresAt      int64
	// AutoApproveTools is the grant's consented auto-approve list, read in this
	// transaction. AutoApproveLive is true only while the owner switch is on
	// with the epoch the pin was admitted under. Neither grants any authority:
	// a command still needs approval: grant and every other check.
	AutoApproveTools []string
	AutoApproveLive  bool
	// AutoApproveOwnerOn is the owner switch alone, so a prepare that is not
	// applied automatically can say which condition failed (reason only).
	AutoApproveOwnerOn bool
}

type appMCPWriteAuthorityError struct{ cause error }

func (e *appMCPWriteAuthorityError) Error() string { return errAppMCPGrantDenied.Error() }
func (e *appMCPWriteAuthorityError) Unwrap() []error {
	if e == nil || e.cause == nil {
		return []error{errAppMCPGrantDenied}
	}
	return []error{errAppMCPGrantDenied, e.cause}
}

func denyAppMCPWriteAuthority(cause error) error {
	return &appMCPWriteAuthorityError{cause: cause}
}

// failAppMCPWriteAuthority reports an infrastructure failure (database,
// authority file, cancellation) while verifying authority. It is NOT a denial:
// it does not match errAppMCPGrantDenied, so callers can log it and tell an
// operator the store is unhealthy instead of reporting a refusal.
func failAppMCPWriteAuthority(what string, cause error) error {
	return fmt.Errorf("connector write authority: %s: %w", what, cause)
}

// appMCPAuthorityReadFailure splits an absent authority record (a denial) from
// any other read error (infrastructure).
func appMCPAuthorityReadFailure(err error) error {
	if errors.Is(err, os.ErrNotExist) {
		return denyAppMCPWriteAuthority(err)
	}
	return failAppMCPWriteAuthority("read owner authority", err)
}

func validateAppMCPWriteManifest(dir string, captured *AppMCPManifest) error {
	if captured == nil {
		return errors.New("captured MCP manifest is unavailable")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	info, err := root.Lstat("mcp.yaml")
	if err != nil || !info.Mode().IsRegular() {
		if err != nil {
			return err
		}
		return errors.New("mcp.yaml must be a regular file")
	}
	file, err := root.Open("mcp.yaml")
	if err != nil {
		return err
	}
	info, err = file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		if err != nil {
			return err
		}
		return errors.New("mcp.yaml must be a regular file")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, yamlMaxBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	if len(data) > yamlMaxBytes {
		return errors.New("mcp.yaml exceeds supported size")
	}
	fresh, err := parseAppMCPManifest(data)
	if err != nil {
		return err
	}
	if fresh == nil {
		return errors.New("mcp.yaml declaration is missing")
	}
	freshJSON, err := json.Marshal(fresh)
	if err != nil {
		return err
	}
	capturedJSON, err := json.Marshal(captured)
	if err != nil {
		return err
	}
	if !bytes.Equal(freshJSON, capturedJSON) || fresh.ContractDigest != captured.ContractDigest || fresh.ExecutionDigest != captured.ExecutionDigest {
		return errors.New("mcp.yaml declaration changed after review")
	}
	return validateAppMCPDigests(dir, captured)
}

func (q *appMCPWriteTxQuerier) Query(query string, args ...any) (*sql.Rows, error) {
	return q.tx.QueryContext(q.ctx, query, args...)
}
func (q *appMCPWriteTxQuerier) QueryRow(query string, args ...any) *sql.Row {
	return q.tx.QueryRowContext(q.ctx, query, args...)
}

// appMCPWriteAuthorityForTx is a transaction-local prerequisite only. Its
// caller must still hold authority through commit and enforce the complete
// operation policy, hooks, validators, and computed-field rules.
func appMCPWriteAuthorityForTx(ctx context.Context, tx *sql.Tx, pin appMCPWriteAuthorityPin, now time.Time) (*appMCPWriteAuthoritySnapshot, error) {
	return appMCPWriteAuthorityForTxMode(ctx, tx, pin, now, true)
}

func appMCPWriteAuthorityForTxMode(ctx context.Context, tx *sql.Tx, pin appMCPWriteAuthorityPin, now time.Time, verifySource bool) (*appMCPWriteAuthoritySnapshot, error) {
	if ctx == nil || tx == nil || pin.Origin == nil || pin.Generation == nil || pin.Generation.origin != pin.Origin ||
		(pin.CredentialHash == "") == (pin.Effect == nil) || pin.GrantID == "" || pin.AppID == "" || pin.Epoch == "" || pin.WriteEpoch == "" ||
		pin.Resource == "" || pin.Client == "" || pin.UserID <= 0 || pin.UserCreated == "" ||
		len(pin.Permissions) == 0 || validateFlowPermissions(pin.Permissions) != nil {
		return nil, denyAppMCPWriteAuthority(errors.New("invalid pinned authority input"))
	}
	if err := ctx.Err(); err != nil {
		return nil, failAppMCPWriteAuthority("context", err)
	}
	if pin.Effect == nil {
		decodedHash, hashErr := hex.DecodeString(pin.CredentialHash)
		if hashErr != nil || len(decodedHash) != 32 || pin.CredentialHash != strings.ToLower(pin.CredentialHash) {
			return nil, denyAppMCPWriteAuthority(errors.New("invalid credential digest"))
		}
	} else if pin.Effect.OperationID == "" || pin.Effect.JobID <= 0 || !appMCPOperationHex(pin.Effect.PayloadDigest, 32) || pin.Effect.Transfer.OperationID != pin.Effect.OperationID {
		return nil, denyAppMCPWriteAuthority(errors.New("invalid sealed effect evidence"))
	}
	ctx, cancel := context.WithTimeout(ctx, readOnlyQueryTimeout)
	defer cancel()
	q := &appMCPWriteTxQuerier{ctx: ctx, tx: tx}
	mainPath, err := mainDatabasePathForQuerier(q)
	if err != nil {
		return nil, failAppMCPWriteAuthority("read main database path", err)
	}
	if canonicalDBPath(mainPath) != canonicalDBPath(filepath.Join(pin.Origin.Dir, "data.db")) {
		return nil, denyAppMCPWriteAuthority(errors.New("transaction belongs to a different application database"))
	}
	state, err := currentAppMCPEpoch(pin.Origin.Dir)
	if err != nil {
		return nil, appMCPAuthorityReadFailure(err)
	}
	if !state.Exposed || state.Version != 2 || state.ApprovedWrites == nil || !*state.ApprovedWrites ||
		state.App != pin.AppID || !SecureCompare(state.Epoch, pin.Epoch) || !SecureCompare(state.ApprovedWriteEpoch, pin.WriteEpoch) {
		return nil, denyAppMCPWriteAuthority(errors.New("owner write authority changed"))
	}
	if pin.Effect != nil && pin.Effect.Transfer.Kind == "push" && (!state.ExternalExport || state.ExternalExportEpoch == "" || state.ExternalExportEpoch != pin.Effect.ExternalExportEpoch) {
		return nil, denyAppMCPWriteAuthority(errors.New("external export authority changed"))
	}
	manifest := pin.Generation.manifest
	authority := pin.Generation.view
	if manifest == nil || authority == nil || !appMCPGenerationCurrent(pin.Origin, pin.Generation) || !validAppMCPResource(pin.Origin, pin.Resource) {
		return nil, denyAppMCPWriteAuthority(errors.New("runtime policy is unavailable or stale"))
	}
	if verifySource {
		if err := validateAppMCPWriteManifest(pin.Origin.Dir, manifest); err != nil {
			return nil, denyAppMCPWriteAuthority(err)
		}
	}
	if pin.Effect != nil {
		if err := appMCPVerifyTransferReceiptJobTx(ctx, tx, pin.Origin, pin.Generation, *pin.Effect); err != nil {
			return nil, denyAppMCPWriteAuthority(err)
		}
	}
	if authority.Group != nil && authority.Group.Table != "" && (pin.Tenant == "" || pin.Tenant == "0") {
		return nil, denyAppMCPWriteAuthority(errors.New("tenant binding is missing"))
	}
	if _, err := appMCPExplicitScopes(strings.Join(pin.Permissions, " ")); err != nil {
		return nil, denyAppMCPWriteAuthority(err)
	}
	var grant appMCPGrant
	var credentialExpiresAt int64
	var revoked int
	if pin.Effect != nil {
		err = q.QueryRow(`SELECT g.id,g.app,g.user_id,g.user_created,g.tenant,g.client,g.resource,g.epoch,g.scopes,g.expires_at,g.revoked,g.expires_at,g.auto_approve,g.auto_approve_epoch
		FROM main._benmore_mcp_grants g WHERE g.id=? AND g.app=? AND g.user_id=? AND g.user_created=? AND g.tenant=? AND g.client=? AND g.resource=? AND g.epoch=? AND g.revoked=0 AND g.expires_at>?`,
			pin.GrantID, pin.AppID, pin.UserID, pin.UserCreated, pin.Tenant, pin.Client, pin.Resource, pin.Epoch, now.Unix()).
			Scan(&grant.ID, &grant.App, &grant.UserID, &grant.UserCreated, &grant.Tenant, &grant.Client, &grant.Resource, &grant.Epoch, &grant.Scopes, &grant.ExpiresAt, &revoked, &credentialExpiresAt, &grant.AutoApprove, &grant.AutoApproveEpoch)
	} else {
		err = q.QueryRow(`SELECT g.id,g.app,g.user_id,g.user_created,g.tenant,g.client,g.resource,g.epoch,g.scopes,g.expires_at,g.revoked,c.expires_at,g.auto_approve,g.auto_approve_epoch
		FROM main._benmore_mcp_credentials c JOIN main._benmore_mcp_grants g ON g.id=c.grant_id
		WHERE c.token_hash=? AND c.kind='access' AND c.used=0 AND c.expires_at>? AND g.id=? AND g.app=? AND g.user_id=?
		AND g.user_created=? AND g.tenant=? AND g.client=? AND g.resource=? AND g.epoch=? AND g.revoked=0 AND g.expires_at>?`,
			pin.CredentialHash, now.Unix(), pin.GrantID, pin.AppID, pin.UserID, pin.UserCreated, pin.Tenant, pin.Client, pin.Resource, pin.Epoch, now.Unix()).
			Scan(&grant.ID, &grant.App, &grant.UserID, &grant.UserCreated, &grant.Tenant, &grant.Client, &grant.Resource, &grant.Epoch, &grant.Scopes, &grant.ExpiresAt, &revoked, &credentialExpiresAt, &grant.AutoApprove, &grant.AutoApproveEpoch)
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, failAppMCPWriteAuthority("read grant", err)
	}
	if err != nil || revoked != 0 {
		if err == nil {
			err = errors.New("grant is revoked")
		}
		return nil, denyAppMCPWriteAuthority(err)
	}
	grant.Revoked = false
	actor, err := loadScheduledActorWith(authority, q, grant.UserID, &grant.Tenant, true)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, failAppMCPWriteAuthority("context", ctxErr)
	}
	if err != nil {
		return nil, denyAppMCPWriteAuthority(err)
	}
	var created string
	incarnationErr := q.QueryRow("SELECT COALESCE(created_at,'') FROM main._benmore_users WHERE id=?", grant.UserID).Scan(&created)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, failAppMCPWriteAuthority("context", ctxErr)
	}
	if incarnationErr != nil && !errors.Is(incarnationErr, sql.ErrNoRows) {
		return nil, failAppMCPWriteAuthority("read account incarnation", incarnationErr)
	}
	if incarnationErr != nil || created != grant.UserCreated {
		if incarnationErr == nil {
			incarnationErr = errors.New("account incarnation changed")
		}
		return nil, denyAppMCPWriteAuthority(incarnationErr)
	}
	grantScopes, err := appMCPExplicitScopes(grant.Scopes)
	if err != nil {
		return nil, denyAppMCPWriteAuthority(err)
	}
	effective := intersectScopes(strings.Join(grantScopes, " "), intersectScopes(actor.Scopes, appMCPDeclaredScopes(manifest)))
	if effective == "_none_:read" || !scopesWithin(effective, strings.Join(pin.Permissions, " ")) || !appMCPGenerationCurrent(pin.Origin, pin.Generation) {
		return nil, denyAppMCPWriteAuthority(errors.New("current permissions do not authorize the pinned operation"))
	}
	currentState, err := currentAppMCPEpoch(pin.Origin.Dir)
	if err != nil {
		return nil, appMCPAuthorityReadFailure(err)
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, failAppMCPWriteAuthority("context", ctxErr)
	}
	if !currentState.Exposed || currentState.Version != 2 || currentState.ApprovedWrites == nil || !*currentState.ApprovedWrites ||
		currentState.App != pin.AppID || !SecureCompare(currentState.Epoch, pin.Epoch) || !SecureCompare(currentState.ApprovedWriteEpoch, pin.WriteEpoch) {
		return nil, denyAppMCPWriteAuthority(errors.New("owner write authority changed"))
	}
	// The grant's consent counts only under the owner epoch it was given in:
	// an off/on cycle or any write-epoch rotation sends the user back to
	// per-write review until they consent again. An old grant has no epoch.
	autoApproveLive := currentState.AutoApprove && pin.AutoApproveEpoch != "" && SecureCompare(currentState.AutoApproveEpoch, pin.AutoApproveEpoch) &&
		grant.AutoApproveEpoch != "" && SecureCompare(currentState.AutoApproveEpoch, grant.AutoApproveEpoch)
	actor.Scopes = effective
	actor.CredentialScopes = effective // grant as currently live (see appMCPGrantActorFor)
	actor.Permissions = strings.Fields(effective)
	actor.ID = "connector:" + grant.ID
	actor.connectorGrant = true
	return &appMCPWriteAuthoritySnapshot{
		Actor: *actor, AppID: grant.App, GrantID: grant.ID, Tenant: grant.Tenant, Client: grant.Client,
		Resource: grant.Resource, Epoch: grant.Epoch, UserCreated: grant.UserCreated, UserID: grant.UserID,
		CredentialExpiresAt: credentialExpiresAt, GrantExpiresAt: grant.ExpiresAt,
		AutoApproveTools: strings.Fields(grant.AutoApprove), AutoApproveLive: autoApproveLive, AutoApproveOwnerOn: currentState.AutoApprove,
	}, nil
}
