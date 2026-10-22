//go:build !cli

package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mattn/go-sqlite3"
)

type appMCPCommandOriginKind uint8

const (
	appMCPCommandConnectorOrigin appMCPCommandOriginKind = iota + 1
	appMCPCommandSessionOrigin
)

// Exactly one closed server-selected authority source is allowed. This type
// is private and is populated only by the native coordinator, never decoded
// from a request or command argument.
type appMCPCommandOrigin struct {
	kind      appMCPCommandOriginKind
	connector *appMCPWriteAuthorityPin
	sessionID string
}

type appMCPCommandRequest struct {
	app            *App
	generation     *appMCPRuntimeGeneration
	toolName       string
	origin         appMCPCommandOrigin
	now            time.Time
	readOnlyStatus bool
}

type appMCPCommandCommitState uint8

const (
	appMCPCommandCommitNotAttempted appMCPCommandCommitState = iota
	appMCPCommandCommitConfirmed
	appMCPCommandCommitUnknown
)

type appMCPCommandTxOutcome struct {
	State             appMCPCommandCommitState
	RollbackConfirmed bool
	CleanupErr        error
}

type appMCPCommandCommitBarrier struct {
	ValidUntil time.Time
}

type appMCPCommandFinalize func(*appMCPCommandCapability, time.Time) (appMCPCommandCommitBarrier, error)

// appMCPWithCommandCapability remains the compatibility adapter for existing
// native callers. Its zero-deadline barrier adds no deadline of its own.
func appMCPWithCommandCapability(ctx context.Context, request appMCPCommandRequest, use func(*appMCPCommandCapability) (bool, error)) error {
	_, err := appMCPWithCommandOutcome(ctx, request, use, func(*appMCPCommandCapability, time.Time) (appMCPCommandCommitBarrier, error) {
		return appMCPCommandCommitBarrier{}, nil
	})
	return err
}

type appMCPCommandBusyTimeoutExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func appMCPCommandSetBusyTimeout(ctx context.Context, executor appMCPCommandBusyTimeoutExecutor, milliseconds int) error {
	if ctx == nil || executor == nil || milliseconds < 0 {
		return errors.New("command connection busy timeout is invalid")
	}
	if _, err := executor.ExecContext(ctx, "PRAGMA busy_timeout="+strconv.Itoa(milliseconds)); err != nil {
		return err
	}
	var actual int
	if err := executor.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&actual); err != nil {
		return err
	}
	if actual != milliseconds {
		return fmt.Errorf("command connection busy timeout readback mismatch: got %d want %d", actual, milliseconds)
	}
	return nil
}

func appMCPCommandReadBusyTimeout(ctx context.Context, executor appMCPCommandBusyTimeoutExecutor) (int, error) {
	if ctx == nil || executor == nil {
		return 0, errors.New("command connection busy timeout is unavailable")
	}
	var milliseconds int
	if err := executor.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&milliseconds); err != nil {
		return 0, err
	}
	if milliseconds < 0 {
		return 0, errors.New("command connection busy timeout is invalid")
	}
	return milliseconds, nil
}

// appMCPWithCommandOutcome owns the non-reentrant lock/connection scope and
// is the sole commit point for native command work.
func appMCPWithCommandOutcome(ctx context.Context, request appMCPCommandRequest, use func(*appMCPCommandCapability) (bool, error), finalize appMCPCommandFinalize) (outcome appMCPCommandTxOutcome, err error) {
	defer func() {
		if outcome.CleanupErr != nil {
			err = errors.Join(err, outcome.CleanupErr)
		}
	}()
	if ctx == nil || request.app == nil || request.app.DB == nil || request.generation == nil || request.generation.origin != request.app ||
		request.toolName == "" || use == nil || finalize == nil || request.origin.kind != appMCPCommandConnectorOrigin && request.origin.kind != appMCPCommandSessionOrigin {
		return outcome, errors.New("invalid private command coordinator input")
	}
	if request.now.IsZero() {
		request.now = time.Now()
	}
	ctx, cancel := appMCPCommandDeadline(ctx)
	defer cancel()
	policyCtx, release, lease, err := acquireAppMCPWritePolicy(ctx, request.app.Dir)
	if err != nil {
		return outcome, err
	}
	defer release()
	conn, err := request.app.DB.Conn(policyCtx)
	if err != nil {
		return outcome, err
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			outcome.CleanupErr = errors.Join(outcome.CleanupErr, closeErr)
		}
	}()
	discardConn := false
	// Conn.Raw treats ErrBadConn as a disposal request. Run that only after
	// the transaction rollback defer below has released database/sql's Tx
	// connection lease, or Raw can deadlock waiting on its own live Tx.
	defer func() {
		if !discardConn {
			return
		}
		if err := conn.Raw(func(any) error { return driver.ErrBadConn }); err != nil && !errors.Is(err, driver.ErrBadConn) {
			outcome.CleanupErr = errors.Join(outcome.CleanupErr, err)
		}
	}()
	if err := policyCtx.Err(); err != nil {
		return outcome, err
	}
	if err := conn.Raw(func(raw any) error {
		if _, ok := raw.(*sqlite3.SQLiteConn); !ok {
			return errors.New("command connection is not a SQLite connection")
		}
		return nil
	}); err != nil {
		return outcome, err
	}
	if err := policyCtx.Err(); err != nil {
		return outcome, err
	}
	originalBusyTimeout, err := appMCPCommandReadBusyTimeout(policyCtx, conn)
	if err != nil {
		return outcome, err
	}
	busyTimeoutChanged := false
	busyTimeoutRestored := true
	defer func() {
		if !busyTimeoutChanged || busyTimeoutRestored {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(policyCtx), 2*time.Second)
		defer cancel()
		if restoreErr := appMCPCommandSetBusyTimeout(cleanupCtx, conn, originalBusyTimeout); restoreErr != nil {
			discardConn = true
			outcome.CleanupErr = errors.Join(outcome.CleanupErr, restoreErr)
		} else {
			busyTimeoutRestored = true
		}
	}()
	// Set this before the first setter: even a failed setter leaves the native
	// connection's actual timeout uncertain until its captured value is read back.
	busyTimeoutChanged = true
	busyTimeoutRestored = false
	if err := appMCPCommandSetBusyTimeout(policyCtx, conn, 0); err != nil {
		return outcome, fmt.Errorf("command BEGIN admission setup failed: %w", err)
	}
	if err := policyCtx.Err(); err != nil {
		return outcome, err
	}
	var tx *sql.Tx
	tx, err = conn.BeginTx(context.WithoutCancel(policyCtx), nil)
	if err != nil {
		return outcome, err
	}
	transactionDone := false
	defer func() {
		if !transactionDone {
			rollbackErr := tx.Rollback()
			transactionDone = true
			if rollbackErr == nil {
				outcome.RollbackConfirmed = true
			} else if !errors.Is(rollbackErr, sql.ErrTxDone) {
				outcome.CleanupErr = errors.Join(outcome.CleanupErr, rollbackErr)
			}
		}
	}()
	cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(policyCtx), 2*time.Second)
	if restoreErr := appMCPCommandSetBusyTimeout(cleanupCtx, tx, originalBusyTimeout); restoreErr != nil {
		discardConn = true
		outcome.CleanupErr = errors.Join(outcome.CleanupErr, restoreErr)
		cleanupCancel()
		return outcome, fmt.Errorf("command BEGIN admission cleanup failed: %w", restoreErr)
	}
	busyTimeoutRestored = true
	cleanupCancel()
	if err := policyCtx.Err(); err != nil {
		return outcome, err
	}
	if err := (appMCPContextTx{tx: tx, ctx: policyCtx, private: true}).cleanMain(); err != nil {
		return outcome, fmt.Errorf("command connection namespace is not clean: %w", err)
	}
	if !appMCPGenerationCurrent(request.app, request.generation) || validateAppMCPWriteManifest(request.app.Dir, request.generation.manifest) != nil {
		return outcome, errors.New("command source generation is stale")
	}
	state, err := lease.read()
	if err != nil || state.App != lease.key || state.ApprovedWrites == nil || !*state.ApprovedWrites || state.ApprovedWriteEpoch == "" {
		if err == nil {
			err = errors.New("private command write authority is disabled")
		}
		return outcome, err
	}
	tool, flow, err := appMCPFindCommandDeclaration(request.generation, request.toolName)
	if err != nil {
		return outcome, err
	}
	var actor Session
	var tenant string
	var actorCreated string
	var autoApproveTools []string
	autoApproveLive, autoApproveOwnerOn := false, false
	switch request.origin.kind {
	case appMCPCommandConnectorOrigin:
		pin := request.origin.connector
		if pin == nil || pin.Origin != request.app || pin.Generation != request.generation || pin.AppID != state.App || pin.Epoch != state.Epoch || pin.WriteEpoch != state.ApprovedWriteEpoch {
			return outcome, errors.New("connector command authority does not match the locked owner")
		}
		snapshot, err := appMCPWriteAuthorityForTx(policyCtx, tx, *pin, request.now)
		if err != nil {
			return outcome, err
		}
		actor, tenant, actorCreated = snapshot.Actor, snapshot.Tenant, snapshot.UserCreated
		autoApproveTools, autoApproveLive, autoApproveOwnerOn = snapshot.AutoApproveTools, snapshot.AutoApproveLive, snapshot.AutoApproveOwnerOn
	case appMCPCommandSessionOrigin:
		actor, tenant, actorCreated, err = appMCPCommandSessionAuthority(policyCtx, request.generation, tx, request.origin.sessionID, tool)
		if err != nil {
			return outcome, err
		}
	}
	if err := appMCPCommandScopes(actor, tool); err != nil {
		return outcome, err
	}
	enrollment, err := verifyAppMCPRevisionEnrollmentForTx(policyCtx, request.app, request.generation, tx, lease)
	if err != nil {
		return outcome, err
	}
	command := flow.Command
	for _, table := range append(append([]string(nil), command.Writes...), appMCPCommandDependencyTables(command)...) {
		if !slices.Contains(enrollment.record.TableNames, table) {
			return outcome, fmt.Errorf("command table %q is outside the active enrollment", table)
		}
	}
	var originPin *appMCPWriteAuthorityPin
	if request.origin.connector != nil {
		pin := *request.origin.connector
		pin.Permissions = append([]string(nil), pin.Permissions...)
		originPin = &pin
	}
	cap := &appMCPCommandCapability{ctx: policyCtx, app: request.app, generation: request.generation, tool: tool, flow: flow, command: command,
		actor: actor, actorCreated: actorCreated, origin: request.origin.kind, tenant: tenant, epoch: state.Epoch, writeEpoch: state.ApprovedWriteEpoch,
		originPin: originPin, sessionID: request.origin.sessionID, readOnlyStatus: request.readOnlyStatus,
		autoApproveTools: autoApproveTools, autoApproveLive: autoApproveLive, autoApproveOwnerOn: autoApproveOwnerOn,
		conn: conn, tx: tx, lease: lease, enrollment: enrollment, budget: &appMCPCommandBudget{}}
	cap.enrollment.sourceVerificationScope = &cap.sourceVerificationScope
	if tool.Transfer != nil && tool.Transfer.Kind == "push" {
		cap.exportEpoch = state.ExternalExportEpoch
		if !request.readOnlyStatus && (!state.ExternalExport || cap.exportEpoch == "") {
			return outcome, errors.New("external export is disabled")
		}
	}
	defer func() {
		cap.sourceVerificationScope = false
		cap.closed = true
	}()
	guardRestored := false
	defer func() {
		if !guardRestored && cap.guard != nil {
			guard := cap.guard
			cleanupErr := cap.restoreConnectionGuard()
			if guard.discardConn {
				discardConn = true
				if cleanupErr == nil {
					guard.markConnectionUncertain(nil)
					cleanupErr = guard.cleanupErr
				}
			}
			if cleanupErr != nil {
				outcome.CleanupErr = errors.Join(outcome.CleanupErr, cleanupErr)
			}
		}
	}()
	if err := cap.installConnectionGuard(); err != nil {
		return outcome, err
	}
	if err := policyCtx.Err(); err != nil {
		return outcome, err
	}
	commit, err := use(cap)
	if err != nil {
		return outcome, err
	}
	if err := cap.validateLifetime(); err != nil {
		return outcome, err
	}
	if commit {
		guard := cap.guard
		if err := cap.beginFinalization(); err != nil {
			return outcome, err
		}
		var barrier appMCPCommandCommitBarrier
		var finalizeErr, finalizeCleanupErr error
		func() {
			defer func() { finalizeCleanupErr = cap.endFinalization() }()
			barrier, finalizeErr = finalize(cap, time.Now().UTC())
		}()
		if guard != nil && guard.discardConn {
			discardConn = true
			if finalizeCleanupErr == nil {
				guard.markConnectionUncertain(nil)
				finalizeCleanupErr = guard.cleanupErr
			}
		}
		if finalizeCleanupErr != nil {
			outcome.CleanupErr = errors.Join(outcome.CleanupErr, finalizeCleanupErr)
			return outcome, finalizeErr
		}
		if finalizeErr != nil {
			return outcome, finalizeErr
		}
		if err := cap.validateLifetime(); err != nil {
			return outcome, err
		}
		if err := cap.restoreConnectionGuard(); err != nil {
			if guard != nil && guard.discardConn {
				discardConn = true
			}
			outcome.CleanupErr = errors.Join(outcome.CleanupErr, err)
			return outcome, nil
		}
		guardRestored = true
		if err := policyCtx.Err(); err != nil {
			return outcome, err
		}
		if !barrier.ValidUntil.IsZero() && !time.Now().UTC().Before(barrier.ValidUntil) {
			return outcome, errors.New("command commit barrier expired")
		}
		// Recheck the complete source immediately before the business transaction
		// can become authoritative. The per-phase scope is no longer trusted past
		// this boundary.
		cap.sourceVerificationScope = false
		if err := cap.validateLifetime(); err != nil {
			return outcome, err
		}
		outcome.State = appMCPCommandCommitUnknown
		if err := tx.Commit(); err != nil {
			transactionDone = true
			return outcome, fmt.Errorf("command outer commit outcome is unknown: %w", err)
		}
		transactionDone = true
		outcome.State = appMCPCommandCommitConfirmed
		return outcome, nil
	}
	guard := cap.guard
	cleanupErr := cap.restoreConnectionGuard()
	if guard != nil && guard.discardConn {
		discardConn = true
		if cleanupErr == nil {
			guard.markConnectionUncertain(nil)
			cleanupErr = guard.cleanupErr
		}
	}
	if cleanupErr != nil {
		outcome.CleanupErr = errors.Join(outcome.CleanupErr, cleanupErr)
		return outcome, nil
	}
	guardRestored = true
	return outcome, nil
}

func appMCPCommandSessionAuthority(ctx context.Context, generation *appMCPRuntimeGeneration, tx *sql.Tx, sessionID string, tool *AppMCPTool) (Session, string, string, error) {
	if ctx == nil || generation == nil || generation.view == nil || tx == nil || sessionID == "" || len(sessionID) > 512 || tool == nil {
		return Session{}, "", "", errAppMCPGrantDenied
	}
	// An absent session is a denial; a failed read (busy, I/O, cancelled) is
	// not, so it surfaces as unavailable_provider instead of "denied".
	stored, loadErr := loadStoredSessionChecked(tx, true, sessionID)
	if loadErr != nil {
		return Session{}, "", "", loadErr
	}
	if stored == nil || stored.ID != sessionID || stored.UserID <= 0 || stored.ImpersonatorUserID != 0 || stored.ActingAsGroup != "" {
		return Session{}, "", "", errAppMCPGrantDenied
	}
	tenant := stored.GroupID
	if generation.view.Group != nil && generation.view.Group.Table != "" && (tenant == "" || tenant == "0") {
		return Session{}, "", "", errAppMCPGrantDenied
	}
	var group *string
	if tenant != "" {
		group = &tenant
	}
	actor, err := loadScheduledActorWith(generation.view, tx, stored.UserID, group, true)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return Session{}, "", "", fmt.Errorf("session authority: %w", ctxErr)
	}
	// An actor row that is absent, deactivated or no longer matches is a
	// denial; a failed read (busy, I/O) is not.
	var readFailure *scheduledActorReadError
	if errors.As(err, &readFailure) {
		return Session{}, "", "", err
	}
	if err != nil || actor == nil || actor.Email != stored.Email || actor.UserID != stored.UserID {
		return Session{}, "", "", errAppMCPGrantDenied
	}
	var actorCreated string
	createdErr := tx.QueryRow("SELECT COALESCE(created_at,'') FROM main._benmore_users WHERE id=?", stored.UserID).Scan(&actorCreated)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return Session{}, "", "", fmt.Errorf("session authority: %w", ctxErr)
	}
	if createdErr != nil && !errors.Is(createdErr, sql.ErrNoRows) {
		return Session{}, "", "", fmt.Errorf("session authority: read account incarnation: %w", createdErr)
	}
	if createdErr != nil || actorCreated == "" {
		return Session{}, "", "", errAppMCPGrantDenied
	}
	// A native session has no connector scopes to widen its authority. Its
	// current stored scopes are intersected with current role policy and the
	// source-owned command declaration.
	stored.Scopes = intersectScopes(stored.Scopes, actor.Scopes)
	stored.Scopes = intersectScopes(stored.Scopes, strings.Join(tool.Permissions, " "))
	if stored.Scopes == "_none_:read" || stored.Scopes == "" || !scopesWithin(stored.Scopes, strings.Join(tool.Permissions, " ")) {
		return Session{}, "", "", errAppMCPGrantDenied
	}
	stored.Roles = append([]string(nil), actor.Roles...)
	stored.Permissions = strings.Fields(stored.Scopes)
	stored.GlobalAdmin = actor.GlobalAdmin
	return *stored, tenant, actorCreated, nil
}
