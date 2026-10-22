//go:build !cli

package main

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
)

type appMCPOperationLifecyclePlan struct {
	origin            *App
	db                *sql.DB
	appDir            string
	mainPath          string
	ownerID           string
	needed            bool
	command           bool
	fresh             bool
	reload            bool
	operationsPresent bool
	approvalsPresent  bool
	attemptsPresent   bool
	addAttempts       bool // provisioned before attempt history: add the empty table at finish
	statePresent      bool
	key               []byte
	state             *appEncryptionState
	ciphertext        string
	currentKey        []byte
}

func appMCPBoundLifecycleKey(app *App) []byte {
	if app == nil {
		return nil
	}
	app.mu.RLock()
	appEnvStore.mu.RLock()
	secret := app.environment["ENCRYPTION_KEY"]
	appEnvStore.mu.RUnlock()
	app.mu.RUnlock()
	if secret == "" {
		return nil
	}
	key, err := cryptoDeriveAppKey(secret)
	if err != nil || len(key) != 32 {
		return nil
	}
	return key
}

func appMCPCheckLifecyclePlanOwner(app *App, plan *appMCPOperationLifecyclePlan) error {
	if app == nil || plan == nil || app != plan.origin || app.DB == nil || app.DB != plan.db {
		return errors.New("operation lifecycle plan belongs to another app")
	}
	appDir, err := filepath.Abs(app.Dir)
	if err != nil || realPathForContainment(appDir) != plan.appDir {
		return errors.New("operation lifecycle app identity changed after preflight")
	}
	ownerID, err := appMCPOperationOwnerID(app.Dir)
	if err != nil || ownerID != plan.ownerID {
		return errors.New("operation lifecycle app identity changed after preflight")
	}
	return nil
}

func appMCPCommandNeeded(config *runtimeConfig) (bool, error) {
	if config == nil || config.mcp == nil {
		return false, nil
	}
	commands := map[string]int{}
	for _, flow := range config.flows {
		if flow.Command != nil {
			commands[flow.Name]++
		}
	}
	bindings := map[string]int{}
	for _, tool := range config.mcp.Tools {
		if tool.Handler.Kind == "flow" && tool.Handler.Operation == "command" {
			bindings[tool.Handler.Flow]++
		}
	}
	for name, count := range commands {
		if count != 1 || bindings[name] != 1 {
			return false, errors.New("operation lifecycle requires an accepted single command binding")
		}
	}
	for name, count := range bindings {
		if count != 1 || commands[name] != 1 {
			return false, errors.New("operation lifecycle command binding is unresolved")
		}
	}
	return len(commands) > 0, nil
}

func appMCPConfiguredLifecycleKey(config *runtimeConfig, env map[string]string) ([]byte, error) {
	if config == nil || env["ENCRYPTION_KEY"] == "" {
		return nil, errors.New("operation lifecycle requires configured ENCRYPTION_KEY")
	}
	key, err := cryptoDeriveAppKey(env["ENCRYPTION_KEY"])
	if err != nil || len(key) != 32 {
		return nil, errors.New("operation lifecycle encryption key is invalid")
	}
	return key, nil
}

func appMCPKeyMatches(a, b []byte) bool {
	return len(a) == 32 && len(b) == 32 && subtle.ConstantTimeCompare(a, b) == 1
}

func appMCPRequireLifecycleRegistry(app *App, key []byte) error {
	if app == nil || app.DB == nil {
		return errors.New("operation lifecycle database is unavailable")
	}
	registered := cryptoKeysForDBPath(filepath.Join(app.Dir, "data.db"))
	if registered == nil || registered.ephemeral || !appMCPKeyMatches(registered.aes, key) {
		return errors.New("operation lifecycle requires the owning registered encryption key")
	}
	return nil
}

func appMCPObjectExists(ctx context.Context, tx *sql.Tx, name string) (bool, error) {
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM main.sqlite_schema WHERE lower(name)=lower(?)", name).Scan(&count); err != nil {
		return false, err
	}
	return count != 0, nil
}

func appMCPReadLifecycleCiphertext(ctx context.Context, tx *sql.Tx) (string, error) {
	var value string
	if err := tx.QueryRowContext(ctx, "SELECT verification_ciphertext FROM main._benmore_encryption_state WHERE singleton=1").Scan(&value); err != nil {
		return "", err
	}
	return value, nil
}

func appMCPCheckMainDB(ctx context.Context, tx *sql.Tx, app *App) (string, error) {
	if ctx == nil || tx == nil || app == nil || app.DB == nil || ctx.Err() != nil {
		return "", errors.New("invalid operation lifecycle database context")
	}
	if err := (appMCPContextTx{tx: tx, ctx: ctx, private: true}).cleanMain(); err != nil {
		return "", fmt.Errorf("operation lifecycle database isolation failed: %w", err)
	}
	mainPath, err := appMCPReadMainIdentity(ctx, tx)
	if err != nil || mainPath == "" {
		return "", errors.New("operation lifecycle main database is unavailable")
	}
	if canonicalDBPath(mainPath) != canonicalDBPath(filepath.Join(app.Dir, "data.db")) {
		return "", errors.New("operation lifecycle database does not belong to its app")
	}
	return mainPath, nil
}

func appMCPReadMainIdentity(ctx context.Context, tx *sql.Tx) (string, error) {
	if ctx == nil || tx == nil || ctx.Err() != nil {
		return "", errors.New("invalid operation lifecycle main identity query")
	}
	var path string
	if err := tx.QueryRowContext(ctx, "SELECT file FROM main.pragma_database_list WHERE name='main'").Scan(&path); err != nil {
		return "", err
	}
	return canonicalDBPath(path), nil
}

// verifyAppMCPCommandStorageWithKey confirms that the complete V2 command
// schema is present under the authenticated owner marker. It deliberately
// leaves transaction ownership with its caller.
func verifyAppMCPCommandStorageWithKey(ctx context.Context, tx *sql.Tx, appID string, key []byte) (*appEncryptionState, error) {
	if ctx == nil || tx == nil || ctx.Err() != nil || !appMCPOperationHex(appID, 32) || len(key) != 32 {
		return nil, errors.New("invalid command storage verification context")
	}
	if err := (appMCPContextTx{tx: tx, ctx: ctx, private: true}).cleanMain(); err != nil {
		return nil, fmt.Errorf("command storage database isolation failed: %w", err)
	}
	if err := verifyAppMCPOperationStorage(ctx, tx); err != nil {
		return nil, err
	}
	if err := verifyAppMCPCommandApprovalStorage(ctx, tx); err != nil {
		return nil, err
	}
	if err := verifyAppMCPCommandAttemptStorage(ctx, tx); err != nil {
		return nil, err
	}
	state, err := readAppEncryptionState(ctx, tx, appID, key)
	if err != nil || state == nil || state.CommandStorageVersion != 2 || !state.OperationStorageProvisioned {
		return nil, errors.New("command storage marker is not provisioned")
	}
	return state, nil
}

func preflightAppMCPOperationLifecycle(ctx context.Context, app *App, config *runtimeConfig, nextEnv map[string]string, reload bool) (*appMCPOperationLifecyclePlan, error) {
	if ctx == nil || ctx.Err() != nil || app == nil || app.DB == nil {
		return nil, errors.New("invalid operation lifecycle preflight")
	}
	needed, err := appMCPCommandNeeded(config)
	if err != nil {
		return nil, err
	}
	appDir, err := filepath.Abs(app.Dir)
	if err != nil {
		return nil, errors.New("cannot resolve operation lifecycle application identity")
	}
	ownerID, err := appMCPOperationOwnerID(app.Dir)
	if err != nil {
		return nil, err
	}
	plan := &appMCPOperationLifecyclePlan{origin: app, db: app.DB, appDir: realPathForContainment(appDir), ownerID: ownerID, needed: needed, command: needed, reload: reload}
	if needed {
		plan.key, err = appMCPConfiguredLifecycleKey(config, nextEnv)
		if err != nil {
			return nil, err
		}
	}
	tx, err := app.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, errors.New("operation lifecycle preflight transaction failed")
	}
	defer tx.Rollback()
	mainPath, err := appMCPReadMainIdentity(ctx, tx)
	if err != nil {
		return nil, errors.New("operation lifecycle main database identity cannot be inspected")
	}
	plan.mainPath = mainPath
	operations, err := appMCPObjectExists(ctx, tx, "_benmore_mcp_operations")
	if err != nil {
		return nil, errors.New("operation storage presence cannot be inspected")
	}
	stateExists, err := appMCPObjectExists(ctx, tx, "_benmore_encryption_state")
	if err != nil {
		return nil, errors.New("encryption state presence cannot be inspected")
	}
	approvals, err := appMCPObjectExists(ctx, tx, "_benmore_mcp_command_approvals")
	if err != nil {
		return nil, errors.New("command approval storage presence cannot be inspected")
	}
	attempts, err := appMCPObjectExists(ctx, tx, "_benmore_mcp_command_attempts")
	if err != nil {
		return nil, errors.New("command attempt storage presence cannot be inspected")
	}
	plan.operationsPresent, plan.approvalsPresent, plan.attemptsPresent, plan.statePresent = operations, approvals, attempts, stateExists
	if !needed && !operations && !approvals && !attempts && !stateExists {
		return plan, nil
	}
	if !needed && (operations || approvals || attempts || stateExists) {
		// Existing private state remains protected even after its declaration is removed.
		needed = true
		plan.needed = true
		if plan.key == nil {
			plan.key, err = appMCPConfiguredLifecycleKey(config, nextEnv)
			if err != nil {
				return nil, err
			}
		}
	}
	// Only protected command/storage paths inspect bound environment state or
	// the registered owner key. Ordinary no-op loads must not take that lock.
	if reload {
		plan.currentKey = appMCPBoundLifecycleKey(app)
		if !appMCPKeyMatches(plan.currentKey, plan.key) {
			return nil, errors.New("operation lifecycle key change requires verified maintenance rotation")
		}
		if err := appMCPRequireLifecycleRegistry(app, plan.key); err != nil {
			return nil, err
		}
	}
	if needed && plan.key == nil {
		return nil, errors.New("operation lifecycle requires configured ENCRYPTION_KEY")
	}
	mainPath, err = appMCPCheckMainDB(ctx, tx, app)
	if err != nil {
		return nil, err
	}
	if canonicalDBPath(mainPath) != plan.mainPath {
		return nil, errors.New("operation lifecycle main database changed during preflight")
	}
	if registered := cryptoKeysForDBPath(mainPath); registered != nil && (registered.ephemeral || !appMCPKeyMatches(registered.aes, plan.key)) {
		return nil, errors.New("operation lifecycle configured key differs from registered key")
	}
	if !operations && !approvals && !attempts && !stateExists {
		plan.fresh = true
		return plan, nil
	}
	// Operations, approvals and the marker without the attempts table are storage
	// provisioned before attempt history existed: the upgrade adds the empty table.
	addAttempts := operations && approvals && !attempts && stateExists
	if !addAttempts && (operations != approvals || approvals != attempts || !stateExists) {
		return nil, errors.New("command storage and encryption state are incomplete; reviewed maintenance is required")
	}
	var state *appEncryptionState
	if operations && approvals && attempts {
		state, err = verifyAppMCPCommandStorageWithKey(ctx, tx, ownerID, plan.key)
		if err != nil {
			return nil, errors.New("command storage readiness verification failed")
		}
	} else if addAttempts {
		if err := verifyAppMCPOperationStorage(ctx, tx); err != nil {
			return nil, errors.New("command storage readiness verification failed")
		}
		if err := verifyAppMCPCommandApprovalStorage(ctx, tx); err != nil {
			return nil, errors.New("command storage readiness verification failed")
		}
		state, err = readAppEncryptionStateMode(ctx, tx, ownerID, plan.key, true)
		if err != nil || state == nil || state.CommandStorageVersion != 2 || !state.OperationStorageProvisioned {
			return nil, errors.New("command storage readiness verification failed")
		}
		plan.addAttempts = true
	} else {
		state, err = readAppEncryptionState(ctx, tx, ownerID, plan.key)
		if err != nil || state == nil {
			return nil, errors.New("operation encryption state verification failed")
		}
		if state.CommandStorageVersion != 0 || state.OperationStorageProvisioned {
			return nil, errors.New("previously provisioned command storage is missing")
		}
		if plan.command {
			return nil, errors.New("operation storage lifecycle upgrade is required")
		}
	}
	plan.state = state
	plan.ciphertext, err = appMCPReadLifecycleCiphertext(ctx, tx)
	if err != nil {
		return nil, errors.New("operation encryption state ciphertext cannot be captured")
	}
	if reload && (!appMCPKeyMatches(plan.currentKey, plan.key) || appMCPRequireLifecycleRegistry(app, plan.key) != nil) {
		return nil, errors.New("operation lifecycle reload requires the unchanged owning key")
	}
	if registered := cryptoKeysForDBPath(mainPath); registered != nil {
		if registered.ephemeral || !appMCPKeyMatches(registered.aes, plan.key) {
			return nil, errors.New("operation lifecycle registered key differs from configured key")
		}
	}
	return plan, nil
}

func finishAppMCPOperationLifecycle(ctx context.Context, app *App, plan *appMCPOperationLifecyclePlan, checkOnly bool) error {
	if ctx == nil || ctx.Err() != nil || app == nil || app.DB == nil || plan == nil {
		return errors.New("invalid operation lifecycle finalization")
	}
	if err := appMCPCheckLifecyclePlanOwner(app, plan); err != nil {
		return err
	}
	if !plan.needed {
		tx, err := plan.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
		if err != nil {
			return errors.New("operation lifecycle absence check failed")
		}
		defer tx.Rollback()
		mainPath, err := appMCPReadMainIdentity(ctx, tx)
		if err != nil || mainPath != plan.mainPath {
			return errors.New("operation lifecycle main database identity changed after preflight")
		}
		for _, name := range []string{"_benmore_mcp_operations", "_benmore_mcp_command_approvals", "_benmore_mcp_command_attempts", "_benmore_encryption_state"} {
			exists, err := appMCPObjectExists(ctx, tx, name)
			if err != nil || exists {
				return errors.New("operation lifecycle objects appeared after preflight")
			}
		}
		return nil
	}
	if err := appMCPRequireLifecycleRegistry(app, plan.key); err != nil {
		return err
	}
	if plan.reload {
		currentKey := appMCPBoundLifecycleKey(app)
		if !appMCPKeyMatches(currentKey, plan.currentKey) || !appMCPKeyMatches(currentKey, plan.key) {
			return errors.New("operation lifecycle key changed during reload")
		}
	}
	tx, err := app.DB.BeginTx(ctx, nil)
	if err != nil {
		return errors.New("operation lifecycle finalization transaction failed")
	}
	defer tx.Rollback()
	if _, err := appMCPCheckMainDB(ctx, tx, app); err != nil {
		return err
	}
	operations, err := appMCPObjectExists(ctx, tx, "_benmore_mcp_operations")
	if err != nil {
		return errors.New("operation storage presence cannot be rechecked")
	}
	stateExists, err := appMCPObjectExists(ctx, tx, "_benmore_encryption_state")
	if err != nil {
		return errors.New("encryption state presence cannot be rechecked")
	}
	approvals, err := appMCPObjectExists(ctx, tx, "_benmore_mcp_command_approvals")
	if err != nil {
		return errors.New("command approval storage presence cannot be rechecked")
	}
	attempts, err := appMCPObjectExists(ctx, tx, "_benmore_mcp_command_attempts")
	if err != nil {
		return errors.New("command attempt storage presence cannot be rechecked")
	}
	if operations != plan.operationsPresent || approvals != plan.approvalsPresent || attempts != plan.attemptsPresent || stateExists != plan.statePresent {
		return errors.New("operation lifecycle object presence changed after preflight")
	}
	if plan.fresh {
		if operations || approvals || attempts || stateExists {
			return errors.New("operation lifecycle objects changed after preflight")
		}
		if err := initializeAppMCPOperationStorage(ctx, tx); err != nil {
			return err
		}
		if err := initializeAppMCPCommandApprovalStorage(ctx, tx); err != nil {
			return err
		}
		if err := initializeAppMCPCommandAttemptStorage(ctx, tx); err != nil {
			return err
		}
		state, err := initializeAppEncryptionState(ctx, tx, plan.ownerID, plan.key)
		if err != nil || state == nil || !state.OperationStorageProvisioned || state.CommandStorageVersion != 2 {
			return errors.New("command lifecycle schema initialization failed")
		}
		if _, err := verifyAppMCPCommandStorageWithKey(ctx, tx, plan.ownerID, plan.key); err != nil {
			return err
		}
		if checkOnly {
			if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
				return errors.New("operation lifecycle check-only rollback failed")
			}
			return appMCPVerifyLifecycleAbsent(ctx, app)
		}
		if err := tx.Commit(); err != nil {
			return errors.New("operation lifecycle commit outcome is unverified")
		}
		return nil
	}
	if plan.state == nil {
		return errors.New("command lifecycle schema changed after preflight")
	}
	if operations && approvals && attempts {
		if _, err := verifyAppMCPCommandStorageWithKey(ctx, tx, plan.ownerID, plan.key); err != nil {
			return err
		}
	} else if plan.addAttempts && operations && approvals && !attempts {
		if err := verifyAppMCPOperationStorage(ctx, tx); err != nil {
			return err
		}
		if err := verifyAppMCPCommandApprovalStorage(ctx, tx); err != nil {
			return err
		}
		marker, err := readAppEncryptionStateMode(ctx, tx, plan.ownerID, plan.key, true)
		if err != nil || marker == nil || *marker != *plan.state {
			return errors.New("operation encryption state changed after preflight")
		}
		if err := initializeAppMCPCommandAttemptStorage(ctx, tx); err != nil {
			return err
		}
		if _, err := verifyAppMCPCommandStorageWithKey(ctx, tx, plan.ownerID, plan.key); err != nil {
			return err
		}
	} else if plan.state.OperationStorageProvisioned || plan.state.CommandStorageVersion != 0 {
		return errors.New("command lifecycle schema changed after preflight")
	}
	state, err := readAppEncryptionState(ctx, tx, plan.ownerID, plan.key)
	if err != nil || state == nil || plan.state == nil || *state != *plan.state {
		return errors.New("operation encryption state changed after preflight")
	}
	ciphertext, err := appMCPReadLifecycleCiphertext(ctx, tx)
	if err != nil || ciphertext != plan.ciphertext {
		return errors.New("operation encryption state changed after preflight")
	}
	if plan.addAttempts && checkOnly {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			return errors.New("operation lifecycle check-only rollback failed")
		}
		return nil
	}
	if err := tx.Commit(); err != nil {
		return errors.New("operation lifecycle verification commit failed")
	}
	return nil
}

func appMCPVerifyLifecycleAbsent(ctx context.Context, app *App) error {
	tx, err := app.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return errors.New("operation lifecycle absence readback failed")
	}
	defer tx.Rollback()
	if _, err := appMCPCheckMainDB(ctx, tx, app); err != nil {
		return err
	}
	for _, name := range []string{"_benmore_mcp_operations", "_benmore_mcp_command_approvals", "_benmore_mcp_command_attempts", "_benmore_encryption_state"} {
		exists, err := appMCPObjectExists(ctx, tx, name)
		if err != nil || exists {
			return errors.New("operation lifecycle check-only left partial storage")
		}
	}
	return nil
}
