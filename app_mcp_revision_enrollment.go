//go:build !cli

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const (
	appMCPRevisionEnrollmentLimit      = 256 * 1024
	appMCPRevisionEnrollmentTableLimit = 256
	appMCPDependencySelectorLimit      = 64
	appMCPDependencySelectorRowsLimit  = 256
	appMCPDependencyRowsLimit          = 1024
)

type appMCPRevisionEnrollment struct {
	Version      int                             `json:"version"`
	App          string                          `json:"app"`
	OwnerEpoch   string                          `json:"owner_epoch"`
	EnrollmentID string                          `json:"enrollment_id"`
	State        string                          `json:"state"`
	TableNames   []string                        `json:"table_names"`
	Tables       []appMCPRevisionEnrollmentTable `json:"tables"`
}

type appMCPRevisionEnrollmentTable struct {
	Table            string `json:"table"`
	Incarnation      string `json:"incarnation"`
	SchemaDigest     string `json:"schema_digest"`
	TriggerSetDigest string `json:"trigger_set_digest"`
}

type appMCPRevisionEnrollmentOutcomeUnknownError struct{ cause error }

func (e *appMCPRevisionEnrollmentOutcomeUnknownError) Error() string {
	return "revision enrollment activation outcome is unknown: " + e.cause.Error()
}
func (e *appMCPRevisionEnrollmentOutcomeUnknownError) Unwrap() error { return e.cause }

type appMCPRevisionEnrollmentStage string

const (
	appMCPRevisionStageBeforeBegin  appMCPRevisionEnrollmentStage = "before_begin"
	appMCPRevisionStageAfterInstall appMCPRevisionEnrollmentStage = "after_install"
	appMCPRevisionStageAfterVerify  appMCPRevisionEnrollmentStage = "after_verify"
	appMCPRevisionStageBeforeCommit appMCPRevisionEnrollmentStage = "before_commit"
	appMCPRevisionStageAfterCommit  appMCPRevisionEnrollmentStage = "after_commit"
)

// This narrowly scoped test seam models lifecycle failures at their durable
// boundaries. Production leaves it nil; it is not an app-controlled callback.
var appMCPRevisionEnrollmentFault func(string, appMCPRevisionEnrollmentStage) error

func appMCPRevisionFailAt(appDir string, stage appMCPRevisionEnrollmentStage) error {
	if appMCPRevisionEnrollmentFault != nil {
		return appMCPRevisionEnrollmentFault(appDir, stage)
	}
	return nil
}

func initializeAppMCPRevisionEnrollment(ctx context.Context, app *App, generation *appMCPRuntimeGeneration) (*appMCPRevisionEnrollment, error) {
	return changeAppMCPRevisionEnrollment(ctx, app, generation, false)
}

func repairAppMCPRevisionEnrollment(ctx context.Context, app *App, generation *appMCPRuntimeGeneration) (*appMCPRevisionEnrollment, error) {
	return changeAppMCPRevisionEnrollment(ctx, app, generation, true)
}

// enableAppMCPRevisionEnrolledWrites is the only enrollment-aware write-enable
// path. It verifies the full active enrollment and main DB under the same gate
// and owner lease before rotating the owner's write epoch.
func enableAppMCPRevisionEnrolledWrites(ctx context.Context, app *App, generation *appMCPRuntimeGeneration) (*appMCPEpochState, error) {
	return enableAppMCPRevisionEnrolledWritesAs(ctx, app, generation, false)
}

// errAppMCPNothingToResume says the owner state holds no suspended approval
// for the loaded reviewed digests, so a start-up resume does not apply.
var errAppMCPNothingToResume = errors.New("no suspended write approval matches the loaded reviewed digests")

// enableAppMCPRevisionEnrolledWritesAs is the one writer of ApprovedWrites=true.
// resume is the start-up form: it enables only a suspension whose recorded
// digests equal the loaded manifest's, decided under the same owner lease as
// the flip. Either form records the digests writes were approved under.
func enableAppMCPRevisionEnrolledWritesAs(ctx context.Context, app *App, generation *appMCPRuntimeGeneration, resume bool) (*appMCPEpochState, error) {
	if ctx == nil || app == nil || app.DB == nil || generation == nil || generation.origin != app || generation.view == nil {
		return nil, errors.New("write enable requires a captured application generation")
	}
	policyCtx, release, lease, err := acquireAppMCPWritePolicy(ctx, app.Dir)
	if err != nil {
		return nil, err
	}
	defer release()
	tx, err := app.DB.BeginTx(policyCtx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := verifyAppMCPRevisionEnrollmentForTx(policyCtx, app, generation, tx, lease); err != nil {
		return nil, fmt.Errorf("verify revision enrollment before write enable: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("revision enrollment preflight commit outcome is unknown: %w", err)
	}
	if err := validateAppMCPWriteManifest(app.Dir, generation.manifest); err != nil || !appMCPGenerationCurrent(app, generation) {
		if err == nil {
			err = errors.New("revision enrollment source generation changed before write enable")
		}
		return nil, err
	}
	state, err := lease.read()
	if err != nil {
		return nil, err
	}
	if !state.Exposed {
		return nil, errors.New("read authority must be exposed before write authority")
	}
	manifest := generation.manifest
	if resume && (state.Version != 2 || state.ApprovedWrites == nil || *state.ApprovedWrites || manifest == nil || state.ApprovedContractDigest == "" ||
		!SecureCompare(state.ApprovedContractDigest, manifest.ContractDigest) || !SecureCompare(state.ApprovedExecutionDigest, manifest.ExecutionDigest)) {
		return nil, errAppMCPNothingToResume
	}
	if state.Version == 2 && state.ApprovedWrites != nil && *state.ApprovedWrites {
		return state, nil
	}
	if state.Version == 1 {
		state.Version = 2
	}
	writes := true
	state.ApprovedWrites = &writes
	state.ApprovedContractDigest, state.ApprovedExecutionDigest = manifest.ContractDigest, manifest.ExecutionDigest
	if err := rotateAppMCPWriteEpoch(state); err != nil {
		return nil, err
	}
	if err := storeAppMCPEpochWithLease(lease, state); err != nil {
		return nil, err
	}
	return state, nil
}

func changeAppMCPRevisionEnrollment(ctx context.Context, app *App, generation *appMCPRuntimeGeneration, repair bool) (*appMCPRevisionEnrollment, error) {
	if ctx == nil || app == nil || app.DB == nil || generation == nil || generation.origin != app || generation.view == nil {
		return nil, errors.New("revision enrollment requires a captured application generation")
	}
	if !appMCPGenerationCurrent(app, generation) {
		return nil, errors.New("revision enrollment source generation is stale")
	}
	if err := validateAppMCPWriteManifest(app.Dir, generation.manifest); err != nil {
		return nil, fmt.Errorf("verify revision enrollment source: %w", err)
	}
	policyCtx, release, lease, err := acquireAppMCPWritePolicy(ctx, app.Dir)
	if err != nil {
		return nil, err
	}
	defer release()
	if err := policyCtx.Err(); err != nil {
		return nil, err
	}
	if lease == nil || lease.key == "" || canonicalDBPath(lease.path) != canonicalDBPath(app.Dir) {
		return nil, errors.New("revision enrollment requires the matching external owner lease")
	}
	if !appMCPGenerationCurrent(app, generation) {
		return nil, errors.New("revision enrollment source generation changed while acquiring authority")
	}
	if err := validateAppMCPWriteManifest(app.Dir, generation.manifest); err != nil {
		return nil, fmt.Errorf("revision enrollment source changed while acquiring authority: %w", err)
	}
	state, err := lease.read()
	if err != nil {
		return nil, fmt.Errorf("read revision enrollment owner: %w", err)
	}
	if state.App != lease.key {
		return nil, errors.New("revision enrollment owner identity changed")
	}
	preflight, err := app.DB.BeginTx(policyCtx, nil)
	if err != nil {
		return nil, fmt.Errorf("preflight revision enrollment effects: %w", err)
	}
	preflightPath, pathErr := mainDatabasePathForQuerier(&appMCPWriteTxQuerier{ctx: policyCtx, tx: preflight})
	if pathErr != nil || canonicalDBPath(preflightPath) != canonicalDBPath(filepath.Join(app.Dir, "data.db")) {
		if pathErr == nil {
			pathErr = errors.New("revision enrollment preflight belongs to another app database")
		}
		err = pathErr
	}
	var tables []string
	if err == nil {
		tables, err = appMCPRevisionUniverse(preflight, generation, repair)
	}
	if err == nil && !appMCPGenerationCurrent(app, generation) {
		err = errors.New("revision enrollment generation changed during effect preflight")
	}
	if err == nil {
		if sourceErr := validateAppMCPWriteManifest(app.Dir, generation.manifest); sourceErr != nil {
			err = fmt.Errorf("revision enrollment source changed during effect preflight: %w", sourceErr)
		}
	}
	if !repair && err == nil {
		for _, name := range []string{appMCPRevisionTablesName, appMCPRowRevisionsName} {
			exists, existsErr := appMCPRevisionObjectExists(preflight, name)
			if existsErr != nil {
				err = existsErr
				break
			}
			if exists {
				err = errors.New("revision sidecars already exist; use explicit repair")
				break
			}
		}
		if err == nil {
			orphaned, orphanErr := appMCPExistingRevisionTriggers(preflight)
			if orphanErr != nil {
				err = orphanErr
			} else if len(orphaned) != 0 {
				err = errors.New("orphaned revision triggers require explicit repair")
			}
		}
	}
	_ = preflight.Rollback()
	if err != nil {
		return nil, err
	}
	if len(tables) == 0 || len(tables) > appMCPRevisionEnrollmentTableLimit {
		return nil, errors.New("revision enrollment universe is empty or exceeds its bound")
	}
	if err := validateAppMCPRevisionEnrollmentPath(lease, repair); err != nil {
		return nil, err
	}
	if !repair {
		if _, err := lease.root.Lstat(lease.key + ".revisions.json"); err == nil {
			return nil, errors.New("revision enrollment already exists; use explicit repair")
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	}
	if err := invalidateAppMCPWritesWithLease(lease); err != nil {
		return nil, fmt.Errorf("disable owner writes before revision enrollment: %w", err)
	}
	state, err = lease.read()
	if err != nil {
		return nil, fmt.Errorf("read disabled revision enrollment owner: %w", err)
	}
	if state.App != lease.key || state.ApprovedWrites == nil || *state.ApprovedWrites {
		return nil, errors.New("owner writes were not disabled for revision enrollment")
	}
	enrollmentID, err := appMCPRandomHex(32)
	if err != nil {
		return nil, err
	}
	pending := &appMCPRevisionEnrollment{
		Version: 1, App: state.App, OwnerEpoch: state.Epoch, EnrollmentID: enrollmentID,
		State: "pending", TableNames: append([]string(nil), tables...), Tables: []appMCPRevisionEnrollmentTable{},
	}
	if err := writeAppMCPRevisionEnrollmentWithLease(lease, pending); err != nil {
		return nil, fmt.Errorf("persist pending revision enrollment: %w", err)
	}
	if err := appMCPRevisionFailAt(app.Dir, appMCPRevisionStageBeforeBegin); err != nil {
		return nil, fmt.Errorf("injected pre-transaction failure: %w", err)
	}

	// app.DB uses sqliteAppDSN's _txlock=immediate, so BeginTx obtains the
	// writer reservation before inspecting or changing the revision registry.
	tx, err := app.DB.BeginTx(policyCtx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin immediate revision enrollment: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	mainPath, err := mainDatabasePathForQuerier(&appMCPWriteTxQuerier{ctx: policyCtx, tx: tx})
	if err != nil || canonicalDBPath(mainPath) != canonicalDBPath(filepath.Join(app.Dir, "data.db")) {
		if err == nil {
			err = errors.New("revision enrollment transaction belongs to another app database")
		}
		return nil, err
	}
	if err := policyCtx.Err(); err != nil {
		return nil, err
	}
	currentTables, err := appMCPRevisionUniverse(tx, generation, repair)
	if err != nil {
		return nil, err
	}
	if !sameStrings(currentTables, tables) {
		return nil, errors.New("revision enrollment effects changed between preflight and immediate transaction")
	}
	if repair {
		err = repairAppMCPRevisionStorage(tx, tables)
	} else {
		err = initializeAppMCPRevisionStorage(tx, tables)
	}
	if err != nil {
		return nil, fmt.Errorf("install revision enrollment storage: %w", err)
	}
	if err := appMCPRevisionFailAt(app.Dir, appMCPRevisionStageAfterInstall); err != nil {
		return nil, fmt.Errorf("injected post-install failure: %w", err)
	}
	if err := verifyAppMCPRevisionStorage(tx, tables); err != nil {
		return nil, fmt.Errorf("verify revision enrollment storage: %w", err)
	}
	if err := appMCPRevisionFailAt(app.Dir, appMCPRevisionStageAfterVerify); err != nil {
		return nil, fmt.Errorf("injected post-verification failure: %w", err)
	}
	entries, err := appMCPRevisionEnrollmentTables(tx, tables)
	if err != nil {
		return nil, err
	}
	if err := policyCtx.Err(); err != nil {
		return nil, err
	}
	if !appMCPGenerationCurrent(app, generation) {
		return nil, errors.New("revision enrollment source generation changed before commit")
	}
	if err := validateAppMCPWriteManifest(app.Dir, generation.manifest); err != nil {
		return nil, fmt.Errorf("revision enrollment source changed before commit: %w", err)
	}
	if err := appMCPRevisionFailAt(app.Dir, appMCPRevisionStageBeforeCommit); err != nil {
		return nil, fmt.Errorf("injected pre-commit failure: %w", err)
	}
	if err := tx.Commit(); err != nil {
		committed = true // Commit outcome is unknown; leave the durable record pending.
		return nil, fmt.Errorf("revision enrollment commit outcome is unknown: %w", err)
	}
	committed = true
	if err := appMCPRevisionFailAt(app.Dir, appMCPRevisionStageAfterCommit); err != nil {
		return nil, fmt.Errorf("injected post-commit pre-activation failure: %w", err)
	}
	active := &appMCPRevisionEnrollment{
		Version: pending.Version, App: pending.App, OwnerEpoch: pending.OwnerEpoch, EnrollmentID: pending.EnrollmentID,
		State: "active", TableNames: append([]string(nil), pending.TableNames...), Tables: entries,
	}
	if err := writeAppMCPRevisionEnrollmentWithLease(lease, active); err != nil {
		var outcome *appMCPRevisionEnrollmentOutcomeUnknownError
		if errors.As(err, &outcome) {
			return nil, err
		}
		return nil, fmt.Errorf("activate revision enrollment after database commit: %w", err)
	}
	return cloneAppMCPRevisionEnrollment(active), nil
}

func appMCPRevisionUniverse(tx *sql.Tx, generation *appMCPRuntimeGeneration, allowRepair bool) ([]string, error) {
	if tx == nil || generation == nil || generation.manifest == nil || generation.view == nil {
		return nil, errors.New("revision enrollment source or transaction is unavailable")
	}
	appTables := make(map[string]string, len(generation.view.Tables))
	for _, table := range generation.view.Tables {
		if isValidColumnName(table.Name) {
			appTables[strings.ToLower(table.Name)] = table.Name
		}
	}
	resolve := func(name string) (string, error) {
		if !isValidColumnName(name) || strings.HasPrefix(strings.ToLower(name), "_benmore_") || strings.HasPrefix(strings.ToLower(name), "sqlite_") {
			return "", fmt.Errorf("revision enrollment contains an invalid or reserved table %q", name)
		}
		var physical string
		if err := tx.QueryRow(`SELECT name FROM main.sqlite_schema WHERE type='table' AND name=? COLLATE NOCASE`, name).Scan(&physical); err != nil {
			return "", fmt.Errorf("resolve admitted table %q: %w", name, err)
		}
		configured, ok := appTables[strings.ToLower(physical)]
		if !ok || !strings.EqualFold(configured, physical) {
			return "", fmt.Errorf("revision target %q is outside the captured physical app tables", physical)
		}
		return physical, nil
	}
	operations := make(map[string]map[string]bool)
	add := func(table, action string) error {
		physical, err := resolve(table)
		if err != nil {
			return err
		}
		if operations[physical] == nil {
			operations[physical] = make(map[string]bool)
		}
		operations[physical][action] = true
		if len(operations) > appMCPRevisionEnrollmentTableLimit {
			return errors.New("revision enrollment universe exceeds its table bound")
		}
		return nil
	}
	for _, tool := range generation.manifest.Tools {
		if tool.Effect != "write" {
			continue
		}
		if tool.Handler.Kind == "native" && tool.Handler.Operation == "table.update" {
			if err := add(tool.Handler.Table, "update"); err != nil {
				return nil, err
			}
			continue
		}
		if tool.Handler.Kind != "flow" || tool.Handler.Operation != "command" {
			return nil, fmt.Errorf("write tool %q has no admitted revision target contract", tool.Name)
		}
		flow := appMCPCommandFlowByName(generation, tool.Handler.Flow)
		if flow == nil {
			return nil, fmt.Errorf("write tool %q has no captured command descriptor", tool.Name)
		}
		command := flow.Command
		for _, table := range command.Writes {
			// The declaration authorizes only these target tables. Enroll all
			// native row operation classes so declared insert/update/delete
			// commands and their verified trigger closure share one inventory.
			for _, action := range []string{"insert", "update", "delete"} {
				if err := add(table, action); err != nil {
					return nil, err
				}
			}
		}
		for _, table := range appMCPCommandDependencyTables(command) {
			if err := add(table, "read"); err != nil {
				return nil, err
			}
		}
		for _, phase := range []FlowCommandPhase{command.Prepare, command.Apply, command.Readback} {
			for _, table := range phase.ReadTables {
				if err := add(table, "read"); err != nil {
					return nil, err
				}
			}
			for _, table := range phase.WriteTables {
				for _, action := range []string{"insert", "update", "delete"} {
					if err := add(table, action); err != nil {
						return nil, err
					}
				}
			}
		}
	}
	if len(operations) == 0 {
		return nil, errors.New("revision enrollment has no admitted write targets")
	}
	if err := appMCPValidateComputedRevisionEffects(generation); err != nil {
		return nil, err
	}
	// Hooks run inside command transactions, so scan update hooks only on
	// tables with an admitted write operation. Read-only dependencies stay in
	// the revision universe without pulling in unrelated hooks. Insert and
	// delete hooks are added below for actions the command apply steps write.
	hookScans := make(map[string]map[string]bool)
	for table, actions := range operations {
		if actions["insert"] || actions["update"] || actions["delete"] {
			hookScans[table] = map[string]bool{"update": true}
		}
	}
	for _, tool := range generation.manifest.Tools {
		if tool.Effect != "write" || tool.Handler.Kind != "flow" || tool.Handler.Operation != "command" {
			continue
		}
		if flow := appMCPCommandFlowByName(generation, tool.Handler.Flow); flow != nil {
			for table, actions := range appMCPCommandApplyWrites(flow.Command) {
				physical, err := resolve(table)
				if err != nil {
					return nil, err
				}
				if hookScans[physical] == nil {
					hookScans[physical] = make(map[string]bool)
				}
				for action := range actions {
					hookScans[physical][action] = true
				}
			}
		}
	}
	for table, actions := range hookScans {
		if generation.hooks == nil {
			continue
		}
		for action := range actions {
			before, on := appMCPHookSets(generation.hooks, action)
			for _, hooks := range [][]Hook{appMCPHooksForTable(before, table), appMCPHooksForTable(on, table)} {
				for _, hook := range hooks {
					if hook.SQL == "" {
						continue
					}
					writes, err := appMCPRevisionHookWrites(hook.SQL)
					if err != nil {
						return nil, fmt.Errorf("unsupported admitted %s hook on %q: %w", action, table, err)
					}
					for _, write := range writes {
						// Framework-owned inbox rows have no revision ledger;
						// hooks may write them, command SQL may not.
						if appMCPCommandHookFrameworkTable(write.Table) {
							continue
						}
						if err := add(write.Table, write.Action); err != nil {
							return nil, err
						}
					}
				}
			}
		}
	}
	// App-authored triggers a write command declares (app_mcp_app_triggers.go).
	// A trigger that can fire from an admitted write extends the universe with
	// its own body writes; resolve refuses _benmore_* and non-app targets.
	appTriggers, err := appMCPDeclaredAppTriggers(generation)
	if err != nil {
		return nil, err
	}
	for changed := true; changed; {
		changed = false
		for _, trigger := range appTriggers {
			on, err := resolve(trigger.table)
			if err != nil {
				return nil, fmt.Errorf("app trigger %q table: %w", trigger.name, err)
			}
			if !operations[on][trigger.events[0]] {
				continue
			}
			// The apply authorizer admits a read only of a table in the
			// universe, so the lookup tables the trigger selects from join it.
			for _, name := range trigger.reads {
				target, err := resolve(name)
				if err != nil {
					return nil, fmt.Errorf("app trigger %q read table: %w", trigger.name, err)
				}
				if len(operations[target]) == 0 {
					if err := add(target, "read"); err != nil {
						return nil, err
					}
					changed = true
				}
			}
			for _, write := range trigger.writes {
				target, err := resolve(write.Table)
				if err != nil {
					return nil, fmt.Errorf("app trigger %q write target: %w", trigger.name, err)
				}
				if !operations[target][write.Action] {
					if err := add(target, write.Action); err != nil {
						return nil, err
					}
					changed = true
				}
			}
		}
		if generation.computed != nil {
			for _, columns := range generation.computed.Fields {
				for _, field := range columns {
					if field == nil || field.Table == "" || field.Column == "" {
						return nil, errors.New("captured computed effect definition is incomplete")
					}
					for _, trigger := range field.Triggers {
						for _, event := range trigger.On {
							if appMCPHasRevisionOperation(operations, trigger.Table, event) {
								target, err := resolve(field.Table)
								if err != nil {
									return nil, fmt.Errorf("computed effect target: %w", err)
								}
								if !operations[target]["update"] {
									if err := add(target, "update"); err != nil {
										return nil, err
									}
									changed = true
								}
							}
						}
					}
				}
			}
		}
		fkEffects, err := appMCPRevisionForeignKeyEffects(tx, appTables, operations, resolve)
		if err != nil {
			return nil, err
		}
		for _, effect := range fkEffects {
			if operations[effect.parent][effect.parentAction] && !operations[effect.child][effect.childAction] {
				if err := add(effect.child, effect.childAction); err != nil {
					return nil, err
				}
				changed = true
			}
		}
	}
	tables := make([]string, 0, len(operations))
	for table := range operations {
		tables = append(tables, table)
	}
	sort.Strings(tables)
	if len(tables) > appMCPRevisionEnrollmentTableLimit {
		return nil, errors.New("revision enrollment universe exceeds its table bound")
	}
	if err := verifyAppMCPDeclaredTriggerClosure(tx, generation, tables, allowRepair); err != nil {
		return nil, err
	}
	return tables, nil
}

func appMCPValidateComputedRevisionEffects(generation *appMCPRuntimeGeneration) error {
	if generation == nil || generation.computed == nil {
		return nil
	}
	for _, fields := range generation.computed.Fields {
		for _, field := range fields {
			if field == nil || !appMCPValidGeneratedSQLIdentifier(field.Table) || !appMCPValidGeneratedSQLIdentifier(field.Column) {
				return errors.New("computed revision effect has an invalid table or column identifier")
			}
			if field.Expr != "" {
				hasPlaceholder := false
				for _, token := range sqlTokenize(field.Expr) {
					if token.kind == sqlTokPunct && token.text == "?" {
						hasPlaceholder = true
					}
				}
				if _, err := normalizeAppMCPRevisionSQL(field.Expr); err != nil || hasPlaceholder || !appMCPBalancedSQLParens(field.Expr) || !isReadOnlyQuery("SELECT ("+field.Expr+")") {
					return fmt.Errorf("computed expression for %s.%s is not one admitted expression", field.Table, field.Column)
				}
			}
			if field.SQL != "" {
				if _, err := normalizeAppMCPRevisionSQL(field.SQL); err != nil || !appMCPBalancedSQLParens(field.SQL) {
					return fmt.Errorf("computed query for %s.%s has malformed SQL quoting", field.Table, field.Column)
				}
				writes, statements := sqlWriteTargets(field.SQL)
				placeholders := 0
				placeholderOffset := -1
				for _, token := range sqlTokenize(field.SQL) {
					if token.kind == sqlTokPunct && token.text == "?" {
						placeholders++
						placeholderOffset = token.start
					}
				}
				if statements != 1 || len(writes) != 0 || placeholders != 1 || placeholderOffset != strings.Index(field.SQL, "?") || !isReadOnlyQuery(field.SQL) {
					return fmt.Errorf("computed query for %s.%s is not one read-only query", field.Table, field.Column)
				}
			}
			for _, trigger := range field.Triggers {
				if !appMCPValidGeneratedSQLIdentifier(trigger.Table) || !appMCPValidGeneratedSQLIdentifier(trigger.FK) {
					return fmt.Errorf("computed trigger for %s.%s has an invalid source identifier", field.Table, field.Column)
				}
				for _, event := range trigger.On {
					if event != "insert" && event != "update" && event != "delete" {
						return fmt.Errorf("unsupported computed trigger event %q", event)
					}
				}
			}
		}
	}
	return nil
}

func appMCPValidGeneratedSQLIdentifier(name string) bool {
	if !isValidColumnName(name) {
		return false
	}
	first := name[0]
	return first == '_' || first >= 'a' && first <= 'z' || first >= 'A' && first <= 'Z'
}

func appMCPBalancedSQLParens(query string) bool {
	depth := 0
	valid := true
	_ = scanSQLBytes(query, func(b byte, kind sqlByteKind) error {
		if kind != sqlCode {
			return nil
		}
		switch b {
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				valid = false
			}
		case ';':
			valid = false
		}
		return nil
	})
	return valid && depth == 0
}

func cloneRevisionOperations(src map[string]map[string]bool) map[string]map[string]bool {
	clone := make(map[string]map[string]bool, len(src))
	for table, actions := range src {
		clone[table] = make(map[string]bool, len(actions))
		for action, enabled := range actions {
			clone[table][action] = enabled
		}
	}
	return clone
}

func appMCPHasRevisionOperation(operations map[string]map[string]bool, table, action string) bool {
	for actual, actions := range operations {
		if strings.EqualFold(actual, table) && actions[action] {
			return true
		}
	}
	return false
}

func appMCPHooksForTable(hooks map[string][]Hook, table string) []Hook {
	for name, items := range hooks {
		if strings.EqualFold(name, table) {
			return items
		}
	}
	return nil
}

func appMCPRevisionHookWrites(query string) ([]sqlWrite, error) {
	var writes []sqlWrite
	var statement []sqlToken
	flush := func() error {
		if len(statement) == 0 {
			return nil
		}
		if write, ok := sqlStatementWrite(statement); ok {
			writes = append(writes, write)
			statement = statement[:0]
			return nil
		}
		verb := appMCPRevisionStatementVerb(statement)
		statement = statement[:0]
		if verb != "SELECT" && verb != "VALUES" {
			return fmt.Errorf("SQL statement verb %q is outside the supported read/write set", verb)
		}
		return nil
	}
	for _, token := range sqlTokenize(query) {
		if token.kind == sqlTokPunct && token.text == ";" {
			if err := flush(); err != nil {
				return nil, err
			}
			continue
		}
		statement = append(statement, token)
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return writes, nil
}

func appMCPRevisionStatementVerb(tokens []sqlToken) string {
	if len(tokens) == 0 {
		return ""
	}
	word := func(i int) string {
		if i < len(tokens) && tokens[i].kind == sqlTokWord {
			return strings.ToUpper(tokens[i].text)
		}
		return ""
	}
	if word(0) != "WITH" {
		return word(0)
	}
	depth := 0
	for i := 1; i < len(tokens); i++ {
		if tokens[i].kind == sqlTokPunct {
			switch tokens[i].text {
			case "(":
				depth++
			case ")":
				if depth > 0 {
					depth--
				}
			}
			continue
		}
		if depth == 0 {
			switch word(i) {
			case "SELECT", "VALUES", "INSERT", "REPLACE", "UPDATE", "DELETE":
				return word(i)
			}
		}
	}
	return "WITH"
}

type appMCPRevisionForeignKeyEffect struct {
	parent, parentAction, child, childAction string
}

func appMCPRevisionForeignKeyEffects(tx *sql.Tx, appTables map[string]string, operations map[string]map[string]bool, resolve func(string) (string, error)) ([]appMCPRevisionForeignKeyEffect, error) {
	var effects []appMCPRevisionForeignKeyEffect
	seen := make(map[string]bool)
	rows, err := tx.Query(`SELECT name FROM main.sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		return nil, err
	}
	var children []string
	for rows.Next() {
		var child string
		if err := rows.Scan(&child); err != nil {
			rows.Close()
			return nil, err
		}
		children = append(children, child)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for _, child := range children {
		rows, err := tx.Query("PRAGMA main.foreign_key_list(" + quoteIdent(child) + ")")
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id, seq int
			var parent, from, to, onUpdate, onDelete, match string
			if err := rows.Scan(&id, &seq, &parent, &from, &to, &onUpdate, &onDelete, &match); err != nil {
				rows.Close()
				return nil, err
			}
			for _, transition := range []struct{ action, parentAction string }{{strings.ToUpper(onUpdate), "update"}, {strings.ToUpper(onDelete), "delete"}} {
				if !appMCPHasRevisionOperation(operations, parent, transition.parentAction) {
					continue
				}
				childAction := ""
				switch transition.action {
				case "NO ACTION", "RESTRICT":
				case "CASCADE":
					childAction = transition.parentAction
				case "SET NULL", "SET DEFAULT":
					childAction = "update"
				default:
					rows.Close()
					return nil, fmt.Errorf("unknown foreign key action %q", transition.action)
				}
				if childAction != "" {
					physicalParent, resolveErr := resolve(parent)
					if resolveErr != nil {
						rows.Close()
						return nil, fmt.Errorf("foreign key effect: %w", resolveErr)
					}
					physicalChild, resolveErr := resolve(child)
					if resolveErr != nil || appTables[strings.ToLower(child)] == "" {
						rows.Close()
						return nil, fmt.Errorf("foreign-key cascade from enrolled parent reaches unsupported non-app table %q", child)
					}
					key := physicalParent + "\x00" + transition.parentAction + "\x00" + physicalChild + "\x00" + childAction
					if !seen[key] {
						seen[key] = true
						effects = append(effects, appMCPRevisionForeignKeyEffect{parent: physicalParent, parentAction: transition.parentAction, child: physicalChild, childAction: childAction})
					}
				}
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		if err := rows.Close(); err != nil {
			return nil, err
		}
	}
	return effects, nil
}

// verifyAppMCPDeclaredTriggerClosure accepts only trigger SQL generated from
// captured Prisma, full-text, computed, and encryption declarations (plus the
// separately verified revision triggers). Authored SQLite triggers are refused
// until their effect contract is represented by an explicit adapter.
func verifyAppMCPDeclaredTriggerClosure(tx *sql.Tx, generation *appMCPRuntimeGeneration, tables []string, allowRepair bool) error {
	_ = allowRepair
	allowed := make(map[string]string)
	owners := make(map[string]string)
	add := func(name, sql, owner string) error {
		if _, exists := allowed[name]; exists {
			return fmt.Errorf("duplicate declared trigger %q", name)
		}
		allowed[name] = sql
		owners[name] = owner
		return nil
	}
	inside := make(map[string]bool, len(tables))
	for _, table := range tables {
		inside[strings.ToLower(table)] = true
	}
	// Prisma's @updatedAt triggers are generated by the framework and are
	// admitted only when their exact SQL can be regenerated from the captured
	// schema source. Never infer this authority from a trigger name or shape.
	if schema, ok := generation.sourceFiles["schema.prisma"]; ok && len(schema) != 0 {
		models, err := ParsePrismaSchema(string(schema))
		if err != nil {
			return fmt.Errorf("parse captured schema.prisma for updatedAt triggers: %w", err)
		}
		for _, model := range models {
			if !inside[strings.ToLower(model.Table)] {
				continue
			}
			if len(model.FullText) > 0 {
				definition, err := makeFTSDefinitionForTable(tx, model.Table, prismaFullTextColumns(model, model.FullText[0].Columns))
				if err != nil {
					return fmt.Errorf("derive captured full-text triggers for %q: %w", model.Table, err)
				}
				indexMatches, triggersMatch, err := definition.matches(tx)
				if err != nil || !indexMatches || !triggersMatch {
					return fmt.Errorf("captured full-text index or sync triggers changed for %q", model.Table)
				}
				// FTS5 owns these shadow tables. They are intentionally outside the
				// app table universe, so refuse extra triggers there rather than
				// treating their writes as another application effect.
				for _, object := range []string{definition.index, definition.index + "_data", definition.index + "_idx", definition.index + "_docsize", definition.index + "_config"} {
					var count int
					if err := tx.QueryRow(`SELECT count(*) FROM main.sqlite_schema WHERE type='trigger' AND tbl_name=? COLLATE NOCASE`, object).Scan(&count); err != nil {
						return err
					}
					if count != 0 {
						return fmt.Errorf("unsupported trigger attached to full-text storage object %q", object)
					}
				}
				for _, trigger := range definition.triggers {
					if err := add(trigger.name, trigger.sql, model.Table); err != nil {
						return err
					}
				}
			}
			for _, field := range model.Fields {
				if !field.UpdatedAt {
					continue
				}
				name := fmt.Sprintf("trg_%s_%s_updated", model.Table, field.Column)
				sql := strings.TrimSuffix(prismaUpdatedAtTriggerSQL(model.Table, field.Column), ";")
				if err := add(name, sql, model.Table); err != nil {
					return err
				}
			}
		}
	}
	if generation.computed != nil {
		for _, fields := range generation.computed.Fields {
			for _, field := range fields {
				if field == nil {
					return errors.New("nil computed field in captured trigger declaration")
				}
				if field.Expr != "" && inside[strings.ToLower(field.Table)] {
					for _, event := range []string{"insert", "update"} {
						name := fmt.Sprintf("_benmore_cf_%s_%s_%s", field.Table, field.Column, event)
						verb := strings.ToUpper(event)
						sql := fmt.Sprintf("CREATE TRIGGER IF NOT EXISTS %s AFTER %s ON %s FOR EACH ROW BEGIN UPDATE %s SET %s = (%s) WHERE rowid = NEW.rowid; END", name, verb, field.Table, field.Table, field.Column, field.Expr)
						if err := add(name, sql, field.Table); err != nil {
							return err
						}
					}
				}
				if field.SQL != "" {
					for _, trigger := range field.Triggers {
						if !inside[strings.ToLower(trigger.Table)] {
							continue
						}
						for _, event := range trigger.On {
							ref := "NEW"
							switch event {
							case "insert", "update":
							case "delete":
								ref = "OLD"
							default:
								return fmt.Errorf("unsupported computed trigger event %q", event)
							}
							name := fmt.Sprintf("_benmore_cf_%s_%s_%s_%s", field.Table, field.Column, trigger.Table, event)
							recalc := strings.Replace(field.SQL, "?", fmt.Sprintf("%s.%s", ref, trigger.FK), 1)
							sql := fmt.Sprintf("CREATE TRIGGER IF NOT EXISTS %s AFTER %s ON %s FOR EACH ROW WHEN %s.%s IS NOT NULL BEGIN UPDATE %s SET %s = (%s) WHERE id = %s.%s; END", name, strings.ToUpper(event), trigger.Table, ref, trigger.FK, field.Table, field.Column, recalc, ref, trigger.FK)
							if err := add(name, sql, trigger.Table); err != nil {
								return err
							}
							if event == "update" {
								name = fmt.Sprintf("_benmore_cf_%s_%s_%s_update_old", field.Table, field.Column, trigger.Table)
								recalc = strings.Replace(field.SQL, "?", fmt.Sprintf("OLD.%s", trigger.FK), 1)
								sql = fmt.Sprintf("CREATE TRIGGER IF NOT EXISTS %s AFTER UPDATE ON %s FOR EACH ROW WHEN OLD.%s IS NOT NULL AND OLD.%s IS NOT NEW.%s BEGIN UPDATE %s SET %s = (%s) WHERE id = OLD.%s; END", name, trigger.Table, trigger.FK, trigger.FK, trigger.FK, field.Table, field.Column, recalc, trigger.FK)
								if err := add(name, sql, trigger.Table); err != nil {
									return err
								}
							}
						}
					}
				}
			}
		}
	}
	if generation.view.Encrypted != nil {
		for table, fields := range generation.view.Encrypted.Fields {
			if !inside[strings.ToLower(table)] {
				continue
			}
			for _, field := range fields {
				if field.BlindIndex {
					return fmt.Errorf("blind-index trigger closure for %s.%s is not yet admitted", table, field.Column)
				}
				col := field.Column
				tableLit := "'" + strings.ReplaceAll(table, "'", "''") + "'"
				colLit := "'" + strings.ReplaceAll(col, "'", "''") + "'"
				for _, event := range []string{"insert", "update"} {
					name := fmt.Sprintf("_benmore_enc_%s_%s_%s", table, col, event)
					var sql string
					if event == "insert" {
						sql = fmt.Sprintf("CREATE TRIGGER IF NOT EXISTS %s AFTER INSERT ON %s FOR EACH ROW WHEN NEW.%s IS NOT NULL AND NOT benmore_ciphertext_matches(NEW.%s, %s, %s) BEGIN UPDATE %s SET %s = benmore_encrypt_plaintext(NEW.%s, %s, %s) WHERE rowid = NEW.rowid; END", name, table, col, col, tableLit, colLit, table, col, col, tableLit, colLit)
					} else {
						sql = fmt.Sprintf("CREATE TRIGGER IF NOT EXISTS %s AFTER UPDATE OF %s ON %s FOR EACH ROW WHEN NEW.%s IS NOT NULL AND NOT benmore_ciphertext_matches(NEW.%s, %s, %s) BEGIN UPDATE %s SET %s = benmore_encrypt_plaintext(NEW.%s, %s, %s) WHERE rowid = NEW.rowid; END", name, col, table, col, col, tableLit, colLit, table, col, col, tableLit, colLit)
					}
					if err := add(name, sql, table); err != nil {
						return err
					}
				}
			}
		}
	}
	appTriggers, err := appMCPDeclaredAppTriggers(generation)
	if err != nil {
		return err
	}
	for _, trigger := range appTriggers {
		if inside[strings.ToLower(trigger.table)] {
			if err := add(trigger.name, trigger.sql, trigger.table); err != nil {
				return err
			}
		}
	}
	for _, table := range tables {
		rows, err := tx.Query(`SELECT name,sql FROM main.sqlite_schema WHERE type='trigger' AND tbl_name=? COLLATE NOCASE AND substr(name,1,17)<>'_benmore_mcp_rev_' ORDER BY name`, table)
		if err != nil {
			return err
		}
		for rows.Next() {
			var name, actual string
			if err := rows.Scan(&name, &actual); err != nil {
				rows.Close()
				return err
			}
			expected, ok := allowed[name]
			matches, compareErr := appMCPRevisionSQLMatches(actual, expected)
			if !ok || compareErr != nil || !matches {
				rows.Close()
				return fmt.Errorf("unrecognized or changed trigger %q on enrolled table %q", name, table)
			}
			delete(allowed, name)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
	}
	for name := range allowed {
		if !inside[strings.ToLower(owners[name])] {
			delete(allowed, name)
		}
	}
	if len(allowed) != 0 {
		return fmt.Errorf("declared trigger %q is missing from the enrolled database", firstRevisionMapKey(allowed))
	}
	return nil
}

func firstRevisionMapKey(values map[string]string) string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return ""
	}
	return keys[0]
}

func verifyAppMCPRevisionEnrollmentForTx(ctx context.Context, app *App, generation *appMCPRuntimeGeneration, tx *sql.Tx, lease *appMCPAuthorityLease) (*appMCPVerifiedRevisionEnrollment, error) {
	return verifyAppMCPRevisionEnrollmentForTxMode(ctx, app, generation, tx, lease, true, nil)
}

// appMCPRevisionStateDigest hashes what the database half of the enrollment
// check reads besides the row ledger: the whole main schema (tables, indexes,
// triggers) and the revision registry rows.
func appMCPRevisionStateDigest(tx *sql.Tx) (string, error) {
	h := sha256.New()
	write := func(query string, columns int) error {
		rows, err := tx.Query(query)
		if err != nil {
			return err
		}
		defer rows.Close()
		values := make([]sql.NullString, columns)
		targets := make([]any, columns)
		for i := range values {
			targets[i] = &values[i]
		}
		var size [8]byte
		for rows.Next() {
			if err := rows.Scan(targets...); err != nil {
				return err
			}
			for _, value := range values {
				binary.BigEndian.PutUint64(size[:], uint64(len(value.String)))
				h.Write(size[:])
				h.Write([]byte(value.String))
			}
		}
		h.Write([]byte{0xff})
		return rows.Err()
	}
	if err := write(`SELECT type,name,tbl_name,sql FROM main.sqlite_schema ORDER BY type,name`, 4); err != nil {
		return "", err
	}
	if err := write(`SELECT table_name,incarnation,schema_digest FROM main._benmore_mcp_revision_tables ORDER BY table_name`, 3); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// verifyAppMCPRevisionEnrollmentForTxMode checks the enrollment against the
// owner lease, the source and the database. A command re-runs it before every
// step, and the database half (universe, storage, row ledger, trigger
// identities) costs a scan of every enrolled table. With prior verified on the
// same transaction, that half is skipped while the active record and
// appMCPRevisionStateDigest are unchanged: the transaction reads one snapshot,
// so only its own writes move it; any DDL changes the schema digest, command
// and hook SQL cannot write _benmore_* tables, and the row ledger is kept by
// the very triggers the schema digest pins.
func verifyAppMCPRevisionEnrollmentForTxMode(ctx context.Context, app *App, generation *appMCPRuntimeGeneration, tx *sql.Tx, lease *appMCPAuthorityLease, verifySource bool, prior *appMCPVerifiedRevisionEnrollment) (*appMCPVerifiedRevisionEnrollment, error) {
	if ctx == nil || app == nil || app.DB == nil || tx == nil || generation == nil || generation.origin != app || generation.view == nil ||
		lease == nil || lease.key == "" || canonicalDBPath(lease.path) != canonicalDBPath(app.Dir) {
		return nil, errors.New("revision enrollment verification requires the matching captured app, transaction, and owner lease")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	mainPath, err := mainDatabasePathForQuerier(&appMCPWriteTxQuerier{ctx: ctx, tx: tx})
	if err != nil || canonicalDBPath(mainPath) != canonicalDBPath(filepath.Join(app.Dir, "data.db")) {
		if err == nil {
			err = errors.New("revision enrollment transaction belongs to another app database")
		}
		return nil, err
	}
	if err := validateAuthorityLockPath(lease.root, lease.file); err != nil {
		return nil, err
	}
	if !appMCPGenerationCurrent(app, generation) {
		return nil, errors.New("revision enrollment generation is stale")
	}
	state, err := lease.read()
	if err != nil {
		return nil, err
	}
	if state.App != lease.key {
		return nil, errors.New("revision enrollment owner identity changed")
	}
	active, err := readAppMCPRevisionEnrollment(lease)
	if err != nil {
		return nil, fmt.Errorf("read independent revision enrollment: %w", err)
	}
	if active.State != "active" || active.OwnerEpoch != state.Epoch || active.App != state.App {
		return nil, errors.New("revision enrollment is pending or belongs to another owner epoch")
	}
	stateDigest, err := appMCPRevisionStateDigest(tx)
	if err != nil {
		return nil, err
	}
	unchanged := prior != nil && prior.tx == tx && prior.app == app && prior.generation == generation && prior.lease == lease && prior.record != nil &&
		prior.stateDigest != "" && prior.stateDigest == stateDigest && prior.record.EnrollmentID == active.EnrollmentID && prior.record.OwnerEpoch == active.OwnerEpoch &&
		sameStrings(prior.record.TableNames, active.TableNames) && sameRevisionEnrollmentTables(prior.record.Tables, active.Tables)
	if !unchanged {
		tables, err := appMCPRevisionUniverse(tx, generation, false)
		if err != nil {
			return nil, err
		}
		if !sameStrings(active.TableNames, tables) || len(active.Tables) != len(tables) {
			return nil, errors.New("revision enrollment universe changed; explicit repair is required")
		}
		if err := verifyAppMCPRevisionStorage(tx, tables); err != nil {
			return nil, err
		}
		actual, err := appMCPRevisionEnrollmentTables(tx, tables)
		if err != nil {
			return nil, err
		}
		if !sameRevisionEnrollmentTables(active.Tables, actual) {
			return nil, errors.New("revision enrollment does not match the main database identities")
		}
	}
	if err := validateAuthorityLockPath(lease.root, lease.file); err != nil {
		return nil, err
	}
	latestOwner, err := lease.read()
	if err != nil || latestOwner.App != state.App || latestOwner.Epoch != state.Epoch {
		if err == nil {
			err = errors.New("revision enrollment owner changed during verification")
		}
		return nil, err
	}
	if !appMCPGenerationCurrent(app, generation) {
		return nil, errors.New("revision enrollment generation changed during verification")
	}
	if verifySource {
		if err := validateAppMCPWriteManifest(app.Dir, generation.manifest); err != nil {
			return nil, fmt.Errorf("revision enrollment source changed during verification: %w", err)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &appMCPVerifiedRevisionEnrollment{app: app, generation: generation, tx: tx, lease: lease, ctx: ctx, record: cloneAppMCPRevisionEnrollment(active), stateDigest: stateDigest}, nil
}

func appMCPRevisionEnrollmentTables(tx *sql.Tx, tables []string) ([]appMCPRevisionEnrollmentTable, error) {
	targets, err := appMCPRevisionTargets(tx, tables)
	if err != nil {
		return nil, err
	}
	actualTriggers, err := appMCPExistingRevisionTriggers(tx)
	if err != nil {
		return nil, err
	}
	entries := make([]appMCPRevisionEnrollmentTable, 0, len(targets))
	for _, target := range targets {
		var incarnation, schemaDigest string
		if err := tx.QueryRow(`SELECT incarnation,schema_digest FROM main._benmore_mcp_revision_tables WHERE table_name=?`, target.name).Scan(&incarnation, &schemaDigest); err != nil {
			return nil, fmt.Errorf("read enrolled identity for %q: %w", target.name, err)
		}
		if schemaDigest != target.schemaDigest {
			return nil, fmt.Errorf("enrolled schema identity changed for %q", target.name)
		}
		triggers := make([]appMCPRevisionTrigger, 0, len(target.triggers))
		for _, expected := range target.triggers {
			actualSQL, ok := actualTriggers[expected.name]
			matches, compareErr := appMCPRevisionSQLMatches(actualSQL, expected.sql)
			if !ok || compareErr != nil || !matches {
				return nil, fmt.Errorf("actual revision trigger %q is missing or changed", expected.name)
			}
			triggers = append(triggers, appMCPRevisionTrigger{name: expected.name, sql: actualSQL})
		}
		triggerDigest, err := appMCPRevisionTriggerSetDigest(triggers)
		if err != nil {
			return nil, err
		}
		entries = append(entries, appMCPRevisionEnrollmentTable{Table: target.name, Incarnation: incarnation, SchemaDigest: schemaDigest, TriggerSetDigest: triggerDigest})
	}
	return entries, nil
}

func appMCPRevisionTriggerSetDigest(triggers []appMCPRevisionTrigger) (string, error) {
	ordered := append([]appMCPRevisionTrigger(nil), triggers...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].name < ordered[j].name })
	var value strings.Builder
	for _, trigger := range ordered {
		value.WriteString(trigger.name)
		value.WriteByte(0)
		normalized, err := normalizeAppMCPRevisionSQL(trigger.sql)
		if err != nil {
			return "", err
		}
		value.WriteString(normalized)
		value.WriteByte(0)
	}
	digest := sha256.Sum256([]byte(value.String()))
	return hex.EncodeToString(digest[:]), nil
}

func writeAppMCPRevisionEnrollmentWithLease(lease *appMCPAuthorityLease, enrollment *appMCPRevisionEnrollment) error {
	if lease == nil || enrollment == nil || enrollment.App != lease.key || lease.key == "" {
		return errors.New("revision enrollment app identity does not match owner lease")
	}
	if err := validateAuthorityLockPath(lease.root, lease.file); err != nil {
		return err
	}
	owner, err := lease.read()
	if err != nil {
		return err
	}
	if owner.App != lease.key || enrollment.OwnerEpoch != owner.Epoch {
		return errors.New("revision enrollment identity does not match current owner epoch")
	}
	if err := validateAppMCPRevisionEnrollment(enrollment); err != nil {
		return err
	}
	data, err := json.Marshal(enrollment)
	if err != nil {
		return err
	}
	if len(data) > appMCPRevisionEnrollmentLimit {
		return errors.New("revision enrollment record exceeds its size bound")
	}
	renamed, err := storeAppMCPAuthorityRecordWithLease(lease, lease.key+".revisions.json", data)
	if err != nil && renamed {
		return &appMCPRevisionEnrollmentOutcomeUnknownError{cause: err}
	}
	return err
}

func readAppMCPRevisionEnrollment(lease *appMCPAuthorityLease) (*appMCPRevisionEnrollment, error) {
	if lease == nil || lease.root == nil || lease.file == nil || validateAuthorityLockPath(lease.root, lease.file) != nil {
		return nil, errors.New("revision enrollment owner lease is unavailable")
	}
	name := lease.key + ".revisions.json"
	info, err := lease.root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !fileOwnedByProcess(info) || info.Size() > appMCPRevisionEnrollmentLimit {
		return nil, errors.New("invalid revision enrollment file")
	}
	f, err := lease.root.Open(name)
	if err != nil {
		return nil, err
	}
	openedInfo, statErr := f.Stat()
	data, readErr := io.ReadAll(io.LimitReader(f, appMCPRevisionEnrollmentLimit+1))
	closeErr := f.Close()
	if statErr != nil || !openedInfo.Mode().IsRegular() || openedInfo.Mode().Perm() != 0600 || !fileOwnedByProcess(openedInfo) ||
		!os.SameFile(info, openedInfo) || readErr != nil || closeErr != nil || len(data) > appMCPRevisionEnrollmentLimit {
		return nil, errors.New("revision enrollment file changed or could not be read")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var enrollment appMCPRevisionEnrollment
	if err := decoder.Decode(&enrollment); err != nil {
		return nil, errors.New("invalid revision enrollment JSON")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return nil, errors.New("revision enrollment contains trailing data")
	}
	if err := validateAppMCPRevisionEnrollment(&enrollment); err != nil {
		return nil, err
	}
	if enrollment.App != lease.key {
		return nil, errors.New("revision enrollment app identity does not match owner lease")
	}
	canonical, err := json.Marshal(&enrollment)
	if err != nil || !bytes.Equal(data, canonical) {
		return nil, errors.New("revision enrollment JSON is noncanonical")
	}
	if err := validateAuthorityLockPath(lease.root, lease.file); err != nil {
		return nil, err
	}
	if err := verifyAppMCPRevisionEnrollmentPathIdentity(lease.root, name, openedInfo); err != nil {
		return nil, err
	}
	return &enrollment, nil
}

func verifyAppMCPRevisionEnrollmentPathIdentity(root *os.Root, name string, openedInfo os.FileInfo) error {
	if root == nil || openedInfo == nil {
		return errors.New("revision enrollment path identity is unavailable")
	}
	finalInfo, err := root.Lstat(name)
	if err != nil || !finalInfo.Mode().IsRegular() || finalInfo.Mode().Perm() != 0600 || !fileOwnedByProcess(finalInfo) || !os.SameFile(openedInfo, finalInfo) {
		return errors.New("revision enrollment pathname changed while it was read")
	}
	return nil
}

func validateAppMCPRevisionEnrollment(enrollment *appMCPRevisionEnrollment) error {
	if enrollment == nil || enrollment.Version != 1 || enrollment.App == "" || !appMCPIsHex(enrollment.OwnerEpoch, 32) ||
		!appMCPIsHex(enrollment.EnrollmentID, 32) || len(enrollment.TableNames) == 0 || len(enrollment.TableNames) > appMCPRevisionEnrollmentTableLimit {
		return errors.New("invalid revision enrollment identity or bounds")
	}
	if enrollment.State != "pending" && enrollment.State != "active" && enrollment.State != "retired" {
		return errors.New("invalid revision enrollment state")
	}
	for i, table := range enrollment.TableNames {
		if !isValidColumnName(table) || strings.HasPrefix(strings.ToLower(table), "_benmore_") || strings.HasPrefix(strings.ToLower(table), "sqlite_") ||
			i > 0 && enrollment.TableNames[i-1] >= table {
			return errors.New("revision enrollment table names are invalid or unsorted")
		}
	}
	if enrollment.State == "pending" || enrollment.State == "retired" {
		if len(enrollment.Tables) != 0 {
			return errors.New("pending or retired revision enrollment cannot contain active table identities")
		}
		return nil
	}
	if len(enrollment.Tables) != len(enrollment.TableNames) {
		return errors.New("active revision enrollment table set is incomplete")
	}
	for i, table := range enrollment.Tables {
		if table.Table != enrollment.TableNames[i] || !appMCPIsHex(table.Incarnation, 16) || !appMCPIsHex(table.SchemaDigest, 32) || !appMCPIsHex(table.TriggerSetDigest, 32) {
			return errors.New("active revision enrollment table identity is malformed")
		}
	}
	return nil
}

func validateAppMCPRevisionEnrollmentPath(lease *appMCPAuthorityLease, allowExisting bool) error {
	if lease == nil || lease.root == nil || lease.file == nil || validateAuthorityLockPath(lease.root, lease.file) != nil {
		return errors.New("revision enrollment owner lease is unavailable")
	}
	info, err := lease.root.Lstat(lease.key + ".revisions.json")
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !allowExisting || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !fileOwnedByProcess(info) || info.Size() > appMCPRevisionEnrollmentLimit {
		return errors.New("revision enrollment already exists or has unsafe file metadata")
	}
	return nil
}

func appMCPIsHex(value string, byteLen int) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == byteLen && value == hex.EncodeToString(decoded)
}

func appMCPRandomHex(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func cloneAppMCPRevisionEnrollment(enrollment *appMCPRevisionEnrollment) *appMCPRevisionEnrollment {
	if enrollment == nil {
		return nil
	}
	clone := *enrollment
	clone.TableNames = append([]string(nil), enrollment.TableNames...)
	clone.Tables = append([]appMCPRevisionEnrollmentTable(nil), enrollment.Tables...)
	return &clone
}

func sameRevisionEnrollmentTables(a, b []appMCPRevisionEnrollmentTable) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

type appMCPRevisionKey struct{ KeyType, RowKey string }

type appMCPRevisionSelector struct {
	Name, Table, IntentField string
	ActorUserID              bool
	MaxRows                  int
}

type appMCPRevisionCommand struct {
	Name      string
	Selectors []appMCPRevisionSelector
}

// appMCPRevisionCommand is only a private native fixture seam. Its selectors
// can read one captured table's id by one validated scalar with a strict
// max+1 bound; it is not the production named-command descriptor/compiler.
// Arbitrary SQL, joins, request-selected targets, and aggregate phantom sets
// remain unsupported until the source-owned descriptor adapter is integrated.

type appMCPRevisionDependencyMember struct {
	Table, Incarnation, KeyType, RowKey string
	Revision                            int64
	Deleted                             bool
}

type appMCPRevisionDependencySet struct {
	Name, Table, Incarnation, SchemaDigest, TriggerSetDigest string
	Members                                                  []appMCPRevisionDependencyMember
}

type appMCPRevisionDependencySnapshot struct {
	Command, OwnerEpoch, EnrollmentID string
	Sets                              []appMCPRevisionDependencySet
}

type appMCPVerifiedRevisionEnrollment struct {
	app                     *App
	generation              *appMCPRuntimeGeneration
	tx                      *sql.Tx
	lease                   *appMCPAuthorityLease
	ctx                     context.Context
	record                  *appMCPRevisionEnrollment
	sourceVerificationScope *bool
	// stateDigest is appMCPRevisionStateDigest at the last full database check
	// on tx; see verifyAppMCPRevisionEnrollmentForTxMode.
	stateDigest string
}

func captureAppMCPDependencySetsForTx(verified *appMCPVerifiedRevisionEnrollment, command appMCPRevisionCommand, validatedIntent map[string]any, verifiedActor Session) (*appMCPRevisionDependencySnapshot, error) {
	enrollment, err := reverifyAppMCPRevisionCapability(verified)
	if err != nil {
		return nil, err
	}
	if command.Name == "" || !appMCPName.MatchString(command.Name) || len(command.Selectors) == 0 ||
		len(command.Selectors) > appMCPDependencySelectorLimit || validatedIntent == nil || verifiedActor.UserID <= 0 {
		return nil, errors.New("invalid bounded revision dependency input")
	}
	intent, err := cloneRevisionIntentScalars(validatedIntent)
	if err != nil {
		return nil, err
	}
	identities := make(map[string]appMCPRevisionEnrollmentTable, len(enrollment.Tables))
	for _, table := range enrollment.Tables {
		identities[table.Table] = table
	}
	sets := make([]appMCPRevisionDependencySet, 0, len(command.Selectors))
	selectorNames := make(map[string]bool, len(command.Selectors))
	total := 0
	for _, selector := range command.Selectors {
		if selector.Name == "" || !appMCPName.MatchString(selector.Name) || selectorNames[selector.Name] ||
			selector.MaxRows < 1 || selector.MaxRows > appMCPDependencySelectorRowsLimit {
			return nil, errors.New("invalid or duplicate revision dependency selector")
		}
		identity, ok := identities[selector.Table]
		if !ok {
			return nil, fmt.Errorf("dependency selector %q names a table outside the app enrollment", selector.Name)
		}
		selectorNames[selector.Name] = true
		if selector.ActorUserID == (selector.IntentField != "") {
			return nil, errors.New("dependency selector must choose exactly one trusted scalar source")
		}
		var value any = verifiedActor.UserID
		if !selector.ActorUserID {
			var exists bool
			value, exists = intent[selector.IntentField]
			if !exists {
				return nil, fmt.Errorf("dependency selector %q names an absent validated intent scalar", selector.Name)
			}
		}
		value, err = revisionSelectorValue(value)
		if err != nil {
			return nil, fmt.Errorf("dependency selector %q value: %w", selector.Name, err)
		}
		keys, err := selectAppMCPRevisionKeys(verified, selector, value)
		if err != nil {
			return nil, fmt.Errorf("select dependency set %q: %w", selector.Name, err)
		}
		total += len(keys)
		if total > appMCPDependencyRowsLimit {
			return nil, errors.New("command dependency sets exceed their total row bound")
		}
		members := make([]appMCPRevisionDependencyMember, 0, len(keys))
		seen := make(map[string]bool, len(keys))
		for _, key := range keys {
			if (key.KeyType != "integer" && key.KeyType != "text") ||
				key.KeyType == "integer" && !appMCPCanonicalIntegerKey(key.RowKey) || seen[key.KeyType+"\x00"+key.RowKey] {
				return nil, fmt.Errorf("dependency set %q returned an invalid or duplicate key", selector.Name)
			}
			seen[key.KeyType+"\x00"+key.RowKey] = true
			var revision int64
			var deleted int
			err := verified.tx.QueryRowContext(verified.ctx, `SELECT revision,deleted FROM main._benmore_mcp_row_revisions WHERE table_name=? AND incarnation=? AND key_type=? AND row_key=?`, selector.Table, identity.Incarnation, key.KeyType, key.RowKey).Scan(&revision, &deleted)
			if err != nil || revision < 1 || deleted != 0 {
				if err == nil {
					err = errors.New("dependency row is marked deleted")
				}
				return nil, fmt.Errorf("dependency row %s/%s is not revision-enrolled: %w", selector.Table, key.RowKey, err)
			}
			members = append(members, appMCPRevisionDependencyMember{Table: selector.Table, Incarnation: identity.Incarnation, KeyType: key.KeyType, RowKey: key.RowKey, Revision: revision})
		}
		sort.Slice(members, func(i, j int) bool {
			if members[i].Table != members[j].Table {
				return members[i].Table < members[j].Table
			}
			if members[i].Incarnation != members[j].Incarnation {
				return members[i].Incarnation < members[j].Incarnation
			}
			if members[i].KeyType != members[j].KeyType {
				return members[i].KeyType < members[j].KeyType
			}
			return members[i].RowKey < members[j].RowKey
		})
		sets = append(sets, appMCPRevisionDependencySet{Name: selector.Name, Table: selector.Table, Incarnation: identity.Incarnation, SchemaDigest: identity.SchemaDigest, TriggerSetDigest: identity.TriggerSetDigest, Members: members})
	}
	return &appMCPRevisionDependencySnapshot{Command: command.Name, OwnerEpoch: enrollment.OwnerEpoch, EnrollmentID: enrollment.EnrollmentID, Sets: sets}, nil
}

func compareAppMCPDependencySetsForTx(verified *appMCPVerifiedRevisionEnrollment, command appMCPRevisionCommand, validatedIntent map[string]any, verifiedActor Session, prepared *appMCPRevisionDependencySnapshot) error {
	enrollment, err := reverifyAppMCPRevisionCapability(verified)
	if err != nil {
		return err
	}
	if prepared == nil || prepared.Command != command.Name || prepared.OwnerEpoch != enrollment.OwnerEpoch || prepared.EnrollmentID != enrollment.EnrollmentID {
		return errors.New("prepared dependency snapshot belongs to another command")
	}
	current, err := captureAppMCPDependencySetsForTx(verified, command, validatedIntent, verifiedActor)
	if err != nil {
		return err
	}
	if len(current.Sets) != len(prepared.Sets) {
		return errors.New("command dependency set membership changed")
	}
	for i := range current.Sets {
		if current.Sets[i].Name != prepared.Sets[i].Name || current.Sets[i].Table != prepared.Sets[i].Table ||
			current.Sets[i].Incarnation != prepared.Sets[i].Incarnation || current.Sets[i].SchemaDigest != prepared.Sets[i].SchemaDigest ||
			current.Sets[i].TriggerSetDigest != prepared.Sets[i].TriggerSetDigest ||
			!sameRevisionDependencyMembers(current.Sets[i].Members, prepared.Sets[i].Members) {
			return fmt.Errorf("command dependency set %q changed", current.Sets[i].Name)
		}
	}
	return nil
}

func reverifyAppMCPRevisionCapability(verified *appMCPVerifiedRevisionEnrollment) (*appMCPRevisionEnrollment, error) {
	if verified == nil || verified.app == nil || verified.generation == nil || verified.tx == nil || verified.lease == nil || verified.ctx == nil || verified.record == nil {
		return nil, errors.New("dependency operation requires a transaction-bound verified enrollment")
	}
	verifySource := verified.sourceVerificationScope == nil || !*verified.sourceVerificationScope
	current, err := verifyAppMCPRevisionEnrollmentForTxMode(verified.ctx, verified.app, verified.generation, verified.tx, verified.lease, verifySource, verified)
	if err != nil {
		return nil, err
	}
	if current.tx != verified.tx || current.app != verified.app || current.generation != verified.generation || current.lease != verified.lease ||
		current.record.OwnerEpoch != verified.record.OwnerEpoch || current.record.EnrollmentID != verified.record.EnrollmentID {
		return nil, errors.New("verified revision enrollment capability is stale or bound to another transaction")
	}
	return current.record, nil
}

func cloneRevisionIntentScalars(intent map[string]any) (map[string]any, error) {
	copy := make(map[string]any, len(intent))
	for name, value := range intent {
		if !appMCPName.MatchString(name) {
			return nil, errors.New("validated dependency intent has an invalid field name")
		}
		scalar, err := revisionSelectorValue(value)
		if err != nil {
			continue
		}
		copy[name] = scalar
	}
	return copy, nil
}

func revisionSelectorValue(value any) (any, error) {
	switch value := value.(type) {
	case string:
		return value, nil
	case int:
		return int64(value), nil
	case int64:
		return value, nil
	case json.Number:
		if integer, err := value.Int64(); err == nil {
			return integer, nil
		}
	}
	return nil, errors.New("selector value must be a scalar string or signed integer")
}

func selectAppMCPRevisionKeys(verified *appMCPVerifiedRevisionEnrollment, selector appMCPRevisionSelector, value any) ([]appMCPRevisionKey, error) {
	if !isValidColumnName(selector.Table) || selector.Name == "" {
		return nil, errors.New("invalid private revision selector")
	}
	rows, err := verified.tx.QueryContext(verified.ctx,
		"SELECT typeof(id),CAST(id AS TEXT) FROM main."+quoteIdent(selector.Table)+" WHERE id=? LIMIT ?", value, selector.MaxRows+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	keys := make([]appMCPRevisionKey, 0, selector.MaxRows)
	for rows.Next() {
		if len(keys) == selector.MaxRows {
			return nil, errors.New("dependency set exceeds its reviewed row bound")
		}
		var key appMCPRevisionKey
		if err := rows.Scan(&key.KeyType, &key.RowKey); err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

func sameRevisionDependencyMembers(a, b []appMCPRevisionDependencyMember) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func appMCPCanonicalIntegerKey(value string) bool {
	parsed, err := strconv.ParseInt(value, 10, 64)
	return err == nil && strconv.FormatInt(parsed, 10) == value
}
