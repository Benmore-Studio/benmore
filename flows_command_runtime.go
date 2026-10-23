//go:build !cli

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mattn/go-sqlite3"
)

type appMCPCommandExecution struct {
	policyMu                   sync.RWMutex
	capability                 *appMCPCommandCapability
	phase                      string
	values                     map[string]any
	responseSchema             *AppMCPSchema
	budget                     *appMCPCommandBudget
	results                    map[string]any
	result                     map[string]any
	responses                  int
	locals                     []map[string]any
	allowedReads               map[string]bool
	allowedWrites              map[string]bool
	verifiedFTSWrites          map[string]bool
	verifiedFTSPriming         map[string]bool
	hookWrites                 map[string]bool
	jobInsert                  bool
	internal                   bool
	queryOnly                  bool
	guardInstalled             bool
	phaseActive                bool
	metadataOp                 appMCPCommandMetadataOp
	finalizing                 bool
	finalizingPreviousInternal bool
	cleanupErr                 error
	discardConn                bool
	resultBytes                int
	// generated holds the values prepare drew for this command (nil in every
	// other phase, where they arrive inside the sealed arguments).
	generated map[string]any
}

const appMCPCommandRowsPerStep = 1000
const appMCPCommandSafeIntegerMax int64 = 9007199254740991

type appMCPCommandAuthorizerPolicy struct {
	internal           bool
	phase              string
	allowedReads       map[string]bool
	allowedWrites      map[string]bool
	verifiedFTSWrites  map[string]bool
	verifiedFTSPriming map[string]bool
	metadataOp         appMCPCommandMetadataOp
	finalizing         bool
	hookWrites         map[string]bool
	// jobInsert admits one INSERT into _benmore_jobs, and only while framework
	// code enqueues a hook/webhook effect inside a hook-write scope.
	jobInsert bool
}

type appMCPCommandMetadataOp uint8

const (
	appMCPCommandMetadataRead appMCPCommandMetadataOp = iota + 1
	appMCPCommandMetadataPrepare
	appMCPCommandMetadataReceipt
	appMCPCommandMetadataAudit
	appMCPCommandMetadataApprove
	appMCPCommandMetadataConsume
	appMCPCommandMetadataSweep
	appMCPCommandMetadataAttempt
	// Hook scopes: probe-savepoint control, read-only before-hooks, and
	// on-hooks that may write (see app_mcp_command_hooks.go).
	appMCPCommandMetadataSavepoint
	appMCPCommandMetadataHookRead
	appMCPCommandMetadataHookWrite
	// Revoke scope: the credential deletes of `run: revoke_user_sessions`
	// (app_mcp_command_revoke.go). Deliberately after HookWrite and routed
	// before the hook range check in authorize.
	appMCPCommandMetadataRevoke
)

// The read/write maps are built before publication and remain immutable after it.
func (g *appMCPCommandExecution) authorizerPolicy() appMCPCommandAuthorizerPolicy {
	g.policyMu.RLock()
	policy := appMCPCommandAuthorizerPolicy{
		internal:           g.internal,
		phase:              g.phase,
		allowedReads:       g.allowedReads,
		allowedWrites:      g.allowedWrites,
		verifiedFTSWrites:  g.verifiedFTSWrites,
		verifiedFTSPriming: g.verifiedFTSPriming,
		metadataOp:         g.metadataOp,
		finalizing:         g.finalizing,
		hookWrites:         g.hookWrites,
		jobInsert:          g.jobInsert,
	}
	g.policyMu.RUnlock()
	return policy
}

func (g *appMCPCommandExecution) swapInternal(internal bool) bool {
	g.policyMu.Lock()
	previous := g.internal
	g.internal = internal
	g.policyMu.Unlock()
	return previous
}

func (g *appMCPCommandExecution) publishAuthorizerPolicy(internal bool, phase string, reads, writes, verifiedFTSWrites map[string]bool) {
	g.policyMu.Lock()
	g.internal = internal
	g.phase = phase
	g.allowedReads = reads
	g.allowedWrites = writes
	g.verifiedFTSWrites = verifiedFTSWrites
	g.policyMu.Unlock()
}

func (g *appMCPCommandExecution) restoreAuthorizerPolicy(policy appMCPCommandAuthorizerPolicy) {
	g.policyMu.Lock()
	g.internal = policy.internal
	g.phase = policy.phase
	g.allowedReads = policy.allowedReads
	g.allowedWrites = policy.allowedWrites
	g.verifiedFTSWrites = policy.verifiedFTSWrites
	g.verifiedFTSPriming = policy.verifiedFTSPriming
	g.metadataOp = policy.metadataOp
	g.finalizing = policy.finalizing
	g.hookWrites = policy.hookWrites
	g.jobInsert = policy.jobInsert
	g.policyMu.Unlock()
}

func (g *appMCPCommandExecution) publishNativeMetadataPolicy(internal bool, op appMCPCommandMetadataOp, finalizing bool) {
	g.policyMu.Lock()
	g.internal = internal
	g.phase = ""
	g.allowedReads = nil
	g.allowedWrites = nil
	g.verifiedFTSWrites = nil
	g.hookWrites = nil
	g.jobInsert = false
	g.metadataOp = op
	g.finalizing = finalizing
	g.policyMu.Unlock()
}

// setJobInsert opens or closes the one-statement job-queue write window.
func (g *appMCPCommandExecution) setJobInsert(on bool) {
	g.policyMu.Lock()
	g.jobInsert = on
	g.policyMu.Unlock()
}

// publishHookWrites admits exactly the revision-enrolled tables for the active
// hook-write scope; every other scope publishes none.
func (g *appMCPCommandExecution) publishHookWrites(writes, verifiedFTSWrites map[string]bool) {
	g.policyMu.Lock()
	g.hookWrites = writes
	g.verifiedFTSWrites = verifiedFTSWrites
	g.policyMu.Unlock()
}

func (g *appMCPCommandExecution) beginFinalizingPolicy() {
	g.policyMu.Lock()
	g.finalizingPreviousInternal = g.internal
	g.internal = true
	g.phase = ""
	g.allowedReads = nil
	g.allowedWrites = nil
	g.verifiedFTSWrites = nil
	g.metadataOp = 0
	g.finalizing = false
	g.policyMu.Unlock()
}

func (g *appMCPCommandExecution) finishFinalizingPolicy() {
	g.policyMu.Lock()
	g.internal = g.finalizingPreviousInternal
	g.phase = ""
	g.allowedReads = nil
	g.allowedWrites = nil
	g.metadataOp = 0
	g.finalizing = false
	g.finalizingPreviousInternal = false
	g.policyMu.Unlock()
}

func (cap *appMCPCommandCapability) installConnectionGuard() error {
	if cap == nil || cap.conn == nil || cap.tx == nil {
		return errors.New("command connection is unavailable")
	}
	exec := &appMCPCommandExecution{capability: cap, internal: true}
	cap.guard = exec
	if err := cap.conn.QueryRowContext(cap.ctx, "PRAGMA query_only").Scan(&exec.queryOnly); err != nil {
		return err
	}
	exec.guardInstalled = true
	if _, err := cap.tx.ExecContext(cap.ctx, "PRAGMA query_only=ON"); err != nil {
		return err
	}
	if err := cap.conn.Raw(func(raw any) error {
		conn, ok := raw.(*sqlite3.SQLiteConn)
		if !ok {
			return errors.New("command connection is not a SQLite connection")
		}
		conn.RegisterAuthorizer(exec.authorize)
		return nil
	}); err != nil {
		return err
	}
	return nil
}

func (cap *appMCPCommandCapability) restoreConnectionGuard() error {
	if cap == nil || cap.conn == nil || cap.tx == nil || cap.guard == nil {
		return errors.New("command connection guard is unavailable")
	}
	guard := cap.guard
	guard.swapInternal(true)
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(cap.ctx), 2*time.Second)
	defer cancel()
	if _, err := cap.tx.ExecContext(cleanupCtx, "PRAGMA query_only="+commandPragmaBool(guard.queryOnly)); err != nil {
		guard.markConnectionUncertain(err)
	}
	if err := cap.conn.Raw(func(raw any) error {
		conn, ok := raw.(*sqlite3.SQLiteConn)
		if !ok {
			return errors.New("command connection is not a SQLite connection")
		}
		restoreConnAuthorizer(conn)
		return nil
	}); err != nil {
		guard.markConnectionUncertain(err)
	}
	if guard.discardConn && guard.cleanupErr == nil {
		guard.markConnectionUncertain(errors.New("command connection cleanup is uncertain"))
	}
	guard.guardInstalled = false
	cap.guard = nil
	return guard.cleanupErr
}

func (guard *appMCPCommandExecution) markConnectionUncertain(err error) {
	if guard == nil {
		return
	}
	if err == nil {
		err = errors.New("command connection cleanup is uncertain")
	}
	guard.discardConn = true
	guard.cleanupErr = errors.Join(guard.cleanupErr, err)
}

func commandPragmaBool(value bool) string {
	if value {
		return "ON"
	}
	return "OFF"
}

func (g *appMCPCommandExecution) authorize(action int, arg1, arg2, database string) int {
	if g == nil {
		return sqlite3.SQLITE_DENY
	}
	policy := g.authorizerPolicy()
	if policy.metadataOp == appMCPCommandMetadataRevoke {
		return authorizeCommandRevoke(action, arg1, arg2, database)
	}
	if policy.metadataOp >= appMCPCommandMetadataSavepoint {
		return authorizeCommandHook(policy, action, arg1, arg2, database)
	}
	if policy.metadataOp != 0 {
		return authorizeCommandNativeMetadata(policy.metadataOp, action, arg1, arg2, database)
	}
	if action == sqlite3.SQLITE_SELECT || action == sqliteRecursiveSelect {
		return sqlite3.SQLITE_OK
	}
	if action == sqlite3.SQLITE_FUNCTION {
		if commandAllowedSQLFunction(arg2) || policy.phase == "apply" && commandVerifiedTriggerFunction(arg2) {
			return sqlite3.SQLITE_OK
		}
		return sqlite3.SQLITE_DENY
	}
	if action == sqlite3.SQLITE_READ {
		// SQLite reports count(*)'s table read with an empty column and, on
		// some driver versions, an empty database name. Admit only that exact
		// columnless form; every other read still has to name main explicitly.
		if !strings.EqualFold(database, "main") && !(database == "" && arg2 == "") {
			return sqlite3.SQLITE_DENY
		}
		if policy.internal {
			if database == "" {
				if arg2 == "" && policy.verifiedFTSPriming[sqliteIdentifierFold(arg1)] {
					return sqlite3.SQLITE_OK
				}
				return sqlite3.SQLITE_DENY
			}
			return sqlite3.SQLITE_OK
		}
		if policy.phase == "apply" && commandVerifiedTriggerRead(arg1) {
			if strings.EqualFold(database, "main") {
				return sqlite3.SQLITE_OK
			}
			return sqlite3.SQLITE_DENY
		}
		if policy.phase == "apply" && strings.EqualFold(database, "main") && policy.verifiedFTSWrites[sqliteIdentifierFold(arg1)] {
			return sqlite3.SQLITE_OK
		}
		if strings.HasPrefix(strings.ToLower(arg1), "_benmore_") || strings.HasPrefix(strings.ToLower(arg1), "sqlite_") {
			return sqlite3.SQLITE_DENY
		}
		if policy.allowedReads[sqliteIdentifierFold(arg1)] || policy.allowedWrites[sqliteIdentifierFold(arg1)] {
			return sqlite3.SQLITE_OK
		}
		return sqlite3.SQLITE_DENY
	}
	if action == sqlite3.SQLITE_PRAGMA && policy.internal {
		if policy.finalizing && strings.EqualFold(arg1, "query_only") && arg2 != "" {
			return sqlite3.SQLITE_DENY
		}
		switch strings.ToLower(arg1) {
		case "query_only", "database_list", "table_info", "table_xinfo", "foreign_key_list", "index_list", "index_info", "index_xinfo", "data_version":
			return sqlite3.SQLITE_OK
		}
	}
	if policy.internal {
		return sqlite3.SQLITE_DENY
	}
	if policy.phase == "apply" && (action == sqlite3.SQLITE_INSERT || action == sqlite3.SQLITE_UPDATE || action == sqlite3.SQLITE_DELETE) {
		if strings.EqualFold(database, "main") && (policy.allowedWrites[sqliteIdentifierFold(arg1)] || policy.verifiedFTSWrites[sqliteIdentifierFold(arg1)] || commandVerifiedTriggerWrite(arg1)) {
			return sqlite3.SQLITE_OK
		}
	}
	if action == sqlite3.SQLITE_PRAGMA && strings.EqualFold(arg1, "data_version") && arg2 == "" {
		return sqlite3.SQLITE_OK
	}
	return sqlite3.SQLITE_DENY
}

func authorizeCommandNativeMetadata(op appMCPCommandMetadataOp, action int, arg1, arg2, database string) int {
	if action == sqlite3.SQLITE_SELECT || action == sqliteRecursiveSelect {
		return sqlite3.SQLITE_OK
	}
	if action == sqlite3.SQLITE_FUNCTION {
		if commandAllowedSQLFunction(arg2) {
			return sqlite3.SQLITE_OK
		}
		return sqlite3.SQLITE_DENY
	}
	if action == sqlite3.SQLITE_READ {
		table := strings.ToLower(arg1)
		db := strings.ToLower(database)
		if db == "temp" && (table == "sqlite_temp_schema" || table == "sqlite_temp_master" || table == "sqlite_schema" || table == "sqlite_master") {
			return sqlite3.SQLITE_OK
		}
		if db != "main" {
			return sqlite3.SQLITE_DENY
		}
		if op == appMCPCommandMetadataAudit && table == "sqlite_sequence" {
			return sqlite3.SQLITE_OK
		}
		switch table {
		case "_benmore_mcp_operations", "_benmore_mcp_command_approvals", "_benmore_mcp_command_attempts", "_benmore_encryption_state", "sqlite_schema", "sqlite_master", "pragma_database_list":
			return sqlite3.SQLITE_OK
		}
		return sqlite3.SQLITE_DENY
	}
	if action == sqlite3.SQLITE_PRAGMA {
		switch strings.ToLower(arg1) {
		case "database_list":
			if arg2 == "" {
				return sqlite3.SQLITE_OK
			}
		case "table_info", "index_list":
			// The encryption-state marker is verified with the command stores.
			if strings.EqualFold(database, "main") && (strings.EqualFold(arg2, "_benmore_mcp_operations") || strings.EqualFold(arg2, "_benmore_mcp_command_approvals") ||
				strings.EqualFold(arg1, "index_list") && strings.EqualFold(arg2, "_benmore_mcp_command_attempts") ||
				strings.EqualFold(arg1, "table_info") && strings.EqualFold(arg2, "_benmore_encryption_state")) {
				return sqlite3.SQLITE_OK
			}
		case "index_info":
			if strings.EqualFold(database, "main") && (strings.EqualFold(arg2, "sqlite_autoindex__benmore_mcp_operations_1") || strings.EqualFold(arg2, "sqlite_autoindex__benmore_mcp_command_approvals_1")) {
				return sqlite3.SQLITE_OK
			}
		}
		return sqlite3.SQLITE_DENY
	}
	if op == appMCPCommandMetadataPrepare && action == sqlite3.SQLITE_INSERT && strings.EqualFold(database, "main") && strings.EqualFold(arg1, "_benmore_mcp_operations") {
		return sqlite3.SQLITE_OK
	}
	if op == appMCPCommandMetadataReceipt && action == sqlite3.SQLITE_UPDATE && strings.EqualFold(database, "main") && strings.EqualFold(arg1, "_benmore_mcp_operations") && (strings.EqualFold(arg2, "receipt_digest") || strings.EqualFold(arg2, "receipt_ciphertext")) {
		return sqlite3.SQLITE_OK
	}
	// The approval row is written once (Approve) and flipped to consumed once
	// (Consume); only its sealed state column may change.
	if op == appMCPCommandMetadataApprove && action == sqlite3.SQLITE_INSERT && strings.EqualFold(database, "main") && strings.EqualFold(arg1, "_benmore_mcp_command_approvals") {
		return sqlite3.SQLITE_OK
	}
	if op == appMCPCommandMetadataConsume && action == sqlite3.SQLITE_UPDATE && strings.EqualFold(database, "main") && strings.EqualFold(arg1, "_benmore_mcp_command_approvals") && strings.EqualFold(arg2, "state_ciphertext") {
		return sqlite3.SQLITE_OK
	}
	// The expiry sweep may delete unfinished operations with their approvals and
	// attempts; it writes nothing else (its caller restricts rows to expired,
	// receipt-less ones).
	if op == appMCPCommandMetadataSweep && action == sqlite3.SQLITE_DELETE && strings.EqualFold(database, "main") &&
		(strings.EqualFold(arg1, "_benmore_mcp_operations") || strings.EqualFold(arg1, "_benmore_mcp_command_approvals") || strings.EqualFold(arg1, "_benmore_mcp_command_attempts")) {
		return sqlite3.SQLITE_OK
	}
	// Claiming a commit attempt inserts one running row before any side effect,
	// and may mark a stale running predecessor unknown (its sealed state only).
	// Normal terminal updates run outside the coordinator (appMCPFinishAttempt).
	if op == appMCPCommandMetadataAttempt && strings.EqualFold(database, "main") && strings.EqualFold(arg1, "_benmore_mcp_command_attempts") &&
		(action == sqlite3.SQLITE_INSERT || action == sqlite3.SQLITE_UPDATE && strings.EqualFold(arg2, "state_ciphertext")) {
		return sqlite3.SQLITE_OK
	}
	if op == appMCPCommandMetadataAudit && action == sqlite3.SQLITE_INSERT && strings.EqualFold(database, "main") && strings.EqualFold(arg1, "_benmore_audit_log") {
		return sqlite3.SQLITE_OK
	}
	return sqlite3.SQLITE_DENY
}

func (cap *appMCPCommandCapability) beginFinalization() error {
	if cap == nil || cap.closed || cap.ctx == nil || cap.guard == nil || cap.guard.phaseActive {
		return errors.New("command finalization state is invalid")
	}
	policy := cap.guard.authorizerPolicy()
	if policy.metadataOp != 0 || policy.finalizing {
		return errors.New("command finalization is already active")
	}
	if err := cap.ctx.Err(); err != nil {
		return err
	}
	guard := cap.guard
	guard.beginFinalizingPolicy()
	if _, err := cap.tx.ExecContext(cap.ctx, "PRAGMA query_only=ON"); err != nil {
		guard.markConnectionUncertain(err)
		return err
	}
	var queryOnly bool
	if err := cap.tx.QueryRowContext(cap.ctx, "PRAGMA query_only").Scan(&queryOnly); err != nil || !queryOnly {
		if err == nil {
			err = errors.New("command finalizer connection is not read-only")
		}
		guard.markConnectionUncertain(err)
		return err
	}
	guard.publishNativeMetadataPolicy(true, 0, true)
	return nil
}

func (cap *appMCPCommandCapability) endFinalization() error {
	if cap == nil || cap.guard == nil {
		return errors.New("command finalization state is unavailable")
	}
	guard := cap.guard
	guard.publishNativeMetadataPolicy(true, 0, false)
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(cap.ctx), 2*time.Second)
	defer cancel()
	if _, err := cap.tx.ExecContext(cleanupCtx, "PRAGMA query_only=ON"); err != nil {
		guard.markConnectionUncertain(err)
		guard.publishNativeMetadataPolicy(true, 0, false)
		return guard.cleanupErr
	}
	guard.finishFinalizingPolicy()
	return nil
}

func (cap *appMCPCommandCapability) withNativeMetadata(op appMCPCommandMetadataOp, use func() error) (err error) {
	if cap == nil || cap.guard == nil || cap.tx == nil || cap.conn == nil || use == nil ||
		op < appMCPCommandMetadataRead || op > appMCPCommandMetadataRevoke || cap.guard.phaseActive {
		return errors.New("native command metadata scope is invalid")
	}
	policy := cap.guard.authorizerPolicy()
	if policy.metadataOp != 0 || policy.finalizing {
		return errors.New("native command metadata scope is already active")
	}
	if err := cap.validateLifetime(); err != nil {
		return err
	}
	var hookFTSWrites map[string]bool
	if op == appMCPCommandMetadataHookWrite {
		var err error
		hookFTSWrites, err = appMCPCommandFullTextTriggerWrites(cap.generation, cap.effectTables())
		if err != nil {
			return fmt.Errorf("derive verified hook full-text trigger writes: %w", err)
		}
	}
	guard := cap.guard
	previousPolicy := guard.authorizerPolicy()
	scopeErr := func() (scopeErr error) {
		guard.swapInternal(true)
		defer func() {
			guard.publishNativeMetadataPolicy(true, 0, false)
			cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(cap.ctx), 2*time.Second)
			defer cancel()
			if _, restoreErr := cap.tx.ExecContext(cleanupCtx, "PRAGMA query_only=ON"); restoreErr != nil {
				guard.markConnectionUncertain(restoreErr)
				scopeErr = errors.Join(scopeErr, restoreErr)
			}
			if guard.discardConn {
				guard.publishNativeMetadataPolicy(true, 0, false)
			} else {
				guard.restoreAuthorizerPolicy(previousPolicy)
			}
			if guard.cleanupErr != nil {
				scopeErr = errors.Join(scopeErr, guard.cleanupErr)
			}
		}()
		if op == appMCPCommandMetadataRead || op == appMCPCommandMetadataSavepoint || op == appMCPCommandMetadataHookRead {
			if _, scopeErr = cap.tx.ExecContext(cap.ctx, "PRAGMA query_only=ON"); scopeErr != nil {
				return scopeErr
			}
		} else {
			if _, scopeErr = cap.tx.ExecContext(cap.ctx, "PRAGMA query_only=OFF"); scopeErr != nil {
				return scopeErr
			}
		}
		guard.publishNativeMetadataPolicy(false, op, false)
		if op == appMCPCommandMetadataHookWrite {
			guard.publishHookWrites(commandTableSet(cap.effectTables()), hookFTSWrites)
		}
		if scopeErr = cap.ctx.Err(); scopeErr != nil {
			return scopeErr
		}
		return use()
	}()
	if scopeErr != nil {
		return scopeErr
	}
	// Revalidate native authority only after the metadata allowlist is gone and
	// the exact prior idle authorizer policy has been restored.
	return cap.validateLifetime()
}

func commandVerifiedTriggerRead(table string) bool {
	switch strings.ToLower(table) {
	case appMCPRowRevisionsName, appMCPRevisionTablesName:
		return true
	default:
		return false
	}
}

func commandVerifiedTriggerWrite(table string) bool {
	return strings.EqualFold(table, appMCPRowRevisionsName)
}

func commandVerifiedTriggerFunction(name string) bool {
	// SQLite reports CURRENT_TIMESTAMP as a function while executing the
	// framework-generated @updatedAt trigger during apply. This is a bounded
	// clock read with no external state or authority effects.
	// Ciphertext authentication is also allowed only while a verified trigger
	// runs: exposing it to command SQL would create a key-validity oracle.
	return strings.EqualFold(name, "raise") || strings.EqualFold(name, "benmore_encrypt") || strings.EqualFold(name, "benmore_encrypt_plaintext") || strings.EqualFold(name, "benmore_ciphertext_matches") || strings.EqualFold(name, "current_timestamp")
}

func commandAllowedSQLFunction(name string) bool {
	switch strings.ToLower(name) {
	case "abs", "avg", "char", "coalesce", "concat", "concat_ws", "count", "date", "datetime", "benmore_today", "glob", "hex", "ifnull", "instr", "length", "like", "lower", "ltrim", "max", "min", "nullif", "printf", "quote", "replace", "round", "rtrim", "sign", "soundex", "sqlite_version", "substr", "substring", "sum", "time", "total", "trim", "typeof", "unicode", "upper", "zeroblob", "json", "json_array", "json_array_length", "json_group_array", "json_extract", "json_insert", "json_object", "json_patch", "json_remove", "json_replace", "json_type", "json_valid", "json_quote", "julianday", "strftime":
		return true
	default:
		return false
	}
}

func (cap *appMCPCommandCapability) enterReadPhase(phase string, tables []string) error {
	return cap.enterPhase(phase, tables, nil, true)
}

func (cap *appMCPCommandCapability) enterPhase(phase string, reads, writes []string, readOnly bool) error {
	if cap == nil || cap.guard == nil || cap.guard.phaseActive || phase != "prepare" && phase != "apply" && phase != "readback" {
		return errors.New("command phase state is invalid")
	}
	policy := cap.guard.authorizerPolicy()
	if policy.metadataOp != 0 || policy.finalizing {
		return errors.New("command phase cannot start during a native metadata scope")
	}
	if err := cap.ctx.Err(); err != nil {
		return err
	}
	guard := cap.guard
	var verifiedFTSWrites map[string]bool
	if phase == "apply" && !readOnly {
		var err error
		verifiedFTSWrites, err = appMCPCommandFullTextTriggerWrites(cap.generation, writes)
		if err != nil {
			return fmt.Errorf("derive verified full-text trigger writes: %w", err)
		}
		indexes, err := appMCPCommandFullTextTriggerIndexes(cap.generation, writes)
		if err != nil {
			return fmt.Errorf("derive verified full-text trigger indexes: %w", err)
		}
		if err := cap.primeFullTextIndexes(indexes); err != nil {
			return fmt.Errorf("initialize captured full-text indexes: %w", err)
		}
	}
	guard.swapInternal(true)
	if readOnly {
		if _, err := cap.tx.ExecContext(cap.ctx, "PRAGMA query_only=ON"); err != nil {
			guard.swapInternal(false)
			return err
		}
	} else {
		if _, err := cap.tx.ExecContext(cap.ctx, "PRAGMA query_only=OFF"); err != nil {
			guard.swapInternal(false)
			return err
		}
	}
	guard.publishAuthorizerPolicy(false, phase, commandTableSet(reads), commandTableSet(writes), verifiedFTSWrites)
	guard.phaseActive = true
	return nil
}

func (cap *appMCPCommandCapability) leaveReadPhase() {
	cap.leavePhase()
}

func (cap *appMCPCommandCapability) leavePhase() {
	if cap == nil || cap.guard == nil || !cap.guard.phaseActive {
		return
	}
	guard := cap.guard
	guard.swapInternal(true)
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(cap.ctx), 2*time.Second)
	defer cancel()
	if _, err := cap.tx.ExecContext(cleanupCtx, "PRAGMA query_only=ON"); err != nil {
		guard.markConnectionUncertain(err)
	}
	guard.publishAuthorizerPolicy(false, "", nil, nil, nil)
	guard.phaseActive = false
}

// primeFullTextIndexes connects each exact captured FTS virtual table before
// the apply authorizer is narrowed. SQLite's xConnect reads its own shadow
// tables (for example <index>_config); doing this under internal read-only
// policy avoids granting command or hook SQL access to FTS storage objects.
func (cap *appMCPCommandCapability) primeFullTextIndexes(indexes map[string]bool) (err error) {
	if cap == nil || cap.guard == nil || len(indexes) == 0 {
		return nil
	}
	guard := cap.guard
	previous := guard.swapInternal(true)
	previousPolicy := guard.authorizerPolicy()
	priming := make(map[string]bool, len(indexes))
	for index := range indexes {
		priming[sqliteIdentifierFold(index)] = true
	}
	guard.policyMu.Lock()
	guard.verifiedFTSPriming = priming
	guard.policyMu.Unlock()
	defer func() {
		guard.restoreAuthorizerPolicy(previousPolicy)
		guard.swapInternal(previous)
	}()
	for index := range indexes {
		if !safeIdent(index) {
			return errors.New("captured full-text index name is invalid")
		}
		rows, queryErr := cap.tx.QueryContext(cap.ctx, `SELECT rowid FROM "`+index+`" LIMIT 1`)
		if queryErr != nil {
			return queryErr
		}
		if closeErr := rows.Close(); closeErr != nil {
			return closeErr
		}
		if rowsErr := rows.Err(); rowsErr != nil {
			return rowsErr
		}
	}
	return nil
}

func commandTableSet(tables []string) map[string]bool {
	set := make(map[string]bool, len(tables))
	for _, table := range tables {
		set[sqliteIdentifierFold(table)] = true
	}
	return set
}

// appMCPCommandFullTextTriggerIndexes returns only FTS virtual indexes
// generated from captured Prisma models this command may write.
func appMCPCommandFullTextTriggerIndexes(generation *appMCPRuntimeGeneration, writes []string) (map[string]bool, error) {
	if generation == nil {
		return nil, nil
	}
	schema, ok := generation.sourceFiles["schema.prisma"]
	if !ok || len(schema) == 0 {
		return nil, nil
	}
	models, err := ParsePrismaSchema(string(schema))
	if err != nil {
		return nil, err
	}
	writeTables := commandTableSet(writes)
	indexes := make(map[string]bool)
	for _, model := range models {
		if !writeTables[sqliteIdentifierFold(model.Table)] || len(model.FullText) == 0 {
			continue
		}
		definition, err := makeFTSDefinition(model.Table, model.FullText[0].Columns)
		if err != nil {
			return nil, err
		}
		indexes[sqliteIdentifierFold(definition.index)] = true
	}
	return indexes, nil
}

// appMCPCommandFullTextTriggerWrites admits the exact FTS5 virtual indexes and
// fixed shadow tables for captured Prisma models this command may write.
// Authored command/hook SQL is separately rejected if it names any of them.
func appMCPCommandFullTextTriggerWrites(generation *appMCPRuntimeGeneration, writes []string) (map[string]bool, error) {
	indexes, err := appMCPCommandFullTextTriggerIndexes(generation, writes)
	if err != nil || len(indexes) == 0 {
		return nil, err
	}
	storage := make(map[string]bool, len(indexes)*5)
	for index := range indexes {
		storage[index] = true
		for _, suffix := range []string{"_config", "_data", "_docsize", "_idx"} {
			storage[index+suffix] = true
		}
	}
	return storage, nil
}

func appMCPCommandFullTextStorageTables(generation *appMCPRuntimeGeneration) (map[string]bool, error) {
	if generation == nil {
		return nil, nil
	}
	schema, ok := generation.sourceFiles["schema.prisma"]
	if !ok || len(schema) == 0 {
		return nil, nil
	}
	models, err := ParsePrismaSchema(string(schema))
	if err != nil {
		return nil, err
	}
	allTables := make([]string, 0, len(models))
	for _, model := range models {
		if len(model.FullText) > 0 {
			allTables = append(allTables, model.Table)
		}
	}
	return appMCPCommandFullTextTriggerWrites(generation, allTables)
}

func validateAppMCPCommandRuntimePhase(phase FlowCommandPhase, name string, writes []string) error {
	if len(phase.Steps) == 0 || name != "prepare" && name != "apply" && name != "readback" {
		return errors.New("command phase declaration is empty or invalid")
	}
	terminal := phase.Steps[len(phase.Steps)-1]
	if terminal.Type != "respond" || terminal.Respond == nil || terminal.Respond.Status != 200 {
		return errors.New("command phase must have one terminal success response")
	}
	if err := validateAppMCPCommandRuntimeSteps(phase.Steps[:len(phase.Steps)-1], name, writes); err != nil {
		return err
	}
	shape := map[string]any{"apply": map[string]any{"ok": true}, "prepare": map[string]any{"arguments": nil, "preview": nil}}
	if expected, ok := shape[name]; ok && !commandLiteralRespondShape(terminal.Respond.JSON, expected) {
		return errors.New("command phase success response shape changed after compile")
	}
	return nil
}

func validateAppMCPCommandRuntimeSteps(steps []FlowStep, phase string, writes []string) error {
	for i := range steps {
		step := &steps[i]
		if step.Retry != 0 || step.RetryDelay != 0 || len(step.OnError) != 0 || step.Type == "parallel" || step.Type == "api" || step.Type == "webhook" || step.Type == "ws" || step.Type == "broadcast" || step.Type == "enqueue" || step.Type == "email" || step.Type == "sms" || step.Type == "redirect" || step.Type == "serve_file" || step.Type == "delete_upload" || step.Type == "inspect_private_upload" || step.Type == "render_pdf_signatures" || step.Type == "parse" || step.Type == "purge_current_user" || step.Type == "transcribe" || step.Type == "sql_dynamic" {
			return fmt.Errorf("command phase contains an unsupported or external-effect step %q", step.Type)
		}
		switch step.Type {
		case "sql":
			if err := validateCommandRuntimeSQLBindings(step, phase); err != nil {
				return err
			}
			if err := validateCommandRuntimeSQLText(step.SQL, phase, writes); err != nil {
				return err
			}
		case "compute":
			if step.Compute == nil || step.Compute.Module == "" || step.Compute.Function == "" {
				return errors.New("command compute step is incomplete")
			}
		case "set":
			if len(step.Set) == 0 {
				return errors.New("command set step is empty")
			}
		case "revoke_user_sessions":
			if phase != "apply" || step.CommandRevokeRef.Kind != "phase_path" || step.CommandRevokeRef.Path == "" || step.RevokeUserID == "" {
				return errors.New("command revoke_user_sessions step is incomplete or outside apply")
			}
		case "respond":
			return errors.New("command response is only allowed as the final phase step")
		case "if":
			if len(step.Steps) == 0 {
				return errors.New("command if step is empty")
			}
		case "for_each":
			if len(step.Steps) == 0 || step.ForEach == "" || step.ForAs == "" || !commandLocalName(step.ForAs) {
				return errors.New("command loop step is incomplete")
			}
			if commandStepsHaveRespond(step.Steps) {
				return errors.New("command loop body cannot hold a response or refusal")
			}
		default:
			return fmt.Errorf("command phase contains unsupported step %q", step.Type)
		}
		// A prepare `if` branch holding just a literal 4xx refusal is the one
		// place a non-final respond is allowed (see commandRefusalStatus).
		refusalBranch := step.Type == "if" && phase == "prepare"
		if !refusalBranch || !commandRefusalBranch(step.Steps) {
			if err := validateAppMCPCommandRuntimeSteps(step.Steps, phase, writes); err != nil {
				return err
			}
		}
		if !refusalBranch || !commandRefusalBranch(step.ElseSteps) {
			if err := validateAppMCPCommandRuntimeSteps(step.ElseSteps, phase, writes); err != nil {
				return err
			}
		}
	}
	return nil
}

func commandStepsHaveRespond(steps []FlowStep) bool {
	for i := range steps {
		if steps[i].Type == "respond" || commandStepsHaveRespond(steps[i].Steps) || commandStepsHaveRespond(steps[i].ElseSteps) {
			return true
		}
	}
	return false
}

func validateCommandRuntimeSQLBindings(step *FlowStep, phase string) error {
	if step == nil || step.SQL == "" || len(step.SQLParams) != len(step.CommandSQLParams) {
		return errors.New("command SQL requires a complete typed binding map")
	}
	raw := make(map[string]string, len(step.CommandSQLParams))
	for name, ref := range step.CommandSQLParams {
		if !commandBindName.MatchString(name) {
			return errors.New("command SQL binding name is invalid")
		}
		switch ref.Kind {
		case "phase_path", "actor_id", "selected_tenant", "loop_path", "step_output":
			if commandActorEmailRef.MatchString(step.SQLParams[name]) {
				return errors.New("command actor email binding lost its exact compiled type")
			}
		case "actor_role", "actor_is_admin":
			if ref.Path != "" || commandActorIdentityKind(step.SQLParams[name]) != ref.Kind {
				return errors.New("command actor role binding lost its exact compiled type")
			}
		case "actor_email":
			if phase != "apply" || ref.Path != "" || !commandActorEmailRef.MatchString(step.SQLParams[name]) {
				return errors.New("command actor email is restricted to exact apply SQL binding")
			}
		default:
			return errors.New("command SQL binding type is unsupported")
		}
		if !commandRawReferenceMatches(step.SQLParams[name], ref, phase) {
			return errors.New("command SQL binding metadata no longer matches its captured source")
		}
		raw[name] = "${{ params.bound }}"
	}
	return validateCommandSQLBindings(step.SQL, raw, false)
}

func commandRawReferenceMatches(raw string, ref FlowCommandParamRef, phase string) bool {
	if commandActorEmailRef.MatchString(raw) {
		return phase == "apply" && ref == (FlowCommandParamRef{Kind: "actor_email"})
	}
	if kind := commandActorIdentityKind(raw); kind != "" {
		return ref == (FlowCommandParamRef{Kind: kind})
	}
	if match := commandParam.FindStringSubmatch(raw); match != nil {
		switch {
		case strings.HasPrefix(match[1], "params."):
			return ref == (FlowCommandParamRef{Kind: "phase_path", Path: strings.TrimPrefix(match[1], "params.")})
		case match[1] == "user.group_id":
			return ref == (FlowCommandParamRef{Kind: "selected_tenant"})
		case match[1] == "user.id":
			return ref == (FlowCommandParamRef{Kind: "actor_id"})
		}
	}
	if match := commandStepOutputRef.FindStringSubmatch(raw); match != nil {
		return ref == (FlowCommandParamRef{Kind: "step_output", Path: "steps." + match[1] + ".outputs." + match[2]})
	}
	if match := commandLoopPathRef.FindStringSubmatch(raw); match != nil {
		return ref == (FlowCommandParamRef{Kind: "loop_path", Path: match[1] + "." + match[2]})
	}
	return false
}

func validateCommandRuntimeSQLText(query, phase string, writes []string) error {
	if err := validateCommandSQLText(query); err != nil {
		return err
	}
	if err := validateCommandAuthoredSQLFunctions(query); err != nil {
		return err
	}
	if _, count := sqlWriteTargets(query); count != 1 || strings.Contains(strings.TrimSpace(query), ";") {
		return errors.New("command SQL must be exactly one prevalidated statement")
	}
	if phase == "apply" {
		if err := validateCommandApplySQL(query, writes); err != nil {
			return err
		}
	} else if err := validateCommandSelect(query); err != nil {
		return err
	}
	if _, err := commandSQLTableInventory(query); err != nil {
		return err
	}
	return nil
}

func validateCommandAuthoredSQLFunctions(query string) error {
	tokens := sqlTokenize(stripSQLComments(query))
	for i := 0; i+1 < len(tokens); i++ {
		if (tokens[i].kind == sqlTokWord || tokens[i].kind == sqlTokIdent) && tokens[i+1].kind == sqlTokPunct && tokens[i+1].text == "(" {
			if commandVerifiedTriggerFunction(tokens[i].text) {
				return fmt.Errorf("command SQL cannot call trigger-only function %q", tokens[i].text)
			}
		}
	}
	return nil
}

func (cap *appMCPCommandCapability) validateSQLPhase(query, phase string, tables []string) error {
	if err := appMCPCommandRejectFTSStorageReferences(cap.generation, query); err != nil {
		return err
	}
	if err := validateCommandRuntimeSQLText(query, phase, cap.command.Writes); err != nil {
		return err
	}
	refs, err := commandSQLTableInventory(query)
	if err != nil {
		return err
	}
	allowed := commandTableSet(tables)
	for _, table := range refs {
		if !allowed[sqliteIdentifierFold(table)] {
			return fmt.Errorf("command SQL reads an undeclared table %q", table)
		}
	}
	return nil
}

func (exec *appMCPCommandExecution) guardStep(step *FlowStep) error {
	if exec == nil || exec.capability == nil || step == nil {
		return errors.New("command step has no capability")
	}
	if err := exec.capability.validateLifetime(); err != nil {
		return err
	}
	if step.Retry != 0 || step.RetryDelay != 0 || len(step.OnError) != 0 {
		return errors.New("command runtime refuses retries and on_error branches")
	}
	if step.Type == "respond" {
		_, _, refusal := commandRefusalStep(step)
		refusal = refusal && exec.phase == "prepare"
		if step.Respond == nil || !refusal && step.Respond.Status != 200 || exec.responses != 0 {
			return errors.New("command runtime refuses a malformed or duplicate response")
		}
	} else if step.Type != "sql" && step.Type != "compute" && step.Type != "set" && step.Type != "if" && step.Type != "for_each" && step.Type != "revoke_user_sessions" {
		return fmt.Errorf("command runtime refuses step type %q", step.Type)
	}
	if exec.budget.steps >= 256 {
		return errors.New("command global step budget exceeded")
	}
	exec.budget.steps++
	return nil
}

func (exec *appMCPCommandExecution) executeSQL(ctx *FlowContext, step *FlowStep) error {
	cap := exec.capability
	if err := cap.validateSQLPhase(step.SQL, exec.phase, append(append([]string(nil), appMCPCommandReadTables(cap.command, exec.phase)...), cap.command.Writes...)); err != nil {
		return err
	}
	params, err := appMCPResolveCommandRefs(step.CommandSQLParams, exec.values, cap.actor, cap.tenant, exec)
	if err != nil {
		return err
	}
	writeTargets, _ := sqlWriteTargets(step.SQL)
	isWrite := len(writeTargets) > 0 && !isReadOnlyQuery(step.SQL)
	if isWrite && exec.phase != "apply" {
		return errors.New("command read phase refuses mutations")
	}
	if isWrite && step.ExpectRows == "" {
		return errors.New("command mutations require an explicit cardinality assertion")
	}
	if isWrite {
		for _, target := range writeTargets {
			if !slices.Contains(cap.command.Writes, target.Table) {
				return errors.New("command SQL write target is outside its declaration")
			}
		}
	}
	args := commandNamedArgs(params)
	if isWrite {
		hookKey, hookTable, hookAction, hooked, err := cap.hookedWrite(step.SQL, writeTargets)
		if err != nil {
			return err
		}
		if hooked {
			affected, err := exec.executeHookedWrite(step, args, hookKey, hookTable, hookAction)
			if err != nil {
				return err
			}
			if affected > 0 {
				cap.noteWrite(hookTable, hookAction)
			}
			return exec.storeStepResult(ctx, step, []map[string]any{{"rows_affected": affected}})
		}
	}
	if err := cap.enterPhase(exec.phase, exec.phaseReadTables(), cap.effectTables(), exec.phase != "apply" || !isWrite); err != nil {
		return err
	}
	defer cap.leavePhase()
	// The RETURNING clause is read off the lexer, not a keyword scan: a write
	// whose text only mentions the word (in a string, say) returns no rows,
	// and one the scan missed reports a stale count through Exec. Either way
	// the cardinality check below would compare a number that is not the
	// statement's own.
	if isReadOnlyQuery(step.SQL) || sqlStatementReturns(sqlTokenize(step.SQL)) {
		result, err := exec.scanStatement(step.SQL, args)
		if err != nil {
			return err
		}
		exec.maskEncryptedRows(result)
		// An apply-phase read may carry expect_rows too (validateCommandStep
		// admits it on any apply SQL); it used to be accepted and skipped.
		// Both compare the rows the statement returned.
		if step.ExpectRows != "" {
			ok, checkErr := evalExpectRows(step.ExpectRows, int64(len(result)))
			if checkErr != nil {
				return checkErr
			}
			if !ok {
				message := "command SQL read cardinality check failed"
				if isWrite {
					message = "command DML RETURNING cardinality check failed"
				}
				return &appMCPCommandRowCountConflictError{message: message}
			}
		}
		if isWrite && len(result) > 0 {
			cap.noteStatementWrites(writeTargets)
		}
		return exec.storeStepResult(ctx, step, result)
	}
	result, err := cap.tx.ExecContext(cap.ctx, step.SQL, args...)
	if err != nil {
		return err
	}
	if !isWrite {
		return errors.New("command non-row-producing read is unsupported")
	}
	affected, err := result.RowsAffected()
	if err != nil || affected < 0 || affected > appMCPCommandRowsPerStep {
		return errors.New("command SQL mutation cardinality is unavailable or out of range")
	}
	if step.ExpectRows != "" {
		ok, checkErr := evalExpectRows(step.ExpectRows, affected)
		if checkErr != nil {
			return checkErr
		}
		if !ok {
			return &appMCPCommandRowCountConflictError{message: "command SQL mutation cardinality check failed"}
		}
	}
	if affected > 0 {
		cap.noteStatementWrites(writeTargets)
	}
	return exec.storeStepResult(ctx, step, []map[string]any{{"rows_affected": affected}})
}

func (exec *appMCPCommandExecution) maskEncryptedRows(rows []map[string]any) {
	if exec == nil || exec.capability == nil || exec.capability.generation == nil {
		return
	}
	cap := exec.capability
	tables := append(appMCPCommandReadTables(cap.command, exec.phase), cap.command.Writes...)
	seen := make(map[string]bool, len(tables))
	for _, authored := range tables {
		table, ok := cap.physicalTable(authored)
		if !ok || seen[sqliteIdentifierFold(table)] {
			continue
		}
		seen[sqliteIdentifierFold(table)] = true
		_ = cap.withInternalRead(func() error {
			maskEncryptedFieldsWith(cap.generation.view, &appMCPWriteTxQuerier{ctx: cap.ctx, tx: cap.tx}, table, rows, &cap.actor)
			return nil
		})
	}
}

func (exec *appMCPCommandExecution) phaseReadTables() []string {
	cap := exec.capability
	reads := append(append([]string(nil), appMCPCommandReadTables(cap.command, exec.phase)...), cap.command.Writes...)
	return append(reads, cap.effectTables()...)
}

// scanStatement runs a row-producing statement on the already-entered phase.
func (exec *appMCPCommandExecution) scanStatement(query string, args []any) ([]map[string]any, error) {
	return exec.scanStatementWithDecrypt(query, args, nil)
}

func (exec *appMCPCommandExecution) scanStatementWithDecrypt(query string, args []any, decrypt rowDecryptFunc) ([]map[string]any, error) {
	cap := exec.capability
	query, ok := sqlRunnableText(query)
	if !ok {
		return nil, errNoSQLStatement
	}
	var result []map[string]any
	err := cap.withCommandLengthLimit(func() error {
		rows, err := cap.tx.QueryContext(cap.ctx, query, args...)
		if err != nil {
			return err
		}
		var key []byte
		keyErr := cap.withInternalRead(func() error {
			var err error
			key, err = cryptoKeyForQuerierMainChecked(&appMCPWriteTxQuerier{ctx: cap.ctx, tx: cap.tx})
			return err
		})
		if keyErr != nil {
			_ = rows.Close()
			return keyErr
		}
		result, err = scanCommandRowsBoundedDecrypt(rows, key, appMCPCommandRowsPerStep, decrypt)
		return err
	})
	return result, err
}

// queryApplyRows runs a write with framework-appended RETURNING * in its own
// apply-phase scope. Its trusted target table supplies the source policy; the
// arbitrary authored SELECT path remains on its separate compatibility decoder.
func (exec *appMCPCommandExecution) queryApplyRows(query string, args []any, sourceTable string) ([]map[string]any, error) {
	cap := exec.capability
	if err := cap.enterPhase(exec.phase, exec.phaseReadTables(), cap.effectTables(), false); err != nil {
		return nil, err
	}
	defer cap.leavePhase()
	return exec.scanStatementWithDecrypt(query, args, nativeRowDecryptor(cap.generation.view, sourceTable))
}

func (exec *appMCPCommandExecution) storeStepResult(ctx *FlowContext, step *FlowStep, rows []map[string]any) error {
	encoded, err := json.Marshal(rows)
	if err != nil || len(encoded) > appMCPResultLimit || exec.resultBytes+len(encoded) > appMCPResultLimit {
		return errors.New("command SQL results exceed the aggregate phase byte bound")
	}
	exec.resultBytes += len(encoded)
	if step.Name == "" {
		return nil
	}
	value := any(rows)
	ctx.Data[step.Name] = value
	exec.results[step.Name] = value
	return exec.checkDataBudget(ctx.Data)
}

func (cap *appMCPCommandCapability) withCommandLengthLimit(run func() error) (retErr error) {
	if cap == nil || cap.conn == nil || run == nil {
		return errors.New("command SQLite connection is unavailable")
	}
	oldLimit := 0
	err := cap.conn.Raw(func(raw any) error {
		conn, ok := raw.(*sqlite3.SQLiteConn)
		if !ok {
			return errors.New("command connection is not a SQLite connection")
		}
		oldLimit = conn.GetLimit(sqlite3.SQLITE_LIMIT_LENGTH)
		conn.SetLimit(sqlite3.SQLITE_LIMIT_LENGTH, appMCPResultLimit)
		return nil
	})
	if err != nil {
		if cap.guard != nil {
			cap.guard.markConnectionUncertain(err)
		}
		return err
	}
	defer func() {
		if err := cap.conn.Raw(func(raw any) error {
			conn, ok := raw.(*sqlite3.SQLiteConn)
			if !ok {
				return errors.New("command connection is not a SQLite connection")
			}
			conn.SetLimit(sqlite3.SQLITE_LIMIT_LENGTH, oldLimit)
			return nil
		}); err != nil {
			if cap.guard != nil {
				cap.guard.markConnectionUncertain(err)
			}
			retErr = errors.Join(retErr, err)
		}
	}()
	return run()
}

func scanCommandRowsBounded(rows *sql.Rows, key []byte, maxRows int) ([]map[string]any, error) {
	return scanCommandRowsBoundedDecrypt(rows, key, maxRows, nil)
}

func scanCommandRowsBoundedDecrypt(rows *sql.Rows, key []byte, maxRows int, decrypt rowDecryptFunc) ([]map[string]any, error) {
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	types, err := rows.ColumnTypes()
	if err != nil {
		return nil, err
	}
	result := make([]map[string]any, 0)
	encodedBytes := 0
	for rows.Next() {
		if len(result) >= maxRows {
			return nil, errors.New("command SQL result exceeds its row bound")
		}
		values := make([]any, len(columns))
		pointers := make([]any, len(columns))
		for i := range values {
			pointers[i] = &values[i]
		}
		if err := rows.Scan(pointers...); err != nil {
			return nil, err
		}
		row := make(map[string]any, len(columns))
		for i, column := range columns {
			value := values[i]
			if bytes, ok := value.([]byte); ok {
				value = string(bytes)
			}
			if stamp, ok := value.(time.Time); ok {
				if stamp.IsZero() {
					value = nil
				} else {
					value = stamp.UTC().Format(time.RFC3339)
				}
			}
			row[column] = value
		}
		if decrypt == nil {
			DecryptRowFields(row, key)
		} else {
			decrypt(row, key)
		}
		for i, column := range columns {
			if i >= len(types) || types[i] == nil {
				continue
			}
			typeName := strings.ToUpper(types[i].DatabaseTypeName())
			value := row[column]
			if typeName == "BOOLEAN" {
				if integer, ok := value.(int64); ok {
					row[column] = integer != 0
				}
				continue
			}
			text, ok := value.(string)
			if !ok {
				continue
			}
			if strings.Contains(typeName, "INT") {
				if integer, err := strconv.ParseInt(text, 10, 64); err == nil {
					row[column] = integer
				}
				continue
			}
			if strings.Contains(typeName, "REAL") || strings.Contains(typeName, "FLOA") || strings.Contains(typeName, "DOUB") || strings.Contains(typeName, "NUM") || strings.Contains(typeName, "DEC") {
				if number, err := strconv.ParseFloat(text, 64); err == nil {
					row[column] = number
				}
			}
		}
		encoded, err := json.Marshal(row)
		if err != nil || encodedBytes+len(encoded) > appMCPResultLimit {
			return nil, errors.New("command SQL result exceeds its byte bound")
		}
		encodedBytes += len(encoded)
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func execStepCommandIf(ctx *FlowContext, step *FlowStep) error {
	condition, err := ctx.command.condition(step.Condition)
	if err != nil {
		return err
	}
	return appMCPCommandLexicalFrame(ctx, ctx.command, func() error {
		if condition {
			executeSteps(ctx, step.Steps)
		} else if len(step.ElseSteps) > 0 {
			executeSteps(ctx, step.ElseSteps)
		}
		return ctx.Error
	})
}

func appMCPCommandLexicalFrame(ctx *FlowContext, exec *appMCPCommandExecution, run func() error) error {
	data := make(map[string]any, len(ctx.Data))
	for key, value := range ctx.Data {
		data[key] = value
	}
	results := make(map[string]any, len(exec.results))
	for key, value := range exec.results {
		results[key] = value
	}
	err := run()
	for key := range ctx.Data {
		delete(ctx.Data, key)
	}
	for key, value := range data {
		ctx.Data[key] = value
	}
	exec.results = results
	return err
}

func execStepCommandForEach(ctx *FlowContext, step *FlowStep) error {
	exec := ctx.command
	path := strings.TrimSpace(step.ForEach)
	if match := commandForEachRef.FindStringSubmatch(path); match != nil {
		path = match[1]
	}
	if !strings.HasPrefix(path, "params.") {
		return errors.New("command loops require a typed array from the current phase values")
	}
	value, ok := exec.lookup(path)
	if !ok {
		return errors.New("command loop source is missing")
	}
	items, ok := value.([]any)
	if !ok {
		return errors.New("command loop source must be a JSON array")
	}
	if len(items) > 256 || exec.budget.loops+len(items) > 256 {
		return errors.New("command global loop iteration budget exceeded")
	}
	itemSchema, err := appMCPCommandArrayItemSchema(exec.capability, exec.phase, strings.TrimPrefix(path, "params."))
	if err != nil {
		return err
	}
	rows := make([]map[string]any, 0, len(items))
	for _, raw := range items {
		row, ok := raw.(map[string]any)
		if !ok || validateAppMCPSchemaValue(itemSchema, row) != nil {
			return errors.New("command loop contains a malformed object element")
		}
		copy, err := cloneCommandObject(row)
		if err != nil {
			return err
		}
		rows = append(rows, copy)
	}
	exec.budget.loops += len(rows)
	for _, row := range rows {
		if commandReservedIdentityMapKey(row) {
			return errors.New("command loop item shadows a reserved identity root")
		}
		if _, exists := ctx.Data[step.ForAs]; exists {
			return errors.New("command loop alias shadows existing phase data")
		}
		for _, scope := range exec.locals {
			if _, exists := scope[step.ForAs]; exists {
				return errors.New("command loop aliases must be distinct")
			}
		}
		priorLocals := len(exec.locals)
		err := appMCPCommandLexicalFrame(ctx, exec, func() error {
			exec.locals = append(exec.locals, map[string]any{step.ForAs: row})
			ctx.Data[step.ForAs] = row
			executeSteps(ctx, step.Steps)
			return ctx.Error
		})
		exec.locals = exec.locals[:priorLocals]
		if err != nil || ctx.Stopped {
			return err
		}
	}
	return nil
}

func commandReservedIdentityMapKey(row map[string]any) bool {
	for _, key := range []string{"params", "user", "operation", "session", "env", "request", "tenant_id", "group_id", "user_id"} {
		if _, exists := row[key]; exists {
			return true
		}
	}
	return false
}

func appMCPCommandArrayItemSchema(cap *appMCPCommandCapability, phase, path string) (*AppMCPSchema, error) {
	var schema *AppMCPSchema
	switch phase {
	case "prepare":
		schema = cap.tool.InputSchema
	default:
		schema = cap.command.PreparedSchema
	}
	if schema == nil || schema.Type != "object" {
		return nil, errors.New("command loop has no closed input schema")
	}
	property, ok := appMCPCommandRequiredSchemaPath(schema, path)
	if !ok {
		return nil, errors.New("command loop source is not a required declared array")
	}
	if property == nil || property.Type != "array" || property.Nullable || property.Items == nil || property.Items.Nullable || property.Items.Type != "object" || property.Items.AdditionalProperties == nil || *property.Items.AdditionalProperties {
		return nil, errors.New("command loop source must be a declared closed object array")
	}
	return property.Items, nil
}

func execStepCommandSet(ctx *FlowContext, step *FlowStep) error {
	exec := ctx.command
	if step.Name != "" && !commandLocalName(step.Name) {
		return errors.New("command set output has a reserved step name")
	}
	resolved := make(map[string]any, len(step.Set))
	for name, raw := range step.Set {
		if !commandLocalName(name) {
			return errors.New("command set output has a reserved name")
		}
		if _, exists := ctx.Data[name]; exists || strings.Contains(name, ".") {
			return errors.New("command set output shadows an existing identity or local")
		}
		value, err := appMCPCommandResolveValue(raw, ctx, exec)
		if err != nil {
			return err
		}
		value, err = appMCPCommandScalar(value)
		if err != nil {
			return err
		}
		resolved[name] = value
	}
	for name, value := range resolved {
		ctx.Data[name] = value
	}
	if step.Name != "" {
		ctx.Data[step.Name] = resolved
		exec.results[step.Name] = resolved
	}
	return exec.checkDataBudget(ctx.Data)
}

func execStepCommandCompute(ctx *FlowContext, step *FlowStep) error {
	if step.Compute == nil || step.Compute.Module == "" || step.Compute.Function == "" {
		return errors.New("command compute declaration is incomplete")
	}
	args, err := appMCPCommandResolveComputeArgs(step.Compute.Args, ctx.command)
	if err != nil {
		return err
	}
	args, err = appMCPComputeArgs(args)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(args)
	if err != nil || len(raw) > appMCPResultLimit {
		return errors.New("command compute input exceeds its phase limit")
	}
	computeCtx := context.WithValue(ctx.command.capability.ctx, appMCPCommandComputeKey{}, ctx.command.capability)
	result, err := RunComputeContext(computeCtx, ctx.App, step.Compute.Module, step.Compute.Function, args, step.Compute.Timeout)
	if err != nil {
		return err
	}
	result, err = appMCPCommandBoundJSON(result, appMCPResultLimit)
	if err != nil {
		return err
	}
	if step.Name == "" || !commandLocalName(step.Name) {
		return errors.New("command compute step requires a safe producer id")
	}
	ctx.Data[step.Name] = result
	ctx.command.results[step.Name] = result
	return ctx.command.checkDataBudget(ctx.Data)
}

func appMCPCommandResolveComputeArgs(value any, exec *appMCPCommandExecution) (any, error) {
	switch value := value.(type) {
	case string:
		path, ok := appMCPCommandTemplatePath(value)
		if !ok {
			if strings.Contains(value, "${{") || strings.Contains(value, "{{") {
				return nil, errors.New("command compute args must use typed references")
			}
			return value, nil
		}
		result, ok := exec.lookup(path)
		if !ok {
			return nil, errors.New("command compute reference is missing")
		}
		return result, nil
	case map[string]any:
		out := make(map[string]any, len(value))
		for key, item := range value {
			resolved, err := appMCPCommandResolveComputeArgs(item, exec)
			if err != nil {
				return nil, err
			}
			out[key] = resolved
		}
		return out, nil
	case []any:
		out := make([]any, len(value))
		for i, item := range value {
			resolved, err := appMCPCommandResolveComputeArgs(item, exec)
			if err != nil {
				return nil, err
			}
			out[i] = resolved
		}
		return out, nil
	default:
		return value, nil
	}
}

func appMCPCommandBoundJSON(value any, limit int) (any, error) {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > limit {
		return nil, errors.New("command output exceeds its byte limit")
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	var clone any
	if err := decoder.Decode(&clone); err != nil {
		return nil, err
	}
	return clone, nil
}

func (exec *appMCPCommandExecution) checkDataBudget(data map[string]any) error {
	raw, err := json.Marshal(data)
	if err != nil || len(raw) > appMCPResultLimit {
		return errors.New("command phase data exceeds its result bound")
	}
	return nil
}

func (exec *appMCPCommandExecution) respond(ctx *FlowContext, step *FlowStep) error {
	// A prepare refusal ends the phase with the author's literal message. No
	// response is recorded, so the coordinator never stores an operation.
	if status, message, ok := commandRefusalStep(step); ok && exec.phase == "prepare" {
		return &appMCPCommandRefusal{Code: commandRefusalCode(status), Message: message}
	}
	if step == nil || step.Respond == nil || step.Respond.Status != 200 {
		return errors.New("command success response is malformed")
	}
	if exec.responses != 0 {
		return errors.New("command phase returned more than once")
	}
	value, err := appMCPCommandResolveRespond(step.Respond.JSON, ctx, exec)
	if err != nil {
		return err
	}
	object, ok := value.(map[string]any)
	if ok && exec.generated != nil {
		// The same values the prepare steps saw are sealed into the arguments.
		// An author-written `generated` key is refused rather than overwritten.
		arguments, isObject := object["arguments"].(map[string]any)
		if _, taken := arguments[commandGeneratedKey]; !isObject || taken {
			return errors.New("command prepare response cannot carry generated values itself")
		}
		sealed := make(map[string]any, len(exec.generated))
		for name, drawn := range exec.generated {
			sealed[name] = drawn
		}
		arguments[commandGeneratedKey] = sealed
	}
	if !ok || validateAppMCPSchemaValue(exec.responseSchema, object) != nil {
		return errors.New("command phase response does not match its closed schema")
	}
	raw, err := json.Marshal(object)
	if err != nil || len(raw) > appMCPResultLimit {
		return errors.New("command phase response exceeds its byte limit")
	}
	exec.result, err = cloneCommandObject(object)
	if err != nil {
		return err
	}
	exec.responses++
	ctx.Stopped = true
	return nil
}

func appMCPCommandResolveRespond(value any, ctx *FlowContext, exec *appMCPCommandExecution) (any, error) {
	switch value.(type) {
	case map[string]any, map[any]any:
		resolved, _, err := appMCPCommandResolveIn(value, ctx, exec, exec.responseSchema)
		return resolved, err
	default:
		return nil, errors.New("command response must be an object")
	}
}

func appMCPCommandResolveValue(value any, ctx *FlowContext, exec *appMCPCommandExecution) (any, error) {
	resolved, _, err := appMCPCommandResolveIn(value, ctx, exec, nil)
	return resolved, err
}

// appMCPCommandResolveIn resolves one response value against the schema that
// will validate it. omitted is true when the value is a declared optional
// param that was left out; the enclosing object then writes an explicit null
// only where the target property is nullable and otherwise leaves the key out,
// so an optional, non-nullable argument can really be omitted and the sealed
// intent stays one deterministic shape. A caller with no object to drop the key
// from (omitted at the top level, or in an array) gets null.
func appMCPCommandResolveIn(value any, ctx *FlowContext, exec *appMCPCommandExecution, schema *AppMCPSchema) (resolved any, omitted bool, err error) {
	child := func(key string) *AppMCPSchema {
		if schema == nil {
			return nil
		}
		return schema.Properties[key]
	}
	object := func(n int, each func(yield func(key string, item any) error) error) (any, bool, error) {
		out := make(map[string]any, n)
		err := each(func(key string, item any) error {
			sub := child(key)
			v, gone, err := appMCPCommandResolveIn(item, ctx, exec, sub)
			if err != nil {
				return err
			}
			if gone {
				if sub == nil || !sub.Nullable {
					return nil
				}
				v = nil
			}
			out[key] = v
			return nil
		})
		return out, false, err
	}
	switch nested := value.(type) {
	case map[string]any:
		return object(len(nested), func(yield func(string, any) error) error {
			for key, item := range nested {
				if err := yield(key, item); err != nil {
					return err
				}
			}
			return nil
		})
	case map[any]any:
		return object(len(nested), func(yield func(string, any) error) error {
			for rawKey, item := range nested {
				key, ok := rawKey.(string)
				if !ok {
					return errors.New("command response key is not a string")
				}
				if err := yield(key, item); err != nil {
					return err
				}
			}
			return nil
		})
	case []any:
		var items *AppMCPSchema
		if schema != nil {
			items = schema.Items
		}
		out := make([]any, len(nested))
		for i, item := range nested {
			v, _, err := appMCPCommandResolveIn(item, ctx, exec, items)
			if err != nil {
				return nil, false, err
			}
			out[i] = v
		}
		return out, false, nil
	}
	text, ok := value.(string)
	if !ok {
		return value, false, nil
	}
	path, ok := appMCPCommandTemplatePath(text)
	if !ok {
		if strings.Contains(text, "${{") || strings.Contains(text, "{{") {
			return nil, false, errors.New("command response template must be one typed reference")
		}
		return text, false, nil
	}
	found, ok := exec.lookup(path)
	if !ok {
		if rest, isParam := strings.CutPrefix(path, "params."); isParam && exec.declaredParamPath(rest) {
			return nil, true, nil
		}
		return nil, false, errors.New("command response reference is missing or out of scope")
	}
	return found, false, nil
}

func appMCPCommandTemplatePath(value string) (string, bool) {
	if strings.TrimSpace(value) == "${{ params }}" || strings.TrimSpace(value) == "{{ params }}" {
		return "params", true
	}
	if whole, ok := commandWholeStepOutput(value); ok {
		return "steps." + whole + ".outputs", true
	}
	if match := commandParam.FindStringSubmatch(strings.TrimSpace(value)); match != nil {
		return match[1], true
	}
	if match := commandForEachRef.FindStringSubmatch(value); match != nil {
		return match[1], true
	}
	if match := commandLoopPathRef.FindStringSubmatch(value); match != nil {
		return match[1] + "." + match[2], true
	}
	return "", false
}

// declaredParamPath reports whether the phase's input schema (the tool input in
// prepare, the prepared arguments afterwards) declares this dotted params path.
// Values are validated against that schema before a phase runs, so a declared
// path that is absent in the values is an omitted optional value.
func (exec *appMCPCommandExecution) declaredParamPath(path string) bool {
	if exec == nil || exec.capability == nil || exec.capability.tool == nil || exec.capability.command == nil {
		return false
	}
	schema := exec.capability.command.PreparedSchema
	if exec.phase == "prepare" {
		schema = exec.capability.tool.InputSchema
	}
	_, ok := appMCPCommandSchemaPath(schema, path)
	return ok
}

func (exec *appMCPCommandExecution) lookup(path string) (any, bool) {
	if exec == nil || exec.capability == nil || path == "" {
		return nil, false
	}
	if rest, ok := strings.CutPrefix(path, "params."); ok {
		return commandLookupPath(exec.values, rest)
	}
	if path == "params" {
		if exec.capability.command != nil && len(exec.capability.command.Generated) > 0 {
			return commandParamsWithoutGenerated(exec.values), true
		}
		return exec.values, true
	}
	if strings.HasPrefix(path, "user.") {
		switch strings.TrimPrefix(path, "user.") {
		case "id":
			return exec.capability.actor.UserID, true
		case "group_id":
			return exec.capability.tenant, true
		}
	}
	if strings.HasPrefix(path, "steps.") {
		rest := strings.TrimPrefix(path, "steps.")
		if producer, suffix, found := strings.Cut(rest, ".outputs"); found && suffix == "" {
			result, ok := exec.results[producer]
			if !ok {
				return nil, false
			}
			if rows, ok := result.([]map[string]any); ok {
				outputs := make([]any, len(rows))
				for i, row := range rows {
					outputs[i] = row
				}
				return outputs, true
			}
			return result, true
		}
		parts := strings.SplitN(rest, ".outputs.", 2)
		if len(parts) != 2 {
			return nil, false
		}
		result, ok := exec.results[parts[0]]
		if !ok {
			return nil, false
		}
		if rest, first := strings.CutPrefix(parts[1], "first."); first {
			rows, ok := result.([]map[string]any)
			if !ok || len(rows) != 1 {
				return nil, false
			}
			return commandLookupPath(rows[0], rest)
		}
		return commandLookupPath(result, parts[1])
	}
	for i := len(exec.locals) - 1; i >= 0; i-- {
		if result, ok := commandLookupPath(exec.locals[i], path); ok {
			return result, true
		}
	}
	return nil, false
}

func (exec *appMCPCommandExecution) condition(condition string) (bool, error) {
	condition = strings.TrimSpace(condition)
	if strings.HasPrefix(condition, "${{") && strings.HasSuffix(condition, "}}") {
		condition = strings.TrimSpace(condition[3 : len(condition)-2])
	} else if strings.HasPrefix(condition, "{{") && strings.HasSuffix(condition, "}}") {
		condition = strings.TrimSpace(condition[2 : len(condition)-2])
	}
	lhs, operator, rhs, hasOperator := splitConditionOperator(condition)
	if !hasOperator {
		if strings.ContainsAny(condition, "|&()") {
			return false, errors.New("command condition is outside the closed scalar grammar")
		}
		left, ok := exec.lookup(condition)
		if !ok {
			return false, errors.New("command condition reference is missing")
		}
		truth, ok := left.(bool)
		if !ok {
			return false, errors.New("command condition requires a boolean")
		}
		return truth, nil
	}
	if lhs == "" || strings.ContainsAny(lhs, "|&()") || strings.Contains(rhs, "{{") || strings.Contains(rhs, "${{") {
		return false, errors.New("command condition is outside the closed scalar grammar")
	}
	leftPath := lhs
	if path, ok := appMCPCommandTemplatePath(lhs); ok {
		leftPath = path
	}
	left, ok := exec.lookup(leftPath)
	if !ok {
		return false, errors.New("command condition reference is missing")
	}
	right := strings.TrimSpace(rhs)
	right = strings.Trim(right, `"'`)
	// splitConditionOperator reads both `=` and `==` as "=", but the
	// comparisons below name equality "==". Without this every authored
	// equality was false (numbers, booleans) or an error (strings).
	if operator == "=" {
		operator = "=="
	}
	comparison, err := appMCPCommandCompare(left, right, operator)
	return comparison, err
}

func appMCPCommandCompare(left any, right, operator string) (bool, error) {
	switch value := left.(type) {
	case string:
		switch operator {
		case "==":
			return value == right, nil
		case "!=":
			return value != right, nil
		default:
			return false, errors.New("string command conditions only support equality")
		}
	case bool:
		if right != "true" && right != "false" {
			return false, errors.New("invalid boolean command condition")
		}
		expected := right == "true"
		if operator == "==" {
			return value == expected, nil
		}
		if operator == "!=" {
			return value != expected, nil
		}
	case int64:
		n, err := strconv.ParseInt(right, 10, 64)
		if err != nil {
			return false, err
		}
		return commandCompareInt(value, n, operator), nil
	case int:
		n, err := strconv.ParseInt(right, 10, 64)
		if err != nil {
			return false, err
		}
		return commandCompareInt(int64(value), n, operator), nil
	case json.Number:
		if a, err := value.Int64(); err == nil {
			if b, err := strconv.ParseInt(right, 10, 64); err == nil {
				return commandCompareInt(a, b, operator), nil
			}
		}
		a, errA := value.Float64()
		b, errB := strconv.ParseFloat(right, 64)
		if errA != nil || errB != nil || math.IsNaN(a) || math.IsInf(a, 0) || math.IsNaN(b) || math.IsInf(b, 0) {
			return false, errors.New("invalid numeric command condition")
		}
		if math.Abs(a) > 1e15 || math.Abs(b) > 1e15 {
			return false, errors.New("numeric command condition exceeds its bound")
		}
		return commandCompareNumber(a, b, operator), nil
	}
	return false, errors.New("command condition values have unsupported types")
}

func commandCompareInt(a, b int64, operator string) bool {
	switch operator {
	case "==":
		return a == b
	case "!=":
		return a != b
	case ">":
		return a > b
	case "<":
		return a < b
	case ">=":
		return a >= b
	case "<=":
		return a <= b
	default:
		return false
	}
}

func commandCompareNumber(a, b float64, operator string) bool {
	switch operator {
	case "==":
		return a == b
	case "!=":
		return a != b
	case ">":
		return a > b
	case "<":
		return a < b
	case ">=":
		return a >= b
	case "<=":
		return a <= b
	default:
		return false
	}
}

func appMCPCommandScalar(value any) (any, error) {
	switch value := value.(type) {
	case string:
		return value, nil
	case bool:
		return value, nil
	case int:
		return appMCPCommandScalar(int64(value))
	case int64:
		if value > appMCPCommandSafeIntegerMax || value < -appMCPCommandSafeIntegerMax {
			return nil, errors.New("command integer is outside the safe range")
		}
		return value, nil
	case json.Number:
		if integer, err := value.Int64(); err == nil {
			if integer > appMCPCommandSafeIntegerMax || integer < -appMCPCommandSafeIntegerMax {
				return nil, errors.New("command integer is outside the safe range")
			}
			return integer, nil
		}
		f, err := value.Float64()
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || math.Abs(f) > 1e15 {
			return nil, errors.New("command number is not finite and bounded")
		}
		return f, nil
	default:
		return nil, errors.New("command reference is not a scalar")
	}
}
