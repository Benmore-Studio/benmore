//go:build !cli

package main

import "strings"

// A transactional flow rolls its transaction back before an on_error handler
// runs (executeSteps), so the handler's writes are durable on their own. The
// outputs of the writes that rollback undid stayed in the flow context: an
// `INSERT ... RETURNING id` handed the handler an id that no longer existed,
// and SQLite gave that id to the handler's own next insert (round 2026-11-05).
// Those outputs are removed before the handler starts. Reads keep theirs: a
// lookup made before the failure is usually what the handler reports.

// noteTxWriteOutput records that step stored the output of a write it ran in
// the flow's transaction.
func noteTxWriteOutput(ctx *FlowContext, step *FlowStep, query string) {
	if ctx == nil || ctx.Tx == nil || step == nil || step.Name == "" || !flowSQLWrites(query) {
		return
	}
	ctx.DataMu.Lock()
	if ctx.txWriteSteps == nil {
		ctx.txWriteSteps = map[string]bool{}
	}
	ctx.txWriteSteps[step.Name] = true
	ctx.DataMu.Unlock()
}

// forgetRolledBackWriteOutputs removes the outputs noteTxWriteOutput
// recorded, after the transaction that made them rolled back. A reference to
// one in the handler is then unresolved, like any output that does not exist
// (a `|| fallback` supplies a value).
func (ctx *FlowContext) forgetRolledBackWriteOutputs() {
	if ctx == nil {
		return
	}
	ctx.DataMu.Lock()
	for name := range ctx.txWriteSteps {
		delete(ctx.Data, name)
		prefix := name + "."
		for key := range ctx.Data {
			if strings.HasPrefix(key, prefix) {
				delete(ctx.Data, key)
			}
		}
	}
	ctx.txWriteSteps = nil
	ctx.DataMu.Unlock()
	ctx.flatCache.invalidate()
}

// flowSQLWrites reports whether any statement of a rendered script is an
// INSERT, UPDATE, DELETE or REPLACE INTO, with or without RETURNING (read off
// the shared lexer, so a column named updated_at is not a write).
func flowSQLWrites(query string) bool {
	for _, stmt := range sqlTokenStatements(sqlTokenize(query)) {
		if kind := flowStatementKind(stmt); kind == flowSQLWrite || kind == flowSQLReturning {
			return true
		}
	}
	return false
}
