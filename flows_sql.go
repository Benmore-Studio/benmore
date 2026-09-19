//go:build !cli

package main

// Parameterized SQL steps, row-count assertions, and trusted dynamic-SQL guards.

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
)

// resolveSQLParamValue evaluates a `with.params:` value for a sql step.
// The raw expression has already had its GHA refs normalized to `{{...}}`
// shape; we run interpolateCtx to fully resolve it against the current
// flow context, then string-coerce. Complex values (slices/maps) get
// JSON-encoded so the agent can pair them with SQLite's json_each() /
// json_extract() without an explicit `| json` pipe in the YAML.
//
// The rawExpr is typically a single `{{...}}` placeholder. If it
// resolves to a primitive (string/number/bool), the rendered form is
// used as-is. If it resolves to a slice or map, the resolved value
// (not the rendered string) is JSON-encoded.
//
// Returns (rendered, isNil). isNil is true when a single-placeholder
// expression resolved to Go `nil`; the SQL bind path uses this to
// bind SQL NULL instead of the literal string. Before this signal
// existed, nil values rendered as `"<nil>"` (Go's fmt default) and
// landed in DB columns as the literal three-character string.
func resolveSQLParamValue(rawExpr string, ctx *FlowContext) (string, bool) {
	rendered := interpolateCtx(rawExpr, ctx)
	// Fast path: pure scalar (no leftover template, value already
	// rendered to a primitive string representation). Most params hit
	// this - IDs, status filters, counts.
	trimmed := strings.TrimSpace(rawExpr)
	if !strings.HasPrefix(trimmed, "{{") || !strings.HasSuffix(trimmed, "}}") {
		return rendered, false
	}
	// Single-placeholder form: check the raw value type in ctx.Data so
	// slices/maps can be JSON-encoded.
	inner := strings.TrimSpace(trimmed[2 : len(trimmed)-2])
	// Strip any pipe chain - `{{ x | length }}` always produces a
	// string from ApplyPipe, never nil.
	key := inner
	if pipeIdx := strings.Index(inner, "|"); pipeIdx >= 0 {
		key = strings.TrimSpace(inner[:pipeIdx])
		// Piped expressions don't go through the nil-checks below.
		flat := flattenData(ctx.Data)
		if _, exists := flat[key]; exists {
			return rendered, false
		}
		return rendered, false
	}
	flat := flattenData(ctx.Data)
	if v, ok := flat[key]; ok {
		if v == nil {
			return "", true
		}
		switch v.(type) {
		case []any, []map[string]any, map[string]any:
			if b, err := json.Marshal(v); err == nil {
				return string(b), false
			}
		}
	}
	return rendered, false
}

// flowDB returns the transaction if active, otherwise the app database.
func flowDB(ctx *FlowContext) interface {
	Exec(query string, args ...any) (sql.Result, error)
	Query(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
} {
	if ctx.Tx != nil {
		return ctx.Tx
	}
	return ctx.App.DB
}

func execStepSQL(ctx *FlowContext, step *FlowStep) error {
	// Resolve any explicit step-local params (`with.params:` in the
	// flow YAML) and merge them into ctx.Params for the duration of
	// this step. interpolateCtxSafe reads `:name` placeholders from
	// ctx.Params, so this is the simplest plumbing. Complex values
	// (slice/map) are JSON-encoded so they pair with SQLite's
	// json_each() / json_extract() without any extra agent ceremony.
	var restoreParams func()
	if len(step.SQLParams) > 0 {
		backup := make(map[string]string, len(step.SQLParams))
		backupNull := make(map[string]bool, len(step.SQLParams))
		for k := range step.SQLParams {
			if old, ok := ctx.Params[k]; ok {
				backup[k] = old
			}
			if ctx.NullParams != nil {
				if wasNull, ok := ctx.NullParams[k]; ok {
					backupNull[k] = wasNull
				}
			}
		}
		if ctx.NullParams == nil {
			ctx.NullParams = make(map[string]bool, len(step.SQLParams))
		}
		for k, rawExpr := range step.SQLParams {
			val, isNil := resolveSQLParamValue(rawExpr, ctx)
			ctx.Params[k] = val
			if isNil {
				ctx.NullParams[k] = true
			} else {
				delete(ctx.NullParams, k)
			}
		}
		restoreParams = func() {
			for k := range step.SQLParams {
				if old, ok := backup[k]; ok {
					ctx.Params[k] = old
				} else {
					delete(ctx.Params, k)
				}
				if wasNull, ok := backupNull[k]; ok {
					ctx.NullParams[k] = wasNull
				} else {
					delete(ctx.NullParams, k)
				}
			}
		}
		defer restoreParams()
	}

	// Use safe interpolation to prevent SQL injection from external data
	query, args := interpolateCtxSafe(step.SQL, ctx)
	db := flowDB(ctx)

	// Detect statement shape. SELECT and any mutation that carries a
	// `RETURNING …` clause both produce rows; route them through Query
	// so ctx.Data[step.Name] captures the values exactly the way
	// `${{ steps.X.outputs.<col> }}` expects. Pre-v2.7.5 every non-
	// SELECT went to db.Exec, which silently dropped RETURNING output
	// - agents wrote
	//   `INSERT … RETURNING id` followed by `${{ steps.ws.outputs.id }}`
	// expecting it to work (it matches every other SQL framework's
	// shape), found `{{ws.id}}` leaking literally into responses,
	// and then had to rewrite as INSERT + follow-up SELECT.
	//
	// Detection is regex-free on purpose: `\bRETURNING\b` test against
	// the uppercased query, after a quick prefix check so we don't pay
	// the scan cost on the common SELECT path.
	//
	// THREE row-producing shapes:
	//   1. `SELECT …` - plain query
	//   2. `WITH foo AS (…) SELECT …` - CTE. Pre-v2.7.6 the prefix
	//      check missed this (starts with WITH, not SELECT), so every
	//      CTE-shaped step landed in db.Exec and the output silently
	//      vanished. Every agent writing non-trivial business rules
	//      hit this - risk-gate calcs (`WITH ref AS …, calc AS …
	//      SELECT …`) are the canonical case. An earlier app build
	//      worked around it by rewriting CTEs as nested subqueries.
	//   3. `INSERT/UPDATE/DELETE … RETURNING …` - already handled by
	//      hasReturningClause since v2.7.5.
	//
	// db.Query is safe for any statement type in SQLite - non-row-
	// producing variants just return an empty result set, no error.
	upper := strings.TrimSpace(strings.ToUpper(query))
	startsWithRowProducer := strings.HasPrefix(upper, "SELECT") ||
		strings.HasPrefix(upper, "WITH")
	hasReturning := !startsWithRowProducer && hasReturningClause(upper)
	// Serialize the actual DB call when running inside a transaction:
	// *sql.Tx is not safe for concurrent use, so a `parallel:` block of
	// SQL steps inside a `transaction: true` flow would otherwise race.
	// The DB pool (ctx.Tx == nil path) is already concurrency-safe, so we
	// only pay the lock on the transactional path.
	if ctx.Tx != nil {
		ctx.TxMu.Lock()
		defer ctx.TxMu.Unlock()
	}
	if startsWithRowProducer || hasReturning {
		key := cryptoKeyForQuerier(db)
		sqlRows, err := db.Query(query, args...)
		if err != nil {
			return fmt.Errorf("sql: %w", err)
		}
		rows, err := scanRows(sqlRows, key)
		if err != nil {
			return fmt.Errorf("sql scan: %w", err)
		}
		if step.Name != "" {
			// Always store as a slice. Pre-v2.3.2 we collapsed a
			// single-row result into a bare map at ctx.Data[step.Name]
			// - that was nice for `{{step.field}}` templates after a
			// single-row WHERE id = :id query, but it made
			// `outputs.rows` / `outputs.*` templates return an object
			// instead of a 1-element array when there was exactly one
			// match. Frontend code then had to handle both shapes.
			//
			// flattenData below restores the per-field shortcut for
			// the 1-row case, so `{{step.field}}` still works AND
			// `{{step.rows}}` returns a real slice.
			ctx.DataMu.Lock()
			ctx.Data[step.Name] = rows
			ctx.DataMu.Unlock()
		}
	} else {
		res, err := db.Exec(query, args...)
		if err != nil {
			return fmt.Errorf("sql: %w", err)
		}
		affected, _ := res.RowsAffected()
		// Expose the affected count as a step output so authors can branch on
		// it (`if: ${{ steps.x.outputs.rows_affected }}`) and so the previously
		// invisible "0 rows" case is observable. Additive: exec steps stored
		// nothing here before, and no existing key is named rows_affected.
		if step.Name != "" {
			ctx.DataMu.Lock()
			ctx.Data[step.Name] = map[string]any{"rows_affected": affected}
			ctx.DataMu.Unlock()
		}
		// expect_rows: fail the flow LOUD when a guarded write affected the
		// wrong number of rows, instead of silently falling through to a 200.
		if step.ExpectRows != "" {
			ok, eerr := evalExpectRows(step.ExpectRows, affected)
			if eerr != nil {
				return eerr
			}
			if !ok {
				return fmt.Errorf("sql: expect_rows assertion failed on step %q: %d row(s) affected, expected %s (the guard/WHERE matched nothing - the write did NOT happen)", step.Name, affected, step.ExpectRows)
			}
		}
	}
	return nil
}

// evalExpectRows evaluates an `expect_rows` assertion (e.g. ">0", ">=1", "=1",
// "!=0", or a bare "1" meaning "=1") against the affected row count.
func evalExpectRows(expr string, n int64) (bool, error) {
	e := strings.TrimSpace(expr)
	op := "="
	for _, o := range []string{">=", "<=", "!=", "==", ">", "<", "="} {
		if strings.HasPrefix(e, o) {
			op = o
			e = strings.TrimSpace(e[len(o):])
			break
		}
	}
	want, err := strconv.ParseInt(strings.TrimSpace(e), 10, 64)
	if err != nil {
		return false, fmt.Errorf("sql: invalid expect_rows %q - use a comparison like \">0\", \">=1\", \"=1\", \"!=0\"", expr)
	}
	switch op {
	case ">":
		return n > want, nil
	case ">=":
		return n >= want, nil
	case "<":
		return n < want, nil
	case "<=":
		return n <= want, nil
	case "!=":
		return n != want, nil
	default: // "=" / "=="
		return n == want, nil
	}
}

// hasReturningClause reports whether the (already-uppercased) query
// contains a `RETURNING …` clause as a standalone keyword. We do a
// substring match guarded by simple word-boundary checks so an
// identifier or string literal that happens to contain "RETURNING"
// doesn't trip the detector. The guard is intentionally permissive:
// `RETURNING` is so uncommon outside its SQL keyword usage that a
// false positive would only land if someone named a column `returning`
// AND referenced it as a bare identifier in a non-RETURNING statement
// - vanishingly rare and the worst outcome is a Query call instead
// of an Exec call on a mutation, which still executes correctly.
func hasReturningClause(upperQuery string) bool {
	const kw = "RETURNING"
	idx := strings.Index(upperQuery, kw)
	if idx < 0 {
		return false
	}
	// Require a non-identifier char before the keyword (start of string
	// or whitespace/punctuation). Without this, an identifier ending in
	// "RETURNING" (e.g. a column literally named `is_returning`) would
	// match.
	if idx > 0 {
		prev := upperQuery[idx-1]
		if (prev >= 'A' && prev <= 'Z') || (prev >= '0' && prev <= '9') || prev == '_' {
			return false
		}
	}
	// Require a non-identifier char after the keyword.
	end := idx + len(kw)
	if end < len(upperQuery) {
		next := upperQuery[end]
		if (next >= 'A' && next <= 'Z') || (next >= '0' && next <= '9') || next == '_' {
			return false
		}
	}
	return true
}

// execStepSQLDynamic is the text-interpolation counterpart to
// execStepSQL. It uses interpolateCtx (which substitutes `{{ ... }}`
// values as raw text into the query string) instead of
// interpolateCtxSafe (which replaces them with `?` placeholders and
// binds values). This is the only path that lets an AI agent's
// generated SQL actually execute: a query string cannot be
// param-bound into itself.
//
// SECURITY: the resolved query is logged and the WHOLE statement is
// inherently injection-shaped - `{{ q }}` becomes literal SQL bytes,
// not a bound value. Use only when the SQL is assembled by trusted
// internal callers (LLM agent flow, admin tooling). NEVER funnel
// user-typed input through this path.
func execStepSQLDynamic(ctx *FlowContext, step *FlowStep) error {
	// Same per-step param overlay as execStepSQL - but written into
	// BOTH ctx.Params (for `:name` placeholders) AND ctx.Data (for
	// `{{name}}` text substitutions, which is the dominant form in
	// sql_dynamic since the whole point is text interpolation).
	// Restored on exit so the overlay doesn't leak into siblings.
	var restoreParams func()
	if len(step.SQLParams) > 0 {
		paramBackup := make(map[string]string, len(step.SQLParams))
		dataBackup := make(map[string]any, len(step.SQLParams))
		dataHad := make(map[string]bool, len(step.SQLParams))
		ctx.DataMu.Lock()
		for k := range step.SQLParams {
			if old, ok := ctx.Params[k]; ok {
				paramBackup[k] = old
			}
			if old, ok := ctx.Data[k]; ok {
				dataBackup[k] = old
				dataHad[k] = true
			}
		}
		for k, rawExpr := range step.SQLParams {
			resolved, _ := resolveSQLParamValue(rawExpr, ctx)
			// sql_dynamic is text-substitution only - NULL has no
			// stable serialization in raw SQL bytes anyway. Resolved
			// empty string is the closest sensible value for nil here.
			ctx.Params[k] = resolved
			ctx.Data[k] = resolved
		}
		ctx.DataMu.Unlock()
		restoreParams = func() {
			ctx.DataMu.Lock()
			defer ctx.DataMu.Unlock()
			for k := range step.SQLParams {
				if old, ok := paramBackup[k]; ok {
					ctx.Params[k] = old
				} else {
					delete(ctx.Params, k)
				}
				if dataHad[k] {
					ctx.Data[k] = dataBackup[k]
				} else {
					delete(ctx.Data, k)
				}
			}
		}
		defer restoreParams()
	}

	// M-1: sql_dynamic substitutes refs as raw SQL TEXT (no param bind),
	// so a request-controlled value reaching the query is an injection
	// sink. Forbid request-sourced refs unless the author explicitly set
	// `trusted: true`. The comment in the template "never funnel user
	// input here" is now enforced, not just advisory.
	if err := flowDynamicGuardRequestRefs(step, ctx); err != nil {
		return err
	}

	query := interpolateCtx(step.SQL, ctx)
	db := flowDB(ctx)

	// Log the resolved query - sql_dynamic is high-risk; surfacing the
	// final SQL into the request log makes audits/reviews tractable.
	log.Printf("flows: sql_dynamic step=%q query=%q", step.Name, query)

	// Same prefix detection as execStepSQL - SELECT, WITH (CTE), or
	// INSERT/UPDATE/DELETE … RETURNING all produce rows we want to
	// capture into ctx.Data[step.Name]. See the longer comment in
	// execStepSQL for context.
	upper := strings.TrimSpace(strings.ToUpper(query))
	startsWithRowProducer := strings.HasPrefix(upper, "SELECT") ||
		strings.HasPrefix(upper, "WITH")
	hasReturning := !startsWithRowProducer && hasReturningClause(upper)
	if startsWithRowProducer || hasReturning {
		key := cryptoKeyForQuerier(db)
		sqlRows, err := db.Query(query)
		if err != nil {
			return fmt.Errorf("sql_dynamic: %w", err)
		}
		rows, err := scanRows(sqlRows, key)
		if err != nil {
			return fmt.Errorf("sql scan: %w", err)
		}
		if step.Name != "" {
			ctx.DataMu.Lock()
			ctx.Data[step.Name] = rows
			ctx.DataMu.Unlock()
		}
	} else {
		if _, err := db.Exec(query); err != nil {
			return fmt.Errorf("sql_dynamic: %w", err)
		}
	}
	return nil
}

// flowDynamicGuardRequestRefs enforces M-1: a `run: sql_dynamic` step
// interpolates references as RAW SQL TEXT, so any request-sourced value
// reaching the query string is a SQL-injection sink. Reject the step at
// run time when its query template references a request-tainted key
// (path/query/form/JSON-body param) unless the author has explicitly
// opted in with `trusted: true`.
//
// Invariant: request-controlled data MUST NOT be funnelled into a
// sql_dynamic query body without an explicit trusted acknowledgement.
// The previous behavior relied on a code comment ("never funnel user
// input here") that nothing enforced.
//
// trusted:true preserves the documented escape hatch (AI-agent /
// admin-tooling flows that assemble SQL from server-side values) for
// backward compatibility - it just makes the dangerous case opt-in
// instead of the default.
func flowDynamicGuardRequestRefs(step *FlowStep, ctx *FlowContext) error {
	if step == nil || ctx == nil || len(ctx.RequestKeys) == 0 {
		return nil
	}
	if step.Trusted {
		return nil // author explicitly accepted raw-text interpolation risk
	}
	for key := range ctx.RequestKeys {
		if key == "" {
			continue
		}
		if flowSQLReferencesKey(step.SQL, key) {
			return fmt.Errorf("sql_dynamic: step %q references request-sourced value %q as raw SQL text (injection risk); use a `run: sql` step with `:%s` param binding, or set `trusted: true` if this SQL is assembled only from trusted internal callers", step.Name, key, key)
		}
		// Also guard any `with.params:` overlay feeding the same key,
		// since those values are written into ctx.Data/ctx.Params and may
		// be derived from request input before reaching the query.
		if _, ok := step.SQLParams[key]; ok {
			return fmt.Errorf("sql_dynamic: step %q binds request-sourced value %q via with.params into raw SQL text (injection risk); set `trusted: true` only if assembled from trusted internal callers", step.Name, key)
		}
	}
	return nil
}

// flowSQLReferencesKey reports whether a sql_dynamic template references
// `key` either as a `:key` placeholder (substituted as text by
// interpolateCtx) or inside a `{{ ... }}` expression (including dotted
// `{{key.sub}}` and piped `{{ key | ... }}` forms). Match boundaries are
// checked so `:user` doesn't spuriously match `:user_id`.
func flowSQLReferencesKey(sql, key string) bool {
	// `:key` form - require a non-identifier char (or end) after the key.
	for idx := 0; ; {
		at := strings.Index(sql[idx:], ":"+key)
		if at < 0 {
			break
		}
		pos := idx + at
		after := pos + 1 + len(key)
		if after >= len(sql) || !flowIsIdentChar(sql[after]) {
			return true
		}
		idx = after
	}
	// `{{ ... key ... }}` form.
	for i := 0; i+1 < len(sql); i++ {
		if sql[i] != '{' || sql[i+1] != '{' {
			continue
		}
		end := strings.Index(sql[i+2:], "}}")
		if end < 0 {
			break
		}
		expr := strings.TrimSpace(sql[i+2 : i+2+end])
		// Leading identifier of the expression (before a pipe / dot /
		// space) is the bound name.
		head := expr
		for _, sep := range []string{"|", ".", " ", "["} {
			if j := strings.Index(head, sep); j >= 0 {
				head = head[:j]
			}
		}
		if strings.TrimSpace(head) == key {
			return true
		}
		i = i + 2 + end + 1
	}
	return false
}

// flowIsIdentChar reports whether b can appear inside a `:param` name
// (used to enforce a word boundary when matching `:key`).
func flowIsIdentChar(b byte) bool {
	return b == '_' ||
		(b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9')
}
