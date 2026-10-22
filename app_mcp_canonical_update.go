//go:build !cli

package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
)

type appMCPContextTx struct {
	tx      *sql.Tx
	ctx     context.Context
	private bool
	// cap, when set, receives every job a hook or webhook subscription queues
	// through this transaction (app_mcp_command_effects.go).
	cap *appMCPCommandCapability
}

func (q appMCPContextTx) cleanMain() error {
	if !q.private {
		return nil
	}
	rows, err := q.tx.QueryContext(q.ctx, "PRAGMA database_list")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var seq int
		var name, file string
		if err := rows.Scan(&seq, &name, &file); err != nil {
			return err
		}
		if name != "main" && name != "temp" {
			return errors.New("attached databases are not supported")
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	var tempObjects int
	if err := q.tx.QueryRowContext(q.ctx, "SELECT count(*) FROM temp.sqlite_schema").Scan(&tempObjects); err != nil {
		return err
	}
	if tempObjects != 0 {
		return errors.New("temporary schema objects are not supported")
	}
	return nil
}

func (q appMCPContextTx) Query(query string, args ...any) (*sql.Rows, error) {
	if err := q.cleanMain(); err != nil {
		return nil, err
	}
	return q.tx.QueryContext(q.ctx, query, args...)
}
func (q appMCPContextTx) QueryRow(query string, args ...any) *sql.Row {
	if err := q.cleanMain(); err != nil {
		return q.tx.QueryRowContext(q.ctx, "SELECT raise(ABORT, 'connector policy check failed')")
	}
	return q.tx.QueryRowContext(q.ctx, query, args...)
}
func (q appMCPContextTx) Exec(query string, args ...any) (sql.Result, error) {
	if err := q.cleanMain(); err != nil {
		return nil, err
	}
	return q.tx.ExecContext(q.ctx, query, args...)
}

// applyAppMCPCanonicalUpdate owns the complete private connector transaction:
// policy serialization, owner-file lease, live grant reauthorization, the
// shared CRUD pipeline, final reauthorization and commit. Public write routing
// remains disabled until B2 approval and recovery are implemented.
func applyAppMCPCanonicalUpdate(ctx context.Context, pin appMCPWriteAuthorityPin, declaration string, input map[string]any, now time.Time) (projected map[string]any, refreshTables []string, err error) {
	if ctx == nil || pin.Origin == nil || pin.Generation == nil || pin.Generation.view == nil || pin.Origin.DB == nil {
		return nil, nil, denyAppMCPWriteAuthority(errors.New("invalid canonical update context"))
	}
	ctx, release, lease, err := acquireAppMCPWritePolicy(ctx, pin.Origin.Dir)
	if err != nil {
		return nil, nil, denyAppMCPWriteAuthority(err)
	}
	defer release()
	if err := ctx.Err(); err != nil {
		return nil, nil, denyAppMCPWriteAuthority(err)
	}
	tool := appMCPUpdateTool(pin.Generation.manifest, declaration)
	if tool == nil || validateAppMCPUpdateDeclaration(*tool) != nil {
		return nil, nil, denyAppMCPWriteAuthority(errors.New("private canonical update declaration is unavailable"))
	}
	payload, err := json.Marshal(input)
	if err != nil || len(payload) > appMCPInputLimit {
		return nil, nil, denyAppMCPWriteAuthority(errors.New("invalid canonical update input"))
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var copiedInput map[string]any
	if decoder.Decode(&copiedInput) != nil || copiedInput == nil {
		return nil, nil, denyAppMCPWriteAuthority(errors.New("invalid canonical update input"))
	}
	id, data, err := validateAppMCPUpdateInput(tool, copiedInput)
	if err != nil {
		return nil, nil, denyAppMCPWriteAuthority(err)
	}
	table := tool.Handler.Table
	pin.Permissions = append([]string(nil), tool.Permissions...)
	tx, err := pin.Origin.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, denyAppMCPWriteAuthority(err)
	}
	defer tx.Rollback()
	ctxTx := appMCPContextTx{tx: tx, ctx: ctx, private: true}
	if err := ctxTx.cleanMain(); err != nil {
		return nil, nil, denyAppMCPWriteAuthority(err)
	}
	if _, err := verifyAppMCPRevisionEnrollmentForTx(ctx, pin.Origin, pin.Generation, tx, lease); err != nil {
		return nil, nil, denyAppMCPWriteAuthority(err)
	}
	// The declaration's key schema must match the one physical id primary key.
	columns, err := mainTableColumnsWith(ctxTx, table)
	if err != nil {
		return nil, nil, denyAppMCPWriteAuthority(err)
	}
	var idColumn *Column
	primaryKeys := 0
	knownColumns := make(map[string]bool, len(columns))
	for i := range columns {
		knownColumns[columns[i].Name] = true
		if columns[i].PK {
			primaryKeys++
			if columns[i].Name == "id" {
				idColumn = &columns[i]
			}
		}
	}
	if idColumn == nil || primaryKeys != 1 || !appMCPUpdateKeyTypeMatches(tool.InputSchema.Properties["id"], idColumn.Type) ||
		tool.InputSchema.Properties["id"].Type == "string" && !idColumn.NotNull {
		return nil, nil, denyAppMCPWriteAuthority(errors.New("update declaration key schema does not match the physical primary key"))
	}
	for field := range data {
		if !knownColumns[field] {
			return nil, nil, denyAppMCPWriteAuthority(errors.New("update declaration contains an unavailable column"))
		}
		var column *Column
		for i := range columns {
			if columns[i].Name == field {
				column = &columns[i]
				break
			}
		}
		if column == nil || !appMCPUpdateValueTypeMatches(tool.InputSchema.Properties["data"].Properties[field], column.Type, data[field], column.NotNull) {
			return nil, nil, denyAppMCPWriteAuthority(errors.New("update field type does not match the physical column"))
		}
	}
	data, err = canonicalUpdateValues(tool, data)
	if err != nil {
		return nil, nil, denyAppMCPWriteAuthority(err)
	}
	for _, field := range tool.Output.Include {
		if !knownColumns[field] || !isValidColumnName(field) || apiHiddenColumn(pin.Generation.view, table, field) {
			return nil, nil, denyAppMCPWriteAuthority(errors.New("update output contains an unavailable or hidden column"))
		}
	}
	if err := appMCPUpdateEffectsSupported(ctxTx, pin.Generation.view, table); err != nil {
		return nil, nil, denyAppMCPWriteAuthority(err)
	}
	protected := protectedUpdateFields(pin.Generation.view, table)
	for field := range data {
		if protected[field] {
			return nil, nil, denyAppMCPWriteAuthority(fmt.Errorf("field %q is not writable", field))
		}
	}
	if v := ownedFieldViolation(pin.Generation.view, table, mapKeys(data)...); v != nil {
		return nil, nil, denyAppMCPWriteAuthority(fmt.Errorf("field %q is owned by command %q", v.Field, v.Command))
	}
	snapshot, err := appMCPWriteAuthorityForTx(ctx, tx, pin, now)
	if err != nil {
		return nil, nil, err
	}
	actor := snapshot.Actor
	if !SessionCanAccessTable(pin.Generation.view, table, OpUpdate, &actor) {
		return nil, nil, denyAppMCPWriteAuthority(errors.New("update is not authorized for the current actor"))
	}
	if !SessionCanAccessTable(pin.Generation.view, table, OpRead, &actor) {
		return nil, nil, denyAppMCPWriteAuthority(errors.New("update readback is not authorized for the current actor"))
	}
	if _, err := txAuthorizedRow(ctxTx, pin.Generation.view, table, id, &actor, "edit"); err != nil {
		return nil, nil, denyAppMCPWriteAuthority(err)
	}
	if pin.Effect != nil && pin.Effect.Transfer.Kind == "pull" {
		if pin.ExpectedRowDigest == "" || !appMCPOperationHex(pin.ExpectedRowDigest, 32) {
			return nil, nil, denyAppMCPWriteAuthority(errors.New("pull row snapshot is unavailable"))
		}
		currentDigest, err := appMCPTransferRowDigest(ctx, tx, pin.Generation.view, table, id)
		if err != nil || !SecureCompare(currentDigest, pin.ExpectedRowDigest) {
			return nil, nil, denyAppMCPWriteAuthority(errors.New("pull target changed after approval"))
		}
	}
	if locked, err := canonicalRecordLocked(ctx, tx, table, id, actor.UserID); err != nil {
		return nil, nil, denyAppMCPWriteAuthority(err)
	} else if locked {
		return nil, nil, denyAppMCPWriteAuthority(errors.New("record is locked by another user"))
	}
	expectedUpdatedAt, err := canonicalRawUpdatedAt(ctx, tx, table, id, knownColumns["updated_at"])
	if err != nil {
		return nil, nil, denyAppMCPWriteAuthority(err)
	}
	_, after, refreshTables, err := applyCanonicalUpdateTxContextPrivate(ctx, tx, pin.Generation.view, &actor, table, id, data, expectedUpdatedAt)
	if err != nil {
		return nil, nil, err
	}
	projected, err = appMCPProjectRow(tool, after)
	if err != nil {
		return nil, nil, denyAppMCPWriteAuthority(err)
	}
	encoded, err := json.Marshal(projected)
	if err != nil || len(encoded) > appMCPResultLimit {
		return nil, nil, denyAppMCPWriteAuthority(errors.New("canonical update result exceeds the supported limit"))
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, denyAppMCPWriteAuthority(err)
	}
	if _, err := appMCPWriteAuthorityForTx(ctx, tx, pin, time.Now().UTC()); err != nil {
		return nil, nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, denyAppMCPWriteAuthority(err)
	}
	if err := validateAppMCPWriteLease(lease, pin); err != nil {
		return nil, nil, denyAppMCPWriteAuthority(err)
	}
	if err := ctxTx.cleanMain(); err != nil {
		return nil, nil, denyAppMCPWriteAuthority(err)
	}
	groupID, userID := canonicalUpdateBroadcastScope(pin.Generation.view, table, actor)
	hookRefreshes := canonicalHookRefreshScopes(pin.Generation.view, refreshTables, table, actor)
	if err := tx.Commit(); err != nil {
		return nil, nil, fmt.Errorf("canonical update commit outcome is unknown: %w", err)
	}
	release()
	Increment(pin.Origin, meterScope(&actor), "row_updates")
	BroadcastScopedDirect(pin.Origin, table, "update", groupID, userID)
	for _, refresh := range hookRefreshes {
		BroadcastScopedDirect(pin.Origin, refresh.Table, "refresh", refresh.GroupID, refresh.UserID)
	}
	return projected, refreshTables, nil
}

type canonicalHookRefreshScope struct {
	Table   string
	GroupID string
	UserID  int64
}

func canonicalHookRefreshScopes(view *App, tables []string, primaryTable string, actor Session) []canonicalHookRefreshScope {
	seen := make(map[string]bool, len(tables))
	refreshes := make([]canonicalHookRefreshScope, 0, len(tables))
	for _, table := range tables {
		folded := sqliteIdentifierFold(table)
		if folded == "" || folded == sqliteIdentifierFold(primaryTable) || strings.HasPrefix(folded, "_benmore_") || seen[folded] {
			continue
		}
		seen[folded] = true
		appTable := false
		for _, candidate := range view.Tables {
			if sqliteIdentifierFold(candidate.Name) == folded {
				appTable = true
				break
			}
		}
		if !appTable {
			continue
		}
		groupID, userID := realtimeNoTenant, int64(0)
		hasUID := hasColumn(view, table, "user_id")
		grouped := view.Group != nil && view.Group.Key != "" && hasColumn(view, table, view.Group.Key)
		mode := ""
		if view.Access != nil {
			mode = view.Access.ModeFor(table, "read", hasUID, grouped)
		}
		if mode == "anon" || mode == "everyone" {
			groupID, userID = "", 0
		} else if grouped {
			if actorGroup := actor.EffectiveGroupID(); actorGroup != "" && actorGroup != "0" {
				groupID = actorGroup
			}
		} else if hasUID {
			groupID = ""
			if actor.UserID > 0 {
				userID = actor.UserID
			} else {
				userID = realtimeNoOwner
			}
		} else {
			groupID = ""
			if actor.UserID > 0 {
				userID = actor.UserID
			} else {
				userID = realtimeNoOwner
			}
		}
		refreshes = append(refreshes, canonicalHookRefreshScope{Table: table, GroupID: groupID, UserID: userID})
	}
	return refreshes
}

func canonicalUpdateBroadcastScope(view *App, table string, actor Session) (string, int64) {
	groupID, userID := actor.EffectiveGroupID(), actor.UserID
	if view == nil || view.Access == nil {
		return groupID, userID
	}
	hasUID, hasGroupKey := hasColumn(view, table, "user_id"), view.Group != nil && view.Group.Key != "" && hasColumn(view, table, view.Group.Key)
	mode := view.Access.ModeFor(table, "read", hasUID, hasGroupKey)
	if mode == "anon" || mode == "everyone" {
		return "", 0
	}
	return groupID, userID
}

func appMCPUpdateKeyTypeMatches(schema *AppMCPSchema, declared string) bool {
	typ := strings.ToUpper(strings.TrimSpace(declared))
	if schema == nil {
		return false
	}
	switch schema.Type {
	case "integer":
		return strings.Contains(typ, "INT")
	case "string":
		return strings.Contains(typ, "CHAR") || strings.Contains(typ, "CLOB") || strings.Contains(typ, "TEXT")
	default:
		return false
	}
}

func canonicalRawUpdatedAt(ctx context.Context, tx *sql.Tx, table, id string, present bool) (string, error) {
	if !present {
		return "", nil
	}
	var stamp sql.NullString
	query := fmt.Sprintf("SELECT CAST(updated_at AS TEXT) FROM main.%s WHERE id = ?", quoteIdent(table))
	if err := tx.QueryRowContext(ctx, query, id).Scan(&stamp); err != nil {
		return "", err
	}
	if !stamp.Valid {
		return "", nil
	}
	return stamp.String, nil
}

func canonicalRecordLocked(ctx context.Context, tx *sql.Tx, table, id string, userID int64) (bool, error) {
	if _, err := tx.ExecContext(ctx, `DELETE FROM main._benmore_locks WHERE table_name = ? AND row_id = ? AND datetime(expires_at) < datetime('now')`, table, id); err != nil {
		return false, err
	}
	var lockUserID int64
	err := tx.QueryRowContext(ctx, `SELECT user_id FROM main._benmore_locks WHERE table_name = ? AND row_id = ?`, table, id).Scan(&lockUserID)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return lockUserID != userID, nil
}

func canonicalUpdateValues(tool *AppMCPTool, values map[string]any) (map[string]any, error) {
	dataSchema := tool.InputSchema.Properties["data"]
	converted := make(map[string]any, len(values))
	for field, value := range values {
		schema := dataSchema.Properties[field]
		if schema == nil {
			return nil, errors.New("update field is not declared")
		}
		switch schema.Type {
		case "null", "boolean", "string":
			converted[field] = value
		case "integer", "number":
			rational, ok := appMCPExactNumber(value)
			if !ok {
				return nil, errors.New("invalid numeric update field")
			}
			if schema.Type == "integer" {
				if !rational.IsInt() || !rational.Num().IsInt64() {
					return nil, errors.New("integer update field is outside SQLite binding range")
				}
				converted[field] = rational.Num().Int64()
				continue
			}
			floating, _ := rational.Float64()
			if math.IsInf(floating, 0) || math.IsNaN(floating) {
				return nil, errors.New("number update field is outside SQLite binding range")
			}
			roundTrip, ok := appMCPExactNumber(floating)
			if !ok || roundTrip.Cmp(rational) != 0 {
				return nil, errors.New("number update field cannot be bound without precision loss")
			}
			converted[field] = floating
		default:
			return nil, errors.New("composite update values are unsupported by canonical SQL binding")
		}
	}
	return converted, nil
}

func appMCPUpdateValueTypeMatches(schema *AppMCPSchema, declared string, value any, notNull bool) bool {
	if schema == nil {
		return false
	}
	if value == nil {
		return schema.Type == "null" && !notNull
	}
	typ := strings.ToUpper(strings.TrimSpace(declared))
	switch {
	case strings.Contains(typ, "INT"):
		return schema.Type == "integer"
	case strings.Contains(typ, "CHAR"), strings.Contains(typ, "CLOB"), strings.Contains(typ, "TEXT"), strings.Contains(typ, "DATE"), strings.Contains(typ, "TIME"):
		return schema.Type == "string"
	case strings.Contains(typ, "REAL"), strings.Contains(typ, "FLOA"), strings.Contains(typ, "DOUB"):
		return schema.Type == "number" || schema.Type == "integer"
	case strings.Contains(typ, "NUMERIC"), strings.Contains(typ, "DECIMAL"):
		return schema.Type == "number" || schema.Type == "integer"
	case strings.Contains(typ, "BOOL"):
		return schema.Type == "boolean"
	default:
		return false
	}
}

func appMCPUpdateEffectsSupported(tx mutationTx, app *App, table string) error {
	if app == nil || tx == nil {
		return errors.New("canonical update policy is unavailable")
	}
	for _, flow := range app.Flows {
		if flow.Trigger.Type == "on_update" && flow.Trigger.Table == table {
			return errors.New("connector update requires unsupported event-flow recovery")
		}
	}
	if app.Hooks != nil {
		for _, hook := range app.Hooks.OnUpdate[table] {
			if hook.SQL == "" || hook.Webhook != "" || hook.Email != nil || hook.Notify != nil || hook.WS != nil || hook.SMS != nil {
				return errors.New("connector update requires unsupported external hook recovery")
			}
		}
	}
	rows, err := queryMetadataRows(tx, "SELECT tables, events FROM main._benmore_webhooks WHERE active=1")
	if err != nil {
		return fmt.Errorf("check connector webhook effects: %w", err)
	}
	for _, webhook := range rows {
		if webhookSubscriptionMatches(webhook, table, "update") {
			return errors.New("connector update requires unsupported webhook recovery")
		}
	}
	return nil
}
