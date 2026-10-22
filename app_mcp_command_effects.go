//go:build !cli

package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Durable effects of an approved write command.
//
// A command's business writes and its SQL hooks run inside one transaction. Every
// other consequence (an email, SMS, webhook, notification or real-time hook
// action, and every matching webhook subscription) is a durable job queued by
// CRUD's own functions (fireAfterHooksTx, enqueueWebhookSubscriptionsTx) through
// that same transaction: a failed enqueue rolls the whole command back, and
// nothing is delivered before COMMIT. The worker delivers after commit.
//
// Each queued job is stamped with the grant identity (never a token) of the
// connector that committed the operation. The receipt stores only the effect
// ids; delivery status is read live from the job row, so a receipt never claims
// "delivered" without evidence and the business commit is reported independently.

// appMCPEffectKey is the job-payload key that marks a connector-command effect.
const appMCPEffectKey = "_mcp_effect"

// appMCPEffectLimit bounds the effects one command may queue.
const appMCPEffectLimit = 64

const (
	appMCPEffectNone      = "none"
	appMCPEffectPending   = "pending"
	appMCPEffectDelivered = "delivered"
	appMCPEffectFailed    = "failed"
	appMCPEffectBlocked   = "blocked"
	appMCPEffectUnknown   = "unknown"

	appMCPEffectBlockedPrefix = "blocked: "
)

var appMCPEffectStatuses = []any{appMCPEffectNone, appMCPEffectPending, appMCPEffectDelivered, appMCPEffectFailed, appMCPEffectBlocked, appMCPEffectUnknown}

// appMCPEffectIntent is the immutable part of an effect, sealed in the receipt.
// ID is the job id; Kind is "hook" or "webhook"; Target is "<table>.<action>".
type appMCPEffectIntent struct {
	ID            string `json:"id"`
	Kind          string `json:"kind"`
	Target        string `json:"target"`
	PayloadDigest string `json:"payload_digest,omitempty"`
}

// appMCPEffectGrant is the stamp a queued effect carries: identity and the
// authority epochs it was committed under, never a credential.
type appMCPEffectGrant struct {
	OperationID         string   `json:"operation_id"`
	GrantID             string   `json:"grant_id"`
	ActorID             int64    `json:"actor_id"`
	ActorCreated        string   `json:"actor_created"`
	Tenant              string   `json:"tenant"`
	Client              string   `json:"client"`
	Resource            string   `json:"resource"`
	OwnerEpoch          string   `json:"owner_epoch"`
	WriteEpoch          string   `json:"write_epoch"`
	ExternalExportEpoch string   `json:"external_export_epoch,omitempty"`
	TransferKind        string   `json:"transfer_kind,omitempty"`
	PayloadDigest       string   `json:"payload_digest,omitempty"`
	Permissions         []string `json:"permissions"`
}

func (q appMCPContextTx) enqueueMutationJob(kind, table, action, jobType, flowName string, payload map[string]any) error {
	if q.cap == nil {
		_, _, err := enqueueTypedJob(q, jobType, "", flowName, payload, nil, jobEnqueueOpts{})
		return err
	}
	return q.cap.enqueueEffect(q, kind, table, action, jobType, flowName, payload)
}

// enqueueEffect queues one effect job in the command transaction, stamped with
// the committing grant, and records its id. It runs only inside the hook-write
// scope, whose authorizer admits a single _benmore_jobs INSERT while the window
// below is open; app hook SQL cannot open it.
func (cap *appMCPCommandCapability) enqueueEffect(tx appMCPContextTx, kind, table, action, jobType, flowName string, payload map[string]any) error {
	pin := cap.originPin
	if cap.origin != appMCPCommandConnectorOrigin || pin == nil || pin.GrantID == "" || !appMCPOperationHex(cap.operationID, 32) {
		return errors.New("command effects need the connector grant that commits the operation")
	}
	if cap.guard == nil || cap.guard.authorizerPolicy().metadataOp != appMCPCommandMetadataHookWrite {
		return errors.New("command effects can be queued only in the hook-write scope")
	}
	if len(cap.effects) >= appMCPEffectLimit {
		return fmt.Errorf("command queued more than %d effects", appMCPEffectLimit)
	}
	permissions := append([]string(nil), cap.tool.Permissions...)
	sort.Strings(permissions)
	payloadDigest := ""
	if jobType == appMCPTransferJobType {
		encoded, encodeErr := json.Marshal(payload[appMCPTransferPayloadKey])
		if encodeErr != nil {
			return errors.New("transfer effect payload could not be sealed")
		}
		payloadDigest = appMCPOperationDigest("benmore:mcp:transfer-payload:v1", encoded)
	}
	stamped := make(map[string]any, len(payload)+1)
	for name, value := range payload {
		stamped[name] = value
	}
	effectStamp := map[string]any{"operation_id": cap.operationID, "grant_id": pin.GrantID,
		"actor_id": pin.UserID, "actor_created": pin.UserCreated, "tenant": pin.Tenant, "client": pin.Client, "resource": pin.Resource,
		"owner_epoch": cap.epoch, "write_epoch": cap.writeEpoch, "permissions": permissions}
	if jobType == appMCPTransferJobType && cap.tool != nil && cap.tool.Transfer != nil {
		effectStamp["transfer_kind"] = cap.tool.Transfer.Kind
		if cap.tool.Transfer.Kind == "push" {
			if cap.exportEpoch == "" {
				return errors.New("external export epoch is unavailable")
			}
			effectStamp["external_export_epoch"] = cap.exportEpoch
		}
	}
	if payloadDigest != "" {
		effectStamp["payload_digest"] = payloadDigest
	}
	stamped[appMCPEffectKey] = effectStamp
	cap.guard.setJobInsert(true)
	id, _, err := enqueueTypedJob(tx, jobType, "", flowName, stamped, nil, jobEnqueueOpts{})
	cap.guard.setJobInsert(false)
	if err != nil {
		return err
	}
	if id <= 0 {
		return errors.New("command effect was not queued")
	}
	cap.effects = append(cap.effects, appMCPEffectIntent{ID: strconv.FormatInt(id, 10), Kind: kind, Target: table + "." + action, PayloadDigest: payloadDigest})
	return nil
}

// appMCPEffectReceipt is the sealed receipt form of the recorded effects.
func appMCPEffectReceipt(effects []appMCPEffectIntent) ([]json.RawMessage, error) {
	raws := make([]json.RawMessage, 0, len(effects))
	for _, effect := range effects {
		raw, err := appMCPCanonicalJSON(effect)
		if err != nil {
			return nil, err
		}
		raws = append(raws, raw)
	}
	return raws, nil
}

// appMCPDecodeEffects strictly decodes the effects of a stored receipt.
func appMCPDecodeEffects(raws []json.RawMessage) ([]appMCPEffectIntent, error) {
	if raws == nil || len(raws) > appMCPEffectLimit {
		return nil, errors.New("command receipt effects are invalid")
	}
	effects := make([]appMCPEffectIntent, 0, len(raws))
	for _, raw := range raws {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		var effect appMCPEffectIntent
		if decoder.Decode(&effect) != nil {
			return nil, errors.New("command receipt effect is invalid")
		}
		if canonical, err := appMCPCanonicalJSON(effect); err != nil || !bytes.Equal(canonical, raw) {
			return nil, errors.New("command receipt effect is not canonical")
		}
		if id, err := strconv.ParseInt(effect.ID, 10, 64); err != nil || id <= 0 || strconv.FormatInt(id, 10) != effect.ID ||
			effect.Kind != "hook" && effect.Kind != "webhook" && effect.Kind != "flow" && effect.Kind != "transfer" || effect.Target == "" || len(effect.Target) > 128 {
			return nil, errors.New("command receipt effect is invalid")
		}
		if effect.Kind == "transfer" && !appMCPOperationHex(effect.PayloadDigest, 32) || effect.Kind != "transfer" && effect.PayloadDigest != "" {
			return nil, errors.New("command receipt transfer digest is invalid")
		}
		effects = append(effects, effect)
	}
	return effects, nil
}

// appMCPEffectStatus maps a job row to a delivery status. completed is the only
// evidence of delivery; a worker that died mid-run, a deleted row, or a lease
// that lapsed without recovery is unknown, never delivered.
func appMCPEffectStatus(status, jobError, lease string, now time.Time) string {
	switch status {
	case "pending":
		return appMCPEffectPending
	case "running":
		if lease != "" && lease < now.UTC().Format(sqliteDateTimeLayout) {
			return appMCPEffectUnknown
		}
		return appMCPEffectPending
	case "completed":
		return appMCPEffectDelivered
	case "failed":
		switch {
		case strings.HasPrefix(jobError, appMCPEffectBlockedPrefix):
			return appMCPEffectBlocked
		case strings.HasPrefix(jobError, "worker died mid-execution"), strings.HasPrefix(jobError, "unknown:"):
			return appMCPEffectUnknown
		}
		return appMCPEffectFailed
	}
	return appMCPEffectUnknown
}

// appMCPEffectAggregate is the one status for a set of effects: anything still
// in flight first, then the least certain outcome; delivered only when all are.
func appMCPEffectAggregate(statuses []string) string {
	if len(statuses) == 0 {
		return appMCPEffectNone
	}
	for _, want := range []string{appMCPEffectPending, appMCPEffectUnknown, appMCPEffectBlocked, appMCPEffectFailed} {
		for _, status := range statuses {
			if status == want {
				return want
			}
		}
	}
	return appMCPEffectDelivered
}

// appMCPEffectsView is the receipt and status shape for downstream effects,
// reported independently of the business commit. Status is read from the job
// rows now; the receipt itself only links the effect ids.
func appMCPEffectsView(cap *appMCPCommandCapability, operationID string, raws []json.RawMessage) (map[string]any, error) {
	effects, err := appMCPDecodeEffects(raws)
	if err != nil {
		return nil, err
	}
	statuses := make([]string, len(effects))
	phases := make([]string, len(effects))
	recoveryRefs := make([]string, len(effects))
	if len(effects) > 0 {
		now := time.Now().UTC()
		err = cap.withInternalRead(func() error {
			for i, effect := range effects {
				id, _ := strconv.ParseInt(effect.ID, 10, 64)
				var status, jobError, lease string
				err := cap.tx.QueryRowContext(cap.ctx, "SELECT status, COALESCE(error,''), COALESCE(lease_expires_at,'') FROM main._benmore_jobs WHERE id=? AND json_extract(payload, '$._mcp_effect.operation_id')=?", id, operationID).Scan(&status, &jobError, &lease)
				switch {
				case errors.Is(err, sql.ErrNoRows):
					statuses[i] = appMCPEffectUnknown
				case err != nil:
					return err
				default:
					statuses[i] = appMCPEffectStatus(status, jobError, lease, now)
				}
				if effect.Kind == "transfer" {
					_ = cap.tx.QueryRowContext(cap.ctx, `SELECT phase,recovery_ref FROM main._benmore_mcp_transfer_state WHERE job_id=? AND operation_id=?`, id, operationID).Scan(&phases[i], &recoveryRefs[i])
					switch phases[i] {
					case "pushed", "attached":
						statuses[i] = appMCPEffectDelivered
					case "unknown", "requesting", "downloaded":
						statuses[i] = appMCPEffectUnknown
					}
				}
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("read command effect status: %w", err)
		}
	}
	items := make([]any, len(effects))
	for i, effect := range effects {
		item := map[string]any{"id": effect.ID, "kind": effect.Kind, "target": effect.Target, "status": statuses[i]}
		if effect.Kind == "transfer" && phases[i] != "" {
			item["phase"] = phases[i]
			if recoveryRefs[i] != "" {
				item["recovery_ref"] = recoveryRefs[i]
			}
		}
		items[i] = item
	}
	return map[string]any{"status": appMCPEffectAggregate(statuses), "items": items}, nil
}

// appMCPEffectsSchema is the connector output schema of appMCPEffectsView.
func appMCPEffectsSchema() map[string]any {
	properties := map[string]any{
		"id":     map[string]any{"type": "string", "pattern": "^[1-9][0-9]{0,18}$"},
		"kind":   map[string]any{"type": "string", "enum": []any{"hook", "webhook", "flow", "transfer"}},
		"target": map[string]any{"type": "string", "maxLength": 128},
		"status": map[string]any{"type": "string", "enum": appMCPEffectStatuses[1:]},
	}
	properties["phase"] = map[string]any{"type": "string", "enum": []any{"queued", "requesting", "downloaded", "attached", "pushed", "unknown"}}
	properties["recovery_ref"] = map[string]any{"type": "string", "maxLength": 256}
	item := map[string]any{"type": "object", "additionalProperties": false, "properties": properties, "required": []string{"id", "kind", "target", "status"}}
	return appMCPClosedObject(map[string]any{
		"status": map[string]any{"type": "string", "enum": appMCPEffectStatuses},
		"items":  map[string]any{"type": "array", "maxItems": appMCPEffectLimit, "items": item},
	})
}

func appMCPBlockedEffect(reason string) error {
	return jobNotRetryable{errors.New(appMCPEffectBlockedPrefix + reason)}
}

// appMCPEffectGate runs before a worker delivers a job. A job queued by a
// connector command runs only while the grant that committed it is active,
// unrevoked and unexpired, the owner's authority is the one it was committed
// under, and the grant's actor still holds the command's permissions. Otherwise
// the job is blocked (failed, never retried, never delivered); the business
// mutation is never re-run. A failure to read the stores is retried.
func appMCPEffectGate(app *App, data map[string]any) error {
	raw, present := data[appMCPEffectKey]
	if !present {
		return nil
	}
	encoded, err := json.Marshal(raw)
	var stamp appMCPEffectGrant
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err != nil || decoder.Decode(&stamp) != nil || stamp.GrantID == "" || len(stamp.Permissions) == 0 {
		return appMCPBlockedEffect("the effect record is malformed")
	}
	if stamp.TransferKind != "" && stamp.TransferKind != "pull" && stamp.TransferKind != "push" || stamp.TransferKind == "push" && (!appMCPOperationHex(stamp.ExternalExportEpoch, 32) || !appMCPOperationHex(stamp.PayloadDigest, 32)) || stamp.TransferKind == "pull" && (stamp.ExternalExportEpoch != "" || !appMCPOperationHex(stamp.PayloadDigest, 32)) {
		return appMCPBlockedEffect("the transfer effect record is malformed")
	}
	now := time.Now().UTC()
	grant, err := readAppMCPGrant(app.DB, stamp.GrantID)
	switch {
	case errors.Is(err, errAppMCPGrantDenied):
		return appMCPBlockedEffect("the connector grant no longer exists")
	case err != nil:
		return fmt.Errorf("read connector grant: %w", err)
	case grant.Revoked:
		return appMCPBlockedEffect("the connector grant is revoked")
	case grant.ExpiresAt <= now.Unix():
		return appMCPBlockedEffect("the connector grant has expired")
	}
	state, err := currentAppMCPEpoch(app.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return appMCPBlockedEffect("the owner authority is unavailable")
	} else if err != nil {
		return fmt.Errorf("read owner authority: %w", err)
	}
	if !state.Exposed || state.ApprovedWrites == nil || !*state.ApprovedWrites || grant.App != state.App ||
		!SecureCompare(grant.Epoch, state.Epoch) || !SecureCompare(stamp.OwnerEpoch, state.Epoch) || !SecureCompare(stamp.WriteEpoch, state.ApprovedWriteEpoch) {
		return appMCPBlockedEffect("the owner authority changed")
	}
	if stamp.TransferKind == "push" && (!state.ExternalExport || state.ExternalExportEpoch != stamp.ExternalExportEpoch) {
		return appMCPBlockedEffect("external export is disabled or changed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), readOnlyQueryTimeout)
	defer cancel()
	actor, err := appMCPGrantActorFor(ctx, app, grant, now)
	if err != nil || !scopesWithin(actor.Scopes, strings.Join(stamp.Permissions, " ")) {
		return appMCPBlockedEffect("the grant no longer holds the command's permissions")
	}
	return nil
}

// appMCPCommandWebhookSubscriptions reads the active webhook subscriptions
// through the transaction, so a missing table is an error, not an empty set.
func (cap *appMCPCommandCapability) webhookSubscriptions() ([]map[string]any, error) {
	var subscriptions []map[string]any
	err := cap.withInternalRead(func() error {
		var err error
		subscriptions, err = queryMetadataRows(&appMCPWriteTxQuerier{ctx: cap.ctx, tx: cap.tx}, "SELECT tables, events FROM main._benmore_webhooks WHERE active=1")
		return err
	})
	return subscriptions, err
}

// webhookSubscribed reports whether an active subscription matches a write.
func (cap *appMCPCommandCapability) webhookSubscribed(table, action string) bool {
	for _, subscription := range cap.subscriptions {
		if webhookSubscriptionMatches(subscription, table, action) {
			return true
		}
	}
	return false
}

// appMCPEffectDisclosure lists, in plain words, what the approved command can
// send or queue, from the captured hooks and the live subscriptions. It is what
// the approver is shown instead of "no downstream effects".
func appMCPEffectDisclosure(cap *appMCPCommandCapability) ([]string, error) {
	subscriptions, err := cap.webhookSubscriptions()
	if err != nil {
		return nil, fmt.Errorf("check command webhook effects: %w", err)
	}
	cap.subscriptions = subscriptions
	var lines []string
	writes := appMCPCommandApplyWrites(cap.command)
	tables := make([]string, 0, len(writes))
	for table := range writes {
		tables = append(tables, table)
	}
	sort.Strings(tables)
	for _, authored := range tables {
		table := authored
		if physical, ok := cap.physicalTable(authored); ok {
			table = physical
		}
		for _, action := range appMCPHookActions {
			if !writes[authored][action] {
				continue
			}
			_, on := appMCPHookSets(cap.generation.hooks, action)
			var kinds []string
			for _, hook := range on[table] {
				if appMCPCommandHookIsSQL(hook) {
					continue
				}
				for _, kind := range []struct {
					present bool
					text    string
				}{{hook.Email != nil, "send an email"}, {hook.SMS != nil, "send a text message"}, {hook.Webhook != "", "call a webhook"},
					{hook.Notify != nil, "create a notification"}, {hook.WS != nil, "broadcast a real-time message"}} {
					if kind.present {
						kinds = append(kinds, kind.text)
					}
				}
			}
			if cap.webhookSubscribed(table, action) {
				kinds = append(kinds, "deliver to a matching webhook subscription")
			}
			if len(kinds) > 0 {
				lines = append(lines, fmt.Sprintf("A %s of %s will %s after it is applied.", action, table, strings.Join(kinds, " and ")))
			}
		}
	}
	if appMCPCommandHasRevoke(cap.command) {
		lines = append(lines, "End every sign-in, API token and connector grant of the member this change names, so they are signed out as it is applied.")
	}
	if cap.tool.Transfer != nil {
		transfer := cap.tool.Transfer
		if transfer.Kind == "pull" {
			lines = append(lines, "Download the selected upstream file and attach its private copy to the reviewed target row.")
		} else if transfer.Kind == "push" {
			lines = append(lines, "Send the reviewed artifact to the configured upstream destination once, with idempotency and read-only reconciliation.")
		}
	}
	return lines, nil
}
