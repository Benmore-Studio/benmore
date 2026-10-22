//go:build !cli

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
)

// A task is a durable delegation, not a saved login. No session ID, token,
// password or credential is stored. Missing metadata denotes a pre-upgrade task.
type scheduledAuthority struct {
	Version int     `json:"version"`
	Actor   Session `json:"actor"`
}

func marshalScheduledAuthority(s *Session) string {
	snapshot := *s
	snapshot.ID, snapshot.Email = "", ""
	snapshot.Permissions = nil
	encoded, _ := json.Marshal(scheduledAuthority{Version: 1, Actor: snapshot})
	return string(encoded)
}

// loadScheduledActor resolves a real account and its current permissions without
// creating a session. Legacy tasks may infer a tenant only if it is unambiguous.
func loadScheduledActor(app *App, userID int64, group *string) (*Session, error) {
	return loadScheduledActorWith(app, app.DB, userID, group, false)
}

// strict is used by connector authority; legacy scheduled tasks retain their
// existing optional role-table fallback during upgrade inventory.
// scheduledActorReadError marks a strict actor load that failed to READ
// (busy, I/O, cancellation) as opposed to reading an actor that is absent or
// not allowed. Authority checks deny the second and report the first.
type scheduledActorReadError struct{ err error }

func (e *scheduledActorReadError) Error() string { return e.err.Error() }
func (e *scheduledActorReadError) Unwrap() error { return e.err }

// scheduledActorFailure wraps the formatted error as a read failure unless
// cause is sql.ErrNoRows, which is an absent row (a denial).
func scheduledActorFailure(cause error, format string, args ...any) error {
	err := fmt.Errorf(format, args...)
	if errors.Is(cause, sql.ErrNoRows) {
		return err
	}
	return &scheduledActorReadError{err: err}
}

func loadScheduledActorWith(app *App, db mutationQuerier, userID int64, group *string, strict bool) (*Session, error) {
	schema := ""
	prefix := ""
	if strict {
		schema = "main"
		prefix = "main."
	}
	actor := &Session{UserID: userID}
	var deactivated sql.NullString
	var verified, grandfathered int
	err := db.QueryRow("SELECT COALESCE(email,''), COALESCE(role,'user'), deactivated_at, COALESCE(verified,0), COALESCE(email_grandfathered,0) FROM "+prefix+"_benmore_users WHERE id=? AND COALESCE(password_change_required,0)=0", userID).Scan(&actor.Email, &actor.Role, &deactivated, &verified, &grandfathered)
	if err != nil {
		if strict {
			return nil, scheduledActorFailure(err, "task owner is missing or unavailable: %w", err)
		}
		return nil, fmt.Errorf("task owner is missing or unavailable")
	}
	if deactivated.Valid && deactivated.String != "" {
		return nil, fmt.Errorf("task owner is deactivated")
	}
	actor.Verified = verified == 1
	actor.EmailGrandfathered = grandfathered == 1
	if app.Design != nil && app.Design.Auth["require_verified"] == "true" && !actor.Verified {
		return nil, fmt.Errorf("task owner must verify their account")
	}
	actor.GlobalAdmin = actor.Role == "admin"
	if !actor.GlobalAdmin {
		actor.GlobalAdmin, err = userHasGlobalAdminGrantWithSchema(db, userID, schema)
		if strict && err != nil {
			return nil, scheduledActorFailure(err, "task owner's administrator grants are unavailable: %w", err)
		}
	}
	if group != nil {
		actor.GroupID = *group
	}
	if g := app.Group; g != nil && g.Table != "" && g.Key != "" && g.UserField != "" {
		// Same rules as a request's tenant check (groupMembershipLive): only
		// live rows count, an email-keyed row needs a verified or
		// grandfathered address, and an id-keyed row matches the user id.
		var rows []map[string]any
		if member, ok := groupMemberValue(g, actor); ok {
			if strict && (!membershipIdentRe.MatchString(g.Key) || !membershipIdentRe.MatchString(g.UserField) || g.RoleField != "" && !membershipIdentRe.MatchString(g.RoleField)) {
				return nil, fmt.Errorf("task owner's tenant configuration is unavailable")
			}
			hasCol, metadataErr := dbColumnCheckerWith(db, g.Table, schema)
			conds := membershipLiveConds(g, g.Table, "", hasCol)
			if strict && metadataErr() != nil {
				return nil, scheduledActorFailure(metadataErr(), "task owner's tenant metadata is unavailable: %w", metadataErr())
			}
			from, name := quoteIdent(g.Table), g.Table
			if strict {
				var valid bool
				from, name, valid = mainAuthorityTable(g.Table)
				if !valid {
					return nil, fmt.Errorf("task owner's tenant table is unavailable")
				}
			}
			key := quoteColumn(name, g.Key)
			query := fmt.Sprintf("SELECT DISTINCT %s AS group_id FROM %s WHERE %s=? AND %s IS NOT NULL%s", key, from, quoteColumn(name, g.UserField), key, conds)
			if strict {
				key, keyErr := cryptoKeyForQuerierMainChecked(db)
				if keyErr != nil {
					return nil, scheduledActorFailure(keyErr, "task owner's tenant encryption key is unavailable: %w", keyErr)
				}
				rows, err = queryRowsWithKeyContextDecrypt(context.Background(), db, key, nativeRowDecryptor(nil, ""), query, member)
			} else {
				rows, err = queryMetadataRows(db, query, member)
			}
			if err != nil {
				if strict {
					return nil, scheduledActorFailure(err, "task owner's tenant membership is unavailable: %w", err)
				}
				return nil, fmt.Errorf("task owner's tenant membership is unavailable")
			}
		}
		var groups []string
		for _, row := range rows {
			v := fmt.Sprint(row["group_id"])
			if v != "" && v != "0" {
				groups = append(groups, v)
			}
		}
		if group == nil {
			if len(groups) > 1 {
				return nil, fmt.Errorf("legacy task has ambiguous tenant membership; assign its intended tenant before release")
			}
			if len(groups) == 1 {
				actor.GroupID = groups[0]
			}
		} else if actor.GroupID != "" && !slices.Contains(groups, actor.GroupID) {
			return nil, fmt.Errorf("task owner's original tenant membership was removed")
		}
	} else if actor.GroupID != "" {
		return nil, fmt.Errorf("task's tenant configuration was removed")
	}
	actor.Roles, err = loadSessionRolesWithSchema(db, userID, actor.Role, actor.GroupID, schema)
	if strict && err != nil {
		return nil, fmt.Errorf("task owner's role grants are unavailable: %w", err)
	}
	actor, err = applySessionRoleScopesWith(app, db, actor, schema)
	if strict && err != nil {
		return nil, err
	}
	return actor, nil
}

// prepareScheduledFlow is read-only. Both the upgrade check and the worker call
// it. Legacy records retain their IDs, payloads and due times; the worker saves
// the inferred authority atomically when it claims the existing record.
func prepareScheduledFlow(app *App, task map[string]any) (*Session, *Flow, string, error) {
	uid := toInt64(task["user_id"])
	raw, _ := task["authorization"].(string)
	var authority scheduledAuthority
	var pinned *string
	if raw != "" {
		if json.Unmarshal([]byte(raw), &authority) != nil || authority.Version != 1 || authority.Actor.UserID != uid || authority.Actor.ID != "" || authority.Actor.ActingAsGroup != "" {
			return nil, nil, "", fmt.Errorf("invalid scheduled authorization metadata")
		}
		pinned = &authority.Actor.GroupID
	}
	current, err := loadScheduledActor(app, uid, pinned)
	if err != nil {
		return nil, nil, "", err
	}
	name, _ := task["flow"].(string)
	if _, err := schedulableFlow(app, name, current); err != nil {
		return nil, nil, "", err
	}
	actor := current
	if raw != "" {
		saved := authority.Actor
		// Added roles do not grant old tasks new authority. Removed grants hold the
		// task for review instead of executing under privileges it no longer has.
		for _, role := range append(slices.Clone(saved.Roles), saved.Role) {
			if role != "" && !HasAnyRole(current, []string{role}) {
				return nil, nil, "", fmt.Errorf("task owner's delegated role was revoked")
			}
		}
		if saved.GlobalAdmin && !current.GlobalAdmin {
			return nil, nil, "", fmt.Errorf("task owner's global administrator grant was revoked")
		}
		saved.Email = current.Email
		saved.Verified = current.Verified
		saved.Scopes = intersectScopes(saved.Scopes, current.Scopes)
		saved.Permissions = strings.Fields(saved.Scopes)
		actor = &saved
	}
	flow, err := schedulableFlow(app, name, actor)
	if err != nil {
		return nil, nil, "", err
	}
	body, _ := task["body"].(string)
	if _, err := scheduledFlowRequest(flow, body); err != nil {
		return nil, nil, "", err
	}
	if raw == "" {
		raw = marshalScheduledAuthority(actor)
	}
	actor.ID = fmt.Sprintf("scheduled:%v", task["id"])
	return actor, flow, raw, nil
}

func scheduledFlowRequest(flow *Flow, body string) (*http.Request, error) {
	if body == "" {
		body = "{}"
	}
	var data map[string]any
	decoder := json.NewDecoder(strings.NewReader(body))
	decoder.UseNumber()
	if decoder.Decode(&data) != nil || !json.Valid([]byte(body)) {
		return nil, fmt.Errorf("scheduled flow body must be a JSON object")
	}
	method := flow.Trigger.Method
	if flow.Trigger.Type != "http" || method == "" {
		method = "POST"
	}
	r, err := http.NewRequest(method, "/", strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("scheduled flow has an invalid HTTP method")
	}
	r.Header.Set("Content-Type", "application/json")
	parts := strings.Split(flow.Trigger.Path, "/")
	for i, part := range parts {
		if !strings.HasPrefix(part, ":") {
			continue
		}
		name := strings.TrimPrefix(part, ":")
		value := data[name]
		switch value.(type) {
		case string, json.Number:
			if fmt.Sprint(value) == "" {
				return nil, fmt.Errorf("scheduled flow requires a path parameter in its body")
			}
		default:
			return nil, fmt.Errorf("scheduled flow requires a path parameter in its body")
		}
		// executeFlowHTTP reads PathValue after positional parsing. A fixed path
		// segment keeps values containing '/' from shifting subsequent parameters.
		parts[i] = "_scheduled"
		r.SetPathValue(name, fmt.Sprint(value))
	}
	if flow.Trigger.Path != "" {
		r.URL.Path = strings.Join(parts, "/")
	}
	return r, nil
}
