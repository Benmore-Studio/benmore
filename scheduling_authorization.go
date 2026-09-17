//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
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
	actor := &Session{UserID: userID}
	var deactivated sql.NullString
	var verified int
	err := app.DB.QueryRow("SELECT COALESCE(email,''), COALESCE(role,'user'), deactivated_at, COALESCE(verified,0) FROM _benmore_users WHERE id=?", userID).Scan(&actor.Email, &actor.Role, &deactivated, &verified)
	if err != nil {
		return nil, fmt.Errorf("task owner is missing or unavailable")
	}
	if deactivated.Valid && deactivated.String != "" {
		return nil, fmt.Errorf("task owner is deactivated")
	}
	actor.Verified = verified == 1
	if app.Design != nil && app.Design.Auth["require_verified"] == "true" && !actor.Verified {
		return nil, fmt.Errorf("task owner must verify their account")
	}
	actor.GlobalAdmin = actor.Role == "admin" || UserHasGlobalAdminGrant(app.DB, userID)
	if group != nil {
		actor.GroupID = *group
	}
	if g := app.Group; g != nil && g.Table != "" && g.Key != "" && g.UserField != "" {
		rows, err := queryRowsWith(app.DB, fmt.Sprintf("SELECT DISTINCT %s AS group_id FROM %s WHERE %s=? AND %s IS NOT NULL", g.Key, g.Table, g.UserField, g.Key), actor.Email)
		if err != nil {
			return nil, fmt.Errorf("task owner's tenant membership is unavailable")
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
	actor.Roles = LoadSessionRoles(app.DB, userID, actor.Role, actor.GroupID)
	return applySessionRoleScopes(app, actor), nil
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
