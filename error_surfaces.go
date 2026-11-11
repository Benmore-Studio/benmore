//go:build !cli

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

type ErrorGroupParams struct {
	Source     string `json:"source,omitempty"`
	Level      string `json:"level,omitempty"`
	Since      string `json:"since,omitempty"`
	Unresolved bool   `json:"unresolved,omitempty"`
	Limit      int    `json:"limit,omitempty"`
	GroupKey   string `json:"group_key,omitempty"`
}

type ErrorGroupEntry struct {
	GroupKey      string          `json:"group_key"`
	Source        string          `json:"source"`
	Kind          string          `json:"kind"`
	Level         string          `json:"level"`
	Type          string          `json:"type"`
	Message       string          `json:"message"`
	Culprit       string          `json:"culprit"`
	Sample        json.RawMessage `json:"sample"`
	LastRequestID string          `json:"last_request_id"`
	Count         int64           `json:"count"`
	FirstSeen     string          `json:"first_seen"`
	LastSeen      string          `json:"last_seen"`
	ResolvedAt    string          `json:"resolved_at,omitempty"`
}

type ErrorGroupResult struct {
	CanEdit   bool                `json:"can_edit"`
	Groups    []ErrorGroupEntry   `json:"groups"`
	Count     int                 `json:"count"`
	Reporting errorReportingState `json:"reporting"`
}

type errorReportingState struct {
	Sentry          string           `json:"sentry"`
	SlackConfigured bool             `json:"slack_configured"`
	Counters        map[string]int64 `json:"counters"`
}

var errorGroupKeyRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

func errorGroupsExist(ctx context.Context, app *App) (bool, error) {
	var n int
	err := app.DB.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='_benmore_error_groups'").Scan(&n)
	return n > 0, err
}

func listErrorGroups(ctx context.Context, app *App, p ErrorGroupParams) (*ErrorGroupResult, error) {
	if p.Source != "" && p.Source != "server" && p.Source != "client" {
		return nil, appDataFail("bad_request", "source must be server or client")
	}
	if p.Level != "" && p.Level != "fatal" && p.Level != "error" && p.Level != "warning" {
		return nil, appDataFail("bad_request", "level must be fatal, error or warning")
	}
	if p.GroupKey != "" && !errorGroupKeyRE.MatchString(p.GroupKey) {
		return nil, appDataFail("bad_request", "invalid group_key")
	}
	if p.Limit <= 0 {
		p.Limit = 50
	}
	if p.Limit > 200 {
		p.Limit = 200
	}
	var where []string
	var args []any
	if p.Source != "" {
		where = append(where, "source=?")
		args = append(args, p.Source)
	}
	if p.Level != "" {
		where = append(where, "level=?")
		args = append(args, p.Level)
	}
	if p.GroupKey != "" {
		where = append(where, "group_key=?")
		args = append(args, p.GroupKey)
	}
	if p.Unresolved {
		where = append(where, "resolved_at IS NULL")
	}
	if p.Since != "" {
		stamp, err := time.Parse(time.RFC3339Nano, p.Since)
		if err != nil {
			d, parseErr := time.ParseDuration(p.Since)
			if parseErr != nil || d <= 0 {
				return nil, appDataFail("bad_request", "since must be an RFC3339 timestamp or positive duration such as 1h")
			}
			stamp = time.Now().Add(-d)
		}
		where = append(where, "last_seen>=?")
		args = append(args, stamp.UTC().Format(errorTimeFormat))
	}
	result := &ErrorGroupResult{Groups: []ErrorGroupEntry{}, Reporting: appErrorReportingState(app)}
	exists, err := errorGroupsExist(ctx, app)
	if err != nil {
		return nil, fmt.Errorf("inspect error groups: %w", err)
	}
	if !exists {
		return result, nil
	}
	query := `SELECT group_key,COALESCE(source,''),COALESCE(kind,''),COALESCE(level,''),COALESCE(type,''),COALESCE(message,''),COALESCE(culprit,''),COALESCE(sample,'null'),COALESCE(last_request_id,''),count,COALESCE(first_seen,''),COALESCE(last_seen,''),COALESCE(resolved_at,'') FROM _benmore_error_groups`
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY last_seen DESC,group_key LIMIT ?"
	args = append(args, p.Limit)
	rows, err := app.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list error groups: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var e ErrorGroupEntry
		var sample string
		if err := rows.Scan(&e.GroupKey, &e.Source, &e.Kind, &e.Level, &e.Type, &e.Message, &e.Culprit, &sample, &e.LastRequestID, &e.Count, &e.FirstSeen, &e.LastSeen, &e.ResolvedAt); err != nil {
			return nil, fmt.Errorf("read error group: %w", err)
		}
		if json.Valid([]byte(sample)) {
			e.Sample = json.RawMessage(sample)
		}
		result.Groups = append(result.Groups, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read error groups: %w", err)
	}
	result.Count = len(result.Groups)
	return result, nil
}

// Reading status must not start a worker or touch the network.
func appErrorReportingState(app *App) errorReportingState {
	state := errorReportingState{Sentry: "not_configured", SlackConfigured: GetEnv(app.Dir, "ERROR_SLACK_WEBHOOK") != "", Counters: (&errorCounters{}).snapshot()}
	dsn := GetEnv(app.Dir, "SENTRY_DSN")
	if dsn != "" {
		state.Sentry = "configured"
		if _, err := parseSentryDSN(dsn); err != nil {
			state.Sentry = "rejected"
		}
	}
	app.errorReporterMu.Lock()
	var r *errorReporter
	if app.errorReporter != nil {
		r = app.errorReporter.reporter
	}
	app.errorReporterMu.Unlock()
	if r != nil {
		state.Counters = r.counters.snapshot()
		if dsn != "" && state.Sentry != "rejected" {
			state.Sentry = r.state.forDSN(dsn).status()
		}
	}
	return state
}

// These are group counts, not lifetime occurrence counts attributed to a day.
func errorHealthCounts(ctx context.Context, app *App) (map[string]int64, error) {
	counts := map[string]int64{"last_24h": 0, "unresolved": 0}
	exists, err := errorGroupsExist(ctx, app)
	if err != nil || !exists {
		return counts, err
	}
	var recent, unresolved int64
	err = app.DB.QueryRowContext(ctx, `SELECT COALESCE(SUM(last_seen>=?),0),COALESCE(SUM(resolved_at IS NULL),0) FROM _benmore_error_groups`, time.Now().Add(-24*time.Hour).UTC().Format(errorTimeFormat)).Scan(&recent, &unresolved)
	if err != nil {
		return nil, fmt.Errorf("count error groups: %w", err)
	}
	counts["last_24h"], counts["unresolved"] = recent, unresolved
	return counts, nil
}
