//go:build !cli

package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

func ensureErrorGroups(db *sql.DB) error {
	return ensureErrorGroupsContext(context.Background(), db)
}

func ensureErrorGroupsContext(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS _benmore_error_groups (
		group_key TEXT PRIMARY KEY, source TEXT, kind TEXT, level TEXT, type TEXT,
		message TEXT, culprit TEXT, sample TEXT, last_request_id TEXT,
		count INTEGER NOT NULL DEFAULT 0, first_seen DATETIME, last_seen DATETIME,
		last_forwarded_at DATETIME, unforwarded INTEGER NOT NULL DEFAULT 0,
		resolved_at DATETIME, sample_user_id INTEGER, last_slack_at DATETIME
	);
	CREATE INDEX IF NOT EXISTS idx_benmore_error_groups_last ON _benmore_error_groups(last_seen)`)
	if err != nil {
		return fmt.Errorf("create error groups: %w", err)
	}
	return nil
}

var errorGroupUUIDRE = regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
var errorGroupHexRE = regexp.MustCompile(`(?i)[0-9a-f]{8,}`)
var errorGroupNumberRE = regexp.MustCompile(`[0-9]+`)
var errorGroupStringRE = regexp.MustCompile(`'[^']*'|"[^"]*"`)

func normalizeErrorMessage(s string) string {
	s = errorExportEmailRE.ReplaceAllString(s, "<email>")
	s = errorGroupStringRE.ReplaceAllString(s, "<str>")
	s = errorGroupUUIDRE.ReplaceAllString(s, "<uuid>")
	s = errorGroupHexRE.ReplaceAllString(s, "<hex>")
	return errorGroupNumberRE.ReplaceAllString(s, "<n>")
}

func errorCulprit(ev errorEvent) string {
	for i := len(ev.Frames) - 1; i >= 0; i-- {
		f := ev.Frames[i]
		if f.InApp {
			return fmt.Sprintf("%s:%d %s", f.Filename, f.Line, f.Function)
		}
	}
	return ev.Route
}

func errorGroupKey(ev errorEvent) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{ev.Source, ev.Kind, ev.Type, normalizeErrorMessage(ev.Message), errorCulprit(ev)}, "|")))
	return hex.EncodeToString(sum[:])
}

// Samples remain valid JSON even when a large stack/context exceeds the row
// budget. Keep the crashing frames; drop the oldest context first. Browser
// reports, which anyone can send, get a quarter of the budget, so the 2000
// kept groups hold at most 16 MiB of anonymous text.
func errorGroupSample(ev errorEvent) string {
	budget := 32 << 10
	if ev.Source == "client" {
		budget = 8 << 10
	}
	for {
		data, err := json.Marshal(ev)
		if err == nil && len(data) <= budget {
			return string(data)
		}
		switch {
		case len(ev.Frames) != 0:
			ev.Frames = ev.Frames[1:]
		case len(ev.Breadcrumbs) != 0:
			ev.Breadcrumbs = ev.Breadcrumbs[1:]
		case ev.Extra != nil:
			ev.Extra = nil
		case ev.Tags != nil:
			ev.Tags = nil
		default:
			data, _ = json.Marshal(map[string]string{"message": truncateRunes(ev.Message, 2048), "type": truncateRunes(ev.Type, 200)})
			return string(data)
		}
	}
}

func recordGroup(app *App, ev errorEvent) (bool, int, error) {
	return recordGroupAt(app, ev, time.Now())
}

func recordGroupAt(app *App, ev errorEvent, now time.Time) (bool, int, error) {
	return recordGroupContext(context.Background(), app, ev, now)
}

const errorTimeFormat = "2006-01-02T15:04:05.000000000Z"

func recordGroupContext(ctx context.Context, app *App, ev errorEvent, now time.Time) (bool, int, error) {
	return recordGroupEligible(ctx, app, ev, now, true)
}

var errErrorAccountPurged = errors.New("error account was purged")

func recordGroupEligible(ctx context.Context, app *App, ev errorEvent, now time.Time, eligible bool) (bool, int, error) {
	key := errorGroupKey(ev)
	tx, err := app.DB.BeginTx(ctx, nil)
	if err != nil {
		return false, 0, fmt.Errorf("begin error group: %w", err)
	}
	defer tx.Rollback()
	if ev.UserID != 0 {
		var exists int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type='table' AND name='_benmore_users'`).Scan(&exists); err != nil {
			return false, 0, fmt.Errorf("inspect error account: %w", err)
		}
		if exists != 0 {
			var purged bool
			if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM _benmore_users WHERE id=? AND `+accountDeactivatedSQL("")+`)`, ev.UserID).Scan(&purged); err != nil {
				return false, 0, fmt.Errorf("inspect error account tombstone: %w", err)
			}
			if purged {
				return false, 0, errErrorAccountPurged
			}
		}
	}
	stamp := now.UTC().Format(errorTimeFormat)
	_, err = tx.ExecContext(ctx, `INSERT INTO _benmore_error_groups
		(group_key,source,kind,level,type,message,culprit,sample,last_request_id,count,first_seen,last_seen,unforwarded,sample_user_id)
		VALUES (?,?,?,?,?,?,?,?,?,1,?,?,1,?)
		ON CONFLICT(group_key) DO UPDATE SET count=count+1,level=excluded.level,
		message=excluded.message,sample=excluded.sample,last_request_id=excluded.last_request_id,
		last_seen=excluded.last_seen,unforwarded=unforwarded+1,resolved_at=NULL,sample_user_id=excluded.sample_user_id`,
		key, ev.Source, ev.Kind, ev.Level, ev.Type, ev.Message, errorCulprit(ev), errorGroupSample(ev), ev.RequestID, stamp, stamp, ev.UserID)
	if err != nil {
		return false, 0, fmt.Errorf("record error group: %w", err)
	}
	// RETURNING observes new values, not the pre-update row. Claim the timestamp
	// and return the accumulated count, then reset it within this write transaction.
	var since int
	err = tx.QueryRowContext(ctx, `UPDATE _benmore_error_groups SET last_forwarded_at=?
		WHERE group_key=? AND ? AND (last_forwarded_at IS NULL OR last_forwarded_at<=?)
		RETURNING unforwarded-1`, stamp, key, eligible, now.Add(-5*time.Minute).UTC().Format(errorTimeFormat)).Scan(&since)
	forward := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, 0, fmt.Errorf("claim error group: %w", err)
	}
	if forward {
		if _, err := tx.ExecContext(ctx, "UPDATE _benmore_error_groups SET unforwarded=0 WHERE group_key=?", key); err != nil {
			return false, 0, fmt.Errorf("reset error count: %w", err)
		}
	}
	if app.errorGroupWrites.Add(1)%200 == 0 {
		if _, err := tx.ExecContext(ctx, `DELETE FROM _benmore_error_groups WHERE group_key NOT IN
			(SELECT group_key FROM _benmore_error_groups ORDER BY last_seen DESC LIMIT 2000)`); err != nil {
			return false, 0, fmt.Errorf("prune error groups: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return false, 0, fmt.Errorf("commit error group: %w", err)
	}
	return forward, since, nil
}
