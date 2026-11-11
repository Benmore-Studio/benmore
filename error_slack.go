//go:build !cli

package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"time"
)

// sendSlack posts once per group an hour (claimed on the group row). With
// claim false (the group could not be recorded) it posts without the claim,
// bounded by the Slack budget alone.
func (r *errorReporter) sendSlack(ctx context.Context, ev errorEvent, claim bool) deliveryResult {
	hook := GetEnv(r.app.Dir, "ERROR_SLACK_WEBHOOK")
	if hook == "" {
		return deliveryResult{}
	}
	if claim {
		stamp := r.now().UTC().Format(errorTimeFormat)
		var key string
		err := r.app.DB.QueryRowContext(ctx, `UPDATE _benmore_error_groups SET last_slack_at=?
		WHERE group_key=? AND (last_slack_at IS NULL OR last_slack_at<=?) RETURNING group_key`,
			stamp, errorGroupKey(ev), r.now().Add(-time.Hour).UTC().Format(errorTimeFormat)).Scan(&key)
		if err == sql.ErrNoRows {
			return deliveryResult{}
		}
		if err != nil {
			r.counters.failed.Add(1)
			return deliveryResult{}
		}
	}
	if !r.allow(errorBudget("slack", ev.Source)) {
		r.counters.throttled.Add(1)
		return deliveryResult{MutedCategories: []string{"slack"}}
	}
	return r.sendSlackDirect(ctx, ev)
}

// Synthetic delivery tests bypass the per-group timestamp, but still use the
// same URL guard, client and timeout. Their caller applies the rate limiter.
func (r *errorReporter) sendSlackDirect(ctx context.Context, ev errorEvent) deliveryResult {
	deliveryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	hook := GetEnv(r.app.Dir, "ERROR_SLACK_WEBHOOK")
	if hook == "" || r.app.errorDeliveryOff.Load() {
		return deliveryResult{}
	}
	if isPrivateURLContext(deliveryCtx, hook) {
		return deliveryResult{Rejected: true}
	}
	text := slackErrorText(scrubForExport(r.app, r.app.AppID), ev.Kind, ev.Message, errorCulprit(ev), 0, 0, "")
	payload, _ := json.Marshal(map[string]string{"text": text})
	req, err := http.NewRequestWithContext(deliveryCtx, http.MethodPost, hook, bytes.NewReader(payload))
	if err != nil {
		return deliveryResult{}
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := r.client.Do(req)
	if err != nil {
		r.counters.failed.Add(1)
		return deliveryResult{}
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
	result := deliveryResult{Status: response.StatusCode, OK: response.StatusCode >= 200 && response.StatusCode < 300}
	result.Rejected = response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden
	if response.StatusCode == http.StatusTooManyRequests {
		result.MutedCategories = []string{"slack"}
	}
	if !result.OK {
		r.counters.failed.Add(1)
	}
	return result
}
