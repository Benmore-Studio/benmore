//go:build !cli

package main

import (
	"encoding/json"
	"net/url"
	"sort"
	"strings"
)

// flowSecretMinLength is the shortest env or secret-derived value redacted
// from a failure's text; shorter values ("1", "true", "prod") are too likely
// to match ordinary words.
const flowSecretMinLength = 8

// flowFailureText is a failed flow's error text with every value the flow can
// read from the app's env, and every value derived from one (FlowContext.
// SecretKeys), replaced by [redacted] - as written and as URL-escaped. The
// request log, the journal and the step_error shown to an app admin all use
// it. serverErrorText redacts query strings and known key shapes, but a
// secret placed in a URL path (a Telegram bot token, a Slack or Discord
// webhook path) reached app admins in step_error (round-2 review, 2026-10-23).
func flowFailureText(ctx *FlowContext, failure error) string {
	return redactFlowSecretValues(ctx, errorText(failure))
}

func redactFlowSecretValues(ctx *FlowContext, text string) string {
	if ctx == nil || text == "" {
		return text
	}
	for _, secret := range flowSecretValues(ctx, true) {
		for _, form := range []string{secret, url.PathEscape(secret), url.QueryEscape(secret)} {
			text = strings.ReplaceAll(text, form, "[redacted]")
		}
	}
	return text
}

// flowSecretValues lists the app's env values the flow can read and, with
// derived, the string values of its secret-derived keys, each at least
// flowSecretMinLength long, longest first (so a secret that contains another
// is matched whole). The caller must not hold ctx.DataMu when derived is set.
func flowSecretValues(ctx *FlowContext, derived bool) []string {
	var secrets []string
	for _, value := range flowEnvSnapshot(ctx) {
		if len(value) >= flowSecretMinLength {
			secrets = append(secrets, value)
		}
	}
	if derived {
		ctx.DataMu.Lock()
		for key := range ctx.SecretKeys {
			if value, ok := ctx.Data[key].(string); ok && len(value) >= flowSecretMinLength {
				secrets = append(secrets, value)
			}
		}
		ctx.DataMu.Unlock()
	}
	sort.Slice(secrets, func(i, j int) bool { return len(secrets[i]) > len(secrets[j]) })
	return secrets
}

// redactedFlowError is a flow run's failure as it is kept and shown outside
// the run: its text has the run's env and secret-derived values redacted
// (flowFailureText) and is one line with credential shapes and URL query
// values redacted (serverErrorText). It unwraps to the original error, so
// the job retry policy and connector effect outcome still see its kind.
type redactedFlowError struct {
	text  string
	cause error
}

func (e *redactedFlowError) Error() string { return e.text }
func (e *redactedFlowError) Unwrap() error { return e.cause }

// flowRunFailure is the error a flow run outside a request (a queued flow
// job, a cron run) reports: its text is what the synchronous path logs.
// A queued job's error is stored, answered on status_url, listed by
// /api/_jobs and describe_jobs and written to the journal; the raw text of a
// failed `run: api` holds its whole URL, env token included, and an
// anonymous async caller read it back (round 2026-11-04).
func flowRunFailure(ctx *FlowContext, err error) error {
	if err == nil {
		return nil
	}
	return &redactedFlowError{text: serverErrorText(flowFailureText(ctx, err)), cause: err}
}

// jobErrorText is a job error as it is stored in _benmore_jobs.error, read
// back (status_url, GET /api/_jobs, describe_jobs) and logged: the app's env
// values redacted as written and URL-escaped, then serverErrorText (one
// line, credential shapes and URL query values redacted, size capped). It
// covers every job type; a flow job's own secret-derived values were already
// redacted by flowRunFailure, which needs the run's context. Reads apply it
// too, for rows stored before job errors were redacted.
func jobErrorText(app *App, text string) string {
	if text == "" {
		return ""
	}
	if app != nil {
		text = redactFlowSecretValues(&FlowContext{App: app}, text)
	}
	return serverErrorText(text)
}

// redactJobErrorColumn applies jobErrorText to a job row's error column.
func redactJobErrorColumn(app *App, row map[string]any) {
	if text, ok := row["error"].(string); ok {
		row["error"] = jobErrorText(app, text)
	}
}

// contextSecretFilter leaves out of a whole-context webhook body what the
// author did not name: a key the secret taint marks as env-derived, with its
// dotted descendants (`<step>.outputs`, a parse step's `<step>.<field>`, a
// `run: set` map's key), and any string that holds a secret value (the app's
// env values and the secret-derived keys' values: a stored row or an upstream
// answer can echo a key without the taint knowing).
type contextSecretFilter struct {
	secretKeys map[string]bool
	values     []string
}

// secretPath reports whether path or one of its dotted prefixes is marked
// secret-derived.
func (f contextSecretFilter) secretPath(path string) bool {
	for p := path; p != ""; {
		if f.secretKeys[p] {
			return true
		}
		i := strings.LastIndexByte(p, '.')
		if i < 0 {
			break
		}
		p = p[:i]
	}
	return false
}

func (f contextSecretFilter) holdsSecret(s string) bool {
	for _, v := range f.values {
		if strings.Contains(s, v) {
			return true
		}
	}
	return false
}

// keep returns v without its secret parts, and false when v is left out
// whole. Maps and lists are copied; the flow context is not changed.
func (f contextSecretFilter) keep(path string, v any) (any, bool) {
	if f.secretPath(path) {
		return nil, false
	}
	switch t := v.(type) {
	case nil, bool, int, int64, float64:
		return v, true
	case string:
		return t, !f.holdsSecret(t)
	case []byte:
		return t, !f.holdsSecret(string(t))
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, cv := range t {
			if kept, ok := f.keep(path+"."+k, cv); ok {
				out[k] = kept
			}
		}
		return out, true
	case []any:
		out := make([]any, 0, len(t))
		for _, e := range t {
			if kept, ok := f.keep(path, e); ok {
				out = append(out, kept)
			}
		}
		return out, true
	case []map[string]any:
		out := make([]map[string]any, 0, len(t))
		for _, e := range t {
			if kept, ok := f.keep(path, e); ok {
				out = append(out, kept.(map[string]any))
			}
		}
		return out, true
	case []string:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if !f.holdsSecret(e) {
				out = append(out, e)
			}
		}
		return out, true
	}
	// Any other shape is judged by its JSON text, which is what is sent.
	if encoded, err := json.Marshal(v); err == nil && f.holdsSecret(string(encoded)) {
		return nil, false
	}
	return v, true
}
