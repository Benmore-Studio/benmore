//go:build !cli

package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Hook represents a single action to take when a data event occurs.
type Hook struct {
	Webhook string // URL to POST to
	Body    string // body template for webhook
	SQL     string // SQL to execute
	Email   *EmailHook
	Notify  *NotifyHook // notification to create
	WS      *WSHook     // broadcast over WebSocket to a room
	When    string      // conditional: "stage = 'won'"
}

// WSHook fires a WebSocket broadcast to every client currently
// joined to the named room. Used for presence, live notifications,
// and any case where a server-side data change should immediately
// reach the UI without polling.
//
//   on_update:
//     orders:
//       - ws:
//           room: "order-{{id}}"
//           payload: {"status": "{{status}}", "by": "{{user_email}}"}
//
// Room IDs are scoped server-side by the connected user's group/user
// so messages can't leak across tenants — same model as bm.useLive
// .join() on the client.
type WSHook struct {
	Room    string // room ID (templates supported, e.g. "order-{{id}}")
	Payload string // JSON-serializable string template; clients receive payload as-is
}

// EmailHook represents an email action.
type EmailHook struct {
	To       string
	Subject  string
	Template string
}

// HookConfig holds all hooks for the app.
type HookConfig struct {
	OnInsert     map[string][]Hook // table -> hooks (after mutation)
	OnUpdate     map[string][]Hook
	OnDelete     map[string][]Hook
	BeforeInsert map[string][]Hook // table -> hooks (before mutation, can abort)
	BeforeUpdate map[string][]Hook
	BeforeDelete map[string][]Hook
}

// LoadHooks reads hooks.yaml from the app directory.
func LoadHooks(dir string) *HookConfig {
	path := filepath.Join(dir, "hooks.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	config := &HookConfig{
		OnInsert:     make(map[string][]Hook),
		OnUpdate:     make(map[string][]Hook),
		OnDelete:     make(map[string][]Hook),
		BeforeInsert: make(map[string][]Hook),
		BeforeUpdate: make(map[string][]Hook),
		BeforeDelete: make(map[string][]Hook),
	}

	section := ""       // "on_insert", "on_update", "on_delete"
	currentTable := ""
	var currentHook *Hook

	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		indent := len(line) - len(strings.TrimLeft(line, " "))

		// Top-level sections
		if indent == 0 && strings.HasSuffix(trimmed, ":") {
			section = strings.TrimSuffix(trimmed, ":")
			continue
		}

		// Table name (indent 2)
		if indent == 2 && strings.HasSuffix(trimmed, ":") {
			currentTable = strings.TrimSuffix(trimmed, ":")
			continue
		}

		// Hook entries (indent 4+)
		if indent >= 4 {
			// List item starting with -
			if strings.HasPrefix(trimmed, "- ") {
				trimmed = strings.TrimPrefix(trimmed, "- ")
			}

			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) != 2 {
				continue
			}
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			val = strings.Trim(val, `"'`)

			switch key {
			case "webhook":
				currentHook = &Hook{Webhook: val}
				addHook(config, section, currentTable, currentHook)
			case "body":
				if currentHook != nil {
					currentHook.Body = val
				}
			case "sql":
				hook := &Hook{SQL: val}
				addHook(config, section, currentTable, hook)
				currentHook = hook
			case "when":
				if currentHook != nil {
					currentHook.When = val
				}
			case "email":
				// Simple form: email: owner template: xxx
				// Parse this later with more context
				hook := &Hook{Email: &EmailHook{To: val}}
				addHook(config, section, currentTable, hook)
				currentHook = nil
			case "to":
				if currentHook != nil && currentHook.Email != nil {
					currentHook.Email.To = val
				}
			case "subject":
				if currentHook != nil && currentHook.Email != nil {
					currentHook.Email.Subject = val
				}
			case "template":
				if currentHook != nil && currentHook.Email != nil {
					currentHook.Email.Template = val
				}
			case "notify":
				// notify: {{user_id}} — creates a notification hook
				hook := &Hook{Notify: &NotifyHook{UserID: val}}
				addHook(config, section, currentTable, hook)
				currentHook = hook
			case "notify_title":
				if currentHook != nil && currentHook.Notify != nil {
					currentHook.Notify.Title = val
				}
			case "notify_body":
				if currentHook != nil && currentHook.Notify != nil {
					currentHook.Notify.Body = val
				}
			case "notify_type":
				if currentHook != nil && currentHook.Notify != nil {
					currentHook.Notify.Type = val
				}
			case "notify_link":
				if currentHook != nil && currentHook.Notify != nil {
					currentHook.Notify.Link = val
				}
			}
		}
	}

	return config
}

func addHook(config *HookConfig, section, table string, hook *Hook) {
	switch section {
	case "on_insert":
		config.OnInsert[table] = append(config.OnInsert[table], *hook)
	case "on_update":
		config.OnUpdate[table] = append(config.OnUpdate[table], *hook)
	case "on_delete":
		config.OnDelete[table] = append(config.OnDelete[table], *hook)
	case "before_insert":
		config.BeforeInsert[table] = append(config.BeforeInsert[table], *hook)
	case "before_update":
		config.BeforeUpdate[table] = append(config.BeforeUpdate[table], *hook)
	case "before_delete":
		config.BeforeDelete[table] = append(config.BeforeDelete[table], *hook)
	}
}

// injectSessionContext adds user session data to a row map for hook/flow interpolation.
// Provides {{user_email}}, {{user_id}}, {{user_role}}, {{user_group_id}} in hook SQL and webhook body templates.
func injectSessionContext(row map[string]any, session *Session) {
	if session == nil {
		return
	}
	row["user_email"] = session.Email
	row["user_id"] = session.UserID
	row["user_role"] = session.Role
	// Multi-role: comma-separated string ("editor,reviewer") so hook SQL
	// can do `WHERE role IN (SELECT ...)` or webhook bodies can ship the
	// full set. Keeping it as a single comma-joined string keeps the
	// template scalar — flows and webhook templates can pipe-split if
	// they want the slice form.
	row["user_roles"] = strings.Join(session.Roles, ",")
	if session.HasGroup() {
		row["user_group_id"] = session.GroupID
	}
}

// FireUserHooks fires hooks for _benmore_users mutations (signup, login, profile update, etc.).
// Called from auth handlers to make the users table hookable like any other table.
func FireUserHooks(app *App, event string, userID int64) {
	if app.Hooks == nil {
		return
	}
	// Load current user fields as the "row" for hook interpolation
	row := LoadUserFields(app.DB, userID)
	if row == nil {
		row = make(map[string]any)
	}
	row["id"] = userID
	FireHooks(app, event, "_benmore_users", row)
}

// FireBeforeHooks executes before-mutation hooks synchronously.
// If any hook SQL returns a row with an "error" column, the operation is aborted.
// Returns nil if all hooks pass, or an error message to return to the client.
func FireBeforeHooks(app *App, event string, table string, row map[string]any) error {
	if app.Hooks == nil {
		return nil
	}

	var hooks []Hook
	switch event {
	case "insert":
		hooks = app.Hooks.BeforeInsert[table]
	case "update":
		hooks = app.Hooks.BeforeUpdate[table]
	case "delete":
		hooks = app.Hooks.BeforeDelete[table]
	}

	for _, hook := range hooks {
		if hook.When != "" && !evaluateCondition(hook.When, row) {
			continue
		}
		if hook.SQL != "" {
			// Translate the documented `RAISE(ABORT,'msg')` idiom into the
			// framework's native abort shape. SQLite rejects RAISE() outside
			// a trigger program ("RAISE() may only be used within a
			// trigger-program"), and before-hook SQL is executed directly —
			// so the documented pattern never worked. We rewrite
			//   SELECT CASE WHEN <cond> THEN RAISE(ABORT,'msg') END
			// into
			//   SELECT 'msg' AS error WHERE <cond>
			// which returns the abort row exactly when <cond> holds.
			raw := translateRaiseAbort(hook.SQL)
			sql, args := interpolateRowSafe(raw, row, app.Dir)
			rows, err := QueryRows(app.DB, sql, args...)
			if err != nil {
				// FAIL CLOSED. A before-hook is a gate (auth / business-rule
				// enforcement). If it can't be evaluated — typo, bad column,
				// unsupported SQL — we must REJECT the mutation, not let it
				// through. Pre-fix this `continue`'d (fail-open), so a broken
				// security hook silently disabled enforcement and the write
				// landed with a 200. The client gets a generic 422; the real
				// SQL error is logged server-side (never leaked).
				log.Printf("BEFORE-HOOK ERROR [%s %s] %s: %s — REJECTING mutation (fail-closed)", event, table, truncate(sql, 80), err)
				return fmt.Errorf("validation check could not be evaluated")
			}
			// If the query returns a row with an "error" field, abort the operation
			if len(rows) > 0 {
				if errMsg, ok := rows[0]["error"]; ok && errMsg != nil && fmt.Sprintf("%v", errMsg) != "" {
					return fmt.Errorf("%v", errMsg)
				}
			}
		}
	}
	return nil
}

// raiseAbortRe matches the documented before-hook abort idiom:
//
//	SELECT CASE WHEN <cond> THEN RAISE(ABORT, 'message') [ELSE ...] END
//
// capturing <cond> (group 1) and the message (group 2). Case-insensitive,
// dot-matches-newline. ABORT/FAIL/ROLLBACK/IGNORE all accepted. Anything
// that doesn't match this exact shape is returned unchanged (and, if it
// uses RAISE in some other shape, will error → fail closed → reject).
var raiseAbortRe = regexp.MustCompile(`(?is)^\s*SELECT\s+CASE\s+WHEN\s+(.+?)\s+THEN\s+RAISE\s*\(\s*(?:ABORT|FAIL|ROLLBACK|IGNORE)\s*,\s*'((?:[^']|'')*)'\s*\).*?\bEND\b\s*;?\s*$`)

// translateRaiseAbort rewrites the documented RAISE(ABORT,…) before-hook
// pattern into the framework's working `SELECT '<msg>' AS error WHERE
// <cond>` form. Returns the SQL unchanged when it doesn't match.
func translateRaiseAbort(sqlText string) string {
	m := raiseAbortRe.FindStringSubmatch(sqlText)
	if m == nil {
		return sqlText
	}
	cond := strings.TrimSpace(m[1])
	msg := m[2] // SQL single-quote escaping ('') preserved verbatim
	return "SELECT '" + msg + "' AS error WHERE " + cond
}

// FireHooks executes all hooks for a given event.
func FireHooks(app *App, event string, table string, row map[string]any) {
	if app.Hooks == nil {
		return
	}

	var hooks []Hook
	switch event {
	case "insert":
		hooks = app.Hooks.OnInsert[table]
	case "update":
		hooks = app.Hooks.OnUpdate[table]
	case "delete":
		hooks = app.Hooks.OnDelete[table]
	}

	for _, hook := range hooks {
		// Check conditional
		if hook.When != "" && !evaluateCondition(hook.When, row) {
			continue
		}

		// After-hooks are enqueued as durable jobs — not fire-and-forget goroutines.
		// This provides: guaranteed execution, retry on failure, visibility in job
		// dashboard, and testability (FlushJobs drains the queue for assertions).
		r := make(map[string]any, len(row))
		for k, v := range row {
			r[k] = v
		}
		EnqueueHookJob(app.DB, hook, r)
	}
}

func executeHook(db *sql.DB, hook Hook, row map[string]any, appDir string) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("HOOK PANIC: %v", r)
		}
	}()

	// Webhook
	if hook.Webhook != "" {
		webhookURL := InterpolateEnv(hook.Webhook, appDir)

		// SSRF protection: block requests to private/internal IPs
		if isPrivateURL(webhookURL) {
			log.Printf("SECURITY: blocked webhook to private URL: %s", webhookURL)
			return
		}

		body := interpolateRow(hook.Body, row, appDir)
		if body == "" {
			data, _ := json.Marshal(row)
			body = string(data)
		}

		// Circuit breaker: skip if endpoint is known-dead
		host := extractHost(webhookURL)
		if err := CheckCircuit(host); err != nil {
			log.Printf("HOOK SKIPPED [webhook] %s: %s", webhookURL, err)
			return
		}

		req, err := http.NewRequest("POST", webhookURL, bytes.NewBufferString(body))
		if err != nil {
			log.Printf("HOOK ERROR [webhook] %s: %s", webhookURL, err)
			RecordFailure(host)
			return
		}
		req.Header.Set("Content-Type", "application/json")

		client := safeHTTPClientStrict(10 * time.Second)
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("HOOK ERROR [webhook] %s: %s", webhookURL, err)
			RecordFailure(host)
			return
		}
		resp.Body.Close()
		if resp.StatusCode >= 500 {
			RecordFailure(host)
		} else {
			RecordSuccess(host)
		}
		log.Printf("HOOK [webhook] %s → %d", webhookURL, resp.StatusCode)
	}

	// SQL — use parameterized interpolation to prevent injection from row data
	if hook.SQL != "" {
		sql, args := interpolateRowSafe(hook.SQL, row, appDir)
		if _, err := db.Exec(sql, args...); err != nil {
			log.Printf("HOOK ERROR [sql] %s: %s", truncate(sql, 80), err)
			return
		}
		log.Printf("HOOK [sql] executed: %s", truncate(sql, 60))
	}

	// Email — actually send via SMTP (or Resend HTTP if configured).
	// Template is loaded from emails/<name>.html if specified; row
	// values are mustache-interpolated into both subject + body.
	if hook.Email != nil {
		to := interpolateRow(hook.Email.To, row, appDir)
		subject := interpolateRow(hook.Email.Subject, row, appDir)
		body := ""
		if hook.Email.Template != "" {
			tmplPath := filepath.Join(appDir, "emails", hook.Email.Template+".html")
			if data, err := os.ReadFile(tmplPath); err == nil {
				body = interpolateRow(stripEmailFrontmatter(string(data)), row, appDir)
			} else {
				// Fall back to a literal template treated as the body.
				body = interpolateRow(hook.Email.Template, row, appDir)
			}
		}
		if err := SendEmail(appDir, to, subject, body); err != nil {
			log.Printf("HOOK [email] send failed: %s", err)
		} else {
			log.Printf("HOOK [email] sent to=%s subject=%s", to, subject)
		}
	}

	// Notification
	if hook.Notify != nil {
		executeNotifyHook(db, hook.Notify, row, appDir)
	}

	// WebSocket broadcast
	if hook.WS != nil && hook.WS.Room != "" {
		room := interpolateRow(hook.WS.Room, row, appDir)
		payload := hook.WS.Payload
		if payload == "" {
			data, _ := json.Marshal(row)
			payload = string(data)
		} else {
			payload = interpolateRow(payload, row, appDir)
		}
		// BroadcastWSToRoomGlobal scopes the room by the
		// authenticated subscribers' own group/user (same logic as
		// scopedRoomID on the inbound side) so an `on_update: orders`
		// hook firing room="order-42" reaches every authenticated
		// client whose scope produces the same scoped key. The hook
		// itself is server-side and has no session; the global
		// variant fans out to every scope-compatible client.
		BroadcastWSToRoomGlobal(room, payload)
		log.Printf("HOOK [ws] broadcast to %s (%d bytes)", room, len(payload))
	}
}

// evaluateCondition checks a simple condition like "stage = 'won'" against row data.
func evaluateCondition(condition string, row map[string]any) bool {
	// Support: field = 'value', field != 'value', field > N, field < N
	condition = strings.TrimSpace(condition)

	// Try equality: field = 'value'
	for _, op := range []string{"!=", "=", ">=", "<=", ">", "<"} {
		parts := strings.SplitN(condition, op, 2)
		if len(parts) != 2 {
			continue
		}

		field := strings.TrimSpace(parts[0])
		expected := strings.TrimSpace(parts[1])
		expected = strings.Trim(expected, `"'`)

		// Format the row value as a string for comparison. Critical
		// detail: when the key is MISSING OR NIL, format as the empty
		// string — not the Go default `"<nil>"`. Pre-v2.7.6, missing
		// keys formatted as `"<nil>"`, so `field != ''` was always
		// true (even when the agent meant "field has a non-empty
		// value"). An earlier app build hit this every time it
		// gated on an optional column. Mirrors what most SQL engines
		// do: NULL compared as if it were "" for the purposes of
		// equality against the empty string literal.
		rawVal, present := row[field]
		var actual string
		if !present || rawVal == nil {
			actual = ""
		} else {
			actual = fmt.Sprintf("%v", rawVal)
		}

		switch op {
		case "=":
			return actual == expected
		case "!=":
			return actual != expected
		case ">":
			return actual > expected
		case "<":
			return actual < expected
		case ">=":
			return actual >= expected
		case "<=":
			return actual <= expected
		}
	}

	return false
}

func interpolateRow(template string, row map[string]any, appDir string) string {
	result := template
	for key, val := range row {
		result = strings.ReplaceAll(result, "{{"+key+"}}", fmt.Sprintf("%v", val))
	}
	result = InterpolateEnv(result, appDir)
	return result
}

// interpolateRowSafe replaces {{key}} AND :name with ? placeholders and
// collects args. Processes left-to-right to maintain correct arg ordering.
//
// Pre-v2.5.9 only `{{key}}` was substituted, so hook SQL using the
// standard SQL `:name` placeholder syntax (matching what every other
// flow SQL step uses) passed `:name` through to SQLite unbound — which
// bound to NULL and silently made `WHERE id = :id` match zero rows.
// An earlier app build diagnosed this as "hooks can't write protected
// fields" because the UPDATE returned success-with-zero-rows-affected.
// Now hooks accept either syntax; one consistent surface across SQL
// steps + hooks.
func interpolateRowSafe(template string, row map[string]any, appDir string) (string, []any) {
	result := InterpolateEnv(template, appDir)
	var args []any
	var output strings.Builder
	inString := false // track if we're inside a SQL string literal
	i := 0
	for i < len(result) {
		// Track SQL string literals (single quotes)
		if result[i] == '\'' && (i == 0 || result[i-1] != '\\') {
			// Check if this is the start of '{{key}}' pattern (entire value is a placeholder)
			if !inString && i+3 < len(result) && result[i+1] == '{' && result[i+2] == '{' {
				end := strings.Index(result[i+3:], "}}'")
				if end >= 0 {
					key := result[i+3 : i+3+end]
					if val, ok := row[key]; ok {
						output.WriteByte('?')
						args = append(args, val)
						i = i + 3 + end + 3
						continue
					}
				}
			}
			inString = !inString
		}

		// Handle {{key}} — different behavior inside vs outside string literals
		if i+2 < len(result) && result[i] == '{' && result[i+1] == '{' {
			end := strings.Index(result[i+2:], "}}")
			if end >= 0 {
				key := result[i+2 : i+2+end]
				if val, ok := row[key]; ok {
					if inString {
						// Inside a SQL string literal: close string, concat param, reopen
						// 'Deal {{title}} won' → 'Deal '||?||' won'
						output.WriteString("'||?||'")
						args = append(args, val) // concatenated into text — keep as string
					} else {
						// Outside string: direct parameter binding. Coerce
						// numeric-looking strings so `amount > 10000` compares
						// numerically (see coerceNumericBind for the SQLite
						// text-affinity trap this avoids).
						output.WriteByte('?')
						args = append(args, coerceNumericBind(val))
					}
					i = i + 2 + end + 2
					continue
				}
			}
		}

		// Handle :name — SQL named-parameter syntax. Only outside string
		// literals (SQLite treats `:name` inside a string as text). The
		// key character set matches identifier rules: letter / digit /
		// underscore, must start with letter or underscore.
		if !inString && result[i] == ':' && i+1 < len(result) &&
			(isLetter(result[i+1]) || result[i+1] == '_') {
			j := i + 1
			for j < len(result) && (isLetter(result[j]) || isDigit(result[j]) || result[j] == '_') {
				j++
			}
			key := result[i+1 : j]
			if val, ok := row[key]; ok {
				output.WriteByte('?')
				args = append(args, coerceNumericBind(val))
				i = j
				continue
			}
		}

		output.WriteByte(result[i])
		i++
	}
	return output.String(), args
}

// numericBindRe matches a string that cleanly represents an integer or
// float: optional sign, no leading zeros (except a bare "0"), optional
// fractional part. "42", "-5", "0", "3.14" match; "007", "1e5", "", "1.2.3"
// do not.
var numericBindRe = regexp.MustCompile(`^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$`)

// coerceNumericBind converts a numeric-looking STRING into the matching
// numeric type before it's bound as a SQL parameter. Before-hook /
// after-hook row values arrive as strings (form + JSON parsing both
// stringify), so a bare `{{amount}}` bound as TEXT hits SQLite's
// storage-class ordering: TEXT sorts above every number, making
// `'42' > 10000` evaluate TRUE. That silently inverted every numeric
// gate (`WHEN amount > 10000`). Coercing clean numeric strings to
// int64/float64 makes the comparison numeric as written.
//
// Leading-zero strings ("007", "00123") are deliberately left as TEXT —
// they're identifier-shaped (zip codes, formatted IDs), not quantities,
// and equality against a quoted literal should keep them textual.
// Non-string values (already-typed float64 from JSON, etc.) pass through.
func coerceNumericBind(v any) any {
	s, ok := v.(string)
	if !ok || !numericBindRe.MatchString(s) {
		return v
	}
	if !strings.Contains(s, ".") {
		if n, err := strconv.ParseInt(s, 10, 64); err == nil {
			return n
		}
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f
	}
	return v
}

func isLetter(b byte) bool { return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') }
func isDigit(b byte) bool  { return b >= '0' && b <= '9' }

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
