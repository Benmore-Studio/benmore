//go:build !cli

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
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
	SMS     *SMSHook    // text message via the configured SMS provider
	When    string      // SQL condition over the event row: "stage = 'won'" (hook_when.go)
}

type canonicalPrivateHookFailure struct {
	message string
	cause   error
}

func (e canonicalPrivateHookFailure) Error() string { return e.message }
func (e canonicalPrivateHookFailure) Unwrap() error { return e.cause }

func beforeHookFailure(db mutationQuerier, cause error) error {
	if bound, ok := db.(appMCPContextTx); ok && bound.private {
		return canonicalPrivateHookFailure{message: "validation check could not be evaluated", cause: cause}
	}
	return fmt.Errorf("validation check could not be evaluated")
}

func afterHookConditionFailure(tx mutationTx, cause error) error {
	if bound, ok := tx.(appMCPContextTx); ok && bound.private {
		return canonicalPrivateHookFailure{message: "after-hook condition could not be evaluated", cause: cause}
	}
	return fmt.Errorf("after-hook condition could not be evaluated")
}

// SMSHook sends a text message when a data event fires. Delivery goes
// through SendSMS, so an explicitly configured provider (Twilio via
// SMS_ACCOUNT_SID, or SMS_WEBHOOK_URL) wins and the hosted platform's
// shared number is the fallback - the app writes the same YAML either way.
//
//	on_insert:
//	  messages:
//	    - sms:
//	        to: "{{recipient}}"
//	        body: "{{sms_body}}"
//	      when: "channel = 'sms'"
//
// Every send costs real money and lands on someone's phone, so a `when:`
// guard is usually load-bearing rather than decorative. Recipients must be
// E.164; the platform path additionally enforces a calling-prefix
// allowlist, per-recipient velocity, and a daily quota.
type SMSHook struct {
	To   string // E.164 recipient (templates supported, e.g. "{{recipient}}")
	Body string // message text (templates supported)
}

// WSHook fires a WebSocket broadcast to every client currently
// joined to the named room. Used for presence, live notifications,
// and any case where a server-side data change should immediately
// reach the UI without polling.
//
//	on_update:
//	  orders:
//	    - ws:
//	        room: "order-{{id}}"
//	        payload: {"status": "{{status}}", "by": "{{user_email}}"}
//
// Room IDs are scoped server-side by the connected user's group/user
// so messages can't leak across tenants - same model as bm.useLive
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
	Body     string // inline body, used when Template is empty
}

// hookEmailBody renders an email hook's body: emails/<template>.html, a
// literal template, or the inline `body:`. The YAML loader used to drop
// `body:`, so a hook written that way (the documented-looking shape) sent an
// empty email.
//
// The body is sent as HTML, so row values are escaped for where they land
// (interpolateRowHTML); `{{{col}}}` and `{{{{col}}}}` ask for markup.
func hookEmailBody(e *EmailHook, row map[string]any, appDir string) string {
	if e.Template != "" {
		// emails/ is part of the digested source; a name that climbs out of it
		// (../docs/x) is not read as a file.
		if name := e.Template + ".html"; filepath.IsLocal(name) {
			if data, err := os.ReadFile(filepath.Join(appDir, "emails", name)); err == nil {
				return interpolateRowHTML(stripEmailFrontmatter(string(data)), row, appDir)
			}
		}
		// Fall back to a literal template treated as the body.
		return interpolateRowHTML(e.Template, row, appDir)
	}
	return interpolateRowHTML(e.Body, row, appDir)
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

	section := "" // "on_insert", "on_update", "on_delete"
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
				// notify: {{user_id}} - creates a notification hook
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
// submittedFieldsKey names the before-hook row value that lists the fields
// the request submitted, as ",a,b," so a guard can test membership with
// instr('{{_submitted}}', ',weight,') > 0. An unsubmitted {{field}} renders
// as its literal placeholder text (submittedHookRow), which a caller could
// also send as a value; this list is the unambiguous signal.
const submittedFieldsKey = "_submitted"

// markSubmittedFields records on a before-hook row the columns the request
// is writing. names must be the request's own values that pass the column
// and protected-field filters: never a column the framework fills in
// (user_id, the tenant key) or a key the write drops (_csrf, query
// parameters, unknown names). Listing a dropped key would let a request
// make an unsubmitted field look submitted, e.g. with a key named "x,title".
func markSubmittedFields(row map[string]any, names []string) {
	list := make([]string, 0, len(names))
	seen := map[string]bool{}
	for _, k := range names {
		if k == "id" || k == submittedFieldsKey || seen[k] {
			continue
		}
		seen[k] = true
		list = append(list, k)
	}
	sort.Strings(list)
	row[submittedFieldsKey] = "," + strings.Join(list, ",") + ","
}

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
	// template scalar - flows and webhook templates can pipe-split if
	// they want the slice form.
	row["user_roles"] = strings.Join(session.Roles, ",")
	// The tenant is session context like the keys above: the EFFECTIVE
	// group (an admin's act-as tenant), never a value the request carried.
	// Update rows start from every submitted key, so without a tenant the
	// key is removed rather than left as whatever the body named.
	if session.EffectiveHasGroup() {
		row["user_group_id"] = session.EffectiveGroupID()
	} else {
		delete(row, "user_group_id")
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
	return fireBeforeHooksWith(app.DB, app, event, table, row)
}
func fireBeforeHooksWith(db mutationQuerier, app *App, event string, table string, row map[string]any) error {
	return fireBeforeHooksRows(db, app, event, table, row, row)
}

// submittedHookRow is what a before_update hook's SQL placeholders resolve
// against on a generic CRUD update: the request's own values. row is the
// stored row merged with the change (validators and `when:` judge the row as
// it will be), but `{{col}}` in hook SQL has always meant the value the
// request sent, with an unsubmitted column left as its literal text; a guard
// such as `'{{status}}' = 'approved'` must not fire for a request that never
// named status because the stored row already holds it. Kept: id, the
// submitted columns, {{_submitted}} and, for a signed-in caller, the session
// keys. A hook reads stored values with a subquery on {{id}}.
func submittedHookRow(row map[string]any, session *Session) map[string]any {
	list, ok := row[submittedFieldsKey].(string)
	if !ok {
		return row
	}
	out := map[string]any{submittedFieldsKey: list}
	if id, ok := row["id"]; ok {
		out["id"] = id
	}
	for _, k := range strings.Split(strings.Trim(list, ","), ",") {
		if v, ok := row[k]; ok && k != "" {
			out[k] = v
		}
	}
	if session != nil {
		for _, k := range []string{"user_email", "user_id", "user_role", "user_roles", "user_group_id"} {
			if v, ok := row[k]; ok {
				out[k] = v
			}
		}
	}
	return out
}

// fireBeforeHooksRows runs the before-hooks with `when:` judged over row and
// the hook SQL's placeholders resolved against sqlRow.
func fireBeforeHooksRows(db mutationQuerier, app *App, event string, table string, row, sqlRow map[string]any) error {
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
		if hook.When != "" {
			// A before-hook is a gate and `when:` decides whether it
			// applies. A condition that can't be evaluated refuses the
			// write, like hook SQL that can't be (below).
			met, err := evaluateWhen(db, app, table, hook.When, row)
			if err != nil {
				logWhenFailure(app, table, hook.When, err)
				return beforeHookFailure(db, err)
			}
			if !met {
				continue
			}
		}
		if hook.SQL != "" {
			// Translate the documented `RAISE(ABORT,'msg')` idiom into the
			// framework's native abort shape. SQLite rejects RAISE() outside
			// a trigger program ("RAISE() may only be used within a
			// trigger-program"), and before-hook SQL is executed directly -
			// so the documented pattern never worked. We rewrite
			//   SELECT CASE WHEN <cond> THEN RAISE(ABORT,'msg') END
			// into
			//   SELECT 'msg' AS error WHERE <cond>
			// which returns the abort row exactly when <cond> holds.
			raw := translateRaiseAbort(hook.SQL)
			sql, args := interpolateRowSafeForApp(raw, sqlRow, app)
			if bound, ok := db.(appMCPContextTx); ok && bound.private {
				if err := bound.cleanMain(); err != nil {
					return beforeHookFailure(db, err)
				}
				if !isReadOnlyQuery(sql) {
					return beforeHookFailure(db, fmt.Errorf("before-hook query is not read-only"))
				}
			}
			rows, err := queryRowsWithAppMCP(db, sql, args...)
			if err != nil {
				// FAIL CLOSED. A before-hook is a gate (auth / business-rule
				// enforcement). If it can't be evaluated - typo, bad column,
				// unsupported SQL - we must REJECT the mutation, not let it
				// through. Pre-fix this `continue`'d (fail-open), so a broken
				// security hook silently disabled enforcement and the write
				// landed with a 200. The client gets a generic 422; the real
				// SQL error is logged server-side (never leaked).
				log.Printf("BEFORE-HOOK ERROR [%s %s] %s: %s - REJECTING mutation (fail-closed)", event, table, truncate(sql, 80), err)
				return beforeHookFailure(db, err)
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
		// `when:` is SQL over the row (hook_when.go); a condition that
		// can't be evaluated doesn't fire the hook.
		if hook.When != "" && !whenHolds(app.DB, app, table, hook.When, row) {
			continue
		}

		// After-hooks are enqueued as durable jobs - not fire-and-forget goroutines.
		// This provides: guaranteed execution, retry on failure, visibility in job
		// dashboard, and testability (FlushJobs drains the queue for assertions).
		r := make(map[string]any, len(row))
		for k, v := range row {
			r[k] = v
		}
		EnqueueHookJob(app, hook, table, r)
	}
}

// fireAfterHooksTx runs SQL-only after-hooks in the mutation transaction and
// records every other hook as a durable job in that same transaction. Delivery
// remains the job worker's responsibility after commit.
func fireAfterHooksTx(tx mutationTx, app *App, event, table string, row map[string]any) ([]string, error) {
	if app.Hooks == nil {
		return nil, nil
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
	return fireHookListTx(tx, app, event, table, row, hooks)
}

// fireHookListTx shares the canonical transactional SQL/job behavior with
// workflow transition hooks. No external delivery occurs before commit.
func fireHookListTx(tx mutationTx, app *App, event, table string, row map[string]any, hooks []Hook) ([]string, error) {
	var refreshTables []string
	for _, hook := range hooks {
		if hook.When != "" {
			met, err := evaluateWhen(tx, app, table, hook.When, row)
			if err != nil {
				logWhenFailure(app, table, hook.When, err)
				return nil, afterHookConditionFailure(tx, err)
			}
			if !met {
				continue
			}
		}
		if hook.SQL != "" && hook.Webhook == "" && hook.Email == nil && hook.Notify == nil && hook.WS == nil && hook.SMS == nil {
			sqlText, args := interpolateRowSafeForApp(hook.SQL, row, app)
			if bound, ok := tx.(appMCPContextTx); ok && bound.private {
				if err := bound.cleanMain(); err != nil {
					return nil, err
				}
				if err := validateCanonicalHookScript(sqlText); err != nil {
					return nil, err
				}
			}
			if _, err := tx.Exec(sqlText, args...); err != nil {
				return nil, fmt.Errorf("after-hook SQL failed: %w", err)
			}
			for _, target := range canonicalHookRefreshTargets(app, sqlText, table) {
				refreshTables = append(refreshTables, target)
			}
			continue
		}
		payload := hookJobPayload(hook, table, row)
		if err := sealJobPayloadRow(tx, app, table, payload); err != nil {
			return nil, fmt.Errorf("enqueue after-hook job: %w", err)
		}
		if err := enqueueMutationJob(tx, "hook", table, event, "hook", "hook", payload); err != nil {
			return nil, fmt.Errorf("enqueue after-hook job: %w", err)
		}
	}
	return refreshTables, nil
}

func canonicalHookRefreshTargets(app *App, executedSQL, primaryTable string) []string {
	targets, _ := sqlWriteTargets(executedSQL)
	seen := make(map[string]bool, len(targets))
	var refresh []string
	for _, target := range targets {
		name := target.Table
		folded := sqliteIdentifierFold(name)
		if folded == "" || folded == sqliteIdentifierFold(primaryTable) || strings.HasPrefix(folded, "_benmore_") || seen[folded] {
			continue
		}
		canonicalName := ""
		for _, appTable := range app.Tables {
			if sqliteIdentifierFold(appTable.Name) == folded {
				canonicalName = appTable.Name
				break
			}
		}
		if canonicalName != "" {
			seen[folded] = true
			refresh = append(refresh, canonicalName)
		}
	}
	return refresh
}

func queryRowsWithAppMCP(db mutationQuerier, query string, args ...any) ([]map[string]any, error) {
	if bound, ok := db.(appMCPContextTx); ok && bound.private {
		return queryRowsWithMainKey(bound, query, args...)
	}
	return queryRowsWith(db, query, args...)
}

func validateCanonicalHookScript(script string) error {
	statements := 0
	err := splitSQLStatements(strings.NewReader(script), func(statement string) error {
		tokens := sqlTokenize(statement)
		if len(tokens) == 0 {
			return nil
		}
		statements++
		if tokens[0].kind != sqlTokWord {
			return fmt.Errorf("hook statement is malformed")
		}
		switch strings.ToUpper(tokens[0].text) {
		case "SELECT", "INSERT", "UPDATE", "DELETE", "REPLACE", "WITH":
		default:
			return fmt.Errorf("hook statement type is unsupported")
		}
		lower := strings.ToLower(statement)
		if strings.Contains(lower, "load_extension") || canonicalHookForbiddenSQL.MatchString(statement) {
			return fmt.Errorf("hook statement contains a forbidden SQL construct")
		}
		return nil
	})
	if err != nil {
		return err
	}
	if statements == 0 {
		return fmt.Errorf("hook must contain a statement")
	}
	return nil
}

var canonicalHookForbiddenSQL = regexp.MustCompile(`(?i)\b(?:PRAGMA|ATTACH|DETACH)\b`)

// postWebhook treats only 2xx as delivered. A transport error is ambiguous: the
// receiver may have processed the POST before the response was lost, so callers
// must not replay it. 408, 429 and 5xx responses remain retryable for ordinary
// subscriptions; command-stamped effects are sealed after any delivery error.
func postWebhook(client *http.Client, req *http.Request) (int, error) {
	// Webhook POSTs must not be transformed into GETs or sent to another host
	// by net/http's redirect policy. The 3xx response is classified below.
	requestClient := *client
	requestClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := requestClient.Do(req)
	if err != nil {
		return 0, jobNotRetryable{errors.New("unknown: webhook response was not confirmed")}
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return resp.StatusCode, nil
	}
	if resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
		return resp.StatusCode, fmt.Errorf("webhook returned %d", resp.StatusCode)
	}
	return resp.StatusCode, jobNotRetryable{fmt.Errorf("webhook returned permanent status %d", resp.StatusCode)}
}

func webhookHostForLog(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return "unknown"
	}
	return u.Hostname()
}

func webhookDeliveryError(err error, commandEffect bool) error {
	if err != nil && commandEffect {
		return jobNotRetryable{err}
	}
	return err
}

func executeHook(app *App, hook Hook, table string, row map[string]any) {
	// Best effort, as before: failures are logged, never retried.
	_ = executeHookResult(app, hook, table, row)
}

// executeHookResult runs one hook and reports the first action that did not
// complete. A connector-command effect job turns that into a failed (not
// retried, not "delivered") effect; every other caller keeps the historic
// log-only behavior through executeHook.
func executeHookResult(app *App, hook Hook, table string, row map[string]any) (err error) {
	db, appDir := app.DB, app.Dir
	// firstErr records a failure the historic flow carried on past (email, sms,
	// notify); a failure it returned on is returned the same way.
	var firstErr error
	note := func(failure error) {
		if firstErr == nil {
			firstErr = failure
		}
	}
	defer func() {
		if r := recover(); r != nil {
			log.Printf("HOOK PANIC: %v", r)
			err = fmt.Errorf("hook panicked")
		}
	}()

	// Webhook
	if hook.Webhook != "" {
		webhookURL := interpolateEnvForApp(hook.Webhook, app)
		webhookHost := webhookHostForLog(webhookURL)

		// SSRF protection: block requests to private/internal IPs
		if isPrivateURL(webhookURL) {
			log.Printf("SECURITY: blocked webhook to private host: %s", webhookHost)
			return errors.New("hook webhook blocked: private URL")
		}

		body := interpolateRowJSONForApp(hook.Body, row, app)
		if body == "" {
			body = hookDefaultBody(app, table, row)
		}

		// Circuit breaker: skip if endpoint is known-dead
		host := circuitKey(app, webhookURL)
		if err := CheckCircuit(host); err != nil {
			log.Printf("HOOK SKIPPED [webhook] %s: %s", webhookHost, err)
			return errors.New("hook webhook skipped: circuit open")
		}

		req, err := http.NewRequest("POST", webhookURL, bytes.NewBufferString(body))
		if err != nil {
			log.Printf("HOOK ERROR [webhook] %s: request could not be built", webhookHost)
			RecordFailure(host)
			return errors.New("hook webhook request could not be built")
		}
		req.Header.Set("Content-Type", "application/json")

		client := safeHTTPClientStrict(10 * time.Second)
		status, err := postWebhook(client, req)
		if err != nil {
			log.Printf("HOOK ERROR [webhook] %s: %s", webhookHost, err)
			RecordFailure(host)
			return err
		}
		RecordSuccess(host)
		log.Printf("HOOK [webhook] %s → %d", webhookHost, status)
	}

	// SQL - use parameterized interpolation to prevent injection from row data
	if hook.SQL != "" {
		sql, args := interpolateRowSafeForApp(hook.SQL, row, app)
		if _, err := db.Exec(sql, args...); err != nil {
			log.Printf("HOOK ERROR [sql] %s: %s", truncate(sql, 80), err)
			return errors.New("hook SQL failed")
		}
		log.Printf("HOOK [sql] executed: %s", truncate(sql, 60))
	}

	// Email - send via SendEmailOpts (platform SES gateway, or SMTP off-platform).
	// Template is loaded from emails/<name>.html if specified; row
	// values are mustache-interpolated into both subject + body.
	if hook.Email != nil {
		// Part by part: a row value is one recipient (email_recipients.go).
		to, toErr := hookEmailRecipients(hook.Email.To, row, appDir)
		subject := interpolateRow(hook.Email.Subject, row, appDir)
		if toErr != nil {
			log.Printf("HOOK [email] send failed: %s", toErr)
			note(errors.New("hook email was not sent"))
		} else if err := SendEmail(appDir, to, subject, hookEmailBody(hook.Email, row, appDir)); err != nil {
			log.Printf("HOOK [email] send failed: %s", logSendErrorRecipients(err, to))
			note(errors.New("hook email was not sent"))
		} else {
			log.Printf("HOOK [email] sent to=%s subject=%s", logRecipientsRef(to), subject)
		}
	}

	// SMS - send via SendSMS (explicit provider if configured, else the
	// platform's shared number). An empty recipient or body after
	// interpolation means the template referenced a column that isn't on
	// the row: say so instead of handing an empty string to the provider.
	if hook.SMS != nil {
		to := interpolateRow(hook.SMS.To, row, appDir)
		body := interpolateRow(hook.SMS.Body, row, appDir)
		switch {
		case to == "":
			log.Printf("HOOK [sms] skipped: `to` resolved empty from template %q - check the column exists on the row", hook.SMS.To)
			note(errors.New("hook sms skipped: empty recipient"))
		case body == "":
			log.Printf("HOOK [sms] skipped: `body` resolved empty from template %q - check the column exists on the row", hook.SMS.Body)
			note(errors.New("hook sms skipped: empty body"))
		default:
			if err := SendSMS(appDir, to, body); err != nil {
				log.Printf("HOOK [sms] send failed to=%s: %s", logAddressRef(to), logSendError(err, to))
				note(errors.New("hook sms was not sent"))
			} else {
				log.Printf("HOOK [sms] sent to=%s", logAddressRef(to))
			}
		}
	}

	// Notification
	if hook.Notify != nil {
		if err := executeNotifyHook(db, hook.Notify, row, appDir); err != nil {
			note(err)
		}
	}

	// WebSocket broadcast
	if hook.WS != nil && hook.WS.Room != "" {
		room := interpolateRow(hook.WS.Room, row, appDir)
		payload := hook.WS.Payload
		if payload == "" {
			payload = hookDefaultWSPayload(table)
		} else {
			payload = interpolateRowJSONWithEnv(payload, row, nil, appDir)
		}
		groupID := ""
		if app.Group != nil && app.Group.Key != "" {
			if v := row[app.Group.Key]; v != nil {
				groupID = fmt.Sprint(v)
			}
		}
		if err := BroadcastWSToRoom(app, groupID, room, payload); err != nil {
			log.Printf("HOOK ERROR [ws]: %s", err)
			note(errors.New("hook ws broadcast failed"))
			return firstErr
		}
		log.Printf("HOOK [ws] broadcast to %s (%d bytes)", room, len(payload))
	}
	return firstErr
}

// hookDefaultBody is what a hook `webhook:` without `body:` posts: the event
// row with the columns an API read would carry, like a webhook subscription
// delivery (webhookPayloadRow). A job queued without its table strips by
// column name.
func hookDefaultBody(app *App, table string, row map[string]any) string {
	data, _ := json.Marshal(webhookPayloadRow(app, table, row))
	return string(data)
}

// hookDefaultWSPayload is what a hook `ws:` without `payload:` broadcasts:
// only the table that changed. Room members are clients and an undeclared
// room is open to any signed-in user of the app or tenant, so the row (which
// row scoping and encrypted-field masking would otherwise filter) is sent
// only when the payload names its columns.
func hookDefaultWSPayload(table string) string {
	if table == "" {
		return "{}"
	}
	data, _ := json.Marshal(map[string]string{"table": table})
	return string(data)
}

// interpolateRow replaces `{{column}}` with the row's value and
// `{{env.X}}` with the app's env value in ONE pass over the author's
// template. Substituted values are never scanned again: row values are
// user input, and re-expanding them let a submitted `{{env.SECRET}}` (or
// another column's `{{name}}`) reach a webhook, email or notification.
func interpolateRow(template string, row map[string]any, appDir string) string {
	return interpolateRowWithEnv(template, row, nil, appDir)
}

func interpolateRowForApp(template string, row map[string]any, app *App) string {
	if app == nil {
		return interpolateRowWithEnv(template, row, map[string]string{}, "")
	}
	app.mu.RLock()
	env := app.environment
	app.mu.RUnlock()
	if env != nil {
		return interpolateRowWithEnv(template, row, env, "")
	}
	return interpolateRowWithEnv(template, row, nil, app.Dir)
}

func interpolateRowWithEnv(template string, row map[string]any, env map[string]string, appDir string) string {
	if !strings.Contains(template, "{{") {
		return template
	}
	var b strings.Builder
	i := 0
	for i < len(template) {
		if strings.HasPrefix(template[i:], "{{") {
			if end := strings.Index(template[i+2:], "}}"); end >= 0 {
				name := template[i+2 : i+2+end]
				if val, ok := row[name]; ok {
					fmt.Fprintf(&b, "%v", val)
					i += end + 4
					continue
				}
				if key, ok := strings.CutPrefix(name, "env."); ok {
					if env == nil {
						env = AppEnvSnapshot(appDir)
					}
					if val, ok := env[key]; ok {
						b.WriteString(val)
						i += end + 4
						continue
					}
				}
			}
		}
		b.WriteByte(template[i])
		i++
	}
	return b.String()
}

// interpolateRowSafe replaces {{key}} AND :name with ? placeholders and
// collects args. Processes left-to-right to maintain correct arg ordering.
//
// Pre-v2.5.9 only `{{key}}` was substituted, so hook SQL using the
// standard SQL `:name` placeholder syntax (matching what every other
// flow SQL step uses) passed `:name` through to SQLite unbound - which
// bound to NULL and silently made `WHERE id = :id` match zero rows.
// An earlier app build diagnosed this as "hooks can't write protected
// fields" because the UPDATE returned success-with-zero-rows-affected.
// Now hooks accept either syntax; one consistent surface across SQL
// steps + hooks.
func interpolateRowSafe(template string, row map[string]any, appDir string) (string, []any) {
	result := interpolateEnvValues(template, AppEnvSnapshot(appDir))
	return interpolateRowSafeValues(result, row)
}

func interpolateRowSafeForApp(template string, row map[string]any, app *App) (string, []any) {
	return interpolateRowSafeValues(interpolateEnvForApp(template, app), row)
}

func interpolateRowSafeValues(result string, row map[string]any) (string, []any) {
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

		// Handle {{key}} - different behavior inside vs outside string literals
		if i+2 < len(result) && result[i] == '{' && result[i+1] == '{' {
			end := strings.Index(result[i+2:], "}}")
			if end >= 0 {
				key := result[i+2 : i+2+end]
				if val, ok := row[key]; ok {
					if inString {
						// Inside a SQL string literal: close string, concat param, reopen
						// 'Deal {{title}} won' → 'Deal '||?||' won'
						output.WriteString("'||?||'")
						args = append(args, val) // concatenated into text - keep as string
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

		// Handle :name - SQL named-parameter syntax. Only outside string
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
// Leading-zero strings ("007", "00123") are deliberately left as TEXT -
// they're identifier-shaped (zip codes, formatted IDs), not quantities,
// and equality against a quoted literal should keep them textual.
// Non-string values (already-typed float64 from JSON, etc.) pass through.
//
// Sibling: flows_interpolate.go's sqlBindValue (v2.7.162) fixes the same trap for
// flow :params with a STRICTER rule (canonical round-trip; '1.50'
// stays TEXT). Hook row values are column data, so the permissive rule
// fits here; flow params are URL/JSON input where identifier-shaped
// strings are common. The divergence is deliberate.
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
