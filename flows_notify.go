//go:build !cli

package main

// `run: notify` - an in-app notification for one user from a flow.
//
// A hooks.yaml `notify:` fires only for writes that run hooks (auto-CRUD,
// workflow transitions, groups bootstrap, approved MCP commands); a flow's own
// SQL writes never fire hooks or event flows, and there is no notification
// create API. So a request, cron, async or data-event flow had no supported
// way to notify a user: an `INSERT INTO _benmore_notifications` stored a row,
// but flow writes to `_benmore_*` tables are never announced, so the
// recipient's bm.notifications.onNew never heard of it.
//
// The step stores the notification through the code hook `notify:` uses
// (insertNotification + announceNotification, notifications.go): the same
// type and link rules, the same per-user retention, and the same live event,
// which reaches only the recipient's own streams (realtimePrincipal.canRead
// for _benmore_notifications) whoever ran the flow, including a run with no
// session. Every field resolves through interpolateCtx in one pass, so request
// values land in title and body as text and are never resolved again. The
// recipient is parsed as a whole number and bound as a SQL parameter.
//
// A recipient id that names no user fails the step (nothing is stored, so a
// later account with that id cannot inherit it); an `on_error:` handler can
// catch it. Inside a transaction the row is written in the transaction and
// announced after COMMIT; a rollback keeps and announces nothing.

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"maps"
	"slices"
	"strconv"
	"strings"
)

// ghaNotifyText reads a `run: notify` `with:` value: text (GHA refs
// normalized) or a bare YAML integer as its decimal text. Any other shape
// reads as "" and is refused by ghaNotifyViolation.
func ghaNotifyText(v any) string {
	switch t := v.(type) {
	case string:
		return normalizeGHARefs(t)
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case uint64:
		return strconv.FormatUint(t, 10)
	}
	return ""
}

// notifyTemplated reports whether a notify value is filled in at run time
// (a `${{ }}` / `{{ }}` ref or a `:param` token) rather than literal text.
func notifyTemplated(s string) bool {
	return strings.Contains(s, "{{") || strings.Contains(s, ":")
}

// notifyStepKeys are the `with:` keys a notify step reads (the
// flowStepKeyTable row, in a fixed order for messages).
var notifyStepKeys = []string{"user_id", "title", "body", "type", "link"}

// ghaNotifyViolation checks every `run: notify` step, at any nesting depth:
// `with.user_id` and `with.title` are required, each value is text or a whole
// number, a literal recipient is a positive whole number, a literal type is
// one of the four notification types, and no other `with:` key is accepted.
// Shared by the write gate, `benmore check` and the flow loader through
// validateGHAFlowsContents.
func ghaNotifyViolation(jobName, parent string, steps []FlowStepGHA) string {
	const example = "\n\nExample:\n" +
		"  - run: notify\n" +
		"    with:\n" +
		"      user_id: ${{ steps.task.outputs.assignee_id }}\n" +
		"      title: \"New task: ${{ steps.task.outputs.title }}\"\n" +
		"      body: \"Due ${{ steps.task.outputs.due_on }}\"   # optional\n" +
		"      link: \"/tasks/${{ steps.task.outputs.id }}\"    # optional\n" +
		"      type: info                                      # optional: info | success | warning | error"
	for i, s := range steps {
		label := fmt.Sprintf("step %d", i)
		if parent != "" {
			label = fmt.Sprintf("%s[%d]", parent, i)
		}
		if strings.EqualFold(strings.TrimSpace(s.Run), "notify") {
			if msg := notifyStepViolation(fmt.Sprintf("flows.yaml: job %q %s (run: notify)", jobName, label), s.With); msg != "" {
				if strings.Contains(msg, " requires ") {
					msg += example
				}
				return msg
			}
		}
		for _, b := range []struct {
			name  string
			steps []FlowStepGHA
		}{{ghaNestedBodyName(s) + " steps", s.Steps}, {"else", s.Else}, {"on_error", s.OnError}} {
			if msg := ghaNotifyViolation(jobName, label+" > "+b.name, b.steps); msg != "" {
				return msg
			}
		}
	}
	return ""
}

func notifyStepViolation(where string, with map[string]any) string {
	for _, key := range slices.Sorted(maps.Keys(with)) {
		if !slices.Contains(notifyStepKeys, key) {
			hint := ""
			if strings.HasPrefix(key, "notify_") {
				hint = fmt.Sprintf(" (`notify_%s` is the hooks.yaml spelling; here it is `%s`)", strings.TrimPrefix(key, "notify_"), strings.TrimPrefix(key, "notify_"))
			}
			return where + fmt.Sprintf(": `with.%s` is not a notify option%s; the step takes user_id, title, body, type and link.", key, hint)
		}
	}
	for _, key := range notifyStepKeys {
		v, present := with[key]
		if !present || v == nil {
			switch key {
			case "user_id":
				return where + " requires `with.user_id` - the id of the user to notify (a whole number, or a `${{ }}` ref that gives one)."
			case "title":
				return where + " requires `with.title` - the notification's heading."
			}
			continue
		}
		switch v.(type) {
		case string, int, int64, uint64:
		default:
			if key == "user_id" {
				return where + fmt.Sprintf(": `with.user_id` must be one user id (a whole number) or a `${{ }}` ref, got %T. To notify several users, put the step in a `for_each:` loop.", v)
			}
			return where + fmt.Sprintf(": `with.%s` must be text, got %T.", key, v)
		}
	}
	userID := ghaNotifyText(with["user_id"])
	if !notifyTemplated(userID) {
		if id, err := strconv.ParseInt(strings.TrimSpace(userID), 10, 64); err != nil || id <= 0 {
			return where + fmt.Sprintf(": `with.user_id` %q is not a user id - write the user's id (a whole number greater than 0) or a `${{ }}` ref that gives one, such as `${{ steps.task.outputs.assignee_id }}`.", userID)
		}
	}
	if strings.TrimSpace(ghaNotifyText(with["title"])) == "" {
		return where + ": `with.title` is empty; a notification needs a heading."
	}
	if t := ghaNotifyText(with["type"]); t != "" && !notifyTemplated(t) && !validNotificationType(strings.ToLower(strings.TrimSpace(t))) {
		return where + fmt.Sprintf(": `with.type` %q is not a notification type; use info, success, warning or error (default info).", t)
	}
	return ""
}

// errNotifyRecipientMissing is the step error for a recipient id that names
// no user.
var errNotifyRecipientMissing = errors.New("no user has that id")

// execStepNotify creates one notification. Outputs: steps.<id>.outputs.id
// (the notification) and .user_id (the recipient).
func execStepNotify(ctx *FlowContext, step *FlowStep) error {
	n := step.Notify
	if n == nil || strings.TrimSpace(n.UserID) == "" {
		return fmt.Errorf("notify step requires `with.user_id`")
	}
	if strings.TrimSpace(n.Title) == "" {
		return fmt.Errorf("notify step requires `with.title`")
	}
	rawID := strings.TrimSpace(interpolateCtx(n.UserID, ctx))
	title := interpolateCtx(n.Title, ctx)
	body := interpolateCtx(n.Body, ctx)
	link := strings.TrimSpace(interpolateCtx(n.Link, ctx))
	notifType := strings.ToLower(strings.TrimSpace(interpolateCtx(n.Type, ctx)))
	// An unresolved ref must not create a notification: return before
	// writing and let the dispatcher report the refs (executeStep).
	ctx.DataMu.Lock()
	unresolved := len(ctx.MissingRefs) > 0
	ctx.DataMu.Unlock()
	if unresolved {
		return nil
	}
	userID, err := strconv.ParseInt(rawID, 10, 64)
	if err != nil || userID <= 0 {
		return fmt.Errorf("notify: user_id %q is not a user id (a whole number greater than 0)", truncate(rawID, 40))
	}
	if strings.TrimSpace(title) == "" {
		return fmt.Errorf("notify: `title` is empty after interpolation (template %q)", n.Title)
	}
	if notifType != "" && !validNotificationType(notifType) {
		log.Printf("flows: notify step=%q type %q is not a notification type; stored as info", step.Name, truncate(notifType, 40))
	}

	var id int64
	if ctx.Tx != nil {
		// Serialize Tx access like every other step that writes through it
		// (a parallel block never shares a transaction, but the mutex is
		// the transaction's one owner).
		mu := ctx.transactionMutex()
		mu.Lock()
		err = notifyRecipientExists(ctx.Tx, userID)
		if err == nil {
			id, notifType, err = insertNotification(ctx.execContext(), ctx.Tx, userID, title, body, notifType, link)
		}
		mu.Unlock()
		if err != nil {
			return notifyStepError(userID, err)
		}
		// Announced once the run's transaction commits; a rollback drops it
		// with the row. A run with no write log announces now.
		db, kind := ctx.App.DB, notifType
		if ctx.Writes != nil {
			ctx.Writes.onCommit(func() { announceNotification(db, userID, kind, title) })
		} else {
			announceNotification(db, userID, kind, title)
		}
	} else {
		if err := notifyRecipientExists(ctx.App.DB, userID); err != nil {
			return notifyStepError(userID, err)
		}
		id, notifType, err = insertNotification(ctx.execContext(), ctx.App.DB, userID, title, body, notifType, link)
		if err != nil {
			return notifyStepError(userID, err)
		}
		announceNotification(ctx.App.DB, userID, notifType, title)
	}
	log.Printf("flows: notify step=%q user=%d notification=%d", step.Name, userID, id)
	ctx.setStepOutput(step.Name, map[string]any{"id": id, "user_id": userID})
	return nil
}

// notifyRecipientExists reports errNotifyRecipientMissing when no
// _benmore_users row has the id. The id is a bound parameter.
func notifyRecipientExists(db mutationQuerier, userID int64) error {
	var one int
	err := db.QueryRow("SELECT 1 FROM _benmore_users WHERE id = ?", userID).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return errNotifyRecipientMissing
	}
	return err
}

func notifyStepError(userID int64, err error) error {
	if errors.Is(err, errNotifyRecipientMissing) {
		return fmt.Errorf("notify: no user has id %d; nothing was stored", userID)
	}
	return fmt.Errorf("notify: %w", err)
}
