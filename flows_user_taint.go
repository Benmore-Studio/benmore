//go:build !cli

package main

// Profile values under `user` are request input.
//
// A signed-in flow's `user` object is the caller's whole _benmore_users row
// (LoadUserFields). Who the caller is (id, email, role, verified, tenant) is
// the server's, but most of the row is text the caller wrote: first_name,
// last_name and the other profile fields through PATCH /api/_auth/profile,
// auth.signup_fields through an anonymous /signup. Both request-input guards
// trusted all of it, so a first_name of `x' UNION SELECT email FROM
// _benmore_users --` reached `run: sql_dynamic` as SQL text and a last_name
// chose the host of a `run: api` call carrying the app's env secret.
//
// Every `user.<col>` except the account columns the framework owns is now in
// the request-taint set, so set, for_each, enqueue and step outputs carry it
// the way they carry a request field. Like a data event's row
// (flowEventRowTaint) the values are stored data, not request text, so a JSON
// column still decodes in a JSON body (flows_request_text.go).
//
// The email is the server's identity and stays trusted everywhere else, but
// the caller chose its text at signup and validAuthEmail accepts quotes and
// SQL comment characters (a local part holding a quote, `/**/` and `--`). So it, and any
// value built from it, is never spliced into `run: sql_dynamic` text
// (SQLTextKeys); `:user_email` in a `run: sql` step binds it safely.

import (
	"sort"
	"strings"
)

// flowUserColumnServerOwned reports whether col of the caller's user row is
// account state the framework owns rather than a value the caller wrote: the
// columns no profile edit and no public signup may set (profileProtectedFields,
// signupProtectedFields: id, role, verified, timestamps, deactivation,
// password state), secret-bearing columns (never in the row anyway), the
// groups: tenant key, role and active columns (signupFieldRefusal), and the
// email, which only a proven inbox changes. Any other column is caller-written
// or may become so (auth.profile_fields, auth.signup_fields), so it is treated
// as request input whether or not the app lists it today.
func flowUserColumnServerOwned(col string, group *GroupConfig) bool {
	lower := strings.ToLower(col)
	if lower == "email" || profileProtectedFields[lower] || signupProtectedFields[lower] || isSensitiveUserColumn(lower) {
		return true
	}
	if group != nil {
		for _, owned := range []string{group.Key, group.RoleField, group.ActiveField} {
			if owned != "" && strings.EqualFold(owned, col) {
				return true
			}
		}
	}
	return false
}

// flowUserProfileKeys returns the taint keys (`user.<col>`) of the
// caller-written columns of ctx's `user` object, sorted.
func flowUserProfileKeys(ctx *FlowContext) []string {
	if ctx == nil {
		return nil
	}
	ctx.DataMu.Lock()
	user, _ := ctx.Data["user"].(map[string]any)
	cols := make([]string, 0, len(user))
	for col := range user {
		cols = append(cols, col)
	}
	ctx.DataMu.Unlock()
	var group *GroupConfig
	if ctx.App != nil {
		group = ctx.App.Group
	}
	var keys []string
	for _, col := range cols {
		if col != "" && !flowUserColumnServerOwned(col, group) {
			keys = append(keys, "user."+col)
		}
	}
	sort.Strings(keys)
	return keys
}

// markFlowUserProfileInput adds the caller-written columns of the `user`
// object to the request-taint set, as computed data. The runtime calls it
// once the session's row is bound, after request fields under `user` were
// dropped.
func markFlowUserProfileInput(ctx *FlowContext) {
	keys := flowUserProfileKeys(ctx)
	ctx.markTainted(keys...)
	ctx.markComputed(keys...)
}

// flowEmailSQLTextKeys are the caller's email address as a flow reads it.
// They are always in the sql-text set: a flow cannot have an email that is
// safe as SQL text.
var flowEmailSQLTextKeys = []string{"user.email", "user_email"}

// sqlTextRef returns the first key template reads that holds the caller's
// email or a value built from it (flowEmailSQLTextKeys, SQLTextKeys), sorted
// for a deterministic message, or "" when it reads none.
func (ctx *FlowContext) sqlTextRef(template string) string {
	if ctx == nil || template == "" {
		return ""
	}
	keys := append([]string(nil), flowEmailSQLTextKeys...)
	ctx.DataMu.Lock()
	for k := range ctx.SQLTextKeys {
		if k != "" {
			keys = append(keys, k)
		}
	}
	ctx.DataMu.Unlock()
	sort.Strings(keys)
	for _, k := range keys {
		if flowTemplateRefsKey(template, k) {
			return k
		}
	}
	return ""
}

// markSQLText adds keys to the set of values built from the caller's email.
func (ctx *FlowContext) markSQLText(keys ...string) {
	if ctx == nil || len(keys) == 0 {
		return
	}
	ctx.DataMu.Lock()
	defer ctx.DataMu.Unlock()
	if ctx.SQLTextKeys == nil {
		ctx.SQLTextKeys = make(map[string]bool, len(keys))
	}
	for _, k := range keys {
		if k != "" {
			ctx.SQLTextKeys[k] = true
		}
	}
}

// flowSQLTextEmailNote explains a sql_dynamic refusal of the caller's email.
const flowSQLTextEmailNote = "the caller's email address (or a value built from it): signup accepts quotes and SQL comment characters in an address, so it is never written into sql_dynamic text"

// flowUserProfileRef returns the first reference in a `${{ ... }}`
// expression that reads a caller-written profile value: the whole `user`
// object or `user.<col>` for a column flowUserColumnServerOwned does not
// own. `user.group_id` and `user.org_id` read the session's tenant
// (ghaRef). The write gate has no app config, so a groups: tenant column is
// left to the runtime check.
func flowUserProfileRef(expr string) string {
	for _, ref := range flowExprRefPaths(expr) {
		col, isUser := strings.CutPrefix(ref, "user.")
		if ref == "user" {
			return ref
		}
		if !isUser {
			continue
		}
		col, _, _ = strings.Cut(col, ".")
		if col == "group_id" || col == "org_id" || flowUserColumnServerOwned(col, nil) {
			continue
		}
		return ref
	}
	return ""
}

// flowTemplateUserProfileRef returns the first caller-written profile
// reference in any `{{ ... }}` region of template, or "".
func flowTemplateUserProfileRef(template string) string {
	for _, expr := range flowTemplateExprs(template) {
		if ref := flowUserProfileRef(strings.TrimSpace(expr)); ref != "" {
			return ref
		}
	}
	return ""
}

// flowUserProfileInputNote explains a refusal whose request-input key is a
// profile value, or returns "".
func flowUserProfileInputNote(key string) string {
	if key != "user" && !strings.HasPrefix(key, "user.") {
		return ""
	}
	return " (a profile value under `user` is written by the caller through PATCH /api/_auth/profile or signup, so it is request input)"
}

// flowTemplateEmailRef returns the first `{{ ... }}` reference in template
// to the caller's email (`user.email`, `user_email`), or "".
func flowTemplateEmailRef(template string) string {
	for _, expr := range flowTemplateExprs(template) {
		for _, ref := range flowExprRefPaths(strings.TrimSpace(expr)) {
			if ref == "user.email" || ref == "user_email" {
				return ref
			}
		}
	}
	return ""
}

// sqlDynamicUserProfileProblem is the write gate's and `benmore check`'s
// refusal of a `run: sql_dynamic` statement that reads a caller-written
// profile value or the caller's email; the runtime refuses it on every
// request.
func sqlDynamicUserProfileProblem(query string) string {
	ref := flowTemplateUserProfileRef(query)
	if ref == "" {
		if email := flowTemplateEmailRef(query); email != "" {
			return "`run: sql_dynamic` reads `${{ " + email + " }}`, " + flowSQLTextEmailNote + ". The runtime refuses it on every request. Bind it with `:user_email` in a `run: sql` step."
		}
		return ""
	}
	return "`run: sql_dynamic` reads `${{ " + ref + " }}`, a profile value the caller writes (PATCH /api/_auth/profile, signup), as raw SQL text. The runtime refuses it as request input on every request. Bind it with `:name` in a `run: sql` step (`params: { name: \"${{ " + ref + " }}\" }`); only the account columns the framework owns (user.id, user.role, user.verified, user.group_id, ...; not user.email) may be written into sql_dynamic text."
}
