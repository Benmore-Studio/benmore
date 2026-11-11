//go:build !cli

package main

import (
	"fmt"
	"strings"
)

// checkScope validates that the session's scopes allow the given action on the given table.
// Returns nil if allowed, an error if denied.
// Empty scopes means unrestricted (cookie sessions, backward compatible).
// Admin does NOT bypass a credential's scopes - they are a constraint ON TOP
// of roles. (The built-in admin role itself holds every scope unless roles:
// declares it: sessionRoleScopes.)
func checkScope(session *Session, table string, action string) error {
	if !hasScope(session, table, action) && !accessDecidesTable(session, table, action) {
		return scopeDenied(session, table, action)
	}
	return nil
}

// scopeDeniedBody is the 403 body of a scope refusal: its sentence, and
// where role and token scopes are documented (refusal_docs.go).
func scopeDeniedBody(err error) map[string]any {
	return withRefusalDocs(map[string]any{"error": err.Error()}, refusalScopeDenied)
}

// scopeDenied names what refused table:action. A credential that carries its
// own scopes (an API token, a scoped Bearer session, a connector grant) is a
// token, and when those scopes leave the permission out the token is the
// reason. Otherwise the account's roles are: role scopes narrow every
// session of an app with a roles: block, a cookie sign-in included, which
// used to be told its "token" lacked the permission.
func scopeDenied(session *Session, table, action string) error {
	cred := ""
	token := false
	if session != nil {
		cred = session.CredentialScopes
		token = strings.HasPrefix(session.ID, "apitoken:") || (cred != "" && cred != "*")
	}
	if token && cred != "" && cred != "*" && !hasScope(&Session{Scopes: cred}, table, action) {
		return fmt.Errorf("scope denied: token does not have %s:%s permission", table, action)
	}
	noun := "session"
	if token {
		noun = "token"
	}
	return fmt.Errorf("scope denied: %s does not have %s:%s permission: no role the account holds grants it under roles: in app.yaml", noun, table, action)
}

// hasScope checks if the session is allowed to perform the given action on the given table.
func hasScope(session *Session, table string, action string) bool {
	if session == nil {
		return false
	}
	// Empty scopes = no restriction (cookie sessions, legacy bearer tokens)
	if session.Scopes == "" {
		return true
	}
	// Explicit full access
	if session.Scopes == "*" {
		return true
	}

	for _, scope := range strings.Fields(session.Scopes) {
		resource, scopeAction := parseScope(scope)
		if resource == "" {
			continue // malformed, skip
		}
		// A wildcard resource still constrains the action (e.g. *:read).
		if resource != "*" && resource != table {
			continue
		}
		// Exact table match - check action
		if scopeAction == "*" {
			return true
		}
		if scopeAction == action {
			return true
		}
		// Write implies read (standard OAuth2 pattern)
		// If you can write to a table, you can obviously read from it
		if action == "read" && scopeAction == "write" {
			return true
		}
		// Delete does NOT imply read or write - it's a separate destructive action
	}
	return false
}

// scopedCredential reports whether a signed-in caller's credential was
// minted with explicit scopes (an API token or Bearer session narrowed for an
// integration, a connector grant): delegated access, the complement of
// accountManagementSession. Auto-CRUD narrows it table by table; a surface
// with no table of its own must ask for a named scope (a flow's
// permissions:, the directory's _benmore_users, notifications'
// _notifications) before acting as the user for it. An unscoped credential
// ("" or "*"), an ordinary sign-in included, is never one.
func scopedCredential(session *Session) bool {
	return session != nil && !accountManagementSession(session)
}

// scopesWithin reports whether every requested permission is covered by the
// caller. A wildcard in the request must itself be covered by a wildcard;
// enumerating today's tables/actions cannot authorize future ones.
func scopesWithin(granted, requested string) bool {
	if granted == "" || granted == "*" || granted == "*:*" {
		return true
	}
	if requested == "" || requested == "*" {
		return false
	}
	s := &Session{Scopes: granted}
	for _, scope := range strings.Fields(requested) {
		resource, action := parseScope(scope)
		if resource == "" || !hasScope(s, resource, action) {
			return false
		}
	}
	return len(strings.Fields(requested)) > 0
}

// intersectScopes constrains a credential by the user's current role grants.
// Empty means unrestricted, so an empty intersection uses the deny sentinel.
func intersectScopes(a, b string) string {
	if a == "" || a == "*" {
		return b
	}
	if b == "" || b == "*" {
		return a
	}
	var out []string
	seen := map[string]bool{}
	for _, left := range strings.Fields(a) {
		lr, la := parseScope(left)
		if lr == "" {
			continue
		}
		for _, right := range strings.Fields(b) {
			rr, ra := parseScope(right)
			if rr == "" || (lr != rr && lr != "*" && rr != "*") {
				continue
			}
			resource := lr
			if resource == "*" {
				resource = rr
			}
			action := la
			switch {
			case la == ra:
			case la == "*":
				action = ra
			case ra == "*":
			case (la == "write" && ra == "read") || (la == "read" && ra == "write"):
				action = "read"
			default:
				continue
			}
			scope := resource + ":" + action
			if !seen[scope] {
				seen[scope] = true
				out = append(out, scope)
			}
		}
	}
	if len(out) == 0 {
		return "_none_:read"
	}
	return strings.Join(out, " ")
}

// parseScope splits "resource:action" into its components.
// Returns ("","") if malformed.
func parseScope(scope string) (string, string) {
	parts := strings.SplitN(scope, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", ""
	}
	return parts[0], parts[1]
}

// validateScopes checks that a scopes string is well-formed.
// Returns an error if any scope is invalid.
//
// `read`, `write`, `delete`, and `*` are the framework's CRUD-handler
// verbs (auth_*.go, crud_*.go, settings.go) - flow handlers route these
// to the right checkScope branch in hasScope. Any *other* verb is an
// app-defined custom action used by the developer's own flows.yaml
// (`reports:review`, `orders:approve`, `posts:publish`, …). Pre-2.7.31
// these were rejected by a hardcoded allowlist - apps.md showed
// "scopes: 'contacts:read contacts:review'" patterns and validators
// then refused to write them. An earlier app build was the
// second demo in a row to trip this.
//
// We now require only that each scope is well-formed (`resource:action`
// with non-empty identifier parts). Identifiers must match the same
// shape as table / column names - alphanumeric + underscore - so junk
// like `posts:do-stuff` or `posts: ` still surfaces as a clear error.
func validateScopes(scopes string) error {
	if scopes == "" || scopes == "*" {
		return nil
	}
	for _, scope := range strings.Fields(scopes) {
		resource, action := parseScope(scope)
		if resource == "" {
			return fmt.Errorf("invalid scope format: %q (expected resource:action)", scope)
		}
		if !isScopeIdentifier(resource) {
			return fmt.Errorf("invalid scope resource %q in %q (allowed chars: a-z, A-Z, 0-9, _, *)", resource, scope)
		}
		if !isScopeIdentifier(action) {
			return fmt.Errorf("invalid scope action %q in %q (allowed chars: a-z, A-Z, 0-9, _, *)", action, scope)
		}
	}
	return nil
}

// isScopeIdentifier returns true for a wildcard or a non-empty
// identifier consisting only of letters, digits, and underscores.
// Mirrors the framework's table/column naming rules so a custom verb
// stays interchangeable with framework-defined verbs everywhere
// hasScope walks.
func isScopeIdentifier(s string) bool {
	if s == "*" {
		return true
	}
	if s == "" {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// accessDecidesTable is the `table_scopes: access` path of the auto-CRUD scope
// gate: for a schema table the role scopes do not decide, the caller's own
// credential (an API token's or connector grant's scopes) still must allow
// the action, and access: rules decide the rest. Only checkScope consults it;
// session scopes, perm: modes, flow and connector permissions never do.
func accessDecidesTable(session *Session, table, action string) bool {
	if session == nil || !session.accessTables[table] {
		return false
	}
	cred := session.CredentialScopes
	return cred == "" || cred == "*" || hasScope(&Session{Scopes: cred}, table, action)
}
