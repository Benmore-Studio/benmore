//go:build !cli

package main

// Write-time gate for auth.signup_fields (see auth_signup_fields.go). The
// runtime already drops these columns from a public signup; refusing the
// declaration tells the author the field would never be stored instead of
// letting it fail silently.

import (
	"fmt"
	"sort"
	"strings"
)

// validateSignupFields returns an error string when app.yaml lists a
// signup field that a public signup may not set.
func validateSignupFields(content string) string {
	doc, _, err := parseAppConfigDocument([]byte(content))
	if err != nil {
		return "" // validateAppYAML reports the parse error
	}
	auth, _ := doc["auth"].(map[string]any)
	if auth == nil {
		return ""
	}
	// auth values are scalars (parseAppConfigDocument refuses anything else).
	raw, ok := auth["signup_fields"].(string)
	if !ok {
		return ""
	}
	fields := strings.Split(raw, ",")
	var group *GroupConfig
	if g, ok := doc["groups"].(map[string]any); ok {
		group = &GroupConfig{}
		group.Key, _ = g["key"].(string)
		group.RoleField, _ = g["role_field"].(string)
		group.ActiveField, _ = g["active_field"].(string)
	}
	var refused []string
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field == "" || signupBuiltinFields[strings.ToLower(field)] {
			continue
		}
		if reason := signupFieldRefusal(field, group); reason != "" {
			refused = append(refused, fmt.Sprintf("%q %s", field, reason))
		}
	}
	if len(refused) == 0 {
		return ""
	}
	sort.Strings(refused)
	return "security [signup-fields-protected] in app.yaml: auth.signup_fields lets anyone who signs up set these _benmore_users columns, so it may only list plain profile columns. Refused: " +
		strings.Join(refused, "; ") +
		". Remove them; set roles with role grants (api(at:'rbac')), verification through the verification flow, and tenant membership through groups.bootstrap or invitations."
}
