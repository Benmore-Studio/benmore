//go:build !cli

package main

// auth.signup_fields: the extra _benmore_users columns a public signup may
// fill. Signup is anonymous, so a column listed there is writable by anyone
// on the internet: listing `role` or `verified` made public signup an admin
// or a verified address. The runtime drops every column that carries
// authority or a secret, and the write gate refuses the declaration
// (validators_signup_fields.go).

import (
	"regexp"
	"strings"
)

var signupFieldIdentRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// signupBuiltinFields are filled by signup itself; listing them is harmless
// and they are skipped.
var signupBuiltinFields = map[string]bool{"email": true, "password": true, "username": true}

// signupProtectedFields carry identity, authority or account state.
var signupProtectedFields = map[string]bool{
	"id": true, "role": true, "verified": true, "deactivated_at": true, "deleted_at": true,
	"password_hash": true, "password_change_required": true, "email_grandfathered": true,
	"created_at": true, "updated_at": true, "last_login_at": true,
	"totp_secret": true, "backup_codes": true, "user_id": true,
}

// signupFieldRefusal returns why field may not be set by a public signup,
// or "" when it may. group is the app's tenant config (nil when none): its
// key, role and active columns place an account in a tenant and are never
// self-assigned.
func signupFieldRefusal(field string, group *GroupConfig) string {
	lower := strings.ToLower(field)
	switch {
	case !signupFieldIdentRe.MatchString(field):
		return "is not a valid column name"
	case signupProtectedFields[lower] || profileProtectedFields[lower]:
		return "is an account-authority column the framework manages"
	case isSensitiveUserColumn(lower):
		return "is a secret-bearing column"
	}
	if group != nil {
		for _, col := range []string{group.Key, group.RoleField, group.ActiveField} {
			if col != "" && strings.EqualFold(col, field) {
				return "is the tenant membership column (groups:)"
			}
		}
	}
	return ""
}

// signupFieldList returns the declared signup_fields a public signup may
// fill, in order and without duplicates. Builtins are skipped silently;
// refused columns are dropped (the write gate reports them).
func signupFieldList(raw string, group *GroupConfig) []string {
	var out []string
	seen := map[string]bool{}
	for _, field := range strings.Split(raw, ",") {
		field = strings.TrimSpace(field)
		key := strings.ToLower(field)
		if field == "" || signupBuiltinFields[key] || seen[key] || signupFieldRefusal(field, group) != "" {
			continue
		}
		seen[key] = true
		out = append(out, field)
	}
	return out
}
