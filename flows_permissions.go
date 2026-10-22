//go:build !cli

package main

import (
	"fmt"
	"strings"
)

func validateFlowPermissions(permissions []string) error {
	seen := map[string]bool{}
	for _, permission := range permissions {
		resource, action := parseScope(permission)
		if permission != strings.TrimSpace(permission) || len(strings.Fields(permission)) != 1 || validateScopes(permission) != nil || resource == "" || resource == "*" || action == "*" || seen[permission] {
			return fmt.Errorf("permissions must contain distinct explicit resource:action scopes")
		}
		seen[permission] = true
	}
	return nil
}
