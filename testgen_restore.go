//go:build !cli

package main

import (
	"net/http"
	"strings"
)

// Generated tests must not revive arbitrary app data or assume app-specific
// update hooks permit restoration. Exercise the native action's invalid-ID
// guard; the successful transaction and rollback paths have isolated Go tests.
func generateRestoreTests(app *App) AppTestFile {
	tests := make(map[string]AppTestCase)
	for _, table := range userTables(app) {
		if !hasColumn(app, table, "deleted_at") || restoreRouteOwnedByFlow(app, table) {
			continue
		}
		// "01" aliases integer key 1 in SQLite, but the request guard must
		// reject its noncanonical spelling. TEXT keys deliberately accept it.
		integerID := false
		for _, col := range tableColumns(app, table) {
			if identIs(col.Name, "id") && col.PK && strings.Contains(strings.ToUpper(col.Type), "INT") {
				integerID = true
			}
		}
		if !integerID || rowIDCanonical(app, table, "01") {
			continue
		}
		tests["restore_invalid_id_"+table] = AppTestCase{
			AsUser: frameworkTestUser,
			Steps:  []AppTestStep{{API: "POST /api/" + table + "/01/restore", Expect: AppTestExpect{Status: http.StatusNotFound}}},
		}
	}
	return AppTestFile{Name: "_framework_restore", Tests: tests}
}
