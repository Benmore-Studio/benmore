//go:build !cli

package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
)

// VersionedConfig holds the list of tables with content versioning enabled.
type VersionedConfig struct {
	Tables []string
}

// LoadVersionedConfig reads the versioned: section from app.yaml.
func LoadVersionedConfig(dir string) *VersionedConfig {
	data, err := os.ReadFile(dir + "/app.yaml")
	if err != nil {
		return nil
	}
	return parseVersionedConfig(data)
}

func parseVersionedConfig(data []byte) *VersionedConfig {
	var raw map[string]any
	if err := decodeConfigYAML(data, &raw); err != nil {
		return nil
	}
	config, _ := parseVersionedSection(raw["versioned"])
	return config
}

// Startup/reload and write validation use the same section parser as on-demand
// consumers, so a malformed replacement cannot silently disable history.
func parseVersionedSection(value any) (*VersionedConfig, error) {
	if value == nil {
		return nil, nil
	}
	items, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("app.yaml: versioned must be a list of table names")
	}
	if len(items) == 0 {
		return nil, nil
	}
	config := &VersionedConfig{Tables: make([]string, 0, len(items))}
	seen := make(map[string]bool, len(items))
	for i, item := range items {
		table, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("app.yaml: versioned[%d] must be a table name", i)
		}
		if err := configIdentError(fmt.Sprintf("app.yaml: versioned[%d]", i), table); err != nil {
			return nil, err
		}
		identity := sqliteIdentifierFold(table)
		if seen[identity] {
			return nil, fmt.Errorf("app.yaml: versioned repeats table %q", table)
		}
		seen[identity] = true
		config.Tables = append(config.Tables, table)
	}
	return config, nil
}

// RegisterVersioningAPI sets up version history and revert endpoints.
func RegisterVersioningAPI(mux appRouteRegistrar, app *App, config *VersionedConfig) {
	if config == nil {
		return
	}

	for _, table := range config.Tables {
		t := table
		// The name becomes a route pattern; InstallVersioningTriggers logged it.
		if !membershipIdentRe.MatchString(t) {
			continue
		}

		// GET /api/{table}/{id}/versions - list all versions
		mux.HandleFunc(fmt.Sprintf("GET /api/%s/{id}/versions", t), func(w http.ResponseWriter, r *http.Request) {
			handleListVersions(w, r, app, t)
		})

		// GET /api/{table}/{id}/versions/{version} - get a specific version
		mux.HandleFunc(fmt.Sprintf("GET /api/%s/{id}/versions/{version}", t), func(w http.ResponseWriter, r *http.Request) {
			handleGetVersion(w, r, app, t)
		})

		// POST /api/{table}/{id}/revert/{version} - revert to a specific version
		mux.HandleFunc(fmt.Sprintf("POST /api/%s/{id}/revert/{version}", t), func(w http.ResponseWriter, r *http.Request) {
			handleRevert(w, r, app, t)
		})

		log.Printf("  versioning: %s (history + revert API)", t)
	}
}

func handleListVersions(w http.ResponseWriter, r *http.Request, app *App, table string) {
	session := getSession(app, r)
	if session == nil {
		httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return
	}
	if !EnforceCRUDAccess(w, r, app, table, OpRead, 0) {
		return
	}

	id := r.PathValue("id")

	if err := checkScope(session, table, "read"); err != nil {
		httpJSON(w, http.StatusForbidden, map[string]any{"error": err.Error()})
		return
	}

	// Verify the user can access this row (same scoping as handleRead)
	if !canAccessRow(app, table, id, session) {
		httpJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}

	scope, scopeArgs := versionSnapshotScope(app, table, session)
	rows, err := queryNativeRowsWith(app.DB, app, table,
		fmt.Sprintf("SELECT _version, _valid_from, _valid_to, _changed_by, _change_type FROM %s WHERE id = ?%s ORDER BY _version DESC", historyFrom(table), scope),
		append([]any{id}, scopeArgs...)...,
	)
	if err != nil {
		serverErrorJSON(w, r, app, table+" versions", err, "version query failed")
		return
	}
	// The listing reveals who changed the row and when; audited tables
	// record it.
	if IsReadAudited(app, table) {
		LogReadAccess(app, table, id, "versions", session)
	}

	httpJSON(w, http.StatusOK, map[string]any{
		"id":       id,
		"versions": rows,
	})
}

func handleGetVersion(w http.ResponseWriter, r *http.Request, app *App, table string) {
	session := getSession(app, r)
	if session == nil {
		httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return
	}
	if !EnforceCRUDAccess(w, r, app, table, OpRead, 0) {
		return
	}

	id := r.PathValue("id")

	if err := checkScope(session, table, "read"); err != nil {
		httpJSON(w, http.StatusForbidden, map[string]any{"error": err.Error()})
		return
	}

	if !canAccessRow(app, table, id, session) {
		httpJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}

	version := r.PathValue("version")
	historyTable := table + "_history"

	// Use history table's actual columns - source table may have columns added after history was created
	historyCols, _ := GetTableColumns(app.DB, historyTable)
	var colNames []string
	for _, col := range historyCols {
		colNames = append(colNames, quoteColumn(table, col.Name)) // historyFrom aliases the history table as table
	}
	if len(colNames) == 0 {
		httpJSON(w, http.StatusNotFound, map[string]any{"error": "version not found"})
		return
	}

	scope, scopeArgs := versionSnapshotScope(app, table, session)
	rows, err := queryNativeRowsWith(app.DB, app, table,
		fmt.Sprintf("SELECT %s FROM %s WHERE id = ? AND _version = ?%s", strings.Join(colNames, ", "), historyFrom(table), scope),
		append([]any{id, version}, scopeArgs...)...,
	)
	if err != nil || len(rows) == 0 {
		httpJSON(w, http.StatusNotFound, map[string]any{"error": "version not found"})
		return
	}

	// Mask encrypted columns with the caller's role, same as the live read
	// path (crud_read.go handleRead). The history row mirrors the source table's
	// columns and QueryRows decrypts the ciphertext-at-rest, so without this a
	// caller who can read the row but is NOT in the column's unmask_roles would
	// recover the plaintext through version history. The history table shares
	// the source table's encrypted-field config (same column names).
	sanitizeResponseRows(app, table, rows, session)
	// A version snapshot is the row's past content: an audited table
	// records the read like a live GET.
	if IsReadAudited(app, table) {
		LogReadAccess(app, table, id, "version", session)
	}
	httpJSON(w, http.StatusOK, rows[0])
}

func handleRevert(w http.ResponseWriter, r *http.Request, app *App, table string) {
	session := getSession(app, r)
	if session == nil {
		httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return
	}

	if !isBearerAuth(r) && !validateCSRF(r) {
		httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid CSRF token"})
		return
	}

	id := r.PathValue("id")

	if err := checkScope(session, table, "write"); err != nil {
		httpJSON(w, http.StatusForbidden, map[string]any{"error": err.Error()})
		return
	}

	if !canAccessRow(app, table, id, session) {
		httpJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}
	version := r.PathValue("version")

	// Get the source table columns (what to restore)
	cols, _ := GetTableColumns(app.DB, table)
	var colNames []string
	for _, col := range cols {
		if col.PK {
			continue // don't overwrite id
		}
		colNames = append(colNames, quoteColumn(table, col.Name)) // historyFrom aliases the history table as table
	}

	// Fetch the historical version
	// A snapshot the caller could not have read (pre-transfer owner or
	// tenant) is "not found": reverting to it would copy that content into
	// the row the caller now reads.
	selectCols := strings.Join(colNames, ", ")
	scope, scopeArgs := versionSnapshotScope(app, table, session)
	rows, err := queryNativeRowsWith(app.DB, app, table,
		fmt.Sprintf("SELECT %s FROM %s WHERE id = ? AND _version = ?%s", selectCols, historyFrom(table), scope),
		append([]any{id, version}, scopeArgs...)...,
	)
	if err != nil || len(rows) == 0 {
		httpJSON(w, http.StatusNotFound, map[string]any{"error": "version not found"})
		return
	}

	versionRow := rows[0]
	// A revert restores every column except command-owned ones, which only
	// their command may change; they keep their current value.
	skippedOwned := stripOwnedFields(app, table, versionRow)

	// Reverts are updates, including write policy, edit ACLs, locks, validators,
	// protected columns, membership, before/after hooks, audit and broadcasts.
	// Reuse the transaction pipeline rather than issuing a privileged raw UPDATE.
	result := newFlowResponseBuffer()
	executeCRUDTransaction(result, r, app, []transactionOp{{
		Table: table, Action: "update", ID: id, Data: versionRow,
	}})
	if result.status != http.StatusOK {
		result.flushTo(w)
		return
	}
	LogAudit(app, "revert", table, id, session,
		map[string]any{"_reverted_to_version": version}, nil)
	appendHXTrigger(w, "benmore:changed")

	httpJSON(w, http.StatusOK, map[string]any{
		"status":              "reverted",
		"id":                  id,
		"reverted_to_version": version,
		"owned_fields_kept":   skippedOwned,
	})
}

// historyFrom names a table's history table ALIASED AS the source table, so
// a rowScopeClause predicate written for the source (unqualified columns, and
// member-of's `<table>.<col>` correlation) evaluates against each snapshot.
func historyFrom(table string) string {
	return quoteIdent(table+"_history") + " AS " + quoteIdent(table)
}

// versionSnapshotScope restricts history rows to snapshots the caller could
// have read: the canonical row scope (owner, tenant, membership, ACL grant)
// evaluated on the SNAPSHOT's own columns. Version history follows the row
// id, so without this a row moved to a new owner or tenant handed its whole
// pre-transfer history to the new owner. Returns an " AND ..." suffix, empty
// for an admin who bypasses row scope (and for tables with no scope
// columns, where the current-row gate already decided). A history table that
// lacks a scope column fails the query - closed, not open.
func versionSnapshotScope(app *App, table string, session *Session) (string, []any) {
	pred, args, bypass := rowScopeClause(app, table, session, "view")
	if bypass || pred == "" {
		return "", nil
	}
	return " AND " + pred, args
}

// hasColumnInList checks if a column name exists in a slice of Column structs.
func hasColumnInList(cols []Column, name string) bool {
	for _, c := range cols {
		if c.Name == name {
			return true
		}
	}
	return false
}

// canAccessRow checks if the session user can READ a specific row. Delegates
// to the canonical rowScopeClause (access.go) so versioning, signed-URL
// authorization, locks, etc. all share ONE policy - act-as aware
// (IsAdminBypass + effective group + ACL). Pre-consolidation this was a
// hand-rolled copy using IsAdmin() + native group, which let a stepped-in
// admin bypass scoping and scoped to the wrong tenant under act-as.
func canAccessRow(app *App, table string, id string, session *Session) bool {
	if session == nil {
		return false
	}
	// Access-MODE gate first (off/admin/role:/perm:). canAccessRowScoped only
	// does per-ROW scoping, which is empty for a table with no user_id/group
	// key - so without this an admin-only or role-gated UNSCOPED table leaked
	// through every canAccessRow caller that isn't already mode-gated:
	// /versions, /versions/{v}, /revert, record locks, and the ?as_of=
	// point-in-time read. The two callers that DO pre-gate (the main CRUD read
	// path via EnforceCRUDAccess, and signed-URL authorization) already
	// satisfy the mode, so this is a no-op for them.
	if !SessionCanAccessTable(app, table, OpRead, session) {
		return false
	}
	return canAccessRowScoped(app, table, id, session, "view")
}

// handlePointInTime returns the state of a row at a specific point in time.
// GET /api/{table}/{id}?as_of=2026-03-01T00:00:00Z
// Searches the version history for the version that was active at that timestamp.
func handlePointInTime(app *App, r *http.Request, table string, id string, asOf string, session *Session) (map[string]any, error) {
	var err error
	asOf, err = normalizePointInTime(asOf)
	if err != nil {
		return nil, err
	}
	historyTable := table + "_history"

	// A missing history table retains the native current-row fallback. Other
	// private query failures must not turn into a successful fallback read.
	tables, err := appMCPReadRows(app, r, "", "SELECT name FROM sqlite_master WHERE type IN ('table','view') AND name=? COLLATE NOCASE", historyTable)
	if err != nil {
		return nil, err
	}
	historyPresent := len(tables) > 0
	var rows []map[string]any
	if historyPresent {
		// Find the version that was valid at the given time
		rows, err = appMCPReadRows(app, r, table,
			"SELECT _version FROM "+quoteIdent(historyTable)+" WHERE id = ? AND _valid_from <= ? AND _valid_to > ? ORDER BY _version DESC LIMIT 1",
			id, asOf, asOf,
		)
	}
	if err != nil {
		return nil, err
	}
	if err == nil && len(rows) == 1 {
		// The state at as_of is a snapshot; it is returned only when the
		// caller could have read it then (same owner/tenant scope). Not
		// found otherwise - never the current row in its place.
		scope, scopeArgs := versionSnapshotScope(app, table, session)
		visible, verr := appMCPReadRows(app, r, table,
			fmt.Sprintf("SELECT * FROM %s WHERE id = ? AND _version = ? AND _valid_from <= ? AND _valid_to > ?%s", historyFrom(table), scope),
			append([]any{id, rows[0]["_version"], asOf, asOf}, scopeArgs...)...)
		if verr != nil || len(visible) == 0 {
			return nil, fmt.Errorf("no version found at %s", asOf)
		}
		rows = visible
	}
	if len(rows) == 0 {
		// If no history entry, maybe the current row was created before as_of and never updated
		scope, scopeArgs := versionSnapshotScope(app, table, session)
		if hasColumn(app, table, "deleted_at") {
			scope += " AND deleted_at IS NULL"
		}
		// Missing/pruned/inverted history is not evidence that today's value
		// existed earlier. Require the current state's latest known boundary.
		// Capture payload and raw boundaries in one SQLite snapshot. The driver
		// decodes malformed DATETIME values as zero time, so validation needs
		// raw text without changing the normal response representation.
		updated := "NULL"
		if hasColumn(app, table, "updated_at") {
			updated = "CAST(updated_at AS TEXT)"
		}
		expressions := []string{"CAST(created_at AS TEXT)", updated}
		if historyPresent {
			for _, column := range []string{"_valid_from", "_valid_to"} {
				expressions = append(expressions, "(SELECT CAST("+column+" AS TEXT) FROM "+quoteIdent(historyTable)+" WHERE id="+quoteIdent(table)+".id ORDER BY _version DESC LIMIT 1)")
			}
		}
		projection := "*"
		aliases := make([]string, len(expressions))
		for i, expression := range expressions {
			alias := fmt.Sprintf("_benmore_asof_boundary_%d", i)
			for hasColumn(app, table, alias) {
				alias += "_"
			}
			aliases[i] = alias
			projection += ", " + expression + " AS " + quoteIdent(alias)
		}
		currentRows, err := appMCPReadRows(app, r, table,
			fmt.Sprintf("SELECT %s FROM %s WHERE id = ? AND created_at <= ?%s", projection, quoteIdent(table), scope),
			append([]any{id, asOf}, scopeArgs...)...)
		if err != nil || len(currentRows) == 0 {
			return nil, fmt.Errorf("no version found at %s", asOf)
		}
		boundaries := make([]any, len(aliases))
		for i, alias := range aliases {
			boundaries[i] = currentRows[0][alias]
			delete(currentRows[0], alias)
		}
		for _, boundary := range boundaries {
			if versionedValueIsNull(boundary) {
				continue
			}
			if _, valid := parseUpdateTimestamp(stringifyForCrypto(boundary)); !valid {
				return nil, fmt.Errorf("no version found at %s", asOf)
			}
		}
		start, known := versionLatestInstant(boundaries...)
		instant, valid := parseUpdateTimestamp(asOf)
		if !known || !valid || instant.Before(start) {
			return nil, fmt.Errorf("no version found at %s", asOf)
		}
		return currentRows[0], nil
	}
	return rows[0], nil
}

var errInvalidPointInTime = errors.New("invalid as_of timestamp: use RFC3339 or a SQLite date/time")

// normalizePointInTime matches SQLite's UTC timestamp text used by the
// versioning triggers. Comparing RFC3339 directly puts 'T' after the stored
// space separator and can select today's row in place of a historical one.
// Keep fractions: truncating or rounding a query could cross a version boundary.
func normalizePointInTime(value string) (string, error) {
	instant, ok := crossFieldInstant(value)
	if !ok {
		return "", errInvalidPointInTime
	}
	return instant.UTC().Format("2006-01-02 15:04:05.999999999"), nil
}
