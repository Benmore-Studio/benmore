//go:build !cli

package main

// Write-time and load-time checks for hook and workflow `when:` conditions.
//
// The write gate (ValidateOnWriteIn, which `benmore check` runs over every
// file) prepares each condition against the app's schema: an in-memory
// database built from schema.prisma (or schema.sql) plus the framework's
// users table, with the same one-row CTE the runtime evaluates against
// (hook_when.go). The loader never refuses a file over a condition; it
// logs a warning (warnWhenConditions).

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// whenSite is one `when:` in a file, with the table its row comes from.
type whenSite struct {
	label string // on_update.orders[0], orders.transitions.pending -> approved
	table string
	when  string
}

// hookWhenSites lists the conditions in a hooks.yaml.
func hookWhenSites(content string) []whenSite {
	var raw HooksYAML
	if err := decodeConfigYAML([]byte(content), &raw); err != nil {
		return nil
	}
	var sites []whenSite
	for _, sec := range []struct {
		name    string
		entries map[string][]HookEntryYAML
	}{
		{"on_insert", raw.OnInsert}, {"on_update", raw.OnUpdate}, {"on_delete", raw.OnDelete},
		{"before_insert", raw.BeforeInsert}, {"before_update", raw.BeforeUpdate}, {"before_delete", raw.BeforeDelete},
	} {
		for _, table := range sortedWhenKeys(sec.entries) {
			for i, e := range sec.entries[table] {
				if strings.TrimSpace(e.When) != "" {
					sites = append(sites, whenSite{fmt.Sprintf("%s.%s[%d]", sec.name, table, i), table, e.When})
				}
			}
		}
	}
	return sites
}

// workflowWhenSites lists the transition and on_transition conditions in a
// workflows.yaml.
func workflowWhenSites(content string) []whenSite {
	var raw map[string]WorkflowYAML
	if err := decodeConfigYAML([]byte(content), &raw); err != nil {
		return nil
	}
	var sites []whenSite
	for _, name := range sortedWhenKeys(raw) {
		wf := raw[name]
		for _, from := range sortedWhenKeys(wf.Transitions) {
			for _, to := range sortedWhenKeys(wf.Transitions[from]) {
				if w := wf.Transitions[from][to].When; strings.TrimSpace(w) != "" {
					sites = append(sites, whenSite{fmt.Sprintf("%s.transitions.%s -> %s", name, from, to), wf.Table, w})
				}
			}
		}
		for _, state := range sortedWhenKeys(wf.OnTransition) {
			for i, e := range wf.OnTransition[state] {
				if strings.TrimSpace(e.When) != "" {
					sites = append(sites, whenSite{fmt.Sprintf("%s.on_transition.%s[%d]", name, state, i), wf.Table, e.When})
				}
			}
		}
	}
	return sites
}

func sortedWhenKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// whenSchemaDB builds an in-memory database with the app's declared
// tables, or nil when there is no schema to check against.
func whenSchemaDB(appDir string) *sql.DB {
	if appDir == "" {
		return nil
	}
	var ddl string
	if data, err := os.ReadFile(filepath.Join(appDir, "schema.prisma")); err == nil {
		models, err := ParsePrismaSchema(string(data))
		if err != nil {
			return nil
		}
		ddl = EmitSQL(models)
	} else if data, err := os.ReadFile(filepath.Join(appDir, "schema.sql")); err == nil {
		ddl = string(data)
	} else {
		return nil
	}
	db, err := sql.Open(sqliteMaintenanceDriver, ":memory:")
	if err != nil {
		return nil
	}
	// One connection: every pooled :memory: connection is its own database.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(ddl); err != nil {
		db.Close()
		return nil
	}
	if err := EnsureUsersTable(db); err != nil {
		db.Close()
		return nil
	}
	return db
}

// whenCheckErrorIgnored reports errors a schema-only check can't judge: a
// table the when: reads that isn't declared (a migration or framework
// table).
func whenCheckErrorIgnored(err error) bool {
	return strings.Contains(err.Error(), "no such table")
}

// whenSiteProblems checks each site: the text always, and a prepare
// against schemaDB when there is one and it declares the site's table.
func whenSiteProblems(sites []whenSite, schemaDB *sql.DB) []string {
	var problems []string
	for _, s := range sites {
		var err error
		if schemaDB != nil && whenTableDeclared(schemaDB, s.table) {
			err = checkWhenCondition(schemaDB, nil, s.table, s.when)
		} else {
			_, err = prepareWhenCondition(s.when)
		}
		if err != nil && !whenCheckErrorIgnored(err) {
			problems = append(problems, fmt.Sprintf("  - %s: %q: %v", s.label, s.when, err))
		}
	}
	return problems
}

func whenTableDeclared(db *sql.DB, table string) bool {
	cols, err := tableColumnsWith(db, table)
	return err == nil && len(cols) > 0
}

// whenConditionHelp explains what a when: is, for validator messages.
const whenConditionHelp = "`when:` is a SQLite condition over the event row: name columns directly (status; old_status on updates), quote text ('paid'), and use user_id, user_email, user_role, user_roles and user_group_id for the caller. It is not a template: write status = 'paid', not {{status}} = 'paid'. See api({at:'hooks'}) → when_conditions."

// validateWhenConditions is the write-time check for hooks.yaml and
// workflows.yaml (file is the base name). It returns "" when every
// condition is valid.
func validateWhenConditions(appDir, file, content string) string {
	var sites []whenSite
	switch file {
	case "hooks.yaml":
		sites = hookWhenSites(content)
	case "workflows.yaml":
		sites = workflowWhenSites(content)
	}
	if len(sites) == 0 {
		return ""
	}
	db := whenSchemaDB(appDir)
	if db != nil {
		defer db.Close()
	}
	problems := whenSiteProblems(sites, db)
	if len(problems) == 0 {
		return ""
	}
	return fmt.Sprintf("%s: `when:` conditions that can't be evaluated (a before-hook would refuse every write it gates; other hooks and transitions would never match):\n%s\n\n%s",
		file, strings.Join(problems, "\n"), whenConditionHelp)
}

// warnWhenConditions logs, at load, each loaded `when:` that can't be
// evaluated against the live database. It never refuses the app.
func warnWhenConditions(app *App) {
	if app == nil || app.DB == nil {
		return
	}
	check := func(label, table, when string) {
		if err := checkWhenCondition(app.DB, app, table, when); err != nil && !whenCheckErrorIgnored(err) {
			log.Printf("WARNING: %s when: %q can't be evaluated (%v); a before-hook refuses the writes it gates, other hooks and transitions don't match. %s", label, when, err, whenConditionHelp)
		}
	}
	if h := app.Hooks; h != nil {
		for _, sec := range []struct {
			name  string
			hooks map[string][]Hook
		}{
			{"on_insert", h.OnInsert}, {"on_update", h.OnUpdate}, {"on_delete", h.OnDelete},
			{"before_insert", h.BeforeInsert}, {"before_update", h.BeforeUpdate}, {"before_delete", h.BeforeDelete},
		} {
			for _, table := range sortedWhenKeys(sec.hooks) {
				for i, hook := range sec.hooks[table] {
					if hook.When != "" {
						check(fmt.Sprintf("hooks.yaml %s.%s[%d]", sec.name, table, i), table, hook.When)
					}
				}
			}
		}
	}
	if app.Workflows != nil {
		for _, name := range sortedWhenKeys(app.Workflows.Workflows) {
			wf := app.Workflows.Workflows[name]
			for _, from := range sortedWhenKeys(wf.Transitions) {
				for _, to := range sortedWhenKeys(wf.Transitions[from]) {
					if w := wf.Transitions[from][to].When; w != "" {
						check(fmt.Sprintf("workflows.yaml %s.transitions.%s -> %s", name, from, to), wf.Table, w)
					}
				}
			}
			for _, state := range sortedWhenKeys(wf.OnTransition) {
				for i, hook := range wf.OnTransition[state] {
					if hook.When != "" {
						check(fmt.Sprintf("workflows.yaml %s.on_transition.%s[%d]", name, state, i), wf.Table, hook.When)
					}
				}
			}
		}
	}
}
