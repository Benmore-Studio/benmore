//go:build !cli

package main

// `admin` on a gate that has no tenant to bound it is the app's global admin:
// a flow's on.request.role (flowRoleAllowed), a page's role= (pageRoleAllowed),
// a `{{#role}}` section (roleSectionOpen) and a workflow transition on a table
// without the tenant key (workflowMembershipRoleAllowed). In an app whose
// tenant members can hold a role named admin, an author who writes
// `role: admin` on one of them probably means the tenant's admin and gets the
// global one. A flow's gate is reported by flowRoleGateWarnings; this file
// reports the other three, from the post-write check and `benmore check`.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// roleSectionTagRe finds a `{{#role "a,b"}}` opening tag the way the template
// engine reads it; group 1 is the quoted role list.
var roleSectionTagRe = regexp.MustCompile(`\{\{\s*#\s*role (["'][^}]*)\}\}`)

// roleListNamesAdmin reports whether a comma-separated role list names
// `admin`, in any letter case.
func roleListNamesAdmin(list string) bool {
	for _, name := range splitCommaList(list) {
		if strings.EqualFold(name, "admin") {
			return true
		}
	}
	return false
}

// roleAdminGateWarnings reports, for the file just written or on a full check
// for every file, each workflow transition, page role gate and role section
// that names `admin` where the app's tenant admins do not pass it. A write of
// app.yaml or schema.prisma (which decide whether a tenant member can hold a
// role named admin, and which tables carry the tenant key) reports them all.
func roleAdminGateWarnings(dir, writtenPath string) []CheckFinding {
	written := cleanWritePath(writtenPath)
	all := written == "" || written == "app.yaml" || written == "schema.prisma"
	var templates []string
	switch {
	case all:
		for _, pattern := range []string{"*.html", "partials/*.html", "layouts/*.html"} {
			matches, _ := filepath.Glob(filepath.Join(dir, filepath.FromSlash(pattern)))
			for _, m := range matches {
				if rel, err := filepath.Rel(dir, m); err == nil {
					templates = append(templates, filepath.ToSlash(rel))
				}
			}
		}
		sort.Strings(templates)
	case strings.HasSuffix(strings.ToLower(written), ".html"):
		if parent := filepath.ToSlash(filepath.Dir(written)); parent == "." || parent == "partials" || parent == "layouts" {
			templates = []string{written}
		}
	}

	// The context costs a parse of app.yaml and the schema: read it only once
	// a file names admin on such a gate.
	var c *flowRoleGateContext
	tenantAdmin := func() string {
		if c == nil {
			c = flowRoleGateContextFor(dir)
		}
		return c.tenantAdmin
	}
	const globalAdmin = "a global admin (the account's own role is admin, or it holds an admin grant for no tenant)"
	var findings []CheckFinding

	if all || written == "workflows.yaml" {
		findings = append(findings, workflowAdminRoleWarnings(dir, tenantAdmin, globalAdmin)...)
	}
	for _, rel := range templates {
		data, err := readFileInRoot(dir, rel)
		if err != nil {
			continue
		}
		content := string(data)
		warn := func(docs, message string) {
			findings = append(findings, CheckFinding{Severity: "warning", Source: "security", File: rel, Message: rel + ": " + message, Docs: docs})
		}
		if filepath.Dir(rel) == "." {
			page := &Page{}
			setPageAttrsFromSource(page, content)
			if roleListNamesAdmin(page.Role) && tenantAdmin() != "" {
				warn("frontend.ssr_page_gates", fmt.Sprintf("the page gate role=%q names `admin`, which only %s passes. A tenant member of this app can hold a role named admin (%s), and a tenant admin does NOT pass a page's role gate: a page counts only roles held for the whole app. For a page the tenant's own admins open, require sign-in on it (`auth=\"required\"`) and decide what it shows from `user.app_role`, the viewer's role in their current tenant. If only the app's global admin should open it, leave it as it is. See api({at:'frontend'}) → ssr_page_gates.",
					page.Role, globalAdmin, tenantAdmin()))
			}
		}
		seen := map[string]bool{}
		for _, m := range roleSectionTagRe.FindAllStringSubmatch(content, -1) {
			list := strings.Trim(m[1], `"' `)
			if seen[list] || !roleListNamesAdmin(list) || tenantAdmin() == "" {
				continue
			}
			seen[list] = true
			warn("ssr.mustache", fmt.Sprintf("{{#role %q}} names `admin`, which opens for %s only. A tenant member of this app can hold a role named admin (%s), and a tenant admin does NOT pass it. For content the tenant's own admins see, write `{{#if user.app_role = \"admin\"}}…{{/if}}`: user.app_role is the viewer's role in their current tenant. If only the app's global admin should see it, leave it as it is. See api({at:'ssr'}) → mustache.",
				list, globalAdmin, tenantAdmin()))
		}
	}
	return findings
}

// workflowAdminRoleWarnings reports each transition of workflows.yaml whose
// `role:` names admin on a table the schema declares without the tenant key
// and the app does not list in groups.shared. A table the schema does not
// declare is left alone: its columns are unknown here.
func workflowAdminRoleWarnings(dir string, tenantAdmin func() string, globalAdmin string) []CheckFinding {
	data, err := os.ReadFile(filepath.Join(dir, "workflows.yaml"))
	if err != nil {
		return nil
	}
	cfg, err := parseWorkflowsYAML(data)
	if err != nil || cfg == nil {
		return nil // the write gate reports the parse error
	}
	type use struct{ where, table string }
	var uses []use
	for _, name := range sortedWhenKeys(cfg.Workflows) {
		wf := cfg.Workflows[name]
		for _, from := range sortedWhenKeys(wf.Transitions) {
			for _, to := range sortedWhenKeys(wf.Transitions[from]) {
				if roleListNamesAdmin(wf.Transitions[from][to].Role) {
					uses = append(uses, use{fmt.Sprintf("%s.transitions.%s -> %s", name, from, to), wf.Table})
				}
			}
		}
	}
	if len(uses) == 0 || tenantAdmin() == "" {
		return nil
	}
	appYAML, _ := os.ReadFile(filepath.Join(dir, "app.yaml"))
	group := parseGroupConfig(appYAML)
	if group == nil || group.Key == "" {
		return nil
	}
	schema, _ := os.ReadFile(filepath.Join(dir, "schema.prisma"))
	models, _ := ParsePrismaSchema(string(schema))
	// unbounded: the schema declares table and gives it no tenant key column.
	unbounded := func(table string) bool {
		for _, shared := range group.Shared {
			if sqliteIdentifierFold(shared) == sqliteIdentifierFold(table) {
				return false
			}
		}
		for _, m := range models {
			if sqliteIdentifierFold(m.Table) != sqliteIdentifierFold(table) {
				continue
			}
			for _, f := range m.Fields {
				if sqliteIdentifierFold(f.Column) == sqliteIdentifierFold(group.Key) {
					return false
				}
			}
			return true
		}
		return false
	}
	var findings []CheckFinding
	for _, u := range uses {
		if !unbounded(u.table) {
			continue
		}
		findings = append(findings, CheckFinding{
			Severity: "warning",
			Source:   "workflows",
			File:     "workflows.yaml",
			Docs:     "workflows.transition_roles",
			Message: fmt.Sprintf("workflows.yaml %s: role names `admin` on %s, a table without the tenant key %s, where only %s passes it. A tenant member of this app can hold a role named admin (%s), and a tenant admin does NOT pass this transition: the table has no tenant column to keep one tenant's admin to its own rows. If the tenant's own admins should make it, add the %s column to %s, list %s under groups.shared, or give the tenant role a name of its own (org_admin) and name that. If only the app's global admin should, leave it as it is. See api({at:'workflows'}) → transition_roles.",
				u.where, u.table, group.Key, globalAdmin, tenantAdmin(), group.Key, u.table, u.table),
		})
	}
	return findings
}
