//go:build !cli

package main

// Write-time advice for the named-join refusals of sql_named_join.go that
// only show when the SQL runs: a page query that joins a protected table by
// column name answers 500 on every render, and a hook whose SQL or `when:`
// joins a connector store or a schema table that way makes every approved
// connector command on its table fail. Both files still load, so the write
// gate and `benmore check` warn. The predicates are the run-time ones, asked
// of the app's source instead of its loaded form; a join inside a view is
// seen only at run time (the view's text is in the database).

import (
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"
)

// namedJoinWarnings checks hooks.yaml and the pages: all of them on a full
// check, the written file after a write.
func namedJoinWarnings(dir, writtenPath string) []CheckFinding {
	if dir == "" {
		return nil
	}
	written := ""
	if writtenPath != "" {
		written = appRelativeFile(dir, writtenPath)
	}
	var findings []CheckFinding
	warn := func(file, problem string) {
		findings = append(findings, CheckFinding{Severity: "warning", Source: "named_join", File: file, Message: file + ": " + problem})
	}
	if written == "" || strings.EqualFold(written, "hooks.yaml") {
		var hooks HooksYAML
		if data := readAppFileOrNil(dir, "hooks.yaml"); data != nil && decodeConfigYAML(data, &hooks) == nil {
			for _, problem := range hookNamedJoinProblems(hooks) {
				warn("hooks.yaml", problem)
			}
		}
	}
	var pages []fileCheck
	switch {
	case written == "":
		pages = walkAppFiles(dir)
	case namedJoinPageFile(written):
		if data, err := readFileInRoot(dir, written); err == nil {
			pages = []fileCheck{{relPath: written, content: string(data)}}
		}
	}
	var app *App
	for _, page := range pages {
		if !namedJoinPageFile(page.relPath) {
			continue
		}
		for _, query := range pageAuthoredSQL(page.content) {
			if app == nil {
				app = namedJoinSourceApp(dir)
			}
			if name := sqlNamedJoinTouches(query, func(name string) bool { return pageQueryReadMatters(app, name) }); name != "" {
				warn(filepath.ToSlash(page.relPath), fmt.Sprintf("a query joins by column name (USING or NATURAL) and names %s, a framework table or a table with encrypted fields, hidden columns or read auditing. The page refuses that query each time it renders and answers 500: write the join with ON.", name))
			}
		}
	}
	return findings
}

// namedJoinPageFile reports a server-rendered page: an .html file outside
// static/, emails/ and templates/.
func namedJoinPageFile(rel string) bool {
	rel = filepath.ToSlash(rel)
	if !strings.HasSuffix(strings.ToLower(rel), ".html") {
		return false
	}
	for _, dir := range []string{"static/", "emails/", "templates/"} {
		if strings.HasPrefix(rel, dir) || strings.Contains(rel, "/"+dir) {
			return false
		}
	}
	return true
}

// pageAuthoredSQL is the SQL a page file runs: its frontmatter `queries:` and
// the sql= of its <query> tags (the from= shorthand joins nothing).
func pageAuthoredSQL(content string) []string {
	var out []string
	if fm, body, err := ExtractFrontmatter(content); err == nil && fm != nil {
		for _, name := range slices.Sorted(maps.Keys(fm.Queries)) {
			out = append(out, fm.Queries[name])
		}
		content = body
	}
	for _, tag := range ExtractQueries(content) {
		if tag.SQL != "" {
			out = append(out, tag.SQL)
		}
	}
	return out
}

// namedJoinSourceApp is what pageQueryReadMatters reads of an app, taken from
// its source: the encrypted fields, the schema's tables and columns, read
// auditing and `compliance: hipaa`.
func namedJoinSourceApp(dir string) *App {
	appYAML := readAppFileOrNil(dir, "app.yaml")
	app := &App{
		Encrypted: parseEncryptedFieldsConfig(readAppFileOrNil(dir, "encrypted.yaml"), appYAML),
		Design:    &DesignConfig{Auth: map[string]string{}},
	}
	var doc struct {
		Auth map[string]any `yaml:"auth"`
	}
	if decodeConfigYAML(appYAML, &doc) == nil {
		if value, ok := doc.Auth["read_audit"]; ok {
			app.Design.Auth["read_audit"] = fmt.Sprint(value)
		}
	}
	if hipaa, err := appYAMLDeclaresHIPAA(appYAML); err == nil && hipaa {
		app.Design.Compliance = complianceHIPAA
	}
	if data := readAppFileOrNil(dir, "schema.prisma"); data != nil {
		if models, err := ParsePrismaSchema(string(data)); err == nil {
			for _, model := range models {
				table := Table{Name: model.Table}
				for _, field := range model.Fields {
					table.Columns = append(table.Columns, Column{Name: field.Column, Type: field.Type})
				}
				app.Tables = append(app.Tables, table)
			}
		}
	}
	return app
}

// hookNamedJoinProblems lists the hooks whose `sql:` or `when:` joins a
// connector store or a schema table by column name (commandHookDeniedRead).
func hookNamedJoinProblems(file HooksYAML) []string {
	sections := []struct {
		name  string
		hooks map[string][]HookEntryYAML
	}{
		{"before_insert", file.BeforeInsert}, {"before_update", file.BeforeUpdate}, {"before_delete", file.BeforeDelete},
		{"on_insert", file.OnInsert}, {"on_update", file.OnUpdate}, {"on_delete", file.OnDelete},
	}
	var problems []string
	for _, section := range sections {
		for _, table := range slices.Sorted(maps.Keys(section.hooks)) {
			for i, entry := range section.hooks[table] {
				for _, text := range []string{entry.SQL, entry.When} {
					if name := sqlNamedJoinTouches(text, commandHookDeniedRead); name != "" {
						problems = append(problems, fmt.Sprintf("%s.%s[%d]: the SQL joins by column name (USING or NATURAL) and names %s, a connector store (_benmore_mcp_*) or a schema table (sqlite_*). The hook runs for ordinary writes, but an approved connector command that writes %s refuses it and fails: write the join with ON.", section.name, table, i, name, table))
						break
					}
				}
			}
		}
	}
	return problems
}
