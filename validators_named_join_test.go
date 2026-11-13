//go:build !cli

package main

import (
	"strings"
	"testing"
)

// A page query or a hook that joins a protected table by column name loads
// and is refused only when it runs, so the write gate and `benmore check`
// say so when the file is written.
func TestNamedJoinWarningsForPagesAndHooks(t *testing.T) {
	dir := writeApp(t, map[string]string{
		"app.yaml":       "auth:\n  read_audit: visits\n",
		"schema.prisma":  "model Patient {\n  id Int @id @default(autoincrement())\n  name String\n  ssn String?\n  @@map(\"patients\")\n}\nmodel Visit {\n  id Int @id @default(autoincrement())\n  patient_id Int\n  @@map(\"visits\")\n}\nmodel Vendor {\n  id Int @id @default(autoincrement())\n  api_key String?\n  @@map(\"vendors\")\n}\nmodel Region {\n  id Int @id @default(autoincrement())\n  label String\n  @@map(\"regions\")\n}\nmodel RegionNote {\n  id Int @id @default(autoincrement())\n  note String\n  @@map(\"region_notes\")\n}\n",
		"encrypted.yaml": "tables:\n  patients:\n    fields: [ssn]\n",
		"hooks.yaml": `on_update:
  visits:
    - sql: UPDATE visits SET patient_id = patient_id WHERE id = {{id}} AND EXISTS (SELECT 1 FROM (SELECT 'x' AS token_hash) g NATURAL JOIN _benmore_mcp_credentials)
    - sql: UPDATE visits SET patient_id = patient_id WHERE id = {{id}} AND EXISTS (SELECT 1 FROM visits a JOIN visits b USING (id))
before_insert:
  regions:
    - sql: SELECT 1
      when: EXISTS (SELECT 1 FROM (SELECT 'x' AS name) g JOIN sqlite_master USING (name))
`,
		"encrypted.html": "---\nengine: gotmpl\nqueries:\n  rows: \"SELECT g.n FROM (SELECT 1 AS id, 2 AS n) g JOIN patients USING (id)\"\n---\n<p>{{ len .rows }}</p>",
		"audited.html":   "<page title=\"Visits\">\n<query sql=\"SELECT v.id FROM visits v NATURAL JOIN regions\" as=\"rows\">{{#rows}}{{id}}{{/rows}}</query>\n</page>",
		"hidden.html":    "---\nengine: gotmpl\nqueries:\n  rows: \"SELECT label FROM regions JOIN vendors USING (id)\"\n---\n<p>{{ len .rows }}</p>",
		"framework.html": "---\nengine: gotmpl\nqueries:\n  rows: \"SELECT g.id FROM (SELECT 1 AS id) g JOIN _benmore_users USING (id)\"\n---\n<p>{{ len .rows }}</p>",
		"plain.html":     "---\nengine: gotmpl\nqueries:\n  rows: \"SELECT r.label FROM regions r JOIN region_notes USING (id)\"\n  on: \"SELECT p.name FROM patients p JOIN visits v ON v.patient_id = p.id\"\n---\n<p>{{ len .rows }}</p>",
		// A static page is served as written: its text is no query.
		"static/docs.html": "<p>SELECT 1 FROM patients JOIN visits USING (id)</p><query sql=\"SELECT 1 FROM patients NATURAL JOIN visits\" as=\"x\"></query>",
	})
	byFile := func(findings []CheckFinding) map[string][]string {
		out := map[string][]string{}
		for _, f := range findings {
			if f.Severity != "warning" || f.Source != "named_join" || !strings.HasPrefix(f.Message, f.File+": ") {
				t.Errorf("finding = %+v", f)
			}
			if !strings.Contains(f.Message, "write the join with ON") {
				t.Errorf("%s: the warning does not say what to write: %s", f.File, f.Message)
			}
			out[f.File] = append(out[f.File], f.Message)
		}
		return out
	}
	all := byFile(namedJoinWarnings(dir, ""))
	for file, want := range map[string]string{
		"encrypted.html": "names patients",
		"audited.html":   "names visits",
		"hidden.html":    "names vendors",
		"framework.html": "names _benmore_users",
	} {
		if len(all[file]) != 1 || !strings.Contains(all[file][0], want) || !strings.Contains(all[file][0], "answers 500") {
			t.Errorf("%s: warnings = %q, want one that %s", file, all[file], want)
		}
	}
	for _, file := range []string{"plain.html", "static/docs.html"} {
		if len(all[file]) != 0 {
			t.Errorf("%s: warned: %q", file, all[file])
		}
	}
	hooks := all["hooks.yaml"]
	if len(hooks) != 2 || !strings.Contains(hooks[0], "before_insert.regions[0]") || !strings.Contains(hooks[0], "sqlite_master") ||
		!strings.Contains(hooks[1], "on_update.visits[0]") || !strings.Contains(hooks[1], "_benmore_mcp_credentials") || !strings.Contains(hooks[1], "approved connector command that writes visits") {
		t.Errorf("hooks.yaml: warnings = %q", hooks)
	}
	if len(all) != 5 {
		t.Errorf("files warned about: %v", all)
	}
	// After a write only the written file is read.
	if got := byFile(namedJoinWarnings(dir, "hidden.html")); len(got) != 1 || len(got["hidden.html"]) != 1 {
		t.Errorf("after writing hidden.html: %v", got)
	}
	if got := byFile(namedJoinWarnings(dir, "hooks.yaml")); len(got) != 1 || len(got["hooks.yaml"]) != 2 {
		t.Errorf("after writing hooks.yaml: %v", got)
	}
	if got := namedJoinWarnings(dir, "flows.yaml"); len(got) != 0 {
		t.Errorf("after writing flows.yaml: %v", got)
	}
	// The check reports them as warnings with the key that states the rule,
	// and none of them refuses the file.
	report := RunSourceCheck(dir, "")
	seen := map[string]string{}
	for _, f := range report.Findings {
		if f.Source == "named_join" {
			seen[f.File] = f.Docs
		}
	}
	if seen["hidden.html"] != "encryption.authored_page_queries" || seen["hooks.yaml"] != "connector.connector_hooks_effects" {
		t.Errorf("check findings and their docs = %v", seen)
	}
	for _, file := range []string{"hooks.yaml", "hidden.html", "audited.html"} {
		content := string(readAppFileOrNil(dir, file))
		if msg := ValidateOnWriteIn(dir, file, content); msg != "" {
			t.Errorf("%s: the write gate refuses the file: %s", file, msg)
		}
	}
}
