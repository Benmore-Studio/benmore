//go:build !cli

package main

import (
	"fmt"
	"strings"
	"testing"
)

const workflowDefaultTestYAML = `orders:
  table: orders
  field: status
  initial: draft
  states: [draft, done]
  transitions:
    draft:
      done: {}
`

func workflowDefaultSQLApp(t *testing.T, statusColumn string) (dir, schema string) {
	t.Helper()
	dir = t.TempDir()
	schema = fmt.Sprintf("CREATE TABLE orders (\n  id INTEGER PRIMARY KEY AUTOINCREMENT,\n  title TEXT NOT NULL DEFAULT '',\n  %s,\n  user_id INTEGER,\n  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,\n  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP\n);\n", statusColumn)
	writeTestFile(t, dir, "app.yaml", "site_name: probe\nauth:\n  identifier: email\n")
	writeTestFile(t, dir, "schema.sql", schema)
	return dir, schema
}

// workflowDefaultSurfaces returns what each of the three surfaces says about
// the state column default: the write gate, `benmore check` over the file on
// disk, and the warning logged when the app loads.
func workflowDefaultSurfaces(t *testing.T, dir string, tables []Table) (gate, check, load string) {
	t.Helper()
	gate = ValidateOnWriteIn(dir, "workflows.yaml", workflowDefaultTestYAML)
	writeTestFile(t, dir, "workflows.yaml", workflowDefaultTestYAML)
	for _, f := range RunSourceCheck(dir, "workflows.yaml").Findings {
		if f.File == "workflows.yaml" {
			check += f.Message + "\n"
		}
	}
	cfg, err := parseWorkflowsYAML([]byte(workflowDefaultTestYAML))
	if err != nil {
		t.Fatal(err)
	}
	load = captureLog(t, func() { warnWorkflowShape(&App{Dir: dir, Tables: tables, Workflows: cfg}) })
	return gate, check, load
}

// The state column's default is compared with `initial:` as SQLite reads it,
// whatever its spelling. `DEFAULT "draft"` (SQLite reads a quoted name there
// as the string) was refused with "would start in "draft", not "draft"", and
// `DEFAULT NULL` was refused although a column with no default, which stores
// the same NULL, was accepted.
func TestWorkflowDefaultCheckReadsTheDefaultAsSQLiteDoes(t *testing.T) {
	cases := []struct {
		column  string // the status column declaration
		refused string // "" = accepted, else the state the message must name
	}{
		{`status TEXT DEFAULT 'draft'`, ""},
		{`status TEXT DEFAULT "draft"`, ""},
		{"status TEXT DEFAULT `draft`", ""},
		{`status TEXT DEFAULT [draft]`, ""},
		{`status TEXT DEFAULT draft`, ""},
		{`status TEXT DEFAULT ('draft')`, ""},
		{`status TEXT DEFAULT ( 'draft' )`, ""},
		{`status TEXT DEFAULT (('draft'))`, ""},
		{`status TEXT`, ""},
		{`status TEXT DEFAULT NULL`, ""},
		{`status TEXT DEFAULT null`, ""},
		{`status TEXT DEFAULT (NULL)`, ""},
		{`status TEXT DEFAULT ''`, `""`},
		{`status TEXT DEFAULT 'Draft'`, `"Draft"`},
		{`status TEXT DEFAULT "done"`, `"done"`},
		{`status TEXT DEFAULT ('done')`, `"done"`},
		{`status TEXT DEFAULT 'it''s'`, `"it's"`},
	}
	for _, tc := range cases {
		t.Run(tc.column, func(t *testing.T) {
			dir, schema := workflowDefaultSQLApp(t, tc.column)
			gate, check, load := workflowDefaultSurfaces(t, dir, ParseCreateTables(schema))
			for surface, msg := range map[string]string{"write gate": gate, "benmore check": check, "load warning": load} {
				if tc.refused == "" {
					if strings.Contains(msg, "column default") {
						t.Errorf("%s refused a default equal to `initial:` (or no default): %s", surface, msg)
					}
					continue
				}
				if want := "would start in " + tc.refused + ", not \"draft\""; !strings.Contains(msg, want) {
					t.Errorf("%s = %q; want it to contain %q", surface, msg, want)
				}
			}
			if tc.refused == "" && gate != "" {
				t.Errorf("write gate refused a correct workflows.yaml: %s", gate)
			}
		})
	}
}

// The fix is worded for the file the default is declared in. A schema.sql app
// was told to change "the Prisma `@default(...)`".
func TestWorkflowDefaultCheckNamesTheSchemaFileInUse(t *testing.T) {
	t.Run("schema.sql", func(t *testing.T) {
		dir, schema := workflowDefaultSQLApp(t, `status TEXT DEFAULT "done"`)
		gate, check, load := workflowDefaultSurfaces(t, dir, ParseCreateTables(schema))
		for surface, msg := range map[string]string{"write gate": gate, "benmore check": check, "load warning": load} {
			if want := "orders.status has column default \"done\" but `initial:` is \"draft\""; !strings.Contains(msg, want) {
				t.Errorf("%s = %q; want it to contain %q", surface, msg, want)
			}
			if want := "In schema.sql, give the column `DEFAULT 'draft'` (or drop the default)."; !strings.Contains(msg, want) {
				t.Errorf("%s = %q; want it to contain %q", surface, msg, want)
			}
			if strings.Contains(msg, "Prisma") || strings.Contains(msg, "@default") {
				t.Errorf("%s names Prisma to a schema.sql app: %s", surface, msg)
			}
		}
	})

	t.Run("schema.prisma", func(t *testing.T) {
		prisma := func(status string) (string, []Table) {
			dir := t.TempDir()
			schema := fmt.Sprintf("model Order {\n  id        Int      @id @default(autoincrement())\n  status    %s\n  updatedAt DateTime @default(now()) @updatedAt @map(\"updated_at\")\n\n  @@map(\"orders\")\n}\n", status)
			writeTestFile(t, dir, "app.yaml", "site_name: probe\nauth:\n  identifier: email\n")
			writeTestFile(t, dir, "schema.prisma", schema)
			models, err := ParsePrismaSchema(schema)
			if err != nil {
				t.Fatal(err)
			}
			return dir, ParseCreateTables(EmitSQL(models))
		}
		dir, tables := prisma(`String @default("done")`)
		gate, check, load := workflowDefaultSurfaces(t, dir, tables)
		for surface, msg := range map[string]string{"write gate": gate, "benmore check": check, "load warning": load} {
			if want := "would start in \"done\", not \"draft\". In schema.prisma, give the field `@default(\"draft\")` (or drop the default)."; !strings.Contains(msg, want) {
				t.Errorf("%s = %q; want it to contain %q", surface, msg, want)
			}
		}
		for _, ok := range []string{`String @default("draft")`, `String?`, `String`} {
			dir, tables := prisma(ok)
			gate, check, load := workflowDefaultSurfaces(t, dir, tables)
			if gate != "" || strings.Contains(check+load, "column default") {
				t.Errorf("status %s refused: gate=%q check=%q load=%q", ok, gate, check, load)
			}
		}
	})

	// The check itself, with no schema file to name.
	columns := func(def string) func(string) []Column {
		return func(string) []Column { return []Column{{Name: "status", Default: def}} }
	}
	got := workflowDefaultProblems(workflowDefaultTestYAML, columns(`'done'`), "")
	if len(got) != 1 || !strings.HasSuffix(got[0], "Make the column default equal `initial:` (or drop the default).") {
		t.Errorf("with no schema file: %q", got)
	}
	// A default that is not one plain value is compared, and shown, as written.
	got = workflowDefaultProblems(workflowDefaultTestYAML, columns(`lower('DRAFT')`), "schema.sql")
	if len(got) != 1 || !strings.Contains(got[0], "would start in lower('DRAFT'), not \"draft\"") {
		t.Errorf("expression default: %q", got)
	}
	got = workflowDefaultProblems(workflowDefaultTestYAML, columns(`'a' || 'b'`), "schema.sql")
	if len(got) != 1 || !strings.Contains(got[0], "would start in 'a' || 'b', not \"draft\"") {
		t.Errorf("concatenation default: %q", got)
	}
}
