//go:build !cli

package main

import (
	"strings"
	"testing"
)

const appMCPCapturedDocsSQL = `CREATE TABLE captured_docs (
	id INTEGER PRIMARY KEY,
	org_id TEXT,
	title TEXT
);`

const appMCPCapturedDocsPrisma = `model CapturedDoc {
	id     Int    @id @default(autoincrement())
	org_id String
	title  String
	@@map("captured_docs")
	@@fulltext([title])
}
`

func TestAppMCPReloadUsesCapturedSQLSchema(t *testing.T) {
	for _, tc := range []struct {
		name      string
		mutation  string
		addPrisma bool
	}{
		{
			name: "valid conflicting schema",
			mutation: `CREATE TABLE captured_docs (
				id INTEGER PRIMARY KEY,
				org_id TEXT,
				wrongcolumn TEXT
			);
			CREATE TABLE evil_table (id INTEGER PRIMARY KEY);`,
		},
		{name: "invalid drop statement", mutation: "DROP TABLE captured_docs;"},
		{name: "new higher-precedence Prisma", mutation: appMCPCapturedDocsSQL, addPrisma: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, _ := auditApp(t)
			writeTestFile(t, app.Dir, "schema.sql", appMCPCapturedDocsSQL)
			writeTestFile(t, app.Dir, "mcp.yaml", strings.ReplaceAll(appMCPManifestFixture(), "notes", "captured_docs"))
			reviewAppMCPFixture(t, app.Dir)
			config, err := loadRuntimeConfig(app.Dir)
			if err != nil {
				t.Fatal(err)
			}
			if config.mcp == nil {
				t.Fatal("staged config has no MCP manifest")
			}
			if source, ok := config.schemaSources["schema.prisma"]; !ok || source != nil {
				t.Fatalf("schema.prisma capture = (%q, present %v), want captured nil", source, ok)
			}

			writeTestFile(t, app.Dir, "schema.sql", tc.mutation)
			// A missing schema.prisma captured at staging remains absent to this
			// config, even if a higher-precedence source appears on disk later.
			if tc.addPrisma {
				writeTestFile(t, app.Dir, "schema.prisma", `model Evil {
				id Int @id
				wrongcolumn String
				@@map("evil_table")
			}`)
			}
			if err := reloadAppConfigStaged(app, config, nil); err != nil {
				t.Fatalf("reload with staged schema source: %v", err)
			}
			assertAppMCPCapturedDocsColumns(t, app)
			assertAppMCPTableMissing(t, app, "evil_table")
		})
	}
}

func TestAppMCPReloadUsesCapturedPrismaSchemaAndMigrationSource(t *testing.T) {
	t.Setenv("BENMORE_TEST_BOOT", "0")
	app, cleanup := newTestApp(t)
	defer cleanup()
	writeTestFile(t, app.Dir, "schema.prisma", appMCPCapturedDocsPrisma)
	writeTestFile(t, app.Dir, "mcp.yaml", strings.ReplaceAll(appMCPManifestFixture(), "notes", "captured_docs"))
	reviewAppMCPFixture(t, app.Dir)
	config, err := loadRuntimeConfig(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if config.mcp == nil {
		t.Fatal("staged config has no MCP manifest")
	}

	mutated := strings.Replace(appMCPCapturedDocsPrisma, "title  String", "wrongcolumn String", 1)
	mutated = strings.Replace(mutated, "@@fulltext([title])", "@@fulltext([wrongcolumn])", 1)
	mutated += `
model Evil {
	id Int @id
	@@map("evil_table")
}
`
	writeTestFile(t, app.Dir, "schema.prisma", mutated)
	if err := reloadAppConfigStaged(app, config, nil); err != nil {
		t.Fatalf("reload with staged Prisma source: %v", err)
	}
	assertAppMCPCapturedDocsColumns(t, app)
	assertAppMCPTableMissing(t, app, "evil_table")

	table, ok := appMCPTable(t, app, "captured_docs")
	if !ok || len(table.FullText) != 1 || len(table.FullText[0]) != 1 || table.FullText[0][0] != "title" {
		t.Fatalf("captured_docs full-text metadata = %+v, want [[title]]", table.FullText)
	}

	var journalName, journalSQL string
	if err := app.DB.QueryRow("SELECT name,sql FROM _benmore_prisma_runtime_journals ORDER BY name DESC LIMIT 1").Scan(&journalName, &journalSQL); err != nil {
		t.Fatalf("read generated DB migration journal: %v", err)
	}
	if !strings.HasPrefix(journalName, prismaRuntimeJournalPrefix) || !strings.Contains(journalSQL, "captured_docs") || strings.Contains(journalSQL, "wrongcolumn") {
		t.Fatalf("journal does not use reviewed schema: %q %q", journalName, journalSQL)
	}

	var source string
	if err := app.DB.QueryRow(`SELECT source FROM _benmore_migrations ORDER BY id DESC LIMIT 1`).Scan(&source); err != nil {
		t.Fatalf("read Prisma migration ledger source: %v", err)
	}
	if source != appMCPCapturedDocsPrisma {
		t.Fatalf("migration ledger source differs from reviewed Prisma source:\n got: %q\nwant: %q", source, appMCPCapturedDocsPrisma)
	}
}

func assertAppMCPCapturedDocsColumns(t *testing.T, app *App) {
	t.Helper()
	columns, err := GetTableColumns(app.DB, "captured_docs")
	if err != nil {
		t.Fatalf("GetTableColumns(captured_docs): %v", err)
	}
	var got []string
	for _, column := range columns {
		got = append(got, column.Name)
	}
	want := []string{"id", "org_id", "title"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("captured_docs live columns = %v, want %v", got, want)
	}
	if stringSliceContains(got, "wrongcolumn") {
		t.Fatal("captured_docs contains unreviewed wrongcolumn")
	}

	table, ok := appMCPTable(t, app, "captured_docs")
	if !ok {
		t.Fatal("published app.Tables omits captured_docs")
	}
	got = got[:0]
	for _, column := range table.Columns {
		got = append(got, column.Name)
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("captured_docs app.Tables columns = %v, want %v", got, want)
	}
}

func assertAppMCPTableMissing(t *testing.T, app *App, name string) {
	t.Helper()
	exists, err := tableExists(app.DB, name)
	if err != nil {
		t.Fatalf("check live table %q: %v", name, err)
	}
	if exists {
		t.Fatalf("unreviewed table %q exists in the live database", name)
	}
	if _, ok := appMCPTable(t, app, name); ok {
		t.Fatalf("unreviewed table %q exists in app.Tables", name)
	}
}

func appMCPTable(t *testing.T, app *App, name string) (Table, bool) {
	t.Helper()
	for _, table := range app.Tables {
		if table.Name == name {
			return table, true
		}
	}
	return Table{}, false
}
