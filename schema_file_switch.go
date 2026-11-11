//go:build !cli

package main

import (
	"fmt"
	"sort"
	"strings"
)

// Which schema file an app loads, and the guard against a write that changes
// it unasked.
//
// A load builds the app's tables from schema.prisma when that file declares a
// model, else from schema.sql (loadSchemaWithReaderCtx, db.go); schema.yaml is
// shorthand the app turns into schema.sql. So the first model that lands in
// the schema.prisma of an app whose schema is schema.sql replaces the app's
// schema: schema.sql is no longer read. Its tables stay in the database with
// their rows, and auto-CRUD still serves them from there, but they are no
// longer in the schema the app loads (App.Tables) and no later schema.sql
// edit is applied. feature_install did that by appending a pack's models to a
// schema.prisma it created, answering ok:true (round 2026-11-10); a
// schema.prisma pushed by hand did the same.
//
// PrismaTablesDroppedOnLoad cannot see it: it diffs against the last
// schema.prisma source the instance applied, such an app has none, and
// nothing is dropped. This check reads source files only.

// schemaFileSet are an app's schema files as a load reads them; nil means
// the file is absent.
type schemaFileSet struct {
	prisma, sql, yaml []byte
	// connector: the app has an mcp.yaml. Its load never writes schema.sql
	// from schema.yaml (app_loader.go).
	connector bool
}

// readSchemaFileSet reads dir's schema files (checked opens in a process
// that does not own dir, readAppConfigFile).
func readSchemaFileSet(dir string) (schemaFileSet, error) {
	var s schemaFileSet
	var err error
	if s.prisma, err = readOptionalConfig(dir, "schema.prisma"); err != nil {
		return s, err
	}
	if s.sql, err = readOptionalConfig(dir, "schema.sql"); err != nil {
		return s, err
	}
	if s.yaml, err = readOptionalConfig(dir, "schema.yaml"); err != nil {
		return s, err
	}
	manifest, err := readOptionalConfig(dir, "mcp.yaml")
	s.connector = manifest != nil
	return s, err
}

// prismaSourceLoads reports whether a load takes src, a schema.prisma, as the
// app's schema: it declares a model. A source that does not parse counts: a
// load refuses it instead of falling back to schema.sql.
func prismaSourceLoads(src []byte) bool {
	models, err := ParsePrismaSchema(string(src))
	return err != nil || len(models) > 0
}

// otherSchema returns the file the app loads its schema from when that is not
// schema.prisma - "schema.sql", or "schema.yaml" before the app has turned it
// into schema.sql - and the tables that file declares, sorted. file is ""
// when the app loads schema.prisma or declares no table: there is nothing a
// schema.prisma could take the place of.
func (s schemaFileSet) otherSchema() (file string, tables []string) {
	if s.prisma != nil && prismaSourceLoads(s.prisma) {
		return "", nil
	}
	var ddl string
	switch {
	case s.sql != nil:
		file, ddl = "schema.sql", string(s.sql)
	case s.yaml != nil:
		file, ddl = "schema.yaml", parseSchemaShorthand(s.yaml)
	default:
		return "", nil
	}
	for _, table := range ParseCreateTables(ddl) {
		tables = append(tables, table.Name)
	}
	if len(tables) == 0 {
		return "", nil
	}
	sort.Strings(tables)
	return file, tables
}

// ownSchemaFile is the file a builder edits to add a table to an app whose
// schema is not schema.prisma: schema.yaml when the app has one (it writes
// schema.sql from it), else schema.sql.
func (s schemaFileSet) ownSchemaFile() string {
	if s.yaml != nil {
		return "schema.yaml"
	}
	return "schema.sql"
}

// schemaTableList names tables for a message, the first ten and a count of
// the rest: the names are the app's own and a refusal should stay readable.
func schemaTableList(tables []string) string {
	const shown = 10
	if len(tables) <= shown {
		return strings.Join(tables, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(tables[:shown], ", "), len(tables)-shown)
}

// schemaPrismaSwitchRefusal is the write-gate refusal for a schema.prisma
// write that would make the app stop loading its schema.sql (or schema.yaml)
// while tables declared there are missing from content. A file that declares
// every one of them is how an app moves to schema.prisma, and is accepted.
// `benmore check` judges the directory as it is, where the file on disk is
// already the one the app loads, so it reports nothing here.
func schemaPrismaSwitchRefusal(appDir, content string) string {
	if appDir == "" {
		return ""
	}
	current, err := readSchemaFileSet(appDir)
	if err != nil {
		return ""
	}
	file, tables := current.otherSchema()
	if file == "" {
		return ""
	}
	models, err := ParsePrismaSchema(content)
	if err != nil || len(models) == 0 {
		return "" // validateSchemaPrisma reports both; neither replaces the schema
	}
	declared := map[string]bool{}
	for _, model := range models {
		declared[sqliteIdentifierFold(model.Table)] = true
	}
	var missing []string
	for _, table := range tables {
		if !declared[sqliteIdentifierFold(table)] {
			missing = append(missing, table)
		}
	}
	if len(missing) == 0 {
		return ""
	}
	return fmt.Sprintf("schema.prisma not written: this app's schema is %s, and an app loads schema.prisma instead as soon as it declares a model. This file leaves out tables %s declares; they would keep their rows but stop being part of the app's schema: %s.\nTo add a table, declare it in %s. To move the app to schema.prisma, declare every table of %s as a model in this file (`@@map(\"<table>\")` keeps a table's name) and write it again. See api(at:\"schema\") schema_file.",
		file, file, schemaTableList(missing), current.ownSchemaFile(), file)
}

// featureInstallSchemaSwitch is the plan collision for a pack whose Prisma
// schema would land in an app that loads another schema file: packModels, the
// pack has models to append to schema.prisma; packPrisma, it carries a
// schema.prisma file a load would take (prismaSourceLoads). "" when the app
// loads schema.prisma, declares no table yet, or the pack brings neither.
// Unlike the write gate this does not compare tables: an install adds to the
// schema the app has and never replaces it.
func featureInstallSchemaSwitch(current schemaFileSet, packModels, packPrisma bool) string {
	if !packModels && !packPrisma {
		return ""
	}
	file, tables := current.otherSchema()
	if file == "" {
		return ""
	}
	brings := "the pack's models go into schema.prisma"
	if !packModels {
		brings = "the pack carries a schema.prisma"
	}
	own := current.ownSchemaFile()
	return fmt.Sprintf("schema.prisma: this app's schema is %s and %s. An app loads schema.prisma instead as soon as it declares a model, so the app's own tables would stop being part of its schema (%s). Nothing is installed. Add the pack's tables to %s and install the pack without its models, or move the app to schema.prisma first: api(at:\"schema\") schema_file.",
		file, brings, schemaTableList(tables), own)
}

// schemaYAMLOverwriteProblem reports a schema.yaml (content, as written or as
// it is on disk) that would replace a hand-written schema.sql.
//
// A load writes schema.sql from schema.yaml (WriteSchemaSQL) unless
// schema.sql is the newer file. It does not ask whether it generated the file
// it replaces: a schema.yaml that lands beside a hand-written schema.sql is
// the newer one, the next load overwrites schema.sql with the shorthand's
// tables, and the load after that no longer declares the tables only the old
// file had (they keep their rows). The one thing that tells a generated
// schema.sql from a hand-written one is the generator's first line
// (schemaShorthandHeader, there since the shorthand exists): an app that
// lives in schema.yaml has it and edits its shorthand freely, tables removed
// included.
//
// So: schema.sql is the file the app loads, it declares a table, and it lacks
// that line. A schema.yaml that names every table of the file is refused too:
// the generated file still replaces the written one, and the created_at
// column the shorthand gives every table (a non-constant default) cannot be
// added to a table that already holds rows, so the load after the overwrite
// fails ("Cannot add a column with non-constant default"). An app with an
// mcp.yaml is never judged: its load does not write schema.sql.
func schemaYAMLOverwriteProblem(current schemaFileSet, content []byte) string {
	if current.connector || current.sql == nil {
		return ""
	}
	if strings.HasPrefix(strings.TrimSpace(string(current.sql)), schemaShorthandHeader) {
		return ""
	}
	file, tables := current.otherSchema()
	if file != "schema.sql" {
		return ""
	}
	generated := parseSchemaShorthand(content)
	if generated == "" {
		return "" // a load writes nothing from it
	}
	declared := map[string]bool{}
	for _, table := range ParseCreateTables(generated) {
		declared[sqliteIdentifierFold(table.Name)] = true
	}
	var missing []string
	for _, table := range tables {
		if !declared[sqliteIdentifierFold(table)] {
			missing = append(missing, table)
		}
	}
	msg := "schema.yaml: this app's schema.sql is written by hand, and an app with a schema.yaml writes its schema.sql from it when it loads (unless schema.sql is the newer file), replacing the file it has."
	if len(missing) > 0 {
		msg += fmt.Sprintf(" These tables of schema.sql are not in this schema.yaml; they would keep their rows but stop being part of the app's schema: %s.", schemaTableList(missing))
	}
	return msg + " Declare the app's tables in schema.sql, and do not keep a schema.yaml beside it. See api(at:\"schema\") schema_file."
}

// schemaYAMLWriteRefusal is schemaYAMLOverwriteProblem for the write gate and
// `benmore check`, which hand the root schema.yaml to it.
func schemaYAMLWriteRefusal(appDir, content string) string {
	if appDir == "" {
		return ""
	}
	current, err := readSchemaFileSet(appDir)
	if err != nil {
		return ""
	}
	return schemaYAMLOverwriteProblem(current, []byte(content))
}
