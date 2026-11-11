//go:build !cli

package main

import (
	"bytes"
	"database/sql"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// Cross-file references the app's load refuses.
//
// Every start and every reload installs computed-field, encrypted-field,
// blind-index and history triggers against the migrated database
// (app_loader.go: installComputedTriggersChecked, installReloadStorage) and
// refuses the whole app when one of them names a table or column that does
// not exist. A reload that fails keeps the previous configuration until the
// app next starts, and that start fails; a push that turns on the app's first
// encrypted field restarts the app at once (encryptionNeedsRestart), so it
// stops serving straight away. The write gate used to accept a missing
// encrypted column with only a warning (round 2026-11-04: the app
// crash-looped), and a schema.prisma removing an encrypted model: its reload
// dropped the table, then failed, and the old routes answered 500.
//
// So a write is refused when, with it, the app's sources hold such a
// reference: any in the written file, and any it newly breaks in another file
// (a schema that removes a model or field that encrypted.yaml, computed.yaml
// or app.yaml's versioned: still names). `benmore check` reports the same
// problems as errors on the file that holds them.
//
// A batch write (deploy, multi-file push) defers its reload and names the
// files it writes next (pending). A reference this write breaks in one of
// those is left to that file's own write, which is judged against this one,
// so a schema change and the config that drops its references land together.
// Deploy writes schema files first and migrations next, so config is always
// judged against both.
//
// Judged statically, as the load will find the database: tables are schema
// models, tables the app's own migrations create or rename into place, and
// framework tables; a model's columns are its fields plus columns those
// migrations add or rename. A migration the Prisma step generated only
// replays the schema's history and is not read. Columns of a table a
// migration creates or renames into place are not judged (the check cannot
// see them). computed.yaml is stricter: the load installs its triggers before
// it runs migrations, so what only a migration creates counts as missing. References the app loads with (an
// access: rule, a hook, workflow, validator or retention policy on a missing
// table) stay warnings or are refused elsewhere (CrossFileWarnings,
// validatorsYAMLViolation).

var (
	migrationCreateTableRe  = regexp.MustCompile(`(?i)\bCREATE\s+(?:TEMP\w*\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:main\.)?["'\x60\[]?(\w+)`)
	migrationRenameTableRe  = regexp.MustCompile(`(?i)\bALTER\s+TABLE\s+(?:main\.)?["'\x60\[]?\w+["'\x60\]]?\s+RENAME\s+TO\s+["'\x60\[]?(\w+)`)
	migrationAddColumnRe    = regexp.MustCompile(`(?i)\bALTER\s+TABLE\s+(?:main\.)?["'\x60\[]?(\w+)["'\x60\]]?\s+ADD\s+(?:COLUMN\s+)?["'\x60\[]?(\w+)`)
	migrationRenameColumnRe = regexp.MustCompile(`(?i)\bALTER\s+TABLE\s+(?:main\.)?["'\x60\[]?(\w+)["'\x60\]]?\s+RENAME\s+(?:COLUMN\s+)?["'\x60\[]?\w+["'\x60\]]?\s+TO\s+["'\x60\[]?(\w+)`)
	schemaSQLCreateTableRe  = regexp.MustCompile(`(?i)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?["']?(\w+)["']?`)
	// The file name the Prisma step gives the migration it generates
	// (prisma_migrate.go applyPrismaMigrationCtx).
	generatedPrismaMigrationNameRe = regexp.MustCompile(`^\d{4,}_(\d{8}T\d{6}Z)_([a-z0-9_]+)\.sql$`)
)

// generatedPrismaMigration reports a migration file the Prisma step wrote from
// schema.prisma (its name and its EmitMigrationSQL header). Its tables and
// columns are the schema's history, not the app's: a model removed since is
// dropped at the next load, so such a file says nothing about what exists.
func generatedPrismaMigration(name, body string) bool {
	m := generatedPrismaMigrationNameRe.FindStringSubmatch(name)
	return m != nil && strings.HasPrefix(body, "-- Migration: "+m[2]+"\n-- Generated: "+m[1]+"\n")
}

// loadRefInputs are the files whose content decides these references.
var loadRefInputs = map[string]bool{"schema.prisma": true, "schema.sql": true, "app.yaml": true, "encrypted.yaml": true, "computed.yaml": true}

type loadRefProblem struct {
	file    string // the file that holds the reference
	key     string // identity of the reference across two states of the app
	message string
	column  bool // a missing column (not a missing table)
}

// loadRefSource reads the app's sources as a write of written would leave
// them ("" reads the directory as it is).
type loadRefSource struct {
	dir, written, content string
}

func (s loadRefSource) read(name string) []byte {
	if s.written == name {
		return []byte(s.content)
	}
	return readAppFileOrNil(s.dir, name)
}

// loadRefSchema is what the load will find: its tables (folded names) and,
// for tables whose columns can be judged, their columns.
type loadRefSchema struct {
	tables    map[string]bool
	tableList string                       // schema tables, for messages
	columns   map[string]map[string]string // folded table → folded column → column
	added     map[string][]string          // folded table → columns migrations add or rename
	migrated  map[string]bool              // folded tables migrations create or rename into place
	schemaDDL string                       // schema.prisma as SQL (computed check)
	declared  map[string]bool              // folded schema and framework tables
}

func readLoadRefSchema(src loadRefSource) *loadRefSchema {
	s := &loadRefSchema{tables: map[string]bool{}, columns: map[string]map[string]string{}, added: map[string][]string{}, migrated: map[string]bool{}, declared: map[string]bool{}}
	schemaTables := map[string]bool{}
	if data := src.read("schema.prisma"); data != nil {
		models, err := ParsePrismaSchema(string(data))
		if err != nil {
			return nil
		}
		for _, m := range models {
			schemaTables[m.Table] = true
			cols := map[string]string{}
			for _, f := range m.Fields {
				cols[sqliteIdentifierFold(f.Column)] = f.Column
			}
			s.columns[sqliteIdentifierFold(m.Table)] = cols
		}
		s.schemaDDL = EmitSQL(models)
	} else if data := src.read("schema.sql"); data != nil {
		for _, m := range schemaSQLCreateTableRe.FindAllStringSubmatch(string(data), -1) {
			schemaTables[strings.ToLower(m[1])] = true
		}
	}
	if len(schemaTables) == 0 {
		return nil
	}
	for table := range schemaTables {
		s.tables[sqliteIdentifierFold(table)] = true
		s.declared[sqliteIdentifierFold(table)] = true
	}
	s.tableList = crossFileSortedKeys(schemaTables)
	for table := range frameworkTables {
		s.tables[sqliteIdentifierFold(table)] = true
		s.declared[sqliteIdentifierFold(table)] = true
	}
	entries, _ := os.ReadDir(filepath.Join(src.dir, "migrations"))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".sql") {
			continue
		}
		body := string(readAppFileOrNil(src.dir, filepath.Join("migrations", entry.Name())))
		if generatedPrismaMigration(entry.Name(), body) {
			continue
		}
		for _, re := range []*regexp.Regexp{migrationCreateTableRe, migrationRenameTableRe} {
			for _, m := range re.FindAllStringSubmatch(body, -1) {
				table := sqliteIdentifierFold(m[1])
				s.tables[table] = true
				s.migrated[table] = true
				delete(s.columns, table) // its columns come from the migration
			}
		}
		for _, re := range []*regexp.Regexp{migrationAddColumnRe, migrationRenameColumnRe} {
			for _, m := range re.FindAllStringSubmatch(body, -1) {
				table := sqliteIdentifierFold(m[1])
				s.added[table] = append(s.added[table], m[2])
			}
		}
	}
	return s
}

func (s *loadRefSchema) hasTable(table string) bool {
	return s.tables[sqliteIdentifierFold(table)]
}

// judged reports whether the columns of table can be judged.
func (s *loadRefSchema) judged(table string) bool {
	_, ok := s.columns[sqliteIdentifierFold(table)]
	return ok
}

// missingColumn reports a column of a judged table that the load will not
// find. Unjudged tables never report one.
func (s *loadRefSchema) missingColumn(table, column string) bool {
	t := sqliteIdentifierFold(table)
	cols, ok := s.columns[t]
	if !ok {
		return false
	}
	c := sqliteIdentifierFold(column)
	if _, ok := cols[c]; ok {
		return false
	}
	for _, added := range s.added[t] {
		if sqliteIdentifierFold(added) == c {
			return false
		}
	}
	return true
}

// migrationOnlyTable reports a table only the app's migrations create.
func (s *loadRefSchema) migrationOnlyTable(table string) bool {
	t := sqliteIdentifierFold(table)
	return s.migrated[t] && !s.declared[t]
}

// migrationOnlyColumn reports a column of a judged table that only the app's
// migrations add.
func (s *loadRefSchema) migrationOnlyColumn(table, column string) bool {
	cols, ok := s.columns[sqliteIdentifierFold(table)]
	if !ok {
		return false
	}
	_, declared := cols[sqliteIdentifierFold(column)]
	return !declared && !s.missingColumn(table, column)
}

func (s *loadRefSchema) columnList(table string) string {
	cols := s.columns[sqliteIdentifierFold(table)]
	names := slices.Sorted(maps.Values(cols))
	names = append(names, s.added[sqliteIdentifierFold(table)]...)
	return strings.Join(names, ", ")
}

// loadRefProblems lists every reference the load would refuse, or nil when
// there is no readable schema to judge against.
func loadRefProblems(src loadRefSource) []loadRefProblem {
	schema := readLoadRefSchema(src)
	if schema == nil {
		return nil
	}
	appData := src.read("app.yaml")
	var out []loadRefProblem
	out = append(out, versionedLoadRefProblems(schema, appData)...)
	out = append(out, encryptedLoadRefProblems(schema, src.read("encrypted.yaml"), appData)...)
	out = append(out, computedLoadRefProblems(schema, src.read("computed.yaml"))...)
	return out
}

func versionedLoadRefProblems(schema *loadRefSchema, appData []byte) []loadRefProblem {
	var raw map[string]any
	if decodeConfigYAML(appData, &raw) != nil {
		return nil
	}
	config, err := parseVersionedSection(raw["versioned"])
	if err != nil || config == nil {
		return nil
	}
	var out []loadRefProblem
	for _, table := range config.Tables {
		if schema.hasTable(table) {
			continue
		}
		out = append(out, loadRefProblem{
			file: "app.yaml",
			key:  "versioned:" + sqliteIdentifierFold(table),
			message: fmt.Sprintf("app.yaml: versioned lists %q, which is not a table of this app (tables in schema.prisma: %s). "+
				"The load refuses a versioned table that does not exist (\"versioning %s: source table is missing or lacks id\").", table, schema.tableList, table),
		})
	}
	return out
}

func encryptedLoadRefProblems(schema *loadRefSchema, encData, appData []byte) []loadRefProblem {
	merged := parseEncryptedFieldsConfig(encData, appData)
	if merged == nil {
		return nil
	}
	fromFile := parseEncryptedFieldsConfig(encData, nil)
	var out []loadRefProblem
	for _, table := range slices.Sorted(maps.Keys(merged.Fields)) {
		file := "app.yaml"
		if fromFile != nil && fromFile.Fields[table] != nil {
			file = "encrypted.yaml"
		}
		if !schema.hasTable(table) {
			out = append(out, loadRefProblem{
				file: file,
				key:  "encrypted-table:" + sqliteIdentifierFold(table),
				message: fmt.Sprintf("%s: encrypted fields name the table %q, which is not a table of this app (tables in schema.prisma: %s). "+
					"Nothing would be encrypted under that name - a misspelled table leaves the real one in plaintext - and the load refuses it.", file, table, schema.tableList),
			})
			continue
		}
		for _, def := range merged.Fields[table] {
			if !schema.missingColumn(table, def.Column) {
				continue
			}
			what := "an encrypted field"
			if def.BlindIndex {
				what = "an encrypted field with a blind index"
			}
			out = append(out, loadRefProblem{
				file:   file,
				key:    "encrypted-column:" + sqliteIdentifierFold(table) + "." + sqliteIdentifierFold(def.Column),
				column: true,
				message: fmt.Sprintf("%s: %s.%s is %s, but %s has no column %q (columns in schema.prisma: %s). "+
					"The load refuses it (\"encrypted field %s.%s: source column does not exist\"), and a misspelled name leaves the real column in plaintext.",
					file, table, def.Column, what, table, def.Column, schema.columnList(table), table, def.Column),
			})
		}
	}
	return out
}

const computedLoadRefNote = "The load refuses a computed field whose tables or columns do not exist (its triggers cannot be installed)."

// computedBeforeMigrationsNote: the load installs computed triggers before it
// runs migrations/ (app_loader.go), so what only a migration creates is not
// there yet on a database that has not run it.
const computedBeforeMigrationsNote = "The load installs computed triggers before it runs migrations/, so a database that has not run that migration yet (a new instance, a promote, `benmore test`) cannot load. Declare it in schema.prisma."

func computedLoadRefProblems(schema *loadRefSchema, data []byte) []loadRefProblem {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	var document map[string]any
	if decodeConfigYAML(data, &document) != nil || len(document) == 0 {
		return nil
	}
	config := parseComputedFieldsYAML(data)
	if config == nil {
		return nil
	}
	var out []loadRefProblem
	var installable []*ComputedField
	for _, table := range slices.Sorted(maps.Keys(config.Fields)) {
		for _, column := range slices.Sorted(maps.Keys(config.Fields[table])) {
			cf := config.Fields[table][column]
			field := sqliteIdentifierFold(cf.Table) + "." + sqliteIdentifierFold(cf.Column)
			found := len(out)
			add := func(key, message string, column bool) {
				out = append(out, loadRefProblem{file: "computed.yaml", key: key, message: message, column: column})
			}
			missing := func(key, message string, column bool) { add(key, message+" "+computedLoadRefNote, column) }
			migrationOnly := func(key, message string, column bool) { add(key, message+" "+computedBeforeMigrationsNote, column) }
			switch {
			case !schema.hasTable(cf.Table):
				missing("computed-table:"+field, fmt.Sprintf("computed.yaml: %s.%s is computed on the table %q, which is not a table of this app (tables in schema.prisma: %s).", cf.Table, cf.Column, cf.Table, schema.tableList), false)
			case schema.migrationOnlyTable(cf.Table):
				migrationOnly("computed-migration-table:"+field, fmt.Sprintf("computed.yaml: %s.%s is computed on the table %q, which only a migration creates.", cf.Table, cf.Column, cf.Table), false)
			case schema.missingColumn(cf.Table, cf.Column):
				missing("computed-column:"+field, fmt.Sprintf("computed.yaml: %s.%s is computed, but %s has no column %q (columns in schema.prisma: %s).", cf.Table, cf.Column, cf.Table, cf.Column, schema.columnList(cf.Table)), true)
			case schema.migrationOnlyColumn(cf.Table, cf.Column):
				migrationOnly("computed-migration-column:"+field, fmt.Sprintf("computed.yaml: %s.%s is computed, but only a migration adds the column %q to %s.", cf.Table, cf.Column, cf.Column, cf.Table), true)
			}
			for _, trigger := range cf.Triggers {
				on := field + ":" + sqliteIdentifierFold(trigger.Table)
				switch {
				case !schema.hasTable(trigger.Table):
					missing("computed-trigger-table:"+on, fmt.Sprintf("computed.yaml: %s.%s recalculates on changes to the table %q, which is not a table of this app (tables in schema.prisma: %s).", cf.Table, cf.Column, trigger.Table, schema.tableList), false)
				case schema.migrationOnlyTable(trigger.Table):
					migrationOnly("computed-trigger-migration-table:"+on, fmt.Sprintf("computed.yaml: %s.%s recalculates on changes to the table %q, which only a migration creates.", cf.Table, cf.Column, trigger.Table), false)
				case trigger.FK == "":
				case schema.missingColumn(trigger.Table, trigger.FK):
					missing("computed-trigger-fk:"+on+"."+sqliteIdentifierFold(trigger.FK), fmt.Sprintf("computed.yaml: %s.%s: the trigger on %s names fk %q, which is not a column of %s (columns in schema.prisma: %s).", cf.Table, cf.Column, trigger.Table, trigger.FK, trigger.Table, schema.columnList(trigger.Table)), true)
				case schema.migrationOnlyColumn(trigger.Table, trigger.FK):
					migrationOnly("computed-trigger-migration-fk:"+on+"."+sqliteIdentifierFold(trigger.FK), fmt.Sprintf("computed.yaml: %s.%s: the trigger on %s names fk %q, which only a migration adds.", cf.Table, cf.Column, trigger.Table, trigger.FK), true)
				}
			}
			if len(out) > found || !schema.judged(cf.Table) {
				continue
			}
			judged := true
			for _, trigger := range cf.Triggers {
				judged = judged && schema.judged(trigger.Table)
			}
			if judged {
				installable = append(installable, cf)
			}
		}
	}
	return append(out, computedSQLColumnProblems(schema, installable)...)
}

// computedSQLColumnProblems installs each field's triggers, as the load does,
// into an in-memory database holding the schema's tables (the load installs
// them before migrations run, so columns migrations add are not there), and
// reports a field whose expression or SQL reads a column that is not there.
// Other failures are not this check's to judge: a table only a migration
// creates is left alone, and an expression SQLite cannot compile is reported
// by computed.yaml's own gate (computedInstallProblems).
func computedSQLColumnProblems(schema *loadRefSchema, fields []*ComputedField) []loadRefProblem {
	errs := computedTriggerInstallErrors(schema, fields)
	var out []loadRefProblem
	for _, cf := range fields {
		err := errs[cf]
		if err == nil || !strings.Contains(err.Error(), "no such column") {
			continue
		}
		out = append(out, loadRefProblem{
			file:    "computed.yaml",
			key:     "computed-sql:" + sqliteIdentifierFold(cf.Table) + "." + sqliteIdentifierFold(cf.Column),
			column:  true,
			message: fmt.Sprintf("computed.yaml: %s.%s reads a column the schema does not have (%v). %s A column only a migration adds does not count: the load installs computed triggers before it runs migrations/.", cf.Table, cf.Column, err, computedLoadRefNote),
		})
	}
	return out
}

// computedTriggerInstallErrors installs each field's triggers with the load's
// own installer into an in-memory database holding the schema's tables, one
// field at a time, and returns the error of each field whose install fails.
func computedTriggerInstallErrors(schema *loadRefSchema, fields []*ComputedField) map[*ComputedField]error {
	if len(fields) == 0 || schema.schemaDDL == "" {
		return nil
	}
	db, err := sql.Open(sqliteMaintenanceDriver, ":memory:")
	if err != nil {
		return nil
	}
	defer db.Close()
	// One connection: every pooled :memory: connection is its own database.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema.schemaDDL); err != nil {
		return nil
	}
	out := map[*ComputedField]error{}
	for _, cf := range fields {
		if err := installComputedTriggersChecked(db, &ComputedFieldConfig{Fields: map[string]map[string]*ComputedField{cf.Table: {cf.Column: cf}}}); err != nil {
			out[cf] = err
		}
	}
	return out
}

// loadRefWriteCheck judges a write of path (relative to dir) with content. It
// refuses the write when, with it, the app's sources would hold a reference
// the load refuses: one in the written file, or one this write breaks in a
// file pending does not name. excused lists the files named in pending whose
// references this write breaks: each must drop them in its own write.
func loadRefWriteCheck(dir, path, content string, pending map[string]bool) (refusal string, excused []string) {
	rel := filepath.ToSlash(filepath.Clean(path))
	if dir == "" || !loadRefInputs[rel] {
		return "", nil
	}
	after := loadRefProblems(loadRefSource{dir: dir, written: rel, content: content})
	if len(after) == 0 {
		return "", nil
	}
	// The references already there are not this write's doing. A file
	// written with its current content (`benmore check`) changes nothing.
	var before map[string]bool
	if disk := readAppFileOrNil(dir, rel); disk == nil || string(disk) != content {
		before = map[string]bool{}
		for _, p := range loadRefProblems(loadRefSource{dir: dir}) {
			before[p.key] = true
		}
	}
	var own, broken []loadRefProblem
	excusedFiles := map[string]bool{}
	for _, p := range after {
		switch {
		case p.file == rel:
			own = append(own, p)
		case before == nil || before[p.key]:
		case pending[p.file]:
			excusedFiles[p.file] = true
		default:
			broken = append(broken, p)
		}
	}
	excused = slices.Sorted(maps.Keys(excusedFiles))
	var parts []string
	if len(own) > 0 {
		parts = append(parts, loadRefOwnMessage(rel, own))
	}
	if len(broken) > 0 {
		parts = append(parts, loadRefBrokenMessage(rel, broken))
	}
	return strings.Join(parts, "\n\n"), excused
}

// loadRefConsequence says what happens to an app whose sources hold such a
// reference.
const loadRefConsequence = "The app cannot load while it is declared: the reload that applies it fails and keeps the previous configuration only until the app next starts, and that start fails (a crash restart, a release, `benmore restart`); a push that turns on the app's first encrypted field restarts the app at once, so it stops serving straight away."

func loadRefOwnMessage(rel string, problems []loadRefProblem) string {
	lines := make([]string, len(problems))
	for i, p := range problems {
		lines[i] = p.message
	}
	return fmt.Sprintf("%s\n%s\n"+
		"Fix the name (a model's table is its @@map, else its lowercased plural name; a column is the field's @map, else its snake_case name) or remove the entry, "+
		"or add the model or field to schema.prisma first: `benmore deploy` writes schema.prisma and migrations/ before the files that use them, and `benmore push schema.prisma %s` does the same.",
		strings.Join(lines, "\n"), loadRefConsequence, rel)
}

func loadRefBrokenMessage(rel string, problems []loadRefProblem) string {
	lines := make([]string, len(problems))
	files := map[string]bool{}
	column := false
	for i, p := range problems {
		lines[i] = "  - " + p.message
		files[p.file] = true
		column = column || p.column
	}
	names := slices.Sorted(maps.Keys(files))
	msg := fmt.Sprintf("%s not written: with it, %s would name tables or columns the app does not have:\n%s\n%s\n"+
		"Remove those references first (push the fixed %s before %s), or write both in one batch: `benmore deploy`, or `benmore push %s %s`, writes %s first and checks each later file against it.",
		rel, strings.Join(names, " and "), strings.Join(lines, "\n"), loadRefConsequence,
		strings.Join(names, ", "), rel, rel, strings.Join(names, " "), rel)
	if column && (rel == "schema.prisma" || rel == "schema.sql") {
		msg += " A removed field's column stays in this instance's database, but a new database (a new instance, `benmore test`, a first promote to prod) is created without it, and the load fails there."
	}
	return msg
}

// loadRefPendingNote accompanies cross_file_pending in a write's answer.
const loadRefPendingNote = "This write removes tables or columns that the files listed in cross_file_pending still name. They are part of this batch: each is checked against this write when it is written, and the batch's reload works only once they no longer name them. If one of them is refused, do not reload the app until it is fixed."

// prismaFullTextProblems lists @@fulltext entries that name no column of the
// model: the load builds the search index from them and refuses the app
// ("fts <table>: rebuild index: no such column").
func prismaFullTextProblems(models []PrismaModel) []string {
	var problems []string
	for _, m := range models {
		columns := map[string]bool{}
		var fields []string
		for _, f := range m.Fields {
			columns[f.Column] = true
			fields = append(fields, f.Name)
		}
		for _, index := range m.FullText {
			for _, column := range prismaFullTextColumns(m, index.Columns) {
				if columns[column] {
					continue
				}
				problems = append(problems, fmt.Sprintf("schema.prisma: model %s: @@fulltext names %q, which is not a field of %s (fields: %s). The load refuses it: building the search index fails (\"no such column\"), so the app cannot start. Name fields of the model.",
					m.Name, column, m.Name, strings.Join(fields, ", ")))
			}
		}
	}
	return problems
}

// stringListArg reads a JSON array of strings from a tool argument.
func stringListArg(v any) []string {
	items, _ := v.([]any)
	var out []string
	for _, item := range items {
		if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
			out = append(out, filepath.ToSlash(filepath.Clean(s)))
		}
	}
	return out
}

// noteCrossFilePending adds to a write's answer the later files of its batch
// whose references it breaks (loadRefWriteCheck).
func noteCrossFilePending(resp map[string]any, files []string) {
	if len(files) == 0 {
		return
	}
	resp["cross_file_pending"] = files
	resp["cross_file_pending_note"] = loadRefPendingNote
}

// deferPendingFindings turns the post-write check's errors about files this
// batch writes next into warnings: each is checked when it is written, and
// the batch reloads only after its last file. A deploy passes through such
// states (the schema lands before the config that follows it).
func deferPendingFindings(report CheckReport, pending []string) CheckReport {
	if len(pending) == 0 {
		return report
	}
	set := map[string]bool{}
	for _, p := range pending {
		set[p] = true
	}
	report.Errors, report.Warnings = 0, 0
	for i, f := range report.Findings {
		if f.Severity == "error" && f.File != "" && set[filepath.ToSlash(filepath.Clean(f.File))] {
			report.Findings[i].Severity = "warning"
			report.Findings[i].Message = "(this batch writes " + f.File + " next; it is checked then) " + f.Message
		}
		if report.Findings[i].Severity == "error" {
			report.Errors++
		} else {
			report.Warnings++
		}
	}
	return report
}
