//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Quoting reserved-word names must change nothing for an app that exists
// today. testdata/ddl_text_baseline holds an app as the binary before the
// change left it: its source, the two migrations/ files that binary wrote,
// and its database (sqlite_master, the migration ledger, a few rows; see
// "about" in database.json). Its schema uses ordinary names and the keywords
// SQLite accepts bare (key, desc, action, offset, first, last, end, plan,
// query, view, cast, raise, range, filter, window), with a relation, a
// compound primary key, single and compound indexes, @unique, @updatedAt, a
// full-text index, version history and both kinds of computed column.

type ddlBaselineObject struct {
	Type  string  `json:"type"`
	Name  string  `json:"name"`
	Table string  `json:"table"`
	SQL   *string `json:"sql"`
}

type ddlBaseline struct {
	Objects []ddlBaselineObject `json:"objects"`
	Ledger  []struct {
		ID         int64  `json:"id"`
		Name       string `json:"name"`
		AppliedAt  string `json:"applied_at"`
		Source     string `json:"source"`
		SourceHash string `json:"source_hash"`
	} `json:"ledger"`
	Rows map[string][]map[string]any `json:"rows"`
}

const ddlBaselineDir = "testdata/ddl_text_baseline"

// ddlBaselineModelTables are the tables the app's schema declares; the
// objects on them, and its full-text index, are what the schema generators
// write. (Version history and the framework's own tables are left out: their
// DDL is the framework's and may change for reasons of its own.)
var ddlBaselineModelTables = map[string]bool{"projects": true, "tasks": true, "notes": true, "memberships": true}

func ddlBaselineGenerated(o ddlBaselineObject) bool {
	if strings.HasPrefix(o.Name, "_benmore_ver_") || strings.HasPrefix(o.Name, "sqlite_") {
		return false
	}
	return ddlBaselineModelTables[o.Table] || strings.HasPrefix(o.Table, "tasks_fts")
}

func readDDLBaseline(t *testing.T) ddlBaseline {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(ddlBaselineDir, "database.json"))
	if err != nil {
		t.Fatal(err)
	}
	var baseline ddlBaseline
	if err := json.Unmarshal(data, &baseline); err != nil {
		t.Fatal(err)
	}
	if len(baseline.Objects) == 0 || len(baseline.Ledger) != 2 {
		t.Fatalf("baseline holds %d objects and %d ledger rows", len(baseline.Objects), len(baseline.Ledger))
	}
	return baseline
}

func ddlBaselineAppFiles(t *testing.T) map[string]string {
	t.Helper()
	files := map[string]string{}
	root := filepath.Join(ddlBaselineDir, "app")
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		files[filepath.ToSlash(rel)] = string(data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func ddlBaselineOpen(t *testing.T, dir string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func ddlBaselineInsertRows(t *testing.T, db *sql.DB, table string, rows []map[string]any, only map[string]bool) {
	t.Helper()
	for _, row := range rows {
		var cols, marks []string
		var args []any
		for col, value := range row {
			if only != nil && !only[col] {
				continue
			}
			cols = append(cols, quoteIdent(col))
			marks = append(marks, "?")
			args = append(args, value)
		}
		if _, err := db.Exec("INSERT INTO "+quoteIdent(table)+" ("+strings.Join(cols, ", ")+") VALUES ("+strings.Join(marks, ", ")+")", args...); err != nil {
			t.Fatalf("insert into %s: %v", table, err)
		}
	}
}

type ddlCatalogRow struct {
	rowid int64
	sql   string
}

func ddlCatalog(t *testing.T, db *sql.DB) map[string]ddlCatalogRow {
	t.Helper()
	rows, err := db.Query(`SELECT rowid, type, name, COALESCE(sql, '') FROM sqlite_master`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]ddlCatalogRow{}
	for rows.Next() {
		var row ddlCatalogRow
		var typ, name string
		if err := rows.Scan(&row.rowid, &typ, &name, &row.sql); err != nil {
			t.Fatal(err)
		}
		out[typ+" "+name] = row
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func ddlMigrationFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(dir, "migrations"))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names
}

// The database and files of an app from before the change, loaded by the
// current code: no migration is generated, the ledger gains no row, and every
// table, index and trigger the schema generators wrote is the same object with
// the same text (nothing dropped, rebuilt or re-created with other DDL).
func TestExistingDatabaseSeesNoSchemaChange(t *testing.T) {
	baseline := readDDLBaseline(t)
	dir := writeApp(t, ddlBaselineAppFiles(t))
	wantFiles := ddlMigrationFiles(t, dir)
	if len(wantFiles) != 2 {
		t.Fatalf("baseline migrations: %v", wantFiles)
	}

	db := ddlBaselineOpen(t, dir)
	asserted := map[string]string{}
	for _, object := range baseline.Objects {
		// SQLite's own objects and the full-text index's shadow tables come
		// with the statements that own them.
		if object.SQL == nil || strings.HasPrefix(object.Name, "sqlite_") || (object.Type == "table" && strings.HasPrefix(object.Name, "tasks_fts_")) {
			continue
		}
		if _, err := db.Exec(*object.SQL); err != nil {
			t.Fatalf("restore %s %s: %v", object.Type, object.Name, err)
		}
	}
	for _, object := range baseline.Objects {
		if object.SQL != nil && ddlBaselineGenerated(object) {
			asserted[object.Type+" "+object.Name] = *object.SQL
		}
	}
	if len(asserted) < 25 {
		t.Fatalf("only %d generated objects in the baseline", len(asserted))
	}
	for _, row := range baseline.Ledger {
		if _, err := db.Exec(`INSERT INTO _benmore_migrations (id, name, applied_at, source, source_hash) VALUES (?, ?, ?, ?, ?)`,
			row.ID, row.Name, row.AppliedAt, row.Source, row.SourceHash); err != nil {
			t.Fatal(err)
		}
	}
	for _, table := range []string{"projects", "memberships"} {
		ddlBaselineInsertRows(t, db, table, baseline.Rows[table], nil)
	}
	before := ddlCatalog(t, db)
	for key, want := range asserted {
		if before[key].sql != want {
			t.Fatalf("restore of %s stored other text:\n got %s\nwant %s", key, before[key].sql, want)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	app, err := loadApp(dir)
	if err != nil {
		t.Fatalf("load the pre-change app: %v", err)
	}
	t.Cleanup(app.Shutdown)

	if got := ddlMigrationFiles(t, dir); strings.Join(got, "\n") != strings.Join(wantFiles, "\n") {
		t.Errorf("the load changed migrations/:\n got %v\nwant %v", got, wantFiles)
	}
	rows, err := app.DB.Query(`SELECT id, name, source_hash FROM _benmore_migrations ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	var ledger []string
	for rows.Next() {
		var id int64
		var name, hash string
		if err := rows.Scan(&id, &name, &hash); err != nil {
			t.Fatal(err)
		}
		ledger = append(ledger, name+" "+hash)
	}
	rows.Close()
	var wantLedger []string
	for _, row := range baseline.Ledger {
		wantLedger = append(wantLedger, row.Name+" "+row.SourceHash)
	}
	if strings.Join(ledger, "\n") != strings.Join(wantLedger, "\n") {
		t.Errorf("the load changed the migration ledger:\n got %v\nwant %v", ledger, wantLedger)
	}

	after := ddlCatalog(t, app.DB)
	for key, want := range asserted {
		got, ok := after[key]
		if !ok {
			t.Errorf("%s is gone after the load", key)
			continue
		}
		if got.sql != want {
			t.Errorf("%s has other DDL after the load:\n got %s\nwant %s", key, got.sql, want)
		}
		// Computed-field triggers are dropped and written again by every
		// load, by design; everything else must be the object it was.
		if !strings.Contains(key, " _benmore_cf_") && got.rowid != before[key].rowid {
			t.Errorf("%s was dropped and created again by the load", key)
		}
	}
	for _, table := range []string{"projects", "memberships"} {
		var n int
		if err := app.DB.QueryRow("SELECT COUNT(*) FROM " + quoteIdent(table)).Scan(&n); err != nil || n != len(baseline.Rows[table]) {
			t.Errorf("%s holds %d rows after the load (err=%v), want %d", table, n, err, len(baseline.Rows[table]))
		}
	}
}

var ddlGeneratedLineRe = regexp.MustCompile(`(?m)^-- Generated: .*$`)

// The same app built from nothing by the current code, in the same two steps:
// the migration files it writes and the DDL it stores are, byte for byte,
// what the binary before the change wrote (the file's Generated timestamp
// aside). The Schema-From / Schema-To digests in those files are part of the
// comparison, so a file one instance generated is still adopted by the other.
func TestCurrentCodeWritesTheSameMigrationsAndDDL(t *testing.T) {
	baseline := readDDLBaseline(t)
	files := ddlBaselineAppFiles(t)
	var wantNames []string
	for name := range files {
		if strings.HasPrefix(name, "migrations/") {
			wantNames = append(wantNames, strings.TrimPrefix(name, "migrations/"))
		}
	}
	sort.Strings(wantNames)

	dir := writeApp(t, map[string]string{
		"app.yaml":      files["app.yaml"],
		"computed.yaml": files["computed.yaml"],
		"schema.prisma": baseline.Ledger[0].Source,
	})
	load := func() {
		t.Helper()
		app, err := loadApp(dir)
		if err != nil {
			t.Fatal(err)
		}
		EnsureScopingIndexes(app) // as `benmore serve` does after a load
		app.Shutdown()
	}
	load()
	db := ddlBaselineOpen(t, dir)
	// The rows the baseline held when its second schema arrived: memberships
	// had rows (its new column came by a table rebuild), tasks had none.
	firstColumns := map[string]map[string]bool{
		"projects":    {"id": true, "user_id": true, "name": true, "key": true, "desc": true, "action": true, "offset": true, "total": true, "created_at": true, "updated_at": true},
		"memberships": {"project_id": true, "user_id": true, "level": true},
	}
	for _, table := range []string{"projects", "memberships"} {
		ddlBaselineInsertRows(t, db, table, baseline.Rows[table], firstColumns[table])
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "schema.prisma"), []byte(baseline.Ledger[1].Source), 0644); err != nil {
		t.Fatal(err)
	}
	load()

	gotNames := ddlMigrationFiles(t, dir)
	if len(gotNames) != len(wantNames) {
		t.Fatalf("migrations written: %v, want the baseline's %v", gotNames, wantNames)
	}
	slug := func(name string) string { // 0001_<timestamp>_<slug>.sql
		return name[:5] + strings.SplitN(name, "_", 3)[2]
	}
	for i, name := range gotNames {
		if slug(name) != slug(wantNames[i]) {
			t.Errorf("migration %d is named %s, the baseline's is %s", i+1, name, wantNames[i])
		}
		got, err := os.ReadFile(filepath.Join(dir, "migrations", name))
		if err != nil {
			t.Fatal(err)
		}
		want := files["migrations/"+wantNames[i]]
		if g, w := ddlGeneratedLineRe.ReplaceAllString(string(got), "-- Generated:"), ddlGeneratedLineRe.ReplaceAllString(want, "-- Generated:"); g != w {
			t.Errorf("migration %s differs from the baseline's %s:\n--- current code\n%s\n--- before the change\n%s", name, wantNames[i], g, w)
		}
	}

	db = ddlBaselineOpen(t, dir)
	defer db.Close()
	catalog := ddlCatalog(t, db)
	compared := 0
	for _, object := range baseline.Objects {
		if object.SQL == nil || !ddlBaselineGenerated(object) {
			continue
		}
		compared++
		key := object.Type + " " + object.Name
		if got, ok := catalog[key]; !ok {
			t.Errorf("the current code did not create %s", key)
		} else if got.sql != *object.SQL {
			t.Errorf("%s:\n current code: %s\n before:       %s", key, got.sql, *object.SQL)
		}
	}
	if compared < 25 {
		t.Fatalf("compared only %d objects", compared)
	}
}

// No schema among the fixture apps declares a name the generators now write
// differently (the platform app's is checked in the platform build).
func TestShippedSchemasKeepTheirDDLText(t *testing.T) {
	var prismaFiles []string
	for _, pattern := range []string{"testdata/*/schema.prisma", "testdata/*/*/schema.prisma"} {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		prismaFiles = append(prismaFiles, matches...)
	}
	checked := 0
	for _, path := range prismaFiles {
		if strings.HasPrefix(filepath.ToSlash(path), "testdata/reserved_word_columns/") {
			continue // the fixture that declares reserved words on purpose
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		models, _ := ParsePrismaSchema(string(data))
		for _, model := range models {
			// Names written where SQL takes a name, and names written in an
			// index or PRIMARY KEY column list (an added @unique field gets
			// an index too).
			names := []string{model.Table}
			indexed := append([]string{}, model.CompoundID...)
			for _, field := range model.Fields {
				names = append(names, field.Column, field.FKTable, field.FKColumn)
				if field.IsUnique {
					indexed = append(indexed, field.Column)
				}
			}
			for _, index := range append(append([]PrismaIndex{}, model.Indexes...), model.Uniques...) {
				indexed = append(indexed, index.Columns...)
			}
			for _, name := range names {
				checked++
				if ddlIdent(name) != name {
					t.Errorf("%s: %s.%s would now be written quoted", path, model.Table, name)
				}
			}
			for _, name := range indexed {
				checked++
				if ddlExprIdent(name) != name {
					t.Errorf("%s: the index column %s.%s would now be written quoted", path, model.Table, name)
				}
			}
		}
	}
	if len(prismaFiles) < 10 || checked < 100 {
		t.Fatalf("checked %d names in %d schema.prisma files", checked, len(prismaFiles))
	}
}
