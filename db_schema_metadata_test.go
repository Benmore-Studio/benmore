//go:build !cli

package main

import (
	"strconv"
	"strings"
	"testing"
)

func TestParseCreateTablesMetadataMatchesSQLite(t *testing.T) {
	fixtures := []struct {
		name string
		sql  string
	}{
		{
			name: "one-line multi-statement",
			sql: `-- leading comment
CREATE TABLE IF NOT EXISTS main.metadata_sample (id INTEGER PRIMARY KEY NOT NULL, org_id TEXT NOT NULL, "display name" TEXT, amount DECIMAL(10,2), note TEXT DEFAULT 'a b,c', expr TEXT DEFAULT ('x,y'), keyword_literal TEXT DEFAULT 'PRIMARY KEY NOT NULL', escaped TEXT DEFAULT 'it''s a b,c);', numeric REAL DEFAULT -1.25e+2, blob BLOB DEFAULT X'4142'); CREATE TABLE metadata_composite (left_id INTEGER NOT NULL, right_id INTEGER NOT NULL, PRIMARY KEY (left_id, right_id));`,
		},
		{
			name: "multiline multi-statement",
			sql: `-- leading comment
CREATE TABLE IF NOT EXISTS main.metadata_sample (
  id INTEGER PRIMARY KEY NOT NULL,
  org_id TEXT NOT NULL,
  "display name" TEXT,
  amount DECIMAL(10,2),
  note TEXT DEFAULT 'a b,c',
  expr TEXT DEFAULT ('x,y'),
  keyword_literal TEXT DEFAULT 'PRIMARY KEY NOT NULL',
  escaped TEXT DEFAULT 'it''s a b,c);',
  numeric REAL DEFAULT -1.25e+2,
  blob BLOB DEFAULT X'4142'
);
CREATE TABLE metadata_composite (
  left_id INTEGER NOT NULL,
  right_id INTEGER NOT NULL,
  PRIMARY KEY (left_id, right_id)
);`,
		},
	}

	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			app, cleanup := newTestApp(t)
			defer cleanup()
			writeTestFile(t, app.Dir, "schema.sql", fixture.sql)

			parsed, _, err := LoadSchema(app.DB, app.Dir)
			if err != nil {
				t.Fatalf("LoadSchema: %v", err)
			}
			if len(parsed) != 2 {
				t.Fatalf("LoadSchema parsed %d tables, want 2: %#v", len(parsed), parsed)
			}

			for i, tableName := range []string{"metadata_sample", "metadata_composite"} {
				live, err := GetTableColumns(app.DB, tableName)
				if err != nil {
					t.Fatalf("GetTableColumns(%q): %v", tableName, err)
				}
				if len(parsed[i].Columns) != len(live) {
					t.Fatalf("%s parsed %d columns, SQLite has %d: parsed=%#v live=%#v", tableName, len(parsed[i].Columns), len(live), parsed[i].Columns, live)
				}
				for j := range live {
					got, want := parsed[i].Columns[j], live[j]
					if strings.HasPrefix(got.Default, "(") && strings.HasSuffix(got.Default, ")") {
						got.Default = got.Default[1 : len(got.Default)-1]
					}
					if got != want {
						t.Errorf("%s column %d metadata = %+v, SQLite reports %+v", tableName, j, got, want)
					}
				}
			}
		})
	}
}

func TestParseColumnDefaultRemainsExecutable(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	if _, err := app.DB.Exec("CREATE TABLE default_roundtrip (id INTEGER)"); err != nil {
		t.Fatal(err)
	}
	col := parseColumnDef("note TEXT DEFAULT (lower('A B,C'))")
	if col == nil || col.Default != "(lower('A B,C'))" {
		t.Fatalf("lost executable expression: %#v", col)
	}
	if _, err := app.DB.Exec(buildAlterAdd("default_roundtrip", *col)); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec("INSERT INTO default_roundtrip(id) VALUES(1)"); err != nil {
		t.Fatal(err)
	}
	var note string
	if err := app.DB.QueryRow("SELECT note FROM default_roundtrip").Scan(&note); err != nil || note != "a b,c" {
		t.Fatalf("default value %q: %v", note, err)
	}
}

func TestSetDefaultActionsPreserveColumnDefault(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	if _, err := app.DB.Exec(`PRAGMA foreign_keys=ON`); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec(`CREATE TABLE parents (id INTEGER PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec(`INSERT INTO parents(id) VALUES (7)`); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec(`CREATE TABLE reference_fixture (id INTEGER PRIMARY KEY, parent_id INTEGER DEFAULT 7 REFERENCES parents(id) ON DELETE SET DEFAULT)`); err != nil {
		t.Fatalf("create REFERENCES fixture: %v", err)
	}
	if _, err := app.DB.Exec(`CREATE TABLE child (id INTEGER PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}

	for _, action := range []string{"ON DELETE SET DEFAULT", "ON UPDATE SET DEFAULT"} {
		t.Run(action, func(t *testing.T) {
			col := parseColumnDef("parent_id INTEGER DEFAULT 7 REFERENCES parents(id) " + action)
			if col == nil || col.Default != "7" {
				t.Fatalf("parsed default = %#v, want raw 7", col)
			}
			if _, err := app.DB.Exec("DROP TABLE IF EXISTS child; CREATE TABLE child (id INTEGER PRIMARY KEY)"); err != nil {
				t.Fatal(err)
			}
			if _, err := app.DB.Exec(buildAlterAdd("child", *col)); err != nil {
				t.Fatalf("buildAlterAdd: %v", err)
			}
			if _, err := app.DB.Exec(`INSERT INTO child(id) VALUES (1)`); err != nil {
				t.Fatalf("insert using column default: %v", err)
			}
			var got int
			if err := app.DB.QueryRow(`SELECT parent_id FROM child WHERE id=1`).Scan(&got); err != nil || got != 7 {
				t.Fatalf("inserted default = %d, want 7 (err=%v)", got, err)
			}
		})
	}
}

func TestAdjacentCheckNotNullMetadataDoesNotRebuild(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	const schema = `CREATE TABLE adjacency_sample (id INTEGER PRIMARY KEY, value TEXT CHECK(length(value)>0)NOT NULL, fallback TEXT DEFAULT('x') NOT NULL, literal TEXT DEFAULT 'CHECK NOT NULL')`
	if _, err := app.DB.Exec(schema); err != nil {
		t.Fatal(err)
	}
	tables := ParseCreateTables(schema)
	if len(tables) != 1 || len(tables[0].Columns) != 4 {
		t.Fatalf("parsed tables = %#v", tables)
	}
	parsedValue := tables[0].Columns[1]
	if !parsedValue.NotNull {
		t.Fatalf("adjacent CHECK...NOT NULL parsed as nullable: %+v", parsedValue)
	}
	live, err := GetTableColumns(app.DB, "adjacency_sample")
	if err != nil {
		t.Fatalf("GetTableColumns: %v", err)
	}
	if parsedValue.NotNull != live[1].NotNull {
		t.Fatalf("parsed NotNull=%v, SQLite NotNull=%v", parsedValue.NotNull, live[1].NotNull)
	}
	if got := tables[0].Columns[2]; !got.NotNull || got.Default != "('x')" {
		t.Errorf("DEFAULT('x') NOT NULL parsed as %+v", got)
	}
	if got := tables[0].Columns[3]; got.NotNull || got.Default != "'CHECK NOT NULL'" {
		t.Errorf("literal constraint words misclassified: %+v", got)
	}
	result, err := Migrate(app.DB, tables, true)
	if err != nil {
		t.Fatalf("Migrate(force=true): %v", err)
	}
	for _, change := range result.Added {
		if strings.Contains(change, "REBUILD") {
			t.Fatalf("unexpected nullability rebuild: %v", result.Added)
		}
	}
	if _, err := app.DB.Exec(`INSERT INTO adjacency_sample(id, value) VALUES (1, NULL)`); err == nil {
		t.Fatal("NULL insert succeeded; original NOT NULL constraint was lost")
	}
}

func TestParseNumericDefaultRemainsExecutable(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	cases := []struct {
		literal string
		want    float64
	}{
		{"1.e+2", 100},
		{"1.e2", 100},
		{"1.e-2", .01},
		{".5e-2", .005},
		{"- 1.e+2", -100},
		{"1.25e+2", 125},
		{"1e2", 100},
		{"0x10", 16},
	}
	for i, tc := range cases {
		t.Run(tc.literal, func(t *testing.T) {
			table := "numeric_default_" + strconv.Itoa(i)
			col := parseColumnDef("amount REAL DEFAULT " + tc.literal)
			if col == nil || col.Default != tc.literal {
				t.Fatalf("parsed default = %#v, want raw %q", col, tc.literal)
			}
			if _, err := app.DB.Exec("CREATE TABLE " + table + " (id INTEGER PRIMARY KEY)"); err != nil {
				t.Fatalf("create fixture: %v", err)
			}
			if _, err := app.DB.Exec(buildAlterAdd(table, *col)); err != nil {
				t.Fatalf("buildAlterAdd: %v", err)
			}
			if _, err := app.DB.Exec("INSERT INTO " + table + " (id) VALUES (1)"); err != nil {
				t.Fatalf("insert using column default: %v", err)
			}
			var got float64
			if err := app.DB.QueryRow("SELECT amount FROM " + table + " WHERE id = 1").Scan(&got); err != nil {
				t.Fatalf("read default: %v", err)
			}
			if got != tc.want {
				t.Fatalf("default value = %v, want %v", got, tc.want)
			}
		})
	}
}
