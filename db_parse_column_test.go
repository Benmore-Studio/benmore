package main

import "testing"

func TestParseColumnDefConstraintBoundaries(t *testing.T) {
	for _, name := range []string{
		"check_status", "checkr_report_id", "check2", "checké", "check$status",
		"unique_code", "unique2", "uniqueé", "unique$code",
		"constraint_hint", "constraint2", "constrainté", "constraint$hint",
	} {
		if col := parseColumnDef(name + " TEXT"); col == nil || col.Name != name {
			t.Errorf("parseColumnDef(%q) = %#v, want column %q", name+" TEXT", col, name)
		}
	}

	tables := ParseCreateTables("CREATE TABLE sample (\n" +
		"  check_status TEXT,\n" +
		"  \"check_status\" TEXT,\n" +
		"  unique_code TEXT,\n" +
		"  \"unique_code\" TEXT,\n" +
		"  constraint_hint TEXT,\n" +
		"  \"constraint_hint\" TEXT,\n" +
		"  \"CHECK\" TEXT,\n" +
		"  \"checkr_report_id\" TEXT,\n" +
		"  PRIMARY KEY(code),\n" +
		"  FOREIGN KEY(code) REFERENCES other(code),\n" +
		"  CHECK(status <> ''),\n" +
		"  CHECK (status <> ''),\n" +
		"  UNIQUE(code),\n" +
		"  UNIQUE (code),\n" +
		"  CONSTRAINT status_check CHECK(status <> ''),\n" +
		"  PRIMARY KEY (check_status),\n" +
		"  FOREIGN KEY (unique_code) REFERENCES other(code)\n" +
		");\n")
	if len(tables) != 1 {
		t.Fatalf("ParseCreateTables returned %d tables, want 1", len(tables))
	}
	want := []string{
		"check_status", "check_status", "unique_code", "unique_code",
		"constraint_hint", "constraint_hint", "CHECK", "checkr_report_id",
	}
	if len(tables[0].Columns) != len(want) {
		t.Fatalf("got columns %v, want %v", tables[0].Columns, want)
	}
	for i, name := range want {
		if tables[0].Columns[i].Name != name {
			t.Errorf("column %d = %q, want %q", i, tables[0].Columns[i].Name, name)
		}
	}
}
