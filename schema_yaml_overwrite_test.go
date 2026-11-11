//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const schemaYAMLHandWritten = "CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);\nCREATE TABLE Tags (id INTEGER PRIMARY KEY AUTOINCREMENT, label TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);\n"

// A load writes schema.sql from schema.yaml whenever schema.yaml is the newer
// file, whoever wrote the schema.sql it replaces. A schema.yaml written into
// an app with a hand-written schema.sql was accepted; the next load
// overwrote schema.sql with the shorthand's tables and the load after that
// no longer declared the app's own. The write is refused, and names the
// tables that would leave the schema.
func TestSchemaYAMLWriteKeepsAHandWrittenSchemaSQL(t *testing.T) {
	dir := schemaSwitchApp(t, map[string]string{"schema.sql": schemaYAMLHandWritten})
	schemaSwitchLoad(t, dir, `INSERT INTO notes (title) VALUES ('kept')`)

	msg := ValidateOnWriteIn(dir, "schema.yaml", "widgets: name\n")
	for _, want := range []string{"schema.yaml: this app's schema.sql is written by hand", "stop being part of the app's schema: Tags, notes.", "Declare the app's tables in schema.sql"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("refusal does not say %q:\n%s", want, msg)
		}
	}
	if msg := ValidateOnWriteIn(dir, "schema.yaml", "notes: title\nwidgets: name\n"); !strings.Contains(msg, "the app's schema: Tags.") {
		t.Fatalf("refusal must list only the table left out:\n%s", msg)
	}
	// Naming every table does not make the file safe to add: the generated
	// schema.sql still replaces the written one.
	if msg := ValidateOnWriteIn(dir, "schema.yaml", "notes: title\ntags: label\nwidgets: name\n"); !strings.Contains(msg, "written by hand") || strings.Contains(msg, "stop being part") {
		t.Fatalf("a schema.yaml that names every table must still be refused, without a table list:\n%s", msg)
	}
	// Only the root schema.yaml is the one a load reads.
	if msg := ValidateOnWriteIn(dir, "docs/schema.yaml", "widgets: name\n"); strings.Contains(msg, "written by hand") {
		t.Fatalf("a file that is not the app's schema.yaml was judged as it:\n%s", msg)
	}
	// Refused, so nothing changed: the app still declares its own tables.
	for i := 0; i < 2; i++ {
		declared, _, notes := schemaSwitchLoad(t, dir, "")
		if want := []string{"Tags", "notes"}; !reflect.DeepEqual(declared, want) || notes != 1 {
			t.Fatalf("load %d declares %v with %d notes, want %v with 1", i+1, declared, notes, want)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "schema.sql")); string(b) != schemaYAMLHandWritten {
		t.Fatalf("schema.sql changed: %q", b)
	}
	// A schema.sql that declares no table has nothing to lose.
	empty := schemaSwitchApp(t, map[string]string{"schema.sql": "-- tables go here\n"})
	if msg := ValidateOnWriteIn(empty, "schema.yaml", "widgets: name\n"); msg != "" {
		t.Fatalf("a schema.yaml beside a schema.sql without tables was refused:\n%s", msg)
	}
	// An app with a connector manifest never writes schema.sql from schema.yaml.
	if msg := schemaYAMLOverwriteProblem(schemaFileSet{sql: []byte(schemaYAMLHandWritten), connector: true}, []byte("widgets: name\n")); msg != "" {
		t.Fatalf("an app with mcp.yaml was judged:\n%s", msg)
	}

	// An app that lives in schema.yaml (its schema.sql is the generated one)
	// edits its shorthand freely, a removed table included.
	lives := schemaSwitchApp(t, map[string]string{"schema.yaml": "notes: title\ntags: label\n"})
	schemaSwitchLoad(t, lives, "")
	if generated, _ := os.ReadFile(filepath.Join(lives, "schema.sql")); !strings.HasPrefix(string(generated), "-- Auto-generated from schema.yaml") {
		t.Fatalf("the app did not write schema.sql from schema.yaml: %q", generated)
	}
	for _, edit := range []string{"notes: title\n", "notes: title, body\ntags: label\nwidgets: name\n"} {
		if msg := ValidateOnWriteIn(lives, "schema.yaml", edit); msg != "" {
			t.Fatalf("an app that lives in schema.yaml could not write %q:\n%s", edit, msg)
		}
	}
}

// `benmore check` runs the same check on the files as they are: a schema.yaml
// lying beside a hand-written schema.sql it does not cover is reported before
// a load overwrites the file, and an app that lives in schema.yaml is not.
func TestCheckReportsASchemaYAMLThatWouldReplaceSchemaSQL(t *testing.T) {
	finding := func(dir string) string {
		for _, f := range runCheck(dir, "", false).Findings {
			if f.File == "schema.yaml" && strings.Contains(f.Message, "written by hand") {
				return f.Severity + ": " + f.Message
			}
		}
		return ""
	}
	hand := schemaSwitchApp(t, map[string]string{"schema.sql": schemaYAMLHandWritten, "schema.yaml": "widgets: name\n"})
	if got := finding(hand); !strings.HasPrefix(got, "error: ") || !strings.Contains(got, "the app's schema: Tags, notes.") {
		t.Fatalf("check did not report the schema.yaml: %q", got)
	}
	lives := schemaSwitchApp(t, map[string]string{"schema.yaml": "notes: title\ntags: label\n"})
	schemaSwitchLoad(t, lives, "")
	writeTestFile(t, lives, "schema.yaml", "notes: title\n")
	if got := finding(lives); got != "" {
		t.Fatalf("check reported an app that lives in schema.yaml: %s", got)
	}
	// An app that loads schema.prisma does not read schema.sql at all.
	prisma := schemaSwitchApp(t, map[string]string{"schema.prisma": schemaSwitchNotePrisma, "schema.sql": schemaYAMLHandWritten, "schema.yaml": "widgets: name\n"})
	if got := finding(prisma); got != "" {
		t.Fatalf("check reported an app that loads schema.prisma: %s", got)
	}
}

// The install path: a pack that carries schema.yaml as a file.
func TestFeatureInstallKeepsAHandWrittenSchemaSQL(t *testing.T) {
	yamlPack := func(body string) (FeaturePack, map[string][]byte) {
		return FeaturePack{Name: "Pack", Slug: "pack", Files: []FeaturePackFile{{Path: "schema.yaml", SHA256: hashBytesSHA256([]byte(body)), Size: int64(len(body))}}},
			map[string][]byte{"schema.yaml": []byte(body)}
	}
	dir := schemaSwitchApp(t, map[string]string{"schema.sql": schemaYAMLHandWritten})
	schemaSwitchLoad(t, dir, `INSERT INTO notes (title) VALUES ('kept')`)
	pack, files := yamlPack("widgets: name\n")
	plan, err := ApplyFeaturePackToDirWithOptions(dir, pack, files, FeatureInstallOptions{})
	joined := strings.Join(plan.Collisions, "\n")
	if err == nil || !plan.Blocked || !strings.Contains(joined, "schema.yaml: this app's schema.sql is written by hand") || !strings.Contains(joined, "Nothing is installed") {
		t.Fatalf("a pack whose schema.yaml would replace a hand-written schema.sql must be refused: blocked=%v collisions=%q err=%v", plan.Blocked, plan.Collisions, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "schema.yaml")); !os.IsNotExist(err) {
		t.Fatalf("a refused install wrote schema.yaml: %v", err)
	}
	for i := 0; i < 2; i++ {
		declared, _, notes := schemaSwitchLoad(t, dir, "")
		if want := []string{"Tags", "notes"}; !reflect.DeepEqual(declared, want) || notes != 1 {
			t.Fatalf("load %d after the refused install declares %v with %d notes, want %v with 1", i+1, declared, notes, want)
		}
	}

	// An app that lives in schema.yaml takes a pack's schema.yaml with replace.
	lives := schemaSwitchApp(t, map[string]string{"schema.yaml": "notes: title\ntags: label\n"})
	schemaSwitchLoad(t, lives, "")
	pack, files = yamlPack("notes: title\n")
	if plan, err := PlanFeatureInstallWithOptions(lives, pack, files, FeatureInstallOptions{DryRun: true, Replace: true}); err != nil || plan.Blocked {
		t.Fatalf("replacing the schema.yaml of an app that lives in it was refused: %q, %v", plan.Collisions, err)
	}
}
