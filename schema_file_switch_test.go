//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

const (
	schemaSwitchNoteSQL    = "CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT);\n"
	schemaSwitchNotePrisma = "model Note {\n  id Int @id @default(autoincrement())\n  title String?\n  @@map(\"notes\")\n}\n"
)

var schemaSwitchFiles = []string{"schema.prisma", "schema.sql", "schema.yaml"}

// schemaSwitchApp writes an app with the given schema files.
func schemaSwitchApp(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	writeTestFile(t, dir, "app.yaml", "site_name: Fixture\n")
	for rel, body := range files {
		writeTestFile(t, dir, rel, body)
	}
	return dir
}

// schemaSwitchLoad loads the app as a start does and returns the tables its
// schema declares, the app tables its database holds, and the rows in notes
// (-1 without that table). exec, when set, runs against the loaded database.
func schemaSwitchLoad(t *testing.T, dir, exec string) (declared, live []string, notes int) {
	t.Helper()
	app, err := loadApp(dir)
	if err != nil {
		t.Fatalf("load app: %v", err)
	}
	defer app.Shutdown()
	if exec != "" {
		if _, err := app.DB.Exec(exec); err != nil {
			t.Fatalf("%s: %v", exec, err)
		}
	}
	for _, table := range app.Tables {
		declared = append(declared, table.Name)
	}
	sort.Strings(declared)
	rows, err := app.DB.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE '\_benmore\_%' ESCAPE '\' AND name NOT LIKE 'sqlite\_%' ESCAPE '\' ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		live = append(live, name)
	}
	notes = -1
	_ = app.DB.QueryRow(`SELECT COUNT(*) FROM notes`).Scan(&notes)
	return declared, live, notes
}

// schemaSwitchBytes reads the app's schema files; an absent file has no entry.
func schemaSwitchBytes(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, name := range schemaSwitchFiles {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err == nil {
			out[name] = string(data)
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	return out
}

// schemaSwitchNotifyPack is a pack with one static file and one model, the
// shape `benmore feature export --paths ... --models Notification` produces.
func schemaSwitchNotifyPack() (FeaturePack, map[string][]byte) {
	body := []byte("export const Notify = () => null")
	return FeaturePack{
		Name:  "Notify Hub",
		Slug:  "notify-hub",
		Files: []FeaturePackFile{{Path: "static/notify.tsx", SHA256: hashBytesSHA256(body), Size: int64(len(body))}},
		SchemaModels: []FeaturePackModel{curatedModel("Notification", `model Notification {
  id Int @id @default(autoincrement())
  title String
  @@map("notifications")
}`)},
	}, map[string][]byte{"static/notify.tsx": body}
}

func schemaSwitchCollision(plan FeatureInstallPlan) string {
	for _, c := range plan.Collisions {
		if strings.HasPrefix(c, "schema.prisma: this app's schema is ") {
			return c
		}
	}
	return ""
}

// A feature pack's models are appended to schema.prisma, and an app loads
// schema.prisma instead of schema.sql as soon as it declares a model. Into an
// app whose schema is schema.sql (or schema.yaml) the install created a
// schema.prisma holding only the pack's models: from the next load the app's
// own tables were no longer declared. It must refuse before any write and
// leave every other app as it was.
func TestFeatureInstallNeverChangesTheSchemaFileAnAppLoads(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files map[string]string
		// loads before the install: a schema.yaml app writes its schema.sql
		// on the first, so two reach the state a deployed app is in.
		loads        int
		refusedFor   string // the file the refusal names; "" = installs
		addTo        string // the file the refusal tells the builder to edit
		wantDeclared []string
	}{
		{name: "schema.prisma app", files: map[string]string{"schema.prisma": schemaSwitchNotePrisma}, loads: 2, wantDeclared: []string{"notes", "notifications"}},
		{name: "schema.sql app", files: map[string]string{"schema.sql": schemaSwitchNoteSQL}, loads: 2, refusedFor: "schema.sql", addTo: "schema.sql", wantDeclared: []string{"notes"}},
		{name: "schema.yaml app", files: map[string]string{"schema.yaml": "notes: title\n"}, loads: 2, refusedFor: "schema.sql", addTo: "schema.yaml", wantDeclared: []string{"notes"}},
		{name: "schema.yaml app never loaded", files: map[string]string{"schema.yaml": "notes: title\n"}, refusedFor: "schema.yaml", addTo: "schema.yaml"},
		{name: "both files, schema.prisma loaded", files: map[string]string{"schema.prisma": schemaSwitchNotePrisma, "schema.sql": "CREATE TABLE legacy (id INTEGER PRIMARY KEY, title TEXT);\n"}, loads: 2, wantDeclared: []string{"notes", "notifications"}},
		{name: "both files, schema.prisma without a model", files: map[string]string{"schema.prisma": "// models go here\n", "schema.sql": schemaSwitchNoteSQL}, loads: 2, refusedFor: "schema.sql", addTo: "schema.sql", wantDeclared: []string{"notes"}},
		{name: "no schema file", files: nil, wantDeclared: []string{"notifications"}},
		{name: "schema.sql that declares no table", files: map[string]string{"schema.sql": "-- tables go here\n"}, wantDeclared: []string{"notifications"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := schemaSwitchApp(t, tc.files)
			var declaredBefore []string
			seeded := false
			for i := 0; i < tc.loads; i++ {
				exec := ""
				if i == tc.loads-1 {
					exec, seeded = `INSERT INTO notes (title) VALUES ('kept')`, true
				}
				declaredBefore, _, _ = schemaSwitchLoad(t, dir, exec)
			}
			before := schemaSwitchBytes(t, dir)

			pack, files := schemaSwitchNotifyPack()
			preview, err := PlanFeatureInstallWithOptions(dir, pack, files, FeatureInstallOptions{DryRun: true})
			if err != nil {
				t.Fatal(err)
			}
			plan, applyErr := ApplyFeaturePackToDirWithOptions(dir, pack, files, FeatureInstallOptions{})
			after := schemaSwitchBytes(t, dir)

			if tc.refusedFor != "" {
				for label, p := range map[string]FeatureInstallPlan{"dry run": preview, "apply": plan} {
					msg := schemaSwitchCollision(p)
					if !p.Blocked || !strings.HasPrefix(msg, "schema.prisma: this app's schema is "+tc.refusedFor+" ") {
						t.Fatalf("%s must refuse an app whose schema is %s: blocked=%v collisions=%q", label, tc.refusedFor, p.Blocked, p.Collisions)
					}
					for _, want := range []string{"(notes)", "Nothing is installed", "Add the pack's tables to " + tc.addTo + " "} {
						if !strings.Contains(msg, want) {
							t.Fatalf("%s refusal does not say %q: %s", label, want, msg)
						}
					}
				}
				if applyErr == nil {
					t.Fatal("apply of a refused plan returned no error")
				}
				if !reflect.DeepEqual(before, after) {
					t.Fatalf("a refused install changed the schema files:\nbefore %q\nafter  %q", before, after)
				}
				if _, err := os.Stat(filepath.Join(dir, "static", "notify.tsx")); !os.IsNotExist(err) {
					t.Fatalf("a refused install wrote a pack file: %v", err)
				}
			} else {
				if preview.Blocked || plan.Blocked || applyErr != nil {
					t.Fatalf("install refused: preview=%q apply=%q err=%v", preview.Collisions, plan.Collisions, applyErr)
				}
				if !strings.Contains(after["schema.prisma"], "model Notification") || !strings.HasPrefix(after["schema.prisma"], before["schema.prisma"]) {
					t.Fatalf("the pack's model was not appended to schema.prisma: %q", after["schema.prisma"])
				}
				for _, name := range []string{"schema.sql", "schema.yaml"} {
					if before[name] != after[name] {
						t.Fatalf("the install changed %s: %q -> %q", name, before[name], after[name])
					}
				}
			}
			if tc.wantDeclared == nil {
				return
			}
			// What the app loads after the install, and on the load after that.
			for i := 0; i < 2; i++ {
				declared, live, notes := schemaSwitchLoad(t, dir, "")
				if !reflect.DeepEqual(declared, tc.wantDeclared) {
					t.Fatalf("load %d after the install declares %v, want %v (before: %v)", i+1, declared, tc.wantDeclared, declaredBefore)
				}
				for _, table := range declaredBefore {
					if !stringSliceContains(declared, table) || !stringSliceContains(live, table) {
						t.Fatalf("table %s was declared before the install and is not after it: declared %v, database %v", table, declared, live)
					}
				}
				if seeded && notes != 1 {
					t.Fatalf("notes holds %d rows after the install, want the 1 it had", notes)
				}
			}
		})
	}
}

// The refusal is about a Prisma schema landing in such an app, not about the
// app: a pack with files only installs, and a pack that carries schema.prisma
// as a file is refused like one with models, whatever replace says.
func TestFeatureInstallIntoSchemaSQLAppByPackShape(t *testing.T) {
	newApp := func(t *testing.T) (string, map[string]string) {
		dir := schemaSwitchApp(t, map[string]string{"schema.sql": schemaSwitchNoteSQL, "static/old.tsx": "old"})
		return dir, schemaSwitchBytes(t, dir)
	}
	filePack := func(whole bool, files map[string][]byte) FeaturePack {
		pack := FeaturePack{Name: "Pack", Slug: "pack", WholeSource: whole}
		for p, body := range files {
			pack.Files = append(pack.Files, FeaturePackFile{Path: p, SHA256: hashBytesSHA256(body), Size: int64(len(body))})
		}
		return pack
	}
	t.Run("files only", func(t *testing.T) {
		dir, before := newApp(t)
		files := map[string][]byte{"static/notify.tsx": []byte("export const Notify = () => null")}
		plan, err := ApplyFeaturePackToDirWithOptions(dir, filePack(false, files), files, FeatureInstallOptions{})
		if err != nil || plan.Blocked {
			t.Fatalf("a pack without a schema must install: %q, %v", plan.Collisions, err)
		}
		if _, err := os.Stat(filepath.Join(dir, "static", "notify.tsx")); err != nil {
			t.Fatalf("pack file not written: %v", err)
		}
		if after := schemaSwitchBytes(t, dir); !reflect.DeepEqual(before, after) {
			t.Fatalf("schema files changed: %q -> %q", before, after)
		}
	})
	for name, opts := range map[string]FeatureInstallOptions{
		"schema.prisma file":               {},
		"schema.prisma file, clone-over":   {Replace: true, DeleteMissing: true},
		"schema.prisma file, replace only": {Replace: true},
		"schema.prisma file, model prefix": {ModelPrefix: "Ops"},
	} {
		t.Run(name, func(t *testing.T) {
			dir, before := newApp(t)
			files := map[string][]byte{
				"app.yaml":      []byte("site_name: Source\n"),
				"schema.prisma": []byte("model Other {\n  id Int @id @default(autoincrement())\n}\n"),
			}
			pack := filePack(true, files)
			plan, err := ApplyFeaturePackToDirWithOptions(dir, pack, files, opts)
			if err == nil || !plan.Blocked || schemaSwitchCollision(plan) == "" {
				t.Fatalf("a pack that carries schema.prisma must be refused: blocked=%v collisions=%q err=%v", plan.Blocked, plan.Collisions, err)
			}
			if !strings.Contains(schemaSwitchCollision(plan), "the pack carries a schema.prisma") {
				t.Fatalf("refusal does not name the pack's file: %s", schemaSwitchCollision(plan))
			}
			if after := schemaSwitchBytes(t, dir); !reflect.DeepEqual(before, after) {
				t.Fatalf("a refused install changed the schema files: %q -> %q", before, after)
			}
			if b, _ := os.ReadFile(filepath.Join(dir, "app.yaml")); string(b) != "site_name: Fixture\n" {
				t.Fatalf("a refused install replaced app.yaml: %q", b)
			}
			if _, err := os.Stat(filepath.Join(dir, "static", "old.tsx")); err != nil {
				t.Fatalf("a refused install deleted a target file: %v", err)
			}
		})
	}
	t.Run("schema.prisma file without a model", func(t *testing.T) {
		// The loader keeps reading schema.sql beside such a file.
		dir, _ := newApp(t)
		files := map[string][]byte{"schema.prisma": []byte("// models go here\n")}
		plan, err := PlanFeatureInstallWithOptions(dir, filePack(false, files), files, FeatureInstallOptions{DryRun: true})
		if err != nil || schemaSwitchCollision(plan) != "" {
			t.Fatalf("a schema.prisma that declares no model replaces nothing: %q, %v", plan.Collisions, err)
		}
	})
}

// The same switch by hand: a schema.prisma written into an app whose schema
// is schema.sql. Refused while it leaves out a table schema.sql declares;
// accepted when it declares them all, which is how an app moves to
// schema.prisma, and that move keeps the tables and their rows.
func TestSchemaPrismaWriteKeepsTheTablesOfSchemaSQL(t *testing.T) {
	twoTables := "CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT);\nCREATE TABLE Tags (id INTEGER PRIMARY KEY AUTOINCREMENT, label TEXT);\n"
	onlyNew := "model Notification {\n  id Int @id @default(autoincrement())\n  title String\n}\n"
	withNotes := schemaSwitchNotePrisma + "\n" + onlyNew
	withAll := withNotes + "\nmodel Tag {\n  id Int @id @default(autoincrement())\n  label String?\n  @@map(\"tags\")\n}\n"

	dir := schemaSwitchApp(t, map[string]string{"schema.sql": twoTables})
	schemaSwitchLoad(t, dir, `INSERT INTO notes (title) VALUES ('kept')`)

	msg := ValidateOnWriteIn(dir, "schema.prisma", onlyNew)
	for _, want := range []string{"schema.prisma not written: this app's schema is schema.sql", ": Tags, notes.", "declare it in schema.sql", "declare every table of schema.sql as a model"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("refusal does not say %q:\n%s", want, msg)
		}
	}
	if msg := ValidateOnWriteIn(dir, "schema.prisma", withNotes); !strings.Contains(msg, ": Tags.") || strings.Contains(msg, "notes.") {
		t.Fatalf("refusal must list only the table still left out:\n%s", msg)
	}
	// Table names compare as SQLite compares them: model Tag maps to tags.
	if msg := ValidateOnWriteIn(dir, "schema.prisma", withAll); msg != "" {
		t.Fatalf("a schema.prisma that declares every table of schema.sql was refused:\n%s", msg)
	}
	// Only the root schema.prisma is the one the app loads.
	if msg := ValidateOnWriteIn(dir, "docs/schema.prisma", onlyNew); strings.Contains(msg, "not written") {
		t.Fatalf("a file that is not the app's schema.prisma was judged as it:\n%s", msg)
	}

	// The accepted write moves the app to schema.prisma with its data.
	writeTestFile(t, dir, "schema.prisma", withAll)
	for i := 0; i < 2; i++ {
		declared, live, notes := schemaSwitchLoad(t, dir, "")
		if want := []string{"Tags", "notes", "notifications"}; !reflect.DeepEqual(live, want) || notes != 1 {
			t.Fatalf("load %d after the move: database %v with %d notes, want %v with 1", i+1, live, notes, want)
		}
		for _, table := range []string{"notes", "notifications"} {
			if !stringSliceContains(declared, table) {
				t.Fatalf("load %d after the move declares %v, missing %s", i+1, declared, table)
			}
		}
	}
	// Now schema.prisma is what the app loads: a later write is not judged
	// against schema.sql, and `benmore check` reports nothing for the files
	// as they are.
	if msg := ValidateOnWriteIn(dir, "schema.prisma", withNotes); strings.Contains(msg, "not written") {
		t.Fatalf("an app that loads schema.prisma was judged against schema.sql:\n%s", msg)
	}
	writeTestFile(t, dir, "schema.prisma", withNotes)
	for _, finding := range runCheck(dir, "", false).Findings {
		if strings.Contains(finding.Message, "this app's schema is schema.sql") {
			t.Fatalf("benmore check reported the write refusal for files already in place: %+v", finding)
		}
	}

	t.Run("schema.yaml app", func(t *testing.T) {
		dir := schemaSwitchApp(t, map[string]string{"schema.yaml": "notes: title\n"})
		schemaSwitchLoad(t, dir, "")
		msg := ValidateOnWriteIn(dir, "schema.prisma", onlyNew)
		for _, want := range []string{"this app's schema is schema.sql", ": notes.", "declare it in schema.yaml"} {
			if !strings.Contains(msg, want) {
				t.Fatalf("refusal does not say %q:\n%s", want, msg)
			}
		}
	})
	t.Run("no schema.sql", func(t *testing.T) {
		if msg := ValidateOnWriteIn(schemaSwitchApp(t, nil), "schema.prisma", onlyNew); msg != "" {
			t.Fatalf("a first schema.prisma was refused:\n%s", msg)
		}
	})
}
