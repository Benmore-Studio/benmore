//go:build !cli

package main

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const (
	adoptSchemaV1 = `model Note {
  id    Int    @id @default(autoincrement())
  title String
}`
	adoptSchemaV2 = `model Note {
  id    Int    @id @default(autoincrement())
  title String
  body  String @default("")
}`
	adoptSchemaV3 = `model Note {
  id    Int    @id @default(autoincrement())
  title String
  body  String @default("")
}

model Tag {
  id    Int    @id @default(autoincrement())
  label String
}`
)

type adoptInstance struct {
	dir string
	db  *sql.DB
}

func newAdoptInstance(t *testing.T) adoptInstance {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return adoptInstance{dir: dir, db: db}
}

// load is what an instance's startup does with schema.prisma and
// migrations/: the Prisma generator, then the user-migration runner.
func (in adoptInstance) load(t *testing.T, schema string) string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(in.dir, "schema.prisma"), []byte(schema), 0o644); err != nil {
		t.Fatal(err)
	}
	name, err := ApplyPrismaMigration(in.db, in.dir, schema)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if err := RunMigrations(in.db, in.dir); err != nil {
		t.Fatalf("user migrations: %v", err)
	}
	return name
}

func (in adoptInstance) files(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(in.dir, "migrations"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names
}

func (in adoptInstance) ledger(t *testing.T) []string {
	t.Helper()
	rows, err := in.db.Query(`SELECT name FROM _benmore_migrations ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		names = append(names, n)
	}
	return names
}

// mirrorMigrations copies src's migrations/ over dst's, removing files src
// lacks, as promote's code mirror does.
func mirrorMigrations(t *testing.T, src, dst adoptInstance) {
	t.Helper()
	dstDir := filepath.Join(dst.dir, "migrations")
	if err := os.RemoveAll(dstDir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range src.files(t) {
		data, err := os.ReadFile(filepath.Join(src.dir, "migrations", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dstDir, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func columnNames(t *testing.T, db *sql.DB, table string) string {
	t.Helper()
	rows, err := db.Query(`SELECT name FROM pragma_table_info(?) ORDER BY cid`, table)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var cols []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			t.Fatal(err)
		}
		cols = append(cols, c)
	}
	return strings.Join(cols, ",")
}

func TestGeneratedMigrationNamesItsSchemaChain(t *testing.T) {
	dev := newAdoptInstance(t)
	name := dev.load(t, adoptSchemaV1)
	data, err := os.ReadFile(filepath.Join(dev.dir, "migrations", name))
	if err != nil {
		t.Fatal(err)
	}
	from, to, ok := migrationSchemaChain(string(data))
	if !ok || from != prismaModelsDigest(nil) {
		t.Fatalf("first migration chain = %q -> %q (%v)", from, to, ok)
	}
	v1, _ := ParsePrismaSchema(adoptSchemaV1)
	if to != prismaModelsDigest(v1) {
		t.Fatalf("Schema-To = %q, want digest of v1", to)
	}
	if !strings.HasPrefix(string(data), "-- Migration: ") || !strings.Contains(string(data), "\n-- UP --\n") {
		t.Fatalf("header broke the file layout:\n%s", data)
	}
	// Formatting and model order do not change the digest.
	reordered, _ := ParsePrismaSchema("model Tag {\n id Int @id @default(autoincrement())\n label String\n}\n\n" + adoptSchemaV2)
	v3, _ := ParsePrismaSchema(adoptSchemaV3)
	if prismaModelsDigest(reordered) != prismaModelsDigest(v3) {
		t.Fatal("model order changed the schema digest")
	}
}

// The reported drift: after a schema-changing promote, prod wrote its own
// migration for the change (dev 0002, prod 0003). Prod now applies dev's files
// and ends with the same migrations/ and the same schema.
func TestPromotedMigrationsAreReusedNotRegenerated(t *testing.T) {
	dev, prod := newAdoptInstance(t), newAdoptInstance(t)
	dev.load(t, adoptSchemaV1)

	// First promote: prod starts from an empty database.
	mirrorMigrations(t, dev, prod)
	if name := prod.load(t, adoptSchemaV1); name != "" {
		t.Fatalf("prod generated %s for a change dev's files cover", name)
	}
	if got, want := strings.Join(prod.files(t), " "), strings.Join(dev.files(t), " "); got != want {
		t.Fatalf("prod migrations %q, dev %q", got, want)
	}

	// Two schema changes on dev, then one promote.
	dev.load(t, adoptSchemaV2)
	dev.load(t, adoptSchemaV3)
	if n := len(dev.files(t)); n != 3 {
		t.Fatalf("dev wrote %d migrations, want 3", n)
	}
	if _, err := prod.db.Exec(`INSERT INTO notes (title) VALUES ('kept')`); err != nil {
		t.Fatal(err)
	}
	mirrorMigrations(t, dev, prod)
	if name := prod.load(t, adoptSchemaV3); name != "" {
		t.Fatalf("prod generated %s after promote", name)
	}
	if got, want := strings.Join(prod.files(t), " "), strings.Join(dev.files(t), " "); got != want {
		t.Fatalf("prod migrations %q, dev %q", got, want)
	}
	if got := strings.Join(prod.ledger(t), " "); got != strings.Join(dev.files(t), " ") {
		t.Fatalf("prod ledger %q, want each dev file once", got)
	}
	if cols := columnNames(t, prod.db, "notes"); cols != "id,title,body" {
		t.Fatalf("prod notes columns %q", cols)
	}
	if cols := columnNames(t, prod.db, "tags"); cols != "id,label" {
		t.Fatalf("prod tags columns %q", cols)
	}
	var kept int
	if err := prod.db.QueryRow(`SELECT COUNT(*) FROM notes WHERE title = 'kept'`).Scan(&kept); err != nil || kept != 1 {
		t.Fatalf("prod data lost: %d %v", kept, err)
	}
	// The snapshot the migration runner would have taken before these files.
	if backups, _ := os.ReadDir(filepath.Join(prod.dir, backupDirName)); len(backups) == 0 {
		t.Fatal("no pre-migration backup before applying the promoted files")
	}
	// The next load is a no-op: the ledger's last row records the schema.
	if name := prod.load(t, adoptSchemaV3); name != "" || len(prod.ledger(t)) != 3 {
		t.Fatalf("reload changed prod: %q %q", name, prod.ledger(t))
	}
	// And dev, refreshed from prod, still matches.
	mirrorMigrations(t, prod, dev)
	if name := dev.load(t, adoptSchemaV3); name != "" || len(dev.ledger(t)) != 3 {
		t.Fatalf("dev after refresh: %q %q", name, dev.ledger(t))
	}
}

// A hand-written migration between generated ones keeps running through the
// user-migration runner, exactly once.
func TestAdoptedChainLeavesHandWrittenMigrationsToTheRunner(t *testing.T) {
	dev, prod := newAdoptInstance(t), newAdoptInstance(t)
	dev.load(t, adoptSchemaV1)
	mirrorMigrations(t, dev, prod)
	prod.load(t, adoptSchemaV1)

	dev.load(t, adoptSchemaV2)
	handWritten := "0002_zz_backfill.sql"
	if err := os.WriteFile(filepath.Join(dev.dir, "migrations", handWritten), []byte("UPDATE notes SET body = 'filled' WHERE body = '';\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dev.load(t, adoptSchemaV2)
	dev.load(t, adoptSchemaV3)

	if _, err := prod.db.Exec(`INSERT INTO notes (title) VALUES ('old')`); err != nil {
		t.Fatal(err)
	}
	mirrorMigrations(t, dev, prod)
	if name := prod.load(t, adoptSchemaV3); name != "" {
		t.Fatalf("prod generated %s", name)
	}
	if got, want := strings.Join(prod.files(t), " "), strings.Join(dev.files(t), " "); got != want {
		t.Fatalf("prod migrations %q, dev %q", got, want)
	}
	var body string
	if err := prod.db.QueryRow(`SELECT body FROM notes WHERE title = 'old'`).Scan(&body); err != nil || body != "filled" {
		t.Fatalf("hand-written backfill did not run on prod: %q %v", body, err)
	}
	seen := map[string]int{}
	for _, n := range prod.ledger(t) {
		seen[n]++
	}
	for _, f := range prod.files(t) {
		if seen[f] != 1 {
			t.Errorf("%s recorded %d times", f, seen[f])
		}
	}
}

// Files without schema headers (written before them, or by hand) are never
// adopted: the instance generates as before and the runner replays them.
func TestHeaderlessPendingMigrationsKeepGenerating(t *testing.T) {
	dev, prod := newAdoptInstance(t), newAdoptInstance(t)
	dev.load(t, adoptSchemaV1)
	mirrorMigrations(t, dev, prod)
	prod.load(t, adoptSchemaV1)
	dev.load(t, adoptSchemaV2)
	// Strip the headers, as a file from an older runtime.
	names := dev.files(t)
	last := filepath.Join(dev.dir, "migrations", names[len(names)-1])
	data, _ := os.ReadFile(last)
	var kept []string
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, migrationSchemaFromHeader) && !strings.HasPrefix(line, migrationSchemaToHeader) {
			kept = append(kept, line)
		}
	}
	if err := os.WriteFile(last, []byte(strings.Join(kept, "\n")), 0o644); err != nil {
		t.Fatal(err)
	}
	mirrorMigrations(t, dev, prod)
	name := prod.load(t, adoptSchemaV2)
	if name == "" || !strings.HasPrefix(name, "0003_") {
		t.Fatalf("prod should generate its own migration for a headerless chain, got %q", name)
	}
	if cols := columnNames(t, prod.db, "notes"); cols != "id,title,body" {
		t.Fatalf("prod notes columns %q", cols)
	}
	ledger := strings.Join(prod.ledger(t), " ")
	if !strings.Contains(ledger, filepath.Base(last)) || !strings.Contains(ledger, name) {
		t.Fatalf("prod ledger %q should hold the replayed file and its own", ledger)
	}
}

// A chain that does not apply cleanly changes nothing and falls back to
// generation, so prod is never left half-migrated.
func TestFailingChainFallsBackToGeneration(t *testing.T) {
	dev, prod := newAdoptInstance(t), newAdoptInstance(t)
	dev.load(t, adoptSchemaV1)
	mirrorMigrations(t, dev, prod)
	prod.load(t, adoptSchemaV1)
	dev.load(t, adoptSchemaV2)
	names := dev.files(t)
	last := filepath.Join(dev.dir, "migrations", names[len(names)-1])
	data, _ := os.ReadFile(last)
	broken := strings.Replace(string(data), "-- DOWN --", "INSERT INTO missing_table VALUES (1);\n-- DOWN --", 1)
	if err := os.WriteFile(last, []byte(broken), 0o644); err != nil {
		t.Fatal(err)
	}
	mirrorMigrations(t, dev, prod)
	adopted, err := adoptPendingPrismaMigrations(context.Background(), prod.db, prod.dir, mustParse(t, adoptSchemaV1), mustParse(t, adoptSchemaV2), adoptSchemaV2, schemaHash(adoptSchemaV2), false)
	if err != nil || adopted != nil {
		t.Fatalf("broken chain adopted: %v %v", adopted, err)
	}
	if cols := columnNames(t, prod.db, "notes"); cols != "id,title" {
		t.Fatalf("abandoned chain left changes behind: %q", cols)
	}
	if got := len(prod.ledger(t)); got != 1 {
		t.Fatalf("abandoned chain left ledger rows: %v", prod.ledger(t))
	}
	// Normal generation still brings prod to the schema; the runner then
	// fails the broken file exactly as it did before adoption existed.
	name, err := ApplyPrismaMigration(prod.db, prod.dir, adoptSchemaV2)
	if err != nil || !strings.HasPrefix(name, "0003_") {
		t.Fatalf("fallback generation = %q, %v", name, err)
	}
	if cols := columnNames(t, prod.db, "notes"); cols != "id,title,body" {
		t.Fatalf("prod notes columns %q", cols)
	}
}

// Round-2 finding L6: a schema change that writes no migration file (here a
// @default change) advanced dev's ledger without a file, so dev's next file
// named a Schema-From prod never reached. Prod could not reuse it and wrote
// its own 0003 beside dev's 0002. The chain now runs from the last file, so
// both instances end with one file name.
func TestFilelessSchemaChangeKeepsThePromotedChain(t *testing.T) {
	const (
		ranked = `model Note {
  id    Int    @id @default(autoincrement())
  title String
  rank  Int    @default(5)
}`
		reranked = `model Note {
  id    Int    @id @default(autoincrement())
  title String
  rank  Int    @default(7)
}`
		flagged = `model Note {
  id    Int     @id @default(autoincrement())
  title String
  rank  Int     @default(7)
  flag  Boolean @default(false)
}`
	)
	dev, prod := newAdoptInstance(t), newAdoptInstance(t)
	dev.load(t, ranked)
	mirrorMigrations(t, dev, prod)
	prod.load(t, ranked)

	if name := dev.load(t, reranked); name != "" {
		t.Fatalf("a default change wrote %s", name)
	}
	dev.load(t, flagged)
	if n := len(dev.files(t)); n != 2 {
		t.Fatalf("dev files %v, want the create and the add", dev.files(t))
	}

	if _, err := prod.db.Exec(`INSERT INTO notes (title) VALUES ('kept')`); err != nil {
		t.Fatal(err)
	}
	mirrorMigrations(t, dev, prod)
	if name := prod.load(t, flagged); name != "" {
		t.Fatalf("prod wrote its own %s beside dev's files", name)
	}
	if got, want := strings.Join(prod.files(t), " "), strings.Join(dev.files(t), " "); got != want {
		t.Fatalf("prod migrations %q, dev %q", got, want)
	}
	if got, want := strings.Join(prod.ledger(t), " "), strings.Join(dev.files(t), " "); got != want {
		t.Fatalf("prod ledger %q, want each dev file once (%q)", got, want)
	}
	if cols := columnNames(t, prod.db, "notes"); cols != "id,title,rank,flag" {
		t.Fatalf("prod notes columns %q", cols)
	}

	// A second file-less change followed by another file still chains.
	reflagged := strings.Replace(flagged, "@default(false)", "@default(true)", 1)
	dev.load(t, reflagged)
	tagged := reflagged + "\n\nmodel Tag {\n  id    Int    @id @default(autoincrement())\n  label String\n}"
	dev.load(t, tagged)
	mirrorMigrations(t, dev, prod)
	if name := prod.load(t, tagged); name != "" {
		t.Fatalf("prod wrote its own %s after a second file-less change", name)
	}
	if got, want := strings.Join(prod.files(t), " "), strings.Join(dev.files(t), " "); got != want {
		t.Fatalf("prod migrations %q, dev %q", got, want)
	}

	// A promote of a file-less change alone leaves prod's ledger ending on a
	// row without a file as well; the next file still chains on both sides.
	retagged := strings.Replace(tagged, "label String", "label String @default(\"none\")", 1)
	dev.load(t, retagged)
	mirrorMigrations(t, dev, prod)
	if name := prod.load(t, retagged); name != "" {
		t.Fatalf("a file-less promote wrote %s on prod", name)
	}
	colored := retagged + "\n\nmodel Color {\n  id   Int    @id @default(autoincrement())\n  name String\n}"
	dev.load(t, colored)
	mirrorMigrations(t, dev, prod)
	if name := prod.load(t, colored); name != "" {
		t.Fatalf("prod wrote its own %s after promoting a file-less change", name)
	}
	if got, want := strings.Join(prod.files(t), " "), strings.Join(dev.files(t), " "); got != want {
		t.Fatalf("prod migrations %q, dev %q", got, want)
	}
}

func mustParse(t *testing.T, src string) []PrismaModel {
	t.Helper()
	models, err := ParsePrismaSchema(src)
	if err != nil {
		t.Fatal(err)
	}
	return models
}
