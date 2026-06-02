//go:build !cli

package main

// Tests for the Prisma schema parser + SQL emitter. The agent's job is
// to write idiomatic Prisma; ours is to compile it to SQLite without
// surprises. Two layers of tests:
//
//   - Helpers (snake-case, pluralization, attribute splitting).
//   - End-to-end: a representative `schema.prisma` → exact SQL.

import (
	"strings"
	"testing"
)

func TestCamelToSnake(t *testing.T) {
	cases := map[string]string{
		"id":          "id",
		"userId":      "user_id",
		"firstName":   "first_name",
		"createdAt":   "created_at",
		"HTTPHeaders": "http_headers", // uppercase run + lowercase: word boundary at the last upper
		"userID":      "user_id",       // single trailing upper run still snakes correctly
		"APIKey":      "api_key",
		"":            "",
	}
	for in, want := range cases {
		if got := camelToSnake(in); got != want {
			t.Errorf("camelToSnake(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPluralizeSnake(t *testing.T) {
	cases := map[string]string{
		"User":        "users",
		"Note":        "notes",
		"Category":    "categories",
		"Box":         "boxes",
		"Class":       "classes",
		"UserSession": "user_sessions",
		"Day":         "days",     // vowel + y, keeps y → days
		"Toy":         "toys",
		"OrderItem":   "order_items",
	}
	for in, want := range cases {
		if got := pluralizeSnake(in); got != want {
			t.Errorf("pluralizeSnake(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPrismaSplitAttrs(t *testing.T) {
	// splitAttrs has to respect parens so @default(now()) doesn't get
	// broken up by the comma inside.
	in := `@id @default(autoincrement()) @map("id") @unique`
	got := splitAttrs(in)
	want := []string{
		`@id`,
		`@default(autoincrement())`,
		`@map("id")`,
		`@unique`,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d attrs, want %d: %v", len(got), len(want), got)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("attr %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestPrismaParse_BasicModel(t *testing.T) {
	src := `
model Account {
  id        Int      @id @default(autoincrement())
  email     String   @unique
  firstName String   @map("first_name")
  createdAt DateTime @default(now())
}
`
	models, err := ParsePrismaSchema(src)
	if err != nil {
		t.Fatalf("parse error: %s", err)
	}
	if len(models) != 1 {
		t.Fatalf("expected 1 model, got %d", len(models))
	}
	m := models[0]
	if m.Table != "accounts" {
		t.Errorf("table = %q, want accounts", m.Table)
	}
	if len(m.Fields) != 4 {
		t.Fatalf("expected 4 fields, got %d", len(m.Fields))
	}
	if m.Fields[2].Column != "first_name" {
		t.Errorf("first_name @map didn't take: %+v", m.Fields[2])
	}
}

func TestPrismaParse_Relation(t *testing.T) {
	// Verifies @relation FK resolution to a NON-reserved target.
	// Reserved targets (User, Session, AuditLog) drop the FK
	// silently — TestPrismaParse_RelationToReservedDropsFK covers that.
	src := `
model Account {
  id    Int    @id @default(autoincrement())
  notes Note[]
}

model Note {
  id      Int  @id @default(autoincrement())
  title   String
  ownerId Int
  owner   Account @relation(fields: [ownerId], references: [id])
}
`
	models, err := ParsePrismaSchema(src)
	if err != nil {
		t.Fatalf("parse error: %s", err)
	}
	var note PrismaModel
	for _, m := range models {
		if m.Name == "Note" {
			note = m
			break
		}
	}
	if len(note.Fields) != 3 {
		t.Fatalf("expected 3 Note fields with columns, got %d: %v", len(note.Fields), note.Fields)
	}
	var ownerIdField *PrismaField
	for i := range note.Fields {
		if note.Fields[i].Column == "owner_id" {
			ownerIdField = &note.Fields[i]
		}
	}
	if ownerIdField == nil {
		t.Fatalf("owner_id field missing in Note: %+v", note.Fields)
	}
	if ownerIdField.FKTable != "accounts" {
		t.Errorf("FKTable = %q, want accounts", ownerIdField.FKTable)
	}
}

func TestPrismaParse_RelationToReservedDropsFK(t *testing.T) {
	// Pointing @relation at User (reserved) drops the FK silently —
	// the FK would target a non-existent / empty `users` table and
	// break every INSERT. The framework's auto-CRUD ensures user_id
	// is always a valid _benmore_users.id, so no FK needed.
	src := `
model Note {
  id     Int  @id @default(autoincrement())
  title  String
  userId Int
  user   User @relation(fields: [userId], references: [id])
}
`
	models, err := ParsePrismaSchema(src)
	if err != nil {
		t.Fatalf("parse error: %s", err)
	}
	note := models[0]
	var userIdField *PrismaField
	for i := range note.Fields {
		if note.Fields[i].Column == "user_id" {
			userIdField = &note.Fields[i]
		}
	}
	if userIdField == nil {
		t.Fatalf("user_id field missing")
	}
	if userIdField.FKTable != "" {
		t.Errorf("FK should be dropped for User relation, got FKTable=%q", userIdField.FKTable)
	}
	// Emit should NOT contain a FOREIGN KEY for the user_id column.
	sql := EmitSQL(models)
	if strings.Contains(sql, "FOREIGN KEY (user_id)") {
		t.Errorf("emitted SQL should NOT have FK on user_id when @relation pointed at User:\n%s", sql)
	}
}

func TestPrismaParse_ModelUserIsReserved(t *testing.T) {
	// Declaring `model User` is rejected with a prescriptive message
	// pointing the agent at the correct pattern (just userId column,
	// no @relation).
	src := `
model User {
  id    Int    @id @default(autoincrement())
  email String @unique
}
`
	_, err := ParsePrismaSchema(src)
	if err == nil {
		t.Fatal("expected error for reserved model User")
	}
	msg := err.Error()
	for _, want := range []string{"reserved", "_benmore_users", "userId Int", "NO `@relation`"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error should mention %q, got:\n%s", want, msg)
		}
	}
}

func TestPrismaParse_BlockAttrs(t *testing.T) {
	src := `
model Item {
  id        Int    @id @default(autoincrement())
  ownerId   Int    @map("owner_id")
  status    String
  createdAt DateTime @default(now())

  @@index([ownerId, createdAt])
  @@unique([ownerId, status])
}
`
	models, err := ParsePrismaSchema(src)
	if err != nil {
		t.Fatalf("parse: %s", err)
	}
	m := models[0]
	if len(m.Indexes) != 1 || len(m.Indexes[0].Columns) != 2 {
		t.Fatalf("expected one 2-col index, got %+v", m.Indexes)
	}
	if m.Indexes[0].Columns[0] != "owner_id" {
		t.Errorf("index column not snake-cased: %v", m.Indexes[0].Columns)
	}
	if len(m.Uniques) != 1 || m.Uniques[0].Columns[1] != "status" {
		t.Errorf("unique cols: %v", m.Uniques)
	}
}

func TestPrismaEmitSQL_RoundTrip(t *testing.T) {
	// Account (not User — User is reserved) pluralizes to `accounts`.
	src := `
model Account {
  id        Int      @id @default(autoincrement())
  email     String   @unique
  firstName String   @map("first_name")
}

model Note {
  id        Int      @id @default(autoincrement())
  title     String
  body      String   @default("")
  ownerId   Int
  owner     Account  @relation(fields: [ownerId], references: [id])
  createdAt DateTime @default(now()) @map("created_at")

  @@index([ownerId, createdAt])
}
`
	models, err := ParsePrismaSchema(src)
	if err != nil {
		t.Fatalf("parse: %s", err)
	}
	sql := EmitSQL(models)

	expectations := []string{
		"CREATE TABLE IF NOT EXISTS accounts (",
		"id INTEGER PRIMARY KEY AUTOINCREMENT",
		"email TEXT NOT NULL UNIQUE",
		"first_name TEXT NOT NULL",

		"CREATE TABLE IF NOT EXISTS notes (",
		"title TEXT NOT NULL",
		"body TEXT NOT NULL DEFAULT ''",
		"owner_id INTEGER NOT NULL",
		"created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP",
		"FOREIGN KEY (owner_id) REFERENCES accounts(id)",

		"CREATE INDEX IF NOT EXISTS idx_notes_owner_id_created_at ON notes(owner_id, created_at)",
	}
	for _, want := range expectations {
		if !strings.Contains(sql, want) {
			t.Errorf("emitted SQL missing %q.\n--- got ---\n%s", want, sql)
		}
	}
}

func TestPrismaEmitSQL_NullableField(t *testing.T) {
	// `?` suffix → nullable column (no NOT NULL).
	src := `
model Item {
  id   Int     @id @default(autoincrement())
  note String?
}
`
	models, err := ParsePrismaSchema(src)
	if err != nil {
		t.Fatalf("parse: %s", err)
	}
	sql := EmitSQL(models)
	if strings.Contains(sql, "note TEXT NOT NULL") {
		t.Errorf("nullable field should NOT have NOT NULL:\n%s", sql)
	}
	if !strings.Contains(sql, "note TEXT") {
		t.Errorf("nullable field missing:\n%s", sql)
	}
}

func TestPrismaParse_SingleLineModelBody(t *testing.T) {
	// Single-line model bodies should parse — the tokenizer recognizes
	// field boundaries by the type token + attribute structure, not by
	// newlines.
	src := `model Note { id Int @id @default(autoincrement()) title String body String @default("") }`
	models, err := ParsePrismaSchema(src)
	if err != nil {
		t.Fatalf("single-line model body should parse, got: %s", err)
	}
	if len(models) != 1 {
		t.Fatalf("expected 1 model, got %d", len(models))
	}
	if len(models[0].Fields) != 3 {
		t.Fatalf("expected 3 fields, got %d: %+v", len(models[0].Fields), models[0].Fields)
	}
	wantNames := []string{"id", "title", "body"}
	for i, w := range wantNames {
		if models[0].Fields[i].Name != w {
			t.Errorf("field %d: got %q want %q", i, models[0].Fields[i].Name, w)
		}
	}
}

func TestPrismaParse_SemicolonSeparated(t *testing.T) {
	// Prisma allows `;` as a statement separator (uncommon but legal).
	src := `model Note {
  id Int @id @default(autoincrement()); title String; body String @default("")
}`
	models, err := ParsePrismaSchema(src)
	if err != nil {
		t.Fatalf("semicolon-separated model should parse, got: %s", err)
	}
	if len(models[0].Fields) != 3 {
		t.Errorf("expected 3 fields, got %d: %+v", len(models[0].Fields), models[0].Fields)
	}
}

func TestPrismaEmitSQL_TableMapping(t *testing.T) {
	// @@map overrides the auto-pluralized table name.
	src := `
model OrderItem {
  id Int @id @default(autoincrement())
  @@map("line_items")
}
`
	models, _ := ParsePrismaSchema(src)
	sql := EmitSQL(models)
	if !strings.Contains(sql, "CREATE TABLE IF NOT EXISTS line_items") {
		t.Errorf("@@map override didn't apply:\n%s", sql)
	}
}

func TestPrismaEmitSQL_UpdatedAtTrigger(t *testing.T) {
	// @updatedAt should emit an AFTER UPDATE trigger so the column
	// actually updates. Without the trigger SQLite leaves the column
	// at its insert-time value — silent data staleness.
	src := `
model Note {
  id        Int      @id @default(autoincrement())
  body      String
  updatedAt DateTime @default(now()) @updatedAt @map("updated_at")
}
`
	models, _ := ParsePrismaSchema(src)
	sql := EmitSQL(models)

	wantParts := []string{
		"CREATE TRIGGER IF NOT EXISTS trg_notes_updated_at_updated",
		"AFTER UPDATE ON notes",
		"UPDATE notes SET updated_at = CURRENT_TIMESTAMP",
	}
	for _, p := range wantParts {
		if !strings.Contains(sql, p) {
			t.Errorf("missing %q in:\n%s", p, sql)
		}
	}
}

func TestPrismaEmitSQL_UUIDDefault(t *testing.T) {
	// uuid() default should expand to lower(hex(randomblob(...))) etc
	// so SQLite can actually produce a value at insert time.
	src := `
model Item {
  id String @id @default(uuid())
}
`
	models, _ := ParsePrismaSchema(src)
	sql := EmitSQL(models)
	if !strings.Contains(sql, "lower(hex(randomblob(") {
		t.Errorf("uuid() should expand to a real SQLite expression:\n%s", sql)
	}
	// Must NOT emit `DEFAULT ''` (the v1 stub).
	if strings.Contains(sql, "id TEXT  PRIMARY KEY DEFAULT ''") {
		t.Errorf("uuid() still emitting empty-string stub:\n%s", sql)
	}
}
