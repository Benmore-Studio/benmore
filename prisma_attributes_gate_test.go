//go:build !cli

package main

import (
	"strings"
	"testing"
)

func prismaAttrModel(lines string) string {
	return "model Invite {\n  id Int @id @default(autoincrement())\n" + lines + "}\n"
}

// The schema compiler applies a fixed set of attributes and skipped every
// other one, so `@uniqe`, `@unique(map: "x")` or `@@unique(fields: [a, b])`
// compiled to a column with no unique constraint while the file read as if
// it had one. The write gate and `benmore check` refuse them; the parser
// (the loader) still accepts the file.
func TestSchemaPrismaWriteGateRefusesIgnoredAttributes(t *testing.T) {
	refused := map[string]string{
		"misspelled unique":     "  token String @uniqe\n",
		"unique with args":      "  token String @unique(map: \"invite_token_key\")\n",
		"id with args":          "  code String @id(map: \"pk\")\n",
		"misspelled default":    "  status String @defualt(\"open\")\n",
		"invented attribute":    "  token String @encrypted\n",
		"bare relation":         "  ownerId Int @relation\n",
		"named-arg unique":      "  a String\n  b String\n  @@unique(fields: [a, b])\n",
		"named-arg index":       "  a String\n  @@index(fields: [a])\n",
		"misspelled block":      "  a String\n  @@uniqe([a])\n",
		"invented block":        "  a String\n  @@access(\"owner\")\n",
		"fulltext without list": "  a String\n  @@fulltext(a)\n",
	}
	for name, lines := range refused {
		src := prismaAttrModel(lines)
		if _, err := ParsePrismaSchema(src); err != nil {
			t.Fatalf("%s: the loader must keep accepting the schema: %v", name, err)
		}
		msg := ValidateOnWrite("schema.prisma", src)
		if !strings.Contains(msg, "model Invite") || !strings.Contains(msg, "not applied") {
			t.Errorf("%s: want an ignored-attribute refusal, got %q", name, msg)
		}
	}
	accepted := prismaAttrModel(
		"  token String @unique\n"+
			"  status String @default(\"open\") @map(\"invite_status\")\n"+
			"  note String @db.Text\n"+
			"  legacy String? @ignore\n"+
			"  updatedAt DateTime @default(now()) @updatedAt @map(\"updated_at\")\n"+
			"  ownerId Int @map(\"owner_id\")\n"+
			"  owner Account @relation(fields: [ownerId], references: [id])\n"+
			"  tags Tag[] @relation(\"InviteTags\")\n"+
			"  @@index([ownerId, updatedAt])\n"+
			"  @@unique([ownerId, token])\n"+
			"  @@fulltext([note])\n"+
			"  @@map(\"invites\")\n") +
		"model Account {\n  id Int @id @default(autoincrement())\n  invites Invite[]\n}\n" +
		"model Tag {\n  id Int @id @default(autoincrement())\n  label String @default(\"a @b (c)\")\n  @@ignore\n}\n" +
		"model Pair {\n  a String\n  b String\n  @@id([a, b])\n}\n"
	if msg := ValidateOnWrite("schema.prisma", accepted); msg != "" {
		t.Fatalf("supported schema refused: %s", msg)
	}
}
