//go:build !cli

package main

import (
	"strings"
	"testing"
)

func relationActionSchema(pointer, reverse string) string {
	return `model Channel {
  id Int @id @default(autoincrement())
  members Member[] ` + reverse + `
}
model Member {
  id Int @id @default(autoincrement())
  channelId Int @map("channel_id")
  channel Channel ` + pointer + `
}
`
}

// The hosted bulletin accepted onDelete: Cascade, but emitted a bare FK:
// deleting a parent with members correctly returned 409. Refuse the ignored
// declaration at authoring time without changing existing app loading or DDL.
func TestPrismaRelationActionsRefusedByWriteAndCheck(t *testing.T) {
	for _, tc := range []struct{ name, pointer, reverse, action, field string }{
		{"delete cascade", `@relation(fields: [channelId], references: [id], onDelete: Cascade)`, "", "onDelete", "channel"},
		{"update cascade first", `@relation(onUpdate: Cascade, fields: [channelId], references: [id])`, "", "onUpdate", "channel"},
		{"named delete restrict", `@relation("Membership", fields: [channelId], onDelete : Restrict, references: [id])`, "", "onDelete", "channel"},
		{"delete no action", `@relation(fields: [channelId], references: [id], onDelete: NoAction)`, "", "onDelete", "channel"},
		{"reverse delete", `@relation(fields: [channelId], references: [id])`, `@relation("Membership", onDelete: SetNull)`, "onDelete", "members"},
		{"reverse update", `@relation(fields: [channelId], references: [id])`, `@relation(onUpdate: Restrict)`, "onUpdate", "members"},
		{"quoted name then real action", `@relation("onDelete: Cascade", fields: [channelId], references: [id], onUpdate: Cascade)`, "", "onUpdate", "channel"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := relationActionSchema(tc.pointer, tc.reverse)
			models, err := ParsePrismaSchema(src)
			if err != nil {
				t.Fatalf("existing loader compatibility: %v", err)
			}
			ddl := EmitSQL(models)
			if strings.Contains(strings.ToUpper(ddl), "ON DELETE") || strings.Contains(strings.ToUpper(ddl), "ON UPDATE") {
				t.Fatalf("loader unexpectedly applies actions: %s", ddl)
			}
			msg := ValidateOnWrite("schema.prisma", src)
			if !strings.Contains(msg, tc.action) || !strings.Contains(msg, "not applied") || !strings.Contains(msg, "field "+tc.field) {
				t.Errorf("write gate accepted ignored action or lacked location: %q", msg)
			}
			dir := writeApp(t, map[string]string{"app.yaml": "site_name: Bulletin\n", "schema.prisma": src})
			for name, report := range map[string]CheckReport{"source": RunSourceCheck(dir, "schema.prisma"), "complete": RunCompleteCheck(dir, "schema.prisma")} {
				found := false
				for _, f := range report.Findings {
					if f.Source == "syntax" && f.File == "schema.prisma" && f.Severity == "error" && strings.Contains(f.Message, tc.action) {
						found = true
					}
				}
				if !found {
					t.Errorf("%s check did not refuse ignored action: %s", name, FormatReport(report))
				}
			}
		})
	}
}

func TestPrismaRelationActionsPreserveSupportedRelations(t *testing.T) {
	for _, name := range []string{`"Membership"`, `"onDelete: Cascade, onUpdate: Restrict"`, `"quoted \"onDelete: Cascade\", onUpdate: Restrict"`} {
		src := relationActionSchema(`@relation(`+name+`, fields: [channelId], references: [id])`, `@relation(`+name+`)`)
		if msg := ValidateOnWrite("schema.prisma", src); msg != "" {
			t.Errorf("relation name/fields/references rejected: %s", msg)
		}
	}
	src := relationActionSchema(`@relation(fields: [channelId], references: [id])`, "")
	models, err := ParsePrismaSchema(src)
	if err != nil {
		t.Fatal(err)
	}
	if ddl := EmitSQL(models); !strings.Contains(ddl, `FOREIGN KEY (channel_id) REFERENCES channels(id)`) {
		t.Fatalf("supported foreign key missing: %s", ddl)
	}
	dir := writeApp(t, map[string]string{"app.yaml": "site_name: Bulletin\n", "schema.prisma": src})
	if report := RunCompleteCheck(dir, "schema.prisma"); !report.Clean() {
		t.Fatalf("supported relation check failed: %s", FormatReport(report))
	}
}
