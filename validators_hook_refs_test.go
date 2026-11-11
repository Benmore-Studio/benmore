//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHookColumnRefWarnings(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("schema.prisma", "model Probe {\n  id   Int    @id @default(autoincrement())\n  n    Int    @default(0)\n  echo String @default(\"\")\n}\n")
	write("hooks.yaml", `on_insert:
  probes:
    - sql: "UPDATE probes SET echo = 'n={{n}} typo={{nn}} at 12:30' || COALESCE(:nnn, '') WHERE id = {{id}}"
on_update:
  probes:
    - sql: "UPDATE probes SET echo = '{{old_n}} {{old_nope}} {{env.SECRET}}' WHERE id = :id"
before_insert:
  probes:
    - sql: "SELECT RAISE(ABORT, 'no') WHERE '{{user_role}}' != 'admin' AND '{{_submitted}}' LIKE '%,n,%'"
`)
	got := strings.Join(hookColumnRefWarnings(dir), "\n")
	for _, want := range []string{"on_insert.probes[0] references :nnn, {{nn}}", "on_update.probes[0] references {{old_nope}}"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	// Columns, old_<column>, env, session keys and text inside quotes are known.
	for _, clean := range []string{"before_insert", "{{n}}", "{{id}}", "{{old_n}}", "env.SECRET", ":30", ":id"} {
		if strings.Contains(got, clean) {
			t.Errorf("false positive %q in:\n%s", clean, got)
		}
	}
}
