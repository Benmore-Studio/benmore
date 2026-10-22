//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An access: rule or an encrypted field that names a table/column missing
// from the schema binds nothing: the real table keeps its implicit default
// and the real column is stored in plaintext. `benmore check` warns.
func TestCrossFileWarnsOnUnboundAccessAndEncryption(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("schema.prisma", "model Note {\n  id Int @id @default(autoincrement())\n  body String\n  secretNote String @map(\"secret_note\")\n  userId Int @map(\"user_id\")\n}\n")
	write("app.yaml", "site_name: x\naccess:\n  default:\n    read: admin\n  note: admin\n  notes: self\n  _benmore_users:\n    read: group\n")
	write("encrypted.yaml", "tables:\n  notes:\n    fields: [bodyy, secret_note]\n  memos:\n    fields: [x]\n")
	got := strings.Join(CrossFileWarnings(dir, ""), "\n")
	for _, want := range []string{"access.note names a table", "notes.bodyy is not a column", "table \"memos\" is not in schema"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing warning %q in:\n%s", want, got)
		}
	}
	for _, bad := range []string{"access.notes ", "access.default", "access._benmore_users", "notes.secret_note"} {
		if strings.Contains(got, bad) {
			t.Errorf("false warning %q in:\n%s", bad, got)
		}
	}
}
