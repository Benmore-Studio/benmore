//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An access: rule that names a table missing from the schema binds nothing:
// the real table keeps its implicit default, and `benmore check` warns. An
// encrypted field naming a missing table or column stops the app loading, so
// it is an error on encrypted.yaml (validators_load_refs.go), not a warning.
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
	for _, want := range []string{"access.note names a table"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing warning %q in:\n%s", want, got)
		}
	}
	for _, bad := range []string{"access.notes ", "access.default", "access._benmore_users", "secret_note", "bodyy", "memos"} {
		if strings.Contains(got, bad) {
			t.Errorf("false or duplicate warning %q in:\n%s", bad, got)
		}
	}
	enc, _ := os.ReadFile(filepath.Join(dir, "encrypted.yaml"))
	refusal := ValidateOnWriteIn(dir, "encrypted.yaml", string(enc))
	for _, want := range []string{"notes.bodyy is an encrypted field", `the table "memos"`} {
		if !strings.Contains(refusal, want) {
			t.Errorf("encrypted.yaml error lacks %q:\n%s", want, refusal)
		}
	}
	if strings.Contains(refusal, "notes.secret_note is") {
		t.Errorf("mapped column refused:\n%s", refusal)
	}
}
