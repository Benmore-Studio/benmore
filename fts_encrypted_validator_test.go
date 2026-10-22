//go:build !cli

package main

import (
	"strings"
	"testing"
)

// TestFulltextEncryptedColumnRefused pins item 30: an encrypted column listed
// in @@fulltext breaks every INSERT on the table (the FTS5 external-content
// index desyncs when the encryption trigger rewrites the column, SQLite
// reports "database disk image is malformed"), and would index plaintext.
// Write-time validation refuses it from whichever file completes the
// conflict, and `benmore check` reports it.
func TestFulltextEncryptedColumnRefused(t *testing.T) {
	const schema = "model Note {\n  id    Int    @id @default(autoincrement())\n  title String\n  body  String @default(\"\")\n  @@fulltext([title, body])\n}\n"
	const encBody = "tables:\n  notes:\n    fields: [body]\n"
	const encOther = "tables:\n  notes:\n    fields: [secret]\n"
	const want = "fulltext-encrypted-column"

	// schema.prisma written while encrypted.yaml already encrypts body.
	dir := writeApp(t, map[string]string{"app.yaml": "seo:\n  site_name: T\n", "encrypted.yaml": encBody})
	if msg := ValidateOnWriteIn(dir, "schema.prisma", schema); !strings.Contains(msg, want) || !strings.Contains(msg, "notes.body") {
		t.Fatalf("schema.prisma write must be refused, got: %q", msg)
	}

	// encrypted.yaml written while schema.prisma already indexes body.
	dir = writeApp(t, map[string]string{"app.yaml": "seo:\n  site_name: T\n", "schema.prisma": schema})
	if msg := ValidateOnWriteIn(dir, "encrypted.yaml", encBody); !strings.Contains(msg, want) {
		t.Fatalf("encrypted.yaml write must be refused, got: %q", msg)
	}

	// Legacy app.yaml `encrypted:` section.
	if msg := ValidateOnWriteIn(dir, "app.yaml", "seo:\n  site_name: T\nencrypted:\n  notes: [body]\n"); !strings.Contains(msg, want) {
		t.Fatalf("app.yaml encrypted: section must be refused, got: %q", msg)
	}

	// Unrelated encrypted column, and fulltext without encryption, are fine.
	if msg := ValidateOnWriteIn(dir, "encrypted.yaml", encOther); strings.Contains(msg, want) {
		t.Fatalf("column outside @@fulltext must pass, got: %q", msg)
	}
	if msg := ValidateOnWriteIn(dir, "schema.prisma", schema); strings.Contains(msg, want) {
		t.Fatalf("@@fulltext without encryption must pass, got: %q", msg)
	}

	// benmore check reports the conflict as an error.
	dir = writeApp(t, map[string]string{"app.yaml": "seo:\n  site_name: T\n", "schema.prisma": schema, "encrypted.yaml": encBody})
	rpt := RunCompleteCheck(dir, "")
	found := false
	for _, f := range rpt.Findings {
		if f.Severity == "error" && strings.Contains(f.Message, want) {
			found = true
		}
	}
	if !found {
		t.Fatalf("benmore check must flag the conflict, got:\n%s", FormatReport(rpt))
	}
}
