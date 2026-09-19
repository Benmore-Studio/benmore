//go:build !cli

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGeneratedBMTypesCompileFixture(t *testing.T) {
	tsc, err := exec.LookPath("tsc")
	if err != nil {
		// A local dev box without tsc legitimately wants a skip, but in CI a
		// missing tsc must be a hard failure: otherwise a broken provisioning
		// step (no setup-node / typescript) silently turns this drift guard
		// into a no-op and bad contracts land green. GitHub Actions sets CI=true.
		if os.Getenv("CI") != "" || os.Getenv("BM_REQUIRE_TSC") != "" {
			t.Fatal("tsc not installed but CI/BM_REQUIRE_TSC is set; the bm.d.ts compile fixture must run here")
		}
		t.Skip("tsc not installed; skipping generated bm.d.ts compile fixture")
	}

	app := &App{Tables: []Table{{
		Name: "messages",
		Columns: []Column{
			{Name: "id", Type: "INTEGER", PK: true, NotNull: true},
			{Name: "body", Type: "TEXT", NotNull: true},
			{Name: "user_id", Type: "INTEGER", NotNull: true},
			{Name: "created_at", Type: "DATETIME", NotNull: true},
		},
	}}}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bm.d.ts"), []byte(GenerateBMTypes(app)), 0644); err != nil {
		t.Fatalf("write bm.d.ts: %v", err)
	}
	// Import the bare specifier 'bm' (not './bm') so the fixture exercises the
	// SAME resolution path production agent code uses: `import * as bm from 'bm'`
	// resolved through tsconfig `paths: { "bm": ["./bm.d.ts"] }` (see the SDK
	// surface comment in bm_types.go). Importing './bm' directly would validate
	// the declarations but skip the paths mapping production depends on.
	fixture := `
import bm, { table, type Message } from 'bm';

async function validUses() {
  const msg = await table('messages').get(1);
  msg.body.toUpperCase();
  // NOTE: create(body) is typed Partial<Row>, so create({ body: 'hello' })
  // compiles even though user_id/created_at are NOT NULL. The missing-required-
  // field looseness is a pre-existing SDK type-design gap, not enforced here.
  // When the SDK tightens create() to require NOT NULL fields, add a positive
  // negative-case asserting create({}) is flagged. (Avoid writing the literal
  // ts-expect-error token in this comment - tsc would treat it as a directive.)
  const msg2: Message = await bm.table('messages').create({ body: 'hello' });
  msg2.created_at.toUpperCase();
}

async function invalidUses() {
  // @ts-expect-error unknown table names must fail at compile time
  await table('typo').list();
  // @ts-expect-error wrong field type must fail at compile time
  await table('messages').create({ body: 123 });
  const msg = await table('messages').get(1);
  // @ts-expect-error row field type must stay string
  const bad: number = msg.body;
}

void validUses;
void invalidUses;
`
	if err := os.WriteFile(filepath.Join(dir, "fixture.ts"), []byte(fixture), 0644); err != nil {
		t.Fatalf("write fixture.ts: %v", err)
	}

	// Mirror the agent's real compiler options, including the `paths` mapping
	// that resolves the bare `bm` specifier to the generated bm.d.ts. This makes
	// the fixture exercise the same module resolution as production rather than
	// a one-off single-file invocation.
	tsconfig := `{
  "compilerOptions": {
    "noEmit": true,
    "strict": true,
    "target": "ES2020",
    "module": "ESNext",
    "moduleResolution": "Bundler",
    "lib": ["ES2020", "DOM"],
    "paths": { "bm": ["./bm.d.ts"] }
  },
  "files": ["fixture.ts"]
}`
	if err := os.WriteFile(filepath.Join(dir, "tsconfig.json"), []byte(tsconfig), 0644); err != nil {
		t.Fatalf("write tsconfig.json: %v", err)
	}

	cmd := exec.Command(tsc, "--project", "tsconfig.json")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	outStr := string(out)
	// Check the unused-directive case (TS2578) BEFORE the generic err != nil
	// branch: tsc exits non-zero in both cases, so without this ordering the
	// specific "expected invalid fixture cases to produce type errors" message
	// would be unreachable and a contract regression would surface only as a
	// generic "failed typecheck".
	if strings.Contains(outStr, "TS2578") || strings.Contains(outStr, "Unused '@ts-expect-error'") {
		t.Fatalf("expected invalid fixture cases to produce type errors (an @ts-expect-error was unused):\n%s", outStr)
	}
	if err != nil {
		t.Fatalf("generated bm.d.ts fixture failed typecheck:\n%s", outStr)
	}
}
