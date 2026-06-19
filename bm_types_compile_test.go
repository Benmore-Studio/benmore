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
	fixture := `
import bm, { table, type Message } from './bm';

async function validUses() {
  const msg = await table('messages').get(1);
  msg.body.toUpperCase();
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

	cmd := exec.Command(tsc,
		"--noEmit",
		"--strict",
		"--target", "ES2020",
		"--module", "ESNext",
		"--moduleResolution", "Bundler",
		"--lib", "ES2020,DOM",
		"fixture.ts",
	)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("generated bm.d.ts fixture failed typecheck:\n%s", string(out))
	}
	if strings.Contains(string(out), "Unused '@ts-expect-error'") {
		t.Fatalf("expected invalid fixture cases to produce type errors:\n%s", string(out))
	}
}
