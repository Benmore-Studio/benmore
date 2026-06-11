package main

import (
	"strings"
	"testing"
)

// TestGenerateBMTypes_BasicShape pins the most-load-bearing pieces of
// the .d.ts output. Failures here mean the agent's editor stops
// autocompleting correctly - high-leverage to catch fast.
func TestGenerateBMTypes_BasicShape(t *testing.T) {
	app := &App{
		Tables: []Table{
			{
				Name: "messages",
				Columns: []Column{
					{Name: "id", Type: "INTEGER", PK: true, NotNull: true},
					{Name: "body", Type: "TEXT", NotNull: true},
					{Name: "user_id", Type: "INTEGER", NotNull: true},
					{Name: "created_at", Type: "DATETIME", NotNull: true},
				},
			},
			{
				Name: "admin_logs",
				Columns: []Column{
					{Name: "id", Type: "INTEGER", PK: true, NotNull: true},
					{Name: "event", Type: "TEXT", NotNull: true},
					{Name: "payload", Type: "TEXT"},
					{Name: "created_at", Type: "DATETIME", NotNull: true},
				},
			},
			{
				Name: "_benmore_users",
				Columns: []Column{
					{Name: "id", Type: "INTEGER", PK: true, NotNull: true},
					{Name: "email", Type: "TEXT", NotNull: true},
					{Name: "first_name", Type: "TEXT"},
					{Name: "password_hash", Type: "TEXT"}, // sensitive - must be filtered
					{Name: "mfa_last_totp", Type: "TEXT"}, // sensitive - must be filtered
					{Name: "role", Type: "TEXT", NotNull: true},
				},
			},
			{
				Name: "_benmore_sessions",
				Columns: []Column{ // framework-internal - must be hidden from TS
					{Name: "id", Type: "TEXT"},
				},
			},
		},
	}

	out := GenerateBMTypes(app)

	mustContain := []string{
		"export interface Message {",
		"export interface AdminLog {",
		"id: number;",
		"body: string;",
		"created_at: string;", // datetimes → string
		"export interface User {",
		"export type TableName = 'admin_logs' | 'messages';", // sorted
		"declare const bm:", // post-2.7.18: flat top-level layout (no `declare module 'bm' {}` wrapper - broke `export default bm` with TS2666)
		"export function table<T extends keyof TableTypeMap>(",
		"): TableClient<TableTypeMap[T], TableFeatures[T]>;",
		// New v2.7.16 sections - every type the agent might land on:
		"export type Role =",
		"export type AggregateName",
		"export interface AggregateMap {",
		"export interface WorkflowMap {",
		"export interface FlowMap {",
		"export type I18nKey",
		"export interface Notification {",
		"export interface AuditEntry {",
		"export interface Job<T = unknown> {",
		"export interface TableFeatures {",
		"export const aggregates:",
		"export const jobs:",
		"export const notifications:",
		"export const audit:",
		"export const permissions:",
		"export function workflow<T extends keyof WorkflowMap>(",
		"export function aggregate<K extends AggregateName>(name: K)",
		"export function upload(",
		"export function signedUrl(",
		"export function t(key: I18nKey,",
		"export const mfa:",
		// post-2.7.18: two-overload live() (typed per table + '*' wildcard)
		"export function live<T extends keyof TableTypeMap>(",
		"export function room(name: string): RoomClient;",
	}
	for _, s := range mustContain {
		if !strings.Contains(out, s) {
			t.Errorf("expected output to contain %q\n--- output ---\n%s", s, out)
		}
	}

	mustNotContain := []string{
		"password_hash",         // sensitive - must not leak
		"mfa_last_totp",         // sensitive - must not leak
		"_benmore_sessions",     // framework-internal - hidden
		"export interface BenmoreSessions",
	}
	for _, s := range mustNotContain {
		if strings.Contains(out, s) {
			t.Errorf("expected output to NOT contain %q (would leak sensitive/internal)", s)
		}
	}
}

// TestGenerateBMTypes_Fingerprint pins the schema-fingerprint stability
// - same input → same hash; small change → different hash. The CLI's
// drift check depends on this.
func TestGenerateBMTypes_Fingerprint(t *testing.T) {
	mk := func() *App {
		return &App{Tables: []Table{
			{Name: "x", Columns: []Column{
				{Name: "id", Type: "INTEGER", PK: true, NotNull: true},
				{Name: "name", Type: "TEXT"},
			}},
		}}
	}
	a, b := mk(), mk()
	if tablesFingerprint(a) != tablesFingerprint(b) {
		t.Fatal("fingerprint should be stable for identical schemas")
	}

	// Now alter b's columns. Hash must change.
	b.Tables[0].Columns[1].Type = "INTEGER"
	if tablesFingerprint(a) == tablesFingerprint(b) {
		t.Fatal("fingerprint should change when a column type changes")
	}

	// Adding a new column must also change it.
	b = mk()
	b.Tables[0].Columns = append(b.Tables[0].Columns, Column{Name: "extra", Type: "TEXT"})
	if tablesFingerprint(a) == tablesFingerprint(b) {
		t.Fatal("fingerprint should change when a column is added")
	}
}

func TestPrismaToTS(t *testing.T) {
	cases := map[string]string{
		"INTEGER":      "number",
		"INT":          "number",
		"BIGINT":       "number",
		"TEXT":         "string",
		"VARCHAR(255)": "string",
		"DATETIME":     "string",
		"DATE":         "string",
		"BOOLEAN":      "boolean",
		"BOOL":         "boolean",
		"REAL":         "number",
		"FLOAT":        "number",
		"JSON":         "Record<string, unknown> | unknown[]",
	}
	for in, want := range cases {
		if got := prismaToTS(in); got != want {
			t.Errorf("prismaToTS(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSingularize(t *testing.T) {
	cases := map[string]string{
		"messages":   "message",
		"users":      "user",
		"admin_logs": "admin_log",
		"stories":    "story",
		"categories": "category",
		"boxes":      "box",
		"address":    "address", // already singular-ish
	}
	for in, want := range cases {
		if got := singularize(in); got != want {
			t.Errorf("singularize(%q) = %q, want %q", in, got, want)
		}
	}
}
