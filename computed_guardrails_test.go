//go:build !cli && !windows

package main

import (
	"strings"
	"testing"
)

// computed.yaml: the write gate refuses what the load refuses, with the
// load's message; a declaration that installs nothing (while the column is
// still taken away from clients) is refused; and a field's expr or sql is one
// expression, so it cannot carry statements into the trigger it becomes.

const computedGuardSchema = `model Order {
  id        Int      @id @default(autoincrement())
  title     String   @default("")
  quantity  Int      @default(1)
  unitPrice Float    @default(0) @map("unit_price")
  lineTotal Float    @default(0) @map("line_total")
  itemCount Int      @default(0) @map("item_count")
}

model Item {
  id      Int    @id @default(autoincrement())
  orderId Int?   @map("order_id")
  name    String @default("")
}

model Victim {
  id   Int    @id @default(autoincrement())
  name String @default("")
}
`

func computedGuardDir(t *testing.T, computedYAML string) string {
	t.Helper()
	dir := t.TempDir()
	writeTestFile(t, dir, "app.yaml", "auth:\n  identifier: email\n")
	writeTestFile(t, dir, "schema.prisma", computedGuardSchema)
	if computedYAML != "" {
		writeTestFile(t, dir, "computed.yaml", computedYAML)
	}
	return dir
}

// computedLoadError loads the app as a start does and returns its error text.
func computedLoadError(t *testing.T, computedYAML string) (dir, loadErr string) {
	t.Helper()
	dir = computedGuardDir(t, computedYAML)
	app, err := loadApp(dir)
	if err != nil {
		return dir, err.Error()
	}
	app.Shutdown()
	return dir, ""
}

const computedItemCount = "  - table: orders\n    column: item_count\n    sql: \"SELECT COUNT(*) FROM items WHERE order_id = ?\"\n    triggers:\n      - table: items\n        on: [insert, update, delete]\n        fk: order_id\n"

// Every file here fails the load. The gate accepted each of them, so the push
// succeeded and the reload (or the next start) failed.
func TestComputedGateRefusesWhatTheLoadRefuses(t *testing.T) {
	cases := map[string]string{
		"sql with two placeholders":  "fields:\n  - table: orders\n    column: item_count\n    sql: \"SELECT COUNT(*) FROM items WHERE order_id = ? AND id > ?\"\n    triggers:\n      - table: items\n        on: [insert]\n        fk: order_id\n",
		"sql with a named parameter": "fields:\n  - table: orders\n    column: item_count\n    sql: \"SELECT COUNT(*) FROM items WHERE order_id = ? AND name = :name\"\n    triggers:\n      - table: items\n        on: [insert]\n        fk: order_id\n",
		"expr with a placeholder":    "fields:\n  - table: orders\n    column: line_total\n    expr: \"quantity * ?\"\n",
		"field without table":        "fields:\n  - column: line_total\n    expr: \"quantity * unit_price\"\n",
		"field without column":       "fields:\n  - table: orders\n    expr: \"quantity * unit_price\"\n",
		"fields a scalar":            "fields: orders\n",
		"field not a mapping":        "fields:\n  - orders\n",
		"expr that does not parse":   "fields:\n  - table: orders\n    column: line_total\n    expr: \"quantity * * unit_price\"\n",
		"expr with unknown function": "fields:\n  - table: orders\n    column: line_total\n    expr: \"no_such_function(quantity)\"\n",
		"sql that does not parse":    "fields:\n  - table: orders\n    column: item_count\n    sql: \"SELECT COUNT(* FROM items WHERE order_id = ?\"\n    triggers:\n      - table: items\n        on: [insert]\n        fk: order_id\n",
		"expr ending in a comment":   "fields:\n  - table: orders\n    column: line_total\n    expr: \"quantity * unit_price -- total\"\n",
		"trigger without fk":         "fields:\n  - table: orders\n    column: item_count\n    sql: \"SELECT COUNT(*) FROM items WHERE order_id = ?\"\n    triggers:\n      - table: items\n        on: [insert]\n",
		"on a scalar":                "fields:\n  - table: orders\n    column: item_count\n    sql: \"SELECT COUNT(*) FROM items WHERE order_id = ?\"\n    triggers:\n      - table: items\n        on: insert\n        fk: order_id\n",
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			dir, loadErr := computedLoadError(t, doc)
			if loadErr == "" {
				t.Fatal("the fixture is wrong: the load accepts this file")
			}
			gate := ValidateOnWriteIn(dir, "computed.yaml", doc)
			if gate == "" {
				t.Fatalf("the load refuses the file (%s); the gate accepted it", loadErr)
			}
			if !strings.Contains(gate, "computed.yaml") {
				t.Errorf("the refusal must name the file, got %q", gate)
			}
		})
	}
}

// What the load installs without a word the gate accepts.
func TestComputedGateAcceptsWhatTheLoadRuns(t *testing.T) {
	cases := map[string]string{
		"list form":         "fields:\n  - table: orders\n    column: line_total\n    expr: \"quantity * unit_price\"\n" + computedItemCount,
		"nested form":       "orders:\n  line_total:\n    expr: \"quantity * unit_price\"\n  item_count:\n    sql: \"SELECT COUNT(*) FROM items WHERE order_id = ?\"\n    triggers:\n      - table: items\n        on: [insert, update, delete]\n        fk: order_id\n",
		"comment and case":  "fields:\n  - table: orders\n    column: line_total\n    expr: |\n      CASE WHEN quantity > 10 THEN quantity * unit_price * 0.9 -- bulk\n      ELSE quantity * unit_price END\n",
		"quoted semicolon":  "fields:\n  - table: orders\n    column: title\n    expr: \"'n; ' || quantity || ' (?)'\"\n",
		"wrapped subselect": "fields:\n  - table: orders\n    column: item_count\n    sql: \"COALESCE((SELECT COUNT(*) FROM items WHERE order_id = ?), 0)\"\n    triggers:\n      - table: items\n        on: [insert, delete]\n        fk: order_id\n",
		"empty list":        "fields: []\n",
		"empty file":        "",
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			dir, loadErr := computedLoadError(t, doc)
			if loadErr != "" {
				t.Fatalf("the fixture is wrong: the load refuses this file: %s", loadErr)
			}
			if gate := ValidateOnWriteIn(dir, "computed.yaml", doc); gate != "" {
				t.Fatalf("the load runs the file; the gate refused it: %s", gate)
			}
		})
	}
}

// Declarations that install no trigger still take the column away from every
// client write, so it can be neither written nor calculated. The load keeps
// accepting a deployed file (and says so); the gate refuses the next write.
func TestComputedGateRefusesDeclarationsThatInstallNothing(t *testing.T) {
	cases := map[string]struct{ doc, want string }{
		"trigger without on":       {"fields:\n  - table: orders\n    column: item_count\n    sql: \"SELECT COUNT(*) FROM items WHERE order_id = ?\"\n    triggers:\n      - table: items\n        fk: order_id\n", "on:"},
		"unknown events":           {"fields:\n  - table: orders\n    column: item_count\n    sql: \"SELECT COUNT(*) FROM items WHERE order_id = ?\"\n    triggers:\n      - table: items\n        on: [create, remove]\n        fk: order_id\n", `"create"`},
		"sql without triggers":     {"fields:\n  - table: orders\n    column: item_count\n    sql: \"SELECT COUNT(*) FROM items WHERE order_id = ?\"\n", "triggers:"},
		"misspelled expr":          {"fields:\n  - table: orders\n    column: line_total\n    expression: \"quantity * unit_price\"\n", `"expression"`},
		"misspelled expr, nested":  {"orders:\n  line_total:\n    expression: \"quantity * unit_price\"\n", `"expression"`},
		"neither expr nor sql":     {"fields:\n  - table: orders\n    column: line_total\n", "expr"},
		"both expr and sql":        {"fields:\n  - table: orders\n    column: item_count\n    expr: \"quantity\"\n    sql: \"SELECT COUNT(*) FROM items WHERE order_id = ?\"\n    triggers:\n      - table: items\n        on: [insert]\n        fk: order_id\n", "both"},
		"misspelled trigger key":   {"fields:\n  - table: orders\n    column: item_count\n    sql: \"SELECT COUNT(*) FROM items WHERE order_id = ?\"\n    triggers:\n      - table: items\n        on: [insert]\n        fk: order_id\n        when: \"1\"\n", `"when"`},
		"fields beside table keys": {"fields:\n  - table: orders\n    column: line_total\n    expr: \"quantity * unit_price\"\norders:\n  item_count:\n    expr: \"quantity\"\n", `"orders"`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			dir, loadErr := computedLoadError(t, tc.doc)
			if loadErr != "" {
				t.Fatalf("a deployed file in this form must keep loading, got %s", loadErr)
			}
			gate := ValidateOnWriteIn(dir, "computed.yaml", tc.doc)
			if !strings.Contains(gate, "computed.yaml") || !strings.Contains(gate, tc.want) {
				t.Fatalf("the gate must refuse it and name %s, got %q", tc.want, gate)
			}
		})
	}
}

// `benmore check` reads the files from disk through the same gate.
func TestCheckReportsComputedAndAggregateProblems(t *testing.T) {
	dir := computedGuardDir(t, "fields:\n  - table: orders\n    column: line_total\n    expression: \"quantity * unit_price\"\n")
	writeTestFile(t, dir, "app.yaml", "auth:\n  identifier: email\naggregates:\n  sneaky:\n    sql: \"DELETE FROM orders RETURNING id\"\n    refresh: 5m\n")
	found := map[string]bool{}
	for _, f := range RunSourceCheck(dir, "").Findings {
		if f.Severity == "error" && f.Source == "syntax" {
			found[f.File] = found[f.File] || strings.Contains(f.Message, "not calculated") || strings.Contains(f.Message, "read-only")
		}
	}
	if !found["computed.yaml"] || !found["app.yaml"] {
		t.Fatalf("benmore check must report the field that is not calculated and the aggregate that writes, got %v", found)
	}
}

// The load says which declared fields are not calculated.
func TestComputedLoadLogsFieldsThatInstallNothing(t *testing.T) {
	dir := computedGuardDir(t, "fields:\n  - table: orders\n    column: line_total\n    expression: \"quantity * unit_price\"\n  - table: orders\n    column: item_count\n    sql: \"SELECT COUNT(*) FROM items WHERE order_id = ?\"\n    triggers:\n      - table: items\n        fk: order_id\n")
	logs := guardCaptureLog(t)
	app, err := loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	for _, want := range []string{"orders.line_total", "orders.item_count", "not calculated"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("the load must log %q; log:\n%s", want, logs.String())
		}
	}
}

// A field's expr (and sql) is spliced into the trigger that keeps the column.
// Text that closes the expression and goes on with statements of its own made
// that trigger delete from another table on every insert.
func TestComputedFieldCannotCarryStatementsIntoItsTrigger(t *testing.T) {
	smuggled := map[string]string{
		"expr":             "fields:\n  - table: orders\n    column: line_total\n    expr: \"quantity) WHERE 0; DELETE FROM victims; END --\"\n",
		"expr, nested":     "orders:\n  line_total:\n    expr: \"quantity) WHERE 0; DELETE FROM victims; END --\"\n",
		"sql":              "fields:\n  - table: orders\n    column: item_count\n    sql: \"SELECT COUNT(*) FROM items WHERE order_id = ?) WHERE 0; DELETE FROM victims; END --\"\n    triggers:\n      - table: items\n        on: [insert]\n        fk: order_id\n",
		"unbalanced close": "fields:\n  - table: orders\n    column: line_total\n    expr: \"quantity), title = ('rewritten'\"\n",
	}
	for name, doc := range smuggled {
		t.Run(name, func(t *testing.T) {
			dir := computedGuardDir(t, doc)
			gate := ValidateOnWriteIn(dir, "computed.yaml", doc)
			if !strings.Contains(gate, "one SQL expression") {
				t.Errorf("the gate must refuse text that is not one expression, got %q", gate)
			}
			app, err := loadApp(dir)
			if err != nil {
				if !strings.Contains(err.Error(), "one SQL expression") {
					t.Errorf("the load must refuse it for the same reason, got %v", err)
				}
				return
			}
			t.Cleanup(app.Shutdown)
			// It loaded: prove what the installed trigger does.
			mustExec(t, app.DB, `INSERT INTO victims (name) VALUES ('kept')`)
			mustExec(t, app.DB, `INSERT INTO orders (quantity, unit_price) VALUES (2, 3)`)
			mustExec(t, app.DB, `INSERT INTO items (order_id, name) VALUES (1, 'a')`)
			var victims int
			var title string
			if err := app.DB.QueryRow(`SELECT COUNT(*) FROM victims`).Scan(&victims); err != nil {
				t.Fatal(err)
			}
			if err := app.DB.QueryRow(`SELECT title FROM orders WHERE id = 1`).Scan(&title); err != nil {
				t.Fatal(err)
			}
			t.Errorf("the load installed the field: after one insert victims has %d row(s) (want 1 and no load) and orders.title is %q", victims, title)
		})
	}
}
