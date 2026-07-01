//go:build !cli

package main

import (
	"database/sql"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

// TestTranslateRaiseAbort covers bug #1: the documented
// `RAISE(ABORT,'msg')` before-hook idiom (which SQLite rejects outside a
// trigger) is rewritten into the framework's working abort shape.
func TestTranslateRaiseAbort(t *testing.T) {
	cases := []struct{ in, want string }{
		{
			`SELECT CASE WHEN amount > 10000 THEN RAISE(ABORT, 'over limit') END`,
			`SELECT 'over limit' AS error WHERE amount > 10000`,
		},
		{
			// nested subquery in the condition + delete-pin example from docs
			`SELECT CASE WHEN (SELECT pinned FROM notes WHERE id = {{id}}) = 1 THEN RAISE(ABORT, 'cannot delete pinned') END`,
			`SELECT 'cannot delete pinned' AS error WHERE (SELECT pinned FROM notes WHERE id = {{id}}) = 1`,
		},
		{
			// FAIL/ROLLBACK + ELSE clause + trailing semicolon, case-insensitive
			`select case when role != 'admin' then raise(FAIL, 'forbidden') else null end;`,
			`SELECT 'forbidden' AS error WHERE role != 'admin'`,
		},
	}
	for _, c := range cases {
		if got := translateRaiseAbort(c.in); got != c.want {
			t.Errorf("translateRaiseAbort(%q)\n  got  %q\n  want %q", c.in, got, c.want)
		}
	}

	// Non-matching SQL passes through untouched.
	passthrough := `SELECT 'x' AS error WHERE 1=1`
	if got := translateRaiseAbort(passthrough); got != passthrough {
		t.Errorf("passthrough mutated: %q", got)
	}
}

// TestFireBeforeHooks_FailClosed covers bug #2: a before-hook whose SQL
// cannot be evaluated must REJECT the mutation (fail closed), not let it
// through. Pre-fix this returned nil and the write proceeded.
func TestFireBeforeHooks_FailClosed(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	app := &App{DB: db, Dir: t.TempDir(), Hooks: &HookConfig{
		BeforeInsert: map[string][]Hook{
			// References a column/table that doesn't exist → SQL errors.
			"orders": {{SQL: "SELECT error FROM nonexistent_gate WHERE 1=1"}},
		},
	}}

	err = FireBeforeHooks(app, "insert", "orders", map[string]any{"amount": 5})
	if err == nil {
		t.Fatal("FAIL-OPEN REGRESSION: broken before-hook SQL returned nil (write would proceed). Must fail closed.")
	}
}

// TestFireBeforeHooks_RaiseAbortAborts is the end-to-end of bug #1+#2:
// a hook using the documented RAISE(ABORT) pattern actually aborts with
// the intended message when the condition holds, and passes when it
// doesn't.
func TestFireBeforeHooks_RaiseAbortAborts(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	app := &App{DB: db, Dir: t.TempDir(), Hooks: &HookConfig{
		BeforeInsert: map[string][]Hook{
			"orders": {{SQL: "SELECT CASE WHEN {{amount}} > 10000 THEN RAISE(ABORT, 'over limit') END"}},
		},
	}}

	// Over the limit → abort with the documented message.
	err = FireBeforeHooks(app, "insert", "orders", map[string]any{"amount": 50000})
	if err == nil {
		t.Fatal("expected abort for amount over limit, got nil")
	}
	if !strings.Contains(err.Error(), "over limit") {
		t.Fatalf("expected 'over limit' message, got %q", err.Error())
	}

	// Under the limit → allowed.
	if err = FireBeforeHooks(app, "insert", "orders", map[string]any{"amount": 5}); err != nil {
		t.Fatalf("expected pass for under-limit amount, got %q", err.Error())
	}

	// CRITICAL: row values arrive as STRINGS (form/JSON parsing). A bare
	// {{amount}} bound as TEXT would make '5' > 10000 evaluate TRUE in
	// SQLite (text sorts above numbers), wrongly aborting an under-limit
	// write. coerceNumericBind must make this compare numerically.
	if err = FireBeforeHooks(app, "insert", "orders", map[string]any{"amount": "5"}); err != nil {
		t.Fatalf("string '5' under limit must pass (SQLite text-affinity trap), got %q", err.Error())
	}
	if err = FireBeforeHooks(app, "insert", "orders", map[string]any{"amount": "50000"}); err == nil {
		t.Fatal("string '50000' over limit must abort")
	}
}

// TestCoerceNumericBind locks the string→number coercion that defeats
// SQLite's text-affinity trap, plus the identifier-shaped exceptions.
func TestCoerceNumericBind(t *testing.T) {
	num := func(v any) bool {
		switch v.(type) {
		case int64, float64:
			return true
		}
		return false
	}
	// Coerced to numeric:
	for _, s := range []string{"42", "-5", "0", "3.14", "-0.5", "1000000"} {
		if !num(coerceNumericBind(s)) {
			t.Errorf("coerceNumericBind(%q) should be numeric, got %T", s, coerceNumericBind(s))
		}
	}
	// Left as TEXT (identifier-shaped or non-numeric):
	for _, s := range []string{"007", "00123", "", "1.2.3", "1e5", "42abc", "abc", "+5"} {
		if num(coerceNumericBind(s)) {
			t.Errorf("coerceNumericBind(%q) should stay string, got numeric", s)
		}
	}
	// Non-strings pass through untouched.
	if got := coerceNumericBind(float64(9)); got != float64(9) {
		t.Errorf("float64 passthrough broke: %v", got)
	}
}
