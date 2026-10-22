//go:build !cli

package main

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

const whenTestSchema = `model Order {
  id         Int      @id @default(autoincrement())
  status     String
  amount     Int?
  trackingNo String?  @map("tracking_number")
  userId     Int?     @map("user_id")
}
`

// The write gate prepares every hooks.yaml `when:` against the schema,
// with old_* and session keys available.
func TestValidateHookWhenConditions(t *testing.T) {
	dir := writeApp(t, map[string]string{"schema.prisma": whenTestSchema})
	valid := []string{
		"status = 'paid'",
		"status = 'paid' AND old_status != 'paid'",
		"status IN ('approved','denied')",
		"tracking_number IS NOT NULL",
		"amount > 5 AND user_id = orders.user_id",
		"user_role = 'admin' OR user_email LIKE '%@example.com'",
		"instr(_submitted, ',status,') > 0",
		"EXISTS (SELECT 1 FROM main.orders o WHERE o.status = orders.status AND o.id != orders.id)",
		"EXISTS (SELECT 1 FROM _benmore_user_roles r WHERE r.user_id = user_id)",
		"amount > 5 -- a comment",
	}
	for _, when := range valid {
		yaml := "on_update:\n  orders:\n    - sql: \"UPDATE orders SET amount = 0 WHERE id = {{id}}\"\n      when: \"" + strings.ReplaceAll(when, `"`, `\"`) + "\"\n"
		if msg := ValidateOnWriteIn(dir, "hooks.yaml", yaml); msg != "" {
			t.Errorf("valid when %q refused:\n%s", when, msg)
		}
	}
	invalid := map[string]string{
		"status = paid":             "no such column: paid",
		"{{status}} = 'paid'":       "not a template",
		"stauts = 'paid'":           "no such column: stauts",
		"status = 'paid'; DELETE":   "one expression",
		"(status = 'paid'":          "unbalanced",
		"status = 'paid' AND":       "syntax error",
		"no_such_fn(status) = 1":    "no such function",
		"old_stauts != status":      "no such column: old_stauts",
		"load_extension('x') = 1":   "load_extension",
		"status = 'paid' ) OR (1=1": "unbalanced",
		"status = :status":          "no parameters",
	}
	for when, want := range invalid {
		yaml := "before_insert:\n  orders:\n    - sql: \"SELECT 'x' AS error\"\n      when: \"" + strings.ReplaceAll(when, `"`, `\"`) + "\"\n"
		msg := ValidateOnWriteIn(dir, "hooks.yaml", yaml)
		if !strings.Contains(msg, want) || !strings.Contains(msg, "before_insert.orders[0]") {
			t.Errorf("when %q: want an error naming the hook and %q, got:\n%s", when, want, msg)
		}
	}
	// A table the schema doesn't declare gets the text checks only.
	if msg := ValidateOnWriteIn(dir, "hooks.yaml", "on_insert:\n  ghosts:\n    - sql: \"SELECT 1\"\n      when: \"anything = 1\"\n"); msg != "" {
		t.Errorf("a when: on an undeclared table was prepared: %s", msg)
	}
	if msg := ValidateOnWriteIn(dir, "hooks.yaml", "on_insert:\n  ghosts:\n    - sql: \"SELECT 1\"\n      when: \"{{x}} = 1\"\n"); !strings.Contains(msg, "not a template") {
		t.Errorf("a template when: on an undeclared table passed: %s", msg)
	}
	// Without an app dir (no schema) the text is still checked.
	if msg := ValidateOnWrite("hooks.yaml", "on_insert:\n  orders:\n    - sql: \"SELECT 1\"\n      when: \"a = 1; b\"\n"); !strings.Contains(msg, "one expression") {
		t.Errorf("text check without a schema: %s", msg)
	}
}

// Workflow transitions and on_transition entries are checked the same way.
func TestValidateWorkflowWhenConditions(t *testing.T) {
	dir := writeApp(t, map[string]string{"schema.prisma": whenTestSchema})
	wf := func(when string) string {
		return `orders:
  table: orders
  field: status
  initial: pending
  transitions:
    pending:
      shipped: { when: "` + when + `" }
  on_transition:
    shipped:
      - sql: "UPDATE orders SET amount = 0 WHERE id = {{id}}"
        when: "old_status = 'pending'"
`
	}
	if msg := ValidateOnWriteIn(dir, "workflows.yaml", wf("tracking_number IS NOT NULL")); msg != "" {
		t.Errorf("valid workflow when refused:\n%s", msg)
	}
	msg := ValidateOnWriteIn(dir, "workflows.yaml", wf("tracking IS NOT NULL"))
	if !strings.Contains(msg, "orders.transitions.pending -> shipped") || !strings.Contains(msg, "no such column: tracking") {
		t.Errorf("invalid transition when: got:\n%s", msg)
	}
}

// benmore check reports the error; the loader still loads the file and
// only warns.
func TestWhenValidationDoesNotRefuseLoad(t *testing.T) {
	hooks := "on_update:\n  orders:\n    - sql: \"UPDATE orders SET amount = 0 WHERE id = {{id}}\"\n      when: \"status = paid\"\n"
	workflows := "orders:\n  table: orders\n  field: status\n  initial: pending\n  transitions:\n    pending:\n      shipped: { when: \"{{tracking_number}} != ''\" }\n"
	if cfg, err := parseHooksYAML([]byte(hooks)); err != nil || cfg == nil || cfg.OnUpdate["orders"][0].When != "status = paid" {
		t.Fatalf("hooks.yaml with an invalid when: did not load: %v", err)
	}
	if cfg, err := parseWorkflowsYAML([]byte(workflows)); err != nil || cfg == nil {
		t.Fatalf("workflows.yaml with an invalid when: did not load: %v", err)
	}
	dir := writeApp(t, map[string]string{
		"schema.prisma":  whenTestSchema,
		"hooks.yaml":     hooks,
		"workflows.yaml": workflows,
	})
	rpt := RunCompleteCheck(dir, "")
	var hooksErr, wfErr bool
	for _, f := range rpt.Findings {
		if f.Severity == "error" && f.File == "hooks.yaml" && strings.Contains(f.Message, "no such column: paid") {
			hooksErr = true
		}
		if f.Severity == "error" && f.File == "workflows.yaml" && strings.Contains(f.Message, "not a template") {
			wfErr = true
		}
	}
	if !hooksErr || !wfErr {
		t.Errorf("benmore check did not report both when: errors:\n%s", FormatReport(rpt))
	}

	app, err := loadApp(dir)
	if err != nil {
		t.Fatalf("an app with invalid when: conditions failed to load: %v", err)
	}
	defer app.DB.Close()
	if app.Hooks == nil || len(app.Hooks.OnUpdate["orders"]) != 1 || app.Workflows == nil {
		t.Fatal("the hooks or workflows were dropped at load")
	}
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	warnWhenConditions(app)
	log.SetOutput(prev)
	out := buf.String()
	if !strings.Contains(out, "hooks.yaml on_update.orders[0]") || !strings.Contains(out, "workflows.yaml orders.transitions.pending -> shipped") {
		t.Errorf("load did not warn about both conditions:\n%s", out)
	}
}
