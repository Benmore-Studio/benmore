//go:build !cli

package main

import (
	"database/sql"
	"go/ast"
	"go/token"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// A runtime hint tells the builder what to write next. These tests read
// every hint the runtime's error envelopes can carry out of its source and
// hold the things a hint names - a step type, an on.request key, an app.yaml
// key, a framework route, an access mode, a model - against what the runtime
// accepts. The addresses, MCP tools and CLI commands a hint names are checked
// in the platform edition (TestRuntimeHintAddressesResolve).

// runtimeHint is one piece of hint text and where it is written.
type runtimeHint struct{ where, text string }

// runtimeHintFiles are the files that build a `hint` of a runtime error
// envelope: every `"hint"` they write is read.
var runtimeHintFiles = []string{
	"access.go", "crud_create.go", "crud_update.go", "flows.go", "flows_response.go",
	"flows_time_limit.go", "settings.go", "workflows.go",
}

// runtimeHintBuilders are functions and constants whose text becomes a
// runtime hint: every string literal in them is read.
var runtimeHintBuilders = map[string][]string{
	"access.go":      {"unauthenticatedAPIBody", "writeCRUDOpDenied"},
	"crud_update.go": {"strippedUpdateHint"},
	"flows.go":       {"flowFailureLogHint"},
	"flows_steps.go": {"stepFailureHint", "unresolvedRefStepOutcome"},
}

// otherHintFiles write a `"hint"` key that is not a runtime error envelope's:
// a tool's answer, a describe report, generated API documentation. A file
// that starts writing one must be listed here or in runtimeHintFiles.
var otherHintFiles = map[string]string{
	"access_describe.go":     "the access report of describe_table",
	"apidocs.go":             "the OpenAPI schema of the error envelope",
	"api_topic_delivery.go":  "the topic reference's own answers",
	"api_topic_search.go":    "the topic reference's own answers",
	"mcp_tools_api.go":       "the topic reference",
	"op_describe.go":         "describe tools",
	"op_diag.go":             "diagnostic tools",
	"op_probe.go":            "probe_route's answer",
	"app_data_ops_errors.go": "decode_stack's answer",
	"refusal_docs.go":        "reads a refusal's hint to choose its address",
}

func runtimeHintTexts(t *testing.T) []runtimeHint {
	t.Helper()
	sources := refusalSourceFiles(t)
	var hints []runtimeHint
	isHintKey := func(expr ast.Expr) bool {
		lit, ok := expr.(*ast.BasicLit)
		return ok && lit.Kind == token.STRING && lit.Value == `"hint"`
	}
	literals := func(where string, node ast.Node) int {
		n := 0
		ast.Inspect(node, func(inner ast.Node) bool {
			if lit, ok := inner.(*ast.BasicLit); ok && lit.Kind == token.STRING {
				if text, err := strconv.Unquote(lit.Value); err == nil && len(text) > 12 {
					hints = append(hints, runtimeHint{where, text})
					n++
				}
			}
			return true
		})
		return n
	}
	for name, src := range sources {
		if !strings.Contains(src, `"hint"`) {
			continue
		}
		runtime := slices.Contains(runtimeHintFiles, name)
		if _, other := otherHintFiles[name]; !runtime && !other {
			// MCP tools, the CLI and the platform's own API answer their
			// callers, not an app's client.
			if strings.HasPrefix(name, "mcp_") || strings.HasPrefix(name, "cli_") || strings.HasPrefix(name, "platform_") {
				continue
			}
			t.Errorf("%s writes a \"hint\": list it in runtimeHintFiles (its hints are then checked) or in otherHintFiles with what the hint belongs to", name)
			continue
		}
		if !runtime {
			continue
		}
		ast.Inspect(parseRefusalSource(t, name, src), func(node ast.Node) bool {
			switch n := node.(type) {
			case *ast.KeyValueExpr:
				if isHintKey(n.Key) {
					literals(name, n.Value)
				}
			case *ast.AssignStmt:
				for i, lhs := range n.Lhs {
					if index, ok := lhs.(*ast.IndexExpr); ok && isHintKey(index.Index) && i < len(n.Rhs) {
						literals(name, n.Rhs[i])
					}
				}
			}
			return true
		})
	}
	for name, builders := range runtimeHintBuilders {
		file := parseRefusalSource(t, name, sources[name])
		for _, builder := range builders {
			found := 0
			for _, decl := range file.Decls {
				switch d := decl.(type) {
				case *ast.FuncDecl:
					if d.Name.Name == builder {
						found += literals(name+" "+builder, d.Body)
					}
				case *ast.GenDecl:
					for _, spec := range d.Specs {
						if value, ok := spec.(*ast.ValueSpec); ok && value.Names[0].Name == builder {
							found += literals(name+" "+builder, value)
						}
					}
				}
			}
			if found == 0 {
				t.Errorf("%s: %s holds no hint text any more: update runtimeHintBuilders", name, builder)
			}
		}
	}
	if len(hints) < 60 {
		t.Fatalf("read only %d pieces of hint text", len(hints))
	}
	return hints
}

var (
	hintStepType   = regexp.MustCompile("`run: ([a-z_]+)`")
	hintRequestKey = regexp.MustCompile(`on\.request\.([a-z_]+)`)
	hintAuthKey    = regexp.MustCompile(`\bauth\.([a-z_]+)`)
	hintGroupsKey  = regexp.MustCompile(`\bgroups\.([a-z_]+)(?:: \{([a-z_]+):)?`)
	hintRoute      = regexp.MustCompile(`\b(GET|POST|PATCH|PUT|DELETE) (/api/_[a-z_/]+)`)
	hintAccessMode = regexp.MustCompile(`\bread: ([a-z_]+)`)
	hintModel      = regexp.MustCompile(`\bmodel ([A-Z][A-Za-z]+)\b`)
	hintAddress    = regexp.MustCompile(`api\(at:\s*\\?["']([a-z][a-z0-9_.-]*)\\?["']\)`)
	hintTool       = regexp.MustCompile("(?:Run |MCP )([a-z]+_[a-z_]+)|`((?:describe|get|list|tail|probe|check)_[a-z_]+)`")
	hintCommand    = regexp.MustCompile(`\bbenmore ([a-z][a-z-]+)\b`)
)

func hintAPIAddresses(text string) []string {
	var out []string
	for _, m := range hintAddress.FindAllStringSubmatch(text, -1) {
		out = append(out, m[1])
	}
	return out
}

func hintToolNames(text string) []string {
	var out []string
	for _, m := range hintTool.FindAllStringSubmatch(text, -1) {
		out = append(out, m[1]+m[2])
	}
	return out
}

func hintCommandNames(text string) []string {
	var out []string
	for _, m := range hintCommand.FindAllStringSubmatch(text, -1) {
		out = append(out, m[1])
	}
	return out
}

// Every step type, trigger key, app.yaml key, framework route, access mode
// and model a runtime hint names is one the runtime has.
func TestRuntimeHintsNameThingsTheRuntimeHas(t *testing.T) {
	// The framework's routes for an app that uses what the hints talk about:
	// tenants with a bootstrap, and sign-in.
	dir := writeApp(t, map[string]string{
		"app.yaml":      "name: t\nauth:\n  profile_fields: \"company\"\ngroups:\n  table: members\n  key: org_id\n  user_field: user_id\n  bootstrap: { org_table: orgs }\n",
		"schema.prisma": "model Org {\n  id   Int    @id @default(autoincrement())\n  name String\n  @@map(\"orgs\")\n}\n\nmodel Member {\n  id     Int @id @default(autoincrement())\n  orgId  Int @map(\"org_id\")\n  userId Int @map(\"user_id\")\n  @@map(\"members\")\n}\n",
	})
	_, mux, err := flowRouteCollisionsIn(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	checked := map[string]int{}
	for _, hint := range runtimeHintTexts(t) {
		for _, m := range hintStepType.FindAllStringSubmatch(hint.text, -1) {
			checked["step types"]++
			if !flowRunTypes[m[1]] {
				t.Errorf("%s names the step type `run: %s`, which flows do not have", hint.where, m[1])
			}
		}
		for _, m := range hintRequestKey.FindAllStringSubmatch(hint.text, -1) {
			checked["on.request keys"]++
			if !flowRequestKeys[m[1]] {
				t.Errorf("%s names on.request.%s, which the trigger does not read", hint.where, m[1])
			}
		}
		for _, m := range hintAuthKey.FindAllStringSubmatch(hint.text, -1) {
			checked["auth keys"]++
			if !knownAuthKeys[m[1]] {
				t.Errorf("%s names app.yaml auth.%s, which is not an auth key", hint.where, m[1])
			}
		}
		for _, m := range hintGroupsKey.FindAllStringSubmatch(hint.text, -1) {
			checked["groups keys"]++
			if !groupKeys[m[1]] || (m[2] != "" && !groupBootstrapKeys[m[2]]) {
				t.Errorf("%s names app.yaml groups.%s %s, which the tenant loader does not read", hint.where, m[1], m[2])
			}
		}
		for _, m := range hintRoute.FindAllStringSubmatch(hint.text, -1) {
			checked["routes"]++
			pattern := m[1] + " " + strings.TrimRight(m[2], "/")
			if registered, _ := mux.conflictingRoute(pattern); registered == "" {
				t.Errorf("%s names the route %s, which the framework does not register", hint.where, pattern)
			}
		}
		for _, m := range hintAccessMode.FindAllStringSubmatch(hint.text, -1) {
			checked["access modes"]++
			if msg := validateAccessMode("notes", "read", m[1]); msg != "" {
				t.Errorf("%s names the access mode `read: %s`, which the write gate refuses: %s", hint.where, m[1], msg)
			}
		}
		for _, m := range hintModel.FindAllStringSubmatch(hint.text, -1) {
			checked["models"]++
			if _, err := ParsePrismaSchema("model " + m[1] + " {\n  id Int @id @default(autoincrement())\n}\n"); err != nil {
				t.Errorf("%s tells the builder to write `model %s`, which schema.prisma refuses: %v", hint.where, m[1], err)
			}
		}
	}
	for _, kind := range []string{"step types", "on.request keys", "auth keys", "groups keys", "routes", "access modes"} {
		if checked[kind] == 0 {
			t.Errorf("no hint names any %s: the extraction no longer matches the hint texts", kind)
		}
	}
	t.Logf("names checked: %v", checked)
}

// The hints a caller actually receives, built by the runtime: the same
// names hold in the finished text, and the body is the JSON a client parses.
func TestBuiltHintsNameThingsTheRuntimeHas(t *testing.T) {
	for stepType := range flowRunTypes {
		for _, failure := range []string{"no such table: x", "unresolved template reference steps.a.outputs.b", "boom"} {
			hint := stepFailureHint("s1", stepType, failure)
			for _, m := range hintStepType.FindAllStringSubmatch(hint, -1) {
				if !flowRunTypes[m[1]] {
					t.Errorf("stepFailureHint(%s, %q) names the step type `run: %s`, which flows do not have", stepType, failure, m[1])
				}
			}
			if !strings.Contains(hint, "(run: "+stepType+")") {
				t.Errorf("stepFailureHint(%s, %q) does not name the failed step's type: %s", stepType, failure, hint)
			}
		}
	}
	app := &App{Workflows: &WorkflowConfig{Workflows: map[string]*Workflow{"order": {Name: "order", Table: "orders", Field: "status"}}}}
	hint := strippedUpdateHint(app, "orders", "7", []string{"status", "user_id"})
	if !strings.Contains(hint, "POST /api/orders/7/transition") || !strings.Contains(hint, "GET /api/orders/7/transitions") || !strings.Contains(hint, "user_id is managed by the framework") {
		t.Errorf("strippedUpdateHint: %s", hint)
	}
}

// The profile hint for a field _benmore_users does not have names the lever
// that adds the column: auth.signup_fields. (It used to say "your
// schema.prisma model User block", a model the schema parser refuses.)
func TestProfileUnknownFieldHintNamesWhatAddsTheColumn(t *testing.T) {
	if _, err := ParsePrismaSchema("model User {\n  id Int @id @default(autoincrement())\n  company String\n}\n"); err == nil {
		t.Fatal("schema.prisma accepts `model User`; the hint could send builders there again")
	}
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`CREATE TABLE _benmore_users (id INTEGER PRIMARY KEY, email TEXT)`); err != nil {
		t.Fatal(err)
	}
	EnsureSignupFieldColumns(db, "company")
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('_benmore_users') WHERE name = 'company'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("auth.signup_fields did not add the column the hint promises (n=%d, err=%v)", n, err)
	}
	hints := 0
	for _, hint := range runtimeHintTexts(t) {
		if hint.where == "settings.go" && strings.Contains(hint.text, "present on _benmore_users") {
			hints++
			if !strings.Contains(hint.text, "auth.signup_fields") || strings.Contains(hint.text, "model User") {
				t.Errorf("the hint does not name auth.signup_fields: %s", hint.text)
			}
		}
	}
	if hints != 2 {
		t.Errorf("found %d unknown-field hints in settings.go, want 2", hints)
	}
}
