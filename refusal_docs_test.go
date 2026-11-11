//go:build !cli

package main

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// refusalSourceFiles are this package's non-test Go files, by name.
func refusalSourceFiles(t *testing.T) map[string]string {
	t.Helper()
	names, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		out[name] = string(data)
	}
	if len(out) < 100 {
		t.Fatalf("read only %d source files", len(out))
	}
	return out
}

func parseRefusalSource(t *testing.T, name, src string) *ast.File {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), name, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return file
}

// A table entry either names a key or says why it has none. An address is
// "<topic>.<key>"; the platform edition checks it against the registry
// (TestRefusalDocsAddressesResolveInTheRegistry).
func TestRefusalDocsEntriesNameAKeyOrAReason(t *testing.T) {
	address := regexp.MustCompile(`^[a-z][a-z0-9_-]*\.[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)*$`)
	check := func(table, name string, rule docsRule) {
		t.Helper()
		switch {
		case rule.Exempt != "" && (rule.At != "" || len(rule.When) > 0):
			t.Errorf("%s[%s] is exempt (%q) and has an address: keep one", table, name, rule.Exempt)
		case rule.Exempt == "" && rule.At == "" && len(rule.When) == 0:
			t.Errorf("%s[%s] has no address and no reason: name the key that states the rule, or set Exempt", table, name)
		}
		for _, at := range append([]string{rule.At}, whenAddresses(rule)...) {
			if at != "" && !address.MatchString(at) {
				t.Errorf("%s[%s]: %q is not a <topic>.<key> address", table, name, at)
			}
		}
		for i, when := range rule.When {
			if strings.TrimSpace(when.Has) == "" || when.At == "" {
				t.Errorf("%s[%s].When[%d] needs both the text and the address", table, name, i)
			}
			for _, earlier := range rule.When[:i] {
				if strings.Contains(when.Has, earlier.Has) {
					t.Errorf("%s[%s]: When %q can never match, the earlier %q matches first", table, name, when.Has, earlier.Has)
				}
			}
		}
	}
	for name, rule := range gateRuleDocs {
		check("gateRuleDocs", string(name), rule)
	}
	for name, rule := range checkSourceDocs {
		check("checkSourceDocs", name, rule)
	}
	for name, rule := range refusalDocs {
		check("refusalDocs", name, rule)
		if _, exempt := refusalCodeExemptions[name]; exempt {
			t.Errorf("%q has an address and is on the exemption list: keep one", name)
		}
		if rule.Exempt != "" {
			t.Errorf("refusalDocs[%s]: a runtime refusal without an address belongs on refusalCodeExemptions", name)
		}
	}
	for code, why := range refusalCodeExemptions {
		if strings.TrimSpace(why) == "" {
			t.Errorf("refusalCodeExemptions[%s] gives no reason", code)
		}
	}
}

func whenAddresses(rule docsRule) []string {
	out := make([]string, len(rule.When))
	for i, when := range rule.When {
		out[i] = when.At
	}
	return out
}

// declaredGateRules reads the gateRule constants out of refusal_docs.go:
// identifier -> value.
func declaredGateRules(t *testing.T, sources map[string]string) map[string]gateRule {
	t.Helper()
	out := map[string]gateRule{}
	for _, decl := range parseRefusalSource(t, "refusal_docs.go", sources["refusal_docs.go"]).Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			value := spec.(*ast.ValueSpec)
			if ident, ok := value.Type.(*ast.Ident); !ok || ident.Name != "gateRule" {
				continue
			}
			text, err := strconv.Unquote(value.Values[0].(*ast.BasicLit).Value)
			if err != nil {
				t.Fatal(err)
			}
			out[value.Names[0].Name] = gateRule(text)
		}
	}
	if len(out) < 40 {
		t.Fatalf("read only %d gateRule constants", len(out))
	}
	return out
}

// These tests read the package's source. The public framework tree ships
// without the platform-tagged files, so what they require holds for any
// subset of the files: everything found has an entry. That every entry is
// still found (no dead rule, source, exemption or When text) needs the whole
// tree and is checked in the platform edition
// (TestRefusalDocsTablesHoldNoDeadEntries).

// gateRulesRaised reads which gateRule constants the source raises: by
// add(rule, msg) in the dispatcher and by gateRefusal(rule, msg) elsewhere.
// raised counts the dispatcher's add calls, appends its appends to issues.
func gateRulesRaised(t *testing.T, sources map[string]string, rules map[string]gateRule) (used map[string]bool, raised, appends int) {
	t.Helper()
	var dispatcher *ast.FuncDecl
	for _, decl := range parseRefusalSource(t, "validators_write.go", sources["validators_write.go"]).Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "writeGateVerdict" {
			dispatcher = fn
		}
	}
	if dispatcher == nil {
		t.Fatal("writeGateVerdict (the write gate's dispatcher) is not in validators_write.go")
	}
	used = map[string]bool{}
	ast.Inspect(dispatcher.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		fn, _ := call.Fun.(*ast.Ident)
		switch {
		case fn != nil && fn.Name == "append" && len(call.Args) > 0:
			if target, _ := call.Args[0].(*ast.Ident); target != nil && target.Name == "issues" {
				appends++
			}
		case fn != nil && fn.Name == "add" && len(call.Args) == 2:
			raised++
			rule, _ := call.Args[0].(*ast.Ident)
			if rule == nil || rules[rule.Name] == "" {
				t.Errorf("an add(...) in writeGateVerdict does not name a gateRule constant of refusal_docs.go")
				return true
			}
			used[rule.Name] = true
		}
		return true
	})
	// Refusals raised outside the dispatcher: gateRefusal(rule, msg).
	gateRefusalCall := regexp.MustCompile(`gateRefusal\((gate[A-Za-z]+),`)
	for name, src := range sources {
		for _, match := range gateRefusalCall.FindAllStringSubmatch(src, -1) {
			if rules[match[1]] == "" {
				t.Errorf("%s: gateRefusal(%s, ...) does not name a gateRule constant", name, match[1])
			}
			used[match[1]] = true
		}
	}
	return used, raised, appends
}

// Every issue the write gate raises names its rule, and every rule has an
// entry in gateRuleDocs. A validator added to the dispatcher with a bare
// append would carry no address; this is what makes that a failure instead of
// a silence.
func TestWriteGateEveryIssueNamesItsRule(t *testing.T) {
	sources := refusalSourceFiles(t)
	rules := declaredGateRules(t, sources)
	_, raised, appends := gateRulesRaised(t, sources, rules)
	if appends != 1 {
		t.Errorf("writeGateVerdict appends to issues %d times; only add(rule, msg) may (1 append, inside add). Raise each issue with add and give its rule an entry in gateRuleDocs (refusal_docs.go)", appends)
	}
	if raised < 50 {
		t.Errorf("found only %d add(rule, msg) calls in writeGateVerdict", raised)
	}
	declared := map[gateRule]string{}
	for ident, rule := range rules {
		if other, dup := declared[rule]; dup {
			t.Errorf("%s and %s are the same rule %q", ident, other, rule)
		}
		declared[rule] = ident
		if _, ok := gateRuleDocs[rule]; !ok {
			t.Errorf("%s (%q) has no entry in gateRuleDocs: name the key that states the rule, or mark it Exempt with the reason", ident, rule)
		}
	}
	for rule := range gateRuleDocs {
		if declared[rule] == "" {
			t.Errorf("gateRuleDocs[%q] is not a declared gateRule constant", rule)
		}
	}
	t.Logf("%d issue sites in the dispatcher, %d rules, all with an entry", raised, len(rules))
}

// checkFindingSources finds the `source` of every CheckFinding literal in
// the package's source.
func checkFindingSources(t *testing.T, sources map[string]string) map[string][]string {
	t.Helper()
	found := map[string][]string{}
	for name, src := range sources {
		if !strings.Contains(src, "CheckFinding{") {
			continue
		}
		ast.Inspect(parseRefusalSource(t, name, src), func(node ast.Node) bool {
			lit, ok := node.(*ast.CompositeLit)
			if !ok {
				return true
			}
			// []CheckFinding{{...}} elides the type of each element.
			if array, ok := lit.Type.(*ast.ArrayType); ok {
				if elem, _ := array.Elt.(*ast.Ident); elem != nil && elem.Name == "CheckFinding" {
					for _, element := range lit.Elts {
						if inner, ok := element.(*ast.CompositeLit); ok && inner.Type == nil {
							inner.Type = elem
						}
					}
				}
				return true
			}
			if typ, _ := lit.Type.(*ast.Ident); typ == nil || typ.Name != "CheckFinding" {
				return true
			}
			for _, element := range lit.Elts {
				pair, ok := element.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if key, _ := pair.Key.(*ast.Ident); key == nil || key.Name != "Source" {
					continue
				}
				value, ok := pair.Value.(*ast.BasicLit)
				if !ok {
					t.Errorf("%s: a CheckFinding sets Source from an expression; write the source as a string literal so its documentation address can be checked", name)
					continue
				}
				source, _ := strconv.Unquote(value.Value)
				found[source] = append(found[source], name)
			}
			return true
		})
	}
	return found
}

// Every `source` a check finding can carry has an entry in checkSourceDocs.
func TestCheckFindingSourcesHaveAnAddress(t *testing.T) {
	found := checkFindingSources(t, refusalSourceFiles(t))
	if len(found) < 10 {
		t.Fatalf("found only %d finding sources: %v", len(found), slices.Sorted(maps.Keys(found)))
	}
	for _, source := range slices.Sorted(maps.Keys(found)) {
		if _, ok := checkSourceDocs[source]; !ok {
			t.Errorf("check findings with source %q (%s) have no entry in checkSourceDocs: name the key that states the rule, or mark it Exempt with the reason", source, strings.Join(slices.Compact(slices.Sorted(slices.Values(found[source]))), ", "))
		}
	}
	// What a finding carries is what the table says.
	for source, rule := range checkSourceDocs {
		got := withFindingDocs([]CheckFinding{{Severity: "warning", Source: source, Message: "x"}})[0].Docs
		if got != rule.At {
			t.Errorf("a %q finding carries docs %q, want %q", source, got, rule.At)
		}
	}
	if kept := withFindingDocs([]CheckFinding{{Source: "flows", Message: "x", Docs: "flows.step_ids"}})[0].Docs; kept != "flows.step_ids" {
		t.Errorf("an address a finding already has was replaced by %q", kept)
	}
	t.Logf("%d finding sources, all with an entry", len(found))
}

// refusalCodeIdentifiers are the constants an answer's `error` is written
// with instead of a literal.
var refusalCodeIdentifiers = map[string]string{
	"uploadsDisabledCode":           uploadsDisabledCode,
	"mediaAllowanceCode":            mediaAllowanceCode,
	"emailVerificationRequiredCode": emailVerificationRequiredCode,
}

// runtimeErrorCodes finds the stable codes the source answers in `error` or
// `code`, with the files that write each. A code is a lower-case identifier;
// a sentence is not one (the sentences that have an address are named in
// refusalDocs).
func runtimeErrorCodes(t *testing.T, sources map[string]string) map[string][]string {
	t.Helper()
	literal := regexp.MustCompile(`\\?"(?:error|code)\\?":\s*\\?"([a-z][a-z0-9]*(?:_[a-z0-9]+)*)\\?"`)
	identifier := regexp.MustCompile(`"(?:error|code)":\s*([A-Za-z][A-Za-z0-9]*Code)\b`)
	found := map[string][]string{}
	for name, src := range sources {
		// The api tool's route descriptions quote example bodies.
		if name == "mcp_tools_api.go" {
			continue
		}
		for _, match := range literal.FindAllStringSubmatch(src, -1) {
			found[match[1]] = append(found[match[1]], name)
		}
		for _, match := range identifier.FindAllStringSubmatch(src, -1) {
			code, known := refusalCodeIdentifiers[match[1]]
			if !known {
				t.Errorf("%s answers `error`/`code` from the constant %s: add it to refusalCodeIdentifiers (this test) and give its value an address in refusalDocs", name, match[1])
				continue
			}
			found[code] = append(found[code], name)
		}
	}
	return found
}

// Every stable code the runtime answers in `error` or `code` has an address
// in refusalDocs or a reason on refusalCodeExemptions, so a new code cannot
// arrive without one.
func TestRuntimeErrorCodesHaveAnAddress(t *testing.T) {
	found := runtimeErrorCodes(t, refusalSourceFiles(t))
	if len(found) < 10 {
		t.Fatalf("found only %d codes: %v", len(found), slices.Sorted(maps.Keys(found)))
	}
	addressed := 0
	for _, code := range slices.Sorted(maps.Keys(found)) {
		_, documented := refusalDocs[code]
		_, exempt := refusalCodeExemptions[code]
		if !documented && !exempt {
			t.Errorf("the runtime answers the code %q (%s) and refusal_docs.go has neither an address for it (refusalDocs) nor a reason it has none (refusalCodeExemptions)", code, strings.Join(slices.Compact(slices.Sorted(slices.Values(found[code]))), ", "))
		}
		if documented {
			addressed++
		}
	}
	// The connector's codes are one closed set; each resolves.
	for _, code := range appMCPErrorCodes {
		if refusalDocsAt(refusalConnectorError, code) == "" {
			t.Errorf("connector error code %q has no address", code)
		}
	}
	for _, when := range refusalDocs[refusalConnectorError].When {
		if !slices.Contains(appMCPErrorCodes, when.Has) {
			t.Errorf("refusalDocs[%s]: %q is not a connector error code", refusalConnectorError, when.Has)
		}
	}
	t.Logf("%d codes in the runtime's source: %d with an address, %d exempt; %d connector codes", len(found), addressed, len(found)-addressed, len(appMCPErrorCodes))
}

// ===== What a refused write answers =====

const refusalTestSchema = "model Note {\n  id    Int    @id @default(autoincrement())\n  title String\n}\n"

// Each sample is refused by the write gate for the reason its rule names,
// and the refusal ends that issue with the address of the key that states
// the rule. The message itself is unchanged: taking the address lines out
// gives back the text the validators wrote.
func TestWriteGateRefusalsCarryTheAddressOfTheirRule(t *testing.T) {
	dir := writeApp(t, map[string]string{"app.yaml": "site_name: T\n", "schema.prisma": refusalTestSchema})
	flow := func(body string) string {
		return "on:\n  request: { method: POST, path: /api/x-do, auth: required }\njobs:\n  main:\n    steps:\n" + body
	}
	cases := []struct {
		name, path, content string
		says                string // text of the refusal, proving which rule fired
		docs                string
	}{
		{"npm file", "package.json", "{}", "forbidden path", "frontend.how_compile_works"},
		{"sidecar", "static/._app.tsx", "x", "desktop metadata sidecar", "frontend.how_compile_works"},
		{"committed secret", "static/app.ts", "const k = 'AKIAIOSFODNN7EXAMPLE';\n", "[secrets]", "recovery.file_tools"},
		{"script syntax", "static/app.ts", "export const x = ;\n", "does not parse", "compute.write_time_parse"},
		{"schema parse", "schema.prisma", "model Note {\n  id Int @id\n  when Whenever\n}\n", "schema.prisma", "schema.field_types"},
		{"reserved table", "schema.prisma", "model Upload {\n  id Int @id @default(autoincrement())\n  @@map(\"_upload\")\n}\n", "_upload", "schema.reserved_table_names"},
		{"flow shape", "flows.yaml", "notes:\n  trigger: POST /api/x\n  steps:\n    - sql: SELECT 1\n", "legacy", "flows.yaml_example"},
		{"flow step type", "flows.yaml", flow("      - run: teleport\n"), "isn't a known step type", "flows.step_types"},
		{"flow step key", "flows/a.yaml", flow("      - run: respond\n        params: { a: 1 }\n        with: { status: 200, body: { ok: true } }\n"), "is not read", "flows.step_keys"},
		{"flow unknown key", "flows.yaml", "on:\n  request: { method: POST, path: /api/x-do, roles: admin }\njobs:\n  main:\n    steps:\n      - run: respond\n        with: { status: 200, body: { ok: true } }\n", "unknown key", "flows.public_flows"},
		{"flow RAISE", "flows.yaml", flow("      - query: SELECT RAISE(ABORT, 'no')\n      - run: respond\n        with: { status: 200, body: { ok: true } }\n"), "RAISE()", "flows.upsert_select"},
		{"flow rate limit", "flows.yaml", "on:\n  request: { method: POST, path: /api/x-do, rate_limit: \"lots\" }\njobs:\n  main:\n    steps:\n      - run: respond\n        with: { status: 200, body: { ok: true } }\n", "rate_limit", "flows.gotchas_request_input"},
		{"flow after respond", "flows.yaml", flow("      - run: respond\n        with: { status: 200, body: { ok: true } }\n      - query: SELECT 1\n"), "steps after an unconditional", "flows.response_reachability"},
		{"flow input", "flows.yaml", "on:\n  request:\n    method: POST\n    path: /api/x-do\n    inputs:\n      n: { type: integer }\njobs:\n  main:\n    steps:\n      - run: respond\n        with: { status: 200, body: { ok: true } }\n", "unknown type", "flows.inputs_block"},
		{"flow reserved prefix", "flows.yaml", "on:\n  request: { method: GET, path: /api/_ping }\njobs:\n  main:\n    steps:\n      - run: respond\n        with: { status: 200, body: { ok: true } }\n", "reserved prefix", "flows.route_collisions"},
		{"flow unknown step id", "flows.yaml", flow("      - if: ${{ steps.nope.outputs.n }} = 1\n        steps:\n          - run: respond\n            with: { status: 200, body: { ok: true } }\n      - run: respond\n        with: { status: 200, body: { ok: false } }\n"), "no step in this flow has id", "flows.step_ids"},
		{"flow sql_dynamic", "flows.yaml", flow("      - run: sql_dynamic\n        with: { query: \"SELECT * FROM notes WHERE title = '{{title}}'\" }\n      - run: respond\n        with: { status: 200, body: { ok: true } }\n"), "sql_dynamic", "sql-dynamic.validation"},
		{"flow auto-CRUD route", "flows.yaml", "on:\n  request: { method: GET, path: /api/notes }\njobs:\n  main:\n    steps:\n      - run: respond\n        with: { status: 200, body: { ok: true } }\n", "/api/notes", "flows.route_collisions"},
		{"flow event table", "flows.yaml", "on:\n  event: { table: nots, op: insert }\njobs:\n  main:\n    steps:\n      - query: SELECT 1\n", "is not a table of this app", "flows.trigger_event"},
		{"hooks", "hooks.yaml", "on_insert:\n  notes:\n    - frobnicate: yes\n", "hooks.yaml", "hooks.yaml_example"},
		{"hook when", "hooks.yaml", "on_insert:\n  notes:\n    - when: \"nope = 1\"\n      sql: \"UPDATE notes SET title = title WHERE id = {{id}}\"\n", "when", "hooks.when_conditions"},
		{"cron", "cron.yaml", "jobs:\n  - name: nightly\n    schedule: \"not a schedule\"\n    run: SELECT 1\n", "cron", "cron.contract"},
		{"workflows", "workflows.yaml", "order:\n  table: notes\n  field: title\n  initial: draft\n  states: [draft]\n  transitions:\n    - { from: draft, to: nowhere }\n", "workflows.yaml", "workflows.keys"},
		{"app.yaml key", "app.yaml", "routes:\n  - /x\n", "[unknown-app-yaml-key]", "recovery.configuration_loading"},
		{"app.yaml auth key", "app.yaml", "auth:\n  enabled: true\n", "[unknown-auth-key]", "auth.app_yaml_flags"},
		{"app.yaml hipaa control", "app.yaml", "compliance: hipaa\nauth:\n  idle_timeout: 1h\n", "compliance: hipaa requires auth.idle_timeout", "compliance.controls"},
		{"app.yaml compliance value", "app.yaml", "compliance: soc2\n", "compliance = soc2 is not recognized", "compliance.controls"},
		{"app.yaml access mode", "app.yaml", "access:\n  notes:\n    read: anybody\n", "is not a known access mode", "access.modes"},
		{"app.yaml csp", "app.yaml", "csp:\n  script: x\n", "[unknown-csp-key]", "csp.gotchas"},
		{"encrypted.yaml", "encrypted.yaml", "tables:\n  ghosts:\n    fields: [secret]\n", "ghosts", "schema.config_references"},
		{"validators.yaml", "validators.yaml", "notes:\n  - frob: 1\n", "validators.yaml", "schema.cross_field_validators"},
		{"retention.yaml", "retention.yaml", "policies:\n  - table: ghosts\n    ttl: 30d\n", "ghosts", "retention.keys"},
		{"computed.yaml", "computed.yaml", "notes:\n  shout:\n    frob: 1\n", "computed.yaml", "computed.declare"},
		{"computed column missing", "computed.yaml", "notes:\n  shout:\n    expr: \"upper(title)\"\n", "has no column", "schema.config_references"},
		{"tsconfig", "tsconfig.json", "{\"compilerOptions\": {\"noEmit\": false}}", "noEmit", "frontend.how_compile_works"},
		{"page at the root", "about.html", "<!DOCTYPE html><html><body>hi</body></html>", "page contract", "ssr.files"},
		{"dead form", "contact.html", "<form><input name=\"a\"></form>\n", "[dead-form]", "ssr.forms"},
		{"video autoplay", "static/live.html", "<!DOCTYPE html><html><body><video autoplay></video></body></html>", "autoplay", "webrtc.gotchas"},
		{"include", "static/index.html", "<!DOCTYPE html><html><body><include src=\"partials/nope.html\" /></body></html>", "nope.html", "frontend.partials"},
	}
	seen := map[string]bool{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verdict, _ := writeGateVerdict(dir, tc.path, tc.content, true, false, nil)
			if verdict.Message == "" {
				t.Fatalf("%s was not refused", tc.path)
			}
			if !strings.Contains(verdict.Message, tc.says) {
				t.Fatalf("%s was refused for another reason than the sample is for (want %q):\n%s", tc.path, tc.says, verdict.Message)
			}
			if verdict.Docs != tc.docs {
				t.Errorf("docs = %q, want %q\n%s", verdict.Docs, tc.docs, verdict.Message)
			}
			line := docsLine(verdict.Docs)
			if !slices.Contains(strings.Split(verdict.Refusal, "\n"), line) {
				t.Errorf("the refusal has no line %q of its own:\n%s", line, verdict.Refusal)
			}
			if strings.Contains(verdict.Message, "docs: api(at:") {
				t.Errorf("the message (a finding's `message`) carries an address line; only the text refusal does:\n%s", verdict.Message)
			}
			if got := ValidateOnWriteIn(dir, tc.path, tc.content); got != verdict.Refusal {
				t.Errorf("ValidateOnWriteIn answers something else than the refusal:\n%s", got)
			}
			var kept []string
			for _, l := range strings.Split(verdict.Refusal, "\n") {
				if !strings.HasPrefix(l, "docs: api(at:\"") {
					kept = append(kept, l)
				}
			}
			if strings.Join(kept, "\n") != verdict.Message {
				t.Errorf("the refusal without its address lines is not the message:\n%s\n---\n%s", verdict.Refusal, verdict.Message)
			}
			seen[verdict.Docs] = true
		})
	}
	if len(seen) < 25 {
		t.Errorf("the samples reach only %d different keys", len(seen))
	}
}

// Several issues in one file: each keeps its own address line, between the
// issue and the separator, and the recovery footer still ends the refusal.
func TestWriteGateRefusalAddressesEachIssue(t *testing.T) {
	dir := writeApp(t, map[string]string{"app.yaml": "site_name: T\n", "schema.prisma": refusalTestSchema})
	// The key-shaped value is joined here, so this file holds none: a public
	// repository refuses a push that carries one, made-up or not.
	content := "auth:\n  enabled: true\n# sk" + "_live_" + "abcdefghijklmnopqrstuvwx\n"
	verdict, _ := writeGateVerdict(dir, "app.yaml", content, true, false, nil)
	parts := strings.Split(verdict.Refusal, "\n\n---\n\n")
	if len(parts) != 2 {
		t.Fatalf("want two issues, got %d:\n%s", len(parts), verdict.Refusal)
	}
	if !strings.HasPrefix(parts[0], "[secrets]") || !strings.HasSuffix(parts[0], "\n"+docsLine("recovery.file_tools")) {
		t.Errorf("the first issue does not end with its address:\n%s", parts[0])
	}
	if !strings.Contains(parts[1], "\n"+docsLine("auth.app_yaml_flags")+"\n\n"+writeRejectionFooter) {
		t.Errorf("the second issue's address does not sit between the issue and the footer:\n%s", parts[1])
	}
	if !strings.HasSuffix(verdict.Refusal, writeRejectionFooter) || !strings.HasSuffix(verdict.Message, writeRejectionFooter) {
		t.Error("the recovery footer no longer ends the refusal")
	}
	if verdict.Docs != "recovery.file_tools" {
		t.Errorf("a finding's docs is the first issue's address, got %q", verdict.Docs)
	}
	// A flow file is named by its own path in both forms.
	verdict, _ = writeGateVerdict(dir, "flows/v1ping.yaml", "on:\n  request: { method: GET, path: /api/_ping }\njobs:\n  main:\n    steps:\n      - run: respond\n        with: { status: 200, body: { ok: true } }\n", true, false, nil)
	if !strings.HasPrefix(verdict.Message, "flows/v1ping.yaml: ") || !strings.HasPrefix(verdict.Refusal, "flows/v1ping.yaml: ") {
		t.Errorf("a flow file's refusal does not name the file:\n%s", verdict.Refusal)
	}
	// A file that passes answers nothing at all.
	if verdict, _ = writeGateVerdict(dir, "schema.prisma", refusalTestSchema, true, false, nil); verdict != (gateVerdict{}) {
		t.Errorf("a clean file has a verdict: %+v", verdict)
	}
	// A rule on the exemption list answers as it always has: no line.
	verdict, _ = writeGateVerdict(dir, "tests/smoke.yaml", "a: [1\n", true, false, nil)
	if !strings.Contains(verdict.Message, "yaml syntax") || verdict.Refusal != verdict.Message || verdict.Docs != "" {
		t.Errorf("an exempt rule's refusal changed: %+v", verdict)
	}
	// A refusal raised after the validators gets the same line.
	if got := gateRefusal(gateSchemaDrop, "schema.prisma not written: it removes the model of a table that still holds data"); !strings.HasSuffix(got, "\n"+docsLine("schema.removed_models")) {
		t.Errorf("gateRefusal: %q", got)
	}
	if got := gateRefusal(gateAutoRun, "resolve app directory: no such file"); strings.Contains(got, "docs:") {
		t.Errorf("an I/O failure names no rule and got an address: %q", got)
	}
}

// A check reports the address as a field of the finding, and its text
// renderings as one more line under the message.
func TestCheckFindingsCarryTheAddress(t *testing.T) {
	dir := writeApp(t, map[string]string{
		"app.yaml":      "site_name: T\n",
		"schema.prisma": refusalTestSchema,
		"flows.yaml":    "on:\n  request: { method: POST, path: /api/x-do, auth: required }\njobs:\n  main:\n    steps:\n      - run: teleport\n",
		"hooks.yaml":    "on_insert:\n  ghosts:\n    - sql: \"DELETE FROM ghosts WHERE id = {{id}}\"\n",
	})
	report := RunSourceCheck(dir, "")
	byDocs := map[string]CheckFinding{}
	for _, f := range report.Findings {
		byDocs[f.Docs] = f
		if strings.Contains(f.Message, "docs: api(at:") {
			t.Errorf("a finding's message carries the address line:\n%s", f.Message)
		}
	}
	syntax, ok := byDocs["flows.step_types"]
	if !ok || syntax.Source != "syntax" || syntax.File != "flows.yaml" || !strings.Contains(syntax.Message, "isn't a known step type") {
		t.Fatalf("no syntax finding with docs flows.step_types: %+v", report.Findings)
	}
	if cross, ok := byDocs["schema.config_references"]; !ok || cross.Source != "cross_file" {
		t.Errorf("the cross-file warning carries no address: %+v", report.Findings)
	}

	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Findings []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, f := range decoded.Findings {
		for _, key := range []string{"severity", "source", "message"} {
			if _, ok := f[key]; !ok {
				t.Errorf("a finding lost its %q field: %v", key, f)
			}
		}
	}
	if !strings.Contains(string(encoded), `"docs":"flows.step_types"`) {
		t.Errorf("the JSON report has no docs field: %s", encoded)
	}
	// A finding no key covers has no docs field at all, as before.
	bare, _ := json.Marshal(CheckFinding{Severity: "error", Source: "check", Message: "m"})
	if string(bare) != `{"severity":"error","source":"check","message":"m"}` {
		t.Errorf("a finding without an address changed shape: %s", bare)
	}

	text := FormatReport(report)
	if !strings.Contains(text, "\n  "+docsLine("flows.step_types")+"\n") {
		t.Errorf("FormatReport does not print the address under the message:\n%s", text)
	}
	// `benmore test` fails on the same finding and says where to read.
	var result *AppTestResult
	for _, r := range sourceCheckTestResults(dir) {
		if strings.Contains(r.Message, "isn't a known step type") {
			result = &r
		}
	}
	if result == nil || !strings.HasSuffix(result.Message, "\n"+docsLine("flows.step_types")) {
		t.Errorf("the test runner's source-check failure has no address line: %+v", result)
	}
}

// ===== What a refused request answers =====

func refusalBody(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	if got := w.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Fatalf("Content-Type %q", got)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("%v: %s", err, w.Body.String())
	}
	return body
}

// The envelope builders of the common runtime refusals add `docs` and
// leave every other field as it was.
func TestRuntimeRefusalsCarryTheAddress(t *testing.T) {
	app := &App{Design: &DesignConfig{Auth: map[string]string{}}, Access: &AccessConfig{}}
	cases := []struct {
		name   string
		write  func(w http.ResponseWriter)
		status int
		fields map[string]any // fields the answer had before, unchanged
		docs   string
	}{
		{"CSRF", func(w http.ResponseWriter) { httpError(w, "Invalid CSRF token", http.StatusForbidden) }, 403,
			map[string]any{"error": "Invalid CSRF token"}, "csrf.how_to_send"},
		{"scope denied", func(w http.ResponseWriter) {
			httpJSON(w, http.StatusForbidden, scopeDeniedBody(scopeDenied(&Session{}, "notes", "read")))
		}, 403, nil, "rbac.gotchas"},
		{"unmatched route", writeUnmatchedAPINotFound, 404,
			map[string]any{"error": "not_found", "message": "no API route matches this path, or the app's access rules do not let you use it"}, "errors.common_envelopes"},
		{"access rule", func(w http.ResponseWriter) { writeCRUDOpDenied(w, app, "notes", OpWrite, "admin", &Session{}, false) }, 403,
			map[string]any{"error": "forbidden", "message": "the app's access rules do not let you create rows in notes (its `write` rule under access: in app.yaml)"}, "access.operations"},
		{"command-owned field", func(w http.ResponseWriter) {
			writeOwnedFieldRefusal(w, &ownedFieldError{Field: "notes.status", Command: "close"})
		}, 403, map[string]any{"error": "field_owned_by_command", "field": "notes.status", "command": "close", "message": "this field can only be changed by its command"}, "scoping.command_owned_fields"},
		{"uploads off", func(w http.ResponseWriter) { writeUploadsDisabled(w, "photo") }, 403,
			map[string]any{"error": "uploads_disabled", "field": "photo"}, "uploads.feature_gate"},
		{"body too large", func(w http.ResponseWriter) { writeRequestBodyTooLarge(w, 1<<20) }, 413,
			map[string]any{"error": "request body too large: the limit is 1.0 MB (1048576 bytes)", "limit_bytes": float64(1 << 20)}, "flows.request_body"},
		{"foreign key", func(w http.ResponseWriter) { writeFKTargetDenial(w, &fkTargetError{}) }, 422, nil, "scoping.foreign_keys"},
		{"storage full", func(w http.ResponseWriter) { httpJSON(w, storageFullStatus, storageFullBody(nil)) }, 507,
			map[string]any{"error": "storage cap reached", "code": "storage_limit"}, "recovery.storage_limit"},
		{"media allowance", func(w http.ResponseWriter) {
			respondMediaAllowance(w, &mediaAllowanceError{Message: "media storage allowance reached", UsedBytes: 2 << 30, LimitBytes: 1 << 30})
		}, 507, map[string]any{"error": "storage cap reached", "code": "media_storage_limit", "limit_bytes": float64(1 << 30)}, "uploads.storage_allowance"},
		{"lock held", func(w http.ResponseWriter) { httpJSON(w, http.StatusConflict, lockErrorResponse(false, "a@b.c")) }, 409,
			map[string]any{"error": "record is locked by another user"}, "locks.conflict"},
		{"app-wide rate limit", func(w http.ResponseWriter) {
			refuseRateLimited(w, httptest.NewRequest("GET", "/api/notes", nil), 0)
		}, 429, map[string]any{"error": rateLimitedMessage}, "errors.text_answers"},
		{"email verification", func(w http.ResponseWriter) { httpJSON(w, http.StatusForbidden, unverifiedCredentialBody(app)) }, 403,
			map[string]any{"error": "email_verification_required"}, "auth.account_state_signin"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			tc.write(w)
			if w.Code != tc.status {
				t.Fatalf("status %d, want %d: %s", w.Code, tc.status, w.Body.String())
			}
			body := refusalBody(t, w)
			if body["docs"] != tc.docs {
				t.Errorf("docs = %v, want %q: %s", body["docs"], tc.docs, w.Body.String())
			}
			for key, want := range tc.fields {
				if body[key] != want {
					t.Errorf("%s = %v, want %v", key, body[key], want)
				}
			}
		})
	}

	// A sentence whose rule depends on the route gets no address from
	// httpError: only the route knows what it means.
	for _, sentence := range []string{"authentication required", "Not found", "forbidden", "title is required"} {
		w := httptest.NewRecorder()
		httpError(w, sentence, http.StatusBadRequest)
		if body := refusalBody(t, w); len(body) != 1 || body["error"] != sentence {
			t.Errorf("httpError(%q) answered %v; want only the error", sentence, body)
		}
	}
	// Outside /api/ the rate-limit refusal stays the text a browser shows.
	w := httptest.NewRecorder()
	refuseRateLimited(w, httptest.NewRequest("GET", "/contact", nil), 0)
	if got := strings.TrimSpace(w.Body.String()); got != rateLimitedMessage {
		t.Errorf("a page's rate-limit refusal changed: %q", got)
	}
}

// The auto-CRUD 401 in each of its three forms.
func TestUnauthenticatedBodyCarriesTheAddress(t *testing.T) {
	app := &App{Design: &DesignConfig{Auth: map[string]string{}}, Access: &AccessConfig{}}
	anonymous := httptest.NewRequest("GET", "/api/notes", nil)
	stale := httptest.NewRequest("GET", "/api/notes", nil)
	stale.Header.Set("Authorization", "Bearer gone")
	for name, raw := range map[string]string{
		"owner-scoped read": unauthenticatedAPIBody(app, anonymous, "notes", OpRead, true),
		"plain":             unauthenticatedAPIBody(app, anonymous, "notes", OpWrite, true),
		"stale credential":  unauthenticatedAPIBody(app, stale, "notes", OpRead, true),
	} {
		var body map[string]any
		if err := json.Unmarshal([]byte(raw), &body); err != nil {
			t.Fatalf("%s: %v: %s", name, err, raw)
		}
		if body["error"] != "authentication required" || body["docs"] != "access.gotchas" {
			t.Errorf("%s: %s", name, raw)
		}
		if _, hinted := body["hint"]; hinted != (name != "plain") {
			t.Errorf("%s: hint presence changed: %s", name, raw)
		}
	}
}

// The connector's failed tool result names the key for its code in _meta,
// beside error_code; the text an assistant reads is unchanged.
func TestConnectorFailureCarriesTheAddress(t *testing.T) {
	for code, want := range map[string]string{
		"denied":            "connector.connector_errors",
		"incomplete_result": "connector.connector_errors",
		"approval_required": "connector.connector_commit",
	} {
		result := appMCPSDKFailure(appMCPResultFailure(code))
		if result.Meta["error_code"] != code || result.Meta["docs"] != want || result.Meta["observed_at"] == nil || !result.IsError {
			t.Errorf("%s: meta %v", code, result.Meta)
		}
		encoded, _ := json.Marshal(result.Content)
		if strings.Contains(string(encoded), "docs") {
			t.Errorf("%s: the result's text names the docs address: %s", code, encoded)
		}
	}
	if got := appMCPHookRefusedResult(&appMCPCommandHookError{Table: "notes"}).Meta["docs"]; got != "connector.connector_hooks_effects" {
		t.Errorf("hook_refused: docs %v", got)
	}
}
