//go:build !cli

package main

import (
	"database/sql"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Manifest validator inventory.
//
// Two file-handler validators once had no production caller: they were
// reachable only through a helper that tests called, so every test of them
// passed while `benmore mcp review` accepted what they refuse. This test reads
// the source so that cannot happen again:
//
//   - every validateAppMCP* function in non-test code is called from non-test
//     code (a validator only tests call belongs in a _test.go file);
//   - every one of them is classified below, either as a review check, which
//     must then be reached from `benmore mcp review` and `mcp check`/`inspect`
//     through plain calls, or with what it checks instead and when.
//
// A new validator therefore cannot land without being wired into review or
// stated here to belong somewhere else.

// appMCPReviewEntryPoints are what `benmore mcp review`, `mcp check` and `mcp
// inspect` run.
var appMCPReviewEntryPoints = []string{"reviewAppMCPSource", "inspectAppMCPSource"}

const appMCPReviewCheck = "review"

// appMCPValidatorInventory classifies every validateAppMCP* function:
// appMCPReviewCheck, or why review does not run it.
var appMCPValidatorInventory = map[string]string{
	// The manifest document itself.
	"validateAppMCPYAMLNode":                  appMCPReviewCheck,
	"validateAppMCPManifestGated":             appMCPReviewCheck,
	"validateAppMCPConnections":               appMCPReviewCheck,
	"validateAppMCPResourceDeclaration":       appMCPReviewCheck,
	"validateAppMCPDeepLink":                  appMCPReviewCheck,
	"validateAppMCPFileMembershipConstraints": appMCPReviewCheck,
	"validateAppMCPReviewFields":              appMCPReviewCheck,
	"validateAppMCPReviewText":                appMCPReviewCheck,
	"validateAppMCPUpdateDeclaration":         appMCPReviewCheck,
	"validateAppMCPSchema":                    appMCPReviewCheck,
	"validateAppMCPArtifactDecl":              appMCPReviewCheck,
	"validateAppMCPExternalGate":              appMCPReviewCheck,
	// The manifest against the rest of the reviewed source.
	"validateAppMCPDeployableSources":               appMCPReviewCheck,
	"validateAppMCPSourceBindings":                  appMCPReviewCheck,
	"validateAppMCPFileColumnBindings":              appMCPReviewCheck,
	"validateAppMCPFileMembershipConstraintBinding": appMCPReviewCheck,
	"validateAppMCPFileUploadTenantBinding":         appMCPReviewCheck,
	"validateAppMCPBindingsForTables":               appMCPReviewCheck,
	"validateAppMCPCommandDescriptor":               appMCPReviewCheck,
	"validateAppMCPCommandTransfer":                 appMCPReviewCheck,
	"validateAppMCPReviewBindings":                  appMCPReviewCheck,
	"validateAppMCPCommandIntentBindings":           appMCPReviewCheck,
	"validateAppMCPCommandComputeSources":           appMCPReviewCheck,
	"validateAppMCPFlowInputContract":               appMCPReviewCheck,
	"validateAppMCPRouteBindings":                   appMCPReviewCheck,
	"validateAppMCPRegisteredBindings":              appMCPReviewCheck,
	"validateAppMCPDeclaredSources":                 appMCPReviewCheck,
	"validateAppMCPTransferOperation":               appMCPReviewCheck,
	"validateAppMCPOpenAPIPath":                     appMCPReviewCheck,
	"validateAppMCPOpenAPISchemaKeywords":           appMCPReviewCheck,

	// Owner authority state on the host: not part of the reviewed source.
	"validateAppMCPAuthorityBindingAuthority": "authority directory binding, checked when owner state is read or written",
	"validateAppMCPAuthorityBindingDirectory": "authority directory binding, checked when owner state is read or written",
	"validateAppMCPAuthorityBindingLocation":  "authority directory binding, checked when owner state is read or written",
	"validateAppMCPAuthorityBindingParent":    "authority directory binding, checked when owner state is read or written",
	"validateAppMCPAuthorityBindingRoot":      "authority directory binding, checked when owner state is read or written",
	"validateAppMCPAuthorityLease":            "authority lock lease, checked while owner state is held",
	"validateAppMCPAuthorityLeaseLocked":      "authority lock lease, checked while owner state is held",
	"validateAppMCPEpoch":                     "a grant's owner epoch, checked when a grant is made, refreshed or used",
	"validateAppMCPWriteLease":                "the approved-writes lease, checked on every table.update write",
	"validateAppMCPWriteManifest":             "reviewed digests against the running source, checked before writes and enrollment",
	"validateAppMCPDigests":                   "reviewed digests against the source on disk, checked on grant use and before writes (a load compares them itself)",
	"validateAppMCPRevisionEnrollment":        "the revision enrollment record, checked when it is read or written",
	"validateAppMCPRevisionEnrollmentPath":    "the revision enrollment file path, checked when enrollment is installed or repaired",
	// Needs the live database, the loaded generation or a call's values.
	"validateAppMCPCandidateRoutes":     "routes against the live database and pending migrations, checked at every load before migration",
	"validateAppMCPCommandDeclaration":  "the loaded command against its tool, checked when a command or grant resolves it",
	"validateAppMCPCommandRuntimePhase": "a phase's steps as loaded, checked before each phase runs (review applies the same SQL function rule through appMCPCheckCommandSQLFunctions)",
	"validateAppMCPCommandRuntimeSteps": "a phase's steps as loaded, checked before each phase runs",
	"validateAppMCPSchemaValue":         "a call's input or output value against the reviewed schema, checked on every call",
	"validateAppMCPSchemaValueAt":       "a call's input or output value against the reviewed schema, checked on every call",
	"validateAppMCPSchemaValuePath":     "a call's input or output value against the reviewed schema, checked on every call",
	"validateAppMCPUpdateInput":         "a table.update call's input, checked on every call",
}

type packageFunction struct {
	calls   map[string]bool // package functions and uniquely named methods called outside function literals
	callers map[string]bool
}

// packagePlainCallGraph parses the package's non-test sources. An edge is a
// direct call written in a function's own body. Calls inside function literals
// are not followed: a route handler registered during review is not run by it.
func packagePlainCallGraph(t *testing.T) map[string]*packageFunction {
	t.Helper()
	sources, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var decls []*ast.FuncDecl
	functions := map[string]bool{}
	methods := map[string]int{}
	for _, source := range sources {
		if strings.HasSuffix(source, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, source, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", source, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			decls = append(decls, fn)
			if fn.Recv == nil {
				functions[fn.Name.Name] = true
			} else {
				methods[fn.Name.Name]++
			}
		}
	}
	graph := map[string]*packageFunction{}
	node := func(name string) *packageFunction {
		if graph[name] == nil {
			graph[name] = &packageFunction{calls: map[string]bool{}, callers: map[string]bool{}}
		}
		return graph[name]
	}
	for _, fn := range decls {
		if fn.Body == nil {
			continue
		}
		// Editions define some functions twice under different build tags; their
		// calls are merged. A method is a node only when its name is unique.
		if fn.Recv != nil && (methods[fn.Name.Name] != 1 || functions[fn.Name.Name]) {
			continue
		}
		from := node(fn.Name.Name)
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if _, literal := n.(*ast.FuncLit); literal {
				return false
			}
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch fun := call.Fun.(type) {
			case *ast.Ident:
				if functions[fun.Name] {
					from.calls[fun.Name] = true
					node(fun.Name).callers[fn.Name.Name] = true
				}
			case *ast.SelectorExpr:
				if methods[fun.Sel.Name] == 1 && !functions[fun.Sel.Name] {
					from.calls[fun.Sel.Name] = true
					node(fun.Sel.Name).callers[fn.Name.Name] = true
				}
			}
			return true
		})
	}
	for name := range functions {
		node(name)
	}
	return graph
}

func TestAppMCPManifestValidatorsHaveProductionCallersOnTheReviewPath(t *testing.T) {
	graph := packagePlainCallGraph(t)
	reached := map[string]bool{}
	pending := append([]string(nil), appMCPReviewEntryPoints...)
	for _, root := range pending {
		if graph[root] == nil {
			t.Fatalf("review entry point %s no longer exists; update appMCPReviewEntryPoints", root)
		}
		reached[root] = true
	}
	for len(pending) > 0 {
		name := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		for callee := range graph[name].calls {
			if !reached[callee] {
				reached[callee] = true
				pending = append(pending, callee)
			}
		}
	}
	var validators []string
	for name := range graph {
		if strings.HasPrefix(name, "validateAppMCP") {
			validators = append(validators, name)
		}
	}
	sort.Strings(validators)
	if len(validators) < 40 {
		t.Fatalf("found only %d validateAppMCP* functions; the source walk is broken", len(validators))
	}
	for _, name := range validators {
		callers := make([]string, 0, len(graph[name].callers))
		for caller := range graph[name].callers {
			if caller != name {
				callers = append(callers, caller)
			}
		}
		sort.Strings(callers)
		class, classified := appMCPValidatorInventory[name]
		switch {
		case len(callers) == 0:
			t.Errorf("%s has no production caller: wire it into validateAppMCPSourceBindings (or the check it belongs to), or move it to a _test.go file", name)
		case !classified:
			t.Errorf("%s (called by %s) is not classified in appMCPValidatorInventory: is it a review check?", name, strings.Join(callers, ", "))
		case class == appMCPReviewCheck && !reached[name]:
			t.Errorf("%s is classified as a review check but no chain of plain calls leads to it from %v (its callers: %s)", name, appMCPReviewEntryPoints, strings.Join(callers, ", "))
		case class == appMCPReviewCheck:
			t.Logf("review   %-46s <- %s", name, strings.Join(callers, ", "))
		default:
			t.Logf("other    %-46s <- %s  [%s]", name, strings.Join(callers, ", "), class)
		}
	}
	for name := range appMCPValidatorInventory {
		if graph[name] == nil {
			t.Errorf("appMCPValidatorInventory lists %s, which no longer exists", name)
		}
	}
	// Review checks that are not named validateAppMCP*.
	for _, name := range []string{"appMCPFileRequirementProblems", "appMCPCheckCommandSQLFunctions", "appMCPCheckCommandDependencyShapes"} {
		if !reached[name] {
			t.Errorf("%s is not on the review path", name)
		}
	}
	// The chain whose missing link was the defect, edge by edge.
	for _, edge := range [][2]string{
		{"reviewAppMCPSource", "loadRuntimeConfigWithManifest"},
		{"inspectAppMCPSource", "loadRuntimeConfig"},
		{"loadRuntimeConfig", "loadRuntimeConfigWithManifest"},
		{"loadRuntimeConfigWithManifest", "stageRuntimeConfig"},
		{"loadRuntimeConfigWithManifest", "reviewRefusal"},
		{"reviewRefusal", "appMCPCheckCommandSQLFunctions"},
		{"stageRuntimeConfig", "validateAppMCPSourceBindings"},
		{"validateAppMCPSourceBindings", "validateAppMCPFileColumnBindings"},
		{"validateAppMCPSourceBindings", "validateAppMCPBindingsForTables"},
		{"validateAppMCPSourceBindings", "validateAppMCPDeclaredSources"},
		{"validateAppMCPSourceBindings", "appMCPFileRequirementProblems"},
		{"appMCPFileRequirementProblems", "validateAppMCPFileMembershipConstraintBinding"},
		{"appMCPFileRequirementProblems", "validateAppMCPFileUploadTenantBinding"},
	} {
		if graph[edge[0]] == nil || !graph[edge[0]].calls[edge[1]] {
			t.Errorf("%s no longer calls %s", edge[0], edge[1])
		}
	}
	// A served load must not refuse what only review refuses: an app reviewed
	// before a check existed would stop loading.
	if graph["loadServedRuntimeConfig"].calls["reviewRefusal"] || graph["stageRuntimeConfig"].calls["reviewRefusal"] || graph["loadServedRuntimeConfig"].calls["loadRuntimeConfigWithManifest"] {
		t.Error("a served load runs reviewRefusal")
	}
}

// validateAppMCPBindings runs the production source-binding checks on the
// files in dir, as a strict load does on its captured sources. Test helper.
func validateAppMCPBindings(dir string, m *AppMCPManifest, flows []Flow) error {
	if m == nil {
		return nil
	}
	definitions, err := appMCPSchemaTableDefinitions(dir)
	if err != nil {
		return err
	}
	problems, err := validateAppMCPSourceBindings(dir, m, flows, definitions, LoadRolesConfig(dir), LoadGroupConfig(dir), LoadEncryptedFieldsConfig(dir))
	if err != nil {
		return err
	}
	if len(problems) > 0 {
		return errors.New(problems[0])
	}
	return nil
}

// validateAppMCPDatabaseBindings checks a manifest's routes against the
// candidate tables of the files in dir and the live database, the check
// validateAppMCPCandidateRoutes runs at load on captured sources. Test helper.
func validateAppMCPDatabaseBindings(dir string, m *AppMCPManifest, flows []Flow, db *sql.DB) error {
	if m == nil {
		return nil
	}
	tables, err := appMCPCandidateTables(dir, db)
	if err != nil {
		return err
	}
	return validateAppMCPRouteBindings(m, flows, tables)
}
