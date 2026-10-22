//go:build !cli

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Incident, 2026-10-14 (fixed in benmore-go#464): the MCP
// connector's single and batch review pages sent `Referrer-Policy:
// no-referrer`. A real browser then posts the approve form with
// `Origin: null`, and appMCPBoundCSRF refused it: no person could approve any
// connector change from a browser, on any app. The Go tests passed, because
// net/http never derives `Origin: null` from a referrer policy; security.md 5b
// already said "never no-referrer" and the documentation stopped nothing.
//
// The rule: a framework file may not set Referrer-Policy no-referrer on a page
// that also renders a same-origin `<form method="post"`. The two halves
// usually sit in different declarations (the policy in a shared opts var or a
// handler, the form in a template var), so the scan links declarations: a
// declaration holding a "no-referrer" string literal is flagged when it, or a
// declaration within referenceDepth hops of it, can also reach a declaration
// holding a post-form literal through the same handler. Source scans are the
// only check that sees this, because the defect lives in a header the test
// client never interprets (TestReferrerPolicyBrowserPostsAreNotRefusedForOrigin
// is the behavioural half).
const referenceDepth = 2

// noReferrerFormAllowlist names the declarations that set no-referrer next to
// a post-form literal on purpose. Key: "file.go:enclosingDecl". Every entry
// must say why its form never needs to name this origin, and the scan fails
// when an entry in a present source file no longer matches a no-referrer
// literal (stale entries hide the next real one). Public exports omit the
// private files below, so their absent-file exemptions do not apply there.
var noReferrerFormAllowlist = map[string]string{
	// The CLI token hand-off page posts a self-submitting form to
	// http://127.0.0.1:<port>/callback (form-action pinned to that one port by
	// CSP). It is cross-origin by design: the loopback listener never checks
	// Origin against this host, and no-referrer keeps the one-time token page's
	// URL out of the loopback request. It posts nothing to this origin.
	"oauth_cli_token.go:writeCLITokenHandoffPage": "cross-origin form to the CLI's loopback listener, by design",

	// ServeEdgeSubdomain sets no-referrer on the served edge page (user-authored
	// HTML on its own isolated origin, 37a). The scan links it to the password
	// gate's `<form method="POST" action="/_paste/unlock">` only because both
	// are reachable from the same handler: renderEdgeLockGate is a separate
	// early-return response that sets no Referrer-Policy at all, so that form
	// posts under the server default (strict-origin-when-cross-origin) and
	// names its origin. The unlock POST has no CSRF origin gate either. If the
	// gate ever starts sending no-referrer itself, this entry is wrong.
	"edge_router.go:ServeEdgeSubdomain": "no-referrer is on the served edge page; the lock-gate form is a separate response without the header",
}

var (
	postFormRe     = regexp.MustCompile(`(?is)<form\b[^>]*\bmethod\s*=\s*["']?post\b`)
	noReferrerMeta = regexp.MustCompile(`(?is)name\s*=\s*["']referrer["'][^>]*content\s*=\s*["']no-referrer`)
)

func isNoReferrerLiteral(s string) bool {
	if noReferrerMeta.MatchString(s) {
		return true
	}
	if len(s) > 64 { // prose that merely mentions the policy
		return false
	}
	for _, part := range strings.Split(s, ",") {
		if strings.EqualFold(strings.TrimSpace(part), "no-referrer") {
			return true
		}
	}
	return false
}

type referrerDecl struct {
	name, file string
	noRefLines []int // lines of no-referrer literals
	hasForm    bool
	refs       map[string]bool // package-level identifiers mentioned
}

func scanReferrerDecls(t *testing.T, dir string) (map[string]*referrerDecl, map[string]bool) {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no framework sources found (glob err %v)", err)
	}
	fset := token.NewFileSet()
	decls := map[string]*referrerDecl{}
	sourceFiles := map[string]bool{}
	for _, path := range files {
		f := filepath.Base(path)
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		sourceFiles[f] = true
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(fset, f, src, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		for _, d := range file.Decls {
			var names []string
			switch d := d.(type) {
			case *ast.FuncDecl:
				names = []string{d.Name.Name}
				if d.Recv != nil { // methods: key by type.method, never resolved by bare name
					names = []string{"(method)" + d.Name.Name + "@" + strconv.Itoa(fset.Position(d.Pos()).Line)}
				}
			case *ast.GenDecl:
				for _, s := range d.Specs {
					switch s := s.(type) {
					case *ast.ValueSpec:
						for _, n := range s.Names {
							names = append(names, n.Name)
						}
					case *ast.TypeSpec:
						names = append(names, s.Name.Name)
					}
				}
			}
			if len(names) == 0 {
				continue
			}
			// One record per top-level declaration; every name it declares
			// resolves to it.
			rec := &referrerDecl{name: names[0], file: f, refs: map[string]bool{}}
			ast.Inspect(d, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.BasicLit:
					if n.Kind != token.STRING {
						return true
					}
					s, err := strconv.Unquote(n.Value)
					if err != nil {
						return true
					}
					if isNoReferrerLiteral(s) {
						rec.noRefLines = append(rec.noRefLines, fset.Position(n.Pos()).Line)
					}
					if postFormRe.MatchString(s) {
						rec.hasForm = true
					}
				case *ast.Ident:
					rec.refs[n.Name] = true
				}
				return true
			})
			for _, n := range names {
				decls[f+":"+n] = rec
			}
			decls[":"+names[0]] = rec // by bare name for reference resolution
		}
	}
	if len(sourceFiles) == 0 {
		t.Fatal("no non-test framework sources found")
	}
	return decls, sourceFiles
}

func referrerFormGuardFailures(decls map[string]*referrerDecl, sourceFiles map[string]bool, allowlist map[string]string) []string {

	// reach returns the declarations within `depth` reference hops of root.
	reach := func(root *referrerDecl) map[*referrerDecl]bool {
		seen := map[*referrerDecl]bool{root: true}
		frontier := []*referrerDecl{root}
		for hop := 0; hop < referenceDepth; hop++ {
			var next []*referrerDecl
			for _, d := range frontier {
				for name := range d.refs {
					if r := decls[":"+name]; r != nil && !seen[r] {
						seen[r] = true
						next = append(next, r)
					}
				}
			}
			frontier = next
		}
		return seen
	}

	unique := map[*referrerDecl]bool{}
	for _, d := range decls {
		unique[d] = true
	}
	failures := map[string]string{} // location -> message; one per literal, however many handlers reach it
	allowUsed := map[string]bool{}
	for root := range unique {
		scope := reach(root)
		for d := range scope {
			if len(d.noRefLines) == 0 {
				continue
			}
			var formDecl string // the smallest name, so the message is stable
			for f := range scope {
				if name := f.file + ":" + f.name; f.hasForm && (formDecl == "" || name < formDecl) {
					formDecl = name
				}
			}
			if formDecl == "" {
				continue
			}
			for _, line := range d.noRefLines {
				key := d.file + ":" + d.name
				if _, ok := allowlist[key]; ok {
					allowUsed[key] = true
					continue
				}
				loc := d.file + ":" + strconv.Itoa(line)
				failures[loc] = loc + " (" + d.name + ") sets no-referrer on a page that also renders a post form (" + formDecl + ", reached from " + root.name + "): " +
					"use Referrer-Policy: same-origin (security.md 5b): a same-origin form POST from a no-referrer page carries Origin: null and the CSRF origin gate refuses it"
			}
		}
	}
	locs := make([]string, 0, len(failures))
	for loc := range failures {
		locs = append(locs, loc)
	}
	sort.Strings(locs)
	var messages []string
	for _, loc := range locs {
		messages = append(messages, failures[loc])
	}
	for key := range allowlist {
		file, _, valid := strings.Cut(key, ":")
		if !valid || (sourceFiles[file] && !allowUsed[key]) {
			messages = append(messages, "noReferrerFormAllowlist entry "+strconv.Quote(key)+" matches nothing: delete it (stale entries hide the next real one)")
		}
	}
	sort.Strings(messages)
	return messages
}

func TestNoReferrerPageDoesNotPostASameOriginForm(t *testing.T) {
	decls, sourceFiles := scanReferrerDecls(t, ".")
	for _, failure := range referrerFormGuardFailures(decls, sourceFiles, noReferrerFormAllowlist) {
		t.Error(failure)
	}
	// A public source tree may legitimately contain no no-referrer literals.
	// Synthetic controls below prove detection without requiring a live hazard
	// or a private-only exemption to exist in every distribution.
}

func TestNoReferrerFormGuardSourceTrees(t *testing.T) {
	const unsafePage = `package main
func page() { setPolicy("no-referrer"); render("<form method='post'>") }
`
	const safePage = `package main
func page() { setPolicy("same-origin"); render("<form method='post'>") }
`
	tests := []struct {
		name      string
		files     map[string]string
		allowlist map[string]string
		want      []string
	}{
		{
			name:  "direct hazard",
			files: map[string]string{"page.go": unsafePage},
			want:  []string{"sets no-referrer on a page that also renders a post form"},
		},
		{
			name: "shared policy and template",
			files: map[string]string{
				"policy.go":   `package main; var policy = "no-referrer"`,
				"template.go": `package main; var template = "<form method='POST'>"`,
				"page.go":     `package main; func page() { setPolicy(policy); render(template) }`,
			},
			want: []string{"sets no-referrer on a page that also renders a post form"},
		},
		{
			name:  "meta policy hazard",
			files: map[string]string{"page.go": `package main; var page = "<meta name='referrer' content='no-referrer'><form method='post'>"`},
			want:  []string{"sets no-referrer on a page that also renders a post form"},
		},
		{
			name:      "clean public tree without private source",
			files:     map[string]string{"page.go": safePage},
			allowlist: map[string]string{"private.go:handoff": "cross-origin handoff"},
		},
		{
			name:      "public hazard remains rejected with absent private exemption",
			files:     map[string]string{"page.go": unsafePage},
			allowlist: map[string]string{"private.go:handoff": "cross-origin handoff"},
			want:      []string{"sets no-referrer on a page that also renders a post form"},
		},
		{
			name:      "reviewed exception in present source",
			files:     map[string]string{"private.go": unsafePage},
			allowlist: map[string]string{"private.go:page": "cross-origin handoff"},
		},
		{
			name:      "stale exception after policy change",
			files:     map[string]string{"private.go": safePage},
			allowlist: map[string]string{"private.go:page": "cross-origin handoff"},
			want:      []string{"matches nothing: delete it"},
		},
		{
			name:      "stale exception after declaration rename",
			files:     map[string]string{"private.go": unsafePage},
			allowlist: map[string]string{"private.go:oldPage": "cross-origin handoff"},
			want:      []string{"matches nothing: delete it", "sets no-referrer on a page that also renders a post form"},
		},
		{
			name:  "test fixtures are not runtime pages",
			files: map[string]string{"page.go": safePage, "fixture_test.go": unsafePage},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, src := range tt.files {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			decls, sourceFiles := scanReferrerDecls(t, dir)
			failures := referrerFormGuardFailures(decls, sourceFiles, tt.allowlist)
			if len(failures) != len(tt.want) {
				t.Fatalf("got failures %q, want %q", failures, tt.want)
			}
			for i, want := range tt.want {
				if !strings.Contains(failures[i], want) {
					t.Errorf("failure %q does not contain %q", failures[i], want)
				}
			}
		})
	}
}
