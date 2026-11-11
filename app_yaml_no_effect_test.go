//go:build !cli && !windows

package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// app.yaml keys that are accepted and change nothing (app_yaml_no_effect.go).
//
// Four things are held here:
//
//  1. each key in the table is accepted and warned about, by the post-write
//     check of a write and by `benmore check`, with the replacement where one
//     exists;
//  2. the scaffold writes none of them;
//  3. each key in the table really changes nothing: what the load keeps of it
//     is only the place recorded here, every reference the source makes to
//     that place and to the key's name is listed with why it is not a read,
//     and a served app answers the same with and without the key. A new
//     reference fails the test: the key has gained a reader and its warning
//     goes, or the reference is recorded;
//  4. no other key is in that state: every top-level key the write gate
//     accepts changes the configuration the app loads, and every auth key it
//     accepts is named somewhere in the runtime source.
//
// The source scan reads names, not data flow. It sees a key named as a string
// literal, a struct tag or the identifier it is stored under; it cannot see a
// key read through a name built at run time or held inside a longer string.
// The served-app comparison is the second line for those.

const noEffectSchema = `model Note {
  id        Int      @id @default(autoincrement())
  title     String
  body      String   @default("")
  userId    Int      @default(0) @map("user_id")
  createdAt DateTime @default(now()) @map("created_at")
  updatedAt DateTime @default(now()) @updatedAt @map("updated_at")
}
`

// noEffectBaseYAML is an app.yaml with none of the keys under test. `css:
// themed` and a server-rendered page make the appearance keys observable if
// they ever act.
const noEffectBaseYAML = `site_name: "No effect"
theme: zinc
css: themed
auth:
  identifier: email
`

// noEffectSamples sets each key of the table to a value an author would write.
// A sample that starts with two spaces continues the base file's `auth:`.
var noEffectSamples = map[string]string{
	"description":                      "description: \"ZZ top-level description\"\n",
	"database":                         "database:\n  mode: per_user\n  shared: [notes]\n",
	"frontend":                         "frontend:\n  stack: gotmpl\n",
	"head":                             "head: \"<script>window.ZZHEAD = 1</script>\"\n",
	"radius":                           "radius: \"2rem\"\n",
	"shadow":                           "shadow: \"0 0 99px red\"\n",
	"nav":                              "nav:\n  style: sidebar\n  items: \"ZZNAV\"\n",
	"nav.theme":                        "nav:\n  theme: rose\n",
	"auth.billing_publishable_key_env": "  billing_provider: stripe\n  billing_publishable_key_env: ZZ_PUBLISHABLE\n",
	"auth.public_api":                  "  public_api: \"notes\"\n",
}

// noEffectControls is the same sample without the key under test, for the
// key whose sample needs a working key beside it.
var noEffectControls = map[string]string{
	"auth.billing_publishable_key_env": "  billing_provider: stripe\n",
}

// noEffectYAML is the base file with sample added: the base ends inside its
// auth: section, so an indented sample continues it and any other starts a
// new top-level key.
func noEffectYAML(sample string) string { return noEffectBaseYAML + sample }

func noEffectDir(t *testing.T, appYAML string) string {
	t.Helper()
	dir := t.TempDir()
	writeTestFile(t, dir, "schema.prisma", noEffectSchema)
	writeTestFile(t, dir, "app.yaml", appYAML)
	writeTestFile(t, dir, "about.html", "<page title=\"About\">\n<h1>About</h1><button class=\"btn\">go</button>\n</page>\n")
	return dir
}

func noEffectWarningsIn(report CheckReport) []string {
	var out []string
	for _, f := range report.Findings {
		if f.Source == "config" && f.File == "app.yaml" {
			if f.Severity != "warning" {
				out = append(out, "NOT A WARNING: "+f.Message)
				continue
			}
			out = append(out, f.Message)
		}
	}
	return out
}

// Every key in the table is accepted by the write gate, and the post-write
// check of an app.yaml write and `benmore check` warn about it once, naming
// the replacement where one exists. A write of another file does not repeat
// the warning.
func TestAppYAMLKeysWithoutEffectWarnAndAreAccepted(t *testing.T) {
	want := map[string]string{
		"description":                      "app.yaml: `description:` has no effect. Pages and the web app manifest take their description from `seo.description`; a top-level `description:` is not read. Use `seo.description` instead.",
		"database":                         "app.yaml: `database:` has no effect. An app has one database, and nothing in this section changes how it is stored. Remove it.",
		"head":                             "app.yaml: `head:` has no effect. Tags for the <head> of every server-rendered page go in a head.html file at the app root; a page under static/ writes its own <head>. Use `head.html` instead.",
		"radius":                           "app.yaml: `radius:` has no effect. Server-rendered pages take their corner radius from the CSS variable --radius, which theme.css at the app root can set (`:root { --radius: 0.75rem; }`). Use `theme.css` instead.",
		"shadow":                           "app.yaml: `shadow:` has no effect. No stylesheet reads it; write shadows in your own CSS or utility classes. Remove it.",
		"nav":                              "app.yaml: `nav.items` and `nav.style` have no effect. `nav:` draws no navigation: write the navigation in a layout or a partial. Remove them.",
		"nav.theme":                        "app.yaml: `nav.theme` has no effect. It is read only while top-level `theme:` is absent. Remove it.",
		"auth.billing_publishable_key_env": "app.yaml: `auth.billing_publishable_key_env` has no effect. The Stripe routes use the secret key and the webhook secret only, and nothing sends a publishable key to the browser; the page that loads Stripe.js holds its own `pk_` key. Remove it.",
		"auth.public_api":                  "app.yaml: `auth.public_api` has no effect. It does not make a table public: an anonymous request to a listed table still gets 401. Use `access.<table>.read: anon` instead.",
	}
	for _, entry := range appYAMLNoEffectKeys {
		t.Run(entry.Key, func(t *testing.T) {
			sample, ok := noEffectSamples[entry.Key]
			if !ok || (want[entry.Key] == "") != entry.Quiet {
				t.Fatalf("no sample or expected warning for %s: add both (a quiet key has a sample and no warning)", entry.Key)
			}
			// A quiet key is accepted like the others and reported by nothing.
			var wantWarnings []string
			if !entry.Quiet {
				wantWarnings = []string{want[entry.Key]}
			}
			content := noEffectYAML(sample)
			dir := noEffectDir(t, noEffectBaseYAML)
			if msg := ValidateOnWriteIn(dir, "app.yaml", content); msg != "" {
				t.Fatalf("the write gate refuses a key apps carry: %s", msg)
			}
			writeTestFile(t, dir, "app.yaml", content)
			for name, report := range map[string]CheckReport{
				"the post-write check of app.yaml": RunSourceCheck(dir, "app.yaml"),
				"benmore check":                    RunSourceCheck(dir, ""),
			} {
				if got := noEffectWarningsIn(report); !slices.Equal(got, wantWarnings) {
					t.Errorf("%s:\n got %q\nwant %q", name, got, wantWarnings)
				}
				if report.Errors != 0 {
					t.Errorf("%s reports %d error(s): %+v", name, report.Errors, report.Findings)
				}
			}
			writeTestFile(t, dir, "tests/smoke.yaml", "smoke:\n  steps:\n    - get: \"/health\"\n      expect:\n        status: 200\n")
			if got := noEffectWarningsIn(RunSourceCheck(dir, "tests/smoke.yaml")); len(got) != 0 {
				t.Errorf("a write of another file repeats the warning: %q", got)
			}
		})
	}
	quiet := 0
	for _, entry := range appYAMLNoEffectKeys {
		if entry.Quiet {
			quiet++
		}
	}
	if len(want)+quiet != len(appYAMLNoEffectKeys) {
		t.Errorf("%d expected warnings and %d quiet keys for %d keys in the table", len(want), quiet, len(appYAMLNoEffectKeys))
	}
}

// The cases the table's wording depends on: a section whose read keys are
// left alone, one unread key, a key that still works, and a clean file.
func TestAppYAMLNoEffectWarningCases(t *testing.T) {
	for _, c := range []struct {
		name, yaml string
		want       []string
	}{
		{"a file with none of the keys", noEffectBaseYAML, nil},
		// The label an earlier scaffold wrote into nearly every app.
		{"the frontend label alone", noEffectBaseYAML + "frontend:\n  stack: html\n", nil},
		{"the frontend label beside a reported key", noEffectBaseYAML + "frontend:\n  stack: html\nshadow: lg\n",
			[]string{"app.yaml: `shadow:` has no effect. No stylesheet reads it; write shadows in your own CSS or utility classes. Remove it."}},
		{"nav keys the admin panel reads", noEffectBaseYAML + "nav:\n  brand: \"#ff00aa\"\n  font: Inter\n", nil},
		{"one unread nav key", noEffectBaseYAML + "nav:\n  brand: \"#ff00aa\"\n  style: sidebar\n",
			[]string{"app.yaml: `nav.style` has no effect. `nav:` draws no navigation: write the navigation in a layout or a partial. Remove it."}},
		{"an empty nav section", noEffectBaseYAML + "nav: {}\n",
			[]string{"app.yaml: `nav:` has no effect. `nav:` draws no navigation: write the navigation in a layout or a partial. Remove it."}},
		// Without `theme:` the key is the theme: the warning says to move it.
		{"nav.theme without theme", "site_name: x\nnav:\n  theme: rose\n",
			[]string{"app.yaml: once `theme:` is set, `nav.theme` has no effect. It is read only while top-level `theme:` is absent. Use `theme` instead."}},
		{"seo.description beside description", noEffectBaseYAML + "description: x\nseo:\n  description: y\n",
			[]string{"app.yaml: `description:` has no effect. Pages and the web app manifest take their description from `seo.description`; a top-level `description:` is not read. Use `seo.description` instead."}},
		{"two keys, in table order", noEffectBaseYAML + "shadow: lg\ndatabase:\n  mode: shared\n",
			[]string{
				"app.yaml: `database:` has no effect. An app has one database, and nothing in this section changes how it is stored. Remove it.",
				"app.yaml: `shadow:` has no effect. No stylesheet reads it; write shadows in your own CSS or utility classes. Remove it.",
			}},
		{"a file that is not YAML", "site_name: [\n", nil},
	} {
		if got := appYAMLNoEffectWarnings(c.yaml); !slices.Equal(got, c.want) {
			t.Errorf("%s:\n got %q\nwant %q", c.name, got, c.want)
		}
	}
}

// The unknown-key errors list the keys an author may write instead. They do
// not offer a key that does nothing, or one the gate refuses.
func TestUnknownKeyErrorsListOnlyKeysWithAnEffect(t *testing.T) {
	top := validateAppYAML("site_name: x\nroutes:\n  - /a\n")
	auth := validateAppYAML("site_name: x\nauth:\n  enabled: true\n")
	if !strings.Contains(top, "unknown-app-yaml-key") || !strings.Contains(auth, "unknown-auth-key") {
		t.Fatalf("not the unknown-key errors:\n%s\n%s", top, auth)
	}
	_, list, _ := strings.Cut(top, "Known keys: ")
	list, _, _ = strings.Cut(list, ". Common fabrications")
	offered := strings.Split(list, ", ")
	for _, key := range []string{"site_name", "seo", "auth", "theme", "access"} {
		if !slices.Contains(offered, key) {
			t.Errorf("the top-level list does not offer %q: %s", key, list)
		}
	}
	_, authList, _ := strings.Cut(auth, "Real auth keys: ")
	authList, _, _ = strings.Cut(authList, ". Common fabrications")
	authOffered := strings.Split(authList, ", ")
	for _, key := range []string{"identifier", "redirect", "billing_provider", "require_mfa_for_roles"} {
		if !slices.Contains(authOffered, key) {
			t.Errorf("the auth list does not offer %q: %s", key, authList)
		}
	}
	for _, entry := range appYAMLNoEffectKeys {
		section, key, nested := strings.Cut(entry.Key, ".")
		switch {
		case !nested && slices.Contains(offered, section):
			t.Errorf("the unknown-key error offers `%s:`, which has no effect: %s", section, list)
		case nested && section == "auth" && slices.Contains(authOffered, key):
			t.Errorf("the unknown-auth-key error offers `auth.%s`, which has no effect: %s", key, authList)
		}
	}
	for key := range deadAuthKeys {
		if slices.Contains(authOffered, key) {
			t.Errorf("the unknown-auth-key error offers `auth.%s`, which the gate refuses: %s", key, authList)
		}
	}
}

// Neither scaffold writes a key that has no effect, and what they write
// passes the write gate.
func TestScaffoldWritesNoAppYAMLKeyWithoutEffect(t *testing.T) {
	for name, write := range map[string]func(dir, title string) error{
		"benmore new / create_app":  WriteHTMLScaffoldFiles,
		"deploy of an existing dir": WriteBareScaffoldFiles,
	} {
		dir := t.TempDir()
		if err := write(dir, "Scaffold Check"); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		data, err := os.ReadFile(filepath.Join(dir, "app.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		if got := appYAMLNoEffectWarnings(string(data)); len(got) != 0 {
			t.Errorf("%s writes app.yaml keys that have no effect: %q\n%s", name, got, data)
		}
		if msg := validateAppYAML(string(data)); msg != "" {
			t.Errorf("%s writes an app.yaml the write gate refuses: %s", name, msg)
		}
	}
}

// ---- 3. the keys in the table change nothing ------------------------------

// noEffectStored clears, in a loaded DesignConfig, the place the load keeps
// each key in. Keys the load keeps nothing of have no entry.
var noEffectStored = map[string]func(*DesignConfig){
	"database":                         func(d *DesignConfig) { delete(d.Colors, "_db_mode") },
	"radius":                           func(d *DesignConfig) { d.Radius = "" },
	"shadow":                           func(d *DesignConfig) { d.Shadow = "" },
	"nav":                              func(d *DesignConfig) { delete(d.Nav, "style"); delete(d.Nav, "items") },
	"nav.theme":                        func(d *DesignConfig) { delete(d.Nav, "theme") },
	"auth.billing_publishable_key_env": func(d *DesignConfig) { delete(d.Auth, "billing_publishable_key_env") },
	"auth.public_api":                  func(d *DesignConfig) { delete(d.Auth, "public_api") },
}

// noEffectRefs lists, per key, every reference the runtime source makes to
// the key's name and to the place the load keeps it in, each with why it is
// not a read that does something. A reference is "<probe> <name> <where>":
//
//	lit   a string literal equal to the name, used anywhere but as a map
//	      index or inside a `{"key": value}` pair
//	idx   the name as a string-literal index, with what is indexed
//	      (`app.Design.SEO["description"]` is `idx description SEO`)
//	tag   a `yaml:"name"` struct tag
//	ident an identifier (the field or function the value is kept in)
//	navkey a key read from DesignConfig.Nav
//
// <where> is "<file>:<function> x<occurrences>". An idx reference may end in
// `*` instead: any place that indexes something of that name (tool arguments,
// a map being built) is the same non-read.
var noEffectRefs = map[string]map[string]string{
	"description": {
		"idx description SEO *":                                                     "seo.description, the key that works",
		"idx description args *":                                                    "an MCP tool's `description` argument",
		"idx description attrs *":                                                   "a <page> tag's description attribute",
		"idx description custom *":                                                  "the body of a custom-field request",
		"idx description prop *":                                                    "an OpenAPI property being written",
		"idx description website *":                                                 "JSON-LD being written",
		"idx description webpage *":                                                 "JSON-LD being written",
		"idx description manifest *":                                                "the web app manifest being written (from seo.description)",
		"lit description apidocs.go:schemaControlFor x1":                            "a column named description gets a textarea",
		"lit description template.go:mockValue x1":                                  "sample text for a column named description",
		"lit description testhelpers.go:smartTestValue x1":                          "test data for a column named description",
		"lit description app_mcp_openapi.go:validateAppMCPOpenAPISchemaKeywords x1": "a JSON Schema keyword",
		"lit description flows_command.go:validateCommandSchemaNode x1":             "a JSON Schema keyword",
		"tag description app_mcp_manifest.go:type AppMCPSchema x1":                  "mcp.yaml",
		"tag description app_mcp_manifest.go:type AppMCPTool x1":                    "mcp.yaml",
		"tag description feature_pack.go:type FeaturePackOption x1":                 "a feature pack's manifest",
		"tag description template_gotmpl.go:type Frontmatter x1":                    "a page's front matter",
	},
	"database": {
		"idx database raw config.go:designFromAppYAML x1":       "the load: copies database.mode into Design.Colors[\"_db_mode\"]",
		"idx _db_mode Colors config.go:designFromAppYAML x1":    "that copy, which is the only mention of _db_mode",
		"idx database checks *":                                 "the health report's database check",
		"idx database out *":                                    "the refresh-dev dry-run answer",
		"tag database config.go:type AppYAML x1":                "the AppYAML struct, which nothing decodes into (its only identifier is its declaration)",
		"ident AppYAML config.go:type AppYAML x1":               "the declaration",
		"ident DatabaseConfig config.go:type AppYAML x1":        "the field of that unused struct",
		"ident DatabaseConfig config.go:type DatabaseConfig x1": "the declaration",
	},
	"frontend": {},
	"head": {
		"lit head app_mcp_openapi.go:appMCPOpenAPIChildKind x1": "the HTTP method",
		"lit head app_mcp_openapi.go:generate x1":               "the HTTP method",
		"lit head flows_proxy.go:execStepProxy x1":              "a log label for a HEAD answer",
		"lit head i18n.go:injectI18nBootstrap x1":               "the <head> element of a page",
		"lit head context_cmd.go:BuildContext x1":               "the file type of head.html",
	},
	"radius": {
		"idx radius raw config.go:designFromAppYAML x1":       "the load: stores it in Design.Radius",
		"tag radius types.go:type DesignConfig x1":            "the field's tag; app.yaml is not decoded into the struct",
		"ident Radius types.go:type DesignConfig x1":          "the declaration",
		"ident Radius config.go:designFromAppYAML x1":         "the store",
		"ident Radius appconfig.go:GenerateAppCSS x2":         "the one reader, in a function nothing calls (next line)",
		"ident GenerateAppCSS appconfig.go:GenerateAppCSS x1": "its declaration is its only mention",
	},
	"shadow": {
		"idx shadow raw config.go:designFromAppYAML x1": "the load: stores it in Design.Shadow",
		"tag shadow types.go:type DesignConfig x1":      "the field's tag; app.yaml is not decoded into the struct",
		"ident Shadow types.go:type DesignConfig x1":    "the declaration",
		"ident Shadow config.go:designFromAppYAML x1":   "the store",
	},
	"nav": {
		"idx nav raw config.go:designFromAppYAML x1":       "the load: copies every nav key into Design.Nav",
		"tag nav types.go:type DesignConfig x1":            "the field's tag; app.yaml is not decoded into the struct",
		"ident Nav types.go:type DesignConfig x1":          "the declaration",
		"ident Nav config.go:designFromAppYAML x2":         "the map is made and filled",
		"ident Nav admin.go:adminShell x3":                 "reads theme, brand and font for the /_admin shell: the keys the table lists as read",
		"ident Nav layout.go:wrapLayoutAt x2":              "reads theme (see nav.theme)",
		"ident Nav app_mcp_pages.go:appMCPPageThemeCSS x1": "reads theme (see nav.theme)",
		"lit nav ast.go:elementToAST x1":                   "the <nav> element",
		"lit nav sanitize.go:getHTMLSanitizer x1":          "the <nav> element",
	},
	"nav.theme": {
		"navkey theme layout.go:wrapLayoutAt x2":              "the default that top-level theme: replaces on the next line",
		"navkey theme admin.go:adminShell x1":                 "read only when top-level theme: is absent",
		"navkey theme app_mcp_pages.go:appMCPPageThemeCSS x1": "the default that top-level theme: replaces",
	},
	"auth.billing_publishable_key_env": {
		"idx billing_publishable_key_env Auth billing.go:loadBillingConfig x1": "the load: stores the name in BillingConfig.PublishableKeyEnv",
		"idx billing_publishable_key_env SEO billing.go:loadBillingConfig x1":  "the same store, from the seo section",
		"ident PublishableKeyEnv billing.go:type BillingConfig x1":             "the declaration",
		"ident PublishableKeyEnv billing.go:loadBillingConfig x1":              "the store; nothing reads the field",
	},
	"auth.public_api": {
		"idx public_api Auth crud.go:requireAPIAuthForOp x1":                   "skips this gate's own 401 for a listed table; the access check after it still answers 401 to an anonymous caller (the served comparison below), and a signed-in request to a listed table is not counted by this gate's usage meter",
		"idx public_api Auth testgen_fixtures.go:generatedAnonCreateExpect x1": "the generated test's expected status, which mirrors that gate and comes out 401 either way",
	},
}

// noEffectProbes are the names scanned for each key.
var noEffectProbes = map[string][]string{
	"description":                      {"lit description", "idx description", "tag description"},
	"database":                         {"lit database", "idx database", "tag database", "lit _db_mode", "idx _db_mode", "ident DatabaseConfig", "ident AppYAML"},
	"frontend":                         {"lit frontend", "idx frontend", "tag frontend"},
	"head":                             {"lit head", "idx head", "tag head"},
	"radius":                           {"lit radius", "idx radius", "tag radius", "ident Radius", "ident GenerateAppCSS"},
	"shadow":                           {"lit shadow", "idx shadow", "tag shadow", "ident Shadow"},
	"nav":                              {"lit nav", "idx nav", "tag nav", "ident Nav"},
	"nav.theme":                        {"navkey theme"},
	"auth.billing_publishable_key_env": {"lit billing_publishable_key_env", "idx billing_publishable_key_env", "tag billing_publishable_key_env", "ident PublishableKeyEnv"},
	"auth.public_api":                  {"lit public_api", "idx public_api", "tag public_api"},
}

type sourceIndex struct {
	refs map[string]map[string]int // probe → where → occurrences
}

var (
	noEffectSourceOnce sync.Once
	noEffectSource     *sourceIndex
	noEffectSourceErr  error
)

var yamlTagNameRe = regexp.MustCompile(`yaml:"([^",]*)`)

// runtimeSourceIndex parses every non-test Go file of the package once and
// indexes string literals, indexed names, yaml struct tags, identifiers and
// the keys read from DesignConfig.Nav.
// noEffectFullSourceTree reports whether this is the whole source tree and
// not the public framework export, which leaves the platform files out.
func noEffectFullSourceTree() bool {
	_, err := os.Stat("edition_platform.go")
	return err == nil
}

func runtimeSourceIndex(t *testing.T) *sourceIndex {
	t.Helper()
	noEffectSourceOnce.Do(func() {
		idx := &sourceIndex{refs: map[string]map[string]int{}}
		add := func(probe, where string) {
			if idx.refs[probe] == nil {
				idx.refs[probe] = map[string]int{}
			}
			idx.refs[probe][where]++
		}
		files, err := filepath.Glob("*.go")
		if err != nil {
			noEffectSourceErr = err
			return
		}
		fset := token.NewFileSet()
		for _, name := range files {
			if strings.HasSuffix(name, "_test.go") {
				continue
			}
			file, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
			if err != nil {
				noEffectSourceErr = err
				return
			}
			for _, decl := range file.Decls {
				fn := "(package)"
				switch d := decl.(type) {
				case *ast.FuncDecl:
					fn = d.Name.Name
				case *ast.GenDecl:
					if len(d.Specs) > 0 {
						switch spec := d.Specs[0].(type) {
						case *ast.TypeSpec:
							fn = "type " + spec.Name.Name
						case *ast.ValueSpec:
							if len(spec.Names) > 0 {
								fn = "var " + spec.Names[0].Name
							}
						}
					}
				}
				where := name + ":" + fn
				var stack []ast.Node
				ast.Inspect(decl, func(n ast.Node) bool {
					if n == nil {
						stack = stack[:len(stack)-1]
						return true
					}
					var parent ast.Node
					if len(stack) > 0 {
						parent = stack[len(stack)-1]
					}
					stack = append(stack, n)
					switch node := n.(type) {
					case *ast.TypeSpec:
						// A struct declared in a `type ( ... )` group or inside
						// a function is named by itself.
						if _, grouped := parent.(*ast.GenDecl); grouped {
							where = name + ":type " + node.Name.Name
						}
					case *ast.Ident:
						add("ident "+node.Name, where)
					case *ast.Field:
						if node.Tag != nil {
							for _, m := range yamlTagNameRe.FindAllStringSubmatch(node.Tag.Value, -1) {
								add("tag "+m[1], where)
							}
						}
					case *ast.BasicLit:
						if node.Kind != token.STRING {
							break
						}
						if _, isTag := parent.(*ast.Field); isTag {
							break
						}
						value, err := strconv.Unquote(node.Value)
						if err != nil {
							break
						}
						// A key or value of `{"key": value}` builds a map (a
						// JSON schema, the accepted-key lists); it reads
						// nothing by that name.
						if _, pair := parent.(*ast.KeyValueExpr); pair {
							break
						}
						if indexed, ok := parent.(*ast.IndexExpr); ok && indexed.Index == n {
							base := "(expression)"
							switch x := indexed.X.(type) {
							case *ast.Ident:
								base = x.Name
							case *ast.SelectorExpr:
								base = x.Sel.Name
							}
							add("idx "+value, base+" "+where)
							if base == "Nav" {
								add("navkey "+value, where)
							}
							break
						}
						add("lit "+value, where)
					}
					return true
				})
			}
		}
		noEffectSource = idx
	})
	if noEffectSourceErr != nil {
		t.Fatal(noEffectSourceErr)
	}
	return noEffectSource
}

// noEffectRefsFound lists what the source holds for probes, as noEffectRefs
// writes it.
func noEffectRefsFound(index *sourceIndex, probes []string) []string {
	var out []string
	for _, probe := range probes {
		for where, n := range index.refs[probe] {
			out = append(out, fmt.Sprintf("%s %s x%d", probe, where, n))
		}
	}
	slices.Sort(out)
	return out
}

// noEffectRefRecorded returns the recorded entry that covers ref: ref itself,
// or `idx <name> <base> *`.
func noEffectRefRecorded(recorded map[string]string, ref string) (string, bool) {
	if _, ok := recorded[ref]; ok {
		return ref, true
	}
	if parts := strings.Fields(ref); len(parts) >= 3 && parts[0] == "idx" {
		wildcard := strings.Join(parts[:3], " ") + " *"
		if _, ok := recorded[wildcard]; ok {
			return wildcard, true
		}
	}
	return "", false
}

// noEffectServed loads an app with appYAML and returns what it serves at the
// paths an appearance, description, routing or access key would show in.
func noEffectServed(t *testing.T, appYAML string) map[string]string {
	t.Helper()
	app, err := loadApp(noEffectDir(t, appYAML))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	t.Cleanup(app.Shutdown)
	mux := buildAppMux(app, false, "https://no-effect.example")
	member := createCrudScopeSession(t, app, "member@example.com", "user", "", "")
	out := map[string]string{}
	// What differs between two loads of one app: tokens (the CSRF token
	// carries a timestamp), nonces, asset versions and times.
	normalize := regexp.MustCompile(`(csrf-token" content|name="_csrf" value)="[^"]*"|[0-9a-f]{32,}|nonce-[A-Za-z0-9+/=_-]+|nonce="[^"]*"|\?v=[A-Za-z0-9]+|[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9:]{8}Z?`)
	for _, probe := range []struct{ who, path string }{
		{"", "/about"}, {"", "/manifest.json"}, {"", "/api/_docs"}, {"", "/llms.txt"}, {"", "/robots.txt"},
		{"", "/api/notes"}, {"", "/api/notes/1"}, {"", "/login"},
		{member, "/about"}, {member, "/api/notes"}, {member, "/api/_schema"}, {member, "/_admin"},
	} {
		req := httptest.NewRequest(http.MethodGet, probe.path, nil)
		who := "anonymous"
		if probe.who != "" {
			req.Header.Set("Authorization", "Bearer "+probe.who)
			who = "member"
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		out[who+" GET "+probe.path] = fmt.Sprintf("%d %s\n%s", rec.Code, rec.Header().Get("Content-Security-Policy"), normalize.ReplaceAllString(rec.Body.String(), "X"))
	}
	return out
}

// Each key in the table changes nothing: the load keeps of it only the place
// recorded in noEffectStored, the source touches that place and the key's
// name only where noEffectRefs says, and an app serves the same responses
// with and without it.
func TestAppYAMLKeysWithoutEffectHaveNoReader(t *testing.T) {
	index := runtimeSourceIndex(t)
	for _, entry := range appYAMLNoEffectKeys {
		t.Run(entry.Key, func(t *testing.T) {
			sample := noEffectSamples[entry.Key]
			control := noEffectBaseYAML + noEffectControls[entry.Key]
			with := noEffectYAML(sample)

			// What the load keeps.
			var rawWith, rawWithout map[string]any
			if err := decodeConfigYAML([]byte(with), &rawWith); err != nil {
				t.Fatal(err)
			}
			if err := decodeConfigYAML([]byte(control), &rawWithout); err != nil {
				t.Fatal(err)
			}
			loaded, plain := designFromAppYAML(rawWith), designFromAppYAML(rawWithout)
			if clear := noEffectStored[entry.Key]; clear != nil {
				if reflect.DeepEqual(loaded, plain) {
					t.Errorf("noEffectStored has an entry for %s, but the load keeps nothing of the key", entry.Key)
				}
				clear(loaded)
			}
			if !reflect.DeepEqual(loaded, plain) {
				t.Errorf("the load keeps %s somewhere noEffectStored does not name:\n with %+v\n without %+v", entry.Key, loaded, plain)
			}

			// Where the source names it.
			probes := noEffectProbes[entry.Key]
			recorded, known := noEffectRefs[entry.Key]
			if len(probes) == 0 || !known {
				t.Fatalf("no probes or no recorded references for %s", entry.Key)
			}
			used := map[string]bool{}
			for _, ref := range noEffectRefsFound(index, probes) {
				covering, ok := noEffectRefRecorded(recorded, ref)
				if !ok {
					t.Errorf("new reference to app.yaml %s: %s\n  If it reads the key, the key has an effect: take it out of appYAMLNoEffectKeys and out of the topic sentence that calls it dead. Otherwise record it in noEffectRefs with why it is not a read.", entry.Key, ref)
				}
				used[covering] = true
			}
			// Only the full tree can call a recorded reference stale: the
			// public export holds the framework files alone, so evidence
			// that lives in a platform or cloud file is not there. A new
			// reference is refused in either tree (above).
			if noEffectFullSourceTree() {
				for ref := range recorded {
					if !used[ref] {
						t.Errorf("noEffectRefs[%q] records %q, which the source no longer has: update the evidence", entry.Key, ref)
					}
				}
			}

			// What an app serves.
			a, b := noEffectServed(t, with), noEffectServed(t, control)
			for _, probe := range slices.Sorted(maps.Keys(b)) {
				if a[probe] != b[probe] {
					t.Errorf("%s answers differently with app.yaml %s, so the key has an effect:\n with    %.300q\n without %.300q", probe, entry.Key, a[probe], b[probe])
				}
			}
		})
	}
	for key := range noEffectProbes {
		if _, ok := appYAMLNoEffectEntry(key); !ok {
			t.Errorf("probes for %s, which is not in the table", key)
		}
	}
	// The nav keys the source reads are exactly the ones the table leaves
	// out of the `nav` warning.
	var read []string
	for probe := range index.refs {
		if key, ok := strings.CutPrefix(probe, "navkey "); ok {
			read = append(read, key)
		}
	}
	slices.Sort(read)
	nav, _ := appYAMLNoEffectEntry("nav")
	if want := slices.Sorted(slices.Values(nav.Reads)); !slices.Equal(read, want) {
		t.Errorf("the source reads nav keys %v; the table's `nav` entry lists %v as read", read, want)
	}
}

// ---- 4. no other accepted key is in that state ----------------------------

// everyAppYAMLKey sets every top-level key the write gate accepts, each to a
// value that turns it on. One document, so keys that depend on one another
// (table_scopes on roles) are judged together.
var everyAppYAMLKey = map[string]string{
	"site_name":        "site_name: \"Everything\"\n",
	"description":      "description: \"ZZ top-level description\"\n",
	"theme":            "theme: rose\n",
	"mode":             "mode: light\n",
	"font":             "font: Inter\n",
	"brand":            "brand: \"#ff00aa\"\n",
	"css":              "css: themed\n",
	"radius":           "radius: \"2rem\"\n",
	"shadow":           "shadow: lg\n",
	"nav":              "nav:\n  style: sidebar\n",
	"seo":              "seo:\n  description: \"ZZ seo description\"\n",
	"auth":             "auth:\n  identifier: email\n",
	"roles":            "roles:\n  manager:\n    scopes: [\"notes:read\"]\n",
	"features":         "features:\n  admin: false\n",
	"groups":           "groups:\n  table: members\n  key: org_id\n  user_field: user_id\n",
	"pwa":              "pwa:\n  name: \"P\"\n",
	"recording":        "recording:\n  mask_inputs: true\n",
	"backup":           "backup:\n  interval: \"12h\"\n  keep: 3\n",
	"versioned":        "versioned: [notes]\n",
	"aggregates":       "aggregates:\n  note_count:\n    sql: \"SELECT COUNT(*) FROM notes\"\n    refresh: \"5m\"\n",
	"database":         "database:\n  mode: per_user\n",
	"head":             "head: \"<meta name=zz>\"\n",
	"oauth":            "oauth:\n  discord:\n    auth_url: https://discord.com/api/oauth2/authorize\n    token_url: https://discord.com/api/oauth2/token\n    userinfo_url: https://discord.com/api/users/@me\n    scopes: \"identify email\"\n",
	"frontend":         "frontend:\n  stack: html\n",
	"scopes":           "scopes:\n  notes:\n    public_read_when: \"1 = 1\"\n",
	"access":           "access:\n  notes: everyone\n",
	"auto_memberships": "auto_memberships:\n  notes:\n    table: members\n",
	"csp":              "csp:\n  img_src: \"https://img.example.com\"\n",
	"table_scopes":     "table_scopes: access\n",
	"compliance":       "compliance: hipaa\n",
	"ws_rooms":         "ws_rooms:\n  \"room-:id\": members(org_id, user_id)\n",
	"encrypted":        "encrypted:\n  notes: [body]\n",
}

const everyKeySchema = noEffectSchema + `
model Member {
  id     Int @id @default(autoincrement())
  orgId  Int @map("org_id")
  userId Int @map("user_id")

  @@map("members")
}
`

// loadedAppConfig is everything an app loads from app.yaml: what a start and
// a reload stage, and the sections read on demand afterwards.
func loadedAppConfig(t *testing.T, appYAML string) map[string]any {
	t.Helper()
	dir := t.TempDir()
	writeTestFile(t, dir, "schema.prisma", everyKeySchema)
	writeTestFile(t, dir, "app.yaml", appYAML)
	staged, err := loadRuntimeConfig(dir)
	if err != nil {
		t.Fatalf("load: %v\n%s", err, appYAML)
	}
	return map[string]any{
		"design": staged.design, "backup": staged.backup, "groups": staged.group, "scopes": staged.scopes,
		"access": staged.access, "roles": staged.roles, "encrypted": staged.encrypted, "ws_rooms": staged.wsRooms,
		"versioned":  parseVersionedConfig([]byte(appYAML)),
		"aggregates": parseAggregateConfig([]byte(appYAML)),
		"oauth":      oauthProvidersForApp(dir),
	}
}

// Every top-level key the write gate accepts either changes the
// configuration the app loads or is in the table, and every auth key it
// accepts is named by the runtime source or is in the table. A key added to
// the accepted lists with nothing behind it fails here.
func TestAppYAMLKeysNothingReadsAreInTheTable(t *testing.T) {
	document := func(without string) string {
		var b strings.Builder
		for _, key := range slices.Sorted(maps.Keys(everyAppYAMLKey)) {
			if key != without {
				b.WriteString(everyAppYAMLKey[key])
			}
		}
		return b.String()
	}
	full := document("")
	if msg := validateAppYAML(full); msg != "" {
		t.Fatalf("the document with every key is refused: %s", msg)
	}
	loaded := loadedAppConfig(t, full)
	var unread []string
	for _, key := range slices.Sorted(maps.Keys(knownAppYAMLKeys)) {
		if everyAppYAMLKey[key] == "" {
			t.Errorf("the write gate accepts top-level %q and everyAppYAMLKey has no sample for it: add one that turns the key on, so this test can tell whether anything reads it", key)
			continue
		}
		without := loadedAppConfig(t, document(key))
		changed := false
		for part := range loaded {
			changed = changed || !reflect.DeepEqual(loaded[part], without[part])
		}
		_, listed := appYAMLNoEffectEntry(key)
		switch {
		case !changed && !listed:
			t.Errorf("app.yaml %q is accepted, and removing it changes nothing the app loads. Add it to appYAMLNoEffectKeys (so it is warned about), or add what reads it to loadedAppConfig.", key)
		case !changed:
			unread = append(unread, key)
		}
	}
	t.Logf("accepted top-level keys the load keeps nothing of (all in the table): %v", unread)
	for key := range everyAppYAMLKey {
		if !knownAppYAMLKeys[key] {
			t.Errorf("everyAppYAMLKey has %q, which the write gate does not accept", key)
		}
	}

	// auth keys are copied into one map whatever their name, so the load
	// cannot tell a read key from an unread one. The source can: a key the
	// runtime reads is named in it.
	index := runtimeSourceIndex(t)
	for _, key := range slices.Sorted(maps.Keys(knownAuthKeys)) {
		if _, dead := deadAuthKeys[key]; dead {
			continue
		}
		if _, listed := appYAMLNoEffectEntry("auth." + key); listed {
			continue
		}
		named := false
		for _, ref := range noEffectRefsFound(index, []string{"lit " + key, "idx " + key, "tag " + key}) {
			named = named || !(strings.Contains(ref, " validators_antipattern.go:") || strings.Contains(ref, " app_yaml_no_effect.go:"))
		}
		if !named {
			t.Errorf("app.yaml auth.%s is accepted, and no runtime source names it. Add it to appYAMLNoEffectKeys, or refuse it (deadAuthKeys).", key)
		}
	}
}
