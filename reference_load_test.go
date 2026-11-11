//go:build !cli

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/scanner"
	"go/token"
	"io"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"
	"unicode/utf8"
)

// referenceLazyTestEnv marks the child process of
// TestReferenceLoadsOnFirstUseOnly, which must start without the reference.
const referenceLazyTestEnv = "BENMORE_REFERENCE_TEST_LAZY"

// Tests read topicRecipes, topicAliases and retiredTopics directly, as they
// did when these were Go literals, so the reference is loaded before any
// test runs. Production code must not rely on this: it reads through
// referenceTopics and its siblings (TestReferenceReadersLoadFirst).
func init() {
	if os.Getenv(referenceLazyTestEnv) == "" {
		referenceLoad()
	}
}

// The embedded reference loads in this edition, and looks like the reference:
// every topic has a summary and keys, and the names the loader refuses are
// absent.
func TestReferenceLoads(t *testing.T) {
	topics := referenceTopics()
	if len(topics) < 80 {
		t.Fatalf("the embedded reference has %d topics; about ninety are expected", len(topics))
	}
	keys := 0
	for topic, recipe := range topics {
		keys += len(recipe)
		if summary, _ := recipe["summary"].(string); summary == "" {
			t.Errorf("%s has no summary: every topic says in one paragraph what it covers", topic)
		}
		for key, value := range recipe {
			if value == nil {
				t.Errorf("%s.%s is empty", topic, key)
			}
		}
	}
	for _, topic := range []string{"harness", "schema", "cron", "auth", "flows", "connector"} {
		if _, ok := topics[topic]; !ok {
			t.Errorf("the topic %s is missing", topic)
		}
	}
	if len(referenceAliases()) == 0 || len(referenceRetired()) == 0 {
		t.Errorf("aliases %v and retired names %v did not load", referenceAliases(), referenceRetired())
	}
	t.Logf("%s edition: %d topics, %d keys, %d aliases, %d retired names", editionName, len(topics), keys, len(referenceAliases()), len(referenceRetired()))
}

// What is embedded is what is on disk: a file the embed pattern does not
// cover (a sub-directory, another extension) would be in the repository and
// missing from the binary.
func TestReferenceEmbedMatchesDisk(t *testing.T) {
	embedded, err := fs.Sub(referenceFS, referenceDir)
	if err != nil {
		t.Fatal(err)
	}
	list := func(fsys fs.FS) map[string]string {
		files := map[string]string{}
		err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			if name := d.Name(); strings.HasPrefix(name, ".") || path == "README.md" {
				return nil // the editing guide is for the repository's readers
			}
			data, err := fs.ReadFile(fsys, path)
			files[path] = string(data)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return files
	}
	inBinary, onDisk := list(embedded), list(os.DirFS(filepath.FromSlash(referenceDir)))
	for path, content := range onDisk {
		if got, ok := inBinary[path]; !ok {
			t.Errorf("%s/%s is on disk and not embedded: the reference holds %s, %s and one <key>.txt or <key>.json per key in each topic directory", referenceDir, path, referenceRegistry, referenceTopicIndex)
		} else if got != content {
			t.Errorf("%s/%s differs from the embedded copy (rebuild)", referenceDir, path)
		}
	}
	for path := range inBinary {
		if _, ok := onDisk[path]; !ok {
			t.Errorf("%s/%s is embedded and not on disk", referenceDir, path)
		}
	}
	if len(inBinary) < 1000 {
		t.Fatalf("only %d files are embedded", len(inBinary))
	}
}

// A file-ignore rule must not hide a reference file: it would be embedded on
// the machine that wrote it and missing from every other checkout, where the
// loader then refuses the directory. The repository's `**/uploads/` rule once
// hid the whole `uploads` topic this way.
func TestReferenceFilesAreNotIgnoredByGit(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is not installed")
	}
	if out, err := exec.Command(git, "rev-parse", "--is-inside-work-tree").Output(); err != nil || strings.TrimSpace(string(out)) != "true" {
		t.Skip("not a git checkout (an exported tree is checked where it is produced)")
	}
	out, err := exec.Command(git, "ls-files", "--others", "--ignored", "--exclude-standard", "--", referenceDir).Output()
	if err != nil {
		t.Fatalf("git ls-files: %v", err)
	}
	for _, name := range strings.Fields(string(out)) {
		t.Errorf("%s is hidden by a .gitignore rule: every checkout but this one lacks it. Add an exception for it in .gitignore, or rename the key or topic", name)
	}
}

// referenceCanonicalJSON writes a JSON document the way the reference keeps
// it: two-space indentation, one list item or object entry per line, entries
// in the order written, strings escaped as little as JSON allows (so `<`,
// `>` and `&` stay readable), one final newline.
func referenceCanonicalJSON(raw []byte) (string, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var out strings.Builder
	quote := func(s string) string {
		var b bytes.Buffer
		enc := json.NewEncoder(&b)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(s)
		return strings.TrimSuffix(b.String(), "\n")
	}
	var value func(indent string) error
	value = func(indent string) error {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		switch v := tok.(type) {
		case json.Delim:
			open, shut := string(v), "]"
			if v == '{' {
				shut = "}"
			}
			if !dec.More() {
				_, err := dec.Token()
				out.WriteString(open + shut)
				return err
			}
			out.WriteString(open + "\n")
			for first := true; dec.More(); first = false {
				if !first {
					out.WriteString(",\n")
				}
				out.WriteString(indent + "  ")
				if v == '{' {
					key, err := dec.Token()
					if err != nil {
						return err
					}
					out.WriteString(quote(key.(string)) + ": ")
				}
				if err := value(indent + "  "); err != nil {
					return err
				}
			}
			out.WriteString("\n" + indent + shut)
			_, err := dec.Token()
			return err
		case string:
			out.WriteString(quote(v))
		case json.Number:
			out.WriteString(v.String())
		case bool:
			out.WriteString(fmt.Sprint(v))
		default:
			return fmt.Errorf("unsupported JSON token %v", tok)
		}
		return nil
	}
	if err := value(""); err != nil {
		return "", err
	}
	if _, err := dec.Token(); err != io.EOF {
		return "", fmt.Errorf("text after the JSON value")
	}
	return out.String() + "\n", nil
}

// Every reference file is in the one form the tools write, so a change shows
// in a diff as the words that changed and nothing else: text files end with
// a newline and hold no carriage return, JSON files are laid out canonically.
func TestReferenceFilesAreCanonical(t *testing.T) {
	root := filepath.FromSlash(referenceDir)
	checked := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel := filepath.ToSlash(path)
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		switch {
		case strings.HasPrefix(d.Name(), "."), rel == referenceDir+"/README.md":
			return nil
		case !utf8.Valid(raw):
			t.Errorf("%s is not valid UTF-8", rel)
		case bytes.ContainsRune(raw, '\r'):
			t.Errorf("%s holds a carriage return: save it with Unix line endings", rel)
		case strings.HasSuffix(rel, ".txt"):
			if !bytes.HasSuffix(raw, []byte("\n")) {
				t.Errorf("%s does not end with a newline: a text value is followed by exactly one (the loader takes it off)", rel)
			}
		case strings.HasSuffix(rel, ".json"):
			want, err := referenceCanonicalJSON(raw)
			if err != nil {
				t.Errorf("%s: %v", rel, err)
			} else if want != string(raw) {
				t.Errorf("%s is not laid out the way the reference keeps JSON (two-space indentation, one item per line, no \\u003c-style escapes, one final newline). Expected:\n%s", rel, abbrevForTest(want, 600))
			}
		default:
			t.Errorf("%s: the reference holds .txt and .json files only", rel)
		}
		checked++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked < 1000 {
		t.Fatalf("only %d files checked", checked)
	}
}

// referenceTextForTest is every string the loaded reference holds, one per
// line: what a test searches when it asks whether the reference still says
// something anywhere.
func referenceTextForTest() string {
	var text strings.Builder
	for _, topic := range apiRecipeTopics() {
		recipe := topicRecipes[topic]
		for _, key := range slices.Sorted(maps.Keys(recipe)) {
			apiSearchText(&text, reflect.ValueOf(recipe[key]))
		}
	}
	return text.String()
}

// referenceTopicFilesForTest is the text of every topic's _topic.json: the
// keys each topic lists and the values it leaves to code.
func referenceTopicFilesForTest(t *testing.T) string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(filepath.FromSlash(referenceDir), "*", referenceTopicIndex))
	if err != nil || len(files) < 80 {
		t.Fatalf("%d topic index files found: %v", len(files), err)
	}
	var text strings.Builder
	for _, name := range files {
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		text.Write(raw)
	}
	return text.String()
}

// referenceKeyOrderForTest is a topic's keys in the order its _topic.json
// lists them.
func referenceKeyOrderForTest(t *testing.T, topic string) []string {
	t.Helper()
	var index referenceTopicFile
	raw, err := os.ReadFile(filepath.Join(filepath.FromSlash(referenceDir), topic, referenceTopicIndex))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &index); err != nil {
		t.Fatalf("%s: %v", topic, err)
	}
	return index.Keys
}

func abbrevForTest(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// Production code reads the reference through referenceTopics,
// referenceAliases and referenceRetired, which load it first. A direct read
// of the variables would see an empty reference in a process that has not
// loaded it yet and report nothing wrong, and no test would notice, because
// tests load the reference before they run.
func TestReferenceReadersLoadFirst(t *testing.T) {
	guarded := map[string]bool{"topicRecipes": true, "topicAliases": true, "retiredTopics": true}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	scanned := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") || name == "reference.go" {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		scanned++
		if !bytes.Contains(src, []byte("topicRecipes")) && !bytes.Contains(src, []byte("topicAliases")) && !bytes.Contains(src, []byte("retiredTopics")) {
			continue
		}
		fset := token.NewFileSet()
		var s scanner.Scanner
		s.Init(fset.AddFile(name, fset.Base(), len(src)), src, nil, 0)
		for {
			pos, tok, lit := s.Scan()
			if tok == token.EOF {
				break
			}
			if tok == token.IDENT && guarded[lit] {
				t.Errorf("%s reads %s directly: use referenceTopics(), referenceAliases() or referenceRetired(), which load the reference first", fset.Position(pos), lit)
			}
		}
	}
	if scanned < 200 {
		t.Fatalf("only %d source files scanned", scanned)
	}
}

// Starting a process does not read the reference: a served app never needs
// it, and hosted development instances run under a small memory limit. The
// test starts itself again without the load that tests do first, and checks
// that nothing in package initialisation loaded the reference, and that the
// first read does.
func TestReferenceLoadsOnFirstUseOnly(t *testing.T) {
	if os.Getenv(referenceLazyTestEnv) != "" {
		if topicRecipes != nil || topicAliases != nil || retiredTopics != nil {
			t.Fatal("the reference was loaded while the package initialised: something reads it at start")
		}
		// Asking whether a topic exists reads no value either.
		if !referenceHasTopic("flows") || referenceHasTopic("no-such-topic") || referenceHasTopic("../agent") || topicRecipes != nil {
			t.Fatal("referenceHasTopic loaded the reference, or answered wrongly")
		}
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		start := time.Now()
		got := len(referenceTopics())
		took := time.Since(start)
		runtime.GC()
		runtime.ReadMemStats(&after)
		if got < 80 {
			t.Fatalf("the first read loaded %d topics", got)
		}
		if topicRecipes == nil || len(apiSearchCorpus()) < 900 {
			t.Fatal("the first read did not load the reference")
		}
		fmt.Printf("reference load cost: %s, %d KiB of heap kept, for %d topics\n", took.Round(10*time.Microsecond), (int64(after.HeapAlloc)-int64(before.HeapAlloc))/1024, got)
		return
	}
	exe, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	cmd := exec.Command(exe, "-test.run", "^TestReferenceLoadsOnFirstUseOnly$", "-test.count=1")
	cmd.Env = append(os.Environ(), referenceLazyTestEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("a process that starts without loading the reference: %v\n%s", err, out)
	}
	// What a process pays the first time it answers from the reference, and
	// what every process that never does saves.
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "reference load cost:") {
			t.Log(line)
		}
	}
}

// referenceTestFiles is a small, valid reference directory.
func referenceTestFiles() fstest.MapFS {
	return fstest.MapFS{
		"_registry.json":       {Data: []byte(`{"topics": ["flows", "ssr"], "aliases": {"pages": "ssr"}, "retired": {"edges": "Retired."}}`)},
		"ssr/_topic.json":      {Data: []byte(`{"keys": ["summary", "pipes", "limits", "table"], "generated": {"table": "ssrTable()", "limits.max": "ssrMax()"}}`)},
		"ssr/summary.txt":      {Data: []byte("Server-rendered pages.\n")},
		"ssr/pipes.json":       {Data: []byte(`["upper", "lower"]`)},
		"ssr/limits.json":      {Data: []byte(`{"queries": 10, "mixed": ["a", {"b": 2}], "rows": [{"n": 1}]}`)},
		"flows/_topic.json":    {Data: []byte(`{"keys": ["summary"]}`)},
		"flows/summary.txt":    {Data: []byte("Custom routes.\n\n")},
		"flows/.DS_Store":      {Data: []byte("ignored")},
		".hidden/anything.txt": {Data: []byte("ignored")},
	}
}

func referenceTestGenerators() map[string]func() any {
	return map[string]func() any{
		"ssr.table":      func() any { return map[string]any{"rule": "generated"} },
		"ssr.limits.max": func() any { return 64 },
	}
}

// A directory in the documented shape loads into the Go types the readers of
// the reference expect.
func TestReferenceReadTypesAndGeneratedValues(t *testing.T) {
	data, err := referenceRead(referenceTestFiles(), referenceTestGenerators())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]map[string]any{
		"ssr": {
			"summary": "Server-rendered pages.",
			"pipes":   []string{"upper", "lower"},
			"limits":  map[string]any{"queries": 10, "mixed": []any{"a", map[string]any{"b": 2}}, "rows": []map[string]any{{"n": 1}}, "max": 64},
			"table":   map[string]any{"rule": "generated"},
		},
		// One newline is the file's own; a second belongs to the value.
		"flows": {"summary": "Custom routes.\n"},
	}
	if !reflect.DeepEqual(data.Topics, want) {
		t.Errorf("loaded\n%#v\nwant\n%#v", data.Topics, want)
	}
	if !maps.Equal(data.Aliases, map[string]string{"pages": "ssr"}) || !maps.Equal(data.Retired, map[string]string{"edges": "Retired."}) {
		t.Errorf("aliases %v, retired %v", data.Aliases, data.Retired)
	}
	if !slices.Equal(data.Order["ssr"], []string{"summary", "pipes", "limits", "table"}) {
		t.Errorf("written key order %v", data.Order["ssr"])
	}
}

// A directory that is not in that shape does not load, and the error names
// the file and what to do: a mistake in the files cannot become a silently
// shorter reference.
func TestReferenceReadRefusesMalformedDirectories(t *testing.T) {
	cases := []struct {
		name   string
		change func(files fstest.MapFS, generators map[string]func() any)
		want   string
	}{
		{"a value file the index does not list", func(f fstest.MapFS, _ map[string]func() any) {
			f["ssr/extra.txt"] = &fstest.MapFile{Data: []byte("x\n")}
		}, `ssr/_topic.json does not list extra.txt`},
		{"a listed key with no file", func(f fstest.MapFS, _ map[string]func() any) { delete(f, "ssr/pipes.json") }, `lists the key pipes, which has no pipes.txt or pipes.json`},
		{"a key with two files", func(f fstest.MapFS, _ map[string]func() any) {
			f["ssr/pipes.txt"] = &fstest.MapFile{Data: []byte("x\n")}
		}, `the key pipes has two files`},
		{"a key listed twice", func(f fstest.MapFS, _ map[string]func() any) {
			f["flows/_topic.json"] = &fstest.MapFile{Data: []byte(`{"keys": ["summary", "summary"]}`)}
		}, `lists the key summary twice`},
		{"a generated key that also has a file", func(f fstest.MapFS, _ map[string]func() any) {
			f["ssr/table.json"] = &fstest.MapFile{Data: []byte(`{}`)}
		}, `ssr/table.json: the key is built by code`},
		{"a generated path with no generator", func(_ fstest.MapFS, g map[string]func() any) { delete(g, "ssr.table") }, `no generator is registered for ssr.table`},
		{"a generator nothing lists", func(_ fstest.MapFS, g map[string]func() any) { g["flows.step_keys"] = func() any { return "x" } }, `a generator is registered for flows.step_keys`},
		{"a generated key missing from keys", func(f fstest.MapFS, _ map[string]func() any) {
			f["ssr/_topic.json"] = &fstest.MapFile{Data: []byte(`{"keys": ["summary", "pipes", "limits"], "generated": {"table": "ssrTable()", "limits.max": "ssrMax()"}}`)}
		}, `generated table: the key is not listed in "keys"`},
		{"a generated path a file already fills", func(f fstest.MapFS, _ map[string]func() any) {
			f["ssr/limits.json"] = &fstest.MapFile{Data: []byte(`{"max": 1}`)}
		}, `generated limits.max: a file already holds a value there`},
		{"a generator that builds nothing", func(_ fstest.MapFS, g map[string]func() any) { g["ssr.table"] = func() any { return nil } }, `its generator built nothing`},
		{"an unknown field in the index", func(f fstest.MapFS, _ map[string]func() any) {
			f["flows/_topic.json"] = &fstest.MapFile{Data: []byte(`{"keys": ["summary"], "order": []}`)}
		}, `unknown field "order"`},
		{"a topic directory with no index", func(f fstest.MapFS, _ map[string]func() any) { delete(f, "flows/_topic.json") }, `flows/_topic.json`},
		// What a file-ignore rule does to a directory named like one of its
		// patterns: present where it was written, absent from every checkout.
		{"a listed topic whose directory is missing", func(f fstest.MapFS, _ map[string]func() any) {
			delete(f, "flows/_topic.json")
			delete(f, "flows/summary.txt")
			delete(f, "flows/.DS_Store")
		}, `_registry.json lists the topic flows, which has no directory`},
		{"a topic directory nobody listed", func(f fstest.MapFS, _ map[string]func() any) {
			f["cron/_topic.json"] = &fstest.MapFile{Data: []byte(`{"keys": ["summary"]}`)}
			f["cron/summary.txt"] = &fstest.MapFile{Data: []byte("Jobs.\n")}
		}, `the topic directory cron is not listed under "topics" in _registry.json`},
		{"a topic listed twice", func(f fstest.MapFS, _ map[string]func() any) {
			f["_registry.json"] = &fstest.MapFile{Data: []byte(`{"topics": ["flows", "ssr", "flows"], "aliases": {}, "retired": {}}`)}
		}, `lists the topic flows twice`},
		{"an alias of a topic that does not exist", func(f fstest.MapFS, _ map[string]func() any) {
			f["_registry.json"] = &fstest.MapFile{Data: []byte(`{"topics": ["flows", "ssr"], "aliases": {"pages": "nope"}, "retired": {}}`)}
		}, `alias pages names the topic nope, which does not exist`},
		{"an alias that is also a topic", func(f fstest.MapFS, _ map[string]func() any) {
			f["_registry.json"] = &fstest.MapFile{Data: []byte(`{"topics": ["flows", "ssr"], "aliases": {"flows": "ssr"}, "retired": {}}`)}
		}, `alias flows is also a topic`},
		{"a retired name that is also a topic", func(f fstest.MapFS, _ map[string]func() any) {
			f["_registry.json"] = &fstest.MapFile{Data: []byte(`{"topics": ["flows", "ssr"], "aliases": {}, "retired": {"flows": "gone"}}`)}
		}, `retired name flows is also a topic`},
		{"a fraction", func(f fstest.MapFS, _ map[string]func() any) {
			f["ssr/pipes.json"] = &fstest.MapFile{Data: []byte(`[1.5]`)}
		}, `the number 1.5 is not a whole number`},
		{"a null", func(f fstest.MapFS, _ map[string]func() any) {
			f["ssr/pipes.json"] = &fstest.MapFile{Data: []byte(`{"a": null}`)}
		}, `null has no place in the reference`},
		{"two JSON values in one file", func(f fstest.MapFS, _ map[string]func() any) {
			f["ssr/pipes.json"] = &fstest.MapFile{Data: []byte(`["a"] ["b"]`)}
		}, `ssr/pipes.json: text after the JSON value`},
		{"another kind of file", func(f fstest.MapFS, _ map[string]func() any) {
			f["ssr/notes.md"] = &fstest.MapFile{Data: []byte("x")}
		}, `ssr/notes.md: a topic directory holds _topic.json and one <key>.txt or <key>.json per key`},
		{"an upper-case topic directory", func(f fstest.MapFS, _ map[string]func() any) {
			f["Flows2/_topic.json"] = &fstest.MapFile{Data: []byte(`{"keys": []}`)}
		}, `Flows2: a topic directory is named in lower case`},
	}
	for _, c := range cases {
		files, generators := referenceTestFiles(), referenceTestGenerators()
		c.change(files, generators)
		_, err := referenceRead(files, generators)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %v, want one containing %q", c.name, err, c.want)
		}
	}
}

// Every key a topic's _topic.json lists under "generated" has a generator in
// this edition and the other way round (the loader refuses both), and what a
// generator builds is not also written in a file.
func TestReferenceGeneratedValuesHaveNoFile(t *testing.T) {
	listed := 0
	for topic := range referenceTopics() {
		var index referenceTopicFile
		raw, err := os.ReadFile(filepath.Join(filepath.FromSlash(referenceDir), topic, referenceTopicIndex))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &index); err != nil {
			t.Fatalf("%s: %v", topic, err)
		}
		for path, note := range index.Generated {
			listed++
			if _, ok := referenceGenerators[topic+"."+path]; !ok {
				t.Errorf("%s.%s is listed as built by code and has no generator", topic, path)
			}
			if strings.TrimSpace(note) == "" {
				t.Errorf("%s/%s: say what builds %s", topic, referenceTopicIndex, path)
			}
		}
	}
	if listed != len(referenceGenerators) || listed == 0 {
		t.Errorf("%d values are listed as built by code, %d generators are registered", listed, len(referenceGenerators))
	}
}
