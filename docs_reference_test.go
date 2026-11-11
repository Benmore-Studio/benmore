//go:build !cli

package main

import (
	"bytes"
	"encoding/json"
	"maps"
	"slices"
	"strings"
	"testing"
)

// docsForTest runs `benmore docs <args>` the way cmdDocs does.
func docsForTest(t *testing.T, args ...string) (code int, guide, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code, guide = docsRun(args, &out, &errOut)
	return code, guide, out.String(), errOut.String()
}

func docsAnswerForTest(t *testing.T, args ...string) map[string]any {
	t.Helper()
	code, guide, stdout, stderr := docsForTest(t, args...)
	var answer map[string]any
	if err := json.Unmarshal([]byte(stdout), &answer); err != nil || guide != "" {
		t.Fatalf("benmore docs %q: exit %d, guide %q, stdout is not one JSON answer (%v): %s\nstderr: %s", args, code, guide, err, abbrevForTest(stdout, 300), stderr)
	}
	return answer
}

// In this edition `benmore docs <topic>` reads every topic of the reference
// from the binary, with the delivery the platform's `api` tool has: a topic
// of at most apiTopicInlineLimit bytes whole, a larger one as the index of
// its keys, and --full the whole of it. The printed JSON is what `benmore
// api <app> <topic>` prints for the same answer.
func TestDocsReadsEveryReferenceTopicInThisEdition(t *testing.T) {
	whole, indexed := 0, 0
	for _, topic := range apiRecipeTopics() {
		args := []string{topic}
		if docsIsGuide(topic) {
			args = append(args, "--reference") // connector, harness: the bare name is the guide
		}
		code, guide, stdout, stderr := docsForTest(t, args...)
		if code != 0 || guide != "" {
			t.Errorf("benmore docs %s: exit %d, guide %q\n%s", topic, code, guide, stderr)
			continue
		}
		if want := docsJSON(apiReadTopic(apiTopicRequest{At: topic})); stdout != want {
			t.Errorf("benmore docs %s does not print the answer api(at:%q) gives", topic, topic)
		}
		recipe := topicRecipes[topic]
		var answer map[string]any
		if err := json.Unmarshal([]byte(stdout), &answer); err != nil {
			t.Fatalf("benmore docs %s: %v", topic, err)
		}
		if answer["topic"] != topic || answer["summary"] != recipe["summary"] {
			t.Errorf("benmore docs %s answers topic %v, summary %v", topic, answer["topic"], answer["summary"])
		}
		if answer["total_bytes"] == nil {
			whole++
			if len(answer) != len(recipe)+1 {
				t.Errorf("benmore docs %s: %d fields for a topic of %d keys", topic, len(answer), len(recipe))
			}
			if stderr != "" && !strings.Contains(stderr, "build guide") {
				t.Errorf("benmore docs %s (whole) wrote to stderr: %s", topic, stderr)
			}
		} else {
			indexed++
			keys, _ := answer["keys"].([]any)
			if len(keys) != len(recipe)-1 {
				t.Errorf("benmore docs %s: the index lists %d keys, the topic has %d besides summary", topic, len(keys), len(recipe)-1)
			}
			if !strings.Contains(stderr, "`benmore docs "+topic+".<key>`") || !strings.Contains(stderr, "`benmore docs "+topic+" --full`") {
				t.Errorf("benmore docs %s (index) does not say how to read a key here: %q", topic, stderr)
			}
		}
		full := docsAnswerForTest(t, topic, "--full")
		if len(full) != len(recipe)+1 || full["total_bytes"] != nil {
			t.Errorf("benmore docs %s --full: %d fields for a topic of %d keys", topic, len(full), len(recipe))
		}
		if _, _, fullOut, _ := docsForTest(t, topic, "--full"); fullOut != docsJSON(apiDescribeTopic(topic)) {
			t.Errorf("benmore docs %s --full is not the whole topic", topic)
		}
	}
	if whole < 20 || indexed < 20 {
		t.Fatalf("%d topics came back whole and %d as an index; both forms are expected", whole, indexed)
	}
	t.Logf("%s edition: benmore docs read %d topics whole and %d as an index", editionName, whole, indexed)
}

// `benmore docs <topic>.<key>` reads every key of every topic, and a dotted
// path walks into a nested map.
func TestDocsReadsEveryKeyByAddress(t *testing.T) {
	keys := 0
	for _, topic := range apiRecipeTopics() {
		for key, value := range topicRecipes[topic] {
			keys++
			answer := docsAnswerForTest(t, topic+"."+key)
			want, _ := json.Marshal(value)
			got, _ := json.Marshal(answer["value"])
			var plain any
			_ = json.Unmarshal(want, &plain)
			want, _ = json.Marshal(plain)
			if answer["topic"] != topic || answer["key"] != key || !bytes.Equal(got, want) {
				t.Errorf("benmore docs %s.%s does not answer that key's value", topic, key)
			}
		}
	}
	if keys < 1000 {
		t.Fatalf("only %d keys read", keys)
	}
	nested := docsAnswerForTest(t, "flows.step_keys.rule")
	if rule, _ := nested["value"].(string); nested["key"] != "step_keys.rule" || rule == "" {
		t.Errorf("benmore docs flows.step_keys.rule = %v", nested)
	}
	// The docs' own notation, pasted as written in a refusal.
	pasted := docsAnswerForTest(t, `api(at:"csrf.how_to_send")`)
	if pasted["key"] != "how_to_send" || pasted["value"] != topicRecipes["csrf"]["how_to_send"] {
		t.Errorf(`benmore docs 'api(at:"csrf.how_to_send")' = %v`, pasted)
	}
	t.Logf("%s edition: %d keys read by address", editionName, keys)
}

// An address that names no key answers with the nearest names and the keys
// that exist, and exits 1: a typo cannot pass for an empty answer.
func TestDocsUnknownKeyNamesTheNearestAndFails(t *testing.T) {
	code, _, stdout, _ := docsForTest(t, "flows.step_key")
	var answer map[string]any
	if err := json.Unmarshal([]byte(stdout), &answer); err != nil {
		t.Fatal(err)
	}
	nearest, _ := answer["nearest"].([]any)
	if code != 1 || answer["error"] != "unknown key: flows.step_key" || !slices.Contains(nearest, any("step_keys")) || answer["keys"] == nil {
		t.Errorf("benmore docs flows.step_key: exit %d, %v", code, abbrevForTest(stdout, 300))
	}
	code, _, stdout, _ = docsForTest(t, "no-such-topic.key")
	if code != 1 || !strings.Contains(stdout, `"error": "unknown topic: no-such-topic"`) {
		t.Errorf("benmore docs no-such-topic.key: exit %d, %s", code, abbrevForTest(stdout, 200))
	}
	code, guide, stdout, stderr := docsForTest(t, "no-such-topic")
	if code != 1 || guide != "" || stdout != "" || !strings.Contains(stderr, `Unknown topic: "no-such-topic"`) || !strings.Contains(stderr, "benmore docs index") || !strings.Contains(stderr, "--search") {
		t.Errorf("benmore docs no-such-topic: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}

// `benmore docs index` lists every topic, and `benmore docs --search` ranks
// keys across all topics or inside one, as api(at:"index") and
// api(search:"...") do.
func TestDocsIndexAndSearch(t *testing.T) {
	index := docsAnswerForTest(t, "index")
	topics, _ := index["topics"].([]any)
	if len(topics) != len(topicRecipes) || index["count"] != float64(len(topicRecipes)) {
		t.Errorf("benmore docs index lists %d topics, the reference has %d", len(topics), len(topicRecipes))
	}
	if _, _, stdout, _ := docsForTest(t, "index"); stdout != docsJSON(apiTopicCatalog()) {
		t.Error("benmore docs index is not the answer api(at:\"index\") gives")
	}
	for _, args := range [][]string{{"--search", "upload private file"}, {"--search=upload private file"}} {
		code, _, stdout, stderr := docsForTest(t, args...)
		if code != 0 || stdout != docsJSON(apiSearchReference("upload private file", "")) || !strings.Contains(stderr, "`benmore docs <at>`") {
			t.Errorf("benmore docs %q: exit %d, not the answer api(search:) gives; stderr %q", args, code, stderr)
		}
	}
	hits, _ := docsAnswerForTest(t, "--search", "upload private file")["hits"].([]any)
	if len(hits) == 0 || len(hits) > apiSearchMaxHits {
		t.Fatalf("search returned %d hits", len(hits))
	}
	// Every hit is an address this command reads.
	for _, hit := range hits {
		at, _ := hit.(map[string]any)["at"].(string)
		if answer := docsAnswerForTest(t, at); answer["error"] != nil || answer["value"] == nil {
			t.Errorf("search hit %s is not readable: %v", at, answer["error"])
		}
	}
	inside := docsAnswerForTest(t, "flows", "--search", "rate limit")
	if inside["topic"] != "flows" {
		t.Errorf("benmore docs flows --search stays inside flows: topic %v", inside["topic"])
	}
	for _, hit := range inside["hits"].([]any) {
		if at, _ := hit.(map[string]any)["at"].(string); !strings.HasPrefix(at, "flows.") {
			t.Errorf("a search inside flows returned %s", at)
		}
	}
	if code, _, stdout, _ := docsForTest(t, "--search", "zzzzqqqqxxxx"); code != 0 || !strings.Contains(stdout, `"count": 0`) {
		t.Errorf("a search with no hit: exit %d, %s", code, stdout)
	}
}

// A guide's own name still prints the guide, byte for byte; any other name
// that is a reference topic, an alias of one or a retired name reads the
// reference; a name only the build guide covers prints that guide.
func TestDocsNamePrecedence(t *testing.T) {
	for _, guideName := range AgentDocsTopics() {
		code, guide, stdout, stderr := docsForTest(t, guideName)
		if code != 0 || guide != guideName || stdout != AgentDocs(guideName) {
			t.Errorf("benmore docs %s no longer prints the guide (exit %d, guide %q)", guideName, code, guide)
		}
		_, isTopic := topicRecipes[guideName]
		if isTopic != strings.Contains(stderr, "`benmore docs "+guideName+" --reference`") {
			t.Errorf("benmore docs %s: topic=%v, stderr %q", guideName, isTopic, stderr)
		}
	}
	// connector and harness are guides and topics: the flag and an address
	// reach the topic.
	both := 0
	for _, name := range AgentDocsTopics() {
		if _, isTopic := topicRecipes[name]; !isTopic {
			continue
		}
		both++
		if answer := docsAnswerForTest(t, name, "--reference"); answer["topic"] != name || answer["summary"] != topicRecipes[name]["summary"] {
			t.Errorf("benmore docs %s --reference = %v", name, answer["topic"])
		}
		if answer := docsAnswerForTest(t, name+".summary"); answer["value"] != topicRecipes[name]["summary"] {
			t.Errorf("benmore docs %s.summary does not read the topic", name)
		}
	}
	if both == 0 {
		t.Error("no name is both a guide and a topic any more: drop --reference or this check")
	}
	// A docs alias that is a topic reads the topic now, and says where the
	// build guide covers it.
	for alias := range docAliases {
		_, isTopic := topicRecipes[alias]
		_, isTopicAlias := topicAliases[alias]
		if alias == "" || docsIsGuide(alias) {
			continue
		}
		code, guide, stdout, stderr := docsForTest(t, alias)
		switch {
		case isTopic || isTopicAlias:
			topic := alias
			if isTopicAlias {
				topic = topicAliases[alias]
			}
			if code != 0 || guide != "" || stdout != docsJSON(apiReadTopic(apiTopicRequest{At: topic})) {
				t.Errorf("benmore docs %s should read the reference topic %s (exit %d, guide %q)", alias, topic, code, guide)
			}
			if section, ok := docAliasSections[alias]; ok && !strings.Contains(stderr, section) {
				t.Errorf("benmore docs %s does not name the build guide section %q: %q", alias, section, stderr)
			}
		default:
			if code != 0 || guide != alias || stdout != AgentDocsPointer(alias)+AgentDocs("build") {
				t.Errorf("benmore docs %s should print the build guide with its pointer (exit %d, guide %q)", alias, code, guide)
			}
			if topic := docAliasAPITopic(alias); topic != "" && !strings.Contains(stderr, "`benmore docs "+topic+"`") {
				t.Errorf("benmore docs %s does not point at the reference topic %s: %q", alias, topic, stderr)
			}
		}
	}
	for _, name := range slices.Sorted(maps.Keys(retiredTopics)) {
		if answer := docsAnswerForTest(t, name); answer["retired"] != retiredTopics[name] {
			t.Errorf("benmore docs %s does not say the topic is retired: %v", name, answer)
		}
	}
	// The list of guides is unchanged in its first lines and now says how to
	// reach the reference.
	code, guide, stdout, _ := docsForTest(t)
	if code != 0 || guide != "" || !strings.HasPrefix(stdout, "Benmore framework documentation.\n\nGuides:\n"+AgentDocsCatalog()) || !strings.Contains(stdout, "benmore docs index") || !strings.Contains(stdout, "benmore docs --search") {
		t.Errorf("benmore docs (no argument): exit %d\n%s", code, stdout)
	}
}

// A usage error stops before anything is read, with exit 2.
func TestDocsUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{"flows", "auth"},
		{"--search"},
		{"--search", "  "},
		{"--full"},
		{"--reference"},
		{"flows", "--bogus"},
	} {
		code, guide, stdout, stderr := docsForTest(t, args...)
		if code != 2 || guide != "" || stdout != "" || !strings.HasPrefix(stderr, "benmore docs: ") || !strings.Contains(stderr, "Usage: benmore docs ") {
			t.Errorf("benmore docs %q: exit %d, stdout %q, stderr %q", args, code, stdout, stderr)
		}
	}
	// The flags are declared, so main's preflight lets them through and
	// refuses any other; --help prints the command's usage lines.
	spec := cliCommandFlagSpecs["docs"]
	for _, flag := range []string{"--full", "--reference", "--search"} {
		if !spec.accepts(flag) {
			t.Errorf("benmore docs does not declare %s", flag)
		}
	}
	var out, errOut bytes.Buffer
	if _, code, stop := cliPreflight("docs", []string{"flows", "--ful"}, &out, &errOut); !stop || code != 2 || !strings.Contains(errOut.String(), "--full") {
		t.Errorf("benmore docs flows --ful: stop %v, exit %d, %q", stop, code, errOut.String())
	}
	out.Reset()
	if _, code, stop := cliPreflight("docs", []string{"--help"}, &out, &errOut); !stop || code != 0 || !strings.Contains(out.String(), "benmore docs [<guide>|<topic>[.<key>]|index]") || !strings.Contains(out.String(), "--search") {
		t.Errorf("benmore docs --help: stop %v, exit %d, %q", stop, code, out.String())
	}
	if args, _, stop := cliPreflight("docs", []string{"flows", "--search=rate limit"}, &out, &errOut); stop || !slices.Equal(args, []string{"flows", "--search", "rate limit"}) {
		t.Errorf("benmore docs flows --search=...: stop %v, args %q", stop, args)
	}
}

// A reference lookup is answered from the binary, so the command's start-up
// sends nothing for it; a guide keeps what it did before.
func TestDocsReferenceLookupsAreOffline(t *testing.T) {
	for _, args := range [][]string{
		{"flows"}, {"flows.summary"}, {"flows", "--full"}, {"harness", "--reference"}, {"harness.guide"},
		{"index"}, {"--search", "rate limit"}, {"flows", "--search", "x"}, {"auth"}, {"pages"}, {"edges"},
		{`api(at:"csrf.how_to_send")`}, {"no-such-topic"}, {"flows", "auth"}, {"--bogus"},
	} {
		if !docsReferenceLookup(args) {
			t.Errorf("benmore docs %q is answered from the binary and should send nothing", args)
		}
	}
	for _, args := range [][]string{{}, {"list"}, {"build"}, {"harness"}, {"connector"}, {"changes"}, {"quickstart"}, {"cli"}} {
		if docsReferenceLookup(args) {
			t.Errorf("benmore docs %q prints a guide: it keeps the command's usual start-up", args)
		}
	}
}
