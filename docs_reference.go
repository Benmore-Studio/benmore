//go:build !cli

package main

// `benmore docs`: the bundled guides, and the app-builder reference read
// offline from this binary, in every edition.
//
//	benmore docs                       the guides, one line each
//	benmore docs build                 a guide (docs/agent/<name>.md)
//	benmore docs index                 every reference topic, one line each
//	benmore docs flows                 a reference topic: whole when small, the index of its keys when large
//	benmore docs csrf.how_to_send      one key (a dotted path reaches into a nested map)
//	benmore docs flows --full          the whole topic, whatever its size
//	benmore docs --search "<words>"    the keys that best match, in all topics or inside the one named
//	benmore docs harness --reference   the reference topic when the name is also a guide
//
// A reference answer is the JSON `benmore api <app> <topic>` prints for the
// same question, byte for byte (api_topic_delivery.go, api_topic_search.go).
// Nothing is sent anywhere to produce it: main skips the update check and
// the usage sync for a reference lookup, and only a guide marks itself read
// on the platform (markDocsRead).

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// docsUsageLines is the entry for `benmore docs` in the usage text.
const docsUsageLines = `  benmore docs [<guide>|<topic>[.<key>]|index] [--full] [--reference] [--search "<words>"]
                                    Guides (build, harness, connector, changes, deploy) and the reference api(at:) answers, read offline:
                                    <topic> a topic (a large one as an index of its keys), <topic>.<key> one key, index every
                                    topic, --full a whole large topic, --search the keys that best match, --reference the
                                    topic when its name is also a guide
`

// docsRequest is what the arguments after `benmore docs` ask for.
type docsRequest struct {
	// Name is the guide, topic or address, as typed; "" lists the guides.
	Name string
	// Full asks for a whole reference topic whatever its size.
	Full bool
	// Reference reads the reference topic when the name is also a guide.
	Reference bool
	// Search holds the words to look for; SearchSet says --search was given.
	Search    string
	SearchSet bool
}

// parseDocsArgs reads the arguments after `benmore docs`. main has run the
// flag preflight, so every flag is declared and `--search=x` is `--search x`.
func parseDocsArgs(args []string) (docsRequest, error) {
	var req docsRequest
	named := false
	for i := 0; i < len(args); i++ {
		switch arg := args[i]; {
		case arg == "--full":
			req.Full = true
		case arg == "--reference":
			req.Reference = true
		case arg == "--search":
			if i+1 >= len(args) {
				return req, fmt.Errorf("--search needs the words to look for")
			}
			i++
			req.Search, req.SearchSet = strings.TrimSpace(args[i]), true
		case strings.HasPrefix(arg, "--search="):
			req.Search, req.SearchSet = strings.TrimSpace(strings.TrimPrefix(arg, "--search=")), true
		case cliFlagToken(arg):
			return req, fmt.Errorf("unknown flag %s", arg)
		case named:
			return req, fmt.Errorf("one guide, topic or address at a time (got %q and %q); quote the words of a search: --search \"<words>\"", req.Name, arg)
		default:
			req.Name, named = docsAt(arg), true
		}
	}
	if req.SearchSet && req.Search == "" {
		return req, fmt.Errorf("--search needs the words to look for")
	}
	if req.Name == "" && (req.Full || req.Reference) {
		return req, fmt.Errorf("--full and --reference need a topic: benmore docs <topic> --full")
	}
	return req, nil
}

// docsAt accepts the docs' notation as typed: `api(at:"csrf.how_to_send")`,
// `at:"flows"` and `at:flows` all mean `flows`.
func docsAt(arg string) string {
	at := strings.TrimSpace(arg)
	if strings.HasPrefix(at, "api(") && strings.HasSuffix(at, ")") {
		at = strings.TrimSpace(at[len("api(") : len(at)-1])
	}
	if rest, ok := strings.CutPrefix(at, "at:"); ok {
		at = strings.TrimSpace(rest)
		if len(at) >= 2 && (at[0] == '"' || at[0] == '\'') && at[len(at)-1] == at[0] {
			at = at[1 : len(at)-1]
		}
	}
	return at
}

// docsSource says where the answer to a request comes from.
type docsSource int

const (
	docsFromGuideList docsSource = iota // the list of guides
	docsFromGuide                       // a bundled guide
	docsFromReference                   // the reference: a topic, a key, the topic list, a search
	docsFromNowhere                     // a name that is no guide, topic or alias
)

// docsPlan decides what a request reads. guide is the docs/agent file to
// print for docsFromGuide.
//
// A name is a guide first (build, harness, connector, changes, deploy), so
// what `benmore docs harness` printed before the reference was readable here
// is what it prints now. Any other name that is a reference topic, an alias
// of one or a retired name reads the reference. A name that is neither but
// that the build guide covers (quickstart, cli, ...) prints that guide.
func docsPlan(req docsRequest) (source docsSource, guide string) {
	name := strings.ToLower(strings.TrimSpace(req.Name))
	if req.SearchSet {
		return docsFromReference, ""
	}
	if name == "" || name == "list" || name == "topics" {
		return docsFromGuideList, ""
	}
	addressed := strings.Contains(name, ".")
	forced := req.Full || req.Reference || addressed
	if !forced && docsIsGuide(name) {
		return docsFromGuide, name
	}
	if forced || name == apiTopicCatalogName {
		return docsFromReference, ""
	}
	if _, _, ok := apiResolveTopic(name); ok {
		return docsFromReference, ""
	}
	if _, retired := referenceRetired()[name]; retired {
		return docsFromReference, ""
	}
	if AgentDocs(name) != "" {
		return docsFromGuide, name // a name the build guide covers
	}
	return docsFromNowhere, ""
}

// docsNearestNames lists the guides and reference topics whose names are
// closest to one that is neither (a typo such as `enviroments`).
func docsNearestNames(name string) []string {
	return apiNearestKeys(strings.ToLower(strings.TrimSpace(name)), append(AgentDocsTopics(), apiRecipeTopics()...))
}

// docsIsGuide reports whether name is a bundled guide's own name.
func docsIsGuide(name string) bool {
	for _, guide := range AgentDocsTopics() {
		if guide == name {
			return true
		}
	}
	return false
}

// docsReferenceLookup reports whether `benmore docs <args>` is answered from
// the embedded reference alone. main then sends nothing: no update check and
// no usage sync.
func docsReferenceLookup(args []string) bool {
	req, err := parseDocsArgs(args)
	if err != nil {
		return true // a usage error prints and exits; nothing to send
	}
	source, _ := docsPlan(req)
	return source == docsFromReference || source == docsFromNowhere
}

// docsJSON renders a reference answer the way the hosted CLI prints the same
// answer from the platform: indented, keys sorted, one final newline.
func docsJSON(answer any) string {
	raw, err := json.Marshal(answer)
	if err != nil {
		return fmt.Sprintf("{\n  \"error\": %q\n}\n", err.Error())
	}
	var plain any
	_ = json.Unmarshal(raw, &plain)
	out, _ := json.MarshalIndent(plain, "", "  ")
	return string(out) + "\n"
}

// docsRun answers `benmore docs <args>`: what it writes and the exit status.
// guide is the guide that was printed, "" when the answer came from anywhere
// else.
func docsRun(args []string, stdout, stderr io.Writer) (code int, guide string) {
	req, err := parseDocsArgs(args)
	if err != nil {
		fmt.Fprintf(stderr, "benmore docs: %s\n%s", err, usageForError(docsUsageLines))
		return 2, ""
	}
	source, guide := docsPlan(req)
	switch source {
	case docsFromGuideList:
		fmt.Fprintln(stdout, "Benmore framework documentation.")
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, "Guides:")
		fmt.Fprint(stdout, AgentDocsCatalog())
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, "Usage: benmore docs <guide>              (e.g. benmore docs build)")
		fmt.Fprintln(stdout)
		fmt.Fprintf(stdout, "Reference (%d topics, the ones api(at:\"<topic>\") answers), read from this binary:\n", len(referenceTopics()))
		fmt.Fprintln(stdout, "  benmore docs index                every topic, one line each")
		fmt.Fprintln(stdout, "  benmore docs --search \"<words>\"   the keys that best match a question")
		fmt.Fprintln(stdout, "  benmore docs <topic>              a topic: whole when small, an index of its keys when large")
		fmt.Fprintln(stdout, "  benmore docs <topic>.<key>        one key")
		return 0, ""
	case docsFromGuide:
		fmt.Fprint(stdout, AgentDocsPointer(req.Name)+AgentDocs(guide))
		// A guide is printed without loading the reference: whether a topic
		// of that name exists is read from the embedded directory.
		if referenceHasTopic(guide) {
			fmt.Fprintf(stderr, "benmore docs: `%[1]s` is also a reference topic: `benmore docs %[1]s --reference` lists its keys and `benmore docs %[1]s.<key>` reads one.\n", guide)
		} else if topic := docAliasAPITopic(guide); referenceHasTopic(topic) && !docsIsGuide(guide) {
			fmt.Fprintf(stderr, "benmore docs: the reference for it is `benmore docs %s`.\n", topic)
		}
		return 0, guide
	case docsFromNowhere:
		fmt.Fprintf(stderr, "Unknown topic: %q\n", req.Name)
		if near := docsNearestNames(req.Name); len(near) > 0 {
			fmt.Fprintf(stderr, "Did you mean: benmore docs %s\n", strings.Join(near, ", benmore docs "))
		}
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "Guides:")
		fmt.Fprint(stderr, AgentDocsCatalog())
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "Reference topics: benmore docs index. Search them: benmore docs --search \"<words>\".")
		return 1, ""
	}

	// The kind of answer is decided from the request, never from the names
	// of the answer's fields: a whole topic carries its keys under their own
	// names, and a topic may one day have a key called `error` or `hits`.
	name := strings.ToLower(strings.TrimSpace(req.Name))
	topicName, _, addressed := strings.Cut(name, ".")
	if req.SearchSet {
		answer := apiSearchReference(req.Search, req.Name)
		fmt.Fprint(stdout, docsJSON(answer))
		if _, found := answer["hits"]; !found {
			return 1, "" // no words to search for, or a topic that does not exist
		}
		fmt.Fprintln(stderr, "benmore docs: read a hit with `benmore docs <at>`.")
		return 0, ""
	}
	answer := apiReadTopic(apiTopicRequest{At: req.Name, Full: req.Full})
	fmt.Fprint(stdout, docsJSON(answer))
	if name == apiTopicCatalogName {
		fmt.Fprintln(stderr, "benmore docs: read a topic with `benmore docs <topic>`, one key with `benmore docs <topic>.<key>`.")
		return 0, ""
	}
	topic, recipe, known := apiResolveTopic(topicName)
	if _, retired := referenceRetired()[topic]; retired {
		return 0, "" // the answer says what replaced it
	}
	if !known {
		return 1, ""
	}
	if addressed {
		if _, _, miss := apiTopicLookup(recipe, strings.TrimSpace(name[len(topicName)+1:])); miss != nil {
			return 1, ""
		}
		return 0, ""
	}
	// What the index's own how_to_read says in api(at:) terms, as commands of
	// this CLI.
	if _, isKey := recipe["total_bytes"]; !isKey && answer["total_bytes"] != nil {
		fmt.Fprintf(stderr, "benmore docs: `%[1]s` is large, so this is the index of its keys. Read one with `benmore docs %[1]s.<key>`, all of it with `benmore docs %[1]s --full`.\n", topic)
	}
	if section, ok := docAliasSections[name]; ok {
		fmt.Fprintf(stderr, "benmore docs: the build guide also covers this (`benmore docs build`, section \"%s\").\n", section)
	}
	return 0, ""
}
