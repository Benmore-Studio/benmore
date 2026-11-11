//go:build !cli

package main

// Delivery of the topic reference (the files under docs/reference, loaded by
// reference.go), in every edition: the `api` tool and `benmore api` on the
// platform, `benmore docs <topic>` everywhere (docs_reference.go).
//
// The reference holds about a megabyte in some ninety topics, and the largest
// topic is over a hundred kilobytes. An agent that wants one answer should not
// have to read all of that, so a topic is delivered in pieces:
//
//	api(at:"flows")                    small topic: whole; large topic: its index
//	api(at:"flows.step_keys")          one key (dotted paths reach nested maps)
//	api(at:"flows", keys:[...])        several keys
//	api(at:"flows", full:true)         the whole topic (apiDescribeTopic)
//	api(at:"index")                    every topic, one line each
//	api(search:"respond json")         ranked keys across all topics (api_topic_search.go)
//
// Nothing here holds documentation text: descriptions in an index are derived
// from the registry's own values.

import (
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	// apiTopicInlineLimit is the largest topic, measured as the compact JSON
	// of its whole answer, that api(at:"<topic>") returns whole. A larger
	// topic answers with its index.
	apiTopicInlineLimit = 8 << 10
	// apiTopicAboutLimit bounds the derived one-line description of a key.
	apiTopicAboutLimit = 140
	// apiTopicCatalogName is the address that lists every topic. It is not a
	// topic, an alias or a retired name ("*" already means the app's routes).
	apiTopicCatalogName = "index"
)

// What the `api` tool's schema says about delivery (toolAPI,
// mcp_tools_api.go). The sentences live here so the tool's description and
// the delivery it describes change together.
const (
	// apiToolDeliveryNote ends the tool description.
	apiToolDeliveryNote = " Do not guess a contract: search='<words>' returns the keys that answer a question, at='<topic>' returns a small topic whole and one over 8 KiB as an index of its keys, and at='<topic>.<key>' reads one key. When an answer names a documentation address, read it with at='<address>' before trying again."
	// apiToolAtDeliveryNote ends the `at` input's description, after the
	// list of topics.
	apiToolAtDeliveryNote = ". at='" + apiTopicCatalogName + "' lists every topic with a one-line summary; at='<topic>.<key>' reads one key of a topic (a dotted path reaches into a nested map)."
	// apiHelpToolDeliveryNote ends the `help` tool's description
	// (toolHelp, mcp_tools_help.go), which is where an agent first reads
	// that feature contracts live in api(at:<topic>).
	apiHelpToolDeliveryNote = " Do not guess a feature contract: api(search:\"<words>\") returns the keys that answer a question, api(at:\"<topic>\") a small topic whole and a large one as an index of its keys (api(at:\"" + apiTopicCatalogName + "\") lists every topic), and api(at:\"<topic>.<key>\") one key. When an answer names a documentation address, fetch it before trying again."
)

// apiTopicRequest is one read of the topic reference.
type apiTopicRequest struct {
	// At is "<topic>" or "<topic>.<key>[.<sub-key>...]"; the topic may be an
	// alias. No topic name contains a dot, so the first dot starts the key.
	At string
	// Keys are keys of the topic to return together, each a key or a dotted
	// path into a nested map.
	Keys []string
	// Full asks for the whole topic whatever its size.
	Full bool
}

// apiTopicKeyEntry is one line of a topic's index.
type apiTopicKeyEntry struct {
	Key   string `json:"key"`
	About string `json:"about"`
	Bytes int    `json:"bytes"`
}

// apiRecipeTopics lists the topics by name. It is shared by tool discovery
// and compatibility documentation.
func apiRecipeTopics() []string {
	recipes := referenceTopics()
	topics := make([]string, 0, len(recipes))
	for topic := range recipes {
		topics = append(topics, topic)
	}
	sort.Strings(topics)
	return topics
}

// apiDescribeTopic is the whole of a topic: every key, under its own name.
// An alias answers as its topic; a retired or unknown name says so.
func apiDescribeTopic(topic string) map[string]any {
	topic = strings.ToLower(strings.TrimSpace(topic))
	if canonical, ok := referenceAliases()[topic]; ok {
		topic = canonical
	}
	if note, ok := referenceRetired()[topic]; ok {
		return map[string]any{"topic": topic, "retired": note}
	}
	if r, ok := referenceTopics()[topic]; ok {
		out := map[string]any{"topic": topic}
		for k, v := range r {
			out[k] = v
		}
		return out
	}
	return map[string]any{
		"error":   "unknown topic: " + topic,
		"hint":    "Pick one of the topics below, or use at='METHOD /path' for a specific route.",
		"nearest": apiNearestKeys(topic, apiRecipeTopics()),
		"topics":  apiRecipeTopics(),
	}
}

// apiReadTopic answers a topic read. A name that is retired or unknown gets
// the answer apiDescribeTopic gives it, in every form.
func apiReadTopic(req apiTopicRequest) map[string]any {
	if strings.EqualFold(strings.TrimSpace(req.At), apiTopicCatalogName) {
		return apiTopicCatalog()
	}
	name, path, addressed := strings.Cut(strings.TrimSpace(req.At), ".")
	topic, recipe, ok := apiResolveTopic(name)
	if !ok {
		return apiDescribeTopic(topic)
	}
	paths := apiKeyPaths(req.Keys)
	switch {
	case addressed && len(paths) == 0:
		return apiTopicKey(topic, recipe, strings.TrimSpace(path))
	case addressed:
		return apiTopicKeys(topic, recipe, append([]string{strings.TrimSpace(path)}, paths...))
	case len(paths) > 0:
		return apiTopicKeys(topic, recipe, paths)
	}
	whole := apiDescribeTopic(topic)
	if req.Full {
		return whole
	}
	return apiTopicWholeOrIndex(topic, recipe, whole)
}

// apiTopicWholeOrIndex returns the whole topic when it fits the inline
// limit, and its index otherwise. A topic just over the limit made of many
// tiny keys can have an index no smaller than itself; it comes back whole
// too, since the index would cost as much and say less.
func apiTopicWholeOrIndex(topic string, recipe, whole map[string]any) map[string]any {
	total := apiJSONBytes(whole)
	if total <= apiTopicInlineLimit {
		return whole
	}
	index := apiTopicIndex(topic, recipe, total)
	if apiJSONBytes(index) >= total {
		return whole
	}
	return index
}

// apiResolveTopic maps what a caller typed onto a registered topic, the way
// apiDescribeTopic does: case and surrounding space ignored, aliases followed.
// ok is false for a retired or unknown name; topic is then the name to report.
func apiResolveTopic(name string) (topic string, recipe map[string]any, ok bool) {
	topic = strings.ToLower(strings.TrimSpace(name))
	if canonical, isAlias := referenceAliases()[topic]; isAlias {
		topic = canonical
	}
	if _, retired := referenceRetired()[topic]; retired {
		return topic, nil, false
	}
	recipe, ok = referenceTopics()[topic]
	return topic, recipe, ok
}

// apiTopicIndex lists a topic's keys with a derived description and size
// each. Keys are listed sorted, which is also the order the whole topic
// renders in (the order they are written in is kept in the topic's
// _topic.json for the files' readers). `summary` is given in full and
// left out of the list.
func apiTopicIndex(topic string, recipe map[string]any, total int) map[string]any {
	keys := make([]apiTopicKeyEntry, 0, len(recipe))
	for _, key := range slices.Sorted(maps.Keys(recipe)) {
		if key == "summary" {
			continue
		}
		keys = append(keys, apiTopicKeyEntry{Key: key, About: apiTopicAbout(recipe[key]), Bytes: apiJSONBytes(recipe[key])})
	}
	out := map[string]any{
		"topic":       topic,
		"keys":        keys,
		"total_bytes": total,
		"how_to_read": fmt.Sprintf("This is the index of a topic too large to return whole: read one key with api(at:\"%[1]s.<key>\") (a dotted path reaches into a nested map), several with api(at:\"%[1]s\", keys:[\"<key>\", ...]), or all %[2]d bytes with api(at:\"%[1]s\", full:true); on the CLI, `benmore api <app> %[1]s.<key>` and `--full`.", topic, total),
	}
	if summary, ok := recipe["summary"]; ok {
		out["summary"] = summary
	}
	return out
}

// apiTopicCatalogEntry is one topic in the list of all topics.
type apiTopicCatalogEntry struct {
	Topic   string `json:"topic"`
	Summary string `json:"summary"`
	Keys    int    `json:"keys"`
	Bytes   int    `json:"bytes"`
}

// apiTopicCatalog lists every topic with the first sentence of its summary,
// its key count and the size of its whole answer. Topics are listed by name:
// only two declare related_topics, and see_also has no one shape, so there is
// no grouping to derive.
func apiTopicCatalog() map[string]any {
	names := apiRecipeTopics()
	recipes := referenceTopics()
	topics := make([]apiTopicCatalogEntry, 0, len(names))
	total := 0
	for _, topic := range names {
		recipe := recipes[topic]
		size := apiJSONBytes(apiDescribeTopic(topic))
		total += size
		topics = append(topics, apiTopicCatalogEntry{Topic: topic, Summary: apiTopicAbout(recipe["summary"]), Keys: len(recipe), Bytes: size})
	}
	return map[string]any{
		"topics":      topics,
		"count":       len(topics),
		"total_bytes": total,
		"aliases":     maps.Clone(referenceAliases()),
		"how_to_read": fmt.Sprintf("Read a topic with api(at:\"<topic>\"): one of at most %d bytes comes back whole, a larger one answers with the index of its keys, and api(at:\"<topic>.<key>\") reads one key. api(search:\"<words>\") finds the keys that answer a question across all topics.", apiTopicInlineLimit),
	}
}

// apiKeyPaths tidies a keys argument: trimmed, blanks and repeats dropped.
func apiKeyPaths(keys []string) []string {
	var paths []string
	for _, key := range keys {
		if key = strings.TrimSpace(key); key != "" && !slices.Contains(paths, key) {
			paths = append(paths, key)
		}
	}
	return paths
}

// apiTopicKey answers one addressed key. The value sits under `value`, not
// under its own name: topics have keys called `keys` and `how_to_read`.
func apiTopicKey(topic string, recipe map[string]any, path string) map[string]any {
	value, canonical, miss := apiTopicLookup(recipe, path)
	if miss != nil {
		return apiUnknownKey(topic, recipe, path, miss)
	}
	return map[string]any{"topic": topic, "key": canonical, "bytes": apiJSONBytes(value), "value": value}
}

// apiTopicKeys answers several keys at once. The ones that exist come back
// under `values`; a name that does not is listed with its nearest matches
// instead of failing the whole read.
func apiTopicKeys(topic string, recipe map[string]any, paths []string) map[string]any {
	values := map[string]any{}
	var unknown []map[string]any
	for _, path := range paths {
		value, canonical, miss := apiTopicLookup(recipe, path)
		if miss != nil {
			unknown = append(unknown, map[string]any{"key": path, "nearest": miss.nearest()})
			continue
		}
		values[canonical] = value
	}
	out := map[string]any{"topic": topic, "values": values, "bytes": apiJSONBytes(values)}
	if len(unknown) > 0 {
		out["unknown"] = unknown
		out["keys"] = slices.Sorted(maps.Keys(recipe))
	}
	if len(values) == 0 {
		out["error"] = "none of the requested keys exist in " + topic
		out["hint"] = apiKeyHint(topic)
	}
	return out
}

// apiKeyMiss is where a dotted path stopped resolving.
type apiKeyMiss struct {
	parent   string   // the part of the path that resolved; "" is the topic itself
	segment  string   // the name that was not found there
	siblings []string // the names that exist there; nil when the parent is not a map
}

// under prefixes a name with the path that resolved, giving a path that can
// be appended to "<topic>." or passed in keys.
func (m *apiKeyMiss) under(name string) string {
	if m.parent == "" {
		return name
	}
	return m.parent + "." + name
}

// nearest lists the existing names closest to the one asked for, as paths.
func (m *apiKeyMiss) nearest() []string {
	near := apiNearestKeys(m.segment, m.siblings)
	for i, name := range near {
		near[i] = m.under(name)
	}
	return near
}

// apiTopicLookup walks a dotted path into a topic, map by map. canonical is
// the path as the registry spells it.
func apiTopicLookup(recipe map[string]any, path string) (value any, canonical string, miss *apiKeyMiss) {
	value = recipe
	segments := strings.Split(path, ".")
	for i, segment := range segments {
		segment = strings.TrimSpace(segment)
		parent := strings.Join(segments[:i], ".")
		rv := reflect.ValueOf(value)
		if rv.Kind() != reflect.Map || rv.Type().Key().Kind() != reflect.String {
			return nil, "", &apiKeyMiss{parent: parent, segment: segment}
		}
		names := apiMapKeys(rv)
		name, ok := apiMatchKey(names, segment)
		if !ok {
			return nil, "", &apiKeyMiss{parent: parent, segment: segment, siblings: names}
		}
		value = rv.MapIndex(reflect.ValueOf(name).Convert(rv.Type().Key())).Interface()
		segments[i] = name
	}
	return value, strings.Join(segments, "."), nil
}

// apiKeyForm is a key name with case and the `-`/`_` choice ignored.
func apiKeyForm(name string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(name)), "-", "_")
}

// apiMatchKey finds want among names: as spelled, else by apiKeyForm when
// exactly one name has that form.
func apiMatchKey(names []string, want string) (string, bool) {
	if slices.Contains(names, want) {
		return want, true
	}
	found := ""
	for _, name := range names {
		if want != "" && apiKeyForm(name) == apiKeyForm(want) {
			if found != "" {
				return "", false
			}
			found = name
		}
	}
	return found, found != ""
}

// apiNearestKeys ranks the names closest to want: a shared prefix, then one
// containing the other, then a typo's distance, then a shared word. At most
// five. When none of those holds, the name or names fewest edits away, if
// under half of want would change (`env_varz_list` for `env_vars`); never
// nil, so an answer's `nearest` is a list and not null.
func apiNearestKeys(want string, names []string) []string {
	want = apiKeyForm(want)
	if want == "" {
		return []string{}
	}
	words := strings.Split(want, "_")
	ranked := map[string]int{}
	for _, name := range names {
		form := apiKeyForm(name)
		switch {
		case strings.HasPrefix(form, want) || strings.HasPrefix(want, form):
			ranked[name] = 0
		case strings.Contains(form, want) || strings.Contains(want, form):
			ranked[name] = 1
		case levenshtein(form, want) <= 2:
			ranked[name] = 2
		case slices.ContainsFunc(strings.Split(form, "_"), func(word string) bool { return len(word) > 2 && slices.Contains(words, word) }):
			ranked[name] = 3
		}
	}
	if len(ranked) == 0 {
		best := len(want)/2 + 1
		for _, name := range names {
			if d := levenshtein(apiKeyForm(name), want); d < best {
				best, ranked = d, map[string]int{name: 0}
			} else if d == best && len(ranked) > 0 {
				ranked[name] = 0
			}
		}
	}
	near := slices.SortedFunc(maps.Keys(ranked), func(a, b string) int {
		if ranked[a] != ranked[b] {
			return ranked[a] - ranked[b]
		}
		return strings.Compare(a, b)
	})
	return append([]string{}, near[:min(len(near), 5)]...)
}

// apiUnknownKey is the answer for an address that names no key: the nearest
// names and the full list of what exists at that level.
func apiUnknownKey(topic string, recipe map[string]any, path string, miss *apiKeyMiss) map[string]any {
	out := map[string]any{"topic": topic, "hint": apiKeyHint(topic)}
	if miss.siblings == nil {
		out["error"] = fmt.Sprintf("unknown key: %s.%s (%s.%s is not a map, so it has no sub-keys)", topic, path, topic, miss.parent)
		out["keys"] = slices.Sorted(maps.Keys(recipe))
		return out
	}
	keys := make([]string, len(miss.siblings))
	for i, name := range miss.siblings {
		keys[i] = miss.under(name)
	}
	out["error"] = "unknown key: " + topic + "." + path
	out["nearest"] = miss.nearest()
	out["keys"] = keys
	return out
}

func apiKeyHint(topic string) string {
	return fmt.Sprintf("Read a key with api(at:\"%[1]s.<key>\"); api(at:\"%[1]s\") lists each key of a large topic with a description and its size.", topic)
}

// apiJSONBytes is the size of v as the compact JSON the HTTP answer carries.
func apiJSONBytes(v any) int {
	data, err := json.Marshal(v)
	if err != nil {
		return 0
	}
	return len(data)
}

// apiTopicAbout derives a one-line description of a registry value: the first
// sentence of a string, the first item of a list, or the sub-key names of a
// map.
func apiTopicAbout(v any) string {
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Invalid:
		return ""
	case reflect.String:
		return apiCutAbout(apiFirstSentence(rv.String()))
	case reflect.Slice, reflect.Array:
		if rv.Len() == 0 {
			return ""
		}
		first := apiTopicAbout(rv.Index(0).Interface())
		if rv.Len() == 1 {
			return first
		}
		return apiCutAbout("(" + strconv.Itoa(rv.Len()) + " items) " + first)
	case reflect.Map:
		return apiCutAbout(strings.Join(apiMapKeys(rv), ", "))
	}
	return apiCutAbout(fmt.Sprint(v))
}

// apiMapKeys returns a map value's keys as sorted text.
func apiMapKeys(rv reflect.Value) []string {
	names := make([]string, 0, rv.Len())
	for _, key := range rv.MapKeys() {
		names = append(names, fmt.Sprint(key.Interface()))
	}
	slices.Sort(names)
	return names
}

// apiSentenceAbbreviations are words whose trailing period does not end a
// sentence.
var apiSentenceAbbreviations = map[string]bool{"e.g": true, "i.e": true, "vs": true, "etc": true, "cf": true, "approx": true}

// apiFirstSentence returns the text up to the first sentence end or line
// break (an example or snippet starts with a title line), on one line.
func apiFirstSentence(s string) string {
	s = strings.TrimSpace(s)
	end := len(s)
scan:
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\n':
			end = i
			break scan
		case '.', '!', '?':
			if i+1 < len(s) && s[i+1] != ' ' && s[i+1] != '\n' {
				continue
			}
			if s[i] == '.' {
				word := s[strings.LastIndexAny(s[:i], " (\n")+1 : i]
				if _, err := strconv.Atoi(word); err == nil || apiSentenceAbbreviations[strings.ToLower(word)] {
					continue // "1." of a numbered list, "e.g."
				}
			}
			end = i + 1
			break scan
		}
	}
	return strings.Join(strings.Fields(s[:end]), " ")
}

// apiCutAbout shortens s to about apiTopicAboutLimit characters, at a word
// boundary where one is near.
func apiCutAbout(s string) string {
	if utf8.RuneCountInString(s) <= apiTopicAboutLimit {
		return s
	}
	cut, runes := 0, 0
	for i := range s {
		if runes == apiTopicAboutLimit {
			cut = i
			break
		}
		runes++
	}
	if space := strings.LastIndexByte(s[:cut], ' '); space > cut-30 {
		cut = space
	}
	return strings.TrimRight(s[:cut], " ,;:") + "..."
}
