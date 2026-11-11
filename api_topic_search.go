//go:build !cli

package main

// Search over the topic reference: api(search:"<words>") answers with the
// addresses of the keys that best match, so an agent reads one key instead
// of guessing which topic holds its answer. It is a plain word match over
// the reference held in memory: no index file and nothing to keep in step.

import (
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"sync"
	"unicode"
)

const (
	// apiSearchMaxHits is how many addresses a search returns.
	apiSearchMaxHits = 10
	// A word found in the key name counts more than one found in the topic
	// name, which counts more than one found in the text; a word that
	// repeats in the text adds up to apiSearchTextCap.
	apiSearchKeyWeight   = 8
	apiSearchTopicWeight = 4
	apiSearchTextCap     = 3
)

// apiSearchHit is one ranked address.
type apiSearchHit struct {
	At    string `json:"at"`
	About string `json:"about"`
	Bytes int    `json:"bytes"`
}

// apiSearchUnit is one addressable piece of the registry, lower-cased for
// matching.
type apiSearchUnit struct {
	at         string // "<topic>.<key path>" as the registry spells it
	topic      string
	topicNames string // the topic's name and the aliases that answer with it
	key        string // the key path
	text       string // every string and nested key name in the value
	about      string
	bytes      int
}

// apiSearchStopWords are dropped from a query unless it has no other word.
var apiSearchStopWords = map[string]bool{
	"an": true, "and": true, "are": true, "as": true, "at": true, "be": true, "by": true, "can": true,
	"do": true, "doe": true, "for": true, "from": true, "how": true, "in": true, "is": true, "it": true,
	"my": true, "of": true, "on": true, "or": true, "that": true, "the": true, "thi": true, "to": true,
	"what": true, "when": true, "with": true,
}

// apiSearchCorpus is the reference as search units, built on first use. The
// reference does not change while the process runs.
var apiSearchCorpus = sync.OnceValue(apiSearchBuildCorpus)

// apiSearchBuildCorpus lists every addressable piece of the reference, by
// topic and key.
func apiSearchBuildCorpus() []apiSearchUnit {
	aliases := map[string][]string{}
	for alias, topic := range referenceAliases() {
		aliases[topic] = append(aliases[topic], alias)
	}
	recipes := referenceTopics()
	var units []apiSearchUnit
	for _, topic := range apiRecipeTopics() {
		names := strings.ToLower(strings.Join(append([]string{topic}, slices.Sorted(slices.Values(aliases[topic]))...), " "))
		recipe := recipes[topic]
		for _, key := range slices.Sorted(maps.Keys(recipe)) {
			units = apiSearchAddUnits(units, topic, names, key, recipe[key])
		}
	}
	return units
}

// apiSearchAddUnits adds the unit for one key. A map larger than the inline
// limit is added by its sub-keys instead, each of which has its own address,
// so a hit stays a small read where the registry's shape allows it.
func apiSearchAddUnits(units []apiSearchUnit, topic, topicNames, path string, value any) []apiSearchUnit {
	size := apiJSONBytes(value)
	if rv := reflect.ValueOf(value); size > apiTopicInlineLimit && rv.Kind() == reflect.Map && rv.Type().Key().Kind() == reflect.String {
		for _, name := range apiMapKeys(rv) {
			sub := rv.MapIndex(reflect.ValueOf(name).Convert(rv.Type().Key())).Interface()
			units = apiSearchAddUnits(units, topic, topicNames, path+"."+name, sub)
		}
		return units
	}
	var text strings.Builder
	apiSearchText(&text, reflect.ValueOf(value))
	return append(units, apiSearchUnit{
		at:         topic + "." + path,
		topic:      topic,
		topicNames: topicNames,
		key:        strings.ToLower(path),
		text:       strings.ToLower(text.String()),
		about:      apiTopicAbout(value),
		bytes:      size,
	})
}

// apiSearchText writes the text of a registry value: its strings, and the
// key names of the maps inside it.
func apiSearchText(out *strings.Builder, rv reflect.Value) {
	switch rv.Kind() {
	case reflect.Invalid:
	case reflect.Interface, reflect.Pointer:
		apiSearchText(out, rv.Elem())
	case reflect.String:
		out.WriteString(rv.String())
		out.WriteByte('\n')
	case reflect.Slice, reflect.Array:
		for i := range rv.Len() {
			apiSearchText(out, rv.Index(i))
		}
	case reflect.Map:
		for _, key := range rv.MapKeys() {
			apiSearchText(out, key)
			apiSearchText(out, rv.MapIndex(key))
		}
	default:
		fmt.Fprintln(out, rv.Interface())
	}
}

// apiSearchWords splits a query into lower-cased words. A plural `s` is
// dropped so `uploads` finds `upload`; words are matched as substrings, so
// the shorter form finds both.
func apiSearchWords(query string) []string {
	var words, all []string
	for _, word := range strings.FieldsFunc(strings.ToLower(query), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }) {
		if len(word) > 3 && strings.HasSuffix(word, "s") && !strings.HasSuffix(word, "ss") {
			word = strings.TrimSuffix(word, "s")
		}
		if slices.Contains(all, word) {
			continue
		}
		all = append(all, word)
		if len(word) > 1 && !apiSearchStopWords[word] {
			words = append(words, word)
		}
	}
	if len(words) == 0 {
		return all
	}
	return words
}

// apiSearchRank returns the best units for the words: most words matched
// first, then the higher weight (key name over topic name over text), then
// the smaller unit, then the address.
func apiSearchRank(units []apiSearchUnit, words []string, limit int) []apiSearchHit {
	type scored struct {
		unit           *apiSearchUnit
		matched, score int
	}
	var found []scored
	for i := range units {
		unit := &units[i]
		matched, score := 0, 0
		for _, word := range words {
			weight := min(strings.Count(unit.text, word), apiSearchTextCap)
			if strings.Contains(unit.key, word) {
				weight += apiSearchKeyWeight
			}
			if strings.Contains(unit.topicNames, word) {
				weight += apiSearchTopicWeight
			}
			if weight > 0 {
				matched++
				score += weight
			}
		}
		if matched > 0 {
			found = append(found, scored{unit, matched, score})
		}
	}
	slices.SortFunc(found, func(a, b scored) int {
		switch {
		case a.matched != b.matched:
			return b.matched - a.matched
		case a.score != b.score:
			return b.score - a.score
		case a.unit.bytes != b.unit.bytes:
			return a.unit.bytes - b.unit.bytes
		}
		return strings.Compare(a.unit.at, b.unit.at)
	})
	hits := make([]apiSearchHit, 0, min(len(found), limit))
	for _, f := range found[:min(len(found), limit)] {
		hits = append(hits, apiSearchHit{At: f.unit.at, About: f.unit.about, Bytes: f.unit.bytes})
	}
	return hits
}

// apiSearchReference answers api(search:"<words>"). With a topic in at the
// search stays inside that topic; a retired or unknown topic gets the answer
// a read of it gets.
func apiSearchReference(query, at string) map[string]any {
	return apiSearchUnits(apiSearchCorpus(), query, at)
}

// apiSearchUnits is apiSearchReference over a given list of units.
func apiSearchUnits(units []apiSearchUnit, query, at string) map[string]any {
	out := map[string]any{"search": query}
	switch name, _, _ := strings.Cut(strings.TrimSpace(at), "."); strings.ToLower(strings.TrimSpace(name)) {
	case "", "*", "all", "routes", apiTopicCatalogName:
	default:
		topic, _, ok := apiResolveTopic(name)
		if !ok {
			return apiDescribeTopic(topic)
		}
		out["topic"] = topic
		units = slices.DeleteFunc(slices.Clone(units), func(unit apiSearchUnit) bool { return unit.topic != topic })
	}
	words := apiSearchWords(query)
	if len(words) == 0 {
		out["error"] = "search needs at least one word"
		out["hint"] = "Pass the words of the question, for example api(search:\"upload private file\"); api(at:\"" + apiTopicCatalogName + "\") lists every topic."
		return out
	}
	hits := apiSearchRank(units, words, apiSearchMaxHits)
	out["hits"] = hits
	out["count"] = len(hits)
	if len(hits) == 0 {
		out["hint"] = "No key mentions any of these words. Try other or fewer words, or api(at:\"" + apiTopicCatalogName + "\") for the list of topics."
		return out
	}
	out["how_to_read"] = "Read a hit with api(at:\"<at>\"). Hits that match more of the words come first; a word in the key name counts more than one in the topic name, which counts more than one in the text; the smaller key wins a tie."
	return out
}
