//go:build !cli

package main

// The app-builder reference: what api(at:"<topic>") and `benmore docs
// <topic>` answer.
//
// It lives in files under docs/reference, embedded into every edition:
//
//	docs/reference/_registry.json        every topic's name, other names for a topic, retired names
//	docs/reference/<topic>/_topic.json   the topic's keys in the order they are written,
//	                                     and the values code builds
//	docs/reference/<topic>/<key>.txt     a string value, followed by one newline
//	docs/reference/<topic>/<key>.json    a list, map or number
//
// A value code builds (a table rendered from the validator's own list, a
// section of a bundled guide) has no file: _topic.json lists its path under
// "generated" and referenceGenerators (reference_generated.go) builds it, so
// nothing holds a copy that could go stale.
//
// The files are read once, on first use: a process that never answers a
// reference question (every served app) reads nothing. Delivery of the
// reference (index, addresses, search) is in api_topic_delivery.go and
// api_topic_search.go; docs/reference/README.md is the editing guide.

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
)

//go:embed docs/reference/_registry.json docs/reference/*/*.json docs/reference/*/*.txt
var referenceFS embed.FS

const (
	referenceDir        = "docs/reference"
	referenceRegistry   = "_registry.json"
	referenceTopicIndex = "_topic.json"
)

// The loaded reference. referenceLoad sets these; nothing writes them
// afterwards. Production code reads them through referenceTopics,
// referenceAliases and referenceRetired, which load first: a direct read
// before the first load would see an empty reference and report nothing
// wrong (TestReferenceReadersLoadFirst holds production code to that).
var (
	// topicRecipes holds each topic's keys and values.
	topicRecipes map[string]map[string]any
	// topicAliases are other names agents reach for, answered with the
	// canonical topic. They are not topics: discovery, the capability map
	// and the unknown-topic list name only the canonical one.
	topicAliases map[string]string
	// retiredTopics answers a topic whose feature was removed, so an agent
	// that still knows the old name learns what happened instead of getting
	// "unknown topic". They are not topics either.
	retiredTopics map[string]string
)

// referenceLoad reads the embedded reference, once. A reference that does
// not load is a defect of the build (the tests of every edition load it), so
// it panics with the file and the reason.
var referenceLoad = sync.OnceFunc(func() {
	fsys, err := fs.Sub(referenceFS, referenceDir)
	if err == nil {
		var loaded *referenceData
		if loaded, err = referenceRead(fsys, referenceGenerators); err == nil {
			topicRecipes, topicAliases, retiredTopics = loaded.Topics, loaded.Aliases, loaded.Retired
			return
		}
	}
	panic("benmore: the embedded reference (" + referenceDir + ") does not load: " + err.Error())
})

// referenceTopics is the reference by topic, loaded on first use.
func referenceTopics() map[string]map[string]any {
	referenceLoad()
	return topicRecipes
}

// referenceAliases maps other names to the topic that answers them.
func referenceAliases() map[string]string {
	referenceLoad()
	return topicAliases
}

// referenceRetired maps retired topic names to what replaced them.
func referenceRetired() map[string]string {
	referenceLoad()
	return retiredTopics
}

// referenceHasTopic reports whether name is a topic directory of the embedded
// reference, without loading the reference.
func referenceHasTopic(name string) bool {
	if !referenceTopicName.MatchString(name) {
		return false
	}
	_, err := fs.Stat(referenceFS, referenceDir+"/"+name+"/"+referenceTopicIndex)
	return err == nil
}

// referenceData is one reading of a reference directory.
type referenceData struct {
	Topics  map[string]map[string]any
	Aliases map[string]string
	Retired map[string]string
	// Order is each topic's keys as _topic.json lists them. Every answer
	// lists keys sorted; the written order is kept for the files' readers.
	Order map[string][]string
}

// referenceTopicFile is a topic's _topic.json.
type referenceTopicFile struct {
	// Keys are the topic's keys, in the order an author wrote them.
	Keys []string `json:"keys"`
	// Generated maps the dotted path of a value code builds to a note of
	// what builds it. The path is a key, or a path into a key's map.
	Generated map[string]string `json:"generated,omitempty"`
}

var (
	referenceTopicName = regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)
	referenceKeyName   = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
)

// referenceRead loads a reference directory. generators builds the values
// the files leave to code, by address ("<topic>.<path>").
func referenceRead(fsys fs.FS, generators map[string]func() any) (*referenceData, error) {
	data := &referenceData{Topics: map[string]map[string]any{}, Order: map[string][]string{}}
	var registry struct {
		// Topics names every topic directory. A directory that is missing
		// (a file-ignore rule can hide one from every checkout but the
		// author's) or one nobody listed is an error, not a shorter or
		// longer reference.
		Topics  []string          `json:"topics"`
		Aliases map[string]string `json:"aliases"`
		Retired map[string]string `json:"retired"`
	}
	if err := referenceReadJSON(fsys, referenceRegistry, &registry); err != nil {
		return nil, err
	}
	data.Aliases, data.Retired = registry.Aliases, registry.Retired
	if data.Aliases == nil {
		data.Aliases = map[string]string{}
	}
	if data.Retired == nil {
		data.Retired = map[string]string{}
	}
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, err
	}
	used := map[string]bool{}
	for _, entry := range entries {
		name := entry.Name()
		if !entry.IsDir() || strings.HasPrefix(name, ".") {
			continue
		}
		if !referenceTopicName.MatchString(name) {
			return nil, fmt.Errorf("%s: a topic directory is named in lower case, with digits, `-` and `_`", name)
		}
		recipe, order, err := referenceReadTopic(fsys, name, generators, used)
		if err != nil {
			return nil, err
		}
		data.Topics[name], data.Order[name] = recipe, order
	}
	if len(data.Topics) == 0 {
		return nil, fmt.Errorf("no topic directory found")
	}
	listed := map[string]bool{}
	for _, topic := range registry.Topics {
		if listed[topic] {
			return nil, fmt.Errorf("%s lists the topic %s twice", referenceRegistry, topic)
		}
		listed[topic] = true
		if _, ok := data.Topics[topic]; !ok {
			return nil, fmt.Errorf("%s lists the topic %s, which has no directory (is %s/ hidden by a file-ignore rule, or not committed?)", referenceRegistry, topic, topic)
		}
	}
	for _, topic := range slices.Sorted(maps.Keys(data.Topics)) {
		if !listed[topic] {
			return nil, fmt.Errorf("the topic directory %s is not listed under \"topics\" in %s: add its name, or remove the directory", topic, referenceRegistry)
		}
	}
	for alias, topic := range data.Aliases {
		if _, ok := data.Topics[topic]; !ok {
			return nil, fmt.Errorf("%s: alias %s names the topic %s, which does not exist", referenceRegistry, alias, topic)
		}
		if _, clash := data.Topics[alias]; clash {
			return nil, fmt.Errorf("%s: alias %s is also a topic", referenceRegistry, alias)
		}
	}
	for name := range data.Retired {
		if _, clash := data.Topics[name]; clash {
			return nil, fmt.Errorf("%s: retired name %s is also a topic", referenceRegistry, name)
		}
	}
	for address := range generators {
		if !used[address] {
			return nil, fmt.Errorf("a generator is registered for %s, which no %s lists under \"generated\"", address, referenceTopicIndex)
		}
	}
	return data, nil
}

// referenceReadTopic loads one topic directory. Every key _topic.json lists
// has exactly one source (a .txt file, a .json file, or a generator), and
// every value file is listed.
func referenceReadTopic(fsys fs.FS, topic string, generators map[string]func() any, used map[string]bool) (map[string]any, []string, error) {
	var index referenceTopicFile
	if err := referenceReadJSON(fsys, topic+"/"+referenceTopicIndex, &index); err != nil {
		return nil, nil, err
	}
	files, err := fs.ReadDir(fsys, topic)
	if err != nil {
		return nil, nil, err
	}
	onDisk := map[string]string{} // key -> file name
	for _, file := range files {
		name := file.Name()
		if name == referenceTopicIndex || strings.HasPrefix(name, ".") {
			continue
		}
		key, ext, _ := strings.Cut(name, ".")
		if file.IsDir() || (ext != "txt" && ext != "json") || !referenceKeyName.MatchString(key) {
			return nil, nil, fmt.Errorf("%s/%s: a topic directory holds %s and one <key>.txt or <key>.json per key", topic, name, referenceTopicIndex)
		}
		if other, twice := onDisk[key]; twice {
			return nil, nil, fmt.Errorf("%s: the key %s has two files, %s and %s", topic, key, other, name)
		}
		onDisk[key] = name
	}
	recipe := make(map[string]any, len(index.Keys))
	for _, key := range index.Keys {
		if _, twice := recipe[key]; twice {
			return nil, nil, fmt.Errorf("%s/%s lists the key %s twice", topic, referenceTopicIndex, key)
		}
		name, hasFile := onDisk[key]
		if _, built := index.Generated[key]; built {
			if hasFile {
				return nil, nil, fmt.Errorf("%s/%s: the key is built by code (%s lists it under \"generated\"), so it has no file", topic, name, referenceTopicIndex)
			}
			recipe[key] = nil // set below
			continue
		}
		if !hasFile {
			return nil, nil, fmt.Errorf("%s/%s lists the key %s, which has no %s.txt or %s.json", topic, referenceTopicIndex, key, key, key)
		}
		raw, err := fs.ReadFile(fsys, topic+"/"+name)
		if err != nil {
			return nil, nil, err
		}
		if strings.HasSuffix(name, ".txt") {
			recipe[key] = strings.TrimSuffix(string(raw), "\n")
		} else if recipe[key], err = referenceDecode(raw); err != nil {
			return nil, nil, fmt.Errorf("%s/%s: %w", topic, name, err)
		}
		delete(onDisk, key)
	}
	if len(onDisk) > 0 {
		return nil, nil, fmt.Errorf("%s/%s does not list %s: add the key to \"keys\", or remove the file", topic, referenceTopicIndex, strings.Join(slices.Sorted(maps.Values(onDisk)), ", "))
	}
	for _, path := range slices.Sorted(maps.Keys(index.Generated)) {
		address := topic + "." + path
		build, ok := generators[address]
		if !ok {
			return nil, nil, fmt.Errorf("%s/%s lists %s as built by code, and no generator is registered for %s (referenceGenerators)", topic, referenceTopicIndex, path, address)
		}
		used[address] = true
		if err := referenceSet(recipe, path, build()); err != nil {
			return nil, nil, fmt.Errorf("%s/%s: generated %s: %w", topic, referenceTopicIndex, path, err)
		}
	}
	return recipe, index.Keys, nil
}

// referenceSet puts a generated value at a dotted path: a key of the topic,
// or a new entry of a map a file holds.
func referenceSet(recipe map[string]any, path string, value any) error {
	segments := strings.Split(path, ".")
	parent := recipe
	for _, segment := range segments[:len(segments)-1] {
		next, ok := parent[segment].(map[string]any)
		if !ok {
			return fmt.Errorf("%s is not a map in the files", segment)
		}
		parent = next
	}
	leaf := segments[len(segments)-1]
	if existing, ok := parent[leaf]; len(segments) == 1 && !ok {
		return fmt.Errorf("the key is not listed in \"keys\"")
	} else if ok && existing != nil {
		return fmt.Errorf("a file already holds a value there")
	}
	if value == nil {
		return fmt.Errorf("its generator built nothing")
	}
	parent[leaf] = value
	return nil
}

func referenceReadJSON(fsys fs.FS, name string, into any) error {
	raw, err := fs.ReadFile(fsys, name)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("%s: text after the JSON value", name)
	}
	return nil
}

// referenceDecode reads a .json value file into the Go types the reference
// uses: see referenceTyped.
func referenceDecode(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("text after the JSON value")
	}
	return referenceTyped(value)
}

// referenceTyped gives a decoded JSON value its Go type: a string stays a
// string, a whole number is an int, a list of strings is []string, a list of
// objects is []map[string]any, any other list is []any, and an object is
// map[string]any. Fractions and null have no place in the reference.
func referenceTyped(value any) (any, error) {
	switch v := value.(type) {
	case string, bool:
		return v, nil
	case json.Number:
		n, err := strconv.Atoi(v.String())
		if err != nil {
			return nil, fmt.Errorf("the number %s is not a whole number: write it as text", v)
		}
		return n, nil
	case map[string]any:
		for key, item := range v {
			typed, err := referenceTyped(item)
			if err != nil {
				return nil, err
			}
			v[key] = typed
		}
		return v, nil
	case []any:
		texts, objects := make([]string, 0, len(v)), make([]map[string]any, 0, len(v))
		for i, item := range v {
			typed, err := referenceTyped(item)
			if err != nil {
				return nil, err
			}
			v[i] = typed
			switch t := typed.(type) {
			case string:
				texts = append(texts, t)
			case map[string]any:
				objects = append(objects, t)
			}
		}
		switch {
		case len(texts) == len(v):
			return texts, nil
		case len(objects) == len(v):
			return objects, nil
		}
		return v, nil
	}
	return nil, fmt.Errorf("unsupported JSON value %v (null has no place in the reference)", value)
}
