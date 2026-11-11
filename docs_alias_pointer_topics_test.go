//go:build !cli

package main

import (
	"sort"
	"strings"
	"testing"
)

// The topic a docs alias points at must be one the reference answers (a
// topicRecipes key, or a topicAliases name), asked the way `benmore api <app>
// <topic>` and `benmore docs <topic>` ask it. An alias added to docAliases
// whose own name is not a topic fails here until docAliasAPITopics maps it to
// one or to "".
func TestDocsAliasPointersNameRegisteredTopics(t *testing.T) {
	answered := func(topic string) bool {
		got := apiDescribeTopic(topic)
		_, unknown := got["error"]
		_, retired := got["retired"]
		return !unknown && !retired && got["topic"] != nil
	}
	if answered("no-such-topic") || !answered("hooks") || !answered("pages") {
		t.Fatal("the topic lookup this test relies on changed shape")
	}

	aliases := make([]string, 0, len(docAliases))
	for alias := range docAliases {
		if alias != "" {
			aliases = append(aliases, alias)
		}
	}
	sort.Strings(aliases)
	pointed := 0
	for _, alias := range aliases {
		pointer := AgentDocsPointer(alias)
		commands := docsPointerAPICommand.FindAllStringSubmatch(pointer, -1)
		if len(commands) == 0 {
			if strings.Contains(pointer, "benmore api") {
				t.Errorf("docs %s: pointer mentions benmore api without a topic: %q", alias, pointer)
			}
			continue
		}
		for _, c := range commands {
			pointed++
			if !answered(c[1]) {
				t.Errorf("docs %s prints `benmore api <app> %s`, which answers unknown topic; map the alias in docAliasAPITopics (docs.go) to a registered topic, or to \"\" for none", alias, c[1])
			}
		}
	}
	if pointed < 20 {
		t.Fatalf("only %d of %d aliases print a `benmore api` pointer; the check is not seeing them", pointed, len(aliases))
	}
	// A topic that covers an alias under the alias's own name is the one named.
	for _, alias := range aliases {
		if _, ok := topicRecipes[alias]; ok && docAliasAPITopic(alias) != alias {
			t.Errorf("docs %s is itself a topic but points at %q", alias, docAliasAPITopic(alias))
		}
	}
}

// api(at:"mobile") says which icon the manifest lists when `pwa.icon` is
// left out, and that `benmore check` names a missing icon file.
func TestMobileTopicStatesTheDefaultManifestIcon(t *testing.T) {
	pwa, _ := topicRecipes["mobile"]["pwa"].(string)
	for _, want := range []string{"`/static/icon-512.png`", "`seo.favicon`", "`/static/favicon.svg`", "`benmore check`"} {
		if !strings.Contains(pwa, want) {
			t.Errorf("api(at:\"mobile\") pwa section does not mention %s", want)
		}
	}
	alt, _ := topicRecipes["mobile"]["alternative"].(string)
	if !strings.Contains(alt, "`icon`") {
		t.Errorf("api(at:\"mobile\") alternative does not say an icon is needed: %s", alt)
	}
}
