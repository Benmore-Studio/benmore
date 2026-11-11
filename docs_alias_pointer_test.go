package main

import (
	"regexp"
	"strings"
	"testing"
)

// docsPointerAPICommand finds the hosted command a docs pointer prints.
var docsPointerAPICommand = regexp.MustCompile("`benmore api <app> ([^`]*)`")

// `benmore docs <alias>` printed "On a deployed app, `benmore api <app>
// <alias>` has the live reference" for every alias, and most aliases (hook,
// ws, security, migrations, quickstart, ...) are not api topics, so the
// command it recommended answered "unknown topic". The pointer now names the
// topic that covers the alias, and says nothing about `benmore api` when no
// topic does. (That every named topic is registered is checked against the
// registry in the platform build: TestDocsAliasPointersNameRegisteredTopics.)
func TestAgentDocsPointerNamesTheTopicThatCoversTheAlias(t *testing.T) {
	for alias, want := range map[string]string{
		"hook": "hooks", "flow": "flows", "workflow": "workflows", "ws": "websocket",
		"migrations": "schema", "migrate": "schema", "prisma": "schema",
		"security": "access", "sec": "access", "bm": "sdk",
		"page": "ssr", "pages": "ssr", "directive": "ssr", "directives": "ssr",
		"queries": "query", "cli": "cli-contracts", "commands": "cli-contracts",
		"mcp": "connector", "tools": "harness",
		// Aliases that are topics under their own name keep it.
		"hooks": "hooks", "flows": "flows", "auth": "auth", "schema": "schema",
		"frontend": "frontend", "sdk": "sdk", "errors": "errors", "sse": "sse",
		"websocket": "websocket", "realtime": "realtime", "query": "query", "workflows": "workflows",
	} {
		pointer := AgentDocsPointer(alias)
		got := docsPointerAPICommand.FindAllStringSubmatch(pointer, -1)
		if len(got) != 1 || got[0][1] != want {
			t.Errorf("docs %s: pointer %q, want one `benmore api <app> %s`", alias, pointer, want)
		}
		if !strings.Contains(pointer, "`"+alias+"` is ") || !strings.Contains(pointer, "the build guide below") || !strings.HasSuffix(pointer, ")\n\n") {
			t.Errorf("docs %s: pointer lost its build-guide note: %q", alias, pointer)
		}
	}

	// General orientation has no topic: the note stays, the command goes.
	for _, alias := range []string{"start", "intro", "overview", "quickstart", "gotchas", "faq"} {
		pointer := AgentDocsPointer(alias)
		if strings.Contains(pointer, "benmore api") || strings.Contains(pointer, "live reference") {
			t.Errorf("docs %s: pointer names a `benmore api` call no topic answers: %q", alias, pointer)
		}
		if pointer != "(`"+alias+"` is part of the build guide below.)\n\n" {
			t.Errorf("docs %s: pointer %q", alias, pointer)
		}
	}

	// The section note is kept next to the mapped topic.
	if got, want := AgentDocsPointer("Security "), "(`security` is covered in the build guide below, section \"Auth, access & server logic\". On a deployed app, `benmore api <app> access` has the live reference.)\n\n"; got != want {
		t.Errorf("docs security:\n got %q\nwant %q", got, want)
	}
	// Real docs and unknown names get no pointer.
	for _, topic := range []string{"", "build", "connector", "deploy", "harness", "no-such-topic"} {
		if got := AgentDocsPointer(topic); got != "" {
			t.Errorf("docs %q: unexpected pointer %q", topic, got)
		}
	}

	// Every alias either prints one command naming a topic or none at all,
	// and no entry of the mapping is left over from a removed alias.
	for alias := range docAliases {
		if alias == "" {
			continue
		}
		pointer := AgentDocsPointer(alias)
		topic := docAliasAPITopic(alias)
		switch got := docsPointerAPICommand.FindAllStringSubmatch(pointer, -1); {
		case topic == "" && (len(got) != 0 || strings.Contains(pointer, "benmore api")):
			t.Errorf("docs %s: no topic, but the pointer prints a command: %q", alias, pointer)
		case topic != "" && (len(got) != 1 || got[0][1] != topic):
			t.Errorf("docs %s: pointer %q does not name topic %s", alias, pointer, topic)
		}
	}
	for alias := range docAliasAPITopics {
		if docAliases[alias] != "build" {
			t.Errorf("docAliasAPITopics has %q, which is not a build-guide alias", alias)
		}
	}
}
