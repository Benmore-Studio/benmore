package main

// Agent docs. Topic-keyed markdown bodies embedded into the binary
// at build time. Both the CLI (`benmore docs [topic]`) and the MCP
// help tool (`help(topic)`) read from this same source so they can't
// drift.
//
// New topic = drop a `<name>.md` file into docs/agent/. The filename
// (without extension) is the topic name.

import (
	"embed"
	"fmt"
	"sort"
	"strings"
)

//go:embed docs/agent/*.md
var agentDocsFS embed.FS

// AgentDocs returns the markdown body for a topic, or "" if not found.
// Topic match is case-insensitive. A few aliases are accepted for
// common typos.
func AgentDocs(topic string) string {
	topic = strings.ToLower(strings.TrimSpace(topic))
	if alias, ok := docAliases[topic]; ok {
		topic = alias
	}
	if topic == "" {
		topic = "overview"
	}
	data, err := agentDocsFS.ReadFile("docs/agent/" + topic + ".md")
	if err != nil {
		return ""
	}
	return string(data)
}

// AgentDocsTopics returns the sorted list of available topic names.
func AgentDocsTopics() []string {
	entries, err := agentDocsFS.ReadDir("docs/agent")
	if err != nil {
		return nil
	}
	var topics []string
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".md") {
			continue
		}
		topics = append(topics, strings.TrimSuffix(name, ".md"))
	}
	sort.Strings(topics)
	return topics
}

// AgentDocsCatalog returns a short human-readable listing of every
// topic with a one-line summary (the first markdown heading body).
func AgentDocsCatalog() string {
	topics := AgentDocsTopics()
	var b strings.Builder
	for _, t := range topics {
		body := AgentDocs(t)
		summary := firstHeading(body)
		fmt.Fprintf(&b, "  %-12s  %s\n", t, summary)
	}
	return b.String()
}

// firstHeading returns the body of the first H1 heading minus the
// "# " prefix. Used to derive a one-line summary for the catalog.
func firstHeading(md string) string {
	for _, line := range strings.Split(md, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "# ") {
			return strings.TrimPrefix(line, "# ")
		}
	}
	return ""
}

// docAliases maps every legacy topic name (and common typos) to the
// single consolidated `build` doc. The framework used to ship many
// topic-keyed docs; they're now collapsed into one comprehensive guide.
// Anyone asking for "auth" / "queries" / "directives" still gets a useful
// response - the relevant section of the one guide.
var docAliases = map[string]string{
	"":           "build",
	"start":      "build",
	"intro":      "build",
	"overview":   "build",
	"quickstart": "build",
	"page":       "build",
	"pages":      "build",
	"query":      "build",
	"queries":    "build",
	"directive":  "build",
	"directives": "build",
	"hook":       "build",
	"hooks":      "build",
	"flow":       "build",
	"flows":      "build",
	"workflow":   "build",
	"workflows":  "build",
	"sse":        "build",
	"ws":         "build",
	"websocket":  "build",
	"realtime":   "build",
	"auth":       "build",
	"sdk":        "build",
	"bm":         "build",
	"frontend":   "build",
	"schema":     "build",
	"prisma":     "build",
	"migrations": "build",
	"migrate":    "build",
	"sec":        "build",
	"security":   "build",
	"errors":     "build",
	"gotchas":    "build",
	"faq":        "build",
	"commands":   "build",
	"cli":        "build",
	"tools":      "build",
	"mcp":        "build",
}

// docAliasSections names the build-guide section an aliased topic lives in,
// so `benmore docs auth` says where to look instead of silently printing the
// whole guide.
var docAliasSections = map[string]string{
	"auth":       "Auth, access & server logic",
	"sec":        "Auth, access & server logic",
	"security":   "Auth, access & server logic",
	"hooks":      "Auth, access & server logic",
	"flow":       "Auth, access & server logic",
	"flows":      "Auth, access & server logic",
	"workflow":   "Auth, access & server logic",
	"workflows":  "Auth, access & server logic",
	"schema":     "`schema.prisma` - the data model",
	"prisma":     "`schema.prisma` - the data model",
	"migrations": "`schema.prisma` - the data model",
	"migrate":    "`schema.prisma` - the data model",
	"sdk":        "The frontend - `static/app.tsx` and the `bm` SDK",
	"bm":         "The frontend - `static/app.tsx` and the `bm` SDK",
	"frontend":   "The frontend - `static/app.tsx` and the `bm` SDK",
}

// AgentDocsPointer is the one-line note printed before an aliased topic.
func AgentDocsPointer(topic string) string {
	topic = strings.ToLower(strings.TrimSpace(topic))
	if docAliases[topic] != "build" || topic == "" || topic == "build" {
		return ""
	}
	if section, ok := docAliasSections[topic]; ok {
		return fmt.Sprintf("(`%s` is covered in the build guide below, section \"%s\". On a deployed app, `benmore api <app> %s` has the live reference.)\n\n", topic, section, topic)
	}
	return fmt.Sprintf("(`%s` is part of the build guide below. On a deployed app, `benmore api <app> %s` has the live reference.)\n\n", topic, topic)
}
