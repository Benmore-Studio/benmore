//go:build !cli

package main

// The harness guide as keys of api(at:"harness").
//
// docs/agent/harness.md is one bundled guide (`benmore docs harness`,
// help(topic:"harness")), larger than a key of the topic reference may be.
// The reference delivers it one `## ` section per key, read from the same
// embedded file, so the guide keeps a single source and an agent reads the
// section it needs.

import "strings"

// harnessGuideSections names each `## ` section of the harness guide as a
// key of api(at:"harness"), in the guide's order. about is the line the
// overview key gives for it.
var harnessGuideSections = []struct{ key, heading, about string }{
	{"guide_surfaces", "Know which surface you are using", "the editions, the skill, AGENTS.md and the MCP tools, and what each is the source of truth for"},
	{"guide_agent_setup", "Set up Codex or Claude", "installing the skill for each agent, where it lands, and how each agent's edits are delivered"},
	{"guide_identity_environment", "Establish identity, app, and environment", "which account, app and environment a command acts on, and how credentials are held"},
	{"guide_lifecycles", "Lifecycles: state, transition, observe", "the state table: sign-in, environment pin, instances, source, a push, release, testing posture, serving, jobs, workflow records, approvals, imports, the connector, idle sessions, compliance"},
	{"guide_reading_contracts", "Read the smallest authoritative contract", "finding and reading a contract before writing against it"},
	{"guide_iterating", "Iterate without losing source or runtime state", "the edit, push, check and exercise loop, and what a rejected reload keeps"},
	{"guide_proving", "Prove the result", "probe, browser checks, `benmore verify`, `benmore ship` and the final sync check"},
	{"guide_diagnosing", "Diagnose rather than retry blindly", "what each failure signal means and the next step"},
	{"guide_cli_commands", "CLI command contracts", "target selection, the `target:` line, and each command's effect, inputs, exit codes and JSON"},
	{"guide_usage_accounting", "Usage accounting and context", "local usage counters, telemetry and the cached API reference"},
}

// agentDocsSections splits a bundled guide at its `## ` headings: the text
// before the first one, then each section from its heading line to the next.
// The parts joined are the guide, byte for byte.
func agentDocsSections(topic string) (intro string, sections []string) {
	rest := AgentDocs(topic)
	const mark = "\n## "
	i := strings.Index(rest, mark)
	if i < 0 {
		return rest, nil
	}
	intro, rest = rest[:i+1], rest[i+1:]
	for {
		i := strings.Index(rest, mark)
		if i < 0 {
			return intro, append(sections, rest)
		}
		sections, rest = append(sections, rest[:i+1]), rest[i+1:]
	}
}

// harnessGuideSection is the value of one harness guide key: its section of
// the bundled guide, heading included.
func harnessGuideSection(key string) string {
	for _, s := range harnessGuideSections {
		if s.key != key {
			continue
		}
		_, sections := agentDocsSections("harness")
		for _, section := range sections {
			if strings.HasPrefix(section, "## "+s.heading+"\n") {
				return strings.TrimRight(section, "\n")
			}
		}
	}
	return ""
}

// harnessGuideOverview is api(at:"harness.guide"): the guide's opening, then
// one line per section key.
func harnessGuideOverview() string {
	intro, _ := agentDocsSections("harness")
	var b strings.Builder
	b.WriteString(strings.TrimRight(intro, "\n"))
	b.WriteString("\n\nThe guide is delivered one section per key of this topic; read the key that matches the question (`benmore docs harness` prints the whole guide):\n")
	for _, s := range harnessGuideSections {
		b.WriteString("\n- `" + s.key + "`: " + s.heading + " (" + s.about + ")")
	}
	return b.String()
}
