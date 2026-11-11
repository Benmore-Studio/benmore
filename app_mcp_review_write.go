//go:build !cli

package main

// How `benmore mcp review --reviewed` (and the Notes starter) write mcp.yaml.
//
// Review used to decode the manifest into Go values and marshal it back. That
// rewrote every integer bound through float64 (maximum: 100000000 became
// 1e+08, 9007199254740991 became 9.007199254740991e+15), re-indented the whole
// file to four spaces, so a tool added later in the documented two-space style
// no longer parsed, and dropped comments. Now review edits only its own three
// top-level keys in the authored text: contract_digest, execution_digest and
// execution_sources. Every other byte stays as written.
//
// Digests are unaffected by formatting: the contract digest hashes the decoded
// manifest (app_mcp_digests.go), never the YAML text. Review computes it from
// the authored text, and appMCPReviewedManifestBytes proves that its output
// decodes to that same manifest apart from the three keys, so the runtime,
// which decodes the written file, computes the same digest. An already
// reviewed file (in any earlier output form) is edited in place and keeps
// its digests when nothing else changed.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"go.yaml.in/yaml/v3"
)

// appMCPReviewKeys are the top-level keys review owns, in insertion order.
var appMCPReviewKeys = []string{"contract_digest", "execution_digest", "execution_sources"}

// appMCPReviewedManifestBytes returns data with the review keys set to the
// given digests and execution_sources: runtime. A line edit is tried first; a
// document it cannot edit safely (a flow-style root, a value spread over
// several lines, a document end marker) is re-encoded from its node tree with
// two-space indentation, which still keeps every scalar as written. Either
// result must decode to the authored manifest apart from the review keys, or
// review refuses rather than write something else.
func appMCPReviewedManifestBytes(data []byte, contract, execution string) ([]byte, error) {
	values := map[string]string{"contract_digest": contract, "execution_digest": execution, "execution_sources": appMCPExecutionSourcesRuntime}
	authored, err := decodeAppMCPManifest(data)
	if err != nil {
		return nil, err
	}
	if authored == nil {
		return nil, fmt.Errorf("review requires a version 1 mcp.yaml")
	}
	if out, ok := appMCPSetReviewKeyLines(data, values); ok && appMCPReviewEditPreserves(authored, out, values) {
		return out, nil
	}
	out, err := appMCPSetReviewKeyNodes(data, values)
	if err != nil || !appMCPReviewEditPreserves(authored, out, values) {
		return nil, fmt.Errorf("mcp.yaml: review could not record its digests without changing other declarations; write contract_digest, execution_digest and execution_sources as plain top-level keys and review again")
	}
	return out, nil
}

// appMCPReviewEditPreserves decodes the edited text and compares it with the
// authored manifest through the contract digest's own encoding, with the
// review keys blanked on both sides.
func appMCPReviewEditPreserves(authored *AppMCPManifest, edited []byte, values map[string]string) bool {
	decoded, err := decodeAppMCPManifest(edited)
	if err != nil || decoded == nil || decoded.ContractDigest != values["contract_digest"] ||
		decoded.ExecutionDigest != values["execution_digest"] || decoded.ExecutionSources != values["execution_sources"] {
		return false
	}
	before, after := *authored, *decoded
	for _, m := range []*AppMCPManifest{&before, &after} {
		m.ContractDigest, m.ExecutionDigest, m.ExecutionSources = "", "", ""
	}
	a, errA := json.Marshal(before)
	b, errB := json.Marshal(after)
	return errA == nil && errB == nil && bytes.Equal(a, b)
}

// appMCPReviewScalar is the YAML spelling of a string value: plain when it
// reads back as that string, quoted otherwise (a hex digest made only of
// digits would otherwise read back as a number).
func appMCPReviewScalar(value string) (string, bool) {
	encoded, err := yaml.Marshal(value)
	text := strings.TrimSuffix(string(encoded), "\n")
	return text, err == nil && !strings.Contains(text, "\n")
}

// appMCPMappingValue finds a key in a mapping node.
func appMCPMappingValue(mapping *yaml.Node, key string) (*yaml.Node, *yaml.Node) {
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if k := mapping.Content[i]; k.Kind == yaml.ScalarNode && k.Value == key {
			return k, mapping.Content[i+1]
		}
	}
	return nil, nil
}

// appMCPSetReviewKeyLines rewrites the line of each review key that exists and
// inserts the missing ones after the `version:` line (or at the end), at the
// root mapping's own indentation and with the file's line ending.
func appMCPSetReviewKeyLines(data []byte, values map[string]string) ([]byte, bool) {
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil || document.Kind != yaml.DocumentNode || len(document.Content) != 1 {
		return nil, false
	}
	root := document.Content[0]
	if root.Kind != yaml.MappingNode || root.Style&yaml.FlowStyle != 0 || len(root.Content) == 0 || root.Content[0].Column < 1 {
		return nil, false
	}
	text := string(data)
	newline := "\n"
	if strings.Contains(text, "\r\n") {
		newline = "\r\n"
	}
	lines := strings.SplitAfter(text, "\n")
	indent := strings.Repeat(" ", root.Content[0].Column-1)
	entry := func(key string) (string, bool) {
		scalar, ok := appMCPReviewScalar(values[key])
		return indent + key + ": " + scalar, ok
	}
	var missing []string
	for _, key := range appMCPReviewKeys {
		k, v := appMCPMappingValue(root, key)
		if k == nil {
			missing = append(missing, key)
			continue
		}
		// Only a one-line scalar written on the key's own line is edited in place.
		if v.Kind != yaml.ScalarNode || v.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0 || v.Line != k.Line || k.Column != root.Content[0].Column || k.Line < 1 || k.Line > len(lines) {
			return nil, false
		}
		line, ok := entry(key)
		if !ok {
			return nil, false
		}
		for _, comment := range []string{k.LineComment, v.LineComment} {
			if comment != "" {
				line += " " + comment
			}
		}
		ending := ""
		if strings.HasSuffix(lines[k.Line-1], "\n") {
			ending = newline
		}
		lines[k.Line-1] = line + ending
	}
	if len(missing) == 0 {
		return []byte(strings.Join(lines, "")), true
	}
	var inserted strings.Builder
	for _, key := range missing {
		line, ok := entry(key)
		if !ok {
			return nil, false
		}
		inserted.WriteString(line + newline)
	}
	at := len(lines) // after the last line
	if k, v := appMCPMappingValue(root, "version"); k != nil && v.Kind == yaml.ScalarNode && v.Line == k.Line && k.Line >= 1 && k.Line <= len(lines) && strings.HasSuffix(lines[k.Line-1], "\n") {
		at = k.Line
	}
	if at == len(lines) {
		// Appending: make sure the last line is terminated first.
		last := len(lines) - 1
		for last >= 0 && lines[last] == "" {
			last--
		}
		if last >= 0 && !strings.HasSuffix(lines[last], "\n") {
			lines[last] += newline
		}
	}
	out := strings.Join(lines[:at], "") + inserted.String() + strings.Join(lines[at:], "")
	return []byte(out), true
}

// appMCPSetReviewKeyNodes is the fallback: set the review keys in the node tree
// and encode it with two-space indentation (the documented style). Scalars
// keep their source text and style, so integers are never rewritten.
func appMCPSetReviewKeyNodes(data []byte, values map[string]string) ([]byte, error) {
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return nil, err
	}
	if document.Kind != yaml.DocumentNode || len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("mcp.yaml: expected one top-level mapping")
	}
	root := document.Content[0]
	for _, key := range appMCPReviewKeys {
		scalar := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: values[key]}
		if k, _ := appMCPMappingValue(root, key); k != nil {
			for i := 0; i+1 < len(root.Content); i += 2 {
				if root.Content[i] == k {
					scalar.LineComment = root.Content[i+1].LineComment
					root.Content[i+1] = scalar
				}
			}
			continue
		}
		root.Content = append(root.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, scalar)
	}
	var buffer bytes.Buffer
	encoder := yaml.NewEncoder(&buffer)
	encoder.SetIndent(2)
	if err := encoder.Encode(&document); err != nil {
		return nil, err
	}
	if err := encoder.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}
