package main

import (
	"bytes"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

// yaml.v3 decodes a mapping by comparing every key with every later key to
// report duplicates, so decoding cost is quadratic in a mapping's width: a
// 1.7 MB app.yaml of flat `kN: v` lines takes over 20 s, and an 8 MB one (the
// MCP write limit) takes on the order of twenty minutes of one CPU core. The
// router validates tenant YAML on every write and parses deployed
// configuration, so one request could pin a core of the process every tenant
// shares. checkYAMLShape measures the decode cost in a linear pass over the
// document tree (which decodes no mappings and expands no aliases) and refuses
// input past a budget no real configuration approaches.
const (
	yamlMaxBytes = 8 << 20
	// Total pairwise key comparisons across all mappings, summed over the
	// documents. One mapping of 20,000 keys is about 2e8: roughly a second per
	// decode. Real configuration and translation files are far below this.
	yamlMaxKeyComparisons int64 = 200_000_000
)

// checkYAMLShape returns an error when data would cost too much to decode.
// Malformed YAML is not its concern: the real decode reports syntax errors,
// and parsing them is linear.
func checkYAMLShape(data []byte) error {
	if len(data) > yamlMaxBytes {
		return fmt.Errorf("yaml document is %d bytes; the limit is %d", len(data), yamlMaxBytes)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var comparisons int64
	for {
		var doc yaml.Node
		if err := dec.Decode(&doc); err != nil {
			if err == io.EOF {
				return nil
			}
			return nil
		}
		if err := yamlNodeCost(&doc, &comparisons); err != nil {
			return err
		}
	}
}

func yamlNodeCost(n *yaml.Node, comparisons *int64) error {
	if n == nil || n.Kind == yaml.AliasNode {
		return nil // an alias is not expanded here; yaml.v3 bounds alias expansion itself
	}
	if n.Kind == yaml.MappingNode {
		width := int64(len(n.Content) / 2)
		*comparisons += width * (width - 1) / 2
		if *comparisons > yamlMaxKeyComparisons {
			return fmt.Errorf("yaml is too large to process: its mappings hold too many keys (a single mapping of about 20,000 keys is the limit)")
		}
	}
	for _, c := range n.Content {
		if err := yamlNodeCost(c, comparisons); err != nil {
			return err
		}
	}
	return nil
}

// yamlUnmarshal is yaml.Unmarshal behind checkYAMLShape.
func yamlUnmarshal(data []byte, out any) error {
	if err := checkYAMLShape(data); err != nil {
		return err
	}
	return yaml.Unmarshal(data, out)
}
