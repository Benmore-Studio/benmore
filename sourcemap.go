//go:build !cli

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
)

type rawSourceMap struct {
	Version        int      `json:"version"`
	File           string   `json:"file"`
	Sources        []string `json:"sources"`
	SourcesContent []string `json:"sourcesContent"`
	Names          []string `json:"names"`
	Mappings       string   `json:"mappings"`
}

type resolvedLoc struct {
	Source       string
	Line, Column int
	Name         string
	sourceIndex  int
}

// Source and name deltas span lines; generated-column deltas reset each line.
// A one-field segment explicitly ends the previous mapped span.
func lookupSourceMap(sm *rawSourceMap, line, col int) (resolvedLoc, bool) {
	if line < 1 || col < 1 {
		return resolvedLoc{}, false
	}
	var src, srcLine, srcCol, name int
	for row, mapping := range strings.Split(sm.Mappings, ";") {
		if row+1 > line {
			break
		}
		var generated int
		var best resolvedLoc
		found := false
		for _, segment := range strings.Split(mapping, ",") {
			if segment == "" {
				continue
			}
			v, err := vlqDecode(segment)
			if err != nil || (len(v) != 1 && len(v) != 4 && len(v) != 5) {
				return resolvedLoc{}, false
			}
			generated += v[0]
			if row+1 == line && generated > col-1 {
				break
			}
			if len(v) == 1 {
				if row+1 == line {
					found = false
				}
				continue
			}
			src += v[1]
			srcLine += v[2]
			srcCol += v[3]
			if len(v) == 5 {
				name += v[4]
			}
			if row+1 == line {
				found = src >= 0 && src < len(sm.Sources) && srcLine >= 0 && srcCol >= 0
				if found {
					best = resolvedLoc{Source: sm.Sources[src], Line: srcLine + 1, Column: srcCol + 1, sourceIndex: src}
					if len(v) == 5 && name >= 0 && name < len(sm.Names) {
						best.Name = sm.Names[name]
					}
				}
			}
		}
		if row+1 == line {
			return best, found
		}
	}
	return resolvedLoc{}, false
}

func decodeSourceMapPos(data []byte, line, col int) (string, int, int, string, error) {
	var sm rawSourceMap
	if err := json.Unmarshal(data, &sm); err != nil {
		return "", 0, 0, "", fmt.Errorf("invalid sourcemap JSON: %w", err)
	}
	loc, ok := lookupSourceMap(&sm, line, col)
	if !ok {
		return "", 0, 0, "", fmt.Errorf("no mapping found at line %d col %d", line, col)
	}
	return loc.Source, loc.Line, loc.Column, loc.Name, nil
}

func vlqDecode(s string) ([]int, error) {
	var out []int
	value, shift := 0, uint(0)
	for i := 0; i < len(s); i++ {
		digit, ok := base64CharToInt(s[i])
		if !ok || shift > 30 {
			return nil, fmt.Errorf("invalid sourcemap VLQ")
		}
		value |= (digit & 31) << shift
		if digit&32 != 0 {
			shift += 5
			continue
		}
		n := value >> 1
		if value&1 != 0 {
			n = -n
		}
		out = append(out, n)
		value, shift = 0, 0
	}
	if shift != 0 {
		return nil, fmt.Errorf("incomplete sourcemap VLQ")
	}
	return out, nil
}

func base64CharToInt(c byte) (int, bool) {
	switch {
	case c >= 'A' && c <= 'Z':
		return int(c - 'A'), true
	case c >= 'a' && c <= 'z':
		return int(c-'a') + 26, true
	case c >= '0' && c <= '9':
		return int(c-'0') + 52, true
	case c == '+':
		return 62, true
	case c == '/':
		return 63, true
	}
	return 0, false
}

func inlineSourceMap(bundle []byte) ([]byte, bool) {
	if len(bundle) > 16<<20 {
		return nil, false
	}
	const marker = "//# sourceMappingURL=data:application/json;base64,"
	i := bytes.LastIndex(bundle, []byte(marker))
	if i < 0 {
		return nil, false
	}
	encoded := bundle[i+len(marker):]
	if end := bytes.IndexByte(encoded, '\n'); end >= 0 {
		encoded = encoded[:end]
	}
	data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	return data, err == nil
}

type errorSourceMapEntry struct {
	path, version string
	sm            *rawSourceMap
}
type errorSourceMapCache struct {
	mu      sync.Mutex
	entries []errorSourceMapEntry
}

func (c *errorSourceMapCache) get(path, version string, bundle []byte) *rawSourceMap {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, e := range c.entries {
		if e.path == path && e.version == version {
			copy(c.entries[1:i+1], c.entries[:i])
			c.entries[0] = e
			return e.sm
		}
	}
	data, ok := inlineSourceMap(bundle)
	if !ok {
		return nil
	}
	var sm rawSourceMap
	if json.Unmarshal(data, &sm) != nil || sm.Version != 3 {
		return nil
	}
	c.entries = append([]errorSourceMapEntry{{path, version, &sm}}, c.entries...)
	if len(c.entries) > 4 {
		c.entries = c.entries[:4]
	}
	return &sm
}

// symbolicatedFramesMax bounds the in-app frames one report maps.
const symbolicatedFramesMax = 10

func symbolicateFrames(app *App, frames []errorFrame) ([]errorFrame, bool) {
	out := append([]errorFrame(nil), frames...)
	stale := false
	if app == nil {
		return out, stale
	}
	var sc *exportScrubber
	// A report names at most 50 frames, any of them chosen by the sender:
	// resolve at most 10, and each bundle once per report.
	type cachedBundle struct {
		path, version string
		bundle        []byte
	}
	bundles := map[string]cachedBundle{}
	mapped := 0
	for i, frame := range out {
		if !frame.InApp || !strings.HasPrefix(frame.Filename, "/static/") || mapped == symbolicatedFramesMax {
			continue
		}
		mapped++
		b, seen := bundles[frame.Filename]
		if !seen {
			if b.path = resolveTSXSource(app.Dir, strings.TrimPrefix(frame.Filename, "/static/")); b.path != "" {
				var ok bool
				if b.bundle, b.version, ok = tsxCachedBundle(b.path); !ok {
					b.path = ""
				}
			}
			bundles[frame.Filename] = b
		}
		if b.path == "" {
			continue
		}
		entryPath, bundle, version := b.path, b.bundle, b.version
		if frame.Version != version {
			stale = true
			continue
		}
		sm := app.errorSourceMaps.get(entryPath, version, bundle)
		if sm == nil {
			continue
		}
		loc, ok := lookupSourceMap(sm, frame.Line, frame.Col)
		if !ok {
			continue
		}
		frame.Filename = filepath.ToSlash(loc.Source)
		frame.Line, frame.Col = loc.Line, loc.Column
		if loc.Name != "" {
			frame.Function = loc.Name
		}
		if loc.sourceIndex < len(sm.SourcesContent) {
			lines := strings.Split(sm.SourcesContent[loc.sourceIndex], "\n")
			if loc.Line <= len(lines) {
				if sc == nil {
					sc = newExportScrubber(app)
				}
				frame.ContextLine = truncateRunes(sc.scrub(lines[loc.Line-1]), 200)
				for j := max(0, loc.Line-6); j < loc.Line-1; j++ {
					frame.PreContext = append(frame.PreContext, truncateRunes(sc.scrub(lines[j]), 200))
				}
				for j := loc.Line; j < min(len(lines), loc.Line+5); j++ {
					frame.PostContext = append(frame.PostContext, truncateRunes(sc.scrub(lines[j]), 200))
				}
			}
		}
		out[i] = frame
	}
	return out, stale
}
