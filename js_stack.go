//go:build !cli

package main

import (
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
)

type errorFrame struct {
	Filename    string   `json:"filename,omitempty"`
	AbsPath     string   `json:"abs_path,omitempty"`
	Function    string   `json:"function,omitempty"`
	Line        int      `json:"lineno,omitempty"`
	Col         int      `json:"colno,omitempty"`
	InApp       bool     `json:"in_app"`
	Version     string   `json:"-"`
	PreContext  []string `json:"pre_context,omitempty"`
	ContextLine string   `json:"context_line,omitempty"`
	PostContext []string `json:"post_context,omitempty"`
}

var jsStackPositionRE = regexp.MustCompile(`^(.*):([0-9]+):([0-9]+)$`)
var jsBundleVersionRE = regexp.MustCompile(`^[A-Za-z0-9]{1,32}$`)

// host is the request's host, never the visitor-supplied page URL. The optional
// form lets diagnostics parse frames without asserting any foreign host is ours.
func parseJSStack(stack string, host ...string) []errorFrame {
	ownHost := ""
	if len(host) != 0 {
		ownHost = host[0]
	}
	var frames []errorFrame
	for _, line := range strings.Split(stack, "\n") {
		if len(frames) == 50 {
			break
		}
		line = strings.TrimSpace(line)
		if strings.Contains(line, "eval at ") || strings.Contains(line, " eval ") {
			continue
		}
		fn, location := "", ""
		if strings.HasPrefix(line, "at ") {
			location = strings.TrimPrefix(line, "at ")
			if i := strings.LastIndex(location, " ("); i >= 0 && strings.HasSuffix(location, ")") {
				fn, location = location[:i], location[i+2:len(location)-1]
			}
			fn = strings.TrimPrefix(fn, "async ")
		} else if i := strings.IndexByte(line, '@'); i >= 0 {
			fn, location = line[:i], line[i+1:]
		} else {
			continue
		}
		m := jsStackPositionRE.FindStringSubmatch(location)
		if m == nil {
			continue
		}
		u, err := url.Parse(m[1])
		if err != nil || (u.Scheme != "" && u.Scheme != "https" && u.Scheme != "http") {
			continue
		}
		lineNo, e1 := strconv.Atoi(m[2])
		col, e2 := strconv.Atoi(m[3])
		if e1 != nil || e2 != nil || lineNo < 1 || col < 1 {
			continue
		}
		v := u.Query().Get("v")
		if !jsBundleVersionRE.MatchString(v) {
			v = ""
		}
		// Bounded before anything maps or scrubs them: a stack line is
		// whatever the anonymous caller sent.
		frames = append(frames, errorFrame{Filename: truncateRunes(path.Clean(u.Path), 300), AbsPath: truncateRunes(clientErrorLocation(m[1]), 500), Function: truncateRunes(fn, 200),
			Line: lineNo, Col: col, Version: v, InApp: strings.HasPrefix(path.Clean(u.Path), "/static/") && (u.Host == "" || strings.EqualFold(u.Host, ownHost))})
	}
	for i, j := 0, len(frames)-1; i < j; i, j = i+1, j-1 {
		frames[i], frames[j] = frames[j], frames[i]
	}
	return frames
}
