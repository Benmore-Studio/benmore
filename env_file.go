//go:build !cli

package main

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

func validAppEnvKey(key string) bool {
	return validEnvCredentialName(key) && !(key[0] >= '0' && key[0] <= '9')
}

// Match EnvironmentFile's character restrictions so systemd cannot silently
// discard an assignment accepted by the runtime. See systemd.exec(5).
func validAppEnvValue(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r == 0 || r == '\uFEFF' || (r >= '\uFDD0' && r <= '\uFDEF') || r&0xffff == 0xfffe || r&0xffff == 0xffff {
			return false
		}
	}
	return true
}

// This is the generated systemd EnvironmentFile subset: unquoted single-line
// metadata and quoted values, including literal newlines and escaped backslashes.
func parseAppEnvironmentFile(data string) (map[string]string, error) {
	vars := map[string]string{}
	for len(data) > 0 {
		data = strings.TrimLeft(data, " \t\r\n")
		if data == "" {
			break
		}
		if data[0] == '#' || data[0] == ';' {
			_, data, _ = strings.Cut(data, "\n")
			continue
		}
		eq := strings.IndexByte(data, '=')
		newline := strings.IndexByte(data, '\n')
		if eq < 1 || (newline >= 0 && newline < eq) {
			return nil, fmt.Errorf("malformed environment assignment")
		}
		key := strings.TrimSpace(data[:eq])
		if !validAppEnvKey(key) {
			return nil, fmt.Errorf("invalid environment key")
		}
		data = strings.TrimLeft(data[eq+1:], " \t")
		var value string
		if len(data) > 0 && (data[0] == '"' || data[0] == '\'') {
			quote := data[0]
			data = data[1:]
			var b strings.Builder
			closed := false
			for len(data) > 0 {
				c := data[0]
				data = data[1:]
				if c == quote {
					closed = true
					break
				}
				if quote == '"' && c == '\\' && len(data) > 0 {
					next := data[0]
					if next == '\n' {
						data = data[1:]
						continue
					}
					if next == '"' || next == '\\' || next == '$' || next == '`' {
						c = next
						data = data[1:]
					}
				}
				b.WriteByte(c)
			}
			if !closed {
				return nil, fmt.Errorf("unterminated environment value")
			}
			tail, rest, _ := strings.Cut(data, "\n")
			if strings.TrimSpace(tail) != "" {
				return nil, fmt.Errorf("unexpected text after environment value")
			}
			data = rest
			value = b.String()
		} else {
			var line string
			line, data, _ = strings.Cut(data, "\n")
			value = strings.TrimSpace(line)
		}
		if !validAppEnvValue(value) {
			return nil, fmt.Errorf("invalid environment value")
		}
		vars[key] = value
	}
	return vars, nil
}

func quoteAppEnvValue(value string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, `$`, `\$`, "`", "\\`").Replace(value) + `"`
}
