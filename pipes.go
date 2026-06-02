//go:build !cli

package main

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// stringifyForPipe converts a pipe-input value to its string form for
// pipes that operate on strings (upper, lower, default, hmac, etc.).
//
// For scalars it's fmt.Sprintf("%v", ...) like before. For SLICES and
// MAPS it's JSON encoding — pre-2.7.35 we used Go's default reflect
// shape ("[map[id:1]]"), which is NOT valid JSON. Agents writing the
// canonical
//
//	params:
//	  hits: "${{ steps.fetch.outputs.json.hits | default:'[]' }}"
//
// got that Go-shape garbage back when the upstream value was a slice,
// then SQLite's json_each() crashed with "malformed JSON" and the
// flow halted mid-pipeline. An earlier app build burned five iterations
// dropping every `| default:'[]'` to work around it. Now: default,
// json, urlencode, base64, sha256, md5 — every pipe that operates on
// the stringified form — sees valid JSON for complex types, so the
// SQL param round-trip works.
//
// Pipes that introspect the value directly (count/length, first/last
// when given a slice) have their own type-switch paths that bypass
// this helper, so they're unaffected.
func stringifyForPipe(value any) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return v
	case []byte:
		return string(v)
	case bool, int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64,
		float32, float64, json.Number:
		return fmt.Sprintf("%v", v)
	}
	// Complex shapes (slice, map, struct) — JSON encode so the pipe
	// chain composes correctly with downstream SQL/JSON consumers.
	if b, err := json.Marshal(value); err == nil {
		return string(b)
	}
	// Best-effort fallback for things json can't encode (channels,
	// funcs — never seen in flow data but defensive). Same as the
	// pre-2.7.35 behavior for the rare unencodable case.
	return fmt.Sprintf("%v", value)
}

// ApplyPipe transforms a value through a named pipe.
func ApplyPipe(value any, pipe string) string {
	s := stringifyForPipe(value)

	// Parse pipe name and param: "truncate:80" or "default:'[]'".
	parts := strings.SplitN(pipe, ":", 2)
	name := strings.TrimSpace(parts[0])
	param := ""
	if len(parts) == 2 {
		param = strings.TrimSpace(parts[1])
		// Strip surrounding single/double quotes, matching what
		// splitPipeNameArg (flows.go) does for the missing-ref path.
		// Pre-2.7.35 the present-but-empty path returned the literal
		// quotes through (`default:'fallback'` → "'fallback'"), so a
		// flow that defaulted an EMPTY string ended up with quoted
		// junk in the SQL param. The missing-ref path stripped
		// quotes; both paths should agree.
		if len(param) >= 2 {
			if (param[0] == '\'' && param[len(param)-1] == '\'') ||
				(param[0] == '"' && param[len(param)-1] == '"') {
				param = param[1 : len(param)-1]
			}
		}
	}

	switch name {
	case "upper":
		return strings.ToUpper(s)
	case "lower":
		return strings.ToLower(s)
	case "title":
		return strings.Title(s)
	case "trim":
		return strings.TrimSpace(s)

	case "truncate":
		n := 80
		fmt.Sscanf(param, "%d", &n)
		if len(s) > n {
			return s[:n] + "..."
		}
		return s

	case "currency":
		f := toFloat(value)
		if f < 0 {
			return fmt.Sprintf("-$%s", formatNumber(math.Abs(f)))
		}
		return fmt.Sprintf("$%s", formatNumber(f))

	case "cents":
		f := toFloat(value)
		return fmt.Sprintf("%.0f", f*100)

	case "number":
		f := toFloat(value)
		return formatNumber(f)

	case "percent":
		f := toFloat(value)
		return fmt.Sprintf("%.1f%%", f)

	case "date":
		return formatDate(s, param)

	case "ago":
		return timeAgo(s)

	case "digits":
		var digits strings.Builder
		for _, c := range s {
			if c >= '0' && c <= '9' {
				digits.WriteRune(c)
			}
		}
		return digits.String()

	case "count", "length":
		// Count items in a list. Native slice / map types are handled
		// directly so flow-engine `${{ steps.X.outputs.rows | count }}`
		// works without round-tripping through fmt.Sprintf and JSON.
		// `length` is a common alias from other templating languages
		// (mustache, handlebars, jinja) — accepted so the agent's
		// muscle memory works the first time.
		switch v := value.(type) {
		case []any:
			return strconv.Itoa(len(v))
		case []map[string]any:
			return strconv.Itoa(len(v))
		case map[string]any:
			return strconv.Itoa(len(v))
		case nil:
			return "0"
		case string:
			// Fall through to the string-based logic below.
		}
		if s == "" || s == "[]" || s == "<nil>" || s == "null" {
			return "0"
		}
		if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
			var arr []any
			if err := json.Unmarshal([]byte(s), &arr); err == nil {
				return strconv.Itoa(len(arr))
			}
		}
		return strconv.Itoa(strings.Count(s, ",") + 1)

	case "md5":
		return fmt.Sprintf("%x", md5.Sum([]byte(s)))
	case "sha256":
		return fmt.Sprintf("%x", sha256.Sum256([]byte(s)))
	case "base64":
		return base64.StdEncoding.EncodeToString([]byte(s))
	case "urlencode":
		return url.QueryEscape(s)

	case "first":
		words := strings.Fields(s)
		if len(words) > 0 {
			return words[0]
		}
		return s

	case "last":
		words := strings.Fields(s)
		if len(words) > 0 {
			return words[len(words)-1]
		}
		return s

	case "initials":
		words := strings.Fields(s)
		var initials strings.Builder
		for _, w := range words {
			if len(w) > 0 {
				initials.WriteByte(w[0])
			}
		}
		return strings.ToUpper(initials.String())

	case "default":
		if s == "" || s == "<nil>" {
			return param
		}
		return s

	case "pluralize":
		f := toFloat(value)
		if f == 1 {
			return s
		}
		if param != "" {
			return param
		}
		return s + "s"

	case "json":
		// Already a string representation
		return s

	case "strip_html":
		// Simple HTML tag stripper
		var result strings.Builder
		inTag := false
		for _, c := range s {
			if c == '<' {
				inTag = true
			} else if c == '>' {
				inTag = false
			} else if !inTag {
				result.WriteRune(c)
			}
		}
		return result.String()

	case "nl2br":
		return strings.ReplaceAll(s, "\n", "<br>")

	case "slug":
		s = strings.ToLower(s)
		s = strings.Map(func(r rune) rune {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
				return r
			}
			if r == ' ' || r == '-' || r == '_' {
				return '-'
			}
			return -1
		}, s)
		// Remove double dashes
		for strings.Contains(s, "--") {
			s = strings.ReplaceAll(s, "--", "-")
		}
		return strings.Trim(s, "-")
	}

	return s
}

func toFloat(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int64:
		return float64(n)
	case int:
		return float64(n)
	case string:
		var f float64
		fmt.Sscanf(n, "%f", &f)
		return f
	default:
		var f float64
		fmt.Sscanf(fmt.Sprintf("%v", v), "%f", &f)
		return f
	}
}

func formatNumber(f float64) string {
	// Format with commas: 1234567.89 → 1,234,567.89
	isNegative := f < 0
	f = math.Abs(f)

	whole := int64(f)
	frac := f - float64(whole)

	// Format whole part with commas
	s := fmt.Sprintf("%d", whole)
	var result strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			result.WriteByte(',')
		}
		result.WriteRune(c)
	}

	// Add fractional part
	if frac > 0.001 {
		result.WriteString(fmt.Sprintf(".%02d", int(frac*100+0.5)))
	}

	if isNegative {
		return "-" + result.String()
	}
	return result.String()
}

func formatDate(s, format string) string {
	if s == "" {
		return ""
	}

	// Try common date formats (including Go's default time.String() output)
	formats := []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05 +0000 UTC",
		"2006-01-02 15:04:05+00:00",
		"2006-01-02 15:04:05",
		"2006-01-02",
	}

	var t time.Time
	var err error
	for _, f := range formats {
		t, err = time.Parse(f, s)
		if err == nil {
			break
		}
	}
	if err != nil {
		return s
	}

	if format == "" {
		format = "Jan 2, 2006"
	}

	// Convert common format strings
	format = strings.ReplaceAll(format, "YYYY", "2006")
	format = strings.ReplaceAll(format, "MM", "01")
	format = strings.ReplaceAll(format, "DD", "02")

	return t.Format(format)
}

func timeAgo(s string) string {
	if s == "" {
		return ""
	}

	formats := []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05 -0700 MST",
		"2006-01-02 15:04:05 +0000 UTC",
		"2006-01-02 15:04:05",
		"2006-01-02",
	}

	var t time.Time
	var err error
	for _, f := range formats {
		t, err = time.Parse(f, s)
		if err == nil {
			break
		}
	}
	if err != nil {
		return s
	}

	diff := time.Since(t)

	switch {
	case diff < time.Minute:
		return "just now"
	case diff < time.Hour:
		n := int(diff.Minutes())
		if n == 1 {
			return "1 minute ago"
		}
		return fmt.Sprintf("%d minutes ago", n)
	case diff < 24*time.Hour:
		n := int(diff.Hours())
		if n == 1 {
			return "1 hour ago"
		}
		return fmt.Sprintf("%d hours ago", n)
	case diff < 7*24*time.Hour:
		n := int(diff.Hours() / 24)
		if n == 1 {
			return "yesterday"
		}
		return fmt.Sprintf("%d days ago", n)
	case diff < 30*24*time.Hour:
		n := int(diff.Hours() / 24 / 7)
		if n == 1 {
			return "1 week ago"
		}
		return fmt.Sprintf("%d weeks ago", n)
	case diff < 365*24*time.Hour:
		n := int(diff.Hours() / 24 / 30)
		if n == 1 {
			return "1 month ago"
		}
		return fmt.Sprintf("%d months ago", n)
	default:
		n := int(diff.Hours() / 24 / 365)
		if n == 1 {
			return "1 year ago"
		}
		return fmt.Sprintf("%d years ago", n)
	}
}
