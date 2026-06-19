//go:build !cli

package main

// Expression evaluator + pipe library for sign recipes.
//
// Templates are strings with `{{ ... }}` substitutions. Inside the
// braces, syntax is `<name>[ | pipe[:arg]]*` where:
//
//   <name>     is a bare identifier (env.AWS_KEY, body, k_date, …) OR
//              a quoted string literal ('aws4_request' or "literal")
//   pipe       is one of the registered pipe names
//   :arg       optional pipe argument - quoted string literal OR
//              bare identifier (resolved as a variable lookup)
//
// Pipes chain left-to-right. The result of one pipe is the input to
// the next. Pipe outputs may be raw bytes (HMAC, SHA produce 32-byte
// strings); use `| hex` or `| base64` to convert before emitting on
// the wire.
//
// Multiple `{{...}}` blocks may appear in a single template string;
// literal text between them is preserved verbatim.

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// evalTemplate renders a template string against the recipe env.
// Returns the rendered string (possibly containing raw bytes if the
// last pipe was a hash/hmac with no encoding pipe).
//
// Brace tracking is depth-aware: a literal containing {{x}} inside an
// outer {{ ... }} expression's quoted arg works, because we count
// opening {{ to find the matching closing }}.
func evalTemplate(tmpl string, env *recipeEnv) (string, error) {
	var out strings.Builder
	i := 0
	for i < len(tmpl) {
		j := strings.Index(tmpl[i:], "{{")
		if j < 0 {
			out.WriteString(tmpl[i:])
			break
		}
		out.WriteString(tmpl[i : i+j])
		i += j + 2 // past opening {{

		// Find matching }} accounting for nested {{ inside quoted literals.
		depth := 1
		endRel := -1
		k := 0
		for k < len(tmpl)-i-1 {
			c0 := tmpl[i+k]
			c1 := tmpl[i+k+1]
			if c0 == '{' && c1 == '{' {
				depth++
				k += 2
				continue
			}
			if c0 == '}' && c1 == '}' {
				depth--
				if depth == 0 {
					endRel = k
					break
				}
				k += 2
				continue
			}
			k++
		}
		if endRel < 0 {
			return "", fmt.Errorf("unterminated {{ in template")
		}
		expr := strings.TrimSpace(tmpl[i : i+endRel])
		i += endRel + 2 // past closing }}

		val, err := evalExpr(expr, env)
		if err != nil {
			return "", fmt.Errorf("{{ %s }}: %w", expr, err)
		}
		out.WriteString(val)
	}
	return out.String(), nil
}

// evalExpr evaluates a pipe chain: `name | pipe | pipe:arg | ...`.
// Resolves the first token to a value, then threads through pipes.
func evalExpr(expr string, env *recipeEnv) (string, error) {
	parts := splitPipes(expr)
	if len(parts) == 0 {
		return "", fmt.Errorf("empty expression")
	}

	// First token: bare identifier OR string literal.
	val, err := resolveOperand(parts[0], env)
	if err != nil {
		return "", err
	}

	for _, p := range parts[1:] {
		name, arg, hasArg := splitPipeArg(p)
		pipe, ok := pipes[name]
		if !ok {
			return "", fmt.Errorf("unknown pipe: %s (known: %s)", name, strings.Join(knownPipes(), ", "))
		}
		var argVal string
		if hasArg {
			argVal, err = resolveOperand(arg, env)
			if err != nil {
				return "", fmt.Errorf("pipe %s arg: %w", name, err)
			}
		}
		val, err = pipe(val, argVal, hasArg)
		if err != nil {
			return "", fmt.Errorf("pipe %s: %w", name, err)
		}
	}
	return val, nil
}

// resolveOperand handles "name" (variable lookup) or "'quoted'" (literal).
// A quoted literal can also contain {{...}} substitutions itself - that
// lets users write `hmac_sha256:'{{ts}}.{{body}}'` to combine vars into
// the pipe arg.
func resolveOperand(tok string, env *recipeEnv) (string, error) {
	tok = strings.TrimSpace(tok)
	if tok == "" {
		return "", fmt.Errorf("empty operand")
	}
	if (strings.HasPrefix(tok, "'") && strings.HasSuffix(tok, "'")) ||
		(strings.HasPrefix(tok, `"`) && strings.HasSuffix(tok, `"`)) {
		literal := tok[1 : len(tok)-1]
		// Literals can themselves contain {{...}} for inline concatenation.
		if strings.Contains(literal, "{{") {
			return evalTemplate(literal, env)
		}
		return literal, nil
	}
	return env.resolve(tok)
}

// splitPipes splits `a | b:c | d` into ["a", "b:c", "d"], respecting
// quoted strings so a literal pipe character inside quotes doesn't
// confuse the split.
func splitPipes(expr string) []string {
	var parts []string
	var cur strings.Builder
	inQuote := byte(0)
	for i := 0; i < len(expr); i++ {
		c := expr[i]
		if inQuote != 0 {
			cur.WriteByte(c)
			if c == inQuote {
				inQuote = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			inQuote = c
			cur.WriteByte(c)
			continue
		}
		if c == '|' {
			parts = append(parts, strings.TrimSpace(cur.String()))
			cur.Reset()
			continue
		}
		cur.WriteByte(c)
	}
	if cur.Len() > 0 {
		parts = append(parts, strings.TrimSpace(cur.String()))
	}
	return parts
}

// splitPipeArg splits "name:arg" - respecting quoted strings so a
// colon inside a literal doesn't terminate the pipe name.
func splitPipeArg(p string) (name, arg string, hasArg bool) {
	inQuote := byte(0)
	for i := 0; i < len(p); i++ {
		c := p[i]
		if inQuote != 0 {
			if c == inQuote {
				inQuote = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			inQuote = c
			continue
		}
		if c == ':' {
			return strings.TrimSpace(p[:i]), strings.TrimSpace(p[i+1:]), true
		}
	}
	return strings.TrimSpace(p), "", false
}

// --- pipe library ---

type pipeFn func(input, arg string, hasArg bool) (string, error)

var pipes = map[string]pipeFn{
	"hmac_sha256": pipeHMAC(sha256.New),
	"hmac_sha512": pipeHMAC(sha512.New),
	"hmac_sha1":   pipeHMAC(sha1.New),
	"sha256":      pipeHash(sha256.New),
	"sha512":      pipeHash(sha512.New),
	"sha1":        pipeHash(sha1.New),
	"md5":         pipeHash(md5.New),
	"hex":         pipeHex,
	"base64":      pipeBase64,
	"base64url":   pipeBase64URL,
	"fmt":         pipeFmtTime,
	"unix":        pipeUnix,
	"unix_milli":  pipeUnixMilli,
	"prepend":     pipePrepend,
	"append":      pipeAppend,
	"lower":       pipeLower,
	"upper":       pipeUpper,
	"default":     pipeDefault,
	"or_env":      pipeOrEnv,
	"urlencode":   pipeURLEncode,
	"pct_encode":  pipePctEncode,
	"json_path":   pipeJSONPathStr,
	"sort_query":  pipeSortQuery,
	"length":      pipeLength,
	"required":    pipeRequired,
}

func knownPipes() []string {
	out := make([]string, 0, len(pipes))
	for k := range pipes {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func pipeHMAC(newHash func() hash.Hash) pipeFn {
	return func(key, msg string, hasArg bool) (string, error) {
		if !hasArg {
			return "", fmt.Errorf("hmac needs a message arg")
		}
		h := hmac.New(newHash, []byte(key))
		h.Write([]byte(msg))
		return string(h.Sum(nil)), nil
	}
}

func pipeHash(newHash func() hash.Hash) pipeFn {
	return func(input, _ string, _ bool) (string, error) {
		h := newHash()
		h.Write([]byte(input))
		return string(h.Sum(nil)), nil
	}
}

func pipeHex(input, _ string, _ bool) (string, error) {
	return hex.EncodeToString([]byte(input)), nil
}

func pipeBase64(input, _ string, _ bool) (string, error) {
	return base64.StdEncoding.EncodeToString([]byte(input)), nil
}

func pipeBase64URL(input, _ string, _ bool) (string, error) {
	return base64.RawURLEncoding.EncodeToString([]byte(input)), nil
}

// pipeFmtTime: input is nanos-since-epoch (decimal). arg is a Go layout.
// Produces a UTC-formatted string. The {{ now }} variable yields a value
// in nanos by convention, so the typical use is `{{ now | fmt:'20060102' }}`.
func pipeFmtTime(input, layout string, hasArg bool) (string, error) {
	if !hasArg {
		return "", fmt.Errorf("fmt needs a layout arg")
	}
	n, err := strconv.ParseInt(input, 10, 64)
	if err != nil {
		return "", fmt.Errorf("fmt: input must be unix nanos, got %q", input)
	}
	return time.Unix(0, n).UTC().Format(layout), nil
}

func pipeUnix(input, _ string, _ bool) (string, error) {
	n, err := strconv.ParseInt(input, 10, 64)
	if err != nil {
		return "", fmt.Errorf("unix: input must be nanos, got %q", input)
	}
	return strconv.FormatInt(n/int64(time.Second), 10), nil
}

func pipeUnixMilli(input, _ string, _ bool) (string, error) {
	n, err := strconv.ParseInt(input, 10, 64)
	if err != nil {
		return "", fmt.Errorf("unix_milli: input must be nanos, got %q", input)
	}
	return strconv.FormatInt(n/int64(time.Millisecond), 10), nil
}

func pipePrepend(input, prefix string, hasArg bool) (string, error) {
	if !hasArg {
		return "", fmt.Errorf("prepend needs an arg")
	}
	return prefix + input, nil
}

func pipeAppend(input, suffix string, hasArg bool) (string, error) {
	if !hasArg {
		return "", fmt.Errorf("append needs an arg")
	}
	return input + suffix, nil
}

func pipeLower(input, _ string, _ bool) (string, error) {
	return strings.ToLower(input), nil
}

func pipeUpper(input, _ string, _ bool) (string, error) {
	return strings.ToUpper(input), nil
}

func pipeDefault(input, fallback string, hasArg bool) (string, error) {
	if !hasArg {
		return "", fmt.Errorf("default needs an arg")
	}
	if input == "" {
		return fallback, nil
	}
	return input, nil
}

// pipeOrEnv returns input if non-empty, else looks up an env var by name.
// Useful in recipes that want to accept a value as a sign-block param
// but fall back to a conventional env var when the caller hasn't passed
// one. Example: `{{ params.secret | or_env:WEBHOOK_SECRET }}`.
func pipeOrEnv(input, envName string, hasArg bool) (string, error) {
	if input != "" {
		return input, nil
	}
	if !hasArg {
		return "", fmt.Errorf("or_env needs an env var name arg")
	}
	return os.Getenv(envName), nil
}

func pipeURLEncode(input, _ string, _ bool) (string, error) {
	return url.QueryEscape(input), nil
}

// pipePctEncode: RFC3986 strict (only A-Za-z0-9-_.~ unreserved). What
// AWS sigv4 expects for query string canonicalization.
func pipePctEncode(input, _ string, _ bool) (string, error) {
	var b strings.Builder
	for i := 0; i < len(input); i++ {
		c := input[i]
		switch {
		case (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'):
			b.WriteByte(c)
		case c == '-' || c == '_' || c == '.' || c == '~':
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String(), nil
}

func pipeJSONPathStr(input, path string, hasArg bool) (string, error) {
	if !hasArg {
		return "", fmt.Errorf("json_path needs a path arg")
	}
	return evalJSONPathBytes([]byte(input), path)
}

// pipeSortQuery: sort a raw query string by key (and within key by value),
// re-emit each k=v separately encoded per RFC3986 strict. Used by sigv4
// recipes that need a canonical query string.
func pipeSortQuery(input, _ string, _ bool) (string, error) {
	if input == "" {
		return "", nil
	}
	q, err := url.ParseQuery(input)
	if err != nil {
		return "", err
	}
	if len(q) == 0 {
		return "", nil
	}
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		vals := append([]string(nil), q[k]...)
		sort.Strings(vals)
		ek, _ := pipePctEncode(k, "", false)
		for _, v := range vals {
			ev, _ := pipePctEncode(v, "", false)
			parts = append(parts, ek+"="+ev)
		}
	}
	return strings.Join(parts, "&"), nil
}

func pipeLength(input, _ string, _ bool) (string, error) {
	return strconv.Itoa(len(input)), nil
}

// pipeRequired surfaces a clear error if the piped value is empty - used
// to validate that env vars / params the recipe depends on were actually
// set. Without this, a missing AWS_SECRET_ACCESS_KEY produces a bogus
// signature and a confusing 403 from the upstream API.
func pipeRequired(input, msg string, hasArg bool) (string, error) {
	if input == "" {
		if hasArg && msg != "" {
			return "", fmt.Errorf("required: %s", msg)
		}
		return "", fmt.Errorf("required value missing")
	}
	return input, nil
}
