//go:build !cli

package main

// Recipe interpreter for outbound HTTP signing.
//
// A Recipe is a declarative description of how to sign / authenticate
// an outbound HTTP request. It has three optional sections:
//
//   before:  HTTP token-exchange step (with caching by cache_key)
//   compute: ordered list of derived bindings using a template +
//            pipe language (hmac_sha256, sha256, hex, base64, …)
//   headers: header_name -> template-rendered value
//   query:   query_param -> template-rendered value
//
// The engine renders templates against a Variables map populated with:
//   - request inputs: method, host, path, query, body, url
//   - now           : current time as nanos since epoch (sentinel)
//   - env.<NAME>    : value via app's GetEnv (env.yaml / systemd creds)
//   - params.<KEY>  : initial bindings passed in by the caller
//   - any binding declared earlier in compute:
//   - any binding extracted by before: token-exchange
//
// All values flow as Go strings. HMAC/SHA pipes return raw bytes
// (Go strings can hold arbitrary bytes - UTF-8 is not required).
// Use `| hex` or `| base64` to convert raw bytes to a printable form
// before placing them in a header.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Recipe is the AST-level form. Constructed either from a YAML inline
// `sign:` block or from a named built-in recipe definition.
type Recipe struct {
	Before  *RecipeBefore
	Compute []RecipeBinding // ordered
	Headers []RecipeBinding // ordered (rare to matter, but kept for determinism)
	Query   []RecipeBinding
}

type RecipeBinding struct {
	Name string
	Expr string
}

// RecipeBefore is the optional token-exchange pre-step. Results land
// in the binding map under the names given in Extract before any of
// compute:/headers:/query: are evaluated. CacheKey is itself a
// template - typically references env vars or params - and dedupes
// concurrent flow runs that want the same token.
type RecipeBefore struct {
	CacheKey string
	Request  *RecipeBeforeRequest
	Extract  []RecipeBinding // ordered; one of the extracted vars is conventionally `ttl` (in seconds)
}

type RecipeBeforeRequest struct {
	Method  string
	URL     string
	Headers map[string]string
	Form    map[string]string
	JSON    map[string]string
	Body    string
}

// recipeEnv is the evaluation context - the bag of bindings the
// expression engine resolves names against. It carries the request
// itself for special-variable lookup (method, host, path, …).
type recipeEnv struct {
	req     *http.Request
	body    []byte
	vars    map[string]string
	app     *App
	nowNano int64 // 0 = use time.Now(); >0 = injected for tests
}

func newRecipeEnv(req *http.Request, body []byte, initial map[string]string, app *App) *recipeEnv {
	vars := make(map[string]string, len(initial))
	for k, v := range initial {
		vars["params."+k] = v
	}
	e := &recipeEnv{req: req, body: body, vars: vars, app: app}
	if tt := initial["_now"]; tt != "" {
		// _now is a hidden binding used by tests. Accept either RFC3339,
		// a Unix nanos integer, or the AWS basic-ISO8601 format.
		if t, err := time.Parse(time.RFC3339, tt); err == nil {
			e.nowNano = t.UnixNano()
		} else if t, err := time.Parse("20060102T150405Z", tt); err == nil {
			e.nowNano = t.UnixNano()
		} else if n, err := strconv.ParseInt(tt, 10, 64); err == nil {
			e.nowNano = n
		}
	}
	return e
}

// resolve looks up a single name (no pipes, no quoted literal). Handles
// dotted prefixes (env.X, params.X), special request vars, and `now`.
func (e *recipeEnv) resolve(name string) (string, error) {
	if dot := strings.Index(name, "."); dot >= 0 {
		prefix, rest := name[:dot], name[dot+1:]
		switch prefix {
		case "env":
			dir := ""
			if e.app != nil {
				dir = e.app.Dir
			}
			return GetEnv(dir, rest), nil
		case "params":
			return e.vars["params."+rest], nil
		case "url":
			switch rest {
			case "host":
				return e.requestHost(), nil
			case "path":
				p := e.req.URL.EscapedPath()
				if p == "" {
					p = "/"
				}
				return p, nil
			case "query":
				return e.req.URL.RawQuery, nil
			case "scheme":
				return e.req.URL.Scheme, nil
			}
		}
		// fall through; might be a compute binding with a literal dot in its name
	}

	// Reserved request vars (no prefix).
	switch name {
	case "method":
		return e.req.Method, nil
	case "host":
		return e.requestHost(), nil
	case "path":
		p := e.req.URL.EscapedPath()
		if p == "" {
			p = "/"
		}
		return p, nil
	case "query":
		return e.req.URL.RawQuery, nil
	case "body":
		return string(e.body), nil
	case "now":
		if e.nowNano > 0 {
			return strconv.FormatInt(e.nowNano, 10), nil
		}
		return strconv.FormatInt(time.Now().UTC().UnixNano(), 10), nil
	}

	v, ok := e.vars[name]
	if !ok {
		return "", fmt.Errorf("undefined: %s", name)
	}
	return v, nil
}

func (e *recipeEnv) requestHost() string {
	if e.req.Host != "" {
		return e.req.Host
	}
	return e.req.URL.Host
}

// runSignRecipe is the entry point. Looks up the named recipe (if any),
// merges built-in compute/headers/query with caller-provided bindings,
// runs through before/compute/headers/query.
func runSignRecipe(req *http.Request, body []byte, sign *FlowAPISign, app *App) error {
	var recipe *Recipe
	if sign.Recipe != "" {
		r, ok := lookupBuiltinRecipe(sign.Recipe)
		if !ok {
			return fmt.Errorf("sign: unknown recipe %q (known: %s)", sign.Recipe,
				strings.Join(builtinRecipeNames(), ", "))
		}
		recipe = r
	} else if sign.Inline != nil {
		recipe = sign.Inline
	} else {
		return fmt.Errorf("sign: must specify recipe: <name> or inline compute:/headers:")
	}

	env := newRecipeEnv(req, body, sign.Bindings, app)

	if recipe.Before != nil {
		if err := execRecipeBefore(env, recipe.Before); err != nil {
			return fmt.Errorf("sign before: %w", err)
		}
	}

	for _, b := range recipe.Compute {
		v, err := evalTemplate(b.Expr, env)
		if err != nil {
			return fmt.Errorf("sign compute %s: %w", b.Name, err)
		}
		env.vars[b.Name] = v
	}

	for _, h := range recipe.Headers {
		v, err := evalTemplate(h.Expr, env)
		if err != nil {
			return fmt.Errorf("sign header %s: %w", h.Name, err)
		}
		// Header NAME can itself be a template (e.g. "{{hdr}}") so the
		// built-in recipes can let the caller pick the header name via
		// params. Skip the interpolation overhead when the literal name
		// has no `{{` - the common case.
		name := h.Name
		if strings.Contains(name, "{{") {
			n, err := evalTemplate(name, env)
			if err != nil {
				return fmt.Errorf("sign header name %s: %w", h.Name, err)
			}
			name = n
		}
		req.Header.Set(name, v)
	}

	if len(recipe.Query) > 0 {
		q := req.URL.Query()
		for _, p := range recipe.Query {
			v, err := evalTemplate(p.Expr, env)
			if err != nil {
				return fmt.Errorf("sign query %s: %w", p.Name, err)
			}
			name := p.Name
			if strings.Contains(name, "{{") {
				n, err := evalTemplate(name, env)
				if err != nil {
					return fmt.Errorf("sign query name %s: %w", p.Name, err)
				}
				name = n
			}
			q.Set(name, v)
		}
		req.URL.RawQuery = q.Encode()
	}

	return nil
}

// --- before: token-exchange with cache ---

type cachedToken struct {
	bindings map[string]string
	expires  time.Time
}

var (
	tokenCacheMu sync.RWMutex
	tokenCache   = map[string]cachedToken{}
)

func execRecipeBefore(env *recipeEnv, before *RecipeBefore) error {
	cacheKey, err := evalTemplate(before.CacheKey, env)
	if err != nil {
		return fmt.Errorf("cache_key: %w", err)
	}

	if cacheKey != "" {
		tokenCacheMu.RLock()
		entry, ok := tokenCache[cacheKey]
		tokenCacheMu.RUnlock()
		if ok && time.Now().Before(entry.expires) {
			for k, v := range entry.bindings {
				env.vars[k] = v
			}
			return nil
		}
	}

	// Build + send the exchange request.
	resp, err := doRecipeBeforeRequest(env, before.Request)
	if err != nil {
		return err
	}

	// Extract bindings via JSON-path expressions over the response body.
	var responseJSON any
	if err := json.Unmarshal(resp, &responseJSON); err != nil {
		// not JSON - extracts will fail; surface what we got.
		return fmt.Errorf("before: response not JSON: %s", truncString(string(resp), 200))
	}

	newBindings := map[string]string{}
	ttlSeconds := int64(300) // default 5 min if no `ttl` extract provided
	for _, b := range before.Extract {
		// Each Expr is a JSON-path expression like "$.access_token". Run it.
		val, err := evalJSONPath(b.Expr, responseJSON)
		if err != nil {
			return fmt.Errorf("extract %s: %w", b.Name, err)
		}
		newBindings[b.Name] = val
		env.vars[b.Name] = val
		if b.Name == "ttl" {
			if n, err := strconv.ParseInt(val, 10, 64); err == nil {
				ttlSeconds = n
			}
		}
	}

	if cacheKey != "" {
		// Reserve 30s buffer before claimed expiry to avoid using
		// almost-expired tokens.
		buffered := ttlSeconds - 30
		if buffered < 10 {
			buffered = ttlSeconds
		}
		tokenCacheMu.Lock()
		tokenCache[cacheKey] = cachedToken{
			bindings: newBindings,
			expires:  time.Now().Add(time.Duration(buffered) * time.Second),
		}
		tokenCacheMu.Unlock()
	}
	return nil
}

func doRecipeBeforeRequest(env *recipeEnv, r *RecipeBeforeRequest) ([]byte, error) {
	if r == nil {
		return nil, fmt.Errorf("before: missing request:")
	}

	urlStr, err := evalTemplate(r.URL, env)
	if err != nil {
		return nil, fmt.Errorf("url: %w", err)
	}
	// Intentionally no isPrivateURL guard here: token-exchange URLs are
	// developer-controlled in flows.yaml (not attacker input), and
	// legitimate use cases include internal/on-prem OAuth servers on
	// RFC1918 IPs. The outer `run: api` URL still gets SSRF-checked.

	method := r.Method
	if method == "" {
		method = "POST"
	}

	var body io.Reader
	contentType := ""
	switch {
	case r.Form != nil:
		var parts []string
		for k, v := range r.Form {
			rendered, err := evalTemplate(v, env)
			if err != nil {
				return nil, fmt.Errorf("form %s: %w", k, err)
			}
			parts = append(parts, k+"="+urlEncode(rendered))
		}
		body = strings.NewReader(strings.Join(parts, "&"))
		contentType = "application/x-www-form-urlencoded"
	case r.JSON != nil:
		obj := map[string]string{}
		for k, v := range r.JSON {
			rendered, err := evalTemplate(v, env)
			if err != nil {
				return nil, fmt.Errorf("json %s: %w", k, err)
			}
			obj[k] = rendered
		}
		raw, _ := json.Marshal(obj)
		body = bytes.NewReader(raw)
		contentType = "application/json"
	case r.Body != "":
		rendered, err := evalTemplate(r.Body, env)
		if err != nil {
			return nil, err
		}
		body = strings.NewReader(rendered)
	}

	req, err := http.NewRequest(method, urlStr, body)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for k, v := range r.Headers {
		rendered, err := evalTemplate(v, env)
		if err != nil {
			return nil, fmt.Errorf("header %s: %w", k, err)
		}
		req.Header.Set(k, rendered)
	}

	client := safeHTTPClient(15 * time.Second)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("token exchange %s returned %d: %s", urlStr, resp.StatusCode,
			truncString(string(respBody), 200))
	}
	return respBody, nil
}

// urlEncode is the standard percent-encoding for form bodies (space → +).
func urlEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'):
			b.WriteByte(c)
		case c == '-' || c == '_' || c == '.' || c == '~':
			b.WriteByte(c)
		case c == ' ':
			b.WriteByte('+')
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func truncString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
