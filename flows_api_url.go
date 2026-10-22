//go:build !cli

package main

// Outbound URL templating for `run: api` and `run: webhook`.
//
// interpolateCtx writes a substituted value verbatim, which is right for a
// respond body but wrong inside a URL: a request value `../admin/keys?x=`
// in `https://api.example.com/v1/customers/{{id}}` would reach another
// endpoint carrying the app's credentials. interpolateURLCtx resolves the
// same `:param` and `{{ref}}` syntax in one pass, but encodes each value for
// the part of the URL it lands in:
//
//   - path: url.PathEscape, so `/`, `?` and `#` become data; a value that is
//     only dots (`.`, `..`) is refused, since it would still be a
//     traversal segment after escaping.
//   - query and fragment: url.QueryEscape.
//   - a `{{x | urlencode}}` value is already query-escaped (no / ? # & =),
//     so it is written as is in the path, query and fragment.
//   - scheme/host (before the first path `/`, `?` or `#`): only host
//     characters are accepted, so a value can't add userinfo, a path or a
//     query to the host it sits in.
//
// Two placements stay verbatim because the author made the value the URL:
// a `{{env.X}}` reference (env is author-controlled, e.g. a configured base
// URL), and a reference at the very start of the template (a stored
// endpoint, an upstream `next` link). Request input may not choose the
// scheme or host of a request that carries the app's secrets: a
// request-tainted value in either of those places is refused when the call
// has an auth header, custom headers, a signer or any env reference
// (apiCallCarriesSecrets), and when it sends a value derived from env
// through an earlier step (apiCallSecretRef, flows_taint.go). For that
// second kind only, a leading value that the producing step fixed itself
// is still accepted (flowValueAuthoredByStep): a token endpoint picked from
// a fixed list in SQL, or a configured URL passed through from env. The
// SSRF guard (isPrivateURL plus the dial-time check) still applies to the
// result in every case.

import (
	"fmt"
	neturl "net/url"
	"strings"
)

type flowURLRegion int

const (
	flowURLAuthority flowURLRegion = iota
	flowURLPath
	flowURLQuery
	flowURLFragment
)

// flowURLScanner tracks which part of the URL the next output byte lands in.
// It reads the OUTPUT, so a verbatim value (env, a leading base URL) moves
// the region exactly as literal text would.
type flowURLScanner struct {
	out    strings.Builder
	region flowURLRegion
}

func (s *flowURLScanner) write(text string) {
	for i := 0; i < len(text); i++ {
		s.writeByte(text[i])
	}
}

func (s *flowURLScanner) writeByte(c byte) {
	switch s.region {
	case flowURLAuthority:
		switch c {
		case '/':
			// The slashes of `scheme://` stay in the authority.
			cur := s.out.String()
			if !strings.HasSuffix(cur, ":") && !strings.HasSuffix(cur, ":/") {
				s.region = flowURLPath
			}
		case '?':
			s.region = flowURLQuery
		case '#':
			s.region = flowURLFragment
		}
	case flowURLPath:
		switch c {
		case '?':
			s.region = flowURLQuery
		case '#':
			s.region = flowURLFragment
		}
	case flowURLQuery:
		if c == '#' {
			s.region = flowURLFragment
		}
	}
	s.out.WriteByte(c)
}

// flowURLHostValue reports whether v is safe to splice into a host: host
// name, IP literal and port characters only.
func flowURLHostValue(v string) bool {
	for i := 0; i < len(v); i++ {
		c := v[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '.' || c == '-' || c == '_' || c == ':' || c == '[' || c == ']') {
			return false
		}
	}
	return true
}

// flowExprIsEnvOnly reports whether a `{{ }}` expression can only produce an
// env value or an author literal: every `||` operand is an `env.` ref (with
// any pipes) or a quoted literal.
func flowExprIsEnvOnly(expr string) bool {
	sawEnv := false
	for _, operand := range strings.Split(expr, "||") {
		base := strings.TrimSpace(strings.SplitN(operand, "|", 2)[0])
		switch {
		case strings.HasPrefix(base, "env.") && len(base) > len("env."):
			sawEnv = true
		case len(base) >= 2 && (base[0] == '\'' || base[0] == '"') && base[len(base)-1] == base[0]:
		default:
			return false
		}
	}
	return sawEnv
}

// flowExprEndsInURLEncode reports whether an expression's last pipe is
// `urlencode` (url.QueryEscape): its output holds no / ? # & = and is
// already encoded, which is how flows put a value in a URL before values
// were encoded by position. Encoding it again would corrupt it.
func flowExprEndsInURLEncode(expr string) bool {
	if strings.Contains(expr, "||") {
		return false
	}
	parts := strings.Split(expr, "|")
	if len(parts) < 2 {
		return false
	}
	name, _, hasArg := splitPipeNameArg(parts[len(parts)-1])
	return name == "urlencode" && !hasArg
}

// interpolateURLCtx renders an outbound URL template (see the file comment).
// secrets says whether the request carries the app's credentials; it decides
// whether request input may choose the scheme or host.
func interpolateURLCtx(template string, ctx *FlowContext, secrets bool) (string, error) {
	return interpolateOutboundURL(template, ctx, secrets, "")
}

// interpolateOutboundURL is interpolateURLCtx for a call that may also send
// a secret-derived value: derived names the first such key it sends ("" for
// none). It refuses request input in the scheme or host like secrets does,
// except for a leading value its producing step fixed (a literal, an env
// value).
func interpolateOutboundURL(template string, ctx *FlowContext, secrets bool, derived string) (string, error) {
	flatData := flatDataForCtx(ctx)
	start := len(template) - len(strings.TrimLeft(template, " \t\r\n"))
	var s flowURLScanner
	place := func(at int, ref, text string, verbatim, encoded bool) error {
		if verbatim {
			s.write(text)
			return nil
		}
		leading := at == start
		tainted := ref != "" && ctx.taintedRef(ref) != ""
		if s.region == flowURLAuthority {
			if tainted && secrets {
				return fmt.Errorf("api url: request input %s may not choose the scheme or host of a request that carries credentials; keep the host literal (or in env) and pass the value in the path or query", ref)
			}
			if tainted && derived != "" && !(leading && ctx.flowValueAuthoredByStep(ref, text)) {
				return fmt.Errorf("api url: request input %s may not choose the scheme or host of a request that sends %s, a value derived from the app's env; keep the host literal (or in env) and pass the value in the path or query", ref, derived)
			}
			if leading {
				s.write(text)
				return nil
			}
			if !flowURLHostValue(text) {
				return fmt.Errorf("api url: value of %s is not a host name and cannot be placed in the host", ref)
			}
			s.write(text)
			return nil
		}
		if s.region == flowURLPath && text != "" && strings.Trim(text, ".") == "" {
			return fmt.Errorf("api url: value of %s is a dot segment and cannot be placed in the path", ref)
		}
		switch {
		case encoded:
			s.write(text)
		case s.region == flowURLPath:
			s.write(neturl.PathEscape(text))
		default:
			s.write(neturl.QueryEscape(text))
		}
		return nil
	}
	i := 0
	for i < len(template) {
		if n, val, ok := colonParamAt(template, i, ctx.Params); ok {
			if err := place(i, template[i:i+n], val, false, false); err != nil {
				return "", err
			}
			i += n
			continue
		}
		if i+2 < len(template) && template[i] == '{' && template[i+1] == '{' {
			if end := strings.Index(template[i+2:], "}}"); end >= 0 {
				expr := strings.TrimSpace(template[i+2 : i+2+end])
				if val, ok := resolveBindExpr(expr, flatData); ok {
					text := ""
					if val != nil {
						text = fmt.Sprintf("%v", val)
					}
					if err := place(i, "{{"+expr+"}}", text, flowExprIsEnvOnly(expr), flowExprEndsInURLEncode(expr)); err != nil {
						return "", err
					}
					i += 2 + end + 2
					continue
				}
				// Same as interpolateCtx: record it so the step halts
				// with template_unresolved instead of sending the literal.
				ctx.noteMissingRef(expr)
			}
		}
		s.writeByte(template[i])
		i++
	}
	return s.out.String(), nil
}

// apiCallCarriesSecrets reports whether an api step sends anything the
// app's author would not hand to an arbitrary host: an Authorization value,
// a header that could hold a credential, a signer, or an env reference
// anywhere in the call.
func apiCallCarriesSecrets(api *FlowAPICall) bool {
	if api == nil {
		return false
	}
	if api.Auth != "" || api.Sign != nil {
		return true
	}
	for name, value := range api.Headers {
		if !apiHeaderIsBenign(name, value) {
			return true
		}
	}
	refsEnv := func(s string) bool { return strings.Contains(s, "env.") }
	if refsEnv(api.URL) || refsEnv(api.Body) {
		return true
	}
	for _, v := range api.Query {
		if refsEnv(v) {
			return true
		}
	}
	for _, v := range api.Form {
		if refsEnv(v) {
			return true
		}
	}
	return jsonTemplateRefsEnv(api.JSON) || jsonTemplateRefsEnv(api.JSONArray)
}

// apiCallSecretRef returns the first secret-derived key (flows_taint.go)
// any template of the call sends, or "" when it sends none.
func (ctx *FlowContext) apiCallSecretRef(api *FlowAPICall) string {
	if ctx == nil || api == nil {
		return ""
	}
	templates := []string{api.URL, api.Body, api.Auth}
	for _, v := range api.Query {
		templates = append(templates, v)
	}
	for _, v := range api.Form {
		templates = append(templates, v)
	}
	for _, v := range api.Headers {
		templates = append(templates, v)
	}
	if api.Sign != nil {
		for _, v := range api.Sign.Bindings {
			templates = append(templates, v)
		}
	}
	templates = appendJSONTemplateStrings(templates, api.JSON)
	templates = appendJSONTemplateStrings(templates, api.JSONArray)
	for _, t := range templates {
		if ref := ctx.secretRef(t); ref != "" {
			return ref
		}
	}
	return ""
}

func appendJSONTemplateStrings(out []string, v any) []string {
	switch t := v.(type) {
	case string:
		out = append(out, t)
	case map[string]any:
		for _, child := range t {
			out = appendJSONTemplateStrings(out, child)
		}
	case []any:
		for _, child := range t {
			out = appendJSONTemplateStrings(out, child)
		}
	}
	return out
}

// apiBenignHeaders are content-negotiation headers whose fixed values say
// how to encode or describe the request, never who is calling.
var apiBenignHeaders = map[string]bool{
	"accept":          true,
	"accept-language": true,
	"content-type":    true,
	"user-agent":      true,
}

// apiHeaderIsBenign reports a header that cannot carry a credential: a
// content-negotiation name with a literal value. Any template (it may read
// env or request data) or any other name, including a literal Authorization
// or API-key header written into the flow, counts as a credential.
func apiHeaderIsBenign(name, value string) bool {
	return apiBenignHeaders[strings.ToLower(strings.TrimSpace(name))] && !strings.Contains(value, "{{")
}

func jsonTemplateRefsEnv(v any) bool {
	switch t := v.(type) {
	case string:
		return strings.Contains(t, "env.")
	case map[string]any:
		for _, child := range t {
			if jsonTemplateRefsEnv(child) {
				return true
			}
		}
	case []any:
		for _, child := range t {
			if jsonTemplateRefsEnv(child) {
				return true
			}
		}
	}
	return false
}
