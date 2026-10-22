//go:build !cli

package main

// gotmpl_sandbox.go - the boundary between Sprig and app-authored
// templates.
//
// Sprig is a library for operator-authored config templates (Helm), so its
// default map reaches outside the template: `env`/`expandenv` read the
// process environment, `getHostByName` resolves DNS, and the gen* certificate
// helpers burn seconds of CPU per call. App templates are tenant code, and
// two processes run them: the app itself at render time (in `benmore host`
// that process also holds the operator's credentials), and the ROUTER, which
// stub-executes every gotmpl page on MCP write_file/edit_file. A tenant
// writing `{{ fail (expandenv "$SECRET") }}` would get the router's secret
// back in the validation error, or exfiltrate it over DNS with getHostByName.
//
// So the map every gotmpl page sees is Sprig minus those functions, with the
// helpers whose output is a product of their inputs (until, repeat, replace,
// indent, ...) capped. Write-time validation adds a step budget, a deadline,
// a per-call size check and a bounded writer on top (validateGotmplExecute),
// because it runs in the router where a runaway template would stall every
// tenant.

import (
	"errors"
	"fmt"
	htmltemplate "html/template"
	"math"
	"reflect"
	"regexp"
	"strings"

	"github.com/Masterminds/sprig/v3"
)

const (
	// gotmplMaxSeqLen caps the element count of until/untilStep/seq.
	gotmplMaxSeqLen = 100_000
	// gotmplMaxStringBytes caps strings built by the multiplicative helpers
	// (repeat, replace, indent, join, regexReplaceAll, rand*).
	gotmplMaxStringBytes = 4 << 20
	// gotmplMaxRenderBytes caps one gotmpl page's rendered output.
	gotmplMaxRenderBytes = 64 << 20
)

var (
	errGotmplLimit       = errors.New("gotmpl: helper result exceeds the template size limit")
	errGotmplOutputLimit = errors.New("gotmpl: rendered output exceeds the page size limit")
)

// gotmplRemovedSprigFuncs are Sprig functions no app template may call:
// they read the process environment, touch the network, or generate RSA/
// ECDSA keys (seconds of CPU per call). The framework's own `env` (per-app
// env.yaml) replaces Sprig's after this list is applied.
var gotmplRemovedSprigFuncs = []string{
	"env", "expandenv", "getHostByName",
	"genPrivateKey", "genCA", "genCAWithKey",
	"genSelfSignedCert", "genSelfSignedCertWithKey",
	"genSignedCert", "genSignedCertWithKey", "buildCustomCert",
}

// gotmplSprigFuncs returns the Sprig function map gotmpl pages render with:
// non-hermetic OS/network helpers removed and allocation-multiplying helpers
// capped. Date and random helpers stay: they vary between renders but read
// nothing outside the template.
func gotmplSprigFuncs() htmltemplate.FuncMap {
	fm := sprig.HtmlFuncMap()
	for _, name := range gotmplRemovedSprigFuncs {
		delete(fm, name)
	}
	capGotmplSprigFuncs(fm)
	return fm
}

func gotmplSizeErr(name string, n float64) error {
	return fmt.Errorf("%s: result of %.0f bytes exceeds the %d-byte template limit: %w", name, n, gotmplMaxStringBytes, errGotmplLimit)
}

// gotmplStepCount is the number of elements Sprig's untilStep produces.
func gotmplStepCount(start, stop, step int) float64 {
	switch {
	case stop < start && step < 0:
		return math.Ceil((float64(start) - float64(stop)) / -float64(step))
	case stop > start && step > 0:
		return math.Ceil((float64(stop) - float64(start)) / float64(step))
	}
	return 0
}

func gotmplSeqCheck(name string, n float64) error {
	if n > gotmplMaxSeqLen {
		return fmt.Errorf("%s: %.0f elements exceeds the %d-element template limit: %w", name, n, gotmplMaxSeqLen, errGotmplLimit)
	}
	return nil
}

// capGotmplSprigFuncs replaces the Sprig helpers whose output size is a
// product of their inputs with versions that refuse an oversized result
// BEFORE allocating it. Each wrapper calls Sprig's own implementation, so
// in-bounds results are unchanged. A helper whose Sprig signature changed
// is removed rather than left uncapped.
func capGotmplSprigFuncs(fm htmltemplate.FuncMap) {
	if until, ok := fm["until"].(func(int) []int); ok {
		fm["until"] = func(count int) ([]int, error) {
			if err := gotmplSeqCheck("until", math.Abs(float64(count))); err != nil {
				return nil, err
			}
			return until(count), nil
		}
	} else {
		delete(fm, "until")
	}
	if untilStep, ok := fm["untilStep"].(func(int, int, int) []int); ok {
		fm["untilStep"] = func(start, stop, step int) ([]int, error) {
			if err := gotmplSeqCheck("untilStep", gotmplStepCount(start, stop, step)); err != nil {
				return nil, err
			}
			return untilStep(start, stop, step), nil
		}
	} else {
		delete(fm, "untilStep")
	}
	if seq, ok := fm["seq"].(func(...int) string); ok {
		fm["seq"] = func(params ...int) (string, error) {
			// Mirror Sprig's parameter forms to size the result first.
			var n float64
			switch len(params) {
			case 1:
				n = math.Abs(float64(params[0])-1) + 1
			case 2:
				n = math.Abs(float64(params[1])-float64(params[0])) + 1
			case 3:
				if params[1] != 0 {
					n = math.Abs(float64(params[2])-float64(params[0]))/math.Abs(float64(params[1])) + 1
				}
			}
			if err := gotmplSeqCheck("seq", n); err != nil {
				return "", err
			}
			return seq(params...), nil
		}
	} else {
		delete(fm, "seq")
	}
	if repeat, ok := fm["repeat"].(func(int, string) string); ok {
		fm["repeat"] = func(count int, str string) (string, error) {
			if count < 0 {
				return "", fmt.Errorf("repeat: negative count %d", count)
			}
			if n := float64(count) * float64(len(str)); n > gotmplMaxStringBytes {
				return "", gotmplSizeErr("repeat", n)
			}
			return repeat(count, str), nil
		}
	} else {
		delete(fm, "repeat")
	}
	for _, name := range []string{"indent", "nindent"} {
		indent, ok := fm[name].(func(int, string) string)
		if !ok {
			delete(fm, name)
			continue
		}
		fm[name] = func(spaces int, v string) (string, error) {
			if spaces < 0 {
				return "", fmt.Errorf("%s: negative width %d", name, spaces)
			}
			lines := float64(strings.Count(v, "\n") + 1)
			if n := float64(spaces)*lines + float64(len(v)) + 1; n > gotmplMaxStringBytes {
				return "", gotmplSizeErr(name, n)
			}
			return indent(spaces, v), nil
		}
	}
	if replace, ok := fm["replace"].(func(string, string, string) string); ok {
		fm["replace"] = func(old, replacement, src string) (string, error) {
			// strings.Count with an empty `old` counts every rune boundary,
			// which is exactly how many insertions strings.Replace makes.
			count := float64(strings.Count(src, old))
			if n := float64(len(src)) + count*float64(len(replacement)-len(old)); n > gotmplMaxStringBytes {
				return "", gotmplSizeErr("replace", n)
			}
			return replace(old, replacement, src), nil
		}
	} else {
		delete(fm, "replace")
	}
	if wrapWith, ok := fm["wrapWith"].(func(int, string, string) string); ok {
		fm["wrapWith"] = func(l int, sep, str string) (string, error) {
			// At most one separator per input byte.
			if n := float64(len(str)) + float64(len(str)+1)*float64(len(sep)); n > gotmplMaxStringBytes {
				return "", gotmplSizeErr("wrapWith", n)
			}
			return wrapWith(l, sep, str), nil
		}
	} else {
		delete(fm, "wrapWith")
	}
	if join, ok := fm["join"].(func(string, interface{}) string); ok {
		fm["join"] = func(sep string, v interface{}) (string, error) {
			elems := 1
			if rv := reflect.ValueOf(v); rv.Kind() == reflect.Slice || rv.Kind() == reflect.Array {
				elems = rv.Len()
			}
			if n := float64(len(sep)) * float64(elems); n > gotmplMaxStringBytes {
				return "", gotmplSizeErr("join", n)
			}
			out := join(sep, v)
			if len(out) > gotmplMaxStringBytes {
				return "", gotmplSizeErr("join", float64(len(out)))
			}
			return out, nil
		}
	} else {
		delete(fm, "join")
	}
	for _, name := range []string{"randAlphaNum", "randAlpha", "randAscii", "randNumeric"} {
		gen, ok := fm[name].(func(int) string)
		if !ok {
			delete(fm, name)
			continue
		}
		fm[name] = func(count int) (string, error) {
			if count < 0 || count > gotmplMaxStringBytes {
				return "", gotmplSizeErr(name, float64(count))
			}
			return gen(count), nil
		}
	}
	if randBytes, ok := fm["randBytes"].(func(int) (string, error)); ok {
		fm["randBytes"] = func(count int) (string, error) {
			if count < 0 || count > gotmplMaxStringBytes {
				return "", gotmplSizeErr("randBytes", float64(count))
			}
			return randBytes(count)
		}
	} else {
		delete(fm, "randBytes")
	}
	// regexReplaceAll's output is matches x expanded replacement; `$0` in
	// the replacement copies a whole match each time. Build it here with a
	// running size check instead of calling Sprig's ReplaceAllString.
	regexReplace := func(name string, literal bool) func(string, string, string) (string, error) {
		return func(pattern, s, repl string) (string, error) {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return "", err
			}
			var out []byte
			last := 0
			for _, m := range re.FindAllStringSubmatchIndex(s, -1) {
				out = append(out, s[last:m[0]]...)
				if literal {
					out = append(out, repl...)
				} else {
					out = re.ExpandString(out, repl, s, m)
				}
				last = m[1]
				if len(out) > gotmplMaxStringBytes {
					return "", gotmplSizeErr(name, float64(len(out)))
				}
			}
			out = append(out, s[last:]...)
			if len(out) > gotmplMaxStringBytes {
				return "", gotmplSizeErr(name, float64(len(out)))
			}
			return string(out), nil
		}
	}
	for _, name := range []string{"regexReplaceAll", "mustRegexReplaceAll"} {
		fm[name] = regexReplace(name, false)
	}
	for _, name := range []string{"regexReplaceAllLiteral", "mustRegexReplaceAllLiteral"} {
		fm[name] = regexReplace(name, true)
	}
}

// gotmplLimitWriter fails a template execution once more than limit bytes
// have been written, so neither a render nor a validation pass can build an
// unbounded page.
type gotmplLimitWriter struct {
	w     interface{ Write([]byte) (int, error) }
	n     int
	limit int
}

func (lw *gotmplLimitWriter) Write(p []byte) (int, error) {
	lw.n += len(p)
	if lw.n > lw.limit {
		return 0, errGotmplOutputLimit
	}
	if lw.w == nil {
		return len(p), nil
	}
	return lw.w.Write(p)
}
