//go:build !cli

package main

// gotmpl_validate.go - bounded stub execution of a gotmpl page at write
// time. validateGotmplParseIn runs in the ROUTER on MCP write_file and
// edit_file, so executing tenant template code there must be hermetic and
// bounded:
//
//   - The function map is the render map (gotmplSprigFuncs: no environment,
//     DNS or key generation), with app/ctx nil.
//   - Every function call is charged against a step budget and a deadline,
//     refuses inputs whose combined size is over gotmplMaxStringBytes, and
//     refuses an oversized result, so neither `cat` over many large values
//     nor repeated doubling can allocate without bound.
//   - Templates loop and recurse without calling any function (`{{range
//     1000000000}}{{end}}`, a {{define}} that calls itself twice), so a
//     budget charge is also injected at the start of every range body and
//     every template body.
//   - print/printf/println never fail, so they are stubbed out: a
//     dynamically built format string could otherwise ask fmt for gigabytes.
//     The builtin html/js/urlquery escapers are budgeted like helpers.
//   - Output goes to a writer that fails after gotmplValidateMaxOutput bytes.
//
// Execution happens on a text/template copy of the page, because
// html/template's escaper would rewrite (and might reject) the injected
// budget actions. The html/template escaping check runs separately, with a
// single injected action at the very start of the page that stops execution
// before anything else runs.
//
// Running out of budget is not an error in the template; validation accepts
// it and the render-time caps still apply.

import (
	"errors"
	"fmt"
	htmltemplate "html/template"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	ttemplate "text/template"
	"text/template/parse"
	"time"
)

const (
	gotmplValidateMaxSteps  = 200_000
	gotmplValidateTimeout   = 2 * time.Second
	gotmplValidateMaxOutput = 1 << 20
	gotmplValidateTickName  = "_benmoreValidateTick"
	gotmplValidateMaxDepth  = 1000
)

var (
	errGotmplValidateBudget = errors.New("gotmpl validation budget exhausted")
	errGotmplValidateStop   = errors.New("gotmpl escape check complete")
)

type gotmplValidateBudget struct {
	steps    int
	deadline time.Time
}

func (b *gotmplValidateBudget) charge() error {
	b.steps++
	if b.steps > gotmplValidateMaxSteps || time.Now().After(b.deadline) {
		return errGotmplValidateBudget
	}
	return nil
}

// gotmplValidationStopped reports whether err is one of the validation
// bounds rather than a fault in the template.
func gotmplValidationStopped(err error) bool {
	return errors.Is(err, errGotmplValidateBudget) || errors.Is(err, errGotmplLimit) || errors.Is(err, errGotmplOutputLimit)
}

// gotmplDeepSize approximates the bytes a value holds (string bytes plus one
// per element/entry), stopping once it passes limit. Shared references count
// each time they are reachable, which is what printing them would cost; a
// cycle (dict set into itself) therefore counts past the limit and stops.
func gotmplDeepSize(v reflect.Value, limit int) int {
	n := 0
	var walk func(reflect.Value, int)
	walk = func(v reflect.Value, depth int) {
		if n > limit || !v.IsValid() {
			return
		}
		if depth > gotmplValidateMaxDepth {
			n = limit + 1
			return
		}
		switch v.Kind() {
		case reflect.String:
			n += v.Len()
		case reflect.Slice, reflect.Array:
			n += v.Len()
			if v.Type().Elem().Kind() == reflect.Uint8 {
				return
			}
			for i := 0; i < v.Len() && n <= limit; i++ {
				walk(v.Index(i), depth+1)
			}
		case reflect.Map:
			n += v.Len()
			iter := v.MapRange()
			for n <= limit && iter.Next() {
				walk(iter.Key(), depth+1)
				walk(iter.Value(), depth+1)
			}
		case reflect.Interface, reflect.Pointer:
			if !v.IsNil() {
				walk(v.Elem(), depth+1)
			}
		default:
			n++
		}
	}
	walk(v, 0)
	return n
}

// gotmplBudgetedFunc wraps fn (any template function) so each call is
// charged against b and refuses oversized inputs and results. The wrapper
// keeps fn's exact signature, so text/template's argument checks are the
// ones the page will meet at render time. Failures panic with an error,
// which text/template turns into "error calling <name>: ...".
func gotmplBudgetedFunc(fn any, b *gotmplValidateBudget) any {
	v := reflect.ValueOf(fn)
	if v.Kind() != reflect.Func {
		return fn
	}
	t := v.Type()
	return reflect.MakeFunc(t, func(args []reflect.Value) []reflect.Value {
		if err := b.charge(); err != nil {
			panic(err)
		}
		total := 0
		for _, a := range args {
			total += gotmplDeepSize(a, gotmplMaxStringBytes-total)
			if total > gotmplMaxStringBytes {
				panic(errGotmplLimit)
			}
		}
		var out []reflect.Value
		if t.IsVariadic() {
			out = v.CallSlice(args)
		} else {
			out = v.Call(args)
		}
		if len(out) > 0 && gotmplDeepSize(out[0], gotmplMaxStringBytes) > gotmplMaxStringBytes {
			panic(errGotmplLimit)
		}
		return out
	}).Interface()
}

// gotmplValidationFuncs is the function map for the bounded execution pass.
func gotmplValidationFuncs(b *gotmplValidateBudget) ttemplate.FuncMap {
	fm := ttemplate.FuncMap{}
	for name, fn := range gotmplHelpers(nil, nil) {
		fm[name] = gotmplBudgetedFunc(fn, b)
	}
	fm["print"] = gotmplBudgetedFunc(fmt.Sprint, b)
	fm["println"] = gotmplBudgetedFunc(fmt.Sprintln, b)
	fm["printf"] = gotmplBudgetedFunc(func(format string, args ...any) (string, error) {
		if n := gotmplFormatWidths(format); n > gotmplMaxStringBytes {
			return "", gotmplSizeErr("printf", n)
		}
		return fmt.Sprintf(format, args...), nil
	}, b)
	// text/template's builtin escapers format every argument into one
	// string before escaping it; unbudgeted, one call over many references
	// to an in-cap string allocates any multiple of the cap.
	fm["html"] = gotmplBudgetedFunc(ttemplate.HTMLEscaper, b)
	fm["js"] = gotmplBudgetedFunc(ttemplate.JSEscaper, b)
	fm["urlquery"] = gotmplBudgetedFunc(ttemplate.URLQueryEscaper, b)
	fm[gotmplValidateTickName] = func() (string, error) { return "", b.charge() }
	return fm
}

// gotmplFormatWidths sums the explicit widths and precisions in a printf
// format (a `*` counts as fmt's own 1e6 ceiling): the padding fmt would
// allocate beyond the arguments themselves. A format string can be built at
// run time (`printf (repeat 4000 "%999999d")`), so its length alone says
// nothing about the output.
func gotmplFormatWidths(format string) float64 {
	total := float64(len(format))
	for i := 0; i < len(format); i++ {
		if format[i] != '%' {
			continue
		}
		num := 0.0
	verb:
		for i++; i < len(format); i++ {
			c := format[i]
			switch {
			case c >= '0' && c <= '9':
				if num = num*10 + float64(c-'0'); num > 1e7 {
					num = 1e7
				}
			case c == '*':
				total += 1e6
			case c == '.' || c == '+' || c == '-' || c == '#' || c == ' ' || c == '[' || c == ']':
				total += num
				num = 0
			default:
				break verb
			}
		}
		total += num
	}
	return total
}

// gotmplTickNode returns a parsed `{{_benmoreValidateTick}}` action to copy
// into other trees.
func gotmplTickNode(funcs ttemplate.FuncMap) (*parse.ActionNode, error) {
	t, err := ttemplate.New("tick").Funcs(funcs).Parse("{{" + gotmplValidateTickName + "}}")
	if err != nil {
		return nil, err
	}
	node, ok := t.Tree.Root.Nodes[0].(*parse.ActionNode)
	if !ok {
		return nil, errors.New("gotmpl validation: unexpected tick node")
	}
	return node, nil
}

// injectGotmplTicks prepends a budget charge to every range body in list
// and, when prepend is set, to list itself.
func injectGotmplTicks(list *parse.ListNode, tick *parse.ActionNode, prepend bool) {
	if list == nil {
		return
	}
	for _, n := range list.Nodes {
		switch n := n.(type) {
		case *parse.ListNode:
			injectGotmplTicks(n, tick, false)
		case *parse.IfNode:
			injectGotmplTicks(n.List, tick, false)
			injectGotmplTicks(n.ElseList, tick, false)
		case *parse.WithNode:
			injectGotmplTicks(n.List, tick, false)
			injectGotmplTicks(n.ElseList, tick, false)
		case *parse.RangeNode:
			injectGotmplTicks(n.List, tick, true)
			injectGotmplTicks(n.ElseList, tick, false)
		}
	}
	if prepend {
		list.Nodes = append([]parse.Node{tick.Copy()}, list.Nodes...)
	}
}

// validateGotmplExecute stub-executes body (with partials) against nil data
// under the bounds described at the top of this file. It returns the first
// template-intrinsic error, or nil when the page is fine or validation ran
// out of budget.
func validateGotmplExecute(name, body string, partials map[string]string) error {
	// 1. html/template escaping check. The single injected action at the
	// start of the page stops execution as soon as escaping has passed.
	stopFuncs := gotmplHelpers(nil, nil)
	stopFuncs[gotmplValidateTickName] = func() (string, error) { return "", errGotmplValidateStop }
	htmlTmpl := htmltemplate.New(name).Funcs(stopFuncs).Option("missingkey=zero")
	for _, pName := range sortedGotmplPartialNames(partials) {
		_, _ = htmlTmpl.New(pName).Parse(partials[pName])
	}
	htmlParsed, err := htmlTmpl.Parse(body)
	if err != nil {
		return err
	}
	stopTick, err := gotmplTickNode(ttemplate.FuncMap(stopFuncs))
	if err != nil {
		return err
	}
	if htmlParsed.Tree != nil && htmlParsed.Tree.Root != nil {
		root := htmlParsed.Tree.Root
		root.Nodes = append([]parse.Node{stopTick.Copy()}, root.Nodes...)
	}
	if err := htmlParsed.Execute(io.Discard, nil); err != nil && !errors.Is(err, errGotmplValidateStop) {
		return err
	}

	// 2. Bounded execution on a text/template copy.
	budget := &gotmplValidateBudget{deadline: time.Now().Add(gotmplValidateTimeout)}
	funcs := gotmplValidationFuncs(budget)
	textTmpl := ttemplate.New(name).Funcs(funcs).Option("missingkey=zero")
	for _, pName := range sortedGotmplPartialNames(partials) {
		_, _ = textTmpl.New(pName).Parse(partials[pName])
	}
	textParsed, err := textTmpl.Parse(body)
	if err != nil {
		return err
	}
	tick, err := gotmplTickNode(funcs)
	if err != nil {
		return err
	}
	for _, t := range textParsed.Templates() {
		if t.Tree != nil {
			injectGotmplTicks(t.Tree.Root, tick, true)
		}
	}
	err = textParsed.Execute(&gotmplLimitWriter{limit: gotmplValidateMaxOutput}, nil)
	if err == nil || gotmplValidationStopped(err) {
		return nil
	}
	return err
}

// readGotmplPartials reads <appDir>/partials/*.html (case-insensitive
// suffix) through an os.Root at appDir, so a partial that is a symlink
// leading outside the app, or a partials/ directory that is one, is not read.
// Keys are file names; values are the raw file contents.
func readGotmplPartials(appDir string) map[string]string {
	out := map[string]string{}
	root, err := os.OpenRoot(appDir)
	if err != nil {
		return out
	}
	defer root.Close()
	dir, err := root.Open("partials")
	if err != nil {
		return out
	}
	entries, err := dir.ReadDir(-1)
	dir.Close()
	if err != nil {
		return out
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".html") {
			continue
		}
		data, err := root.ReadFile(filepath.Join("partials", e.Name()))
		if err != nil {
			continue
		}
		out[e.Name()] = string(data)
	}
	return out
}

// sortedGotmplPartialNames returns m's keys in order, so partials parse
// deterministically (a later {{define}} of the same name wins).
func sortedGotmplPartialNames(m map[string]string) []string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
