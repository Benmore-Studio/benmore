//go:build !cli

package main

// Flow condition expressions: `&&`, `||`, `!` and parentheses around the
// comparison operators in `if:` and `success_when:`, and `${{ }}` value
// expressions in serve_file's `disposition:`.
//
// The author's condition is parsed into a tree before any value is
// resolved. Refs are looked up only when the tree is evaluated, and a
// resolved value is only ever an operand: nothing a request, a row or a
// step supplies is parsed, so a value can never add an operator, a
// connective or another ref.
//
// Conditions that are one comparison or operator-less keep the 2.7.246
// evaluator (evaluateFlowCondition); conditionUsesExpressionSyntax decides
// which one a condition gets, so their results are unchanged.

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
)

type condExprKind int

const (
	condLit condExprKind = iota
	condRef
	condNot
	condAnd
	condOr
	condCmp
)

// condExpr is one node of a parsed condition.
type condExpr struct {
	kind        condExprKind
	lit         any    // condLit: string, bool or nil
	ref         string // condRef: translated ref, pipes appended (`x.y | default:''`)
	op          string // condCmp: = != > < >= <=
	left, right *condExpr
}

// condMaxDepth bounds nesting so a pathological condition can't recurse
// without limit.
const condMaxDepth = 64

// eval resolves the tree against the flattened flow data. `&&` and `||`
// return an operand, as in JavaScript: `a || 'x'` is the first truthy
// operand (or the last one), `a && b` the first falsy one (or the last).
// `!` and comparisons return a bool. Truthiness is isTruthyCondition.
func (e *condExpr) eval(flat map[string]any) any {
	switch e.kind {
	case condLit:
		return e.lit
	case condRef:
		if v, ok := resolveBindExpr(e.ref, flat); ok {
			return v
		}
		return nil
	case condNot:
		return !isTruthyCondition(e.left.eval(flat))
	case condAnd:
		l := e.left.eval(flat)
		if !isTruthyCondition(l) {
			return l
		}
		return e.right.eval(flat)
	case condOr:
		l := e.left.eval(flat)
		if isTruthyCondition(l) {
			return l
		}
		return e.right.eval(flat)
	case condCmp:
		return compareLiteralCondition(condOperandText(e.left.eval(flat)), e.op, condOperandText(e.right.eval(flat)))
	}
	return nil
}

// condOperandText formats an operand for compareLiteralCondition the way
// the single-comparison evaluator does (conditionRowValue): a missing or
// nil value is the empty string, anything else its %v text.
func condOperandText(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%v", v)
}

// conditionUsesExpressionSyntax reports whether a condition needs the
// expression evaluator. It scans outside quoted text, and treats `{{ }}`
// (or `${{ }}`) spans as operands:
//
//   - before the first comparison operator: `&&`, a unary `!`, `(`, `)`,
//     or `||` next to a span (`${{ a }} || ${{ b }}`). A `||` between
//     bare refs and literals is the fallback it always was
//     (`a || 'x' == 'x'` compares the fallback), so it stays with the
//     single-comparison evaluator;
//   - after the first comparison operator: `&&` or `||`;
//   - inside a span: `&&`, a unary `!`, parentheses or a two-character
//     comparison operator.
//
// Pipe arguments (`| default:(none)`) are opaque. Everything else is a
// shape the single-comparison evaluator already handled, and keeps it.
func conditionUsesExpressionSyntax(c string) bool {
	topOp := false     // a comparison operator outside spans has been seen
	span := false      // inside {{ }}
	pipeArg := false   // after a single '|' until the next operator or span end
	afterSpan := false // the last thing outside spans was a span
	for i := 0; i < len(c); i++ {
		ch := c[i]
		if !span && ch != ' ' && ch != '\t' && ch != '\n' && ch != '\r' && ch != '|' {
			afterSpan = false
		}
		if ch == '\'' || ch == '"' {
			if end := strings.IndexByte(c[i+1:], ch); end >= 0 {
				i += end + 1
				continue
			}
		}
		if !span {
			if strings.HasPrefix(c[i:], "${{") {
				span, pipeArg = true, false
				i += 2
				continue
			}
			if strings.HasPrefix(c[i:], "{{") {
				span, pipeArg = true, false
				i++
				continue
			}
		} else if strings.HasPrefix(c[i:], "}}") {
			span, pipeArg, afterSpan = false, false, true
			i++
			continue
		}
		two := ""
		if i+1 < len(c) {
			two = c[i : i+2]
		}
		switch two {
		case "&&":
			return true
		case "||":
			if !span {
				next := strings.TrimLeft(c[i+2:], " \t\r\n")
				if topOp || afterSpan || strings.HasPrefix(next, "{{") || strings.HasPrefix(next, "${{") {
					return true
				}
			}
			pipeArg = false
			i++
			continue
		case "==", "!=", ">=", "<=":
			if span {
				if !pipeArg {
					return true
				}
			} else {
				topOp, pipeArg = true, false
			}
			i++
			continue
		}
		switch ch {
		case '|':
			pipeArg = true
		case '=', '<', '>':
			if !span {
				topOp, pipeArg = true, false
			}
		case '!', '(', ')':
			if !pipeArg && (span || !topOp) {
				return true
			}
		}
	}
	return false
}

// evaluateFlowExpression evaluates a condition with the expression
// grammar. A condition that doesn't parse is false.
func evaluateFlowExpression(condition string, ctx *FlowContext) bool {
	e, err := parseFlowCondExpr(condition)
	if err != nil {
		return false
	}
	return isTruthyCondition(e.eval(flatDataForCtx(ctx)))
}

// flowValueTemplate resolves a flow value that may be a `{{ expr }}`
// expression (`${{ params.dl == '1' && 'attachment' || 'inline' }}`). A
// template that is exactly one span is evaluated with the condition
// grammar; any other text is interpolated as usual.
func flowValueTemplate(tmpl string, ctx *FlowContext) string {
	t := strings.TrimSpace(tmpl)
	if strings.HasPrefix(t, "{{") && strings.HasSuffix(t, "}}") && strings.Count(t, "{{") == 1 {
		e, err := parseFlowCondExpr(t[2 : len(t)-2])
		if err != nil {
			return ""
		}
		return condOperandText(e.eval(flatDataForCtx(ctx)))
	}
	return interpolateCtx(tmpl, ctx)
}

// flowConditionNeverHolds reports why a runtime condition (the text
// evaluateFlowCondition receives) can never evaluate true whatever the data,
// or "" when it can. It uses the evaluator's own decisions, so it names only
// conditions the runtime would always treat as false: an expression that
// doesn't parse, or a single comparison whose left side is neither a field
// nor a ref. A guard written that way never fires, which fails open when the
// branch is the refusal (`if: <cond>` → respond 403).
func flowConditionNeverHolds(condition string) string {
	if strings.TrimSpace(condition) == "" {
		return ""
	}
	if conditionUsesExpressionSyntax(condition) {
		if _, err := parseCondExpr(condition); err != nil {
			return err.Error()
		}
		return ""
	}
	lhs, _, rhs, ok := splitConditionOperator(condition)
	if !ok || lhs == "" {
		return ""
	}
	if strings.Contains(lhs, "&&") || conditionHasConnective(rhs) {
		return "a joined comparison that isn't one expression"
	}
	if !conditionLHSNeedsResolution(lhs) && !conditionFieldName(lhs) {
		return fmt.Sprintf("the left side %q is not a field or ref", truncate(lhs, 80))
	}
	return ""
}

// flowValueTemplateNeverParses reports why a `{{ expr }}` value template
// (serve_file disposition) can't be evaluated, or "".
func flowValueTemplateNeverParses(tmpl string) string {
	t := strings.TrimSpace(tmpl)
	if strings.HasPrefix(t, "{{") && strings.HasSuffix(t, "}}") && strings.Count(t, "{{") == 1 {
		if _, err := parseCondExpr(t[2 : len(t)-2]); err != nil {
			return err.Error()
		}
	}
	return ""
}

type condParsed struct {
	expr *condExpr
	err  error
}

// condExprCache holds parsed conditions by their text. Conditions come
// from flow files, so the set is small; the cap only bounds a pathological
// app.
var (
	condExprCache    sync.Map
	condExprCached   atomic.Int64
	condExprCacheCap int64 = 4096
)

// parseFlowCondExpr parses (and caches) a condition. A parse error is
// logged the first time that condition is seen.
func parseFlowCondExpr(condition string) (*condExpr, error) {
	if v, ok := condExprCache.Load(condition); ok {
		p := v.(condParsed)
		return p.expr, p.err
	}
	e, err := parseCondExpr(condition)
	if err != nil {
		log.Printf("flows: condition %q does not parse (%v); it evaluates false", truncate(condition, 200), err)
	}
	if condExprCached.Load() < condExprCacheCap {
		if _, loaded := condExprCache.LoadOrStore(condition, condParsed{e, err}); !loaded {
			condExprCached.Add(1)
		}
	}
	return e, err
}

// parseCondExpr parses a condition:
//
//	or      := and ( '||' and )*
//	and     := cmp ( '&&' cmp )*
//	cmp     := unary ( op unary )?        op: == = != >= <= > <
//	unary   := '!' unary | primary
//	primary := '(' or ')' | '{{' or '}}' | '${{' or '}}'
//	         | 'text' | "text" | number | true | false | null | undefined
//	         | ref ( '|' pipe )*
//
// A ref is a dotted path (`steps.x.outputs.rows[0].id`, `params.a`,
// `user.id`), translated like any `${{ }}` ref; pipes apply through
// resolveBindExpr. A comparison takes one operator: `a < b < c` is an
// error.
func parseCondExpr(s string) (*condExpr, error) {
	p := &condParser{lex: condLexer{s: s}}
	if err := p.advance(); err != nil {
		return nil, err
	}
	e, err := p.parseOr(0)
	if err != nil {
		return nil, err
	}
	if p.tok.kind != condTokEOF {
		return nil, fmt.Errorf("unexpected %q at offset %d", p.tok.text, p.tok.pos)
	}
	return e, nil
}

type condTokKind int

const (
	condTokEOF condTokKind = iota
	condTokLParen
	condTokRParen
	condTokOpenRef
	condTokCloseRef
	condTokAnd
	condTokOr
	condTokNot
	condTokCmp
	condTokPipe
	condTokString
	condTokNumber
	condTokIdent
)

type condTok struct {
	kind condTokKind
	text string // string: contents; cmp: operator (== is =); others: source text
	pos  int
}

type condLexer struct {
	s   string
	pos int
}

func condIdentStart(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func condIdentByte(b byte) bool {
	return condIdentStart(b) || (b >= '0' && b <= '9') || b == '-' || b == '.'
}

func (l *condLexer) next() (condTok, error) {
	s := l.s
	for l.pos < len(s) && (s[l.pos] == ' ' || s[l.pos] == '\t' || s[l.pos] == '\n' || s[l.pos] == '\r') {
		l.pos++
	}
	start := l.pos
	if l.pos >= len(s) {
		return condTok{kind: condTokEOF, pos: start}, nil
	}
	rest := s[l.pos:]
	tok := func(k condTokKind, n int, text string) (condTok, error) {
		l.pos += n
		return condTok{kind: k, text: text, pos: start}, nil
	}
	switch {
	case strings.HasPrefix(rest, "${{"):
		return tok(condTokOpenRef, 3, "${{")
	case strings.HasPrefix(rest, "{{"):
		return tok(condTokOpenRef, 2, "{{")
	case strings.HasPrefix(rest, "}}"):
		return tok(condTokCloseRef, 2, "}}")
	case strings.HasPrefix(rest, "&&"):
		return tok(condTokAnd, 2, "&&")
	case strings.HasPrefix(rest, "||"):
		return tok(condTokOr, 2, "||")
	case strings.HasPrefix(rest, "=="):
		return tok(condTokCmp, 2, "=")
	case strings.HasPrefix(rest, "!="), strings.HasPrefix(rest, ">="), strings.HasPrefix(rest, "<="):
		return tok(condTokCmp, 2, rest[:2])
	}
	c := rest[0]
	switch c {
	case '(':
		return tok(condTokLParen, 1, "(")
	case ')':
		return tok(condTokRParen, 1, ")")
	case '!':
		return tok(condTokNot, 1, "!")
	case '|':
		return tok(condTokPipe, 1, "|")
	case '=', '>', '<':
		return tok(condTokCmp, 1, rest[:1])
	case '\'', '"':
		end := strings.IndexByte(rest[1:], c)
		if end < 0 {
			return condTok{}, fmt.Errorf("unterminated string at offset %d", start)
		}
		return tok(condTokString, end+2, rest[1:1+end])
	}
	if (c >= '0' && c <= '9') || (c == '-' && len(rest) > 1 && rest[1] >= '0' && rest[1] <= '9') {
		n := 1
		for n < len(rest) && rest[n] >= '0' && rest[n] <= '9' {
			n++
		}
		if n+1 < len(rest) && rest[n] == '.' && rest[n+1] >= '0' && rest[n+1] <= '9' {
			n++
			for n < len(rest) && rest[n] >= '0' && rest[n] <= '9' {
				n++
			}
		}
		if n < len(rest) && condIdentByte(rest[n]) {
			return condTok{}, fmt.Errorf("malformed number at offset %d", start)
		}
		return tok(condTokNumber, n, rest[:n])
	}
	if condIdentStart(c) {
		n := 1
		for n < len(rest) {
			if condIdentByte(rest[n]) {
				n++
				continue
			}
			// Bracket index: rows[0].
			if rest[n] == '[' {
				j := n + 1
				for j < len(rest) && rest[j] >= '0' && rest[j] <= '9' {
					j++
				}
				if j > n+1 && j < len(rest) && rest[j] == ']' {
					n = j + 1
					continue
				}
			}
			break
		}
		return tok(condTokIdent, n, rest[:n])
	}
	return condTok{}, fmt.Errorf("unexpected character %q at offset %d", c, start)
}

// pipeSegment reads one pipe (`default:'x'`, `length`) as source text, up
// to the next pipe, connective, comparison operator, closing paren or
// span end. Quoted text and balanced parentheses are part of the segment.
func (l *condLexer) pipeSegment() (string, error) {
	s := l.s
	start := l.pos
	depth := 0
	i := l.pos
scan:
	for i < len(s) {
		c := s[i]
		switch c {
		case '\'', '"':
			end := strings.IndexByte(s[i+1:], c)
			if end < 0 {
				return "", fmt.Errorf("unterminated string at offset %d", i)
			}
			i += end + 2
			continue
		case '(':
			depth++
		case ')':
			if depth == 0 {
				break scan
			}
			depth--
		case '|', '=', '<', '>':
			break scan
		case '&':
			if strings.HasPrefix(s[i:], "&&") {
				break scan
			}
		case '!':
			if strings.HasPrefix(s[i:], "!=") {
				break scan
			}
		case '}':
			if strings.HasPrefix(s[i:], "}}") {
				break scan
			}
		}
		i++
	}
	seg := strings.TrimSpace(s[start:i])
	if seg == "" {
		return "", fmt.Errorf("empty pipe at offset %d", start)
	}
	l.pos = i
	return seg, nil
}

type condParser struct {
	lex condLexer
	tok condTok
}

func (p *condParser) advance() error {
	t, err := p.lex.next()
	if err != nil {
		return err
	}
	p.tok = t
	return nil
}

func (p *condParser) parseOr(depth int) (*condExpr, error) {
	left, err := p.parseAnd(depth)
	if err != nil {
		return nil, err
	}
	for p.tok.kind == condTokOr {
		if err := p.advance(); err != nil {
			return nil, err
		}
		right, err := p.parseAnd(depth)
		if err != nil {
			return nil, err
		}
		left = &condExpr{kind: condOr, left: left, right: right}
	}
	return left, nil
}

func (p *condParser) parseAnd(depth int) (*condExpr, error) {
	left, err := p.parseCmp(depth)
	if err != nil {
		return nil, err
	}
	for p.tok.kind == condTokAnd {
		if err := p.advance(); err != nil {
			return nil, err
		}
		right, err := p.parseCmp(depth)
		if err != nil {
			return nil, err
		}
		left = &condExpr{kind: condAnd, left: left, right: right}
	}
	return left, nil
}

func (p *condParser) parseCmp(depth int) (*condExpr, error) {
	left, err := p.parseUnary(depth)
	if err != nil {
		return nil, err
	}
	if p.tok.kind != condTokCmp {
		return left, nil
	}
	op := p.tok.text
	if err := p.advance(); err != nil {
		return nil, err
	}
	right, err := p.parseUnary(depth)
	if err != nil {
		return nil, err
	}
	if p.tok.kind == condTokCmp {
		return nil, fmt.Errorf("chained comparison at offset %d: compare once, join with && or ||", p.tok.pos)
	}
	return &condExpr{kind: condCmp, op: op, left: left, right: right}, nil
}

func (p *condParser) parseUnary(depth int) (*condExpr, error) {
	if depth > condMaxDepth {
		return nil, fmt.Errorf("condition nests too deeply")
	}
	if p.tok.kind == condTokNot {
		if err := p.advance(); err != nil {
			return nil, err
		}
		inner, err := p.parseUnary(depth + 1)
		if err != nil {
			return nil, err
		}
		return &condExpr{kind: condNot, left: inner}, nil
	}
	return p.parsePrimary(depth)
}

func (p *condParser) parsePrimary(depth int) (*condExpr, error) {
	t := p.tok
	switch t.kind {
	case condTokLParen, condTokOpenRef:
		closer := condTokRParen
		if t.kind == condTokOpenRef {
			closer = condTokCloseRef
		}
		if err := p.advance(); err != nil {
			return nil, err
		}
		inner, err := p.parseOr(depth + 1)
		if err != nil {
			return nil, err
		}
		if p.tok.kind != closer {
			return nil, fmt.Errorf("unclosed %q from offset %d", t.text, t.pos)
		}
		return inner, p.advance()
	case condTokString, condTokNumber:
		return &condExpr{kind: condLit, lit: t.text}, p.advance()
	case condTokIdent:
		switch strings.ToLower(t.text) {
		case "true":
			return &condExpr{kind: condLit, lit: true}, p.advance()
		case "false":
			return &condExpr{kind: condLit, lit: false}, p.advance()
		case "null", "undefined":
			return &condExpr{kind: condLit, lit: nil}, p.advance()
		}
		ref := translateGHAExpr(t.text)
		// A pipe is read as source text straight after the '|', so peek
		// for it without tokenizing what follows.
		for {
			rest := strings.TrimLeft(p.lex.s[p.lex.pos:], " \t\r\n")
			if !strings.HasPrefix(rest, "|") || strings.HasPrefix(rest, "||") {
				break
			}
			p.lex.pos = len(p.lex.s) - len(rest) + 1
			seg, err := p.lex.pipeSegment()
			if err != nil {
				return nil, err
			}
			ref += " | " + seg
		}
		return &condExpr{kind: condRef, ref: ref}, p.advance()
	case condTokEOF:
		return nil, fmt.Errorf("condition ends where a value was expected")
	}
	return nil, fmt.Errorf("unexpected %q at offset %d", t.text, t.pos)
}
