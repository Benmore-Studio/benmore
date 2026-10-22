//go:build !cli

package main

// Recipient lists for the `to:` of a flow `run: email` step and a hooks.yaml
// `email:` action.
//
// The mail senders (SendEmailOpts) read To as a comma list. `to:` is a
// template, and the values substituted into it are data - a column of the
// written row, a request field, a query result - so a value that contained a
// comma used to become several recipients. A public form's email field set
// to fifty addresses turned a one-recipient confirmation into fifty messages
// per request, each recipient seeing the others, on the app's own sender.
// The auth paths already refuse such addresses (validAuthEmail); this is the
// same rule for app-authored sends, in the framework's usual shape: a
// substituted value is an operand, never syntax.
//
// A `to:` therefore lists recipients in three ways only:
//
//   - commas the author wrote in the template: "{{owner}}, ops@example.org"
//   - an env value, which is the author's own configuration:
//     "{{env.ADMIN_EMAILS}}"
//   - a value the author marks as a list: "{{ team_emails | recipients }}"
//
// Any other substituted value that brings a comma with it fails the send
// with an error naming the template part.

import (
	"fmt"
	"regexp"
	"strings"
)

// emailListRefRe matches a template part that is exactly one reference whose
// last pipe is `recipients`; group 1 is the expression without that pipe.
var emailListRefRe = regexp.MustCompile(`^\{\{\s*(.*?)\s*\|\s*recipients\s*\}\}$`)

// emailRecipients renders a `to:` template part by part. render resolves one
// part exactly as the whole template was resolved before, so a template whose
// values each hold one address produces the same bytes as it always did.
func emailRecipients(template string, render func(part string) string) (string, error) {
	parts := splitRecipientTemplate(template)
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if m := emailListRefRe.FindStringSubmatch(trimmed); m != nil {
			// Keep the part's own surrounding whitespace.
			lead := part[:len(part)-len(strings.TrimLeft(part, " \t\r\n"))]
			trail := part[len(strings.TrimRight(part, " \t\r\n")):]
			out = append(out, lead+render("{{"+m[1]+"}}")+trail)
			continue
		}
		rendered := render(part)
		if expr, ok := soleFlowExpr(part); !(ok && flowExprIsEnvOnly(expr)) &&
			strings.Count(rendered, ",") > recipientLiteralCommas(part) {
			return "", fmt.Errorf("email to: %s resolved to more than one address; a `to:` value is one recipient - list recipients in the template, send one email per recipient (for_each), or mark a value that is meant to be a list with `| recipients`", trimmed)
		}
		out = append(out, rendered)
	}
	return strings.Join(out, ","), nil
}

// splitRecipientTemplate splits a `to:` template at the commas its author
// wrote as separators: outside `{{ }}` references and outside a quoted
// display name.
func splitRecipientTemplate(template string) []string {
	var parts []string
	start, depth, quoted := 0, 0, false
	for i := 0; i < len(template); i++ {
		switch {
		case strings.HasPrefix(template[i:], "{{"):
			depth++
			i++
		case depth > 0 && strings.HasPrefix(template[i:], "}}"):
			depth--
			i++
		case depth == 0 && template[i] == '"':
			quoted = !quoted
		case depth == 0 && !quoted && template[i] == ',':
			parts = append(parts, template[start:i])
			start = i + 1
		}
	}
	return append(parts, template[start:])
}

// recipientLiteralCommas counts the commas a template part carries in its own
// text (inside a quoted display name), not counting any inside a reference.
func recipientLiteralCommas(part string) int {
	n, depth := 0, 0
	for i := 0; i < len(part); i++ {
		switch {
		case strings.HasPrefix(part[i:], "{{"):
			depth++
			i++
		case depth > 0 && strings.HasPrefix(part[i:], "}}"):
			depth--
			i++
		case depth == 0 && part[i] == ',':
			n++
		}
	}
	return n
}

// hookEmailRecipients renders a hooks.yaml `email: to:` against the event row.
func hookEmailRecipients(template string, row map[string]any, appDir string) (string, error) {
	return emailRecipients(template, func(part string) string { return interpolateRow(part, row, appDir) })
}
