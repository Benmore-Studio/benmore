//go:build !cli

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

// Human-facing review fields of a command tool (#770): title, review_summary,
// labels and review_changes in mcp.yaml. They are reviewed content, so they are
// part of the contract digest; every field is omitempty in the canonical JSON,
// so a manifest that declares none keeps the digest it was reviewed under.

const (
	appMCPReviewTitleMax   = 80
	appMCPReviewSummaryMax = 500
	appMCPReviewLabelMax   = 60
	appMCPReviewLabelsMax  = 64
	appMCPReviewChangesMax = 16
)

// AppMCPReviewPair names the preview keys that hold one field's current and
// proposed value, for an app whose prepare step returns a flat preview such as
// {field, old_value, new_value}. Exactly one of Label (a fixed row label) and
// Field (a preview key whose value names the field being changed) is set.
type AppMCPReviewPair struct {
	Before string `yaml:"before" json:"Before"`
	After  string `yaml:"after" json:"After"`
	Field  string `yaml:"field,omitempty" json:"Field,omitempty"`
	Label  string `yaml:"label,omitempty" json:"Label,omitempty"`
}

var (
	appMCPReviewKey      = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$`)
	appMCPReviewPreviewK = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
)

// appMCPHiddenRune is a character that renders invisibly or reorders the text
// around it (bidi controls, zero-width and other format characters, variation
// selectors, fillers, control and non-ASCII space characters). A plain space is
// visible, so it is not hidden.
func appMCPHiddenRune(r rune) bool {
	return r != ' ' && (unicode.IsSpace(r) || r == '⠀' ||
		unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp, unicode.Variation_Selector, unicode.Other_Default_Ignorable_Code_Point))
}

func appMCPWriteEscaped(out *strings.Builder, r rune) {
	for _, unit := range utf16.Encode([]rune{r}) {
		fmt.Fprintf(out, `\u%04x`, unit)
	}
}

// appMCPReviewText is a string shown as it will be written: every hidden
// character (a newline too) becomes its \u escape, and a literal backslash
// before "u" is doubled so typed text can never read as such an escape.
func appMCPReviewText(s string) string {
	var out strings.Builder
	runes := []rune(s)
	for i, r := range runes {
		switch {
		case appMCPHiddenRune(r):
			appMCPWriteEscaped(&out, r)
		case r == '\\' && i+1 < len(runes) && runes[i+1] == 'u':
			out.WriteString(`\\`)
		default:
			out.WriteRune(r)
		}
	}
	return out.String()
}

// appMCPReviewValueText is the display text of one decoded preview value:
// strings as written, numbers plain, booleans Yes/No, null a dash, nested
// values compact JSON, all escaped like appMCPReviewPreviewText.
func appMCPReviewValueText(value any) string {
	switch v := value.(type) {
	case nil:
		return "—"
	case string:
		return appMCPReviewText(v)
	case bool:
		if v {
			return "Yes"
		}
		return "No"
	case json.Number:
		if n, ok := appMCPExactNumber(v); ok {
			if n.IsInt() {
				return n.Num().String()
			}
			return appMCPReviewText(v.String()) // exact: a float would round what is shown, not what is applied
		}
		return appMCPReviewText(v.String())
	}
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if encoder.Encode(value) != nil {
		return "—"
	}
	var out strings.Builder
	for _, r := range strings.TrimSuffix(buf.String(), "\n") {
		if appMCPHiddenRune(r) {
			appMCPWriteEscaped(&out, r)
		} else {
			out.WriteRune(r)
		}
	}
	return out.String()
}

// appMCPHumanizeKey turns "project_status" into "Project status".
func appMCPHumanizeKey(key string) string {
	text := strings.Join(strings.Fields(strings.NewReplacer("_", " ", "-", " ", ".", " ").Replace(key)), " ")
	if text == "" {
		return key
	}
	first, size := utf8.DecodeRuneInString(text)
	return string(unicode.ToUpper(first)) + text[size:]
}

func validateAppMCPReviewText(name, value string, max int) error {
	if value != strings.TrimSpace(value) {
		return fmt.Errorf("%s must not start or end with whitespace", name)
	}
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) > max {
		return fmt.Errorf("%s must be valid text of at most %d characters", name, max)
	}
	for _, r := range value {
		if appMCPHiddenRune(r) {
			return fmt.Errorf("%s contains a control, invisible or direction-changing character (U+%04X)", name, r)
		}
	}
	return nil
}

// validateAppMCPReviewFields checks the shape of a tool's review fields. Which
// preview and input names exist is checked with the flow (validateAppMCPReviewBindings).
func validateAppMCPReviewFields(tool AppMCPTool, commandTool bool) error {
	if tool.Title == "" && tool.ReviewSummary == "" && len(tool.Labels) == 0 && len(tool.ReviewChanges) == 0 {
		return nil
	}
	if !commandTool {
		return fmt.Errorf("title, review_summary, labels and review_changes apply only to flow command tools, which a person reviews")
	}
	if tool.Title != "" {
		if err := validateAppMCPReviewText("title", tool.Title, appMCPReviewTitleMax); err != nil {
			return err
		}
	}
	if tool.ReviewSummary != "" {
		if err := validateAppMCPReviewText("review_summary", tool.ReviewSummary, appMCPReviewSummaryMax); err != nil {
			return err
		}
	}
	if len(tool.Labels) > appMCPReviewLabelsMax {
		return fmt.Errorf("labels declares more than %d entries", appMCPReviewLabelsMax)
	}
	for key, label := range tool.Labels {
		if !appMCPReviewKey.MatchString(key) {
			return fmt.Errorf("labels key %q is not a plain name", key)
		}
		if strings.TrimSpace(label) == "" {
			return fmt.Errorf("labels[%s] is empty", key)
		}
		if err := validateAppMCPReviewText("labels["+key+"]", label, appMCPReviewLabelMax); err != nil {
			return err
		}
	}
	if len(tool.ReviewChanges) > appMCPReviewChangesMax {
		return fmt.Errorf("review_changes declares more than %d entries", appMCPReviewChangesMax)
	}
	used := map[string]bool{}
	for i, pair := range tool.ReviewChanges {
		for _, key := range []string{pair.Before, pair.After, pair.Field} {
			if key == "" {
				continue
			}
			if !appMCPReviewPreviewK.MatchString(key) || used[key] {
				return fmt.Errorf("review_changes[%d] key %q is not a plain preview key or is used twice", i, key)
			}
			used[key] = true
		}
		if pair.Before == "" || pair.After == "" || (pair.Field == "") == (pair.Label == "") {
			return fmt.Errorf("review_changes[%d] requires before, after and exactly one of field or label", i)
		}
		if pair.Label != "" {
			if err := validateAppMCPReviewText(fmt.Sprintf("review_changes[%d].label", i), pair.Label, appMCPReviewLabelMax); err != nil {
				return err
			}
		}
	}
	return nil
}

// appMCPReviewLabelKeys are the names a label may be declared for: the intent's
// argument properties, the preview's properties and, for a review_changes
// entry driven by a field key, the enum values that field can name.
func appMCPReviewLabelKeys(tool AppMCPTool, preview *AppMCPSchema) map[string]bool {
	keys := map[string]bool{}
	var inputs []*AppMCPSchema
	if tool.InputSchema != nil {
		inputs = append(inputs, tool.InputSchema)
		if args := tool.InputSchema.Properties["arguments"]; args != nil {
			inputs = append(inputs, args)
		}
	}
	for _, schema := range inputs {
		for name := range schema.Properties {
			keys[name] = true
		}
	}
	if preview != nil {
		for name := range preview.Properties {
			keys[name] = true
		}
	}
	for _, pair := range tool.ReviewChanges {
		if pair.Field == "" {
			continue
		}
		var sources []*AppMCPSchema
		if preview != nil {
			sources = append(sources, preview.Properties[pair.Field])
		}
		for _, schema := range inputs {
			sources = append(sources, schema.Properties[pair.Field])
		}
		for _, schema := range sources {
			if schema == nil {
				continue
			}
			for _, value := range schema.Enum {
				if s, ok := value.(string); ok {
					keys[s] = true
				}
			}
		}
	}
	return keys
}

// validateAppMCPReviewBindings checks the review fields against the command's
// declared preview and the tool's input schema.
func validateAppMCPReviewBindings(tool AppMCPTool, command *FlowCommand) error {
	if len(tool.Labels) == 0 && len(tool.ReviewChanges) == 0 {
		return nil
	}
	if command == nil || command.PreviewSchema == nil {
		return fmt.Errorf("review fields need the command's preview_schema")
	}
	properties := command.PreviewSchema.Properties
	for i, pair := range tool.ReviewChanges {
		for _, key := range []string{pair.Before, pair.After} {
			if properties[key] == nil {
				return fmt.Errorf("review_changes[%d] names %q, which preview_schema does not declare", i, key)
			}
		}
		if pair.Field != "" && (properties[pair.Field] == nil || properties[pair.Field].Type != "string") {
			return fmt.Errorf("review_changes[%d] field %q must be a string property of preview_schema", i, pair.Field)
		}
	}
	allowed := appMCPReviewLabelKeys(tool, command.PreviewSchema)
	for key := range tool.Labels {
		if !allowed[key] {
			return fmt.Errorf("labels key %q names no declared input property, preview key or field value", key)
		}
	}
	return nil
}

// appMCPReviewChanges builds the labelled rows of a sealed preview. Plain keys
// become After-only rows (a create); a key whose preview_schema declares an
// object with exactly before and after, and each review_changes entry, become
// before to after rows. Every Before comes from the prepared preview, which the
// command's own prepare step read on the server and the operation digest seals;
// nothing is read again at review time.
func appMCPReviewChanges(tool *AppMCPTool, schema *AppMCPSchema, preview map[string]any) []appMCPReviewChange {
	label := func(key string) string {
		if declared := tool.Labels[key]; declared != "" {
			return appMCPReviewText(declared)
		}
		return appMCPReviewText(appMCPHumanizeKey(key))
	}
	consumed := map[string]bool{}
	for _, pair := range tool.ReviewChanges {
		consumed[pair.Before], consumed[pair.After], consumed[pair.Field] = true, true, true
	}
	keys := make([]string, 0, len(preview))
	for key := range preview {
		if !consumed[key] {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	var rows []appMCPReviewChange
	for _, key := range keys {
		row := appMCPReviewChange{Label: label(key)}
		var declared *AppMCPSchema
		if schema != nil {
			declared = schema.Properties[key]
		}
		if object, ok := preview[key].(map[string]any); ok && declared != nil && declared.Type == "object" && len(declared.Properties) == 2 &&
			declared.Properties["before"] != nil && declared.Properties["after"] != nil && len(object) == 2 {
			before, hasBefore := object["before"]
			after, hasAfter := object["after"]
			if hasBefore && hasAfter {
				row.Before, row.After = appMCPReviewValueText(before), appMCPReviewValueText(after)
				row.Changed = row.Before != row.After
				rows = append(rows, row)
				continue
			}
		}
		// A plain preview value has no before: it is context or a new value, never
		// "changed". An empty one stays (the template shows "(empty)"): it may be
		// a field being cleared, which the approver must see.
		row.After = appMCPReviewValueText(preview[key])
		rows = append(rows, row)
	}
	for _, pair := range tool.ReviewChanges {
		row := appMCPReviewChange{Before: appMCPReviewValueText(preview[pair.Before]), After: appMCPReviewValueText(preview[pair.After])}
		if pair.Label != "" {
			row.Label = appMCPReviewText(pair.Label)
		} else if name, ok := preview[pair.Field].(string); ok && name != "" {
			row.Label = label(name)
		} else {
			row.Label = label(pair.Field)
		}
		row.Changed = row.Before != row.After
		rows = append(rows, row)
	}
	return rows
}

// appMCPApprovalReason says, in a fixed phrase, why a connector call was
// prepared for a person instead of applied. It reads only what the grant holder
// already knows: its own consent list, the owner's auto-approve switch (the
// holder can see it in the app) and the reviewed manifest. Empty when the call
// is eligible or is not a connector call. It never decides anything: _commit
// still re-checks every condition.
func appMCPApprovalReason(cap *appMCPCommandCapability) string {
	if cap == nil || cap.tool == nil || cap.origin != appMCPCommandConnectorOrigin || cap.originPin == nil || appMCPAutoApproveEligible(cap) {
		return ""
	}
	switch {
	case cap.tool.Approval != "grant" || cap.tool.Transfer != nil:
		return "This kind of change always needs your approval"
	case !cap.autoApproveOwnerOn:
		return "Auto-approve is turned off for this app"
	}
	ticked := slices.ContainsFunc(cap.autoApproveTools, func(entry string) bool { return appMCPAutoApproveDisplayName(entry) == cap.tool.Name })
	switch {
	case !ticked:
		// Fixed text: a title is up to 80 runes, which can exceed the sealed
		// record's 256-byte cap and would refuse every prepare of the tool.
		return "This connection was not allowed to auto-approve this kind of change"
	case !cap.autoApproveLive:
		return "Auto-approve was switched off and on since you connected; reconnect to re-enable it"
	}
	return "The app's tools changed since you connected; reconnect the assistant to re-enable auto-approve"
}
