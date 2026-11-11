//go:build !cli

package main

// referenceGenerators are the values of the reference that code builds, by
// address. A topic's _topic.json lists each under "generated" and holds no
// file for it, so the value cannot differ from the table or guide it is
// rendered from: the flow tables come from the lists the flow validator
// checks against, and the harness guide keys are sections of the bundled
// guide (`benmore docs harness`).
//
// To add one: write the function, register its address here, and list the
// path under "generated" in docs/reference/<topic>/_topic.json (and the key
// under "keys" when it is a key of the topic). The loader refuses a listed
// path with no generator and a generator no file lists.
var referenceGenerators = referenceGeneratorTable()

func referenceGeneratorTable() map[string]func() any {
	table := map[string]func() any{
		"flows.checked_values":       func() any { return flowCheckedValuesReference() },
		"flows.identity_step_ids":    func() any { return flowIdentityStepIDsReference() },
		"flows.missing_values":       func() any { return flowMissingValuesReference() },
		"flows.respond_headers.rule": func() any { return flowRespondHeadersRuleReference() },
		"flows.step_keys":            func() any { return flowStepKeysReference() },
		"harness.guide":              func() any { return harnessGuideOverview() },
	}
	for _, section := range harnessGuideSections {
		table["harness."+section.key] = func() any { return harnessGuideSection(section.key) }
	}
	return table
}
