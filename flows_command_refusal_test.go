//go:build !cli

package main

import (
	"strings"
	"testing"
)

func commandRefusalIf(status, body string) string {
	return "      - if: '${{ steps.item.outputs.first.id }} == x'\n        steps:\n          - run: respond\n            with: {status: " + status + ", json: " + body + "}\n"
}

func TestFlowCommandPrepareAcceptsOnlyLiteralRefusalRespond(t *testing.T) {
	tables := map[string]bool{"work_items": true}
	compile := func(source string) error {
		_, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(source), tables)
		return err
	}
	good := `{error: "Only an owner can complete items."}`
	for _, status := range []string{"400", "403", "404", "409", "422", "499"} {
		if err := compile(insertCommandPrepareSteps(t, commandFixture, commandRefusalIf(status, good))); err != nil {
			t.Fatalf("status %s refusal rejected: %v", status, err)
		}
	}
	unquoted := "      - if: ${{ steps.item.outputs.first.id }} == 0\n        steps:\n          - run: respond\n            with:\n              status: 403\n              json: " + good + "\n"
	if err := compile(insertCommandPrepareSteps(t, commandFixture, unquoted)); err != nil {
		t.Fatalf("documented unquoted form rejected: %v", err)
	}
	elseBranch := "      - if: '${{ steps.item.outputs.first.id }} == x'\n        steps:\n          - run: set\n            with: {seen: done}\n        else:\n          - run: respond\n            with: {status: 403, json: " + good + "}\n"
	if err := compile(insertCommandPrepareSteps(t, commandFixture, elseBranch)); err != nil {
		t.Fatalf("else-branch refusal rejected: %v", err)
	}
	bad := map[string]string{
		"2xx status":            commandRefusalIf("200", good),
		"3xx status":            commandRefusalIf("302", good),
		"5xx status":            commandRefusalIf("500", good),
		"401 challenge":         commandRefusalIf("401", good),
		"407 challenge":         commandRefusalIf("407", good),
		"templated message":     commandRefusalIf("403", `{error: "${{ params.arguments.id }}"}`),
		"mustache message":      commandRefusalIf("403", `{error: "hello {{ user.id }}"}`),
		"empty message":         commandRefusalIf("403", `{error: ""}`),
		"oversized message":     commandRefusalIf("403", `{error: "`+strings.Repeat("x", 501)+`"}`),
		"non-string message":    commandRefusalIf("403", `{error: 7}`),
		"extra body key":        commandRefusalIf("403", `{error: "no", detail: "x"}`),
		"wrong body key":        commandRefusalIf("403", `{message: "no"}`),
		"control character":     commandRefusalIf("403", `{error: "a\nb"}`),
		"templated status":      commandRefusalIf("'${{ params.arguments.id }}'", good),
		"refusal beside others": "      - if: '${{ steps.item.outputs.first.id }} == x'\n        steps:\n          - run: set\n            with: {seen: done}\n          - run: respond\n            with: {status: 403, json: " + good + "}\n",
		"bare top-level":        "      - run: respond\n        with: {status: 403, json: " + good + "}\n",
		"inside for_each":       "      - for_each: params.arguments.items\n        as: row\n        steps:\n          - run: respond\n            with: {status: 403, json: " + good + "}\n",
	}
	for name, steps := range bad {
		t.Run("prepare "+name, func(t *testing.T) {
			if err := compile(insertCommandPrepareSteps(t, commandFixture, steps)); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
	// Apply and readback keep the final-step-only rule.
	refusal := "      - if: '${{ params.arguments.id }} == x'\n        steps:\n          - run: respond\n            with: {status: 403, json: " + good + "}\n"
	for phase, marker := range map[string]string{
		"apply":    "      - run: respond\n        with: {status: 200, json: {ok: true}}",
		"readback": "      - run: respond\n        with: {status: 200, json: {items: '${{ steps.item.outputs }}'}}",
	} {
		source := replaceCommandPhaseTextOnce(t, commandFixture, phase, marker, refusal+marker)
		if err := compile(source); err == nil {
			t.Fatalf("%s accepted a refusal respond", phase)
		}
	}
}

func TestFlowCommandRefusalInsideLoopIsRefusedAtCompile(t *testing.T) {
	source := strings.Replace(commandFixture,
		"          id: {type: string, maxLength: 64}\n        required: [id]",
		"          id: {type: string, maxLength: 64}\n          items: {type: array, maxItems: 2, items: {type: object, additionalProperties: false, properties: {id: {type: string, maxLength: 64}}, required: [id]}}\n        required: [id]", 1)
	good := `{error: "Not allowed."}`
	tables := map[string]bool{"work_items": true}
	// The same loop without a respond compiles, so the rejections below are
	// the respond's doing.
	plain := "      - for_each: params.arguments.items\n        as: row\n        steps:\n          - run: set\n            with: {seen: '${{ row.id }}'}\n"
	if _, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(insertCommandPrepareSteps(t, source, plain)), tables); err != nil {
		t.Fatalf("baseline loop rejected: %v", err)
	}
	for name, body := range map[string]string{
		"if in loop":     "          - if: '${{ row.id }} == x'\n            steps:\n              - run: respond\n                with: {status: 403, json: " + good + "}\n",
		"else in loop":   "          - if: '${{ row.id }} == x'\n            steps:\n              - run: set\n                with: {seen: done}\n            else:\n              - run: respond\n                with: {status: 403, json: " + good + "}\n",
		"nested loop if": "          - for_each: params.arguments.items\n            as: inner\n            steps:\n              - if: '${{ inner.id }} == x'\n                steps:\n                  - run: respond\n                    with: {status: 403, json: " + good + "}\n",
		"bare in loop":   "          - run: respond\n            with: {status: 403, json: " + good + "}\n",
	} {
		steps := "      - for_each: params.arguments.items\n        as: row\n        steps:\n" + body
		_, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(insertCommandPrepareSteps(t, source, steps)), tables)
		if err == nil || !strings.Contains(err.Error(), "for_each loop") {
			t.Errorf("%s: want a loop-refusal error, got %v", name, err)
		}
	}
}
