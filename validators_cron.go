//go:build !cli

package main

// cron.yaml entries decode into structs, and yaml.v3 drops keys a struct
// doesn't declare, so `enabled: false` (the job kept running), `timezone:`
// (schedules stay in the server's local zone), `max_attempt:` or `retries:` (the
// job stayed at-most-once) parsed clean and did nothing. The write gate and
// `benmore check` refuse unknown job keys; a deployed file still loads and
// each problem is logged.

import (
	"fmt"
	"log"
	"maps"
	"slices"
	"strings"
)

var (
	cronMapEntryKeys = yamlStructKeys(cronMapEntry{})
	cronJobListKeys  = yamlStructKeys(cronJobYAML{})
	// Inline cron steps use the legacy step shape (FlowStepYAML).
	cronStepKeys       = yamlStructKeys(FlowStepYAML{})
	cronStepObjectKeys = map[string]map[string]bool{
		"api":     yamlStructKeys(FlowAPIYAML{}),
		"email":   yamlStructKeys(FlowEmailYAML{}),
		"respond": yamlStructKeys(FlowRespondYAML{}),
		"ws":      yamlStructKeys(FlowWSYAML{}),
		"enqueue": yamlStructKeys(FlowEnqueueYAML{}),
	}
)

var cronStepKeyHints = map[string]string{
	"when":        "(use `if:`; an ignored guard means the step always runs)",
	"id":          "(use `name:`)",
	"query":       "(use `sql:`)",
	"run":         "(inline cron steps use the legacy keys such as `sql:`; write run/with steps in a flows.yaml flow and reference it with `flow:`)",
	"with":        "(inline cron steps use the legacy keys such as `sql:`; write run/with steps in a flows.yaml flow and reference it with `flow:`)",
	"expect_rows": "(not available in inline cron steps; put the step in a flows.yaml flow and reference it with `flow:`)",
	"params":      "(not available in inline cron steps; put the step in a flows.yaml flow and reference it with `flow:`)",
}

// cronStepProblems checks one inline step list, recursing into nested ones.
func cronStepProblems(where string, raw any) []string {
	list, _ := raw.([]any)
	var problems []string
	for i, item := range list {
		step, _ := item.(map[string]any)
		at := fmt.Sprintf("%s[%d]", where, i)
		for _, key := range sortedWhenKeys(step) {
			if !cronStepKeys[key] {
				msg := fmt.Sprintf("cron.yaml %s: unknown step key %q; the scheduler ignores it", at, key)
				if hint := cronStepKeyHints[key]; hint != "" {
					msg += " " + hint
				}
				problems = append(problems, msg+".")
				continue
			}
			if valid, ok := cronStepObjectKeys[key]; ok {
				obj, _ := step[key].(map[string]any)
				for _, sub := range sortedWhenKeys(obj) {
					if !valid[sub] {
						problems = append(problems, fmt.Sprintf("cron.yaml %s.%s: unknown key %q (valid: %s); the scheduler ignores it.", at, key, sub, strings.Join(slices.Sorted(maps.Keys(valid)), ", ")))
					}
				}
			}
		}
		for _, nested := range []string{"steps", "else", "on_error"} {
			problems = append(problems, cronStepProblems(at+"."+nested, step[nested])...)
		}
	}
	return problems
}

var cronKeyHints = map[string]string{
	"enabled":     "(there is no switch: remove the job, or comment it out, to stop it)",
	"disabled":    "(there is no switch: remove the job, or comment it out, to stop it)",
	"timezone":    "(schedules are evaluated in the server process's local time zone)",
	"tz":          "(schedules are evaluated in the server process's local time zone)",
	"cron":        "(use `schedule:`)",
	"every":       "(use `schedule: \"every 15m\"`)",
	"retries":     "(use `max_attempts:`)",
	"max_attempt": "(use `max_attempts:`)",
	"max_retries": "(use `max_attempts:`)",
	"attempts":    "(use `max_attempts:`)",
	"query":       "(use `sql:` for a one-line query)",
	"transaction": "(declare `transaction: true` on the flow a `flow:` job runs)",
	"flow_name":   "(use `flow:`)",
	"description": "(use a YAML comment)",
}

// cronShapeProblems lists cron.yaml job keys the loader ignores.
func cronShapeProblems(content string) []string {
	var shape map[string]any
	if err := decodeConfigYAML([]byte(content), &shape); err != nil || len(shape) == 0 {
		return nil // parseCronYAML reports syntax and shape errors
	}
	var problems []string
	check := func(where string, entry map[string]any, valid map[string]bool) {
		for _, nested := range []string{"run", "steps"} {
			problems = append(problems, cronStepProblems(where+"."+nested, entry[nested])...)
		}
		for _, key := range sortedWhenKeys(entry) {
			if valid[key] {
				continue
			}
			msg := fmt.Sprintf("cron.yaml %s: unknown key %q (valid: %s); the scheduler ignores it", where, key, strings.Join(slices.Sorted(maps.Keys(valid)), ", "))
			if hint := cronKeyHints[key]; hint != "" {
				msg += " " + hint
			}
			problems = append(problems, msg+".")
		}
	}
	if list, ok := shape["jobs"].([]any); ok {
		for i, item := range list {
			entry, _ := item.(map[string]any)
			name := fmt.Sprintf("jobs[%d]", i)
			if id, ok := entry["id"].(string); ok && id != "" {
				name = fmt.Sprintf("jobs[%d] (%s)", i, id)
			}
			check(name, entry, cronJobListKeys)
		}
		return problems
	}
	for _, name := range sortedWhenKeys(shape) {
		entry, _ := shape[name].(map[string]any)
		check(name, entry, cronMapEntryKeys)
	}
	return problems
}

// warnCronShape logs, at load, each ignored key in a deployed cron.yaml.
func warnCronShape(content []byte) {
	for _, p := range cronShapeProblems(string(content)) {
		log.Printf("WARNING: %s", p)
	}
}
