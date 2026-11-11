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
				// An inline enqueue step's payload, as in a flow file
				// (enqueueValueProblems): the identity names are never queued.
				if key == "enqueue" {
					payload, _ := obj["with"].(map[string]any)
					for _, name := range sortedWhenKeys(payload) {
						if flowJobIdentityKey(name) {
							problems = append(problems, fmt.Sprintf("cron.yaml %s.enqueue: %s", at, flowJobIdentityKeyProblem("with."+name)))
						}
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

// cronFlowRefProblems lists cron jobs whose `flow:` names no flow the app
// loads. The scheduler looks the flow up each time the job fires and fails
// that run ("flow not found"), so a misspelled or removed flow passed the
// write gate and failed every run, visible only in the journal. Write gate
// and `benmore check` (app dir known); flows that do not load are reported
// by their own validator, so the check is skipped then.
func cronFlowRefProblems(appDir string, cfg *CronConfig) []string {
	var problems []string
	for _, m := range cronFlowRefMissing(appDir, cfg) {
		problems = append(problems, m.message)
	}
	return problems
}

// cronFlowRef is one cron job naming a flow the app does not define.
type cronFlowRef struct {
	flow, message string
}

// cronFlowRefMissing is cronFlowRefProblems with the missing flow's name kept,
// for the check after a flow write (cronFlowRefFindingsAfterWrite).
func cronFlowRefMissing(appDir string, cfg *CronConfig) []cronFlowRef {
	if appDir == "" || cfg == nil {
		return nil
	}
	var named []CronJob
	for _, j := range cfg.Jobs {
		if j.Flow != "" {
			named = append(named, j)
		}
	}
	if len(named) == 0 {
		return nil
	}
	flows, err := loadFlowsChecked(appDir, true)
	if err != nil {
		return nil
	}
	defined := make(map[string]bool, len(flows))
	for _, f := range flows {
		defined[f.Name] = true
	}
	known := slices.Sorted(maps.Keys(defined))
	if len(known) > 20 {
		known = append(known[:20], "...")
	}
	var problems []cronFlowRef
	for _, j := range named {
		if defined[j.Flow] {
			continue
		}
		msg := fmt.Sprintf("cron.yaml %s: flow %q is not defined, so every run of this job would fail with \"flow not found\".", j.ID, j.Flow)
		if len(known) > 0 {
			msg += " Defined flows: " + strings.Join(known, ", ") + "."
		} else {
			msg += " The app has no flows yet."
		}
		msg += " A flow is named after its file (flows/<name>.yaml with one job) or its job key (flows.yaml). Push the flow first, then cron.yaml (`benmore push` and `benmore deploy` order them that way)."
		problems = append(problems, cronFlowRef{flow: j.Flow, message: msg})
	}
	return problems
}

// warnCronFlowRefs logs, at load, each cron job whose flow the app does not
// define (the write gate refuses these; a deployed file still loads).
func warnCronFlowRefs(app *App) {
	if app == nil || app.Cron == nil {
		return
	}
	defined := make(map[string]bool, len(app.Flows))
	for _, f := range app.Flows {
		defined[f.Name] = true
	}
	for _, j := range app.Cron.Jobs {
		if j.Flow != "" && !defined[j.Flow] {
			log.Printf("WARNING: cron.yaml %s: flow %q is not defined; every run of this job fails until it is", j.ID, j.Flow)
		}
	}
}
