//go:build !cli

package main

import (
	"net/http"
	"strings"
	"testing"
)

// A `run: respond` written with no `with:` answers 200 with an empty body and
// ends the run, so one left in front of a refusal turns the refusal into a
// 200. It is accepted (deployed files carry it) and warned about when the
// file is written, in `benmore check` and in the log when the file loads.
func TestRespondWithNoWithIsWarnedAbout(t *testing.T) {
	const head = "on:\n  request: { method: POST, path: /api/guard, auth: required }\njobs:\n  guard:\n    steps:\n"
	const refusal = "      - run: respond\n        with: { status: 403, json: { error: forbidden } }\n"
	const gate = "        if: ${{ params.a || '' }} == 'x'\n"
	const stray = head + "      - id: stray\n" + gate + "        run: respond\n" + refusal
	const warning = "has no `with:`, so it answers 200 with an empty body and ends the flow here; later steps do not run"

	// What the warning says is what happens.
	app, _ := auditApp(t)
	sid := createCrudScopeSession(t, app, "caller@example.com", "user", "", "")
	var flows []Flow
	logged := captureLog(t, func() { flows = notifyFlows(t, "flows/guard.yaml", stray) })
	if rr := respondShapeRun(t, app, &flows[0], sid, map[string]any{"a": "x"}); rr.Code != http.StatusOK || strings.TrimSpace(rr.Body.String()) != "" {
		t.Fatalf("the stray respond answered %d %q, want 200 with an empty body", rr.Code, rr.Body.String())
	}
	if want := `WARNING: flows/guard.yaml: job "guard" step steps[0] ("stray"): this ` + "`run: respond` " + warning; !strings.Contains(logged, want) {
		t.Errorf("loading the file logged no warning for the stray respond:\n%s", logged)
	}

	dir := t.TempDir()
	writeTestFile(t, dir, "app.yaml", "site_name: guard\n")
	warnings := func(report CheckReport) (out []string) {
		for _, f := range report.Findings {
			if strings.Contains(f.Message, warning) {
				if f.Severity != "warning" || f.Source != "flows" || f.File != "flows/guard.yaml" {
					t.Errorf("finding is not a flows warning on the file: %+v", f)
				}
				if got := checkFindingDocs(f); got != "flows.step_types" {
					t.Errorf("the warning is documented at %q, want flows.step_types", got)
				}
				out = append(out, f.Message)
			}
		}
		return out
	}
	for name, c := range map[string]struct {
		src  string
		want int
	}{
		"no with":                  {stray, 1},
		"empty with":               {head + "      -" + gate[7:] + "        run: respond\n        with: {}\n" + refusal, 1},
		"nested, with and without": {head + "      -" + gate[7:] + "        steps:\n          - run: respond\n" + "      - if: ${{ params.a || '' }} == 'y'\n        steps:\n          - run: respond\n            with: { status: 204 }\n" + refusal, 1},
		"status only":              {head + "      -" + gate[7:] + "        run: respond\n        with: { status: 204 }\n" + refusal, 0},
		"async (a no-op there)":    {strings.Replace(stray, "auth: required", "auth: required, mode: async", 1), 0},
	} {
		if msg := ValidateOnWriteIn(dir, "flows/guard.yaml", c.src); msg != "" {
			t.Fatalf("%s: the write gate refuses a flow shape deployed apps carry: %s", name, msg)
		}
		writeTestFile(t, dir, "flows/guard.yaml", c.src)
		for where, report := range map[string]CheckReport{
			"the post-write check of the flow file": RunSourceCheck(dir, "flows/guard.yaml"),
			"benmore check":                         RunSourceCheck(dir, ""),
		} {
			if got := warnings(report); len(got) != c.want {
				t.Errorf("%s, %s: %d warning(s), want %d: %q", name, where, len(got), c.want, got)
			}
			if report.Errors != 0 {
				t.Errorf("%s, %s reports %d error(s): %+v", name, where, report.Errors, report.Findings)
			}
		}
		if got := warnings(RunSourceCheck(dir, "app.yaml")); len(got) != 0 {
			t.Errorf("%s: a write of another file repeats the warning: %q", name, got)
		}
	}
}
