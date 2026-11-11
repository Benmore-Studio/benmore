//go:build !cli

package main

import "testing"

// A deployed flow whose contract the write gate would refuse still loads (the
// problem is only logged), so one stale key cannot unload the app's flows.
// `benmore test` refuses such a source before serving, so a fixture cannot
// reach this load path.
func TestFlowContractProblemDoesNotStopLoad(t *testing.T) {
	for name, contract := range map[string]string{
		"legacy scalar":   "contract: legacy-v1",
		"unknown key":     "contract: {nope: 1}",
		"unquoted status": "contract:\n      responses:\n        200: {type: object}",
	} {
		src := "name: f\non:\n  request:\n    method: POST\n    path: /api/f\n    " + contract + "\njobs:\n  main:\n    steps:\n      - run: respond\n        with: {json: {ok: true}}\n"
		flows, err := parseGHAFlowFile("flows/f.yaml", []byte(src))
		if err != nil || len(flows) != 1 {
			t.Fatalf("%s: flows=%d err=%v, want the flow loaded", name, len(flows), err)
		}
		if flows[0].Trigger.Contract != nil {
			t.Fatalf("%s: invalid contract kept: %v", name, flows[0].Trigger.Contract)
		}
	}
}
