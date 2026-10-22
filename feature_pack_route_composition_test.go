//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFeatureInstallComposesCustomRoutesWithModelTransforms(t *testing.T) {
	const route = "/api/handoffs/:id/complete"
	for _, tc := range []struct {
		name, wantRoute, wantTable string
		opts                       FeatureInstallOptions
	}{
		{"model prefix", route, "ops_handoffs", FeatureInstallOptions{ModelPrefix: "Ops"}},
		{"combined prefixes", "/api/ops/handoffs/:id/complete", "ops_handoffs", FeatureInstallOptions{RoutePrefix: "ops", ModelPrefix: "Ops"}},
		{"exact maps", "/api/archive/handoffs/:id/finish", "archived_handoffs", FeatureInstallOptions{RouteMap: map[string]string{route: "/api/archive/handoffs/:id/finish"}, ModelMap: map[string]string{"Handoff": "ArchivedHandoff"}}},
		{"route prefix", "/api/ops/handoffs/:id/complete", "handoffs", FeatureInstallOptions{RoutePrefix: "ops"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			flow := []byte(`on:
  request:
    method: POST
    path: /api/handoffs/:id/complete
    auth: required
jobs:
  complete:
    steps:
      - run: sql
        query: UPDATE handoffs SET status = 'complete' WHERE id = :id AND owner_id = :user_id
        expect_rows: "=1"
      - run: respond
        with:
          body: {ok: true}
`)
			page := []byte(`export const complete = '/api/handoffs/:id/complete'; export const preview = '/api/handoffs/:id/complete?preview=1'; export const crud = '/api/handoffs'; export const table = 'handoffs';`)
			files := map[string][]byte{"flows/complete.yaml": flow, "static/handoffs.tsx": page}
			pack := FeaturePack{Name: "Handoffs", Slug: "handoffs", Routes: []string{route}, SchemaModels: []FeaturePackModel{curatedModel("Handoff", `model Handoff {
  id Int @id @default(autoincrement())
  owner_id Int
  status String
}`)}}
			for p, b := range files {
				pack.Files = append(pack.Files, FeaturePackFile{Path: p, SHA256: hashBytesSHA256(b), Size: int64(len(b))})
			}
			preview, err := PlanFeatureInstallWithOptions(dir, pack, files, tc.opts)
			if err != nil || preview.Blocked {
				t.Fatalf("preview: %#v, %v", preview, err)
			}
			plan, err := ApplyFeaturePackToDirWithOptions(dir, pack, files, tc.opts)
			if err != nil || plan.Blocked {
				t.Fatalf("install: %#v, %v", plan, err)
			}
			for _, p := range []FeatureInstallPlan{preview, plan} {
				if tc.wantRoute == route {
					if len(p.RouteRenames) != 0 {
						t.Fatalf("model-only install advertised route renames: %#v", p.RouteRenames)
					}
				} else if len(p.RouteRenames) != 1 || p.RouteRenames[0] != (FeaturePackRename{From: route, To: tc.wantRoute}) {
					t.Fatalf("advertised routes: %#v", p.RouteRenames)
				}
			}
			flows := LoadFlowsGHA(dir)
			if len(flows) != 1 || flows[0].Trigger.Path != tc.wantRoute {
				t.Fatalf("installed route does not match preview: %#v", flows)
			}
			if flows[0].Auth != "required" || len(flows[0].Steps) != 2 || !strings.Contains(flows[0].Steps[0].SQL, "UPDATE "+tc.wantTable+" SET") || !strings.Contains(flows[0].Steps[0].SQL, "owner_id = :user_id") || flows[0].Steps[0].ExpectRows != "=1" {
				t.Fatalf("flow SQL/auth contract changed: %#v", flows[0])
			}
			pagePath := "static/handoffs.tsx"
			for _, rename := range plan.FileRenames {
				if rename.From == pagePath {
					pagePath = rename.To
					break
				}
			}
			b, err := os.ReadFile(filepath.Join(dir, pagePath))
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"complete = '" + tc.wantRoute + "'", "preview = '" + tc.wantRoute + "?preview=1'", "crud = '/api/" + tc.wantTable + "'", "table = '" + tc.wantTable + "'"} {
				if !strings.Contains(string(b), want) {
					t.Errorf("installed page missing %q: %s", want, b)
				}
			}
		})
	}
}

func TestFeatureRouteRewriteUsesOriginalLiteralsOnce(t *testing.T) {
	tokens := map[string]string{"handoffs": "ops_handoffs"}
	routes := map[string]string{
		"/handoffs": "/archive/handoffs", "/archive/handoffs": "/done",
		"/api/handoffs": "/api/ops/handoffs", "/api/handoffs/complete": "/api/ops/handoffs/finish",
	}
	input := `'/handoffs' '/archive/handoffs' '/api/handoffs/complete?preview=1' '/api/handoffs' '/handoffs-more' '/api/handoffs-other' SELECT * FROM handoffs;`
	want := `'/archive/handoffs' '/done' '/api/ops/handoffs/finish?preview=1' '/api/ops/handoffs' '/ops_handoffs-more' '/api/ops_handoffs-other' SELECT * FROM ops_handoffs;`
	if got := rewriteFeaturePackText(input, tokens, routes); got != want {
		t.Fatalf("route replacements must not consume model renames or each other:\n got %s\nwant %s", got, want)
	}
	// A route declaration does not make arbitrary JavaScript concatenation an
	// exact route literal. Keep the existing token-only behavior in that case.
	dynamic := `'/api/handoffs/' + id + '/complete'`
	if got := rewriteFeaturePackText(dynamic, tokens, map[string]string{"/api/handoffs/:id/complete": "/api/ops/handoffs/:id/complete"}); got != `'/api/ops_handoffs/' + id + '/complete'` {
		t.Fatalf("unexpected inference for a dynamic URL: %s", got)
	}
	// Manifest route strings are literal input. Even a non-UTF-8 declaration
	// cannot make processing an unrelated valid text file panic.
	if got := rewriteFeaturePackText("SELECT * FROM handoffs", tokens, map[string]string{"/api/\xff": "/ignored"}); got != "SELECT * FROM ops_handoffs" {
		t.Fatalf("malformed unrelated route changed table rewriting: %s", got)
	}
}
