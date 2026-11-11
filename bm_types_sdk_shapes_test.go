//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// sdkShapesApp is a multi-tenant app shaped like the Round 2 build: a
// kebab-named flow file, a workflow, tenant roles and a role_field.
func sdkShapesApp() *App {
	return &App{
		Tables: []Table{
			{Name: "bookings", Columns: []Column{
				{Name: "id", Type: "INTEGER", PK: true, NotNull: true},
				{Name: "starts_at", Type: "DATETIME", NotNull: true},
				{Name: "status", Type: "TEXT", NotNull: true},
				{Name: "studio_id", Type: "INTEGER"},
				{Name: "user_id", Type: "INTEGER"},
			}},
			{Name: "_benmore_users", Columns: []Column{
				{Name: "id", Type: "INTEGER", PK: true, NotNull: true},
				{Name: "email", Type: "TEXT", NotNull: true},
				{Name: "role", Type: "TEXT", NotNull: true},
				// A signup field that shares the name the profile uses for
				// the tenant must not become a second (conflicting) member.
				{Name: "group_id", Type: "TEXT"},
			}},
		},
		Flows: []Flow{
			{Name: "save-quote", Trigger: FlowTrigger{Type: "http", Method: "POST", Path: "/api/quote", Inputs: map[string]FlowInput{"hours": {Type: "number"}}}},
			{Name: "add_member", Role: "owner", Trigger: FlowTrigger{Type: "http", Path: "/api/members"}},
			{Name: "nightly", Trigger: FlowTrigger{Type: "cron", Cron: "every 24h"}},
		},
		Workflows: &WorkflowConfig{Workflows: map[string]*Workflow{
			"bookings": {Table: "bookings", Field: "status", Initial: "requested", States: []string{"requested", "confirmed"},
				Transitions: map[string]map[string]Transition{"requested": {"confirmed": {Role: "staff"}}}},
		}},
		Group: &GroupConfig{Table: "studio_members", Key: "studio_id", UserField: "user_id", RoleField: "member_role",
			Bootstrap: &GroupBootstrapConfig{OrgTable: "studios", FoundingRole: "founder"}},
		Access: &AccessConfig{rules: map[string]map[AccessOp]string{
			"services": {OpWrite: "role:staff,front_desk"},
			"bookings": {OpRead: "owner_or_role:manager"},
		}},
	}
}

// B3: flows/save-quote.yaml registered as 'save-quote', so the documented
// bm.flows.saveQuote threw "not declared" and the types offered only
// bm.flows['save-quote'].
func TestFlowRegistryKeysCamelCaseKebabNames(t *testing.T) {
	app := sdkShapesApp()
	mux := http.NewServeMux()
	RegisterBMTypesRoute(mux, app)
	rec := typesGet(mux, "/_internal/flows.json", "", "")
	var reg map[string]map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &reg); err != nil {
		t.Fatal(err)
	}
	if e := reg["saveQuote"]; e == nil || e["path"] != "/api/quote" {
		t.Fatalf("flows.json = %s, want saveQuote → /api/quote", rec.Body.String())
	}
	if _, ok := reg["save-quote"]; ok {
		t.Fatalf("flows.json still keys the flow by its file name: %s", rec.Body.String())
	}

	out := GenerateBMTypes(app)
	for _, want := range []string{
		"  saveQuote: (params: Record<string, never>, body?: { hours?: number }) => Promise<unknown>;",
		// The key older types emitted keeps compiling.
		"  'save-quote': (params: Record<string, never>, body?: { hours?: number }) => Promise<unknown>;",
		"  addMember: (",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("FlowMap missing %q\n%s", want, flowMapSection(out))
		}
	}
	// A snake_case name was already camelCased; it gains no alias.
	if strings.Contains(out, "  add_member:") {
		t.Errorf("FlowMap grew an alias for a snake_case name:\n%s", flowMapSection(out))
	}
}

// Two flows that camelCase to the same key both stay reachable, and the key
// does not depend on which flows a caller may see.
func TestFlowRegistryKeysCollision(t *testing.T) {
	flows := []Flow{
		{Name: "save_quote", Trigger: FlowTrigger{Type: "http"}},
		{Name: "save-quote", Trigger: FlowTrigger{Type: "http"}},
		{Name: "saveQuote2", Trigger: FlowTrigger{Type: "http"}},
		{Name: "tick", Trigger: FlowTrigger{Type: "cron"}},
	}
	got := flowRegistryKeys(flows)
	want := map[string]string{"save-quote": "saveQuote", "save_quote": "save_quote", "saveQuote2": "saveQuote2"}
	if len(got) != len(want) {
		t.Fatalf("keys = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("keys = %v, want %v", got, want)
		}
	}
	// The one already spelled as the key keeps it.
	got = flowRegistryKeys(append(flows, Flow{Name: "saveQuote", Trigger: FlowTrigger{Type: "http"}}))
	if got["saveQuote"] != "saveQuote" || got["save-quote"] != "save-quote" {
		t.Fatalf("keys with an exact camelCase flow = %v", got)
	}
	for in, want := range map[string]string{"company_setup": "companySetup", "Company-Setup": "companySetup", "a--b__c": "aBC", "x": "x", "_lead": "lead"} {
		if got := flowSDKName(in); got != want {
			t.Errorf("flowSDKName(%q) = %q, want %q", in, got, want)
		}
	}
}

// B9, B13, B14, B17: the generated types match what the runtime sends.
func TestGeneratedTypesMatchRuntimeShapes(t *testing.T) {
	out := GenerateBMTypes(sdkShapesApp())
	for _, want := range []string{
		// B9: available() is { current, transitions }, transitionTo() the handler's answer.
		"available(): Promise<WorkflowAvailable<WorkflowMap[T]['states']>>;",
		"transitionTo(state: WorkflowMap[T]['states']): Promise<WorkflowTransitionResult<WorkflowMap[T]['states']>>;",
		"transitions: Array<{ to: S; role?: string }>;",
		"status: 'transitioned';",
		// B13: tenant roles named in config, widened for role_field data.
		"export type Role = 'admin' | 'founder' | 'front_desk' | 'manager' | 'owner' | 'staff' | 'user' | (string & {});",
		// B14: REST list options.
		"orderBy?: string;",
		"include?: string | string[];",
		"page?: number;",
		"per_page?: number;",
		// B17: the profile's tenant id.
		"  group_id: string | null;",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("generated types missing %q", want)
		}
	}
	if strings.Contains(out, "available(): Promise<WorkflowMap[T]['states'][]>") {
		t.Error("available() is still typed as a state array")
	}
	if n := strings.Count(out, "  group_id"); n != 1 {
		t.Errorf("User declares group_id %d times, want 1", n)
	}

	// Without groups:, no tenant id and no widening.
	plain := &App{Roles: &RolesConfig{Roles: map[string]RoleDef{"editor": {}}}}
	out = GenerateBMTypes(plain)
	if !strings.Contains(out, "export type Role = 'admin' | 'editor' | 'user';") {
		t.Errorf("plain app Role union changed:\n%s", roleLine(out))
	}
	if strings.Contains(out, "group_id: string | null") {
		t.Error("a single-tenant app's User declares group_id")
	}
}

// The generated declarations compile, and code written to the runtime
// shapes type-checks (tsc fixture, like TestGeneratedBMTypesCompileFixture).
func TestGeneratedTypesRuntimeShapesCompile(t *testing.T) {
	tsc, err := exec.LookPath("tsc")
	if err != nil {
		if os.Getenv("CI") != "" || os.Getenv("BM_REQUIRE_TSC") != "" {
			t.Fatal("tsc not installed but CI/BM_REQUIRE_TSC is set")
		}
		t.Skip("tsc not installed")
	}
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("bm.d.ts", GenerateBMTypes(sdkShapesApp()))
	write("fixture.ts", `
import bm from 'bm';

async function validUses() {
  await bm.flows.saveQuote({}, { hours: 2 });
  await bm.flows['save-quote']({}, { hours: 2 });
  await bm.flows.addMember({});
  const wf = bm.workflow('bookings', 1);
  const avail = await wf.available();
  const current: 'requested' | 'confirmed' = avail.current;
  const targets: Array<'requested' | 'confirmed'> = avail.transitions.map(t => t.to);
  const moved = await wf.transitionTo('confirmed');
  const status: 'transitioned' = moved.status;
  const id: string = moved.id;
  const state: 'requested' | 'confirmed' = await wf.current();
  const me = await bm.auth.me();
  const staff: boolean = me?.roles.includes('staff') ?? false;
  const tenantRole: boolean = me?.roles.includes('member_role_value') ?? false;
  const tenant: string | null | undefined = me?.group_id;
  const rows = await bm.table('bookings').list({ orderBy: 'starts_at:asc', include: ['client'], fields: 'id,status', page: 2, per_page: 10 });
  const room = bm.room('lobby')
    .on('bm:status', (s) => { const st: 'open' | 'reconnecting' | 'closed' = s.state; void [st, s.reconnected, s.retryIn, s.reason, s.unsent]; })
    .on('bm:error', (e) => { const why: 'not_member' | 'too_many_rooms' | 'join_refused' | 'unauthorized' | 'forbidden' = e.code; void [why, e.message]; })
    .on('chat', (payload, from) => void [payload, from])
    .onAny((payload, from, kind) => void [payload, from, kind]);
  const sentNow: boolean = room.send({ kind: 'chat', text: 'hi' });
  const roomState: 'connecting' | 'open' | 'reconnecting' | 'closed' = room.state;
  void [current, targets, status, id, state, staff, tenantRole, tenant, rows, sentNow, roomState];
}

async function invalidUses() {
  const wf = bm.workflow('bookings', 1);
  // @ts-expect-error available() answers an object, not a state array
  (await wf.available()).map(s => s);
  // @ts-expect-error transitionTo() answers { status, from, to, id }, no state key
  (await wf.transitionTo('confirmed')).state;
  // @ts-expect-error unknown flow names still fail
  await bm.flows.saveQuotes({});
  // @ts-expect-error a room status is a state, not a peer payload
  const notAState: 'open' = bm.room('lobby').state;
  void notAState;
}

void validUses;
void invalidUses;
`)
	write("tsconfig.json", `{
  "compilerOptions": {
    "noEmit": true, "strict": true, "target": "ES2020", "module": "ESNext",
    "moduleResolution": "Bundler", "lib": ["ES2020", "DOM"],
    "paths": { "bm": ["./bm.d.ts"] }
  },
  "files": ["fixture.ts"]
}`)
	cmd := exec.Command(tsc, "--project", "tsconfig.json")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if strings.Contains(string(out), "TS2578") {
		t.Fatalf("an invalid use type-checked (unused @ts-expect-error):\n%s", out)
	}
	if err != nil {
		t.Fatalf("generated types failed the runtime-shape fixture:\n%s", out)
	}
}

func flowMapSection(out string) string {
	i := strings.Index(out, "export interface FlowMap {")
	if i < 0 {
		return "(no FlowMap)"
	}
	j := strings.Index(out[i:], "\n}\n")
	if j < 0 {
		return out[i:]
	}
	return out[i : i+j+2]
}

func roleLine(out string) string {
	lines := strings.Split(out, "\n")
	var hits []string
	for _, l := range lines {
		if strings.HasPrefix(l, "export type Role") {
			hits = append(hits, l)
		}
	}
	sort.Strings(hits)
	return strings.Join(hits, "\n")
}
