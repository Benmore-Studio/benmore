//go:build !cli

package main

// A step id that is one of the runtime's identity names.
//
// A step stores its outputs under its id, and `${{ steps.<id>.outputs.<x> }}`
// is read as `<id>.<x>`. With `id: user` that is where the signed-in caller's
// values live: the step's row replaced `${{ user.* }}` for the rest of the
// flow, so a lookup of another account stood in for the caller in every later
// reference, bind and guard, and before the step ran `steps.user.outputs.*`
// read the caller.
//
// Such a step now stores its outputs under a key of its own
// (flowIdentityStepPrefix + id) and `steps.<id>.outputs.*` reads that key, so:
//
//   - the identity values the runtime holds always win: `${{ user.id }}`,
//     `${{ user.email }}`, `${{ user_id }}` ... stay the caller's;
//   - `${{ steps.user.outputs.<name> }}` is the step's output, and nothing
//     else;
//   - a name the runtime does not hold under the identity name still reads the
//     step's output through it (`${{ user.plan_name }}` for a column the
//     caller's own row does not have, and every `${{ user.<name> }}` on a flow
//     nobody signs in to), as it did (overlayIdentityStepOutputs).
//
// The write gate warns about such an id (ghaIdentityStepIDWarnings); it is
// not refused, because deployed flows use `id: user`.

import (
	"fmt"
	"maps"
	"slices"
	"strings"
)

// flowIdentityStepPrefix starts the key a step named like an identity value
// stores its outputs under. A request field of that name is moved aside like
// one named after any step id (shadowStepNamedRequestKeys).
const flowIdentityStepPrefix = "__benmore_step_"

// flowStepOutputKey is where a step with this id stores its outputs: the id,
// except for one of the runtime's identity names (flowIdentityKeys).
func flowStepOutputKey(id string) string {
	if slices.Contains(flowIdentityKeys, id) {
		return flowIdentityStepPrefix + id
	}
	return id
}

// flowStepDisplayName is a step's name as its author wrote it, for an answer
// or a log line.
func flowStepDisplayName(name string) string {
	return strings.TrimPrefix(name, flowIdentityStepPrefix)
}

// flowStepRefOutputKey maps the part of a `steps.<id>...` reference after
// `steps.` onto the key its step stores its outputs under.
func flowStepRefOutputKey(rest string) string {
	id := rest
	if i := strings.IndexAny(id, ".["); i >= 0 {
		id = id[:i]
	}
	return flowStepOutputKey(id) + rest[len(id):]
}

// restoreStepIDs gives every step its authored id back as its name. Command
// flows keep their own closed set of reserved ids and resolve references by
// the authored id (convertCommandGHASteps).
func restoreStepIDs(steps []FlowStep) {
	for i := range steps {
		steps[i].Name = flowStepDisplayName(steps[i].Name)
		restoreStepIDs(steps[i].Steps)
		restoreStepIDs(steps[i].ElseSteps)
		restoreStepIDs(steps[i].OnError)
	}
}

// overlayIdentityStepOutputs lets a name the runtime does not hold under an
// identity name read the output of the step with that id, in a flattened
// view: `user.plan_name` from a step `id: user` when the caller's own values
// have no `plan_name`, and all of `user.*` when nobody is signed in. A name
// the runtime holds is never touched, so the caller's values always win.
func overlayIdentityStepOutputs(flat map[string]any) {
	for _, id := range flowIdentityKeys {
		alias := flowIdentityStepPrefix + id
		if _, ran := flat[alias]; !ran {
			continue
		}
		add := map[string]any{}
		for key, value := range flat {
			if key != alias && !strings.HasPrefix(key, alias+".") {
				continue
			}
			target := id + key[len(alias):]
			if _, held := flat[target]; !held {
				add[target] = value
			}
		}
		maps.Copy(flat, add)
	}
}

// ghaIdentityStepIDWarnings names each step whose id is one of the runtime's
// identity names. Advisory: the file is accepted and keeps loading. Shared by
// the write path and `benmore check` (redirectWarnings).
func ghaIdentityStepIDWarnings(content string) []string {
	var file FlowFileGHA
	if err := yamlUnmarshal([]byte(content), &file); err != nil || file.Jobs == nil {
		return nil
	}
	better := map[string]string{"user": "account", "user_id": "owner_id", "user_email": "contact_email", "user_role": "member_role", "user_group_id": "group", "_group_id": "group", "_group_key": "group"}
	var out []string
	var walk func(job string, steps []FlowStepGHA)
	walk = func(job string, steps []FlowStepGHA) {
		for _, s := range steps {
			if id := strings.TrimSpace(s.ID); slices.Contains(flowIdentityKeys, id) {
				out = append(out, fmt.Sprintf("job %q step %q is named like the signed-in caller's `%s`. The caller's values always win: `${{ user.id }}`, `${{ user.email }}` and the other identity values keep reading the caller after this step, and only `${{ steps.%s.outputs.<name> }}` reads what the step returned. Give the step an id of its own (for example `id: %s`) so that no reference can be read either way.",
					job, id, id, id, better[id]))
			}
			walk(job, s.Steps)
			walk(job, s.Else)
			walk(job, s.OnError)
		}
	}
	for _, job := range slices.Sorted(maps.Keys(file.Jobs)) {
		walk(job, file.Jobs[job].Steps)
	}
	return out
}

// flowIdentityStepIDsReference is api(at:"flows") → identity_step_ids, for
// app builders. The names are flowIdentityKeys, so the text lists exactly the
// ids the runtime treats this way.
func flowIdentityStepIDsReference() string {
	names := make([]string, len(flowIdentityKeys))
	for i, id := range flowIdentityKeys {
		names[i] = "`" + id + "`"
	}
	return "A step whose `id` is one of the caller's identity names (" + strings.Join(names, ", ") + ") does not take the caller's place. After `id: user`, `${{ user.id }}`, `${{ user.email }}`, `${{ user.role }}` and the other identity values keep reading the signed-in caller, in templates, SQL binds and `if:` conditions; the step's outputs are read as `${{ steps.user.outputs.<name> }}`, which reads nothing before the step has run. " +
		"A name the caller's own values do not have still reads the step's output through the identity name: `${{ user.plan_name }}` for a column the step selected, and every `${{ user.<name> }}` on a flow nobody signs in to. " +
		"The write gate and `benmore check` warn about such an id and the flow keeps loading; give the step an id of its own (`id: account`) so that no reference can be read either way."
}
