//go:build !cli

package main

import "testing"

// Inside one `${{ }}` a ref on the right of a comparison is a ref, as it is
// on the left and as it is in `${{ a }} == ${{ b }}`. Read as literal text,
// `${{ params.token == steps.invite.outputs.token }}` held for a request that
// sent the text "invite.token", and `${{ steps.doc.outputs.owner_id !=
// user.id }}` compared the owner with the text "user.id" (always unequal).
func TestFlowConditionRightSideRefIsARef(t *testing.T) {
	ctx := &FlowContext{
		Data: map[string]any{
			"invite": []map[string]any{{"token": "s3cret"}},
			"doc":    []map[string]any{{"owner_id": int64(7)}},
			"user":   map[string]any{"id": int64(7)},
			"token":  "invite.token",
			"code":   "otp.code",
			"otp":    []map[string]any{{"code": "123456"}},
			"n":      "3",
		},
		Params:      map[string]string{"token": "invite.token", "code": "otp.code", "n": "3"},
		RequestKeys: map[string]bool{"token": true, "code": true, "n": true},
	}
	for _, c := range []struct {
		cond string
		want bool
	}{
		// The literal text of the translated ref must not satisfy the guard.
		{"${{ params.token == steps.invite.outputs.token }}", false},
		{"${{ params.code != steps.otp.outputs.code }}", true},
		// Ownership check from the flows_gha.go header example.
		{"${{ steps.doc.outputs.owner_id != user.id }}", false},
		{"${{ steps.doc.outputs.owner_id == user.id }}", true},
		{"${{ user.id == steps.doc.outputs.owner_id }}", true},
		// A literal on the left, a ref on the right.
		{"${{ 5 < params.n }}", false},
		{"${{ 1 < params.n }}", true},
		// Literals on the right stay literals.
		{"${{ params.n == 3 }}", true},
		{"${{ params.n == '3' }}", true},
		{"${{ params.token == 'invite.token' }}", true},
		{"${{ user.id == 7 }}", true},
		{"${{ params.n != true }}", true},
	} {
		if got := evaluateFlowCondition(ghaIfToFlowCondition(c.cond), ctx); got != c.want {
			t.Errorf("%s -> %v, want %v (translated %q)", c.cond, got, c.want, ghaIfToFlowCondition(c.cond))
		}
	}
}
