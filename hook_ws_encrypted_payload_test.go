//go:build !cli

package main

import (
	"encoding/json"
	"testing"
)

// A hook `ws:` with no `payload:` broadcasts to every member of the room -
// clients, any of whom may lack the role an encrypted.yaml column names in
// unmask_roles. The row used to carry that column's plaintext (and an update's
// old_<col> delta) to them. The default payload is now only the table name, so
// no row value reaches the room unless the author's payload names it.
func TestHookWSDefaultPayloadMasksRoleGatedEncryptedColumns(t *testing.T) {
	resetWSHub(t)
	app := &App{Dir: t.TempDir(), Encrypted: &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{
		"patients": {
			{Column: "ssn", Roles: []string{"clinician"}},
			{Column: "diary", Roles: []string{"self"}},
			{Column: "nickname"},
		},
	}}}
	member := newWSTestClient("", 2, "")
	member.appID = realtimeAppID(app.Dir)
	registerWSClient(member)
	defer unregisterWSClient(member)
	wsJoinAs(member, "ward")

	row := map[string]any{"id": 1, "user_id": 1, "ssn": "123-45-6789", "old_ssn": "987-65-4321",
		"diary": "private entry", "nickname": "Sam"}
	if err := executeHookResult(app, Hook{WS: &WSHook{Room: "ward"}}, "patients", row); err != nil {
		t.Fatal(err)
	}
	var msg struct {
		Payload map[string]any `json:"payload"`
	}
	select {
	case b := <-member.send:
		if err := json.Unmarshal(b, &msg); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatal("room member got no hook broadcast")
	}
	if len(msg.Payload) != 1 || msg.Payload["table"] != "patients" {
		t.Errorf("default hook ws payload = %v, want only the table", msg.Payload)
	}
	for _, plain := range []string{"123-45-6789", "987-65-4321", "private entry"} {
		for k, v := range msg.Payload {
			if v == plain {
				t.Errorf("room member received plaintext in %s", k)
			}
		}
	}
	if row["ssn"] != "123-45-6789" {
		t.Error("the broadcast changed the hook's row")
	}

	// An explicit payload template is the author's choice and is unchanged.
	if err := executeHookResult(app, Hook{WS: &WSHook{Room: "ward", Payload: `{"ssn":"{{ssn}}"}`}}, "patients", row); err != nil {
		t.Fatal(err)
	}
	select {
	case b := <-member.send:
		json.Unmarshal(b, &msg)
		if msg.Payload["ssn"] != "123-45-6789" {
			t.Errorf("explicit payload changed: %v", msg.Payload)
		}
	default:
		t.Fatal("room member got no explicit-payload broadcast")
	}
}
