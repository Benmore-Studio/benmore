//go:build !cli

package main

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func fakeIDToken(claims map[string]any) string {
	b, _ := json.Marshal(claims)
	return "e30." + base64.RawURLEncoding.EncodeToString(b) + ".sig"
}

func TestMicrosoftConsumerAccountsTrustedWithoutGraph(t *testing.T) {
	tok := fakeIDToken(map[string]any{"tid": microsoftConsumerTenantID})
	if !microsoftEmailTrusted("unused", tok, "someone@outlook.com") {
		t.Fatal("personal Microsoft account should be trusted")
	}
}

// A work/school tenant may only present emails in one of ITS verified
// domains; the lookup failing (no network in tests) must refuse.
func TestMicrosoftWorkAccountFailsClosed(t *testing.T) {
	tok := fakeIDToken(map[string]any{"tid": "11111111-2222-3333-4444-555555555555"})
	if microsoftEmailTrusted("invalid-token", tok, "ceo@victim.example") {
		t.Fatal("unverifiable work-account email must be refused")
	}
}

func TestMicrosoftDomainInOrg(t *testing.T) {
	orgs := []struct {
		VerifiedDomains []struct {
			Name string `json:"name"`
		} `json:"verifiedDomains"`
	}{{VerifiedDomains: []struct {
		Name string `json:"name"`
	}{{Name: "attacker.onmicrosoft.com"}, {Name: "Attacker.example"}}}}
	if !microsoftDomainInOrg("attacker.example", orgs) {
		t.Fatal("verified domain not matched")
	}
	if microsoftDomainInOrg("victim.example", orgs) {
		t.Fatal("unverified domain matched")
	}
}

func TestIsMicrosoftGraphProvider(t *testing.T) {
	ms := oauthProviders["microsoft"]
	if !isMicrosoftGraphProvider(&ms) {
		t.Fatal("built-in Microsoft provider not detected")
	}
	g := oauthProviders["google"]
	if isMicrosoftGraphProvider(&g) || isMicrosoftGraphProvider(nil) {
		t.Fatal("non-Microsoft provider detected as Microsoft")
	}
}
