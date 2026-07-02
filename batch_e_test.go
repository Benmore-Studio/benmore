package main

import "testing"

// TestSMSPhoneValidation covers round-2: E.164 normalization collapses format
// variants to one rate-limit key and rejects garbage / bad-length numbers.
func TestSMSPhoneValidation(t *testing.T) {
	if a := smsNormalizePhone("+1 (415) 555-1234"); a != "+14155551234" {
		t.Fatalf("normalize: %q", a)
	}
	good := []string{"+14155551234", "14155551234", "+447911123456"}
	bad := []string{"", "123", "+0123456789", "+1415555abcd", "+1234567890123456"}
	for _, g := range good {
		if !smsValidE164(smsNormalizePhone(g)) {
			t.Errorf("expected %q valid", g)
		}
	}
	for _, b := range bad {
		if smsValidE164(smsNormalizePhone(b)) {
			t.Errorf("expected %q invalid", b)
		}
	}
}

// TestPresenceKeyTenantNamespacing covers round-2: presence keys are namespaced
// by the caller's group so one tenant can't read another's slug.
func TestPresenceKeyTenantNamespacing(t *testing.T) {
	app := &App{Group: &GroupConfig{Key: "company_id"}}
	a := &Session{GroupID: "A"}
	b := &Session{GroupID: "B"}
	if presenceKey(app, a, "huddle:42") == presenceKey(app, b, "huddle:42") {
		t.Fatal("different tenants must produce different presence keys")
	}
	if got := presenceKey(&App{}, a, "huddle:42"); got != "huddle:42" {
		t.Fatalf("non-tenant app should not namespace, got %q", got)
	}
}
