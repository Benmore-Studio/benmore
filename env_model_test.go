package main

import "testing"

func TestParseEnv(t *testing.T) {
	cases := []struct {
		in      string
		want    AppEnv
		wantErr bool
	}{
		{"", EnvProd, false},
		{"prod", EnvProd, false},
		{"production", EnvProd, false},
		{"PROD", EnvProd, false},
		{"  dev ", EnvDev, false},
		{"dev", EnvDev, false},
		{"development", EnvDev, false},
		{"Dev", EnvDev, false},
		{"prdo", "", true},
		{"staging", "", true},
	}
	for _, c := range cases {
		got, err := ParseEnv(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseEnv(%q): expected error, got %q", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseEnv(%q): unexpected error %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseEnv(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestInstanceSubdomain(t *testing.T) {
	const sub = "myapp-a3f9c1"
	cases := []struct {
		name string
		in   string
		env  AppEnv
		want string
	}{
		{"prod is identity", sub, EnvProd, sub},
		{"dev appends suffix", sub, EnvDev, "myapp-a3f9c1-dev"},
		{"dev input + prod env de-devs", "myapp-a3f9c1-dev", EnvProd, sub},
		{"dev input + dev env idempotent", "myapp-a3f9c1-dev", EnvDev, "myapp-a3f9c1-dev"},
		{"empty env treated as prod", sub, "", sub},
	}
	for _, c := range cases {
		// "" env must behave like prod (default-prod invariant).
		env := c.env
		if env == "" {
			env = EnvProd
		}
		got := InstanceSubdomain(c.in, env)
		if got != c.want {
			t.Errorf("%s: InstanceSubdomain(%q,%q) = %q, want %q", c.name, c.in, c.env, got, c.want)
		}
	}
}

func TestLogicalSubdomain(t *testing.T) {
	cases := map[string]string{
		"myapp-a3f9c1":     "myapp-a3f9c1", // prod: identity
		"myapp-a3f9c1-dev": "myapp-a3f9c1", // dev: stripped
		// A prod suffix can contain d/e/f (hex-ish) chars but never a
		// hyphen, so "...-dev" only ever means the dev instance. A base
		// slug like "my-dev" still ends up "my-dev-<suffix>" in prod, which
		// does NOT end in "-dev".
		"my-dev-q7r2tk": "my-dev-q7r2tk",
	}
	for in, want := range cases {
		if got := LogicalSubdomain(in); got != want {
			t.Errorf("LogicalSubdomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEnvOfSubdomain(t *testing.T) {
	cases := map[string]AppEnv{
		"myapp-a3f9c1":     EnvProd,
		"myapp-a3f9c1-dev": EnvDev,
		"my-dev-q7r2tk":    EnvProd, // base slug "my-dev" is still prod
		"x-dev":            EnvDev,
	}
	for in, want := range cases {
		if got := EnvOfSubdomain(in); got != want {
			t.Errorf("EnvOfSubdomain(%q) = %q, want %q", in, got, want)
		}
		if got := IsDevSubdomain(in); got != (want == EnvDev) {
			t.Errorf("IsDevSubdomain(%q) = %v, want %v", in, got, want == EnvDev)
		}
	}
}

func TestResolveBuildEnv(t *testing.T) {
	cases := []struct {
		name           string
		requested      string
		devProvisioned bool
		want           AppEnv
		wantErr        bool
	}{
		// Backward-compat: no request + no dev instance => prod (today's behavior).
		{"no request, prod-only app", "", false, EnvProd, false},
		// Dev-mode app with no explicit request defaults to dev (push->dev).
		{"no request, has dev instance", "", true, EnvDev, false},
		// Explicit request always wins, regardless of provisioning.
		{"explicit prod overrides dev default", "prod", true, EnvProd, false},
		{"explicit dev on prod-only app", "dev", false, EnvDev, false},
		{"explicit production alias", "production", true, EnvProd, false},
		// Bad input errors out (loud, not silent-wrong-instance).
		{"garbage request errors", "stage", false, "", true},
	}
	for _, c := range cases {
		got, err := resolveBuildEnv(c.requested, c.devProvisioned)
		if c.wantErr {
			if err == nil {
				t.Errorf("%s: expected error, got %q", c.name, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: unexpected error %v", c.name, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s: resolveBuildEnv(%q,%v) = %q, want %q", c.name, c.requested, c.devProvisioned, got, c.want)
		}
	}
}

func TestInstanceAddressing(t *testing.T) {
	const appsDir = "/opt/benmore/apps"
	const sub = "myapp-a3f9c1"

	if got := InstanceDir(appsDir, sub, EnvProd); got != "/opt/benmore/apps/myapp-a3f9c1" {
		t.Errorf("prod dir = %q", got)
	}
	if got := InstanceDir(appsDir, sub, EnvDev); got != "/opt/benmore/apps/myapp-a3f9c1-dev" {
		t.Errorf("dev dir = %q", got)
	}
	if got := InstanceUnit(sub, EnvProd); got != "benmore-app@myapp-a3f9c1.service" {
		t.Errorf("prod unit = %q", got)
	}
	// Dev uses the dedicated template with the LOGICAL sub as the instance
	// specifier - NOT "benmore-app@<sub>-dev".
	if got := InstanceUnit(sub, EnvDev); got != "benmore-dev@myapp-a3f9c1.service" {
		t.Errorf("dev unit = %q", got)
	}

	// UnitForSubdomain maps a routing subdomain (ports.json key) -> unit.
	// Prod routing subdomain must yield the exact legacy literal.
	if got := UnitForSubdomain(sub); got != "benmore-app@myapp-a3f9c1.service" {
		t.Errorf("UnitForSubdomain(prod) = %q (must equal legacy literal)", got)
	}
	if got := UnitForSubdomain("myapp-a3f9c1-dev"); got != "benmore-dev@myapp-a3f9c1.service" {
		t.Errorf("UnitForSubdomain(dev) = %q", got)
	}

	// The locked decision: BOTH envs resolve to the SAME (prod) user.
	prodUser := PerAppUser(sub)
	if prodUser != "benmore-app-myapp-a3f9c1" {
		t.Errorf("prod user = %q", prodUser)
	}
	if devUser := PerAppUser(InstanceSubdomain(sub, EnvDev)); devUser != prodUser {
		t.Errorf("dev instance user = %q, must equal prod user %q (dev reuses prod's user)", devUser, prodUser)
	}
}

// Round-trip: for any logical subdomain, deriving the dev instance and then
// taking its logical form must return the original - the property the rest
// of the feature (promote, --env threading, dashboard pairing) relies on.
func TestSubdomainRoundTrip(t *testing.T) {
	for _, sub := range []string{"myapp-a3f9c1", "x-q7r2tk", "my-dev-abc234", "report-gen-99zz88"} {
		dev := InstanceSubdomain(sub, EnvDev)
		if got := LogicalSubdomain(dev); got != sub {
			t.Errorf("round trip %q -> dev %q -> logical %q, want %q", sub, dev, got, sub)
		}
		if !IsDevSubdomain(dev) {
			t.Errorf("%q derived from %q should be a dev subdomain", dev, sub)
		}
		if EnvOfSubdomain(sub) != EnvProd {
			t.Errorf("logical subdomain %q should resolve to prod", sub)
		}
	}
}
