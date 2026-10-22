//go:build !cli

package main

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// or_env is the fallback pipe signer recipes use for credentials. An app's
// recipe runs in a process whose environment also carries operator values
// (a hosted unit loads platform.env; `benmore host` serves many apps from one
// process), so the fallback must read the app's own environment, like
// env.NAME does, and never the process environment.
func TestSignerOrEnvReadsOnlyTheAppEnvironment(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".benmore"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".benmore", "env"), []byte("APP_TOKEN=\"app-fixture-value\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPERATOR_ONLY_CREDENTIAL", "operator-fixture-value")
	if err := LoadEnv(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { storeAppEnv(dir, nil) })
	app := &App{Dir: dir}

	req, _ := http.NewRequest("POST", "https://example.com/hook", nil)
	sign := &FlowAPISign{Inline: &Recipe{Headers: []RecipeBinding{
		{Name: "X-Operator", Expr: "{{ params.missing | or_env:'OPERATOR_ONLY_CREDENTIAL' }}"},
		{Name: "X-App", Expr: "{{ params.missing | or_env:'APP_TOKEN' }}"},
	}}}
	if err := applySigner(req, nil, sign, app); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if got := req.Header.Get("X-Operator"); got != "" {
		t.Fatalf("or_env returned a process-only value to the app: %q", got)
	}
	if got := req.Header.Get("X-App"); got != "app-fixture-value" {
		t.Fatalf("or_env lost the app's own value: %q", got)
	}

	// The built-in bearer_token recipe falls back to the app's API_TOKEN.
	if err := os.WriteFile(filepath.Join(dir, ".benmore", "env"), []byte("API_TOKEN=\"app-bearer-fixture\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("API_TOKEN", "operator-bearer-fixture")
	if err := LoadEnv(dir); err != nil {
		t.Fatal(err)
	}
	req, _ = http.NewRequest("GET", "https://api.example.com/v1/foo", nil)
	if err := applySigner(req, nil, &FlowAPISign{Recipe: "bearer_token"}, app); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer app-bearer-fixture" {
		t.Fatalf("bearer_token used %q, want the app's API_TOKEN", got)
	}
}
