//go:build !cli

package main

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReviewAppEnvironmentIsolation(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	for _, dir := range []string{a, b} {
		if err := os.MkdirAll(filepath.Join(dir, ".benmore"), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, ".benmore/env"), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(b, "env.yaml"), []byte("REVIEW_OTHER_APP_SECRET: synthetic-secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	LoadEnv(a)
	LoadEnv(b)
	if got := GetEnv(a, "REVIEW_OTHER_APP_SECRET"); got != "" {
		t.Error("app lookup disclosed another app's secret")
	}
	if got := InterpolateEnv("{{env.REVIEW_OTHER_APP_SECRET}}", a); strings.Contains(got, "synthetic-secret") {
		t.Error("template disclosed another app's secret")
	}
	flat := flatDataForCtx(&FlowContext{App: &App{Dir: a}, Data: map[string]any{}})
	if _, ok := flat["env.REVIEW_OTHER_APP_SECRET"]; ok {
		t.Error("flow disclosed another app's secret")
	}
	t.Setenv("REVIEW_REMOVED_SECRET", "stale-process-secret")
	if got := GetEnv(a, "REVIEW_REMOVED_SECRET"); got != "" {
		t.Error("removed app secret resurfaced from process")
	}
}

func TestReviewPlatformProcessSecretsStayPrivate(t *testing.T) {
	old := isolateAppEnvironment.Load()
	isolateAppEnvironment.Store(true)
	t.Cleanup(func() { isolateAppEnvironment.Store(old) })
	t.Setenv("REVIEW_PLATFORM_SECRET", "operator-secret")
	dir := t.TempDir()
	LoadEnv(dir)
	if GetEnv(dir, "REVIEW_PLATFORM_SECRET") != "" {
		t.Fatal("platform process secret entered tenant environment")
	}
	if GetEnv("", "REVIEW_PLATFORM_SECRET") != "operator-secret" {
		t.Fatal("platform lost its own configuration")
	}
	SetAppEnv(dir, "REVIEW_PLATFORM_SECRET", "tenant-explicit-value")
	if GetEnv("", "REVIEW_PLATFORM_SECRET") != "operator-secret" {
		t.Fatal("tenant overwrote operator configuration")
	}
	credDir := t.TempDir()
	t.Setenv("CREDENTIALS_DIRECTORY", filepath.Join(credDir, "credentials"))
	if err := os.MkdirAll(filepath.Join(credDir, "credentials"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(credDir, "outside"), []byte("outside-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if GetEnv("", "../outside") != "" {
		t.Fatal("credential lookup escaped its directory")
	}
}

func TestReviewCredentialExchangesBlockPrivateDestinations(t *testing.T) {
	for _, target := range []string{"http://127.0.0.1/token", "http://169.254.169.254/token", "http://10.0.0.1/token", "file:///etc/passwd"} {
		t.Run(target, func(t *testing.T) {
			app := &App{Dir: t.TempDir()}
			r, _ := http.NewRequest("GET", "https://example.com/", nil)
			sign := &FlowAPISign{Inline: &Recipe{Before: &RecipeBefore{Request: &RecipeBeforeRequest{URL: target}}}}
			if err := applySigner(r, nil, sign, app); err == nil {
				t.Fatal("private token endpoint accepted")
			}
			SetAppEnv(app.Dir, "SMS_WEBHOOK_URL", target)
			if err := sendSMSWebhook(app.Dir, "synthetic", "synthetic", ""); err == nil {
				t.Fatal("private SMS endpoint accepted")
			}
		})
	}
}

func TestReviewSignerCacheIsolation(t *testing.T) {
	old := recipeBeforeClient.Transport
	fetches := 0
	recipeBeforeClient.Transport = auditRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		fetches++
		_ = r.ParseForm()
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"access_token":"` + r.FormValue("client_secret") + `","expires_in":3600}`))}, nil
	})
	t.Cleanup(func() { recipeBeforeClient.Transport = old })
	a, b := &App{Dir: t.TempDir()}, &App{Dir: t.TempDir()}
	for _, app := range []*App{a, b} {
		SetAppEnv(app.Dir, "OAUTH_CLIENT_ID", "same-public-client-id")
	}
	SetAppEnv(a.Dir, "OAUTH_CLIENT_SECRET", "token-a")
	SetAppEnv(b.Dir, "OAUTH_CLIENT_SECRET", "token-b")
	sign := &FlowAPISign{Recipe: "oauth_client_credentials", Bindings: map[string]string{"token_url": "https://93.184.216.34/review-token"}}
	for _, tc := range []struct {
		app    *App
		secret string
	}{{a, "token-a"}, {a, "token-a"}, {b, "token-b"}, {a, "token-rotated"}} {
		SetAppEnv(tc.app.Dir, "OAUTH_CLIENT_SECRET", tc.secret)
		r, _ := http.NewRequest("GET", "https://example.com/", nil)
		if err := applySigner(r, nil, sign, tc.app); err != nil {
			t.Fatal(err)
		}
		if r.Header.Get("Authorization") != "Bearer "+tc.secret {
			t.Error("cached credential crossed app or rotation boundary")
		}
	}
	if fetches != 3 {
		t.Errorf("token exchanges = %d, want 3", fetches)
	}
}

func TestReviewQueryDecryptionIsTenantBound(t *testing.T) {
	a, cleanupA := newTestApp(t)
	defer cleanupA()
	b, cleanupB := newTestApp(t)
	defer cleanupB()
	keyA, keyB := bytes.Repeat([]byte{11}, 32), bytes.Repeat([]byte{22}, 32)
	RegisterDBEncryptionKey(filepath.Join(a.Dir, "data.db"), keyA)
	RegisterDBEncryptionKey(filepath.Join(b.Dir, "data.db"), keyB)
	old := appEncryptionKey
	appEncryptionKey = keyA
	t.Cleanup(func() { appEncryptionKey = old })
	ciphertext, err := fieldEncryptCtx(keyA, "", "", "tenant-a-secret")
	if err != nil {
		t.Fatal(err)
	}
	rows, err := QueryRows(b.DB, "SELECT ? AS stolen", ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatal("fixture returned no row")
	}
	if rows[0]["stolen"] != "[DECRYPTION_FAILED]" && rows[0]["stolen"] != decryptFailMask {
		t.Fatal("query decrypted another tenant's ciphertext")
	}
	rows, err = QueryRows(a.DB, "SELECT ? AS own", ciphertext)
	if err != nil || len(rows) != 1 || rows[0]["own"] != "tenant-a-secret" {
		t.Fatalf("own key did not decrypt: %v", err)
	}
}
