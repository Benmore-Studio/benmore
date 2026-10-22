//go:build !cli

package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// withPlatformMedia pins the process media config for one test.
func withPlatformMedia(t *testing.T, cfg *PlatformMediaConfig) {
	t.Helper()
	platformMediaOnce.Do(func() {})
	old := platformMedia
	platformMedia = cfg
	t.Cleanup(func() { platformMedia = old })
}

func testMediaConfig(t *testing.T) *PlatformMediaConfig {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return &PlatformMediaConfig{Bucket: "media", Region: "us-east-1", CDNDomain: "cdn.example.test", KeyPairID: "KLOCAL", PrivateKey: key}
}

// fakeMediaBroker stands in for the router's broker socket and records what
// the tenant asked for.
type fakeMediaBroker struct {
	mu    sync.Mutex
	reqs  []map[string]any
	reply map[string]any
}

func (b *fakeMediaBroker) requests() []map[string]any {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]map[string]any(nil), b.reqs...)
}

func startFakeMediaBroker(t *testing.T, reply map[string]any) *fakeMediaBroker {
	t.Helper()
	dir, err := os.MkdirTemp("", "bmps")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "p.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	t.Setenv("BENMORE_PRESIGN_SOCKET", sock)
	b := &fakeMediaBroker{reply: reply}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			var req map[string]any
			_ = json.NewDecoder(io.LimitReader(conn, 16<<10)).Decode(&req)
			b.mu.Lock()
			b.reqs = append(b.reqs, req)
			b.mu.Unlock()
			out, _ := json.Marshal(b.reply)
			conn.Write(out)
			conn.Close()
		}
	}()
	return b
}

func serveFileForTest(t *testing.T, app *App, raw string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	ctx := &FlowContext{App: app, Writer: rec, Request: httptest.NewRequest(http.MethodGet, "/f/doc", nil), Data: map[string]any{}, Params: map[string]string{}}
	if err := execStepServeFile(ctx, &FlowStep{Type: "serve_file", ServeFile: &FlowServeFile{Path: raw}}); err != nil {
		t.Fatalf("serve_file: %v", err)
	}
	return rec
}

// A hosted tenant process never signs a private CDN URL with a local key,
// even when its environment still carries one (tenant.env written before
// signing moved into the router). With no broker reachable it fails closed.
func TestServeFileHostedTenantNeverSignsLocally(t *testing.T) {
	t.Setenv("BENMORE_BIND_LOOPBACK", "1")
	t.Setenv("BENMORE_PRESIGN_SOCKET", filepath.Join(t.TempDir(), "missing.sock"))
	cfg := testMediaConfig(t)
	withPlatformMedia(t, cfg)
	app := &App{Dir: t.TempDir()}
	raw := "https://" + cfg.CDNDomain + "/private/" + appMediaPrefix(app) + "/uploads/private/a.pdf"

	rec := serveFileForTest(t, app, raw)
	if loc := rec.Header().Get("Location"); strings.Contains(loc, "Signature=") || strings.Contains(loc, "KLOCAL") {
		t.Fatalf("hosted tenant signed locally: %s", loc)
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 when the platform signer is unreachable", rec.Code)
	}
}

// Whenever the broker socket is reachable the router signs: the tenant sends
// the object key and requested lifetime and uses the router's URL.
func TestServeFileSignsThroughBroker(t *testing.T) {
	for _, hosted := range []string{"1", ""} {
		t.Run("hosted="+hosted, func(t *testing.T) {
			t.Setenv("BENMORE_BIND_LOOPBACK", hosted)
			broker := startFakeMediaBroker(t, map[string]any{"url": "https://cdn.example.test/router-signed", "key": "k"})
			cfg := testMediaConfig(t)
			withPlatformMedia(t, cfg)
			app := &App{Dir: t.TempDir()}
			key := "private/" + appMediaPrefix(app) + "/uploads/private/a.pdf"

			rec := serveFileForTest(t, app, "https://"+cfg.CDNDomain+"/"+key)
			if rec.Code != http.StatusFound || rec.Header().Get("Location") != "https://cdn.example.test/router-signed" {
				t.Fatalf("serve_file = %d %q, want 302 to the broker's URL", rec.Code, rec.Header().Get("Location"))
			}
			reqs := broker.requests()
			if len(reqs) != 1 {
				t.Fatalf("broker saw %d requests, want 1", len(reqs))
			}
			got := reqs[0]
			if got["operation"] != "sign" || got["path"] != key || got["prefix"] != appMediaPrefix(app) {
				t.Fatalf("broker request = %#v", got)
			}
			if ttl, _ := got["expires_in"].(float64); ttl != 120 {
				t.Fatalf("requested lifetime = %v, want 120", got["expires_in"])
			}
		})
	}
}

// A broker refusal is final: no local fallback, whatever the process holds.
func TestServeFileBrokerRefusalFailsClosed(t *testing.T) {
	for _, hosted := range []string{"1", ""} {
		t.Run("hosted="+hosted, func(t *testing.T) {
			t.Setenv("BENMORE_BIND_LOOPBACK", hosted)
			startFakeMediaBroker(t, map[string]any{"error": "path outside caller's private media"})
			cfg := testMediaConfig(t)
			withPlatformMedia(t, cfg)
			app := &App{Dir: t.TempDir()}
			rec := serveFileForTest(t, app, "https://"+cfg.CDNDomain+"/private/"+appMediaPrefix(app)+"/uploads/private/a.pdf")
			if rec.Code != http.StatusInternalServerError || rec.Header().Get("Location") != "" {
				t.Fatalf("serve_file = %d %q, want 500 and no redirect", rec.Code, rec.Header().Get("Location"))
			}
		})
	}
}

// Self-hosted and single-process `benmore host` keep signing with the key
// they hold when no broker socket exists.
func TestServeFileSelfHostedSignsLocally(t *testing.T) {
	t.Setenv("BENMORE_BIND_LOOPBACK", "")
	t.Setenv("BENMORE_PRESIGN_SOCKET", filepath.Join(t.TempDir(), "missing.sock"))
	cfg := testMediaConfig(t)
	withPlatformMedia(t, cfg)
	app := &App{Dir: t.TempDir()}
	rec := serveFileForTest(t, app, "https://"+cfg.CDNDomain+"/private/"+appMediaPrefix(app)+"/uploads/private/a.pdf")
	loc := rec.Header().Get("Location")
	if rec.Code != http.StatusFound || !strings.Contains(loc, "Signature=") || !strings.Contains(loc, "Key-Pair-Id=KLOCAL") {
		t.Fatalf("serve_file = %d %q, want a locally signed redirect", rec.Code, loc)
	}
}

// verifyCloudFrontCannedSignature checks a canned-policy signed URL against
// the public key, rebuilding the policy the way CloudFront does.
func verifyCloudFrontCannedSignature(t *testing.T, signed string, pub *rsa.PublicKey) (resource string, expires int64) {
	t.Helper()
	i := strings.Index(signed, "?Expires=")
	if i < 0 {
		t.Fatalf("no Expires in %s", signed)
	}
	resource = signed[:i]
	var sig, keyPair string
	for _, part := range strings.Split(signed[i+1:], "&") {
		k, v, _ := strings.Cut(part, "=")
		switch k {
		case "Expires":
			if _, err := fmt.Sscan(v, &expires); err != nil {
				t.Fatalf("bad Expires %q", v)
			}
		case "Signature":
			sig = v
		case "Key-Pair-Id":
			keyPair = v
		}
	}
	if keyPair == "" || sig == "" {
		t.Fatalf("incomplete signed url %s", signed)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.NewReplacer("-", "+", "_", "=", "~", "/").Replace(sig))
	if err != nil {
		t.Fatalf("signature encoding: %v", err)
	}
	policy := fmt.Sprintf(`{"Statement":[{"Resource":"%s","Condition":{"DateLessThan":{"AWS:EpochTime":%d}}}]}`, resource, expires)
	sum := sha1.Sum([]byte(policy))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA1, sum[:], raw); err != nil {
		t.Fatalf("signature does not verify for %s: %v", resource, err)
	}
	return resource, expires
}

// The router signs only keys under the connecting peer's own private
// prefix, using the same containment rule serve_file applies, and refuses
// every way of naming another app's object.
func TestPresignBrokerSignScopesToPeerPrefix(t *testing.T) {
	cfg := testMediaConfig(t)
	now := time.Unix(1_900_000_000, 0)
	sign := func(req presignReq, allowed string, firstParty bool) (*presignResp, error) {
		req.Operation = "sign"
		if req.ExpiresIn == 0 {
			req.ExpiresIn = 120
		}
		return dispatchPresignBrokerRequest(req, allowed, firstParty, cfg, now)
	}

	resp, err := sign(presignReq{Prefix: "tenant", Path: "private/tenant/uploads/private/a.pdf"}, "tenant", false)
	if err != nil {
		t.Fatalf("own private object refused: %v", err)
	}
	resource, _ := verifyCloudFrontCannedSignature(t, resp.URL, &cfg.PrivateKey.PublicKey)
	if resource != "https://cdn.example.test/private/tenant/uploads/private/a.pdf" {
		t.Fatalf("signed resource = %q", resource)
	}
	// Nested private folders (uploads/<kind>/private/...) stay signable.
	if _, err := sign(presignReq{Path: "private/tenant/uploads/docs/private/b.pdf"}, "tenant", false); err != nil {
		t.Fatalf("nested private object refused: %v", err)
	}

	refused := map[string]presignReq{
		"other app":               {Path: "private/victim/uploads/private/a.pdf"},
		"claimed prefix":          {Prefix: "victim", Path: "private/victim/uploads/private/a.pdf"},
		"public object":           {Path: "public/tenant/uploads/files/a.png"},
		"traversal":               {Path: "private/tenant/uploads/../../victim/uploads/private/a.pdf"},
		"encoded traversal":       {Path: "private/tenant/uploads/%2e%2e/%2e%2e/victim/a.pdf"},
		"backslash":               {Path: "private/tenant/uploads\\..\\victim\\a.pdf"},
		"double slash":            {Path: "private/tenant//victim/a.pdf"},
		"leading slash":           {Path: "/private/tenant/uploads/private/a.pdf"},
		"no object":               {Path: "private/tenant"},
		"policy injection":        {Path: `private/tenant/uploads/private/a","Resource":"https://cdn.example.test/private/victim/*`},
		"quote without slashes":   {Path: `private/tenant/uploads/private/a","Condition":{"x":"y`},
		"control character":       {Path: "private/tenant/uploads/private/a\n.pdf"},
		"negative expiry":         {Path: "private/tenant/uploads/private/a.pdf", ExpiresIn: -5},
		"unknown visibility tier": {Path: "secret/tenant/uploads/private/a.pdf"},
	}
	for name, req := range refused {
		if resp, err := sign(req, "tenant", false); err == nil {
			t.Errorf("%s: broker signed %q", name, resp.URL)
		}
	}
	// An unmapped uid (not benmore, not benmore-app-<sub>) gets nothing.
	if _, err := sign(presignReq{Prefix: "tenant", Path: "private/tenant/uploads/private/a.pdf"}, "", false); err == nil {
		t.Error("unmapped caller was served")
	}
	// First party (_platform) names its own prefix.
	if _, err := sign(presignReq{Prefix: "_platform", Path: "private/_platform/uploads/private/v.webm"}, "", true); err != nil {
		t.Errorf("first-party signing refused: %v", err)
	}
	if _, err := sign(presignReq{Path: "private/_platform/uploads/private/v.webm"}, "", true); err == nil {
		t.Error("first-party request without a prefix was served")
	}
	// A router without the signing key refuses rather than minting nothing.
	unsigned := &PlatformMediaConfig{Bucket: "media", CDNDomain: "cdn.example.test"}
	if _, err := dispatchPresignBrokerRequest(presignReq{Operation: "sign", Path: "private/tenant/uploads/private/a.pdf", ExpiresIn: 60}, "tenant", false, unsigned, now); err == nil {
		t.Error("broker signed without a configured key")
	}
}

// The router caps the lifetime a tenant may request.
func TestPresignBrokerSignClampsExpiry(t *testing.T) {
	cfg := testMediaConfig(t)
	now := time.Unix(1_900_000_000, 0)
	for _, tc := range []struct {
		requested int64
		want      int64
	}{
		{120, 120},
		{int64(mediaSignMaxTTL / time.Second), int64(mediaSignMaxTTL / time.Second)},
		{7 * 24 * 3600, int64(mediaSignMaxTTL / time.Second)},
		{1 << 62, int64(mediaSignMaxTTL / time.Second)},
	} {
		resp, err := dispatchPresignBrokerRequest(presignReq{Operation: "sign", Path: "private/tenant/uploads/private/a.pdf", ExpiresIn: tc.requested}, "tenant", false, cfg, now)
		if err != nil {
			t.Fatalf("expires_in=%d: %v", tc.requested, err)
		}
		_, expires := verifyCloudFrontCannedSignature(t, resp.URL, &cfg.PrivateKey.PublicKey)
		if got := expires - now.Unix(); got != tc.want {
			t.Errorf("expires_in=%d signed for %ds, want %ds", tc.requested, got, tc.want)
		}
	}
	if _, err := dispatchPresignBrokerRequest(presignReq{Operation: "sign", Path: "private/tenant/uploads/private/a.pdf"}, "tenant", false, cfg, now); err == nil {
		t.Error("missing expires_in was accepted")
	}
}

// transcribe signs this app's private CDN audio through the broker, and
// fails with a signing error (not a misleading 403 from an unsigned fetch)
// when a hosted tenant cannot reach it.
func TestTranscribePrivateCDNAudioSigning(t *testing.T) {
	t.Setenv("BENMORE_BIND_LOOPBACK", "1")
	cfg := testMediaConfig(t)
	withPlatformMedia(t, cfg)
	app := &App{Dir: t.TempDir()}
	own := "https://" + cfg.CDNDomain + "/private/" + appMediaPrefix(app) + "/uploads/private/brief.webm"

	t.Run("broker", func(t *testing.T) {
		broker := startFakeMediaBroker(t, map[string]any{"url": "https://cdn.example.test/router-signed-audio"})
		signed, ok, err := signPrivateCDNURLForApp(app, own)
		if err != nil || !ok || signed != "https://cdn.example.test/router-signed-audio" {
			t.Fatalf("signPrivateCDNURLForApp = %q, %v, %v", signed, ok, err)
		}
		if reqs := broker.requests(); len(reqs) != 1 || reqs[0]["operation"] != "sign" {
			t.Fatalf("broker requests = %#v", reqs)
		}
	})
	t.Run("unreachable", func(t *testing.T) {
		t.Setenv("BENMORE_PRESIGN_SOCKET", filepath.Join(t.TempDir(), "missing.sock"))
		if _, _, err := signPrivateCDNURLForApp(app, own); err == nil {
			t.Fatal("hosted tenant signed without the broker")
		}
		if _, _, _, err := resolveTranscribeInput(context.Background(), app, own, transcribeConfig()); err == nil || !strings.Contains(err.Error(), "sign") {
			t.Fatalf("resolveTranscribeInput error = %v, want a signing error", err)
		}
		// Other apps' objects and public objects are fetched as given.
		for _, raw := range []string{
			"https://" + cfg.CDNDomain + "/private/other-app/uploads/private/a.webm",
			"https://" + cfg.CDNDomain + "/public/" + appMediaPrefix(app) + "/uploads/files/a.webm",
		} {
			if _, ok, err := signPrivateCDNURLForApp(app, raw); ok || err != nil {
				t.Errorf("signPrivateCDNURLForApp(%q) = %v, %v; want untouched", raw, ok, err)
			}
		}
	})
}

// A hosted tenant does not load the signing key even when its environment
// carries it; the router and self-hosted processes still do.
func TestHostedTenantMediaConfigOmitsSigningKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	t.Setenv("BENMORE_PLATFORM_MEDIA_BUCKET", "media")
	t.Setenv("BENMORE_PLATFORM_MEDIA_CDN_DOMAIN", "cdn.example.test")
	t.Setenv("BENMORE_PLATFORM_MEDIA_KEYPAIR_ID", "KLOCAL")
	t.Setenv("BENMORE_PLATFORM_MEDIA_PRIVATE_KEY", pemKey)

	t.Setenv("BENMORE_BIND_LOOPBACK", "1")
	cfg := loadPlatformMediaConfig()
	if cfg == nil || cfg.CDNDomain != "cdn.example.test" || cfg.Bucket != "media" {
		t.Fatalf("hosted media config = %#v", cfg)
	}
	if cfg.PrivateKey != nil || cfg.KeyPairID != "" || cfg.canSign() {
		t.Fatal("hosted tenant loaded the CloudFront signing key")
	}

	t.Setenv("BENMORE_BIND_LOOPBACK", "")
	if cfg := loadPlatformMediaConfig(); cfg == nil || !cfg.canSign() {
		t.Fatal("self-hosted process lost its signing key")
	}
}
