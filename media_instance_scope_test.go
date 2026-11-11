//go:build !cli

package main

import (
	"encoding/json"
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

const (
	scopeTestApp     = "shop-a1b2c3"
	scopeTestDev     = "shop-a1b2c3-dev"
	scopeTestProdKey = "private/" + scopeTestApp + "/uploads/private/prod.pdf"
	scopeTestDevKey  = "private/" + scopeTestDev + "/uploads/private/dev.pdf"
)

// withInstanceSecrets gives this process a stable server secret (the
// instance's own) and the router's lookup the secrets of both instances.
func withInstanceSecrets(t *testing.T, own string, secrets map[string]string) {
	t.Helper()
	oldOwn, oldLookup := serverSecret, presignInstanceSecret
	serverSecret = own
	presignInstanceSecret = func(instance string) string { return secrets[instance] }
	t.Cleanup(func() { serverSecret, presignInstanceSecret = oldOwn, oldLookup })
}

// signedPresignReq builds a request carrying instance's proof under secret.
func signedPresignReq(req presignReq, instance, secret string, now time.Time) presignReq {
	req.Instance, req.Time = instance, now.Unix()
	req.Proof = presignInstanceMAC(secret, req)
	return req
}

// startScopedTestBroker stands in for the router's broker: every request is
// scoped exactly as handlePresignConn scopes it for a peer uid mapped to
// allowedPrefix (presignCallerScope); deletes go to the fake bucket s3.
func startScopedTestBroker(t *testing.T, allowedPrefix string, cfg *PlatformMediaConfig, s3 *S3Storage) {
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
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			var req presignReq
			_ = json.NewDecoder(io.LimitReader(conn, 16<<10)).Decode(&req)
			var resp *presignResp
			scope, err := presignCallerScope(req, allowedPrefix, false, time.Now())
			if err == nil {
				if req.Operation == "sign" {
					resp, err = executeMediaSignRequest(req, scope, cfg, time.Now())
				} else {
					resp, err = executePresignBrokerRequest(req, scope, s3)
				}
			}
			if err != nil {
				resp = &presignResp{Error: err.Error()}
			}
			out, _ := json.Marshal(resp)
			conn.Write(out)
			conn.Close()
		}
	}()
}

// fakeMediaBucketServer records the object keys DELETEd from bucket "media".
func fakeMediaBucketServer(t *testing.T) (*S3Storage, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var deleted []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			mu.Lock()
			deleted = append(deleted, strings.TrimPrefix(r.URL.Path, "/media/"))
			mu.Unlock()
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	s3 := &S3Storage{Bucket: "media", Region: "us-east-1", Endpoint: srv.URL, Key: "AKIDFIXTURE", Secret: "fixture-secret"}
	return s3, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), deleted...)
	}
}

// Reported 2026-11-04: dev and prod shared one media prefix, so a dev
// instance's delete_upload deleted production's object (a row copied by
// refresh-dev --with-data names it) and its new uploads landed next to
// production's. Now the dev instance writes and deletes only under
// <sub>-dev, end to end through the broker, while production's references
// stay servable from dev.
func TestDevInstanceMediaStaysOffProductionObjects(t *testing.T) {
	t.Setenv("BENMORE_BIND_LOOPBACK", "")
	cfg := testMediaConfig(t)
	withPlatformMedia(t, cfg)
	devSecret, prodSecret := strings.Repeat("d", 64), strings.Repeat("p", 64)
	withInstanceSecrets(t, devSecret, map[string]string{scopeTestDev: devSecret, scopeTestApp: prodSecret})
	s3, deleted := fakeMediaBucketServer(t)
	startScopedTestBroker(t, scopeTestApp, cfg, s3)

	appsDir := t.TempDir()
	dev := &App{Dir: filepath.Join(appsDir, scopeTestDev)}
	prod := &App{Dir: filepath.Join(appsDir, scopeTestApp)}
	cdn := "https://" + cfg.CDNDomain + "/"

	// New dev uploads are keyed under the dev instance's own prefix.
	if got := newCDNStorage(dev).cdnKeyFor("uploads/private/new.pdf"); got != "private/"+scopeTestDev+"/uploads/private/new.pdf" {
		t.Fatalf("dev upload key = %q, want it under %s", got, scopeTestDev)
	}
	if got := newCDNStorage(prod).cdnKeyFor("uploads/private/new.pdf"); got != "private/"+scopeTestApp+"/uploads/private/new.pdf" {
		t.Fatalf("prod upload key = %q", got)
	}

	// delete_upload from dev of a production reference fails before any
	// storage I/O; its own reference and a logical path stay in dev's prefix.
	if err := deletePrivateUpload(dev, cdn+scopeTestProdKey); err == nil {
		t.Fatal("the dev instance deleted a production object")
	}
	if err := deletePrivateUpload(dev, cdn+scopeTestDevKey); err != nil {
		t.Fatalf("dev could not delete its own upload: %v", err)
	}
	if err := deletePrivateUpload(dev, "uploads/private/prod.pdf"); err != nil {
		t.Fatalf("dev logical delete: %v", err)
	}
	want := []string{scopeTestDevKey, "private/" + scopeTestDev + "/uploads/private/prod.pdf"}
	if got := deleted(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("deleted keys = %q, want only dev's own %q", got, want)
	}

	// Production's references stay readable from dev (signed by the
	// router), and prod cannot serve the dev instance's objects.
	rec := serveFileForTest(t, dev, cdn+scopeTestProdKey)
	if rec.Code != http.StatusFound || !strings.HasPrefix(rec.Header().Get("Location"), cdn+scopeTestProdKey+"?Expires=") {
		t.Fatalf("dev serve_file of a production reference = %d %q, want a signed redirect", rec.Code, rec.Header().Get("Location"))
	}
	resource, _ := verifyCloudFrontCannedSignature(t, rec.Header().Get("Location"), &cfg.PrivateKey.PublicKey)
	if resource != cdn+scopeTestProdKey {
		t.Fatalf("signed resource = %q", resource)
	}
	if _, _, ok := cdnURLForServe(prod, cdn+scopeTestDevKey, cfg); ok {
		t.Fatal("prod resolved the dev instance's object")
	}
	if _, _, ok := cdnURLForServe(dev, cdn+"private/other-app/uploads/private/x.pdf", cfg); ok {
		t.Fatal("dev resolved another app's object")
	}
}

// The broker, not the app process, is the boundary: a compromised dev
// process can name any key, prefix or instance it likes. Only a proof under
// the instance's own secret moves a request off the uid's legacy scope, and
// a dev proof never reaches production's prefix for a write or delete.
func TestPresignBrokerScopesTheDevInstanceByItsProof(t *testing.T) {
	t.Setenv(presignRequireInstanceEnv, "")
	devSecret, prodSecret := strings.Repeat("d", 64), strings.Repeat("p", 64)
	withInstanceSecrets(t, devSecret, map[string]string{scopeTestDev: devSecret, scopeTestApp: prodSecret})
	now := time.Unix(1_900_000_000, 0)
	scope := func(req presignReq) (presignScope, error) {
		return presignCallerScope(req, scopeTestApp, false, now)
	}
	del := presignReq{Operation: "delete", Prefix: scopeTestApp, Path: "uploads/private/prod.pdf"}

	// Proven dev: writes and deletes under <sub>-dev whatever prefix it
	// claims; reads both.
	got, err := scope(signedPresignReq(del, scopeTestDev, devSecret, now))
	if err != nil || got.write != scopeTestDev || strings.Join(got.read, ",") != scopeTestDev+","+scopeTestApp {
		t.Fatalf("dev scope = %+v, %v", got, err)
	}
	// Proven prod: its own prefix only.
	got, err = scope(signedPresignReq(del, scopeTestApp, prodSecret, now))
	if err != nil || got.write != scopeTestApp || strings.Join(got.read, ",") != scopeTestApp {
		t.Fatalf("prod scope = %+v, %v", got, err)
	}

	refused := map[string]presignReq{
		"dev claims prod":        signedPresignReq(del, scopeTestApp, devSecret, now),
		"another app's instance": signedPresignReq(del, "other-x9y8z7-dev", devSecret, now),
		"expired proof":          signedPresignReq(del, scopeTestDev, devSecret, now.Add(-2*presignInstanceWindow)),
		"future proof":           signedPresignReq(del, scopeTestDev, devSecret, now.Add(2*presignInstanceWindow)),
		"proof without instance": {Operation: "delete", Path: del.Path, Proof: "00"},
		"instance without proof": {Operation: "delete", Path: del.Path, Instance: scopeTestDev, Time: now.Unix()},
	}
	tampered := signedPresignReq(presignReq{Operation: "sign", Path: scopeTestDevKey, ExpiresIn: 60}, scopeTestDev, devSecret, now)
	tampered.Operation = "delete"
	refused["proof for another operation"] = tampered
	moved := signedPresignReq(presignReq{Operation: "sign", Path: scopeTestDevKey, ExpiresIn: 60}, scopeTestDev, devSecret, now)
	moved.Path = scopeTestProdKey
	refused["proof for another key"] = moved
	for name, req := range refused {
		if got, err := scope(req); err == nil {
			t.Errorf("%s: scoped %+v", name, got)
		}
	}

	// A proof the router cannot check (it has no secret for the instance)
	// gets no more than sending no proof: the legacy scope, refused once
	// proofs are required (below).
	lookup := presignInstanceSecret
	presignInstanceSecret = func(string) string { return "" }
	if got, err := scope(signedPresignReq(del, scopeTestDev, devSecret, now)); err != nil || got.write != scopeTestApp || len(got.read) != 1 {
		t.Errorf("unverifiable proof scoped %+v, %v; want the legacy scope", got, err)
	}
	presignInstanceSecret = lookup

	// A delete executes under the proven write prefix.
	s3, deleted := fakeMediaBucketServer(t)
	devScope, _ := scope(signedPresignReq(del, scopeTestDev, devSecret, now))
	if _, err := executePresignBrokerRequest(del, devScope, s3); err != nil {
		t.Fatal(err)
	}
	if got := deleted(); len(got) != 1 || got[0] != "private/"+scopeTestDev+"/uploads/private/prod.pdf" {
		t.Fatalf("dev delete removed %q, want only the dev instance's key", got)
	}

	// Signing: dev may read production's private objects, prod never dev's.
	cfg := testMediaConfig(t)
	sign := func(path, instance, secret string) error {
		_, err := dispatchPresignBrokerRequest(signedPresignReq(presignReq{Operation: "sign", Path: path, ExpiresIn: 60}, instance, secret, now), scopeTestApp, false, cfg, now)
		return err
	}
	if err := sign(scopeTestProdKey, scopeTestDev, devSecret); err != nil {
		t.Errorf("dev could not sign a production reference: %v", err)
	}
	if err := sign(scopeTestDevKey, scopeTestDev, devSecret); err != nil {
		t.Errorf("dev could not sign its own object: %v", err)
	}
	if err := sign(scopeTestDevKey, scopeTestApp, prodSecret); err == nil {
		t.Error("prod signed the dev instance's object")
	}

	// No proof: an older binary keeps the uid's legacy scope until the
	// operator requires proofs; then it is refused.
	legacy, err := scope(del)
	if err != nil || legacy.write != scopeTestApp {
		t.Fatalf("legacy scope = %+v, %v", legacy, err)
	}
	t.Setenv(presignRequireInstanceEnv, "1")
	if got, err := scope(del); err == nil {
		t.Fatalf("a request without a proof was scoped %+v while proofs are required", got)
	}
	presignInstanceSecret = func(string) string { return "" }
	if got, err := scope(signedPresignReq(del, scopeTestDev, devSecret, now)); err == nil {
		t.Fatalf("an unverifiable proof was scoped %+v while proofs are required", got)
	}
	presignInstanceSecret = lookup
	if _, err := scope(signedPresignReq(del, scopeTestDev, devSecret, now)); err != nil {
		t.Fatalf("a valid proof was refused while proofs are required: %v", err)
	}
	// The trusted first-party user still names its own prefix.
	if got, err := presignCallerScope(presignReq{Prefix: "_platform"}, "", true, now); err != nil || got.write != "_platform" {
		t.Fatalf("first party = %+v, %v", got, err)
	}
}

// The app process proves its instance with its own server secret on every
// broker request, and sends nothing it cannot prove.
func TestPresignClientAttachesItsInstanceProof(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	secret := strings.Repeat("s", 64)
	withInstanceSecrets(t, secret, nil)
	req := presignReq{Operation: "sign", Path: scopeTestDevKey, ExpiresIn: 120}
	attachPresignInstanceProof(&req, scopeTestDev, now)
	if req.Instance != scopeTestDev || req.Time != now.Unix() || req.Proof != presignInstanceMAC(secret, req) {
		t.Fatalf("proof = %+v", req)
	}
	serverSecret = "short"
	req = presignReq{Operation: "sign", Path: scopeTestDevKey, Instance: "forged", Proof: "x"}
	attachPresignInstanceProof(&req, scopeTestDev, now)
	if req.Instance != "" || req.Proof != "" || req.Time != 0 {
		t.Fatalf("a process without a stable secret sent %+v", req)
	}
}
