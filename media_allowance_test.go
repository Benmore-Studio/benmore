//go:build !cli

package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// noMediaMeter runs a test as every process but the router runs: nothing
// keeps an allowance.
func noMediaMeter(t *testing.T) {
	t.Helper()
	old := presignMediaMeter
	presignMediaMeter = nil
	t.Setenv(presignRequireSizeEnv, "")
	t.Cleanup(func() { presignMediaMeter = old })
}

// Without a meter (self-hosted, the framework edition, any process that is
// not the router) the broker's code path issues and deletes exactly as it
// did: no allowance, no refusal, no extra storage request. A declared size is
// still signed into the URL; a request without one gets the URL it always got.
func TestPresignBrokerWithoutAMeterKeepsNoAllowance(t *testing.T) {
	noMediaMeter(t)
	var heads, deletes atomic.Int64
	bucket := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodHead:
			heads.Add(1)
		case http.MethodDelete:
			deletes.Add(1)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(bucket.Close)
	s3 := &S3Storage{Bucket: "media", Region: "us-east-1", Endpoint: bucket.URL, Key: "AKIDFIXTURE", Secret: "fixture-secret"}
	scope := presignScope{write: "shop", read: []string{"shop"}}

	size := int64(4096)
	sized, err := executePresignBrokerRequest(presignReq{Path: "uploads/files/a.png", Size: &size}, scope, s3)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sized.URL, "X-Amz-SignedHeaders=cache-control%3Bcontent-length%3Bcontent-type%3Bhost") {
		t.Fatalf("a declared size is not signed into the URL: %s", sized.URL)
	}
	if _, sent := sized.Headers["Content-Length"]; sent {
		t.Fatalf("the length is the body's to carry, not a header to copy: %v", sized.Headers)
	}
	// An older binary declares none and gets the URL it always got.
	legacy, err := executePresignBrokerRequest(presignReq{Path: "uploads/files/a.png"}, scope, s3)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(legacy.URL, "X-Amz-SignedHeaders=cache-control%3Bcontent-type%3Bhost") {
		t.Fatalf("a request without a size changed shape: %s", legacy.URL)
	}
	// Two URLs for different sizes carry different signatures: the length is
	// part of what is signed.
	other := int64(4097)
	resized, _ := executePresignBrokerRequest(presignReq{Path: "uploads/files/a.png", Size: &other}, scope, s3)
	signature := func(u string) string { return u[strings.LastIndex(u, "X-Amz-Signature="):] }
	if resized == nil || signature(resized.URL) == signature(sized.URL) {
		t.Fatal("the signature does not depend on the declared size")
	}
	if _, err := executePresignBrokerRequest(presignReq{Operation: "delete", Path: "uploads/private/a.pdf"}, scope, s3); err != nil {
		t.Fatal(err)
	}
	if heads.Load() != 0 || deletes.Load() != 1 {
		t.Fatalf("without a meter a delete made %d HEAD and %d DELETE request(s), want 0 and 1", heads.Load(), deletes.Load())
	}

	// Sizes the store could not hold are refused.
	for _, bad := range []int64{-1, presignMaxObjectBytes + 1} {
		if _, err := executePresignBrokerRequest(presignReq{Path: "uploads/files/a.png", Size: &bad}, scope, s3); err == nil || err.Error() != "bad upload size" {
			t.Errorf("declared size %d: %v, want a refusal", bad, err)
		}
	}
	// The operator's switch refuses a request that declares none.
	t.Setenv(presignRequireSizeEnv, "1")
	if _, err := executePresignBrokerRequest(presignReq{Path: "uploads/files/a.png"}, scope, s3); err == nil || err.Error() != "upload size required" {
		t.Fatalf("an undeclared size with the switch on: %v", err)
	}
	if _, err := executePresignBrokerRequest(presignReq{Path: "uploads/files/a.png", Size: &size}, scope, s3); err != nil {
		t.Fatalf("a declared size with the switch on: %v", err)
	}
	if _, err := executePresignBrokerRequest(presignReq{Operation: "delete", Path: "uploads/private/a.pdf"}, scope, s3); err != nil {
		t.Fatalf("a delete with the switch on: %v", err)
	}
}

// The app process declares the exact length of what it uploads, and turns the
// broker's allowance refusal into the typed error the upload routes answer
// with 507; any other broker error stays what it was.
func TestAppProcessDeclaresUploadSizeAndRelaysTheAllowanceRefusal(t *testing.T) {
	var got atomic.Int64
	put := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got.Store(r.ContentLength) }))
	t.Cleanup(put.Close)
	c := &CDNStorage{s3: &S3Storage{Bucket: "media", Region: "us-east-1"}, Prefix: "shop", CDNDomain: "cdn.example.test"}

	broker := startFakeMediaBroker(t, map[string]any{"url": put.URL + "/media/public/shop/uploads/files/a.txt", "key": "public/shop/uploads/files/a.txt", "headers": map[string]string{"Content-Type": "text/plain"}})
	if _, err := c.saveViaBroker(presignBrokerSocketPath(), "uploads/files/a.txt", strings.NewReader(strings.Repeat("a", 1234)), "text/plain", ""); err != nil {
		t.Fatal(err)
	}
	reqs := broker.requests()
	if len(reqs) != 1 || reqs[0]["size"] != float64(1234) || got.Load() != 1234 {
		t.Fatalf("the app declared size %v and sent %d bytes, want 1234 and 1234 (%v)", reqs[0]["size"], got.Load(), reqs)
	}
	// An empty file declares 0, not nothing.
	if _, err := c.saveViaBroker(presignBrokerSocketPath(), "uploads/files/a.txt", strings.NewReader(""), "text/plain", ""); err != nil {
		t.Fatal(err)
	}
	if reqs := broker.requests(); reqs[1]["size"] != float64(0) {
		t.Fatalf("an empty upload declared %v, want 0", reqs[1]["size"])
	}

	// The allowance refusal, as the router's broker replies it.
	refusal := presignErrorReply(&mediaAllowanceError{Message: "media storage allowance reached: 1.0 GB of its 1 GB allowance", UsedBytes: 1 << 30, LimitBytes: 1 << 30})
	startFakeMediaBroker(t, map[string]any{"error": refusal.Error, "code": refusal.Code, "used_bytes": refusal.UsedBytes, "limit_bytes": refusal.LimitBytes})
	_, err := c.saveViaBroker(presignBrokerSocketPath(), "uploads/files/a.txt", strings.NewReader("abc"), "text/plain", "")
	var refused *mediaAllowanceError
	if !errors.As(err, &refused) || refused.UsedBytes != 1<<30 || refused.LimitBytes != 1<<30 {
		t.Fatalf("the allowance refusal arrived as %v", err)
	}
	rec := httptest.NewRecorder()
	if !respondMediaAllowance(rec, fmt.Errorf("save upload: %w", err)) {
		t.Fatal("the upload routes did not recognize the refusal")
	}
	body := rec.Body.String()
	if rec.Code != http.StatusInsufficientStorage {
		t.Fatalf("status %d, want 507", rec.Code)
	}
	for _, want := range []string{`"error":"storage cap reached"`, `"code":"media_storage_limit"`, `"docs":"uploads.storage_allowance"`, `"used_bytes":1073741824`, `"limit_bytes":1073741824`, `"detail":"media storage allowance reached: 1.0 GB of its 1 GB allowance"`} {
		if !strings.Contains(body, want) {
			t.Errorf("the 507 body %s does not carry %s", body, want)
		}
	}

	// Any other refusal is still a broker error, never the allowance answer.
	startFakeMediaBroker(t, map[string]any{"error": "file type not allowed"})
	_, err = c.saveViaBroker(presignBrokerSocketPath(), "uploads/files/a.html", strings.NewReader("abc"), "text/html", "")
	if err == nil || errors.As(err, &refused) || !strings.Contains(err.Error(), "presign broker: file type not allowed") {
		t.Fatalf("another broker refusal arrived as %v", err)
	}
	if respondMediaAllowance(httptest.NewRecorder(), err) {
		t.Fatal("an ordinary upload error was answered as an allowance refusal")
	}
	if reply := presignErrorReply(errors.New("bad path")); reply.Error != "bad path" || reply.Code != "" || reply.UsedBytes != 0 {
		t.Fatalf("an ordinary error's reply = %+v", reply)
	}
}

// ObjectSize is how the router measures a stored object: the length the store
// reports, "no such object", or an error it does not guess around.
func TestS3ObjectSizeReadsTheStore(t *testing.T) {
	bucket := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		switch r.URL.Path {
		case "/media/private/shop/uploads/private/a.pdf":
			w.Header().Set("Content-Length", "52428800")
		case "/media/private/shop/uploads/private/empty.pdf":
			w.Header().Set("Content-Length", "0")
		case "/media/private/shop/uploads/private/denied.pdf":
			w.WriteHeader(http.StatusForbidden)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(bucket.Close)
	s3 := &S3Storage{Bucket: "media", Region: "us-east-1", Endpoint: bucket.URL, Key: "AKIDFIXTURE", Secret: "fixture-secret"}
	ctx := context.Background()
	if size, found, err := s3.ObjectSize(ctx, "private/shop/uploads/private/a.pdf"); err != nil || !found || size != 50<<20 {
		t.Fatalf("a stored object: %d %v %v", size, found, err)
	}
	if size, found, err := s3.ObjectSize(ctx, "private/shop/uploads/private/empty.pdf"); err != nil || !found || size != 0 {
		t.Fatalf("an empty object: %d %v %v", size, found, err)
	}
	if _, found, err := s3.ObjectSize(ctx, "private/shop/uploads/private/missing.pdf"); err != nil || found {
		t.Fatalf("a missing object: found=%v err=%v", found, err)
	}
	if _, found, err := s3.ObjectSize(ctx, "private/shop/uploads/private/denied.pdf"); err == nil || found {
		t.Fatalf("a refused HEAD must be an error, not a size: found=%v err=%v", found, err)
	}
	if _, _, err := s3.ObjectSize(ctx, ""); err == nil {
		t.Fatal("an empty key was accepted")
	}
}
