//go:build !cli

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
)

func TestCDNKeyMapping(t *testing.T) {
	c := &CDNStorage{Prefix: "demo-app", CDNDomain: "cdn.example.com"}
	cases := map[string]string{
		"uploads/files/abc.png":   "public/demo-app/uploads/files/abc.png",
		"uploads/private/x.pdf":   "private/demo-app/uploads/private/x.pdf",
		"/uploads/avatars/a.webp": "public/demo-app/uploads/avatars/a.webp",
	}
	for in, want := range cases {
		if got := c.cdnKeyFor(in); got != want {
			t.Errorf("cdnKeyFor(%q)=%q want %q", in, got, want)
		}
	}
}

func TestUploadContentMeta(t *testing.T) {
	if ct, disp := uploadContentMeta("png", "image/png", "x.png"); !strings.HasPrefix(ct, "image/png") || disp != "" {
		t.Errorf("png: ct=%q disp=%q (want inline image/png)", ct, disp)
	}
	if _, disp := uploadContentMeta("svg", "text/xml", "x.svg"); !strings.Contains(disp, "attachment") {
		t.Errorf("svg should force attachment, got %q", disp)
	}
	if _, disp := uploadContentMeta("pdf", "application/pdf", "x.pdf"); disp != "" {
		t.Errorf("pdf should be inline, got %q", disp)
	}
}

func TestSignCloudFrontURL(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	signed, err := signCloudFrontURL("https://cdn.example.com/private/app/uploads/private/x.pdf", 1900000000, "K123", key)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Expires=1900000000", "Signature=", "Key-Pair-Id=K123"} {
		if !strings.Contains(signed, want) {
			t.Errorf("signed url missing %q: %s", want, signed)
		}
	}
	// CloudFront base64 must not contain +, =, / in the signature.
	sig := signed[strings.Index(signed, "Signature=")+len("Signature="):]
	sig = sig[:strings.Index(sig, "&")]
	if strings.ContainsAny(sig, "+=/") {
		t.Errorf("signature not CloudFront-base64 encoded: %s", sig)
	}
	// nil key → clear error, not a panic.
	if _, err := signCloudFrontURL("https://x/y", 1, "K", nil); err == nil {
		t.Error("expected error for nil key")
	}
}
