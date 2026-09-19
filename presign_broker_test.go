package main

import (
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestAWSURIEncode(t *testing.T) {
	cases := []struct {
		in          string
		encodeSlash bool
		want        string
	}{
		{"public/app/uploads/a b.png", false, "public/app/uploads/a%20b.png"}, // space encoded, slash kept
		{"public/app/uploads/a b.png", true, "public%2Fapp%2Fuploads%2Fa%20b.png"},
		{"AKIA.../scope", true, "AKIA...%2Fscope"}, // dots pass, slash encoded
		{"safe-_.~chars", true, "safe-_.~chars"},   // unreserved pass through
		{"a+b=c", true, "a%2Bb%3Dc"},               // + and = encoded
	}
	for _, c := range cases {
		if got := awsURIEncode(c.in, c.encodeSlash); got != c.want {
			t.Errorf("awsURIEncode(%q,%v) = %q, want %q", c.in, c.encodeSlash, got, c.want)
		}
	}
}

func TestAWSCanonicalQuery(t *testing.T) {
	got := awsCanonicalQuery(map[string]string{
		"X-Amz-SignedHeaders": "content-type;host",
		"X-Amz-Algorithm":     "AWS4-HMAC-SHA256",
		"X-Amz-Date":          "20260601T000000Z",
	})
	// Must be sorted by key, RFC3986-encoded (semicolon → %3B).
	want := "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Date=20260601T000000Z&X-Amz-SignedHeaders=content-type%3Bhost"
	if got != want {
		t.Errorf("awsCanonicalQuery =\n  %q\nwant\n  %q", got, want)
	}
}

func TestPresignS3PutURL_Structure(t *testing.T) {
	s3 := &S3Storage{Bucket: "test-bucket", Region: "us-east-1", Key: "AKIATEST", Secret: "secret"}
	url, headers, err := presignS3PutURL(s3, "public/myapp/uploads/avatar.png", "image/png", "", "public, max-age=31536000, immutable", 90*time.Second)
	if err != nil {
		t.Fatalf("presign err: %v", err)
	}
	// Path-style host + bucket + key.
	if !strings.HasPrefix(url, "https://s3.us-east-1.amazonaws.com/test-bucket/public/myapp/uploads/avatar.png?") {
		t.Errorf("unexpected url base: %s", url)
	}
	for _, must := range []string{
		"X-Amz-Algorithm=AWS4-HMAC-SHA256",
		"X-Amz-Credential=AKIATEST%2F",
		"X-Amz-Expires=90",
		// cache-control sorts before content-type before host.
		"X-Amz-SignedHeaders=cache-control%3Bcontent-type%3Bhost",
		"&X-Amz-Signature=",
	} {
		if !strings.Contains(url, must) {
			t.Errorf("url missing %q:\n%s", must, url)
		}
	}
	// Signature is 64 lowercase hex chars.
	sig := regexp.MustCompile(`X-Amz-Signature=([0-9a-f]+)`).FindStringSubmatch(url)
	if sig == nil || len(sig[1]) != 64 {
		t.Errorf("signature not 64 hex chars: %v", sig)
	}
	// The caller must send exactly the content-type that was signed.
	if headers["Content-Type"] != "image/png" {
		t.Errorf("headers Content-Type = %q, want image/png", headers["Content-Type"])
	}
	if _, ok := headers["Content-Disposition"]; ok {
		t.Error("no disposition was set; header should be absent")
	}
	// Public media must be returned (and signed) with immutable Cache-Control
	// so browsers/CloudFront stop revalidating content-hash-named objects.
	if headers["Cache-Control"] != "public, max-age=31536000, immutable" {
		t.Errorf("public Cache-Control = %q, want immutable", headers["Cache-Control"])
	}
}

func TestPresignS3PutURL_WithDisposition(t *testing.T) {
	s3 := &S3Storage{Bucket: "b", Region: "us-east-1", Key: "AKIATEST", Secret: "secret"}
	url, headers, err := presignS3PutURL(s3, "private/app/uploads/doc.bin", "application/octet-stream",
		`attachment; filename="doc.bin"`, "", 90*time.Second)
	if err != nil {
		t.Fatalf("presign err: %v", err)
	}
	// content-disposition sorts before content-type before host.
	if !strings.Contains(url, "X-Amz-SignedHeaders=content-disposition%3Bcontent-type%3Bhost") {
		t.Errorf("signed headers should include disposition, sorted:\n%s", url)
	}
	if headers["Content-Disposition"] != `attachment; filename="doc.bin"` {
		t.Errorf("disposition header not returned: %q", headers["Content-Disposition"])
	}
}

func TestPresignS3PutURL_NoCreds(t *testing.T) {
	// Empty key + non-AWS endpoint → resolveCreds returns "" → presign refuses
	// (no silent unsigned URL).
	s3 := &S3Storage{Bucket: "b", Region: "us-east-1", Endpoint: "https://minio.local"}
	if _, _, err := presignS3PutURL(s3, "k", "image/png", "", "", time.Minute); err == nil {
		t.Error("expected error when no credentials resolvable")
	}
}
