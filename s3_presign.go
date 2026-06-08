//go:build !cli

package main

// AWS Signature V4 — presigned URL variant.
//
// signAWSv4 (upload.go) signs requests with HEADERS; presigned URLs put
// the signature in the QUERY STRING so a client without our credentials
// can do a single direct PUT or GET to S3. That's the whole point of
// "no files hitting EC2" — the bytes go browser → S3 directly.
//
// Standard recipe:
// https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html
//
// We support PUT (client uploads) and GET (client reads private files).
// PUT URLs bake in content-length range + content-type via signed
// headers (browser MUST send those exact values on the PUT or S3 rejects
// — that's the policy enforcement).

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

// PresignOptions controls what gets baked into a presigned URL.
//
// ContentType, when set on a PUT, forces the client to send exactly
// that Content-Type header — S3 verifies it against the signature and
// rejects mismatches. That's how we enforce "this URL only uploads
// PNGs" without trusting the browser.
//
// MaxSize, when set, adds a Content-Length header to the signed set so
// S3 enforces it. (S3 also accepts policy-based content-length-range
// via POST forms, but PUT uses the simpler header check.)
type PresignOptions struct {
	ContentType string
	MaxSize     int64 // bytes; 0 = no cap (don't do this in prod)
	ExpiresIn   time.Duration
}

// PresignS3PutURL returns a presigned PUT URL the client can use to
// upload one object to S3. The signature covers Content-Type and
// Content-Length (when set), so a request with mismatched headers gets
// 403 SignatureDoesNotMatch from S3 before bytes flow.
//
// bucket/region/key identify the object. creds come from the caller —
// usually IMDS via S3Storage.resolveCreds, but the function takes them
// directly so it's testable in isolation.
func PresignS3PutURL(bucket, region, key, accessKey, secretKey, sessionToken string, opts PresignOptions) string {
	return presignS3URL("PUT", bucket, region, key, accessKey, secretKey, sessionToken, opts)
}

// PresignS3GetURL returns a presigned GET URL with no content-type
// constraint. Used for private file reads — short TTL, single use is
// not enforceable by S3 itself but the short window keeps the blast
// radius small if a URL leaks.
func PresignS3GetURL(bucket, region, key, accessKey, secretKey, sessionToken string, expiresIn time.Duration) string {
	return presignS3URL("GET", bucket, region, key, accessKey, secretKey, sessionToken, PresignOptions{
		ExpiresIn: expiresIn,
	})
}

func presignS3URL(method, bucket, region, key, accessKey, secretKey, sessionToken string, opts PresignOptions) string {
	if opts.ExpiresIn <= 0 {
		opts.ExpiresIn = 5 * time.Minute
	}
	if opts.ExpiresIn > 7*24*time.Hour {
		opts.ExpiresIn = 7 * 24 * time.Hour // S3 max is 7 days
	}

	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")
	host := fmt.Sprintf("%s.s3.%s.amazonaws.com", bucket, region)
	credentialScope := fmt.Sprintf("%s/%s/s3/aws4_request", dateStamp, region)

	// Signed headers: just Host for GET. PUT also signs Content-Type
	// (and Content-Length when MaxSize set) so the policy is locked into
	// the signature — clients can't upload a different content type.
	//
	// CRITICAL: the canonical-headers block MUST be sorted alphabetically
	// by header name. Build into a map keyed by lowercased name and
	// emit in sorted order — otherwise S3 returns SignatureDoesNotMatch.
	headerMap := map[string]string{"host": host}
	if method == "PUT" && opts.ContentType != "" {
		headerMap["content-type"] = opts.ContentType
	}
	if method == "PUT" && opts.MaxSize > 0 {
		headerMap["content-length"] = fmt.Sprintf("%d", opts.MaxSize)
	}
	signedHeaderList := make([]string, 0, len(headerMap))
	for k := range headerMap {
		signedHeaderList = append(signedHeaderList, k)
	}
	sort.Strings(signedHeaderList)
	var canonicalHeaders strings.Builder
	for _, k := range signedHeaderList {
		canonicalHeaders.WriteString(k)
		canonicalHeaders.WriteByte(':')
		canonicalHeaders.WriteString(headerMap[k])
		canonicalHeaders.WriteByte('\n')
	}
	signedHeaders := strings.Join(signedHeaderList, ";")

	// Build canonical query string. Sigv4 requires sorted, URL-encoded
	// (RFC 3986) query keys + values, and `X-Amz-Signature` itself is
	// appended AFTER signing (not in the canonical string).
	query := url.Values{}
	query.Set("X-Amz-Algorithm", "AWS4-HMAC-SHA256")
	query.Set("X-Amz-Credential", accessKey+"/"+credentialScope)
	query.Set("X-Amz-Date", amzDate)
	query.Set("X-Amz-Expires", fmt.Sprintf("%d", int(opts.ExpiresIn.Seconds())))
	query.Set("X-Amz-SignedHeaders", signedHeaders)
	if sessionToken != "" {
		query.Set("X-Amz-Security-Token", sessionToken)
	}
	canonicalQuery := canonicalQueryString(query)

	// Canonical URI: the object path, URL-encoded per RFC 3986 except
	// the slash separator. S3 normalizes "//" so we leave the leading
	// slash and encode the rest of the key.
	canonicalURI := "/" + s3EscapePath(key)

	// For presigned URLs the payload hash is the literal string
	// "UNSIGNED-PAYLOAD" — the client's PUT body is not signed (only the
	// content-length/content-type headers, when present).
	payloadHash := "UNSIGNED-PAYLOAD"

	canonicalRequest := strings.Join([]string{
		method,
		canonicalURI,
		canonicalQuery,
		canonicalHeaders.String(),
		signedHeaders,
		payloadHash,
	}, "\n")

	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credentialScope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")

	kDate := hmacSHA256([]byte("AWS4"+secretKey), dateStamp)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, "s3")
	kSigning := hmacSHA256(kService, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(kSigning, stringToSign))

	return fmt.Sprintf("https://%s%s?%s&X-Amz-Signature=%s",
		host, canonicalURI, canonicalQuery, signature)
}

// canonicalQueryString builds the sigv4 canonical query string: keys
// sorted alphabetically, each key+value RFC-3986-encoded with no `+`.
// url.Values.Encode() uses url.QueryEscape which encodes space as `+`
// not `%20`, so we hand-roll it.
func canonicalQueryString(q url.Values) string {
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		for _, v := range q[k] {
			parts = append(parts, rfc3986Escape(k)+"="+rfc3986Escape(v))
		}
	}
	return strings.Join(parts, "&")
}

// s3EscapePath URL-encodes an S3 key path. Slashes are preserved as
// path separators per the sigv4 spec — everything else is RFC 3986
// encoded. We deliberately don't escape "." either, since S3 lets keys
// like "foo.png" through unencoded.
func s3EscapePath(key string) string {
	parts := strings.Split(key, "/")
	for i, p := range parts {
		parts[i] = rfc3986Escape(p)
	}
	return strings.Join(parts, "/")
}

// rfc3986Escape percent-encodes a string per RFC 3986. The standard
// library's url.QueryEscape encodes space as `+` which S3 rejects in
// canonical strings — we have to use `%20` and leave the unreserved
// set unencoded.
func rfc3986Escape(s string) string {
	const unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if strings.IndexByte(unreserved, c) >= 0 {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// hmacSHA256 + sha256Hex live in upload.go.

// resolvePlatformS3Creds returns AWS credentials for the platform
// uploads bucket, in order of preference: explicit BENMORE_UPLOADS_S3_KEY
// env vars first (lets operators run with a dedicated access key on
// non-EC2 hosts), then IMDSv2 (the standard EC2 instance-role path).
//
// Returns ("","","") when no credentials are available — callers should
// 503 in that case rather than hand back a URL that won't work.
func resolvePlatformS3Creds() (accessKey, secretKey, sessionToken string) {
	if k := os.Getenv("BENMORE_UPLOADS_S3_KEY"); k != "" {
		return k, os.Getenv("BENMORE_UPLOADS_S3_SECRET"), ""
	}
	if c := imdsCredentials(); c != nil {
		return c.AccessKeyID, c.SecretAccessKey, c.Token
	}
	return "", "", ""
}

// PlatformS3Bucket returns the configured platform uploads bucket
// (BENMORE_UPLOADS_S3_BUCKET). Empty means presigned uploads are not
// configured — endpoints should 503 rather than fall back to local disk
// (defeats the whole "no bytes hit EC2" goal).
func PlatformS3Bucket() string {
	return os.Getenv("BENMORE_UPLOADS_S3_BUCKET")
}

// PlatformS3Region returns the bucket's region. Defaults to us-east-1
// to match the deploy region.
func PlatformS3Region() string {
	if r := os.Getenv("BENMORE_UPLOADS_S3_REGION"); r != "" {
		return r
	}
	return "us-east-1"
}

// DeletePlatformObject removes an object from the platform uploads
// bucket. Used by delete_media + admin cleanup. No-op when creds are
// not available (returns nil so the DB row can still be removed —
// orphan objects get caught by the lifecycle rule).
func DeletePlatformObject(objectKey string) error {
	bucket := PlatformS3Bucket()
	if bucket == "" {
		return nil
	}
	ak, sk, tk := resolvePlatformS3Creds()
	if ak == "" {
		return nil
	}
	region := PlatformS3Region()
	host := fmt.Sprintf("%s.s3.%s.amazonaws.com", bucket, region)
	objURL := fmt.Sprintf("https://%s/%s", host, s3EscapePath(objectKey))

	req, err := http.NewRequest("DELETE", objURL, nil)
	if err != nil {
		return err
	}
	if tk != "" {
		req.Header.Set("X-Amz-Security-Token", tk)
	}
	signAWSv4(req, nil, ak, sk, region, "s3")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 && resp.StatusCode != 404 {
		return fmt.Errorf("S3 DELETE returned %d", resp.StatusCode)
	}
	return nil
}

// s3HeadObject runs a signed HEAD against the platform bucket and
// returns the object's size and content-type. Used by the upload
// confirm step to verify the PUT actually completed.
//
// We sign with header-based v4 (not presigned) since the server makes
// the request directly — there's no client involvement.
func s3HeadObject(bucket, objectKey string) (size int64, contentType string, err error) {
	ak, sk, tk := resolvePlatformS3Creds()
	if ak == "" {
		return 0, "", fmt.Errorf("no S3 credentials available")
	}
	region := PlatformS3Region()
	host := fmt.Sprintf("%s.s3.%s.amazonaws.com", bucket, region)
	objURL := fmt.Sprintf("https://%s/%s", host, s3EscapePath(objectKey))

	req, err := http.NewRequest("HEAD", objURL, nil)
	if err != nil {
		return 0, "", err
	}
	if tk != "" {
		req.Header.Set("X-Amz-Security-Token", tk)
	}
	signAWSv4(req, nil, ak, sk, region, "s3")

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return 0, "", fmt.Errorf("object not found in S3")
	}
	if resp.StatusCode >= 400 {
		return 0, "", fmt.Errorf("S3 HEAD returned %d", resp.StatusCode)
	}
	return resp.ContentLength, resp.Header.Get("Content-Type"), nil
}
