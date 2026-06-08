//go:build !cli

package main

// media_cdn.go — platform-tier user-media storage (v2.7.126).
//
// When the operator sets the platform media block in the platform env file,
// EVERY app's uploads go to a single locked-down S3 bucket and are served from
// an ISOLATED, cookieless CDN origin (cdn.example.com) — never from the
// app's own subdomain. Two trust tiers by key prefix:
//
//   public/<app>/uploads/...   → open, CloudFront-cached, referenced directly.
//   private/<app>/uploads/...  → CloudFront signed-URL required (fail-closed
//                                default behavior). Served only via a flow that
//                                has authorized the request (serve_file → 302
//                                to a short-TTL signed URL).
//
// Falls back to local disk when the platform block is unset, so nothing changes
// for self-hosted / unconfigured deployments.
//
// Env (the platform environment file):
//   BENMORE_PLATFORM_MEDIA_BUCKET        S3 bucket (e.g. my-media-bucket)
//   BENMORE_PLATFORM_MEDIA_REGION        default us-east-1
//   BENMORE_PLATFORM_MEDIA_CDN_DOMAIN    e.g. cdn.example.com
//   BENMORE_PLATFORM_MEDIA_KEYPAIR_ID    CloudFront public-key id (signing)
//   BENMORE_PLATFORM_MEDIA_PRIVATE_KEY_FILE  path to the RSA private key PEM
//   BENMORE_PLATFORM_MEDIA_PRIVATE_KEY   (alt) inline PEM if no file

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"mime"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// PlatformMediaConfig is the resolved deployment-wide media backend (nil = unset).
type PlatformMediaConfig struct {
	Bucket     string
	Region     string
	CDNDomain  string
	KeyPairID  string
	PrivateKey *rsa.PrivateKey // for CloudFront signed URLs (private files)
	// S3Key/S3Secret are an OPTIONAL scoped static credential for the upload
	// PUT/DELETE. When set they're used directly; when empty the S3 client
	// falls back to the EC2 instance role via IMDS. On the hardened platform
	// host, non-root processes are firewalled off IMDS (an SSRF guard so an
	// app flow can't steal the instance role), so the per-app upload path —
	// which runs as the non-root benmore-app-<sub> user — MUST use a scoped
	// key here or every PutObject fails 403. The key is least-privilege
	// (PutObject/GetObject/DeleteObject on the media bucket only), so even if
	// it leaked its blast radius is one bucket — far less than the instance
	// role. Tenant flows can't read it (InterpolateEnv ignores os.Getenv).
	S3Key    string
	S3Secret string
}

var (
	platformMedia     *PlatformMediaConfig
	platformMediaOnce sync.Once
)

// getPlatformMedia resolves the platform media config once. Returns nil when
// the bucket/CDN aren't configured (→ callers fall back to local disk).
func getPlatformMedia() *PlatformMediaConfig {
	platformMediaOnce.Do(func() {
		bucket := strings.TrimSpace(os.Getenv("BENMORE_PLATFORM_MEDIA_BUCKET"))
		cdn := strings.TrimSpace(os.Getenv("BENMORE_PLATFORM_MEDIA_CDN_DOMAIN"))
		if bucket == "" || cdn == "" {
			return // not configured
		}
		cfg := &PlatformMediaConfig{
			Bucket:    bucket,
			Region:    strings.TrimSpace(os.Getenv("BENMORE_PLATFORM_MEDIA_REGION")),
			CDNDomain: strings.TrimPrefix(strings.TrimPrefix(cdn, "https://"), "http://"),
			KeyPairID: strings.TrimSpace(os.Getenv("BENMORE_PLATFORM_MEDIA_KEYPAIR_ID")),
			S3Key:     strings.TrimSpace(os.Getenv("BENMORE_PLATFORM_MEDIA_S3_KEY")),
			S3Secret:  strings.TrimSpace(os.Getenv("BENMORE_PLATFORM_MEDIA_S3_SECRET")),
		}
		if cfg.Region == "" {
			cfg.Region = "us-east-1"
		}
		// Private signing key — preferred form is base64-encoded PEM in the
		// env var itself (single-line, always present in the process env, no
		// filesystem read under the sandboxed app namespace). Falls back to
		// inline PEM, then a file path.
		pemStr := ""
		if b64 := strings.TrimSpace(os.Getenv("BENMORE_PLATFORM_MEDIA_PRIVATE_KEY_B64")); b64 != "" {
			if dec, err := base64.StdEncoding.DecodeString(b64); err == nil {
				pemStr = string(dec)
			}
		}
		if pemStr == "" {
			pemStr = os.Getenv("BENMORE_PLATFORM_MEDIA_PRIVATE_KEY")
		}
		if pemStr == "" {
			if p := strings.TrimSpace(os.Getenv("BENMORE_PLATFORM_MEDIA_PRIVATE_KEY_FILE")); p != "" {
				if b, err := os.ReadFile(p); err == nil {
					pemStr = string(b)
				}
			}
		}
		if pemStr != "" {
			if k, err := parseRSAPrivateKey([]byte(pemStr)); err == nil {
				cfg.PrivateKey = k
			}
		}
		platformMedia = cfg
	})
	return platformMedia
}

// mediaCDNEnabled reports whether the platform CDN media backend is active.
func mediaCDNEnabled() bool { return getPlatformMedia() != nil }

// appMediaPrefix is the per-app key namespace under the bucket — the app's
// subdomain in host mode (basename of its dir), sanitized.
func appMediaPrefix(app *App) string {
	if app == nil {
		return "_unknown"
	}
	base := filepath.Base(strings.TrimRight(app.Dir, "/"))
	// Media is keyed by the LOGICAL app, shared across dev/prod — a dev
	// instance (<sub>-dev) must use the SAME CDN prefix (<sub>) as prod, or
	// files uploaded/stored under <sub> (incl. prod data copied into dev via
	// refresh-dev) sign to a <sub>-dev key that doesn't exist → CloudFront 403.
	base = LogicalSubdomain(base)
	base = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return '-'
		}
	}, base)
	if base == "" {
		return "_unknown"
	}
	return base
}

// isPrivateUploadPath reports whether a logical upload path is private-tier.
// The kind=private convention lands files at uploads/private/...
func isPrivateUploadPath(p string) bool {
	p = strings.TrimPrefix(p, "/")
	return strings.HasPrefix(p, "uploads/private/") || strings.Contains(p, "/private/")
}

// uploadContentMeta derives the S3 object Content-Type + Content-Disposition.
// Safe media renders inline; active/unknown content is force-downloaded
// (defense-in-depth on top of the upload-time MIME block + the CDN CSP).
func uploadContentMeta(ext, sniffed, downloadName string) (contentType, disposition string) {
	contentType = mime.TypeByExtension("." + ext)
	if contentType == "" {
		contentType = sniffed
	}
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	switch strings.ToLower(ext) {
	case "jpg", "jpeg", "png", "gif", "webp", "avif", "ico",
		"mp4", "webm", "mov", "m4a", "mp3", "wav", "ogg",
		"pdf", "txt", "csv", "json":
		disposition = "" // inline OK
	default:
		if downloadName == "" {
			downloadName = "download." + ext
		}
		disposition = fmt.Sprintf("attachment; filename=%q", downloadName)
	}
	return
}

// CDNStorage is the platform media backend: PUTs to S3 under a per-app,
// per-visibility key prefix and returns the CloudFront URL.
type CDNStorage struct {
	s3        *S3Storage
	Prefix    string // per-app namespace
	CDNDomain string
}

func newCDNStorage(app *App) *CDNStorage {
	cfg := getPlatformMedia()
	if cfg == nil {
		return nil
	}
	return &CDNStorage{
		// Key/Secret are the scoped static credential when configured; empty
		// → S3Storage.resolveCreds falls back to IMDS (off-platform / dev).
		s3:        &S3Storage{Bucket: cfg.Bucket, Region: cfg.Region, Key: cfg.S3Key, Secret: cfg.S3Secret},
		Prefix:    appMediaPrefix(app),
		CDNDomain: cfg.CDNDomain,
	}
}

// cdnKeyFor maps a logical upload path (uploads/...) to the bucket key
// <visibility>/<app>/<path>.
func (c *CDNStorage) cdnKeyFor(path string) string {
	vis := "public"
	if isPrivateUploadPath(path) {
		vis = "private"
	}
	return vis + "/" + c.Prefix + "/" + strings.TrimPrefix(path, "/")
}

func (c *CDNStorage) Save(path string, data io.Reader) (string, error) {
	return c.SaveWithMeta(path, data, "", "")
}

// SaveWithMeta PUTs the object with Content-Type/Content-Disposition and
// returns the CloudFront URL. For private objects the returned URL is
// UNSIGNED (fetching it directly is 403 by the fail-closed default behavior);
// serve_file mints a signed URL at access time.
func (c *CDNStorage) SaveWithMeta(path string, data io.Reader, contentType, disposition string) (string, error) {
	// Per-app processes hold no durable AWS key (the scoped media key is in
	// the router only) and are firewalled off IMDS, so they upload through the
	// presign broker. The router / dev / off-platform (which DO have a static
	// key or reachable IMDS) sign directly. See presign_broker.go.
	if c.s3.Key == "" {
		if sock := presignBrokerSocketPath(); brokerSocketReachable(sock) {
			return c.saveViaBroker(sock, path, data, contentType, disposition)
		}
	}
	key := c.cdnKeyFor(path)
	if _, err := c.s3.SaveWithMeta(key, data, contentType, disposition); err != nil {
		return "", err
	}
	return "https://" + c.CDNDomain + "/" + key, nil
}

func (c *CDNStorage) Delete(path string) error {
	return c.s3.Delete(c.cdnKeyFor(path))
}

// cdnURLForServe resolves a serve_file path to a CloudFront URL under the
// platform media CDN. Accepts either a full CDN URL (the form uploads store)
// or a logical uploads/ path. Returns the UNSIGNED url, whether it's private
// (→ caller signs), and ok=false if it isn't a CDN-servable media path.
func cdnURLForServe(app *App, raw string, cfg *PlatformMediaConfig) (url string, isPrivate bool, ok bool) {
	prefix := "https://" + cfg.CDNDomain + "/"
	if strings.HasPrefix(raw, prefix) {
		clean := raw
		if i := strings.IndexByte(clean, '?'); i >= 0 {
			clean = clean[:i] // drop any existing query
		}
		key := strings.TrimPrefix(clean, prefix)
		// TENANT CLAMP: the signing key is deployment-wide, so a flow could
		// otherwise hand serve_file another app's CDN URL and get it
		// signed. Require the key's <visibility>/<app>/ segment to be THIS
		// app's own prefix; refuse anything else (→ caller 404s).
		parts := strings.SplitN(key, "/", 3)
		if len(parts) < 3 || parts[1] != appMediaPrefix(app) || (parts[0] != "public" && parts[0] != "private") {
			return "", false, false
		}
		return clean, parts[0] == "private", true
	}
	p := strings.TrimPrefix(raw, "/")
	if strings.HasPrefix(p, "uploads/") && !strings.Contains(p, "..") {
		c := newCDNStorage(app)
		if c == nil {
			return "", false, false
		}
		key := c.cdnKeyFor(p)
		return prefix + key, strings.HasPrefix(key, "private/"), true
	}
	return "", false, false
}

// ─── CloudFront signed URLs (private files) ──────────────────────────────

// parseRSAPrivateKey parses a PEM RSA private key (PKCS1 or PKCS8).
func parseRSAPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("media: no PEM block in private key")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("media: parse private key: %w", err)
	}
	rk, ok := keyAny.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("media: private key is not RSA")
	}
	return rk, nil
}

// cfBase64 is CloudFront's URL-safe base64 (+ → -, = → _, / → ~).
func cfBase64(b []byte) string {
	s := base64.StdEncoding.EncodeToString(b)
	return strings.NewReplacer("+", "-", "=", "_", "/", "~").Replace(s)
}

// signCloudFrontURL builds a CloudFront canned-policy signed URL (RSA-SHA1)
// valid until `expires` (unix seconds). resourceURL is the full https URL.
func signCloudFrontURL(resourceURL string, expires int64, keyPairID string, priv *rsa.PrivateKey) (string, error) {
	if priv == nil || keyPairID == "" {
		return "", fmt.Errorf("media: CloudFront signing not configured (key pair id / private key missing)")
	}
	policy := fmt.Sprintf(`{"Statement":[{"Resource":"%s","Condition":{"DateLessThan":{"AWS:EpochTime":%d}}}]}`, resourceURL, expires)
	sum := sha1.Sum([]byte(policy))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA1, sum[:])
	if err != nil {
		return "", fmt.Errorf("media: sign cloudfront url: %w", err)
	}
	sep := "?"
	if strings.Contains(resourceURL, "?") {
		sep = "&"
	}
	return fmt.Sprintf("%s%sExpires=%d&Signature=%s&Key-Pair-Id=%s",
		resourceURL, sep, expires, cfBase64(sig), keyPairID), nil
}
