//go:build !cli

package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const maxUploadSize = 50 << 20 // 50MB default max

// StorageBackend is the interface for file storage.
// Default: local disk. Apps can configure S3-compatible storage via env vars.
type StorageBackend interface {
	Save(path string, data io.Reader) (publicURL string, err error)
	Delete(path string) error
}

// metaSaver is implemented by backends that can store Content-Type +
// Content-Disposition object metadata (S3 / CDN). HandleFileUpload prefers it.
type metaSaver interface {
	SaveWithMeta(path string, data io.Reader, contentType, disposition string) (publicURL string, err error)
}

// storageBackend is the active storage backend, set on startup.
var storageBackend StorageBackend

// InitStorage sets up the storage backend based on env vars.
// If S3_BUCKET is set, uses S3-compatible storage. Otherwise local disk.
func InitStorage(appDir string) {
	bucket := GetEnv(appDir, "S3_BUCKET")
	if bucket != "" {
		storageBackend = &S3Storage{
			Bucket:   bucket,
			Region:   GetEnv(appDir, "S3_REGION"),
			Endpoint: GetEnv(appDir, "S3_ENDPOINT"),
			Key:      GetEnv(appDir, "S3_KEY"),
			Secret:   GetEnv(appDir, "S3_SECRET"),
		}
	} else {
		storageBackend = &LocalStorage{Dir: appDir}
	}
}

// LocalStorage saves files to the app's uploads/ directory.
type LocalStorage struct {
	Dir string
}

func (ls *LocalStorage) Save(path string, data io.Reader) (string, error) {
	fullPath := filepath.Join(ls.Dir, path)
	os.MkdirAll(filepath.Dir(fullPath), 0755)
	f, err := os.Create(fullPath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := io.Copy(f, data); err != nil {
		return "", err
	}
	return "/" + path, nil
}

func (ls *LocalStorage) Delete(path string) error {
	return os.Remove(filepath.Join(ls.Dir, path))
}

// S3Storage saves files to an S3-compatible bucket (AWS, Cloudflare R2, MinIO, etc.).
type S3Storage struct {
	Bucket   string
	Region   string
	Endpoint string // custom endpoint for R2/MinIO
	Key      string
	Secret   string
}

func (s3 *S3Storage) Save(path string, data io.Reader) (string, error) {
	return s3.SaveWithMeta(path, data, "", "")
}

// SaveWithMeta PUTs to an explicit object key with optional Content-Type and
// Content-Disposition (stored as object metadata; S3 honors standard headers
// even when unsigned). contentType "" → application/octet-stream;
// disposition "" → omitted (inline).
func (s3 *S3Storage) SaveWithMeta(path string, data io.Reader, contentType, disposition string) (string, error) {
	body, err := io.ReadAll(data)
	if err != nil {
		return "", err
	}

	endpoint := s3.Endpoint
	awsNative := endpoint == "" || strings.Contains(endpoint, "amazonaws.com")
	if endpoint == "" {
		endpoint = fmt.Sprintf("https://s3.%s.amazonaws.com", s3.Region)
	}
	url := fmt.Sprintf("%s/%s/%s", endpoint, s3.Bucket, path)

	req, err := http.NewRequest("PUT", url, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	req.Header.Set("Content-Type", contentType)
	if disposition != "" {
		req.Header.Set("Content-Disposition", disposition)
	}
	// Cache-Control as S3 object metadata, scoped to the CDN media key
	// convention (public/… vs private/…). Public media is content-hash-named
	// → immutable, cache forever (kills the revalidation / cold-origin-fetch
	// latency). Private → no-store (never cache a signed object). Other keys
	// (e.g. backups) are left untouched. Sent unsigned like Content-Type/
	// Disposition above - S3 stores standard metadata headers without them
	// being in the sigv4 SignedHeaders set.
	if strings.HasPrefix(path, "public/") {
		req.Header.Set("Cache-Control", "public, max-age=31536000, immutable")
	} else if strings.HasPrefix(path, "private/") {
		req.Header.Set("Cache-Control", "no-store")
	}
	key, secret, token := s3.resolveCreds()
	if key != "" {
		if awsNative {
			if token != "" {
				req.Header.Set("X-Amz-Security-Token", token)
			}
			signAWSv4(req, body, key, secret, s3.Region, "s3")
		} else {
			// DO Spaces / R2 / MinIO accept basic auth as a fallback
			req.SetBasicAuth(key, secret)
		}
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("S3 upload failed: %d: %s", resp.StatusCode, string(respBody))
	}

	return url, nil
}

// signAWSv4 adds AWS Signature V4 headers to an outbound request.
// Stdlib-only - no AWS SDK. Standard recipe from the AWS docs:
// https://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html
func signAWSv4(req *http.Request, body []byte, key, secret, region, service string) {
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")

	payloadHash := sha256Hex(body)
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	req.Header.Set("Host", req.URL.Host)

	// Canonical headers (sorted, lowercased). When the caller supplied
	// an X-Amz-Security-Token (i.e. we're using temporary IMDS-fetched
	// credentials) include it in the signed set - otherwise AWS rejects
	// the request with a "SignatureDoesNotMatch" since the token would
	// be present but unsigned.
	securityToken := req.Header.Get("X-Amz-Security-Token")
	signedHeaders := "host;x-amz-content-sha256;x-amz-date"
	canonicalHeaders := fmt.Sprintf("host:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\n",
		req.URL.Host, payloadHash, amzDate)
	if securityToken != "" {
		signedHeaders += ";x-amz-security-token"
		canonicalHeaders += "x-amz-security-token:" + securityToken + "\n"
	}

	canonicalRequest := strings.Join([]string{
		req.Method,
		req.URL.EscapedPath(),
		req.URL.RawQuery,
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")

	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", dateStamp, region, service)
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credentialScope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")

	kDate := hmacSHA256([]byte("AWS4"+secret), dateStamp)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	kSigning := hmacSHA256(kService, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(kSigning, stringToSign))

	auth := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		key, credentialScope, signedHeaders, signature)
	req.Header.Set("Authorization", auth)
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func (s3 *S3Storage) Delete(path string) error {
	endpoint := s3.Endpoint
	awsNative := endpoint == "" || strings.Contains(endpoint, "amazonaws.com")
	if endpoint == "" {
		endpoint = fmt.Sprintf("https://s3.%s.amazonaws.com", s3.Region)
	}
	url := fmt.Sprintf("%s/%s/%s", endpoint, s3.Bucket, path)

	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return err
	}
	key, secret, token := s3.resolveCreds()
	if key != "" {
		if awsNative {
			if token != "" {
				req.Header.Set("X-Amz-Security-Token", token)
			}
			signAWSv4(req, nil, key, secret, s3.Region, "s3")
		} else {
			req.SetBasicAuth(key, secret)
		}
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// S3Object is one entry returned by S3Storage.List.
type S3Object struct {
	Key          string
	Size         int64
	LastModified string
}

// List enumerates objects under a key prefix via S3 ListObjectsV2. Returns up
// to 1000 objects (a single page) - enough for any one app's retained
// snapshots. Used by the platform Backups view.
func (s3 *S3Storage) List(prefix string) ([]S3Object, error) {
	endpoint := s3.Endpoint
	awsNative := endpoint == "" || strings.Contains(endpoint, "amazonaws.com")
	if endpoint == "" {
		endpoint = fmt.Sprintf("https://s3.%s.amazonaws.com", s3.Region)
	}
	vals := neturl.Values{}
	vals.Set("list-type", "2")
	vals.Set("max-keys", "1000")
	if prefix != "" {
		vals.Set("prefix", prefix)
	}
	// vals.Encode() sorts keys and percent-encodes (slashes → %2F), which is
	// exactly the canonical query form signAWSv4 signs from req.URL.RawQuery.
	reqURL := fmt.Sprintf("%s/%s?%s", endpoint, s3.Bucket, vals.Encode())
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	key, secret, token := s3.resolveCreds()
	if key != "" {
		if awsNative {
			if token != "" {
				req.Header.Set("X-Amz-Security-Token", token)
			}
			signAWSv4(req, nil, key, secret, s3.Region, "s3")
		} else {
			req.SetBasicAuth(key, secret)
		}
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("S3 list failed: %d: %s", resp.StatusCode, string(body))
	}
	var parsed struct {
		Contents []struct {
			Key          string `xml:"Key"`
			Size         int64  `xml:"Size"`
			LastModified string `xml:"LastModified"`
		} `xml:"Contents"`
	}
	if err := xml.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("S3 list parse: %w", err)
	}
	out := make([]S3Object, 0, len(parsed.Contents))
	for _, c := range parsed.Contents {
		out = append(out, S3Object{Key: c.Key, Size: c.Size, LastModified: c.LastModified})
	}
	return out, nil
}

// Fetch GETs an object and returns the live response for streaming. Caller
// MUST close resp.Body. Used by the backups download proxy.
func (s3 *S3Storage) Fetch(path string) (*http.Response, error) {
	endpoint := s3.Endpoint
	awsNative := endpoint == "" || strings.Contains(endpoint, "amazonaws.com")
	if endpoint == "" {
		endpoint = fmt.Sprintf("https://s3.%s.amazonaws.com", s3.Region)
	}
	reqURL := fmt.Sprintf("%s/%s/%s", endpoint, s3.Bucket, path)
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	key, secret, token := s3.resolveCreds()
	if key != "" {
		if awsNative {
			if token != "" {
				req.Header.Set("X-Amz-Security-Token", token)
			}
			signAWSv4(req, nil, key, secret, s3.Region, "s3")
		} else {
			req.SetBasicAuth(key, secret)
		}
	}
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("S3 fetch failed: %d: %s", resp.StatusCode, string(b))
	}
	return resp, nil
}

// HandleFileUpload processes file uploads from multipart forms.
// Returns the saved file path (relative to uploads/) or empty string.
// Accepts *App so storage resolves per-app in multi-tenant host mode
// (fixes: global storageBackend was last-loaded-app wins).
func HandleFileUpload(app *App, r *http.Request, fieldName, folder string, maxSize int64, allowedTypes []string) (string, error) {
	if maxSize == 0 {
		maxSize = maxUploadSize
	}

	r.Body = http.MaxBytesReader(nil, r.Body, maxSize)

	file, header, err := r.FormFile(fieldName)
	if err != nil {
		if err == http.ErrMissingFile {
			return "", nil // no file uploaded, not an error
		}
		return "", fmt.Errorf("upload: %w", err)
	}
	defer file.Close()

	// Check file size
	if header.Size > maxSize {
		return "", fmt.Errorf("file too large (max %dMB)", maxSize/(1<<20))
	}

	// Check file type
	ext := strings.ToLower(filepath.Ext(header.Filename))
	ext = strings.TrimPrefix(ext, ".")
	if len(allowedTypes) > 0 {
		allowed := false
		for _, t := range allowedTypes {
			if strings.TrimSpace(strings.ToLower(t)) == ext {
				allowed = true
				break
			}
		}
		if !allowed {
			return "", fmt.Errorf("file type .%s not allowed (allowed: %s)", ext, strings.Join(allowedTypes, ", "))
		}
	}

	// Detect MIME type from content (don't trust extension alone)
	buf := make([]byte, 512)
	n, _ := file.Read(buf)
	mimeType := http.DetectContentType(buf[:n])
	file.Seek(0, io.SeekStart)

	// Block dangerous MIME types
	dangerousMimes := []string{"application/x-executable", "application/x-sharedlib", "text/html", "application/javascript"}
	for _, d := range dangerousMimes {
		if strings.HasPrefix(mimeType, d) {
			return "", fmt.Errorf("file type not allowed: %s", mimeType)
		}
	}

	// Generate safe filename: uuid.ext
	uuid := generateShortID()
	safeName := fmt.Sprintf("%s.%s", uuid, ext)

	if folder == "" {
		folder = "files"
	}
	destPath := filepath.Join("uploads", folder, safeName)

	// Object metadata: a correct Content-Type so media renders, and
	// force-download for active/unknown content (belt on top of the MIME
	// block above + the CDN's script-killing CSP).
	contentType, disposition := uploadContentMeta(ext, mimeType, safeName)

	// Backend precedence: explicit per-app S3 (S3_BUCKET) > platform CDN
	// media (deployment-wide, isolated origin) > local disk. Per-app avoids the
	// global-state race in host mode.
	var backend StorageBackend
	if app != nil {
		if bucket := GetEnv(app.Dir, "S3_BUCKET"); bucket != "" {
			backend = &S3Storage{
				Bucket:   bucket,
				Region:   GetEnv(app.Dir, "S3_REGION"),
				Endpoint: GetEnv(app.Dir, "S3_ENDPOINT"),
				Key:      GetEnv(app.Dir, "S3_KEY"),
				Secret:   GetEnv(app.Dir, "S3_SECRET"),
			}
		} else if cdn := newCDNStorage(app); cdn != nil {
			backend = cdn
		} else {
			backend = &LocalStorage{Dir: app.Dir}
		}
	} else if storageBackend != nil {
		backend = storageBackend
	}

	if backend != nil {
		if ms, ok := backend.(metaSaver); ok {
			url, err := ms.SaveWithMeta(destPath, file, contentType, disposition)
			if err != nil {
				return "", fmt.Errorf("save upload: %w", err)
			}
			return url, nil
		}
		url, err := backend.Save(destPath, file)
		if err != nil {
			return "", fmt.Errorf("save upload: %w", err)
		}
		return url, nil
	}

	// Fallback: direct local save (if InitStorage wasn't called)
	os.MkdirAll(filepath.Dir(destPath), 0755)
	dest, err := os.Create(destPath)
	if err != nil {
		return "", fmt.Errorf("save upload: %w", err)
	}
	defer dest.Close()
	if _, err := io.Copy(dest, file); err != nil {
		return "", fmt.Errorf("write upload: %w", err)
	}
	return "/" + destPath, nil
}

func generateShortID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// RegisterUploadRoute registers POST /api/_upload - the canonical
// generic upload endpoint the bm SDK / docs reference. v2.7.20+.
//
// Accepts multipart/form-data with:
//
//   file       (required) the file blob
//   kind       (optional) subfolder under uploads/ - "avatars", "imports",
//              "feedback", etc. Defaults to "files".
//   _csrf      (required for cookie auth) framework's CSRF token.
//              Bearer-auth requests are exempt.
//
// Returns JSON:
//
//   { "path": "/uploads/<kind>/<id>.<ext>",
//     "url":  "<absolute or signed url>",
//     "size": <bytes>,
//     "mime": "<detected mime>",
//     "filename": "<original filename>" }
//
// 200 on success, 401 if anonymous + auth required, 403 on CSRF mismatch,
// 413 (Payload Too Large) when the file exceeds the per-app cap,
// 415 (Unsupported Media Type) when the MIME-type sniff rejects it.
func RegisterUploadRoute(mux *http.ServeMux, app *App) {
	mux.HandleFunc("POST /api/_upload", func(w http.ResponseWriter, r *http.Request) {
		// Auth: require a session when the app has auth: configured.
		if NeedsAuth(app) {
			if session := getSession(app, r); session == nil {
				httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
				return
			}
		}
		// CSRF - bypass for bearer.
		if !isBearerAuth(r) && !validateCSRF(r) {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid CSRF token"})
			return
		}

		// `kind` becomes the storage folder under uploads/. Whitelist to
		// safe identifiers so an attacker can't traverse with "../foo".
		kind := r.FormValue("kind")
		if kind == "" {
			kind = "files"
		}
		for _, c := range kind {
			ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
				(c >= '0' && c <= '9') || c == '-' || c == '_'
			if !ok {
				httpJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid kind (alphanumeric/-/_ only)"})
				return
			}
		}

		// HandleFileUpload parses the multipart body, validates size +
		// MIME, writes via the per-app storage backend (local or S3).
		// Returns the stored path/URL.
		savedURL, err := HandleFileUpload(app, r, "file", kind, 0, nil)
		if err != nil {
			msg := err.Error()
			status := http.StatusBadRequest
			switch {
			case strings.Contains(msg, "too large"):
				status = http.StatusRequestEntityTooLarge
			case strings.Contains(msg, "not allowed"):
				status = http.StatusUnsupportedMediaType
			}
			httpJSON(w, status, map[string]any{"error": msg})
			return
		}
		if savedURL == "" {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "no file in form (field 'file' missing)"})
			return
		}

		// HandleFileUpload may return either a relative path "/uploads/..."
		// or an absolute S3 URL. Surface both: callers usually want `path`
		// for the framework's signed-url + soft-delete handling, plus
		// `url` for direct rendering.
		out := map[string]any{
			"path": savedURL,
			"url":  savedURL,
		}
		// Best-effort enrich the response with the original filename + size,
		// re-read from the form (cheap, header is small).
		if file, header, ferr := r.FormFile("file"); ferr == nil {
			out["filename"] = header.Filename
			out["size"] = header.Size
			file.Close()
		}
		httpJSON(w, http.StatusOK, out)
	})
}

// ParseUploadDirective extracts :upload, :max, :types from an HTML input element.
func ParseUploadDirective(html string) (folder string, maxSize int64, types []string) {
	// :upload="avatars"
	if idx := strings.Index(html, `:upload="`); idx >= 0 {
		rest := html[idx+9:]
		if end := strings.Index(rest, `"`); end >= 0 {
			folder = rest[:end]
		}
	}

	// :max="5mb"
	if idx := strings.Index(html, `:max="`); idx >= 0 {
		rest := html[idx+6:]
		if end := strings.Index(rest, `"`); end >= 0 {
			sizeStr := strings.ToLower(rest[:end])
			var n int64
			if strings.HasSuffix(sizeStr, "mb") {
				fmt.Sscanf(sizeStr, "%dmb", &n)
				maxSize = n << 20
			} else if strings.HasSuffix(sizeStr, "kb") {
				fmt.Sscanf(sizeStr, "%dkb", &n)
				maxSize = n << 10
			}
		}
	}

	// :types="jpg,png,gif"
	if idx := strings.Index(html, `:types="`); idx >= 0 {
		rest := html[idx+8:]
		if end := strings.Index(rest, `"`); end >= 0 {
			for _, t := range strings.Split(rest[:end], ",") {
				types = append(types, strings.TrimSpace(t))
			}
		}
	}

	return
}

// applyUploadDispositionHeaders forces user-uploaded files to be treated
// as non-executable in the browser. Without this, an uploaded .html or
// .svg renders in the app's origin with full DOM access (CSP currently
// allows 'unsafe-inline' which means stored XSS lands). We allow inline
// rendering only for an allowlist of safe media types; everything else
// gets Content-Disposition: attachment so browsers download instead of
// rendering. Also sets X-Content-Type-Options to defeat MIME sniffing.
func applyUploadDispositionHeaders(w http.ResponseWriter, fullPath string) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	ext := strings.ToLower(filepath.Ext(fullPath))
	switch ext {
	case ".jpg", ".jpeg", ".png", ".gif", ".webp", ".avif", ".ico",
		".mp4", ".webm", ".mov", ".m4a", ".mp3", ".wav", ".ogg",
		".pdf", ".txt", ".csv", ".json":
		// Inline OK - these can't carry script in the app's origin.
		return
	}
	// Everything else (.html, .svg, .xml, .js, .wasm, .htm, anything
	// unknown) downloads instead of renders.
	base := filepath.Base(fullPath)
	w.Header().Set("Content-Disposition", `attachment; filename="`+base+`"`)
}

// ===== Credential resolution =====
//
// AWS S3 requests can use either:
//
//   1. Static keys passed in by env vars (BACKUP_S3_KEY / S3_KEY etc.) -
//      the historical path.
//   2. IAM role credentials fetched from IMDSv2 - the AWS-recommended
//      path. Drops the need to keep a long-lived access key in the
//      systemd unit. The framework's stdlib-only SigV4 signer learned
//      to add X-Amz-Security-Token (above) so role creds work.
//
// resolveCreds chooses between them. Explicit Key wins (operators can
// override on a per-instance basis). When Key is empty AND we're on
// AWS (no custom Endpoint), we hit IMDSv2 and cache the response in
// memory until it expires.

func (s3 *S3Storage) resolveCreds() (key, secret, token string) {
	if s3.Key != "" {
		return s3.Key, s3.Secret, ""
	}
	// Non-AWS endpoints (R2, MinIO, Spaces) never have IMDS - return
	// empty so the caller can choose to send unsigned.
	if s3.Endpoint != "" && !strings.Contains(s3.Endpoint, "amazonaws.com") {
		return "", "", ""
	}
	creds := imdsCredentials()
	if creds == nil {
		return "", "", ""
	}
	return creds.AccessKeyID, creds.SecretAccessKey, creds.Token
}

// imdsCreds holds a cached role credential set plus its expiry.
type imdsCreds struct {
	AccessKeyID     string
	SecretAccessKey string
	Token           string
	Expiry          time.Time
}

var (
	imdsCredsCache *imdsCreds
	imdsCredsMu    sync.Mutex
)

// imdsCredentials fetches the EC2 instance role's temporary credentials
// using IMDSv2. Returns nil if the host isn't on EC2 or the IMDS
// endpoint is blocked (HttpEndpoint=disabled on the instance). Cached
// until 5 minutes before expiry to avoid hammering IMDS.
func imdsCredentials() *imdsCreds {
	imdsCredsMu.Lock()
	defer imdsCredsMu.Unlock()
	if imdsCredsCache != nil && time.Now().Before(imdsCredsCache.Expiry.Add(-5*time.Minute)) {
		return imdsCredsCache
	}
	// 1. Get an IMDSv2 token (PUT with TTL header).
	tokenReq, _ := http.NewRequest("PUT", "http://169.254.169.254/latest/api/token", nil)
	tokenReq.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")
	client := &http.Client{Timeout: 2 * time.Second}
	tokResp, err := client.Do(tokenReq)
	if err != nil {
		return nil
	}
	tokBytes, _ := io.ReadAll(io.LimitReader(tokResp.Body, 2048))
	tokResp.Body.Close()
	if tokResp.StatusCode != 200 || len(tokBytes) == 0 {
		return nil
	}
	imdsToken := string(tokBytes)

	// 2. Discover the role name attached to the instance.
	roleReq, _ := http.NewRequest("GET",
		"http://169.254.169.254/latest/meta-data/iam/security-credentials/", nil)
	roleReq.Header.Set("X-aws-ec2-metadata-token", imdsToken)
	roleResp, err := client.Do(roleReq)
	if err != nil {
		return nil
	}
	roleName, _ := io.ReadAll(io.LimitReader(roleResp.Body, 256))
	roleResp.Body.Close()
	if roleResp.StatusCode != 200 || len(roleName) == 0 {
		return nil
	}

	// 3. Fetch the credential document.
	credReq, _ := http.NewRequest("GET",
		"http://169.254.169.254/latest/meta-data/iam/security-credentials/"+string(roleName), nil)
	credReq.Header.Set("X-aws-ec2-metadata-token", imdsToken)
	credResp, err := client.Do(credReq)
	if err != nil {
		return nil
	}
	credBody, _ := io.ReadAll(io.LimitReader(credResp.Body, 16*1024))
	credResp.Body.Close()
	if credResp.StatusCode != 200 {
		return nil
	}
	var doc struct {
		AccessKeyID     string `json:"AccessKeyId"`
		SecretAccessKey string `json:"SecretAccessKey"`
		Token           string `json:"Token"`
		Expiration      string `json:"Expiration"`
	}
	if err := json.Unmarshal(credBody, &doc); err != nil {
		return nil
	}
	exp, err := time.Parse(time.RFC3339, doc.Expiration)
	if err != nil {
		exp = time.Now().Add(5 * time.Minute) // pessimistic fallback
	}
	imdsCredsCache = &imdsCreds{
		AccessKeyID:     doc.AccessKeyID,
		SecretAccessKey: doc.SecretAccessKey,
		Token:           doc.Token,
		Expiry:          exp,
	}
	return imdsCredsCache
}
