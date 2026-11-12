//go:build !cli

package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const maxUploadSize = 50 << 20 // 50MB default max

// uploadBodyOverhead is headroom for multipart framing and small form fields
// (_csrf, kind) on top of the per-file cap, so a file of exactly
// maxUploadSize still fits.
const uploadBodyOverhead = 1 << 20

// limitUploadBody caps a single-file upload request body and parses it before
// any other form access. The CSRF check and FormValue parse the multipart
// body on first use, so a cap installed after them (as in HandleFileUpload)
// never applied: file parts spilled to temporary disk in full before the
// per-file size check ran. Writes 413 and returns false when the body is over
// the cap; other parse errors are left to the existing handling.
//
// It also takes one of the process's upload slots, charged to client
// (uploadClientKey; 503 + Retry-After when none frees up), and parses with a
// small in-memory threshold, so file parts spill to temporary files instead
// of RAM. The caller must call release when the request is done; release
// also removes the temporary files.
func limitUploadBody(w http.ResponseWriter, r *http.Request, client string) (release func(), ok bool) {
	releaseSlot, ok := acquireUploadSlot(w, r, client)
	if !ok {
		return nil, false
	}
	release = func() {
		removeMultipartTemp(r)
		releaseSlot()
	}
	// A 50 MB file does not arrive within the server's 15 s read deadline on
	// an ordinary connection. Extended only once the request holds a slot,
	// so slow bodies cannot outnumber the slots.
	extendBulkBodyDeadlines(w)
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize+uploadBodyOverhead)
	if err := r.ParseMultipartForm(uploadMemoryThreshold); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			release()
			httpJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"error": fmt.Sprintf("file too large (max %dMB)", maxUploadSize/(1<<20))})
			return nil, false
		}
	}
	return release, true
}

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
	base, err := filepath.Abs(ls.Dir)
	if err != nil {
		return err
	}
	full, err := filepath.Abs(filepath.Join(base, path))
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(base, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return fmt.Errorf("delete upload: path escapes storage root")
	}
	current := base
	for _, part := range strings.Split(filepath.Dir(rel), string(os.PathSeparator)) {
		if part == "." || part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, statErr := os.Lstat(current)
		if os.IsNotExist(statErr) {
			return nil
		}
		if statErr != nil {
			return statErr
		}
		if !info.IsDir() {
			return fmt.Errorf("delete upload: storage path has non-directory parent")
		}
	}
	err = os.Remove(full)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// S3Storage saves files to an S3-compatible bucket (AWS, Cloudflare R2, MinIO, etc.).
type S3Storage struct {
	Bucket   string
	Region   string
	Endpoint string // custom endpoint for R2/MinIO
	Key      string
	Secret   string
	// Token is the session token of temporary credentials (an STS session
	// scoped to one app's backup prefix, backup_session.go); empty for a
	// long-lived key.
	Token string
}

func (s3 *S3Storage) objectURL(path string) string {
	endpoint := s3.Endpoint
	if endpoint == "" {
		endpoint = fmt.Sprintf("https://s3.%s.amazonaws.com", s3.Region)
	}
	return fmt.Sprintf("%s/%s/%s", endpoint, s3.Bucket, path)
}

func (s3 *S3Storage) Save(path string, data io.Reader) (string, error) {
	return s3.SaveWithMeta(path, data, "", "")
}

// SaveWithMeta PUTs to an explicit object key with optional Content-Type and
// Content-Disposition (stored as object metadata; S3 honors standard headers
// even when unsigned). contentType "" → application/octet-stream;
// disposition "" → omitted (inline).
func (s3 *S3Storage) SaveWithMeta(path string, data io.Reader, contentType, disposition string) (string, error) {
	size, openBody, err := uploadBodyWithSize(data)
	if err != nil {
		return "", err
	}
	// A caller may already be past EOF; ReadAll previously uploaded an empty
	// body without rewinding it. Keep that behavior without changing the
	// broker's shared reader factory.
	size = max(size, 0)
	var hashBody io.Reader
	if _, ok := data.(interface {
		io.ReaderAt
		io.Seeker
	}); ok {
		// Consume the original cursor as ReadAll did, even when HTTP later
		// fails. Transmission/replay uses independent readers over exactly
		// the same range, and never closes the caller's file.
		hashBody = io.LimitReader(data, size)
	} else if hashBody, err = openBody(); err != nil {
		return "", err
	}
	hash := sha256.New()
	n, err := io.Copy(hash, hashBody)
	if err != nil {
		return "", err
	}
	if n != size {
		return "", io.ErrUnexpectedEOF
	}
	payloadHash := hex.EncodeToString(hash.Sum(nil))

	awsNative := s3.Endpoint == "" || strings.Contains(s3.Endpoint, "amazonaws.com")
	url := s3.objectURL(path)

	req, err := http.NewRequest("PUT", url, http.NoBody)
	if err != nil {
		return "", err
	}
	if size > 0 {
		req.GetBody = func() (io.ReadCloser, error) {
			body, err := openBody()
			if err != nil {
				return nil, err
			}
			return io.NopCloser(body), nil
		}
		if req.Body, err = req.GetBody(); err != nil {
			return "", err
		}
		req.ContentLength = size
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
			signAWSv4PayloadHash(req, payloadHash, key, secret, s3.Region, "s3")
		} else {
			// DO Spaces / R2 / MinIO accept basic auth as a fallback
			// (temporary credentials still carry their session token).
			if token != "" {
				req.Header.Set("X-Amz-Security-Token", token)
			}
			req.SetBasicAuth(key, secret)
		}
	}

	client := s3HTTPClient(30 * time.Second)
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
	signAWSv4PayloadHash(req, sha256Hex(body), key, secret, region, service)
}

// signAWSv4PayloadHash also supports file uploads without materializing the
// payload in memory. The digest is computed over the exact transmitted range.
func signAWSv4PayloadHash(req *http.Request, payloadHash, key, secret, region, service string) {
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")

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
	awsNative := s3.Endpoint == "" || strings.Contains(s3.Endpoint, "amazonaws.com")
	url := s3.objectURL(path)

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
			if token != "" {
				req.Header.Set("X-Amz-Security-Token", token)
			}
			req.SetBasicAuth(key, secret)
		}
	}

	client := s3HTTPClient(10 * time.Second)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	if (resp.StatusCode >= 200 && resp.StatusCode < 300) || resp.StatusCode == http.StatusNotFound {
		return nil
	}
	return fmt.Errorf("S3 delete failed: %d: %s", resp.StatusCode, string(body))
}

// S3Object is one entry returned by S3Storage.List.
type S3Object struct {
	Key          string
	Size         int64
	LastModified string
}

// Fetch GETs an object and returns the live response for streaming. Caller
// MUST close resp.Body. Used by the backups download proxy.
func (s3 *S3Storage) Fetch(path string) (*http.Response, error) {
	return s3.FetchContext(context.Background(), path)
}

// FetchContext reads one object from the configured S3-compatible backend.
// Redirects are refused so private object reads cannot leave the configured
// endpoint or forward an authenticated request to another origin.
func (s3 *S3Storage) FetchContext(ctx context.Context, path string) (*http.Response, error) {
	if ctx == nil || path == "" || strings.ContainsAny(path, "\\\x00?#%") {
		return nil, errors.New("S3 fetch path is invalid")
	}
	endpoint := s3.Endpoint
	awsNative := endpoint == "" || strings.Contains(endpoint, "amazonaws.com")
	if endpoint == "" {
		endpoint = fmt.Sprintf("https://s3.%s.amazonaws.com", s3.Region)
	}
	reqURL := fmt.Sprintf("%s/%s/%s", endpoint, s3.Bucket, path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
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
			if token != "" {
				req.Header.Set("X-Amz-Security-Token", token)
			}
			req.SetBasicAuth(key, secret)
		}
	}
	client := s3HTTPClient(60 * time.Second)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("S3 fetch failed: 404: %w", os.ErrNotExist)
		}
		return nil, fmt.Errorf("S3 fetch failed: %d: %s", resp.StatusCode, string(b))
	}
	return resp, nil
}

// storageBackendForApp is the single backend precedence used by upload and
// delete: explicit per-app S3, managed CDN, then local disk. Nil preserves the
// global single-app fallback used by legacy callers.
func storageBackendForApp(app *App) StorageBackend {
	if app == nil {
		return storageBackend
	}
	if bucket := GetEnv(app.Dir, "S3_BUCKET"); bucket != "" {
		return &S3Storage{
			Bucket:   bucket,
			Region:   GetEnv(app.Dir, "S3_REGION"),
			Endpoint: GetEnv(app.Dir, "S3_ENDPOINT"),
			Key:      GetEnv(app.Dir, "S3_KEY"),
			Secret:   GetEnv(app.Dir, "S3_SECRET"),
		}
	}
	if cdn := newCDNStorage(app); cdn != nil {
		return cdn
	}
	return &LocalStorage{Dir: app.Dir}
}

func privateLogicalUploadPath(raw string) (string, error) {
	if raw == "" || raw != strings.TrimSpace(raw) || strings.ContainsAny(raw, "\\\x00?#%") {
		return "", fmt.Errorf("delete upload: invalid private upload reference")
	}
	if strings.HasPrefix(raw, "/") {
		raw = raw[1:]
	}
	if !strings.HasPrefix(raw, "uploads/private/") {
		return "", fmt.Errorf("delete upload: only uploads/private files may be deleted")
	}
	parts := strings.Split(strings.TrimPrefix(raw, "uploads/private/"), "/")
	if len(parts) == 0 {
		return "", fmt.Errorf("delete upload: empty private upload path")
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return "", fmt.Errorf("delete upload: invalid private upload path")
		}
	}
	return raw, nil
}

// privateUploadPath proves a stored reference belongs to the selected backend
// and returns the logical uploads/private/... key passed to StorageBackend.
func privateUploadPath(app *App, backend StorageBackend, raw string) (string, error) {
	logical, logicalErr := privateLogicalUploadPath(raw)
	if logicalErr == nil {
		return logical, nil
	}
	if !strings.Contains(raw, "://") {
		return "", logicalErr
	}
	if strings.ContainsAny(raw, "\\\x00?#%") {
		return "", fmt.Errorf("delete upload: invalid private upload URL")
	}
	switch store := backend.(type) {
	case *CDNStorage:
		u, err := neturl.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Host != store.CDNDomain || u.User != nil {
			return "", fmt.Errorf("delete upload: URL is not this app's configured CDN")
		}
		// Compared on the raw text, not the parsed URL: url.Parse lowercases
		// the scheme, and the stored spelling is the only accepted one.
		prefix := "https://" + store.CDNDomain + "/private/" + appMediaPrefix(app) + "/"
		key, ok := strings.CutPrefix(raw, prefix)
		if !ok {
			return "", fmt.Errorf("delete upload: CDN URL is outside this app's private prefix")
		}
		return privateUploadKeyAfterPrefix(key)
	case *S3Storage:
		key, ok := strings.CutPrefix(raw, store.objectURL(""))
		if !ok {
			return "", fmt.Errorf("delete upload: URL is not this app's configured S3 bucket")
		}
		return privateUploadKeyAfterPrefix(key)
	default:
		return "", fmt.Errorf("delete upload: URL references are unsupported by the selected backend")
	}
}

// privateUploadReadPath is privateUploadPath for a read (serve_file). A dev
// instance may also read the production prefix (appMediaReadPrefixes), which
// the rows refresh-dev --with-data copies still name, so its CDN URLs resolve
// too. Writes and deletes keep privateUploadPath, which accepts the
// instance's own prefix only.
func privateUploadReadPath(app *App, backend StorageBackend, raw string) (string, error) {
	logical, err := privateUploadPath(app, backend, raw)
	store, isCDN := backend.(*CDNStorage)
	if err == nil || !isCDN || strings.ContainsAny(raw, "\\\x00?#%") {
		return logical, err
	}
	for _, p := range appMediaReadPrefixes(app)[1:] {
		if key, ok := strings.CutPrefix(raw, "https://"+store.CDNDomain+"/private/"+p+"/"); ok {
			return privateUploadKeyAfterPrefix(key)
		}
	}
	return logical, err
}

// privateUploadKeyAfterPrefix checks the key part of a stored URL. The prefix
// already ends in a slash, so a key starting with another one is a doubled
// slash: privateLogicalUploadPath would take it for the one leading slash of a
// served path and return the same object as the stored URL.
func privateUploadKeyAfterPrefix(key string) (string, error) {
	if strings.HasPrefix(key, "/") {
		return "", fmt.Errorf("delete upload: invalid private upload URL")
	}
	return privateLogicalUploadPath(key)
}

// publicLogicalUploadPath accepts a public upload's logical path in its one
// canonical form: uploads/<segments>, at most one leading slash, no empty,
// dot or dot-dot segment, no backslash, NUL, query, fragment or
// percent-encoding (the form the presign broker's delete takes,
// brokerPublicDeletePath), and no folder named private in any letter case: a
// case-insensitive disk opens uploads/PRIVATE/x as the private file
// uploads/private/x, which only the private rule may delete.
func publicLogicalUploadPath(raw string) (string, error) {
	logical, ok := brokerPublicDeletePath(raw)
	if !ok || isPrivateUploadPath(strings.ToLower(logical)) {
		return "", fmt.Errorf("delete upload: not a canonical reference to an upload of this app (uploads/<path>, or the URL the upload returned)")
	}
	return logical, nil
}

// publicUploadPath is privateUploadPath for the public tier: it proves a
// stored reference names a public file under this app's own prefix on the
// selected backend and returns the logical uploads/... key passed to
// StorageBackend. The URL forms are compared on the raw text, so the stored
// spelling is the only one accepted.
func publicUploadPath(app *App, backend StorageBackend, raw string) (string, error) {
	if !strings.Contains(raw, "://") {
		return publicLogicalUploadPath(raw)
	}
	if strings.ContainsAny(raw, "\\\x00?#%") {
		return "", fmt.Errorf("delete upload: invalid upload URL")
	}
	var key string
	switch store := backend.(type) {
	case *CDNStorage:
		u, err := neturl.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Host != store.CDNDomain || u.User != nil {
			return "", fmt.Errorf("delete upload: URL is not this app's configured CDN")
		}
		var ok bool
		if key, ok = strings.CutPrefix(raw, "https://"+store.CDNDomain+"/public/"+appMediaPrefix(app)+"/"); !ok {
			return "", fmt.Errorf("delete upload: CDN URL is outside this app's own prefix")
		}
	case *S3Storage:
		var ok bool
		if key, ok = strings.CutPrefix(raw, store.objectURL("")); !ok {
			return "", fmt.Errorf("delete upload: URL is not this app's configured S3 bucket")
		}
	default:
		return "", fmt.Errorf("delete upload: URL references are unsupported by the selected backend")
	}
	// The prefix ends in a slash: a key starting with another is a doubled
	// slash, a second spelling of the stored URL (privateUploadKeyAfterPrefix).
	if strings.HasPrefix(key, "/") {
		return "", fmt.Errorf("delete upload: invalid upload URL")
	}
	return publicLogicalUploadPath(key)
}

// localUploadStoredAs reports whether logical is the spelling under which the
// file is stored in dir, or names nothing at all (deleting a missing file
// succeeds). A case-insensitive disk opens uploads/Avatars/A.PNG as
// uploads/avatars/a.png, but the uploader record is keyed by the stored
// spelling, so another spelling would reach the file past its record. It is
// the delete and signing side of the rule reads apply in openStoredUpload:
// names are compared byte for byte, never lower-cased or normalized.
func localUploadStoredAs(dir, logical string) bool {
	current := dir
	for _, part := range strings.Split(logical, "/") {
		entries, err := os.ReadDir(current)
		if err != nil {
			return os.IsNotExist(err)
		}
		stored := false
		for _, entry := range entries {
			if entry.Name() == part {
				stored = true
				break
			}
		}
		current = filepath.Join(current, part)
		if !stored {
			_, err := os.Lstat(current)
			return os.IsNotExist(err)
		}
	}
	return true
}

func deletePrivateUpload(app *App, raw string) error {
	backend := storageBackendForApp(app)
	if backend == nil {
		return fmt.Errorf("delete upload: storage backend unavailable")
	}
	path, err := privateUploadPath(app, backend, raw)
	if err != nil {
		return err
	}
	if err := localUploadSpellingRefusal(backend, path); err != nil {
		return err
	}
	if err := backend.Delete(path); err != nil {
		return fmt.Errorf("delete upload %q: %w", path, err)
	}
	return nil
}

// localUploadSpellingRefusal refuses a delete on local disk through a
// reference that is not the stored spelling of an existing file, private or
// public (localUploadStoredAs). It runs before the uploader rule is asked: a
// respelled private reference finds no uploader record, which reads as a file
// from before uploaders were recorded.
func localUploadSpellingRefusal(backend StorageBackend, logical string) error {
	if local, ok := backend.(*LocalStorage); ok && !localUploadStoredAs(local.Dir, logical) {
		return fmt.Errorf("delete upload: the reference is not spelled as the file is stored")
	}
	return nil
}

// deleteUploadAuthorized deletes the upload raw names, private or public,
// once authorize accepts the backend, the logical path the reference resolved
// to and its tier; its error stops the delete before any storage I/O. A
// reference that is neither this app's private upload (privateUploadPath) nor
// its public one (publicUploadPath) is refused before authorize is asked.
func deleteUploadAuthorized(app *App, raw string, authorize func(backend StorageBackend, logical string, public bool) error) error {
	backend := storageBackendForApp(app)
	if backend == nil {
		return fmt.Errorf("delete upload: storage backend unavailable")
	}
	public := false
	path, err := privateUploadPath(app, backend, raw)
	if err != nil {
		publicPath, publicErr := publicUploadPath(app, backend, raw)
		switch {
		case publicErr == nil:
			path, public, err = publicPath, true, nil
		case !isPrivateUploadPath(strings.ToLower(raw)):
			// Not a private-tier reference: the public rule says why.
			err = publicErr
		}
	}
	if err != nil {
		return err
	}
	if err := localUploadSpellingRefusal(backend, path); err != nil {
		return err
	}
	if err := authorize(backend, path, public); err != nil {
		return err
	}
	if err := backend.Delete(path); err != nil {
		return fmt.Errorf("delete upload %q: %w", path, err)
	}
	return nil
}

// uploadsDisabledCode is the stable `error` value of a request refused
// because the app set features.uploads: false.
const uploadsDisabledCode = "uploads_disabled"

// errUploadsDisabled is what a path that would store an uploaded file
// returns while the app has features.uploads: false.
var errUploadsDisabled = errors.New("file uploads are turned off for this app (features.uploads: false in app.yaml)")

// uploadsAllowed is the one check behind features.uploads. Every path that
// stores a file a client or a connector source sent calls it before it
// reads or stores anything: handleFileUploadAt (multipart creates,
// POST /api/_upload, POST /api/_files) and the connector's file pull. The
// switch used to be consulted only by the two upload routes, so a multipart
// POST /api/<table> still stored its file parts.
func uploadsAllowed(app *App) error {
	if app != nil && !app.FeatureEnabled("uploads") {
		return errUploadsDisabled
	}
	return nil
}

// uploadFilePart names a file part of a parsed multipart form (the first in
// name order), or "" when the form carries fields only.
func uploadFilePart(form *multipart.Form) string {
	if form == nil {
		return ""
	}
	name := ""
	for field, headers := range form.File {
		if len(headers) > 0 && (name == "" || field < name) {
			name = field
		}
	}
	return name
}

// writeUploadsDisabled answers a create that carries a file part while
// uploads are off: 403 with a stable code, in the shape of the create's
// other configuration refusal (field_owned_by_command). The two upload
// routes answer 404 instead, because the whole route is off.
func writeUploadsDisabled(w http.ResponseWriter, field string) {
	httpJSON(w, http.StatusForbidden, withRefusalDocs(map[string]any{
		"error":   uploadsDisabledCode,
		"field":   field,
		"message": errUploadsDisabled.Error() + ": the file was not accepted and nothing was saved; send the request without file parts",
	}, uploadsDisabledCode))
}

// HandleFileUpload processes file uploads from multipart forms.
// Returns the saved file path (relative to uploads/) or empty string.
// Accepts *App so storage resolves per-app in multi-tenant host mode
// (fixes: global storageBackend was last-loaded-app wins).
func HandleFileUpload(app *App, r *http.Request, fieldName, folder string, maxSize int64, allowedTypes []string) (string, error) {
	url, _, err := handleFileUploadAt(app, r, fieldName, folder, maxSize, allowedTypes)
	return url, err
}

// handleFileUploadAt is HandleFileUpload that also returns the storage path
// it reserved (set as soon as the ownership row or any bytes may exist, even
// on error) so a caller whose enclosing operation is refused can remove them
// with discardStoredUpload.
func handleFileUploadAt(app *App, r *http.Request, fieldName, folder string, maxSize int64, allowedTypes []string) (url, destPath string, err error) {
	// features.uploads: false closes every caller, present and future,
	// before the part is read: no bytes, no ownership row.
	if err := uploadsAllowed(app); err != nil {
		return "", "", err
	}
	if maxSize == 0 {
		maxSize = maxUploadSize
	}

	r.Body = http.MaxBytesReader(nil, r.Body, maxSize)

	file, header, err := r.FormFile(fieldName)
	if err != nil {
		if err == http.ErrMissingFile {
			return "", "", nil // no file uploaded, not an error
		}
		return "", "", fmt.Errorf("upload: %w", err)
	}
	defer file.Close()

	// Check file size
	if header.Size > maxSize {
		return "", "", fmt.Errorf("file too large (max %dMB)", maxSize/(1<<20))
	}

	// Check file type
	ext := strings.ToLower(filepath.Ext(header.Filename))
	ext = strings.TrimPrefix(ext, ".")
	// The extension becomes part of the storage key and the served URL.
	if !safeUploadExt(ext) {
		return "", "", fmt.Errorf("file extension not allowed (letters and digits only, at most 10)")
	}
	if len(allowedTypes) > 0 {
		allowed := false
		for _, t := range allowedTypes {
			if strings.TrimSpace(strings.ToLower(t)) == ext {
				allowed = true
				break
			}
		}
		if !allowed {
			return "", "", fmt.Errorf("file type .%s not allowed (allowed: %s)", ext, strings.Join(allowedTypes, ", "))
		}
	}

	// Detect MIME type from content (don't trust extension alone)
	buf := make([]byte, 512)
	n, _ := file.Read(buf)
	mimeType := http.DetectContentType(buf[:n])
	file.Seek(0, io.SeekStart)

	// Block dangerous MIME types. SVG and XML are included because they
	// can carry inline <script>/external entities and, if ever served
	// inline in the app origin, become stored XSS. Match on both the
	// sniffed content type and the declared extension - http.DetectContentType
	// classifies SVG as "text/xml" or "text/plain", so the extension
	// check is the reliable gate for the SVG case.
	dangerousMimes := []string{
		"application/x-executable", "application/x-sharedlib",
		"text/html", "application/javascript",
		"image/svg+xml", "application/xml", "text/xml",
	}
	for _, d := range dangerousMimes {
		if strings.HasPrefix(mimeType, d) {
			return "", "", fmt.Errorf("file type not allowed: %s", mimeType)
		}
	}
	switch ext {
	case "svg", "svgz", "xml", "xhtml", "html", "htm", "js", "mjs":
		return "", "", fmt.Errorf("file type not allowed: .%s", ext)
	}

	// Generate safe filename: uuid.ext
	uuid := generateShortID()
	safeName := fmt.Sprintf("%s.%s", uuid, ext)

	if folder == "" {
		folder = "files"
	}
	// compliance: hipaa keeps every upload on the private (signed URL) tier:
	// the auto-CRUD table folder and /api/_files go under uploads/private/.
	if app.hipaa() && !isPrivateUploadPath("uploads/"+folder+"/") {
		folder = "private/" + folder
	}
	destPath = filepath.Join("uploads", folder, safeName)

	// Object metadata: a correct Content-Type so media renders, and
	// force-download for active/unknown content (belt on top of the MIME
	// block above + the CDN's script-killing CSP).
	contentType, disposition := uploadContentMeta(ext, mimeType, safeName)

	backend := storageBackendForApp(app)
	// The platform's media store refuses some keys by their extension.
	// Refuse those here, before the ownership row is written and the store
	// is asked, with a message the client can act on.
	if err := platformMediaTypeRefusal(backend, destPath); err != nil {
		return "", "", err
	}
	// Record ownership before storing private bytes. A failed DB write must
	// not leave a new file looking like an unowned legacy upload. If storage
	// fails later, retain this harmless reservation: a remote failure may
	// have persisted bytes even when it returned an error. A public file's
	// uploader is recorded too, best effort (recordUploadOwner).
	if err := recordUploadOwner(app, r, destPath); err != nil {
		return "", "", fmt.Errorf("record upload owner: %w", err)
	}

	if backend != nil {
		if ms, ok := backend.(metaSaver); ok {
			url, err = ms.SaveWithMeta(destPath, file, contentType, disposition)
			if err != nil {
				return "", destPath, uploadSaveError(backend, destPath, err)
			}
			return url, destPath, nil
		}
		url, err = backend.Save(destPath, file)
		if err != nil {
			return "", destPath, uploadSaveError(backend, destPath, err)
		}
		return url, destPath, nil
	}

	// Fallback: direct local save (if InitStorage wasn't called)
	os.MkdirAll(filepath.Dir(destPath), 0755)
	dest, err := os.Create(destPath)
	if err != nil {
		return "", destPath, fmt.Errorf("save upload: %w", err)
	}
	defer dest.Close()
	if _, err := io.Copy(dest, file); err != nil {
		return "", destPath, fmt.Errorf("write upload: %w", err)
	}
	return "/" + destPath, destPath, nil
}

// errUploadNeedsExtension refuses a file with no filename extension where
// the platform's media store holds the app's uploads.
var errUploadNeedsExtension = errors.New("file type not allowed: the file name has no extension, and on the hosted platform an upload needs one (for example .pdf or .txt); send the file under a name that has an extension")

// platformMediaTypeRefusal applies the platform media store's own file-type
// rule (brokerObjectMeta) in the app process, for an upload that would go
// to that store. The store decides an object's served type from the key's
// extension alone, so it refuses a key with none, and the active types. The
// app used to send such an upload anyway and hand the store's refusal to the
// client as "save upload: save upload: presign broker: file type not
// allowed", after writing the ownership row. Other backends (local disk, the
// app's own bucket, a process that holds the media key itself) have no such
// rule and keep accepting a file with no extension.
func platformMediaTypeRefusal(backend StorageBackend, destPath string) error {
	cdn, ok := backend.(*CDNStorage)
	if !ok {
		return nil
	}
	if _, viaBroker := cdn.brokerSocket(); !viaBroker {
		return nil
	}
	if _, _, err := brokerObjectMeta(filepath.ToSlash(destPath)); err != nil {
		ext := strings.TrimPrefix(filepath.Ext(destPath), ".")
		if ext == "" {
			return errUploadNeedsExtension
		}
		return fmt.Errorf("file type not allowed: .%s", ext)
	}
	return nil
}

// errUploadStoreFault is what a client is told when the platform's media
// store did not take an upload for a reason that is not the client's.
var errUploadStoreFault = errors.New("save upload: the media store did not accept the file; try again, and see the app's log if it keeps failing")

// uploadSaveError is the error of an upload whose bytes the backend did not
// store. A fault of the platform's media store is logged and answered in
// general terms: its text names the platform's own components, never
// something the client can change. The account's media allowance, and the
// errors of local disk or the app's own bucket, pass through.
func uploadSaveError(backend StorageBackend, destPath string, err error) error {
	var allowance *mediaAllowanceError
	if _, platform := backend.(*CDNStorage); !platform || errors.As(err, &allowance) {
		return fmt.Errorf("save upload: %w", err)
	}
	log.Printf("upload %s: media store: %v", destPath, err)
	return errUploadStoreFault
}

// Names of the upload refusals in refusal_docs.go.
const (
	refusalUploadFileSize = "upload_file_too_large" // 413, one file over the per-file cap
	refusalUploadFileType = "upload_file_type"      // 415, a refused type or extension
)

// uploadRefusalStatus is the status of an upload handleFileUploadAt refused,
// the same on every path that stores a client's file (POST /api/_upload,
// POST /api/_files, a multipart create): 413 for a file over the per-file
// cap, 415 for a refused type or extension, 400 otherwise.
func uploadRefusalStatus(err error) int {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "too large"):
		return http.StatusRequestEntityTooLarge
	case strings.Contains(msg, "not allowed"):
		return http.StatusUnsupportedMediaType
	}
	return http.StatusBadRequest
}

// writeUploadRefusal answers an upload handleFileUploadAt refused. The three
// paths each mapped the error themselves, and only POST /api/_upload
// answered the documented 415 and 413; the multipart create and POST
// /api/_files answered 400 for the same file.
func writeUploadRefusal(w http.ResponseWriter, err error) {
	// The owner account's media allowance on the hosted platform: 507 with
	// the usage and the way out, like the database limit.
	if respondMediaAllowance(w, err) {
		return
	}
	switch status := uploadRefusalStatus(err); status {
	case http.StatusRequestEntityTooLarge:
		httpRefusal(w, err.Error(), status, refusalUploadFileSize)
	case http.StatusUnsupportedMediaType:
		httpRefusal(w, err.Error(), status, refusalUploadFileType)
	default:
		httpError(w, err.Error(), status)
	}
}

// writeUploadsOff answers a request to an upload route while the app has
// features.uploads: false: the route's 404, as JSON like every other
// /api/* miss, with the code a multipart create's refusal carries, so page
// code can tell "uploads are switched off" from a wrong path. The body is
// never read.
func writeUploadsOff(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	httpJSON(w, http.StatusNotFound, withRefusalDocs(map[string]any{
		"error":   uploadsDisabledCode,
		"message": errUploadsDisabled.Error(),
	}, uploadsDisabledCode))
}

// discardStoredUpload removes the bytes a refused request left behind, then
// their ownership row, and only if the byte delete succeeded (or the object was
// already gone). Best effort and logged: the request is already being refused.
func discardStoredUpload(app *App, destPath string) {
	var err error
	if backend := storageBackendForApp(app); backend != nil {
		err = backend.Delete(destPath)
	} else if err = os.Remove(destPath); os.IsNotExist(err) {
		err = nil
	}
	if err != nil {
		// Keep the ownership row: bytes with no row look like a legacy file
		// and fall under the looser reference-only rule (upload_owners.go).
		log.Printf("discard refused upload %s: %v (ownership row kept)", destPath, err)
		return
	}
	if app != nil && app.DB != nil {
		owners := publicUploadOwnersTable
		if isPrivateUploadPath(destPath) {
			owners = privateUploadOwnersTable
		}
		if _, err := app.DB.Exec(`DELETE FROM `+owners+` WHERE path = ?`, uploadRelPath(destPath)); err != nil && !strings.Contains(err.Error(), "no such table") {
			log.Printf("discard refused upload %s ownership: %v", destPath, err)
		}
	}
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
//	file       (required) the file blob
//	kind       (optional) subfolder under uploads/ - "avatars", "imports",
//	           "feedback", etc. Defaults to "files".
//	_csrf      (required for cookie auth) framework's CSRF token.
//	           Bearer-auth requests are exempt.
//
// Returns JSON (the generated bm.d.ts types bm.upload's answer from this;
// TestUploadTypeMatchesTheAnswer keeps the two the same):
//
//	{ "path": "<the stored reference: /uploads/<kind>/<id>.<ext>, or a media CDN URL>",
//	  "url":  "<the same reference>",
//	  "filename": "<original filename>",
//	  "size": <bytes> }
//
// 200 on success, 401 if anonymous + auth required, 403 on CSRF mismatch,
// 413 (Payload Too Large) when the file exceeds the per-file cap,
// 415 (Unsupported Media Type) for a refused type or extension.
func RegisterUploadRoute(mux appRouteRegistrar, app *App) {
	mux.HandleFunc("POST /api/_upload", func(w http.ResponseWriter, r *http.Request) {
		if !app.FeatureEnabled("uploads") {
			writeUploadsOff(w)
			return
		}
		// Auth: require a session when the app has auth: configured.
		if NeedsAuth(app) {
			if session := getSession(app, r); session == nil {
				httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
				return
			}
		}
		release, ok := limitUploadBody(w, r, uploadClientKey(app, r))
		if !ok {
			return
		}
		defer release()
		// CSRF - bypass for bearer.
		if !isBearerAuth(r) && !validateCSRF(r) {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid CSRF token"})
			return
		}

		// `kind` becomes the storage folder under uploads/.
		kind, err := normalizeUploadKind(r.FormValue("kind"))
		if err != nil {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		if app.hipaa() {
			// Under compliance: hipaa the default is private and a public
			// kind is refused: PHI must never land on the public tier.
			if r.FormValue("kind") != "" && kind != "private" {
				httpJSON(w, http.StatusBadRequest, map[string]any{"error": hipaaPublicUploadRefusal(kind)})
				return
			}
			kind = "private"
		}

		// HandleFileUpload parses the multipart body, validates size +
		// MIME, writes via the per-app storage backend (local or S3).
		// Returns the stored path/URL.
		savedURL, err := HandleFileUpload(app, r, "file", kind, 0, nil)
		if err != nil {
			writeUploadRefusal(w, err)
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

// normalizeUploadKind maps POST /api/_upload's `kind` onto its storage
// folder under uploads/. Only the folder `private` is the private tier
// (isPrivateUploadPath); every other folder is PUBLIC. So `private` and
// `public` are matched in any letter case (`Private` used to make a public
// folder named Private, silently), and a kind that reads as private but is
// not that folder (`private-docs`, `my_private`) is refused rather than
// stored public. Other names stay public folders (`avatars`), restricted to
// letters, digits, `-` and `_` so a kind cannot traverse ("../foo").
func normalizeUploadKind(kind string) (string, error) {
	if kind == "" {
		return "files", nil
	}
	for _, c := range kind {
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_'
		if !ok {
			return "", fmt.Errorf("invalid kind (alphanumeric/-/_ only)")
		}
	}
	switch lower := strings.ToLower(kind); {
	case lower == "private" || lower == "public":
		return lower, nil
	case strings.Contains(lower, "private"):
		return "", fmt.Errorf("kind %q is not private: only kind=private stores a private file, and every other kind is a PUBLIC folder. Use kind=private, or a public folder name without \"private\"", kind)
	}
	return kind, nil
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
	applyUploadDispositionWithSniff(w, fullPath, func() bool { return uploadsSniffActive(fullPath) })
}

// applyUploadFileDispositionHeaders sniffs the same pinned file that the
// caller will serve. ReadAt leaves its position unchanged for streaming.
func applyUploadFileDispositionHeaders(w http.ResponseWriter, fullPath string, file io.ReaderAt) {
	applyUploadDispositionWithSniff(w, fullPath, func() bool { return uploadsReaderSniffActive(file) })
}

func applyUploadDispositionWithSniff(w http.ResponseWriter, fullPath string, sniffActive func() bool) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	ext := strings.ToLower(filepath.Ext(fullPath))
	inlineOK := false
	switch ext {
	case ".jpg", ".jpeg", ".png", ".gif", ".webp", ".avif", ".ico",
		".mp4", ".webm", ".mov", ".m4a", ".mp3", ".wav", ".ogg",
		".pdf", ".txt", ".csv", ".json":
		// Inline OK - these can't carry script in the app's origin.
		inlineOK = true
	}
	// Defense in depth: base the decision on the SNIFFED content type, not
	// just the extension. A file renamed to a safe extension (e.g. a
	// polyglot SVG saved as "logo.png") can still sniff to an
	// active/scriptable type; force attachment whenever the bytes look
	// like HTML/XML/SVG/script regardless of the extension allowlist.
	if inlineOK && sniffActive() {
		inlineOK = false
	}
	if inlineOK {
		return
	}
	// Everything else (.html, .svg, .xml, .js, .wasm, .htm, anything
	// unknown or sniffed-active) downloads instead of renders.
	base := filepath.Base(fullPath)
	w.Header().Set("Content-Disposition", `attachment; filename="`+base+`"`)
}

// uploadsSniffActive reports whether the file's leading bytes sniff to an
// active/scriptable content type (HTML, XML, SVG) that must never be
// served inline in the app origin. Best-effort: an unreadable file is
// treated as non-active (the extension allowlist already vetted it).
func uploadsSniffActive(fullPath string) bool {
	f, err := os.Open(fullPath)
	if err != nil {
		return false
	}
	defer f.Close()
	return uploadsReaderSniffActive(f)
}

func uploadsReaderSniffActive(f io.ReaderAt) bool {
	buf := make([]byte, 512)
	n, _ := f.ReadAt(buf, 0)
	sniff := strings.ToLower(http.DetectContentType(buf[:n]))
	if strings.HasPrefix(sniff, "text/html") ||
		strings.HasPrefix(sniff, "text/xml") ||
		strings.HasPrefix(sniff, "application/xml") ||
		strings.HasPrefix(sniff, "image/svg") {
		return true
	}
	// http.DetectContentType never returns image/svg+xml; catch a leading
	// "<svg" / "<?xml" prefix directly (after an optional UTF-8 BOM and
	// surrounding whitespace).
	head := strings.TrimPrefix(string(buf[:n]), "\uFEFF") // strip UTF-8 BOM
	head = strings.ToLower(strings.TrimSpace(head))
	if strings.HasPrefix(head, "<?xml") || strings.HasPrefix(head, "<svg") {
		return true
	}
	return false
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
		return s3.Key, s3.Secret, s3.Token
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
