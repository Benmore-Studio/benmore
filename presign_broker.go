package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ─── Presign broker ───────────────────────────────────────────────────────
//
// WHY THIS EXISTS. In a multi-tenant deployment each app process runs non-root,
// and the host firewalls non-root processes off the IMDS endpoint (an SSRF
// guard: a tenant flow must not be able to fetch the EC2 instance role and
// steal deployment-wide credentials). So the per-app upload path - which runs as
// the non-root, per-tenant benmore-app-<sub> user - cannot reach IMDS and
// must not hold a durable AWS key either (it executes sandboxed tenant code).
//
// The broker keeps the ONE durable, least-privilege media key in the router
// process only (the router runs no tenant code) and hands each per-app
// process a short-lived, prefix-scoped presigned PUT URL, executes a scoped
// delete, or signs a CloudFront URL for a private object over a unix socket.
// The router authenticates the caller by the socket's peer-uid (SO_PEERCRED),
// derives the app from that uid, and refuses to presign, delete or sign
// outside that app's own <visibility>/<app>/ key prefix - so a
// fully-compromised per-app process can only mutate, or mint read access to,
// its own namespace. An app's dev and prod instances share the uid, so each
// request also carries an instance proof under the instance's own server
// secret (presign_instance.go): a proven dev instance writes and deletes only
// under <app>-dev. No root process, no IMDS exposure, no durable
// credential (storage key or CloudFront signing key) in any tenant-executing
// process.

// presignBrokerSocketPath returns the unix socket the router listens on and
// per-app processes dial. Overridable for tests / alternate layouts.
func presignBrokerSocketPath() string {
	if p := strings.TrimSpace(os.Getenv("BENMORE_PRESIGN_SOCKET")); p != "" {
		return p
	}
	return "/run/benmore/presign.sock"
}

// presignReq is the per-app → router request. For put/delete the client
// sends its own prefix + the logical upload path; the broker derives
// visibility from the path and validates the prefix against the connection's
// peer-uid. For sign, Path is the full bucket key (private/<prefix>/...) and
// ExpiresIn the requested lifetime in seconds.
type presignReq struct {
	Operation   string `json:"operation,omitempty"` // empty/put (back-compat), delete or sign
	Prefix      string `json:"prefix"`
	Path        string `json:"path"`
	ContentType string `json:"content_type"`
	Disposition string `json:"disposition"`
	ExpiresIn   int64  `json:"expires_in,omitempty"`
	// Size is the exact length of the body a put will carry. The broker signs
	// it into the URL as the Content-Length, so the store refuses any other
	// body, and charges it to the owner account's media allowance
	// (media_allowance.go). Older binaries send none.
	Size *int64 `json:"size,omitempty"`
	// Instance, Time and Proof say which instance of the peer uid's app
	// sent the request: an HMAC under that instance's own server secret
	// (presignInstanceMAC). Older binaries send none.
	Instance string `json:"instance,omitempty"`
	Time     int64  `json:"ts,omitempty"`
	Proof    string `json:"proof,omitempty"`
}

// mediaSignMaxTTL caps the lifetime of a broker-signed CloudFront URL: the
// same ceiling bm.signedUrl applies (a signed URL is a replayable bearer
// credential; see signCloudFrontURL).
const mediaSignMaxTTL = oauthMaxSignedURLTTL

// mediaSignSlots bounds concurrent RSA signatures in the router, so a tenant
// flooding the broker with sign requests cannot take every core from the
// proxy path.
var mediaSignSlots = make(chan struct{}, max(1, runtime.NumCPU()/2))

// presignResp is the router → per-app reply.
type presignResp struct {
	URL     string            `json:"url,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Key     string            `json:"key,omitempty"`
	Error   string            `json:"error,omitempty"`
	// Code, UsedBytes and LimitBytes accompany Error when the upload was
	// refused for the owner account's media allowance (mediaAllowanceCode).
	Code       string `json:"code,omitempty"`
	UsedBytes  int64  `json:"used_bytes,omitempty"`
	LimitBytes int64  `json:"limit_bytes,omitempty"`
}

// StartPresignBroker starts the router-side presign listener. No-op (returns
// nil) when the platform media config is absent or this process holds
// neither the scoped storage key nor the CloudFront signing key - i.e. off
// the platform host, where CDNStorage and signPrivateMediaURL work
// directly. Called once from router boot; the listener runs for the process
// lifetime.
func StartPresignBroker(sockPath string) error {
	cfg := getPlatformMedia()
	if cfg == nil || (cfg.S3Key == "" && !cfg.canSign()) {
		return nil // broker disabled: no media CDN, or no media credential in this process
	}
	if !cfg.canSign() {
		log.Printf("  WARN: presign broker: no CloudFront signing key (BENMORE_PLATFORM_MEDIA_KEYPAIR_ID + PRIVATE_KEY*); hosted apps cannot sign private media URLs")
	}
	if err := os.MkdirAll(sockPathDir(sockPath), 0o750); err != nil {
		return fmt.Errorf("presign broker: mkdir socket dir: %w", err)
	}
	_ = os.Remove(sockPath) // clear a stale socket from a prior run
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return fmt.Errorf("presign broker: listen %s: %w", sockPath, err)
	}
	// Group-rw so per-app processes (Group=benmore) can connect; the socket
	// is owned by the router's user:group (benmore:benmore).
	_ = os.Chmod(sockPath, 0o660)
	log.Printf("  presign broker: listening on %s (media bucket %s)", sockPath, cfg.Bucket)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			uconn, ok := conn.(*net.UnixConn)
			if !ok {
				conn.Close()
				continue
			}
			presignBrokerGate.serve("presign broker", uconn, func() { handlePresignConn(uconn, cfg) })
		}
	}()
	return nil
}

// brokerSocketReachable reports whether the presign broker socket exists. The
// per-app upload path uses this to decide between broker and direct signing.
// Presign requests are tiny (16 KiB cap); the gate bounds fan-out per tenant
// uid and keeps 32 slots for the router's own uid (_platform uploads).
var presignBrokerGate = &brokerConnGate{perUID: map[int]int{}, maxTotal: 288, maxPerUID: 32, reserved: 32, ownUID: os.Getuid()}

// presignRequestReadTimeout bounds delivery of the (16 KiB) request.
const presignRequestReadTimeout = 2 * time.Second

func brokerSocketReachable(sock string) bool {
	fi, err := os.Stat(sock)
	return err == nil && fi.Mode()&os.ModeSocket != 0
}

func sockPathDir(p string) string {
	if i := strings.LastIndexByte(p, '/'); i > 0 {
		return p[:i]
	}
	return "."
}

// handlePresignConn authenticates one connection by peer-uid, scopes the key
// to that uid's app, mints a presigned PUT, and replies.
func handlePresignConn(conn *net.UnixConn, cfg *PlatformMediaConfig) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	// The request is 16 KiB at most: anything slower is holding a slot.
	beginBrokerRead(conn, presignRequestReadTimeout)

	uid, err := peerUID(conn)
	if err != nil {
		writePresignErr(conn, "peer identity unavailable")
		return
	}

	var req presignReq
	dec := json.NewDecoder(io.LimitReader(conn, 16<<10))
	if err := dec.Decode(&req); err != nil {
		writePresignErr(conn, "bad request")
		return
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Derive the caller's allowed prefix from its uid. A per-tenant uid is
	// named benmore-app-<sub>; its key namespace is exactly <sub>. The shared
	// first-party user (router / _platform, "benmore") is trusted to name its
	// own prefix. Anything else is rejected.
	allowedPrefix, firstParty := prefixForUID(uid)
	resp, err := dispatchPresignBrokerRequest(req, allowedPrefix, firstParty, cfg, time.Now())
	if err != nil {
		b, _ := json.Marshal(presignErrorReply(err))
		conn.Write(b)
		return
	}
	b, _ := json.Marshal(resp)
	conn.Write(b)
}

// dispatchPresignBrokerRequest routes one authenticated request: the caller's
// scope (uid, then instance proof) first, then sign to the CloudFront signer
// and everything else to the storage presigner.
func dispatchPresignBrokerRequest(req presignReq, allowedPrefix string, firstParty bool, cfg *PlatformMediaConfig, now time.Time) (*presignResp, error) {
	scope, err := presignCallerScope(req, allowedPrefix, firstParty, now)
	if err != nil {
		return nil, err
	}
	if strings.EqualFold(strings.TrimSpace(req.Operation), "sign") {
		return executeMediaSignRequest(req, scope, cfg, now)
	}
	s3 := &S3Storage{Bucket: cfg.Bucket, Region: cfg.Region, Key: cfg.S3Key, Secret: cfg.S3Secret}
	return executePresignBrokerRequest(req, scope, s3)
}

// executeMediaSignRequest signs a CloudFront URL for one private object under
// a prefix the caller may read, for at most mediaSignMaxTTL. The key must
// pass the same containment rule the app process applies
// (mediaKeyVisibility), and the resource is checked again by
// signCloudFrontURL before it enters the policy.
func executeMediaSignRequest(req presignReq, scope presignScope, cfg *PlatformMediaConfig, now time.Time) (*presignResp, error) {
	if !cfg.canSign() {
		return nil, fmt.Errorf("media signing not configured")
	}
	readable := false
	for _, prefix := range scope.read {
		if vis, ok := mediaKeyVisibility(req.Path, prefix); ok && vis == "private" {
			readable = true
			break
		}
	}
	if !readable {
		return nil, fmt.Errorf("path outside caller's private media")
	}
	if req.ExpiresIn <= 0 {
		return nil, fmt.Errorf("bad expiry")
	}
	ttl := mediaSignMaxTTL
	if req.ExpiresIn < int64(mediaSignMaxTTL/time.Second) {
		ttl = time.Duration(req.ExpiresIn) * time.Second
	}
	select {
	case mediaSignSlots <- struct{}{}:
		defer func() { <-mediaSignSlots }()
	case <-time.After(2 * time.Second):
		return nil, fmt.Errorf("signer busy")
	}
	signed, err := signCloudFrontURL("https://"+cfg.CDNDomain+"/"+req.Path, now.Add(ttl).Unix(), cfg.KeyPairID, cfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("sign failed")
	}
	return &presignResp{URL: signed, Key: req.Path}, nil
}

func writePresignErr(conn *net.UnixConn, msg string) {
	b, _ := json.Marshal(presignResp{Error: msg})
	conn.Write(b)
}

// prefixForUID (uid → app prefix, cached) lives in broker_limits.go.

// executePresignBrokerRequest presigns a PUT or deletes one private object,
// always under the caller's own write prefix (a dev instance's <app>-dev).
func executePresignBrokerRequest(req presignReq, scope presignScope, s3 *S3Storage) (*presignResp, error) {
	prefix := scope.write
	if prefix == "" {
		return nil, fmt.Errorf("no prefix")
	}

	operation := strings.ToLower(strings.TrimSpace(req.Operation))
	if operation == "delete" {
		key := ""
		if logical, err := privateLogicalUploadPath(req.Path); err == nil {
			key = "private/" + prefix + "/" + logical
		} else if logical, ok := brokerPublicDeletePath(req.Path); ok {
			// A multipart create that is refused removes the public file it
			// stored (discardStoredUpload). The caller can already PUT over
			// any key under this prefix, so deleting one grants nothing new.
			key = "public/" + prefix + "/" + logical
		} else {
			return nil, err
		}
		// Reads and deletes are never refused for the allowance. The object
		// is measured at the store first, so the account gets back exactly
		// what the delete freed; a store too slow to say does not hold the
		// delete up (the meter lists the app instead).
		freed := int64(-1)
		if presignMediaMeter != nil {
			// Measure, delete and credit as one step per key.
			defer lockMediaKey(key)()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			if size, found, err := s3.ObjectSize(ctx, key); err == nil {
				freed = 0
				if found {
					freed = size
				}
			}
			cancel()
		}
		if err := s3.Delete(key); err != nil {
			return nil, err
		}
		if presignMediaMeter != nil {
			presignMediaMeter.deleted(prefix, key, freed)
		}
		return &presignResp{Key: key}, nil
	}
	if operation != "" && operation != "put" {
		return nil, fmt.Errorf("unsupported operation")
	}

	logical := strings.TrimPrefix(req.Path, "/")
	if logical == "" || strings.Contains(logical, "..") {
		return nil, fmt.Errorf("bad path")
	}
	vis := "public"
	if isPrivateUploadPath(logical) {
		vis = "private"
	}
	key := vis + "/" + prefix + "/" + logical
	cacheControl := "public, max-age=31536000, immutable"
	if vis == "private" {
		cacheControl = "no-store"
	}
	contentType, disposition, err := brokerObjectMeta(logical)
	if err != nil {
		return nil, err
	}
	size, err := presignDeclaredSize(req)
	if err != nil {
		return nil, err
	}
	url, headers, err := presignS3PutURLSized(s3, key, contentType, disposition, cacheControl, size, presignPutURLTTL)
	if err != nil {
		return nil, fmt.Errorf("presign failed")
	}
	// The allowance is the last gate: everything above refuses without
	// charging anything, and the URL leaves the router only for an upload
	// that was charged.
	if presignMediaMeter != nil {
		if refused := presignMediaMeter.admit(mediaUpload{
			Prefix: prefix, Key: key, Size: size, FirstParty: scope.firstParty,
			Measure: func() (int64, bool, error) {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				return s3.ObjectSize(ctx, key)
			},
		}); refused != nil {
			return nil, refused
		}
	}
	return &presignResp{URL: url, Headers: headers, Key: key}, nil
}

// brokerPublicDeletePath accepts a public upload reference for the broker's
// delete in its one canonical form: uploads/<segments>, at most one leading
// slash, no empty, dot or dot-dot segment, no backslash, NUL, query, fragment
// or percent-encoding, and not a path the PUT branch would store privately
// (those keep the stricter uploads/private rule).
func brokerPublicDeletePath(raw string) (string, bool) {
	if raw == "" || raw != strings.TrimSpace(raw) || strings.ContainsAny(raw, "\\\x00?#%") {
		return "", false
	}
	raw = strings.TrimPrefix(raw, "/")
	if !strings.HasPrefix(raw, "uploads/") || isPrivateUploadPath(raw) {
		return "", false
	}
	for _, part := range strings.Split(raw, "/") {
		if part == "" || part == "." || part == ".." {
			return "", false
		}
	}
	return raw, true
}

// brokerObjectMeta decides an object's Content-Type and Content-Disposition
// from its path alone. The broker is the trust boundary for tenant writes to
// the shared media origin, so a tenant-supplied type (text/html, say, with
// an inline disposition) is never used: the same extension policy as the
// upload path applies, and the active types that path refuses are refused
// here too.
func brokerObjectMeta(logical string) (contentType, disposition string, err error) {
	ext := strings.ToLower(strings.TrimPrefix(path.Ext(logical), "."))
	switch ext {
	case "svg", "svgz", "xml", "xhtml", "html", "htm", "shtml", "js", "mjs", "":
		return "", "", fmt.Errorf("file type not allowed")
	}
	contentType, disposition = uploadContentMeta(ext, "", path.Base(logical))
	switch strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0])) {
	case "text/html", "application/xhtml+xml", "image/svg+xml", "text/xml", "application/xml",
		"application/javascript", "text/javascript", "application/ecmascript", "text/ecmascript":
		contentType = "application/octet-stream"
	}
	return contentType, disposition, nil
}

// ─── Per-app client ─────────────────────────────────────────────────────────

// requestPresignBroker dials the broker for a presigned PUT, scoped delete or
// signed CloudFront URL, proving which instance (instance subdomain) asks.
func requestPresignBroker(sockPath string, req presignReq, instance string) (*presignResp, error) {
	attachPresignInstanceProof(&req, instance, time.Now())
	conn, err := net.DialTimeout("unix", sockPath, 3*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	b, _ := json.Marshal(req)
	if _, err := conn.Write(b); err != nil {
		return nil, err
	}
	if uc, ok := conn.(*net.UnixConn); ok {
		uc.CloseWrite() // signal EOF so the broker's decoder returns
	}
	var resp presignResp
	if err := json.NewDecoder(io.LimitReader(conn, 64<<10)).Decode(&resp); err != nil {
		return nil, err
	}
	if resp.Code == mediaAllowanceCode {
		// The owner account's media allowance: a refusal the upload routes
		// answer as such (respondMediaAllowance), not a broker fault.
		return nil, &mediaAllowanceError{Message: resp.Error, UsedBytes: resp.UsedBytes, LimitBytes: resp.LimitBytes}
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("presign broker: %s", resp.Error)
	}
	if req.Operation != "delete" && resp.URL == "" {
		return nil, fmt.Errorf("presign broker: empty url")
	}
	return &resp, nil
}

// ─── SigV4 query-string presign (PUT, single object) ─────────────────────────

// presignS3PutURL builds a SigV4 query-string presigned PUT URL valid for
// `expires`. It signs host + content-type (+ content-disposition when set) so
// the stored object's type/disposition are pinned to what the broker
// authorized; the payload is UNSIGNED-PAYLOAD (the bytes are not hashed into
// the signature - object size is enforced upstream by the upload handler).
// The caller MUST PUT with exactly the returned headers. AWS-native only.
func presignS3PutURL(s3 *S3Storage, key, contentType, disposition, cacheControl string, expires time.Duration) (string, map[string]string, error) {
	return presignS3PutURLSized(s3, key, contentType, disposition, cacheControl, -1, expires)
}

// presignS3PutURLSized is presignS3PutURL that also signs the exact length
// of the body when size is not negative: content-length joins the signed
// headers, so the store answers SignatureDoesNotMatch to a PUT of any other
// length and the object stored is exactly size bytes. The length is not
// among the returned headers: an HTTP client sends it from the body it
// carries.
func presignS3PutURLSized(s3 *S3Storage, key, contentType, disposition, cacheControl string, size int64, expires time.Duration) (string, map[string]string, error) {
	accessKey, secret, token := s3.resolveCreds()
	if accessKey == "" {
		return "", nil, fmt.Errorf("presign: no credentials")
	}
	region := s3.Region
	if region == "" {
		region = "us-east-1"
	}
	host := fmt.Sprintf("s3.%s.amazonaws.com", region)
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")
	credentialScope := dateStamp + "/" + region + "/s3/aws4_request"

	// Signed headers, sorted by lowercase name.
	hdrs := [][2]string{{"content-type", contentType}, {"host", host}}
	if disposition != "" {
		hdrs = append(hdrs, [2]string{"content-disposition", disposition})
	}
	if cacheControl != "" {
		hdrs = append(hdrs, [2]string{"cache-control", cacheControl})
	}
	if size >= 0 {
		hdrs = append(hdrs, [2]string{"content-length", strconv.FormatInt(size, 10)})
	}
	sort.Slice(hdrs, func(i, j int) bool { return hdrs[i][0] < hdrs[j][0] })
	var canonHeaders strings.Builder
	names := make([]string, len(hdrs))
	for i, h := range hdrs {
		canonHeaders.WriteString(h[0])
		canonHeaders.WriteByte(':')
		canonHeaders.WriteString(strings.TrimSpace(h[1]))
		canonHeaders.WriteByte('\n')
		names[i] = h[0]
	}
	signedHeaders := strings.Join(names, ";")

	// Canonical query (the X-Amz-* params, minus the signature itself).
	qp := map[string]string{
		"X-Amz-Algorithm":     "AWS4-HMAC-SHA256",
		"X-Amz-Credential":    accessKey + "/" + credentialScope,
		"X-Amz-Date":          amzDate,
		"X-Amz-Expires":       strconv.Itoa(int(expires.Seconds())),
		"X-Amz-SignedHeaders": signedHeaders,
	}
	if token != "" {
		qp["X-Amz-Security-Token"] = token
	}
	canonicalQuery := awsCanonicalQuery(qp)

	canonicalURI := "/" + s3.Bucket + "/" + awsURIEncode(key, false)
	canonicalRequest := strings.Join([]string{
		"PUT",
		canonicalURI,
		canonicalQuery,
		canonHeaders.String(),
		signedHeaders,
		"UNSIGNED-PAYLOAD",
	}, "\n")

	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credentialScope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")

	kDate := hmacSHA256([]byte("AWS4"+secret), dateStamp)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, "s3")
	kSigning := hmacSHA256(kService, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(kSigning, stringToSign))

	signedURL := "https://" + host + canonicalURI + "?" + canonicalQuery + "&X-Amz-Signature=" + signature
	respHeaders := map[string]string{"Content-Type": contentType}
	if disposition != "" {
		respHeaders["Content-Disposition"] = disposition
	}
	if cacheControl != "" {
		respHeaders["Cache-Control"] = cacheControl
	}
	return signedURL, respHeaders, nil
}

// awsCanonicalQuery renders X-Amz-* params as a sorted, RFC3986-encoded query
// string per the SigV4 canonical-request rules.
func awsCanonicalQuery(params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, awsURIEncode(k, true)+"="+awsURIEncode(params[k], true))
	}
	return strings.Join(parts, "&")
}

// awsURIEncode applies AWS's RFC3986 encoding: unreserved chars pass through,
// everything else is %XX. '/' is preserved in path segments (encodeSlash=false)
// and encoded in query values (encodeSlash=true).
func awsURIEncode(s string, encodeSlash bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~':
			b.WriteByte(c)
		case c == '/' && !encodeSlash:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// ─── CDNStorage broker integration ──────────────────────────────────────────

// saveViaBroker uploads through the presign broker: ask the router (which
// holds the scoped key) for a presigned PUT scoped to this app's prefix, then
// PUT the bytes straight to S3. Used by the per-app process, which holds no
// durable AWS credential and cannot reach IMDS.
func (c *CDNStorage) saveViaBroker(sockPath, path string, data io.Reader, contentType, disposition string) (string, error) {
	// Stream a seekable body (the spooled multipart file, a bytes.Reader)
	// with its exact length: reading a 50 MB upload whole and copying it
	// into a string held over 100 MB per upload, enough for the process's
	// eight upload slots to exceed a hosted app's memory limit.
	size, openBody, err := uploadBodyWithSize(data)
	if err != nil {
		return "", err
	}
	// A reader already past its end uploads an empty body, as before.
	size = max(size, 0)
	resp, err := requestPresignBroker(sockPath, presignReq{
		Prefix:      c.Prefix,
		Path:        strings.TrimPrefix(path, "/"),
		ContentType: contentType,
		Disposition: disposition,
		// Declared so the router can sign it into the URL and count it.
		Size: &size,
	}, c.Instance)
	if err != nil {
		return "", fmt.Errorf("save upload: %w", err)
	}
	req, err := http.NewRequest("PUT", resp.URL, http.NoBody)
	if err != nil {
		return "", err
	}
	if size > 0 {
		// GetBody lets a 307/308 replay the body, as the in-memory reader did.
		req.GetBody = func() (io.ReadCloser, error) {
			b, err := openBody()
			return io.NopCloser(b), err
		}
		if req.Body, err = req.GetBody(); err != nil {
			return "", err
		}
		req.ContentLength = size
	}
	for k, v := range resp.Headers {
		req.Header.Set(k, v)
	}
	client := &http.Client{Timeout: 60 * time.Second}
	r, err := client.Do(req)
	if err != nil {
		return "", err
	}
	rb, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if r.StatusCode >= 400 {
		return "", fmt.Errorf("save upload: S3 PUT via presign failed: %d: %s", r.StatusCode, string(rb))
	}
	return "https://" + c.CDNDomain + "/" + resp.Key, nil
}

// uploadBodyWithSize returns the length of the rest of data and a function
// that opens an independent reader over exactly those bytes. A file or
// bytes.Reader (io.ReaderAt + io.Seeker: the spooled multipart file is
// either) is read in place, never buffered; anything else is read into
// memory once.
func uploadBodyWithSize(data io.Reader) (int64, func() (io.Reader, error), error) {
	if ra, ok := data.(interface {
		io.ReaderAt
		io.Seeker
	}); ok {
		start, err := ra.Seek(0, io.SeekCurrent)
		if err != nil {
			return 0, nil, err
		}
		end, err := ra.Seek(0, io.SeekEnd)
		if err != nil {
			return 0, nil, err
		}
		if _, err := ra.Seek(start, io.SeekStart); err != nil {
			return 0, nil, err
		}
		return end - start, func() (io.Reader, error) { return io.NewSectionReader(ra, start, end-start), nil }, nil
	}
	b, err := io.ReadAll(data)
	if err != nil {
		return 0, nil, err
	}
	return int64(len(b)), func() (io.Reader, error) { return bytes.NewReader(b), nil }, nil
}

func (c *CDNStorage) deleteViaBroker(sockPath, path string) error {
	_, err := requestPresignBroker(sockPath, presignReq{
		Operation: "delete",
		Prefix:    c.Prefix,
		Path:      strings.TrimPrefix(path, "/"),
	}, c.Instance)
	if err != nil {
		return fmt.Errorf("delete upload: %w", err)
	}
	return nil
}
