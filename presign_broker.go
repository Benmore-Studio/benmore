package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/user"
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
// steal deployment-wide credentials). So the per-app upload path — which runs as
// the non-root, per-tenant benmore-app-<sub> user — cannot reach IMDS and
// must not hold a durable AWS key either (it executes sandboxed tenant code).
//
// The broker keeps the ONE durable, least-privilege media key in the router
// process only (the router runs no tenant code) and hands each per-app
// process a short-lived, prefix-scoped presigned PUT URL over a unix socket.
// The router authenticates the caller by the socket's peer-uid (SO_PEERCRED),
// derives the app from that uid, and refuses to presign outside that app's
// own <visibility>/<app>/ key prefix — so a fully-compromised per-app process
// can at most write 60s-scoped objects into its own namespace, and a leaked
// URL is a single PUT to one key. No root process, no IMDS exposure, no
// durable credential in any tenant-executing process.

// presignBrokerSocketPath returns the unix socket the router listens on and
// per-app processes dial. Overridable for tests / alternate layouts.
func presignBrokerSocketPath() string {
	if p := strings.TrimSpace(os.Getenv("BENMORE_PRESIGN_SOCKET")); p != "" {
		return p
	}
	return "/run/benmore/presign.sock"
}

// presignReq is the per-app → router request. The client sends only its own
// prefix + the logical upload path; the broker derives visibility from the
// path and validates the prefix against the connection's peer-uid.
type presignReq struct {
	Prefix      string `json:"prefix"`
	Path        string `json:"path"`
	ContentType string `json:"content_type"`
	Disposition string `json:"disposition"`
}

// presignResp is the router → per-app reply.
type presignResp struct {
	URL     string            `json:"url,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Key     string            `json:"key,omitempty"`
	Error   string            `json:"error,omitempty"`
}

// StartPresignBroker starts the router-side presign listener. No-op (returns
// nil) when the platform media config or the scoped key is absent — i.e. off
// the platform host, where CDNStorage falls back to direct signing. Called
// once from router boot; the listener runs for the process lifetime.
func StartPresignBroker(sockPath string) error {
	cfg := getPlatformMedia()
	if cfg == nil || cfg.S3Key == "" {
		return nil // broker disabled: no media CDN, or no scoped key in this process
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
			go handlePresignConn(uconn, cfg)
		}
	}()
	return nil
}

// brokerSocketReachable reports whether the presign broker socket exists. The
// per-app upload path uses this to decide between broker and direct signing.
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

	// Derive the caller's allowed prefix from its uid. A per-tenant uid is
	// named benmore-app-<sub>; its key namespace is exactly <sub>. The shared
	// first-party user (router / _platform, "benmore") is trusted to name its
	// own prefix. Anything else is rejected.
	allowedPrefix, firstParty := prefixForUID(uid)
	prefix := req.Prefix
	if !firstParty {
		if allowedPrefix == "" {
			writePresignErr(conn, "unmapped caller")
			return
		}
		// Tenant process: ignore the client-supplied prefix entirely and use
		// the uid-derived one, so a compromised app cannot target another's.
		prefix = allowedPrefix
	}
	if prefix == "" {
		writePresignErr(conn, "no prefix")
		return
	}

	logical := strings.TrimPrefix(req.Path, "/")
	if logical == "" || strings.Contains(logical, "..") {
		writePresignErr(conn, "bad path")
		return
	}
	vis := "public"
	if isPrivateUploadPath(logical) {
		vis = "private"
	}
	key := vis + "/" + prefix + "/" + logical

	// Cache-Control, decided server-side by tier (not by the client):
	//   public  → immutable, cache forever. Object names are content hashes,
	//             so the URL never changes meaning. Without this, public media
	//             ships with no Cache-Control → browsers revalidate every
	//             navigation and CloudFront cold-fetches from S3 (~0.5–1s
	//             "random slow image" spikes).
	//   private → no-store. Never cache a signed/private object — caching it
	//             by path could let an UNSIGNED request be served the cached
	//             copy and bypass the signature. (Tightens private, never loosens.)
	cacheControl := "public, max-age=31536000, immutable"
	if vis == "private" {
		cacheControl = "no-store"
	}

	s3 := &S3Storage{Bucket: cfg.Bucket, Region: cfg.Region, Key: cfg.S3Key, Secret: cfg.S3Secret}
	url, headers, err := presignS3PutURL(s3, key, req.ContentType, req.Disposition, cacheControl, 90*time.Second)
	if err != nil {
		writePresignErr(conn, "presign failed")
		return
	}
	resp := presignResp{URL: url, Headers: headers, Key: key}
	b, _ := json.Marshal(resp)
	conn.Write(b)
}

func writePresignErr(conn *net.UnixConn, msg string) {
	b, _ := json.Marshal(presignResp{Error: msg})
	conn.Write(b)
}

// prefixForUID maps a connecting uid to its app key prefix. Returns
// (prefix, firstParty). firstParty=true for the shared "benmore" user (the
// router and the _platform app), which is trusted to supply its own prefix.
func prefixForUID(uid int) (prefix string, firstParty bool) {
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return "", false
	}
	if u.Username == "benmore" {
		return "", true
	}
	if sub := strings.TrimPrefix(u.Username, "benmore-app-"); sub != u.Username && sub != "" {
		return sub, false
	}
	return "", false
}

// ─── Per-app client ─────────────────────────────────────────────────────────

// requestPresignedPut dials the broker socket and returns the presigned URL +
// the headers the caller must send verbatim on the PUT.
func requestPresignedPut(sockPath string, req presignReq) (*presignResp, error) {
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
	if resp.Error != "" {
		return nil, fmt.Errorf("presign broker: %s", resp.Error)
	}
	if resp.URL == "" {
		return nil, fmt.Errorf("presign broker: empty url")
	}
	return &resp, nil
}

// ─── SigV4 query-string presign (PUT, single object) ─────────────────────────

// presignS3PutURL builds a SigV4 query-string presigned PUT URL valid for
// `expires`. It signs host + content-type (+ content-disposition when set) so
// the stored object's type/disposition are pinned to what the broker
// authorized; the payload is UNSIGNED-PAYLOAD (the bytes are not hashed into
// the signature — object size is enforced upstream by the upload handler).
// The caller MUST PUT with exactly the returned headers. AWS-native only.
func presignS3PutURL(s3 *S3Storage, key, contentType, disposition, cacheControl string, expires time.Duration) (string, map[string]string, error) {
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
	body, err := io.ReadAll(data)
	if err != nil {
		return "", err
	}
	resp, err := requestPresignedPut(sockPath, presignReq{
		Prefix:      c.Prefix,
		Path:        strings.TrimPrefix(path, "/"),
		ContentType: contentType,
		Disposition: disposition,
	})
	if err != nil {
		return "", fmt.Errorf("save upload: %w", err)
	}
	req, err := http.NewRequest("PUT", resp.URL, strings.NewReader(string(body)))
	if err != nil {
		return "", err
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
