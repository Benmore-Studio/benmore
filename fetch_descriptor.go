//go:build !cli

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// Async fetches carry an encrypted server-authored descriptor, never secrets
// or caller-editable URLs/headers. AEAD binds it to its app; audience and expiry
// bind the page render to the same current session and permissions.
type fetchDescriptor struct {
	URL, Headers, As, Inner, Cache, Audience string
	Expires                                  int64
}

const fetchDescriptorTTL = 10 * time.Minute

func fetchAppIdentity(app *App) string {
	dir, _ := filepath.Abs(app.Dir)
	return filepath.Clean(dir)
}

func sessionSecurityFingerprint(session *Session) string {
	if session == nil {
		return "anonymous"
	}
	copy := *session
	copy.Roles = slices.Clone(session.Roles)
	copy.Permissions = slices.Clone(session.Permissions)
	slices.Sort(copy.Roles)
	slices.Sort(copy.Permissions)
	b, _ := json.Marshal(copy)
	return fmt.Sprintf("%x", sha256.Sum256(b))
}

func fetchDescriptorCipher() (cipher.AEAD, error) {
	if serverSecret == "" {
		return nil, fmt.Errorf("server secret unavailable")
	}
	mac := hmac.New(sha256.New, []byte(serverSecret))
	mac.Write([]byte("async-fetch-descriptor-v1"))
	block, err := aes.NewCipher(mac.Sum(nil))
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func sealFetchDescriptor(app *App, desc fetchDescriptor) (string, error) {
	aead, err := fetchDescriptorCipher()
	if err != nil {
		return "", err
	}
	plain, err := json.Marshal(desc)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := aead.Seal(nonce, nonce, plain, []byte(fetchAppIdentity(app)))
	token := base64.RawURLEncoding.EncodeToString(sealed)
	if len(token) > 64<<10 {
		return "", fmt.Errorf("fetch template is too large")
	}
	return token, nil
}

func openFetchDescriptor(app *App, token string, session *Session) (*fetchDescriptor, error) {
	if len(token) > 64<<10 {
		return nil, fmt.Errorf("fetch descriptor too large")
	}
	b, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return nil, fmt.Errorf("invalid fetch descriptor")
	}
	aead, err := fetchDescriptorCipher()
	if err != nil || len(b) < aead.NonceSize() {
		return nil, fmt.Errorf("invalid fetch descriptor")
	}
	plain, err := aead.Open(nil, b[:aead.NonceSize()], b[aead.NonceSize():], []byte(fetchAppIdentity(app)))
	if err != nil {
		return nil, fmt.Errorf("invalid fetch descriptor")
	}
	var desc fetchDescriptor
	if json.Unmarshal(plain, &desc) != nil || desc.Expires <= time.Now().Unix() ||
		!hmac.Equal([]byte(desc.Audience), []byte(sessionSecurityFingerprint(session))) {
		return nil, fmt.Errorf("fetch descriptor expired or belongs to another session")
	}
	return &desc, nil
}

func resolveFetchURL(app *App, raw string) (string, bool, error) {
	origin := uploadsCanonicalOrigin(app)
	if strings.HasPrefix(raw, "/") {
		if origin == "" {
			return "", false, fmt.Errorf("relative fetch URLs require BENMORE_PUBLIC_URL")
		}
		raw = origin + raw
	}
	u, err := url.Parse(raw)
	if err != nil || isPrivateURL(raw) {
		return "", false, fmt.Errorf("private/internal fetch URL blocked")
	}
	co, _ := url.Parse(origin)
	local := co != nil && co.Host != "" && strings.EqualFold(u.Host, co.Host) && strings.EqualFold(u.Scheme, co.Scheme)
	return raw, local, nil
}

func fetchCacheKey(app *App, rawURL string) string {
	b, _ := json.Marshal([]string{fetchAppIdentity(app), rawURL})
	return fmt.Sprintf("%x", sha256.Sum256(b))
}

func cacheableFetchResponse(resp *http.Response) bool {
	cc := strings.ToLower(resp.Header.Get("Cache-Control"))
	return !strings.Contains(cc, "private") && !strings.Contains(cc, "no-store") &&
		len(resp.Header.Values("Set-Cookie")) == 0 && resp.Header.Get("Vary") == ""
}

func fetchHTTPClient(timeout time.Duration) *http.Client {
	client := safeHTTPClientStrict(timeout)
	check := client.CheckRedirect
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		// Custom credential headers are not stripped by net/http on redirects.
		// Keep fetches on the original origin, including its scheme and port.
		if len(via) > 0 && (req.URL.Scheme != via[0].URL.Scheme || req.URL.Host != via[0].URL.Host) {
			return fmt.Errorf("cross-origin fetch redirect blocked")
		}
		return check(req, via)
	}
	return client
}

func setFetchHeaders(req *http.Request, headers string) {
	for _, h := range strings.Split(headers, ",") {
		parts := strings.SplitN(strings.TrimSpace(h), ":", 2)
		if len(parts) == 2 {
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}
}
