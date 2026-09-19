//go:build !cli

package main

// Short-lived HMAC-signed tokens binding (user_email, scope) so signed
// upload URLs can be handed to anonymous clients while still pinning the
// upload to the originator's identity.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

const signedTokenTTL = 24 * time.Hour

func signToken(userEmail, scope string) string {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	payload := userEmail + "|" + scope + "|" + ts
	mac := hmac.New(sha256.New, []byte(serverSecret))
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))
	return base64.RawURLEncoding.EncodeToString([]byte(payload + "|" + sig))
}

func verifyToken(token string) (userEmail, scope string, ok bool) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return
	}
	parts := strings.SplitN(string(raw), "|", 4)
	if len(parts) != 4 {
		return
	}
	userEmail = parts[0]
	scope = parts[1]
	tsStr := parts[2]
	providedSig := parts[3]

	payload := userEmail + "|" + scope + "|" + tsStr
	mac := hmac.New(sha256.New, []byte(serverSecret))
	mac.Write([]byte(payload))
	expectedSig := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(providedSig), []byte(expectedSig)) {
		userEmail, scope = "", ""
		return
	}

	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil || time.Now().Unix()-ts > int64(signedTokenTTL/time.Second) {
		userEmail, scope = "", ""
		return
	}

	ok = true
	return
}
