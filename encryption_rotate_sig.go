//go:build !cli

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"time"
)

// A hosted app's ENCRYPTION_KEY lives in the platform's environment vault,
// and the unit's materialized env file (loaded after env.yaml) overrides the
// env.yaml copy RotateEncryptionKey writes. A rotation the router did not run
// therefore reverted to the OLD key at the next restart and every rotated
// value failed to decrypt. In a hosted tenant only the router's owner-only
// rotate_encryption_key may rotate: it chooses the key, signs the request with
// the app's own server secret and saves the key to the vault on success.
const (
	rotateSigHeader     = "X-Benmore-Rotate-Sig"
	rotateSigTimeHeader = "X-Benmore-Rotate-Time"
)

// rotateSigMAC binds the signature to the new key (by hash) and the time.
func rotateSigMAC(secret, ts, newKey string) string {
	sum := sha256.Sum256([]byte(newKey))
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("benmore-encryption-rotate\n" + ts + "\n" + hex.EncodeToString(sum[:])))
	return hex.EncodeToString(mac.Sum(nil))
}

// signRotateHeaders adds the router's rotation signature for newKey.
func signRotateHeaders(h map[string]string, secret, newKey string) bool {
	if len(secret) < routerSigMinSecret || newKey == "" {
		return false
	}
	ts := strconv.FormatInt(routerSigNow().Unix(), 10)
	h[rotateSigTimeHeader] = ts
	h[rotateSigHeader] = rotateSigMAC(secret, ts, newKey)
	return true
}

// rotateSigValid checks the signature against this process's server secret.
func rotateSigValid(r *http.Request, newKey string) bool {
	if len(serverSecret) < routerSigMinSecret || newKey == "" {
		return false
	}
	ts := r.Header.Get(rotateSigTimeHeader)
	sig := r.Header.Get(rotateSigHeader)
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || sig == "" {
		return false
	}
	if skew := routerSigNow().Sub(time.Unix(sec, 0)); skew < -routerSigWindow || skew > routerSigWindow {
		return false
	}
	return hmac.Equal([]byte(rotateSigMAC(serverSecret, ts, newKey)), []byte(sig))
}
