package main

import (
	"bytes"
	"testing"
)

// TestSignedURLKeyNotCachedBeforeSecret covers round-2 (signed-URL ephemeral
// key): when serverSecret is empty, csrfKeyBytes must NOT cache the ephemeral
// key, so once serverSecret is set the REAL key is derived (the old sync.Once
// permanently locked in the ephemeral key, breaking validation across restart).
func TestSignedURLKeyNotCachedBeforeSecret(t *testing.T) {
	savedSecret, savedKey := serverSecret, signedURLKey
	defer func() { serverSecret, signedURLKey = savedSecret, savedKey }()

	serverSecret, signedURLKey = "", nil
	eph1 := csrfKeyBytes()
	if signedURLKey != nil {
		t.Fatal("ephemeral key was cached while serverSecret empty (would lock in a non-secret key)")
	}
	eph2 := csrfKeyBytes()
	if bytes.Equal(eph1, eph2) {
		t.Fatal("pre-init returned a stable (cached) key; expected fresh ephemeral each call")
	}
	// Once the secret is set, the real key derives and is stable + cached.
	serverSecret = "test-server-secret-value-1234567890"
	real1 := csrfKeyBytes()
	real2 := csrfKeyBytes()
	if !bytes.Equal(real1, real2) || signedURLKey == nil {
		t.Fatal("post-init key is not stable/cached")
	}
	if bytes.Equal(real1, eph1) {
		t.Fatal("post-init key equals the pre-init ephemeral key (not re-derived)")
	}
}
