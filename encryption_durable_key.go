//go:build !cli

package main

// Durable keys for framework secrets.
//
// Some values the framework seals are read back by the app itself long after
// they were written: a webhook subscription's signing secret (every delivery
// signs with it) and a user's OAuth provider tokens (flows call the provider
// with them). They must open after the process restarts. An app with no
// configured ENCRYPTION_KEY runs on a key generated for the process alone
// (initFieldEncryption), and a value sealed under it is lost at the next
// restart, deploy or platform release: every subscription delivery then failed
// with "webhook secret decryption failed" and nothing else said so.
//
// durableSealKey therefore never returns a per-process key. The first time
// such a value is sealed it saves the generated key to the app's env.yaml (the
// same file and line the first start of an app with encrypted fields writes),
// reads the app's environment back the way the next load will, and continues
// only when that yields the same key. Afterwards the key is durable for every
// sealer (TOTP secrets, job rows) as if it had been configured. Hosted, the
// key in env.yaml is the instance key the router already honours: refresh
// copies it, rotation replaces it, and the restart that enables encrypted
// fields or MCP commands pins it in the instance vault.
//
// When the key cannot be saved (env.yaml is not a regular file or cannot be
// written, or the environment the next load reads resolves a different or
// empty ENCRYPTION_KEY) nothing is sealed and the caller refuses with
// errNoDurableEncryptionKey. Storing the value in plaintext instead, as TOTP
// secrets do without a durable key, would leave signing secrets and provider
// tokens readable in every backup and SQL console; sealing under the
// per-process key would lose them silently.

import (
	"crypto/hmac"
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"sync"
)

// errNoDurableEncryptionKey is returned, wrapped with the reason, when a
// framework secret cannot be sealed under a key that outlives the process.
var errNoDurableEncryptionKey = errors.New("this app has no durable ENCRYPTION_KEY to seal the secret under: set ENCRYPTION_KEY (`openssl rand -hex 32`) in env.yaml or the app's environment and restart, then try again")

// durableKeyMu serializes saving a generated key, so two first seals in one
// process write env.yaml once.
var durableKeyMu sync.Mutex

// durableSealKey returns the key a framework secret that must survive a
// restart is sealed under for db, making a generated per-process key durable
// first (see the file comment). It never returns an ephemeral key.
func durableSealKey(db mutationQuerier) ([]byte, error) {
	path, err := mainDatabasePathForQuerier(db)
	var keys *dbCryptoKeys
	if err == nil {
		keys = cryptoKeysForDBPath(path)
	}
	if keys == nil {
		// Unregistered database: only a dedicated process's own configured
		// key may be used, never another tenant's or a generated one.
		switch {
		case isolateAppEnvironment.Load():
			return nil, fmt.Errorf("database encryption key is not registered")
		case len(appEncryptionKey) == 0:
			return nil, fmt.Errorf("field encryption requested but no encryption key is initialized (ENCRYPTION_KEY missing)")
		case appEncryptionKeyEphemeral:
			return nil, errNoDurableEncryptionKey
		}
		return appEncryptionKey, nil
	}
	if len(keys.aes) == 0 {
		return nil, fmt.Errorf("database encryption key is not registered")
	}
	if !keys.ephemeral {
		return keys.aes, nil
	}
	return persistGeneratedEncryptionKey(path)
}

// persistGeneratedEncryptionKey saves the generated key registered for the
// database at path to its app's env.yaml and marks it durable.
func persistGeneratedEncryptionKey(path string) ([]byte, error) {
	durableKeyMu.Lock()
	defer durableKeyMu.Unlock()
	keys := cryptoKeysForDBPath(path)
	if keys == nil || len(keys.aes) == 0 {
		return nil, fmt.Errorf("database encryption key is not registered")
	}
	if !keys.ephemeral {
		return keys.aes, nil // saved by a concurrent first seal
	}
	// The key belongs to an app's data.db; its env.yaml sits beside it.
	if keys.source == "" || filepath.Base(path) != "data.db" {
		return nil, errNoDurableEncryptionKey
	}
	dir := filepath.Dir(path)
	if err := appendToEnvYaml(dir, "ENCRYPTION_KEY", keys.source); err != nil {
		log.Printf("encryption: could not save the generated ENCRYPTION_KEY to env.yaml: %v", err)
		return nil, fmt.Errorf("%w (saving the generated key to env.yaml failed)", errNoDurableEncryptionKey)
	}
	// The next load reads env.yaml under the materialized environment, the
	// process environment and the vault: only a key it resolves is durable.
	vars, err := readAppEnv(dir)
	if err != nil {
		log.Printf("encryption: could not read the app environment back after saving ENCRYPTION_KEY: %v", err)
		return nil, fmt.Errorf("%w (the app environment could not be read back)", errNoDurableEncryptionKey)
	}
	if !hmac.Equal([]byte(vars["ENCRYPTION_KEY"]), []byte(keys.source)) {
		log.Printf("encryption: env.yaml was given this process's generated ENCRYPTION_KEY, but the environment the next start reads resolves a different or empty ENCRYPTION_KEY (env.yaml already names one, or the process environment or materialized environment sets it); nothing was sealed. Set ENCRYPTION_KEY once and restart.")
		return nil, fmt.Errorf("%w (the environment the next start reads sets a different ENCRYPTION_KEY)", errNoDurableEncryptionKey)
	}
	registerDBEncryptionKey(path, keys.aes, false)
	log.Printf("encryption: saved this process's generated ENCRYPTION_KEY to %s so sealed framework secrets (webhook subscription secrets, OAuth tokens, TOTP secrets) survive restarts. Keep env.yaml with the app's data; changing the key later needs the key-rotation workflow.", filepath.Join(dir, "env.yaml"))
	return keys.aes, nil
}
