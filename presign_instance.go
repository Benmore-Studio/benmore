//go:build !cli

package main

// Instance proof for the presign broker.
//
// The broker knows a caller by its socket peer uid, and an app's dev and
// prod instances run as the same per-app user (benmore-dev@.service), so the
// uid alone cannot keep a dev instance off production's media. Each instance
// has its own server secret, though, which the router writes into that
// instance's directory and hands to that instance alone (the same secret the
// router signs X-Benmore-Router-Sig with, router_sig.go). The other instance
// cannot read it: the instance directories are masked from each other by the
// units' mount namespaces and the processes are non-dumpable, so neither
// /proc/<pid>/environ nor /proc/<pid>/root reaches it.
//
// So every broker request carries the instance subdomain, a timestamp and an
// HMAC under that instance's secret over the request's effect (operation,
// object key, lifetime). The router reads the claimed instance's secret,
// which must be the uid's app (<sub>) or its dev instance (<sub>-dev), and
// scopes the request:
//
//   - prod (<sub>): writes, deletes and signs under <sub>;
//   - dev (<sub>-dev): writes and deletes under <sub>-dev only, and signs
//     under <sub>-dev or <sub> (read only: the production references
//     refresh-dev --with-data copies into dev, and dev's own uploads from
//     before the split, stay servable).
//
// A request with a proof that does not verify (wrong secret, another key or
// operation, outside the time window, an instance of another app) is
// refused, never downgraded. A request with no proof at all comes from a
// binary older than this one and keeps the old scope (everything under
// <sub>), and so does one whose instance has no secret the router can read;
// both are refused once the operator sets
// BENMORE_PLATFORM_MEDIA_REQUIRE_INSTANCE=1 in the router's platform.env,
// after every instance runs a binary that sends proofs.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// presignInstanceSecret returns an app instance's own server secret ("" when
// it cannot be read). The router sets it (Router.appRouterSecret); in any
// other process it stays nil and no instance proof verifies.
var presignInstanceSecret func(instance string) string

// presignInstanceWindow is how far a proof's timestamp may be from the
// router's clock (both run on the same host).
const presignInstanceWindow = 30 * time.Second

// presignRequireInstanceEnv is the router's switch that refuses requests
// without an instance proof. BENMORE_PLATFORM_* keys are platform-reserved,
// so no app can set it in its own environment.
const presignRequireInstanceEnv = "BENMORE_PLATFORM_MEDIA_REQUIRE_INSTANCE"

func presignRequireInstance() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(presignRequireInstanceEnv))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// presignScope is what one authenticated request may touch: write is the
// prefix puts and deletes land under, read the prefixes sign accepts.
type presignScope struct {
	write string
	read  []string
	// firstParty: the router's own user asked. Its uploads are counted
	// against the prefix it names and never refused for an allowance.
	firstParty bool
}

// presignOperation is the request's operation as the broker executes it.
func presignOperation(req presignReq) string {
	op := strings.ToLower(strings.TrimSpace(req.Operation))
	if op == "" {
		return "put"
	}
	return op
}

// presignInstanceMAC binds a proof to the instance, the time and what the
// request does. The key is domain-separated so the MAC is never valid for
// another use of the server secret (CSRF, router signatures, handoffs).
func presignInstanceMAC(secret string, req presignReq) string {
	km := hmac.New(sha256.New, []byte(secret))
	km.Write([]byte("benmore-presign-instance-v1-key"))
	m := hmac.New(sha256.New, km.Sum(nil))
	for _, part := range []string{
		strconv.FormatInt(req.Time, 10), req.Instance, presignOperation(req), req.Path,
		strconv.FormatInt(req.ExpiresIn, 10),
	} {
		// Length-prefix each field so none can borrow bytes from the next.
		m.Write([]byte(strconv.Itoa(len(part)) + ":" + part + "\n"))
	}
	return hex.EncodeToString(m.Sum(nil))
}

// attachPresignInstanceProof signs req as instance with this process's own
// server secret. A process without a stable secret (or an unknown instance)
// sends no proof and gets the legacy scope, or a refusal once the router
// requires proofs.
func attachPresignInstanceProof(req *presignReq, instance string, now time.Time) {
	req.Instance, req.Time, req.Proof = "", 0, ""
	if instance == "" || len(serverSecret) < routerSigMinSecret {
		return
	}
	req.Instance = instance
	req.Time = now.Unix()
	req.Proof = presignInstanceMAC(serverSecret, *req)
}

// presignCallerScope decides what a request may touch. A first-party caller
// (the router's own user) names its prefix. A tenant is confined to its
// uid's app (allowedPrefix) and, within it, to the instance its proof
// verifies for.
func presignCallerScope(req presignReq, allowedPrefix string, firstParty bool, now time.Time) (presignScope, error) {
	if firstParty {
		if req.Prefix == "" {
			return presignScope{}, fmt.Errorf("no prefix")
		}
		return presignScope{write: req.Prefix, read: []string{req.Prefix}, firstParty: true}, nil
	}
	if allowedPrefix == "" {
		return presignScope{}, fmt.Errorf("unmapped caller")
	}
	// legacy is the scope of a request the router cannot place in an
	// instance: the whole uid's app, as before instance proofs existed,
	// until the operator requires proofs. It grants nothing a caller could
	// not get by sending no proof at all.
	legacy := func(reason string) (presignScope, error) {
		if presignRequireInstance() {
			return presignScope{}, fmt.Errorf("%s", reason)
		}
		return presignScope{write: allowedPrefix, read: []string{allowedPrefix}}, nil
	}
	if req.Instance == "" && req.Proof == "" {
		return legacy("instance proof required")
	}
	devInstance := allowedPrefix + devSubdomainSuffix
	if req.Instance != allowedPrefix && req.Instance != devInstance {
		return presignScope{}, fmt.Errorf("instance outside caller's app")
	}
	if skew := now.Sub(time.Unix(req.Time, 0)); req.Time <= 0 || skew > presignInstanceWindow || skew < -presignInstanceWindow {
		return presignScope{}, fmt.Errorf("instance proof expired")
	}
	instanceKey := ""
	if presignInstanceSecret != nil {
		instanceKey = presignInstanceSecret(req.Instance)
	}
	if len(instanceKey) < routerSigMinSecret {
		// The router has no secret for the instance (none provisioned, or
		// unreadable): it can neither confirm nor refute the proof.
		return legacy("instance proof unverifiable")
	}
	if !hmac.Equal([]byte(presignInstanceMAC(instanceKey, req)), []byte(req.Proof)) {
		return presignScope{}, fmt.Errorf("instance proof invalid")
	}
	if req.Instance == devInstance {
		return presignScope{write: devInstance, read: []string{devInstance, allowedPrefix}}, nil
	}
	return presignScope{write: allowedPrefix, read: []string{allowedPrefix}}, nil
}
