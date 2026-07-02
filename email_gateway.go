//go:build !cli

package main

// Platform email gateway - CLIENT side (runs inside per-app processes).
//
// WHY. Tenant processes must never hold SES credentials: any flow could
// then send arbitrary mail as anyone, and SES reputation is ACCOUNT-wide
// (one abusive tenant poisons deliverability for every app). So per-app
// processes send platform email the same way they presign uploads
// (presign_broker.go): dial a router-owned unix socket; the router
// authenticates the caller by peer-uid, enforces from-address
// authorization + per-app quotas + suppression, and makes the actual
// SESv2 call with the one fleet credential.
//
// This file is the tenant/framework side only: the socket path, the wire
// types, and the dialing client. The server lives in email_broker.go
// (platform build). On self-hosted / framework builds the socket simply
// doesn't exist, so the gateway is skipped and email.go behaves exactly
// as before.

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

// emailGatewaySocketPath returns the unix socket the router listens on
// and per-app processes dial. Overridable for tests / alternate layouts.
func emailGatewaySocketPath() string {
	if p := strings.TrimSpace(os.Getenv("BENMORE_EMAIL_SOCKET")); p != "" {
		return p
	}
	return "/run/benmore/email.sock"
}

// emailGatewayReq is the per-app → router send request. From may be
// empty: the broker fills the app's default address on the platform
// shared domain (<sub>@<mail domain>) with the app's display name.
// The broker IGNORES any claimed app identity - the app is derived from
// the connection's peer uid, exactly like the presign broker.
type emailGatewayReq struct {
	From           string   `json:"from,omitempty"`
	To             []string `json:"to"`
	ReplyTo        string   `json:"reply_to,omitempty"`
	Subject        string   `json:"subject"`
	HTML           string   `json:"html,omitempty"`
	Text           string   `json:"text,omitempty"`
	UnsubscribeURL string   `json:"unsubscribe_url,omitempty"`
	// App is honored ONLY for first-party (router/_platform) callers,
	// which are trusted to name the app they send on behalf of.
	App string `json:"app,omitempty"`
}

// emailGatewayResp is the router → per-app reply.
type emailGatewayResp struct {
	MessageID string `json:"message_id,omitempty"`
	From      string `json:"from,omitempty"` // the resolved from-address actually used
	Error     string `json:"error,omitempty"`
}

// emailGatewayReachable reports whether the broker socket exists - the
// cheap feature-detect email.go uses before attempting the gateway.
func emailGatewayReachable() bool {
	_, err := os.Stat(emailGatewaySocketPath())
	return err == nil
}

// requestGatewayEmailSend dials the broker and performs one send.
// Errors are returned verbatim - the broker writes precise, actionable
// messages (unauthorized from-domain, quota exceeded, suppressed
// recipient, paused app) that must reach the hook/flow audit log intact.
func requestGatewayEmailSend(req emailGatewayReq) (*emailGatewayResp, error) {
	conn, err := net.DialTimeout("unix", emailGatewaySocketPath(), 3*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	// Sending an email (SES round-trip) can take a couple of seconds;
	// leave headroom beyond the presign broker's 5s.
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	b, _ := json.Marshal(req)
	if _, err := conn.Write(b); err != nil {
		return nil, err
	}
	if uc, ok := conn.(*net.UnixConn); ok {
		uc.CloseWrite() // signal EOF so the broker's decoder returns
	}
	var resp emailGatewayResp
	if err := json.NewDecoder(io.LimitReader(conn, 64<<10)).Decode(&resp); err != nil {
		return nil, err
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("platform email: %s", resp.Error)
	}
	return &resp, nil
}
