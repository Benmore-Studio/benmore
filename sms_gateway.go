//go:build !cli

package main

// Platform SMS gateway - CLIENT side (runs inside per-app processes).
// The SMS twin of email_gateway.go: tenant processes never hold the AWS
// End User Messaging credential; sends dial a router-owned unix socket,
// the router authenticates by peer-uid and enforces destination policy,
// quotas, velocity, and the global send rate before calling AWS.
//
// On self-hosted / framework builds the socket doesn't exist and sms.go
// behaves exactly as before (Twilio / webhook / loud no-provider error).

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

func smsGatewaySocketPath() string {
	if p := strings.TrimSpace(os.Getenv("BENMORE_SMS_SOCKET")); p != "" {
		return p
	}
	return "/run/benmore/sms.sock"
}

// smsGatewayReq is the per-app → router send request. The broker derives
// the app from peer-uid; App is honored only for first-party callers.
type smsGatewayReq struct {
	To   string `json:"to"`   // E.164
	Body string `json:"body"` // message text
	App  string `json:"app,omitempty"`
}

type smsGatewayResp struct {
	MessageID string `json:"message_id,omitempty"`
	From      string `json:"from,omitempty"` // origination number used
	Error     string `json:"error,omitempty"`
}

func smsGatewayReachable() bool {
	_, err := os.Stat(smsGatewaySocketPath())
	return err == nil
}

func requestGatewaySMSSend(req smsGatewayReq) (*smsGatewayResp, error) {
	conn, err := net.DialTimeout("unix", smsGatewaySocketPath(), 3*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	b, _ := json.Marshal(req)
	if _, err := conn.Write(b); err != nil {
		return nil, err
	}
	if uc, ok := conn.(*net.UnixConn); ok {
		uc.CloseWrite()
	}
	var resp smsGatewayResp
	if err := json.NewDecoder(io.LimitReader(conn, 64<<10)).Decode(&resp); err != nil {
		return nil, err
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("platform sms: %s", resp.Error)
	}
	return &resp, nil
}
