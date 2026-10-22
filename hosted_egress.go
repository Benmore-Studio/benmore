//go:build !cli

package main

// Egress guards for tenant-configured endpoints on the hosted platform.
//
// A few integrations take their network destination from the app's own
// environment rather than from a URL that passes the SSRF guard: a BYO S3
// endpoint (S3_ENDPOINT) and SMTP (SMTP_HOST). Off-platform those may
// legitimately be on a private network (MinIO on the LAN). In a hosted
// tenant process a private or loopback destination can only be the host's
// own services - other tenants' app ports among them - so there the
// endpoint must resolve publicly, checked at connect time.

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"syscall"
	"time"
)

// hostedTenantProcess reports whether this process is an app instance on
// the hosted platform. The per-app units set BENMORE_BIND_LOOPBACK=1, and an
// app cannot override it (tenantReservedEnvKey).
func hostedTenantProcess() bool {
	return os.Getenv("BENMORE_BIND_LOOPBACK") == "1"
}

// publicOnlyDialer refuses private, loopback and reserved addresses at
// connect time, after DNS resolution.
var publicOnlyDialer = &net.Dialer{
	Timeout: 10 * time.Second,
	Control: func(network, address string, c syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("dial: bad address %q", address)
		}
		ip := net.ParseIP(host)
		if ip == nil || blockedOutboundIP(ip) {
			return fmt.Errorf("dial to private/reserved address blocked: %s", host)
		}
		return nil
	},
}

// s3HTTPClient is the HTTP client for S3-compatible storage requests. In a
// hosted tenant process it dials only public addresses.
func s3HTTPClient(timeout time.Duration) *http.Client {
	if !hostedTenantProcess() {
		return &http.Client{Timeout: timeout}
	}
	return &http.Client{Timeout: timeout, Transport: &http.Transport{
		DialContext:           publicOnlyDialer.DialContext,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
	}}
}
