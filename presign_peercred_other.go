//go:build !linux

package main

import (
	"fmt"
	"net"
)

// peerUID is Linux-only (SO_PEERCRED). The presign broker only runs on the
// Linux platform host; on other platforms (the dev/darwin build) it's never
// started, so this stub just reports unsupported.
func peerUID(conn *net.UnixConn) (int, error) {
	return 0, fmt.Errorf("peer credentials unsupported on this platform")
}
