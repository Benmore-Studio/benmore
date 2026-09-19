//go:build linux

package main

import (
	"fmt"
	"net"
	"syscall"
)

// peerUID returns the uid of the process on the other end of a unix-socket
// connection via SO_PEERCRED. This is the broker's authentication primitive:
// the kernel vouches for the caller's identity, so no shared secret is needed.
func peerUID(conn *net.UnixConn) (int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var ucred *syscall.Ucred
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		ucred, sockErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if sockErr != nil {
		return 0, sockErr
	}
	if ucred == nil {
		return 0, fmt.Errorf("no peer credentials")
	}
	return int(ucred.Uid), nil
}
