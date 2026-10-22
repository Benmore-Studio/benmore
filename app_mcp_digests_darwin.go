//go:build !cli

package main

import (
	"io/fs"
	"syscall"
)

func appMCPDigestFileStamp(info fs.FileInfo) (appMCPDigestStamp, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return appMCPDigestStamp{}, false
	}
	return appMCPDigestStamp{mtimeNS: stat.Mtimespec.Nano(), ctimeNS: stat.Ctimespec.Nano(), inode: uint64(stat.Ino), device: uint64(stat.Dev)}, true
}
