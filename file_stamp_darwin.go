//go:build darwin

package main

import (
	"os"
	"syscall"
)

func fileStampSys(info os.FileInfo) (ctime int64, ino, dev uint64, ok bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, 0, false
	}
	return int64(st.Ctimespec.Sec)*1e9 + int64(st.Ctimespec.Nsec), uint64(st.Ino), uint64(st.Dev), true
}
