//go:build !linux && !darwin

package main

import "os"

// No portable ctime: callers hash the content instead.
func fileStampSys(os.FileInfo) (ctime int64, ino, dev uint64, ok bool) {
	return 0, 0, 0, false
}
