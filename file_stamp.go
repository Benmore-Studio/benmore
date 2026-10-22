package main

import (
	"os"
	"time"
)

// fileStamp identifies a file's content without reading it: size, mtime,
// inode change time (ctime) and inode identity. A program cannot set ctime,
// so an edit that restores the mtime still changes the stamp. Stamps are
// trusted only when the file had been stable for fileStampSettle before it
// was stamped: file timestamps come from a coarse clock, so a write landing
// in the same tick as the stat could otherwise leave the stamp unchanged.
type fileStamp struct {
	size    int64
	mtime   int64
	ctime   int64
	ino     uint64
	dev     uint64
	stamped time.Time
}

const fileStampSettle = time.Second

// statFileStamp returns path's stamp, or ok=false where the platform gives
// no ctime (callers then fall back to hashing the content).
func statFileStamp(path string) (fileStamp, bool) {
	now := time.Now()
	info, err := os.Stat(path)
	if err != nil {
		return fileStamp{}, false
	}
	ctime, ino, dev, ok := fileStampSys(info)
	if !ok {
		return fileStamp{}, false
	}
	return fileStamp{size: info.Size(), mtime: info.ModTime().UnixNano(), ctime: ctime, ino: ino, dev: dev, stamped: now}, true
}

// trusted reports whether the stamp can stand in for a content check.
func (s fileStamp) trusted() bool {
	return !s.stamped.IsZero() && s.stamped.Sub(time.Unix(0, s.ctime)) >= fileStampSettle && s.stamped.Sub(time.Unix(0, s.mtime)) >= fileStampSettle
}

// sameFile reports whether current describes the same, unchanged file.
func (s fileStamp) sameFile(current fileStamp) bool {
	return s.size == current.size && s.mtime == current.mtime && s.ctime == current.ctime && s.ino == current.ino && s.dev == current.dev
}
