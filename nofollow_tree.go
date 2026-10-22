package main

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"syscall"
)

// treeDir is one directory of a tree that somebody else may be rewriting
// while it is read or written: an app directory, which its tenant process
// owns, read by the router, which can open every app's files.
//
// A path walked by name is only as good as the last lstat: between the check
// and the open the tenant can swap a file or a parent directory for a symlink
// into another app, and the router would follow it. Here every level is held
// by handle (an os.Root on that directory, so nothing resolves outside it),
// children are named by a single component, and whatever was opened is
// compared with what lstat saw. os.Root alone is not enough: it follows a
// link that stays inside the root, ignoring O_NOFOLLOW.
type treeDir struct{ root *os.Root }

var (
	// errTreeNotRegular: the name is not (or no longer) a regular file.
	errTreeNotRegular = errors.New("not a regular file")
	// errTreeNotDir: the name is not (or no longer) a directory.
	errTreeNotDir = errors.New("not a directory")
	// errTreeChanged: the name kept changing between lstat and open.
	errTreeChanged = errors.New("changed while it was being read")
)

func openTreeDir(path string) (*treeDir, error) {
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	return &treeDir{root: root}, nil
}

func (d *treeDir) Close() error { return d.root.Close() }

// names lists the directory's entries, sorted.
func (d *treeDir) names() ([]string, error) {
	f, err := d.root.Open(".")
	if err != nil {
		return nil, err
	}
	names, err := f.Readdirnames(-1)
	f.Close()
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	return names, nil
}

func (d *treeDir) lstat(name string) (os.FileInfo, error) { return d.root.Lstat(name) }

// openDir opens the child directory name: a real directory entry of this
// one, never the target of a link.
func (d *treeDir) openDir(name string) (*treeDir, error) {
	for attempt := 0; attempt < 3; attempt++ {
		seen, err := d.root.Lstat(name)
		if err != nil {
			return nil, err
		}
		if !seen.IsDir() {
			return nil, fmt.Errorf("%s: %w", name, errTreeNotDir)
		}
		sub, err := d.root.OpenRoot(name)
		if err != nil {
			return nil, err
		}
		opened, err := sub.Stat(".")
		if err == nil && os.SameFile(seen, opened) {
			return &treeDir{root: sub}, nil
		}
		sub.Close()
		if err != nil {
			return nil, err
		}
	}
	return nil, fmt.Errorf("%s: %w", name, errTreeChanged)
}

// openRegular opens the regular file name for reading and returns the lstat
// it was matched against. A FIFO or device swapped in cannot block the open.
func (d *treeDir) openRegular(name string) (*os.File, os.FileInfo, error) {
	for attempt := 0; attempt < 3; attempt++ {
		seen, err := d.root.Lstat(name)
		if err != nil {
			return nil, nil, err
		}
		if !seen.Mode().IsRegular() {
			return nil, nil, fmt.Errorf("%s: %w", name, errTreeNotRegular)
		}
		f, err := d.root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
		if err != nil {
			return nil, nil, err
		}
		opened, err := f.Stat()
		if err == nil && opened.Mode().IsRegular() && os.SameFile(seen, opened) {
			return f, seen, nil
		}
		f.Close()
		if err != nil {
			return nil, nil, err
		}
	}
	return nil, nil, fmt.Errorf("%s: %w", name, errTreeChanged)
}
