package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"runtime"
	"slices"
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

// storedAs reports whether the directory holds an entry whose name is name
// byte for byte. Opening name proves less: a disk that folds letter case, or
// that treats two Unicode normalizations of a name as one, opens another
// spelling as the same entry, and a record keyed by the stored spelling is
// then never found for it. Nothing is lower-cased or normalized here.
//
// The directory's own listing is the comparison (lists). Two lstats decide
// the common case without it (entryStoredAs).
func (d *treeDir) storedAs(name string) (bool, error) {
	return entryStoredAs(name, d.root.Lstat, func() (bool, error) { return d.lists(name) })
}

// lists reports whether name is among the entry names the directory returns,
// compared as bytes.
func (d *treeDir) lists(name string) (bool, error) {
	f, err := d.root.Open(".")
	if err != nil {
		return false, err
	}
	defer f.Close()
	for {
		names, err := f.Readdirnames(512)
		if slices.Contains(names, name) {
			return true, nil
		}
		if err == io.EOF {
			return false, nil
		}
		if err != nil {
			return false, err
		}
	}
}

// entryStoredAs decides storedAs for a directory read through lstat, asking
// listed (the full listing) only when two lstats cannot settle it. A large
// uploads folder on a case-sensitive disk would otherwise be listed for
// every file served.
//
// The shortcut holds for a disk that matches a name byte for byte, or after
// folding letter case, or after canonical Unicode normalization, or both.
// Each step under that model:
//
//   - name does not exist: no entry answers to it in any spelling, so it is
//     not stored.
//   - name is ASCII with a letter, and its case-swapped spelling does not
//     exist: a directory that folds case would have opened the swapped
//     spelling as the very entry name opened, so this one does not fold case
//     for the name. What is left is normalization, and name is ASCII: an
//     entry spelled otherwise could only normalize onto it through a code
//     point whose canonical form is ASCII. There are three (the Kelvin sign
//     onto K, the Greek question mark onto ;, the Greek varia onto `), and a
//     name holding one of those characters is left to the listing
//     (caseSwappedASCII). So the entry is spelled name.
//   - the swapped spelling exists as another file: a folding directory holds
//     one entry per folded name, so two files mean two entries and no
//     folding; the same argument then applies.
//   - the swapped spelling is the same file: a folding disk, or a hard link
//     under the other name. The lstats cannot tell these apart: list.
//
// Everything else is listed: a name with a byte outside ASCII
// (normalization), a name with no letter (nothing to swap, so nothing shows
// whether the directory folds), any other lstat error, and every name on
// Windows, whose path handling also drops trailing dots and spaces and knows
// short names, which no case probe sees. A disk set to compatibility
// normalization and case-sensitive matching is outside the model.
func entryStoredAs(name string, lstat func(string) (os.FileInfo, error), listed func() (bool, error)) (bool, error) {
	seen, err := lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	swapped, ok := caseSwappedASCII(name)
	if err != nil || !ok || runtime.GOOS == "windows" {
		return listed()
	}
	other, err := lstat(swapped)
	if errors.Is(err, fs.ErrNotExist) || (err == nil && !os.SameFile(seen, other)) {
		return true, nil
	}
	return listed()
}

// caseSwappedASCII returns name with the case of every ASCII letter swapped.
// ok is false when the swap proves nothing: name has a byte outside ASCII,
// has no letter, or holds K, ; or ` (the three ASCII characters another code
// point normalizes onto; see entryStoredAs).
func caseSwappedASCII(name string) (swapped string, ok bool) {
	b := []byte(name)
	for i, c := range b {
		switch {
		case c >= 0x80 || c == 'K' || c == ';' || c == '`':
			return "", false
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z':
			b[i] = c ^ 0x20
			ok = true
		}
	}
	if !ok {
		return "", false
	}
	return string(b), true
}

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

// errTreeTooLarge: the file is larger than the caller's read limit.
var errTreeTooLarge = errors.New("file is larger than the read limit")

// readRegularBounded reads the regular file name (openRegular: never a link,
// FIFO or device) whole, refusing one larger than limit. The size is judged
// on the opened handle and the read itself is capped, so a file that grows
// after the check still cannot make the reader allocate past limit.
func (d *treeDir) readRegularBounded(name string, limit int64) ([]byte, error) {
	f, _, err := d.openRegular(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.Size() > limit {
		return nil, fmt.Errorf("%s: %w (%d bytes, limit %d)", name, errTreeTooLarge, st.Size(), limit)
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s: %w (limit %d)", name, errTreeTooLarge, limit)
	}
	return data, nil
}
