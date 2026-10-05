package sandbox

import (
	"archive/tar"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const (
	archiveLimit = 8 << 30
	maxEntries   = 200000
)

// No guest block image is ever mounted or parsed by the host kernel. Export is
// untrusted tar, bounded and unpacked through os.Root into a fresh directory.
// It returns the number of entries read. The end of the tar alone does not
// say the export is complete; the microVM's result stream does (receiveExport).
func importWorkspace(dst string, input io.Reader) (int, error) {
	root, err := os.OpenRoot(dst)
	if err != nil {
		return 0, err
	}
	defer func() { _ = root.Close() }()
	reader := tar.NewReader(io.LimitReader(input, archiveLimit+1))
	seen := make(map[string]bool)
	var total int64
	for count := 0; ; count++ {
		h, err := reader.Next()
		if err == io.EOF {
			return count, nil
		}
		if err != nil {
			return count, err
		}
		if count >= maxEntries {
			return count, fmt.Errorf("too many workspace entries")
		}
		name := filepath.Clean(h.Name)
		if name == "." && h.Typeflag == tar.TypeDir {
			continue
		}
		if filepath.IsAbs(name) || name == ".." || strings.HasPrefix(name, "../") || strings.ContainsRune(name, '\x00') || seen[name] {
			return count, fmt.Errorf("invalid or duplicate workspace path %q", h.Name)
		}
		seen[name] = true
		// os.Root confines symlinks, but following an earlier archive symlink could
		// alias another file. Reject symlink parents as well as lexical traversal.
		for parent := filepath.Dir(name); parent != "."; parent = filepath.Dir(parent) {
			st, err := root.Lstat(parent)
			if err == nil && st.Mode()&os.ModeSymlink != 0 {
				return count, fmt.Errorf("symlink parent of %q", name)
			}
			if err != nil && !os.IsNotExist(err) {
				return count, err
			}
		}
		if err := root.MkdirAll(filepath.Dir(name), 0o700); err != nil {
			return count, err
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if err := root.MkdirAll(name, 0o700); err != nil {
				return count, err
			}
		case tar.TypeReg:
			if h.Size < 0 || h.Size > archiveLimit-total {
				return count, fmt.Errorf("workspace exceeds export limit")
			}
			total += h.Size
			mode := fs.FileMode(h.Mode & 0o777)
			f, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
			if err != nil {
				return count, err
			}
			// The umask masked the mode OpenFile gave; review compares it.
			if err := f.Chmod(mode); err != nil {
				_ = f.Close()
				return count, err
			}
			_, err = io.CopyN(f, reader, h.Size)
			closeErr := f.Close()
			if err != nil {
				return count, err
			}
			if closeErr != nil {
				return count, closeErr
			}
		case tar.TypeSymlink:
			if err := root.Symlink(h.Linkname, name); err != nil {
				return count, err
			}
		default:
			return count, fmt.Errorf("unsupported workspace entry %q (%d)", name, h.Typeflag)
		}
	}
}

// exportStats is what exportWorkspace wrote: the tar entries, and the
// special files it left out.
type exportStats struct {
	entries int
	skipped []string
}

// exportWorkspace writes root as a tar. With skipSpecial, sockets, FIFOs
// and devices are left out and listed, as the microVM guest does with
// what the agent made; the host copies the real workspace without it, and
// such a file fails the copy rather than be missing from the branch. The
// tar is finished only when every entry was written: on an error it stops
// where it is, and the stream around it says the export failed.
func exportWorkspace(root string, output io.Writer, skipSpecial bool) (exportStats, error) {
	var st exportStats
	// WalkDir does not descend into a root that is a symlink: a workspace
	// reached through one (a non-git cwd) would export empty, a branch in
	// which every real file is gone. Walk the directory it names.
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		return st, err
	}
	source, err := os.OpenRoot(root)
	if err != nil {
		return st, err
	}
	defer func() { _ = source.Close() }()
	writer := tar.NewWriter(output)
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() && !info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
			if skipSpecial && info.Mode()&(os.ModeNamedPipe|os.ModeSocket|os.ModeDevice) != 0 {
				st.skipped = append(st.skipped, rel)
				return nil
			}
			return fmt.Errorf("unsupported workspace file %s", path)
		}
		link := ""
		if info.Mode()&os.ModeSymlink != 0 {
			link, err = os.Readlink(path)
			if err != nil {
				return err
			}
		}
		h, err := tar.FileInfoHeader(info, link)
		if err != nil {
			return err
		}
		h.Name = rel
		if err := writer.WriteHeader(h); err != nil {
			return err
		}
		st.entries++
		if info.Mode().IsRegular() {
			f, err := source.Open(h.Name)
			if err != nil {
				return err
			}
			_, err = io.Copy(writer, f)
			closeErr := f.Close()
			if err != nil {
				return err
			}
			return closeErr
		}
		return nil
	})
	if err != nil {
		return st, err // no trailer: a partial tar must not read as a whole one
	}
	return st, writer.Close()
}
