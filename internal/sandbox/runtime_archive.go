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

const archiveLimit = 8 << 30

// No guest block image is ever mounted or parsed by the host kernel. Export is
// untrusted tar, bounded and unpacked through os.Root into a fresh directory.
func importWorkspace(dst string, input io.Reader) error {
	root, err := os.OpenRoot(dst)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	reader := tar.NewReader(io.LimitReader(input, archiveLimit+1))
	seen := make(map[string]bool)
	var total int64
	for count := 0; ; count++ {
		h, err := reader.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if count >= 200000 {
			return fmt.Errorf("too many workspace entries")
		}
		name := filepath.Clean(h.Name)
		if name == "." && h.Typeflag == tar.TypeDir {
			continue
		}
		if filepath.IsAbs(name) || name == ".." || strings.HasPrefix(name, "../") || strings.ContainsRune(name, '\x00') || seen[name] {
			return fmt.Errorf("invalid or duplicate workspace path %q", h.Name)
		}
		seen[name] = true
		// os.Root confines symlinks, but following an earlier archive symlink could
		// alias another file. Reject symlink parents as well as lexical traversal.
		for parent := filepath.Dir(name); parent != "."; parent = filepath.Dir(parent) {
			st, err := root.Lstat(parent)
			if err == nil && st.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("symlink parent of %q", name)
			}
			if err != nil && !os.IsNotExist(err) {
				return err
			}
		}
		if err := root.MkdirAll(filepath.Dir(name), 0o700); err != nil {
			return err
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if err := root.MkdirAll(name, 0o700); err != nil {
				return err
			}
		case tar.TypeReg:
			if h.Size < 0 || h.Size > archiveLimit-total {
				return fmt.Errorf("workspace exceeds export limit")
			}
			total += h.Size
			f, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, fs.FileMode(h.Mode&0o777))
			if err != nil {
				return err
			}
			_, err = io.CopyN(f, reader, h.Size)
			closeErr := f.Close()
			if err != nil {
				return err
			}
			if closeErr != nil {
				return closeErr
			}
		case tar.TypeSymlink:
			if err := root.Symlink(h.Linkname, name); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported workspace entry %q (%d)", name, h.Typeflag)
		}
	}
}

func exportWorkspace(root string, output io.Writer) error {
	// WalkDir does not descend into a root that is a symlink: a workspace
	// reached through one (a non-git cwd) would export empty, a branch in
	// which every real file is gone. Walk the directory it names.
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		return err
	}
	source, err := os.OpenRoot(root)
	if err != nil {
		return err
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
		st, err := d.Info()
		if err != nil {
			return err
		}
		if !st.Mode().IsRegular() && !st.IsDir() && st.Mode()&os.ModeSymlink == 0 {
			return fmt.Errorf("unsupported workspace file %s", path)
		}
		link := ""
		if st.Mode()&os.ModeSymlink != 0 {
			link, err = os.Readlink(path)
			if err != nil {
				return err
			}
		}
		h, err := tar.FileInfoHeader(st, link)
		if err != nil {
			return err
		}
		h.Name, err = filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if err := writer.WriteHeader(h); err != nil {
			return err
		}
		if st.Mode().IsRegular() {
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
		_ = writer.Close()
		return err
	}
	return writer.Close()
}
