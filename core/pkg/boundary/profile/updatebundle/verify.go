package updatebundle

import (
	"archive/tar"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

// VerifyBundle streams the tar.gz payload once and proves it matches the
// signed manifest exactly. Fail-closed: extra members, missing members,
// content or size mismatches, path traversal, and non-regular-file members
// (symlinks, devices, hard links) are all errors. Directory members are
// tolerated as structure but never trusted. Only stdlib archive/tar and
// compress/gzip are used — the verifier stays dependency-free.
func VerifyBundle(r io.Reader, manifest UpdateBundleManifest, publicKey ed25519.PublicKey) error {
	if err := VerifyManifest(manifest, publicKey); err != nil {
		return err
	}
	expected := make(map[string]BundleEntry, len(manifest.Entries))
	for _, entry := range manifest.Entries {
		expected[entry.Path] = entry
	}

	gz, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("update bundle is not a gzip stream: %w", err)
	}
	defer gz.Close()

	seen := map[string]bool{}
	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read update bundle tar: %w", err)
		}
		name := strings.TrimPrefix(header.Name, "./")
		if header.Typeflag == tar.TypeDir {
			continue
		}
		if header.Typeflag != tar.TypeReg {
			return fmt.Errorf("update bundle member %q has unsupported type %q: only regular files are allowed", header.Name, header.Typeflag)
		}
		if err := validateEntryPath(name); err != nil {
			return err
		}
		entry, ok := expected[name]
		if !ok {
			return fmt.Errorf("update bundle member %q is not in the signed manifest", name)
		}
		if seen[name] {
			return fmt.Errorf("update bundle member %q appears more than once", name)
		}
		seen[name] = true

		hasher := sha256.New()
		// Limit to the manifest size + 1 so an oversized member is detected
		// without reading unbounded data.
		n, err := io.Copy(hasher, io.LimitReader(tr, entry.Size+1))
		if err != nil {
			return fmt.Errorf("read update bundle member %q: %w", name, err)
		}
		if n != entry.Size {
			return fmt.Errorf("update bundle member %q size %d does not match manifest size %d", name, n, entry.Size)
		}
		if got := "sha256:" + hex.EncodeToString(hasher.Sum(nil)); got != entry.SHA256 {
			return fmt.Errorf("update bundle member %q hash %s does not match manifest %s", name, got, entry.SHA256)
		}
	}

	for _, entry := range manifest.Entries {
		if !seen[entry.Path] {
			return fmt.Errorf("update bundle is missing manifest entry %q", entry.Path)
		}
	}
	return nil
}
