// quantum_posture: bundle verification trusts classical Ed25519 signatures
// and SHA-256 content hashes; no hybrid or post-quantum claim.
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
// content or size mismatches, path traversal (in file *and* directory
// members), symlinks, hard links, devices and other non-regular types, and
// any non-padding bytes trailing the tar archive are all errors. Directory
// members carry no content and are skipped after their path is validated;
// every other member must be a regular file named by the manifest. Only
// stdlib archive/tar and compress/gzip are used — the verifier stays
// dependency-free.
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
			// Directories carry no content, but their names still have to be
			// clean: "../etc/" must not ride along unchecked.
			if err := validateEntryPath(strings.TrimSuffix(name, "/")); err != nil {
				return err
			}
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

	// Everything after the tar end-of-archive marker must be zero padding.
	// Non-zero trailing bytes (or a concatenated gzip member, which the
	// multistream reader would otherwise absorb) would smuggle content past
	// the manifest. Scanned streaming with a fixed buffer and a hard cap so
	// a hostile bundle cannot force a large allocation in an offline
	// verifier.
	buf := make([]byte, 32*1024)
	var padding int64
	for {
		n, err := gz.Read(buf)
		for _, b := range buf[:n] {
			if b != 0 {
				return fmt.Errorf("update bundle carries non-padding data after the archive")
			}
		}
		padding += int64(n)
		if padding > maxTrailerPaddingBytes {
			return fmt.Errorf("update bundle trailer exceeds %d bytes of padding", maxTrailerPaddingBytes)
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read update bundle trailer: %w", err)
		}
	}
	return nil
}

// maxTrailerPaddingBytes bounds the zero padding tolerated after the tar
// end-of-archive marker. Real archives pad to a 10 KiB block at most.
const maxTrailerPaddingBytes = 1 << 20
