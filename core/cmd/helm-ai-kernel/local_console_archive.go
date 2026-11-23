// quantum_posture: local Console integrity uses classical SHA-256/HMAC and
// Sigstore-verified release evidence; it makes no post-quantum assurance.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
)

type localConsoleArchiveFile struct {
	SHA256 string
	Mode   int64
	Data   []byte
}

func verifyLocalConsoleRawArchive(archivePath, target string, source localConsoleSource, inner localConsoleInnerArtifact, inventoryBytes []byte, external localConsoleExternalProvenance) error {
	archive, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("open local Console release archive: %w", err)
	}
	defer archive.Close()
	compressed, err := gzip.NewReader(archive)
	if err != nil {
		return fmt.Errorf("read local Console release archive: %w", err)
	}

	expectedRoot := localConsoleBundlePrefix + target
	reader := tar.NewReader(compressed)
	files := make(map[string]localConsoleArchiveFile)
	var total int64
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read local Console release archive: %w", err)
		}
		relativePath, err := localConsoleArchiveRelativePath(header.Name, expectedRoot, header.Typeflag == tar.TypeDir)
		if err != nil {
			return err
		}
		if header.Typeflag == tar.TypeDir {
			if header.Linkname != "" {
				return fmt.Errorf("local Console release archive directory is invalid")
			}
			continue
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			return fmt.Errorf("local Console release archive contains an unsupported entry")
		}
		if relativePath == "" || header.Linkname != "" || header.Size < 0 || header.Size > localConsoleBundleMaxBytes || total > localConsoleBundleMaxBytes-header.Size {
			return fmt.Errorf("local Console release archive payload is invalid")
		}
		total += header.Size
		if _, duplicate := files[relativePath]; duplicate {
			return fmt.Errorf("local Console release archive contains a duplicate payload")
		}
		hash := sha256.New()
		writer := io.Writer(hash)
		var contents bytes.Buffer
		capture := relativePath == localConsoleInventoryFile || relativePath == localConsoleProvenanceFile
		if capture {
			if header.Size > localConsoleInventoryMaxBytes {
				return fmt.Errorf("local Console release archive metadata exceeds the validation limit")
			}
			writer = io.MultiWriter(hash, &contents)
		}
		written, err := io.Copy(writer, reader)
		if err != nil || written != header.Size {
			return fmt.Errorf("read local Console release archive payload")
		}
		files[relativePath] = localConsoleArchiveFile{
			SHA256: hex.EncodeToString(hash.Sum(nil)),
			Mode:   header.Mode,
			Data:   contents.Bytes(),
		}
	}
	if _, err := io.Copy(io.Discard, compressed); err != nil {
		return fmt.Errorf("read local Console release archive trailer: %w", err)
	}
	if err := compressed.Close(); err != nil {
		return fmt.Errorf("close local Console release archive: %w", err)
	}
	for _, required := range []string{localConsoleInventoryFile, localConsoleProvenanceFile, localConsoleServerFile, localConsoleNodeFile, localConsoleNodeLicenseFile} {
		if _, ok := files[required]; !ok {
			return fmt.Errorf("local Console release archive is missing %s", required)
		}
	}
	if !bytes.Equal(files[localConsoleInventoryFile].Data, inventoryBytes) {
		return fmt.Errorf("local Console release archive inventory does not match the release asset")
	}
	if files[localConsoleNodeFile].Mode&0111 == 0 {
		return fmt.Errorf("local Console release archive bundled Node is not executable")
	}
	entries, err := parseLocalConsoleInventory(inventoryBytes)
	if err != nil {
		return err
	}
	payloadCount := 0
	for relativePath, file := range files {
		if relativePath == localConsoleInventoryFile || relativePath == localConsoleProvenanceFile {
			continue
		}
		payloadCount++
		entry, ok := entries[relativePath]
		if !ok || !hmac.Equal([]byte(file.SHA256), []byte(entry.SHA256)) {
			return fmt.Errorf("local Console release archive payload does not match its inventory")
		}
	}
	if payloadCount != len(entries) {
		return fmt.Errorf("local Console release archive payload does not match its inventory")
	}
	if actual := sha256Hex(inventoryBytes); !hmac.Equal([]byte(actual), []byte(inner.BundleSHA256)) {
		return fmt.Errorf("local Console release archive inventory hash does not match its manifest")
	}
	var embedded localConsoleProvenance
	if err := decodeLocalConsoleJSON(files[localConsoleProvenanceFile].Data, &embedded); err != nil {
		return fmt.Errorf("decode embedded local Console provenance: %w", err)
	}
	if err := validateLocalConsoleProvenance(embedded, target); err != nil {
		return err
	}
	if embedded != external.localConsoleProvenance || embedded.Source != source || embedded.BundleSHA256 != inner.BundleSHA256 || embedded.Signature != inner.Signature {
		return fmt.Errorf("embedded local Console provenance does not match the release manifest")
	}
	return nil
}

func localConsoleArchiveRelativePath(name, expectedRoot string, directory bool) (string, error) {
	if name == "" || strings.Contains(name, "\\") || path.IsAbs(name) {
		return "", fmt.Errorf("local Console release archive path is invalid")
	}
	canonical := name
	if directory && strings.HasSuffix(canonical, "/") {
		canonical = strings.TrimSuffix(canonical, "/")
		if canonical == "" || strings.HasSuffix(canonical, "/") {
			return "", fmt.Errorf("local Console release archive path is invalid")
		}
	}
	if !directory && strings.HasSuffix(canonical, "/") {
		return "", fmt.Errorf("local Console release archive path is invalid")
	}
	if canonical == "." || canonical == ".." || strings.HasPrefix(canonical, "../") || path.Clean(canonical) != canonical {
		return "", fmt.Errorf("local Console release archive path is invalid")
	}
	parts := strings.Split(canonical, "/")
	if len(parts) == 0 || parts[0] != expectedRoot {
		return "", fmt.Errorf("local Console release archive escapes the expected bundle root")
	}
	if len(parts) == 1 {
		if !directory {
			return "", fmt.Errorf("local Console release archive root is not a directory")
		}
		return "", nil
	}
	relativePath := strings.Join(parts[1:], "/")
	if _, err := canonicalLocalConsoleRelativePath(relativePath); err != nil {
		return "", fmt.Errorf("local Console release archive path is invalid")
	}
	return relativePath, nil
}
