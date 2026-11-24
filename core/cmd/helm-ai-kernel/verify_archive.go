package main

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func extractEvidenceArchive(bundlePath, dstDir string) error {
	file, err := os.Open(bundlePath)
	if err != nil {
		return err
	}
	defer file.Close()

	var reader io.Reader = file
	if strings.HasSuffix(bundlePath, ".gz") || strings.HasSuffix(bundlePath, ".tgz") {
		gzReader, err := gzip.NewReader(file)
		if err != nil {
			return fmt.Errorf("open gzip archive: %w", err)
		}
		defer gzReader.Close()
		reader = gzReader
	}

	tarReader := tar.NewReader(reader)
	var extractedBytes int64
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read tar entry: %w", err)
		}

		targetPath, err := safeArchiveEntryPath(dstDir, header.Name)
		if err != nil {
			return err
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, 0750); err != nil {
				return fmt.Errorf("create directory %s: %w", targetPath, err)
			}
		case tar.TypeReg:
			if header.Size < 0 {
				return fmt.Errorf("archive entry %s has invalid size", header.Name)
			}
			if header.Size > maxEvidenceBundleBytes {
				return fmt.Errorf("archive entry %s exceeds %d bytes", header.Name, maxEvidenceBundleBytes)
			}
			if extractedBytes+header.Size > maxEvidenceBundleBytes {
				return fmt.Errorf("archive exceeds %d extracted bytes", maxEvidenceBundleBytes)
			}
			if err := os.MkdirAll(filepath.Dir(targetPath), 0750); err != nil {
				return fmt.Errorf("prepare file %s: %w", targetPath, err)
			}
			outFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
			if err != nil {
				return fmt.Errorf("create file %s: %w", targetPath, err)
			}
			written, err := io.Copy(outFile, tarReader)
			if err != nil {
				outFile.Close()
				return fmt.Errorf("extract file %s: %w", targetPath, err)
			}
			if written != header.Size {
				outFile.Close()
				return fmt.Errorf("archive entry %s size mismatch", header.Name)
			}
			extractedBytes += written
			if err := outFile.Close(); err != nil {
				return fmt.Errorf("close file %s: %w", targetPath, err)
			}
		default:
			return fmt.Errorf("unsupported archive entry %s", header.Name)
		}
	}
}

func hasCanonicalEvidenceLayout(root string) bool {
	if _, err := os.Stat(filepath.Join(root, "00_INDEX.json")); err == nil {
		return true
	}
	if _, err := os.Stat(filepath.Join(root, "02_PROOFGRAPH")); err == nil {
		return true
	}
	return false
}
