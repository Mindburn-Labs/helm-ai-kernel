package evidencepack

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"sort"
	"time"
)

// Archive creates a deterministic tar archive from the evidence pack contents.
// Determinism is guaranteed by:
//   - Sorting entries lexicographically by path
//   - Zeroing all timestamps, UID/GID, and permissions to fixed values
//   - Using a fixed block size
//
// NOTE: Compression (zstd) should be applied externally if desired.
// The raw tar is deterministic; compression may not be unless the compressor
// is also configured for determinism (zstd level 3 with deterministic mode).
func Archive(contents map[string][]byte) ([]byte, error) {
	if len(contents) == 0 {
		return nil, fmt.Errorf("cannot archive empty evidence pack")
	}

	// Sort paths for determinism
	paths := make([]string, 0, len(contents))
	for path := range contents {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	defer func() { _ = tw.Close() }()

	// Fixed timestamp for determinism: Unix epoch
	var zeroTime time.Time

	for _, path := range paths {
		data := contents[path]

		hdr := &tar.Header{
			Name:    path,
			Size:    int64(len(data)),
			Mode:    0644,
			ModTime: zeroTime,
			Uid:     0,
			Gid:     0,
			Uname:   "",
			Gname:   "",
			Format:  tar.FormatPAX,
		}

		if err := tw.WriteHeader(hdr); err != nil {
			return nil, fmt.Errorf("write tar header for %s: %w", path, err)
		}
		if _, err := tw.Write(data); err != nil {
			return nil, fmt.Errorf("write tar content for %s: %w", path, err)
		}
	}

	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("close tar: %w", err)
	}

	return buf.Bytes(), nil
}

// Unarchive extracts a deterministic tar archive into a content map.
func Unarchive(data []byte) (map[string][]byte, error) {
	contents := make(map[string][]byte)

	tr := tar.NewReader(bytes.NewReader(data))
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read tar: %w", err)
		}

		var buf bytes.Buffer
		if _, err := io.Copy(&buf, tr); err != nil {
			return nil, fmt.Errorf("read tar entry %s: %w", hdr.Name, err)
		}
		contents[hdr.Name] = buf.Bytes()
	}

	return contents, nil
}
