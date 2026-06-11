package translog

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// leavesFileName is the append-only leaf hash journal inside the log
// directory: one 64-char lowercase hex SHA-256 leaf hash per line.
const leavesFileName = "leaves"

// Log is a file-backed, append-only RFC 6962 Merkle log over receipt
// hashes. It follows the kernel's simple local persistence convention
// (plain files under the data directory, like freeze state).
type Log struct {
	mu         sync.Mutex
	dir        string
	leafHashes [][HashSize]byte
}

// Open loads (or initializes) a transparency log in dir.
func Open(dir string) (*Log, error) {
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, fmt.Errorf("translog: create log dir: %w", err)
	}
	l := &Log{dir: dir}
	path := filepath.Join(dir, leavesFileName)
	f, err := os.Open(path) // #nosec G304 -- path is derived from the kernel data dir
	if err != nil {
		if os.IsNotExist(err) {
			return l, nil
		}
		return nil, fmt.Errorf("translog: open leaves journal: %w", err)
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	line := 0
	for scanner.Scan() {
		line++
		text := strings.TrimSpace(scanner.Text())
		if text == "" {
			continue
		}
		h, err := decodeHash(text)
		if err != nil {
			return nil, fmt.Errorf("translog: corrupt leaves journal at line %d: %w", line, err)
		}
		l.leafHashes = append(l.leafHashes, h)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("translog: read leaves journal: %w", err)
	}
	return l, nil
}

// Append adds a new leaf for the given leaf input (the raw receipt hash
// bytes), persists it durably, and returns the assigned leaf index.
// Appends are fail-closed: if the journal write fails, the in-memory
// tree is not advanced and the error is returned to the caller.
func (l *Log) Append(leafInput []byte) (uint64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	leaf := LeafHash(leafInput)
	path := filepath.Join(l.dir, leavesFileName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600) // #nosec G304 -- path is derived from the kernel data dir
	if err != nil {
		return 0, fmt.Errorf("translog: open leaves journal for append: %w", err)
	}
	defer func() { _ = f.Close() }()

	if _, err := f.WriteString(hex.EncodeToString(leaf[:]) + "\n"); err != nil {
		return 0, fmt.Errorf("translog: append leaf: %w", err)
	}
	if err := f.Sync(); err != nil {
		return 0, fmt.Errorf("translog: sync leaves journal: %w", err)
	}

	l.leafHashes = append(l.leafHashes, leaf)
	return uint64(len(l.leafHashes) - 1), nil
}

// Size returns the current tree size (number of leaves).
func (l *Log) Size() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return uint64(len(l.leafHashes))
}

// Root returns the Merkle tree hash over the first treeSize leaves.
// treeSize == Size() yields the current root.
func (l *Log) Root(treeSize uint64) ([HashSize]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if treeSize > uint64(len(l.leafHashes)) {
		return [HashSize]byte{}, fmt.Errorf("translog: tree size %d out of range (have %d leaves)", treeSize, len(l.leafHashes))
	}
	return RootFromLeafHashes(l.leafHashes[:treeSize]), nil
}

// LeafHashAt returns the stored leaf hash at index i.
func (l *Log) LeafHashAt(i uint64) ([HashSize]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if i >= uint64(len(l.leafHashes)) {
		return [HashSize]byte{}, fmt.Errorf("translog: leaf index %d out of range (have %d leaves)", i, len(l.leafHashes))
	}
	return l.leafHashes[i], nil
}

// InclusionProof builds the audit path for the leaf at leafIndex under
// the tree of treeSize.
func (l *Log) InclusionProof(leafIndex, treeSize uint64) (*InclusionProof, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return BuildInclusionProof(l.leafHashes, leafIndex, treeSize)
}

// ConsistencyProof builds the consistency proof between the trees at
// oldSize and newSize.
func (l *Log) ConsistencyProof(oldSize, newSize uint64) (*ConsistencyProof, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return BuildConsistencyProof(l.leafHashes, oldSize, newSize)
}
