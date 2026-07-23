package agentruntime

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/translog"
)

// InfraError classifies a storage-layer failure. An InfraError is never a
// tool error and never a turn failure: it must not be recorded in the log
// as tool_result or turn_failed. Crash-recovery semantics treat it as an
// infrastructure fact the caller handles outside the turn's causal history.
type InfraError struct {
	Op  string
	Err error
}

func (e *InfraError) Error() string {
	return fmt.Sprintf("agentruntime: infrastructure failure during %s: %v", e.Op, e.Err)
}

// Unwrap exposes the underlying OS error.
func (e *InfraError) Unwrap() error { return e.Err }

// AsInfraError reports whether err is (or wraps) an InfraError.
func AsInfraError(err error) (*InfraError, bool) {
	var ie *InfraError
	if errors.As(err, &ie) {
		return ie, true
	}
	return nil, false
}

// AppendResult summarizes one durable append.
type AppendResult struct {
	TurnID  string `json:"turn_id"`
	FromSeq uint64 `json:"from_seq"`
	ToSeq   uint64 `json:"to_seq"` // inclusive
	// HeadHash is the hash of the last appended event — the new chain head.
	HeadHash string `json:"head_hash"`
	// AnchorLeafIndices are the transparency-log leaf indices assigned to
	// the appended events, in order. Empty when the store has no anchor.
	AnchorLeafIndices []uint64 `json:"anchor_leaf_indices,omitempty"`
}

// Store is a JSONL turn-log store with hash-chained integrity. Appends go
// through the reducer or not at all: ValidateAppend runs before any byte
// is written. Reads strictly re-verify the whole file — canonical form,
// hash chain, and reducer legality — and fail loudly on any deviation.
// There is no repair path.
//
// When constructed WithAnchor, every appended event hash is also added as
// a leaf to the kernel's RFC 6962 transparency log (core/pkg/translog),
// so turn history is Merkle-anchored by construction.
type Store struct {
	dir    string
	anchor *translog.Log

	mu        sync.Mutex
	turnLocks map[string]*sync.Mutex
}

// StoreOption configures a Store.
type StoreOption func(*Store)

// WithAnchor anchors every appended event hash into l.
func WithAnchor(l *translog.Log) StoreOption {
	return func(s *Store) { s.anchor = l }
}

// OpenStore opens (or initializes) a turn-log store rooted at dir,
// following the kernel's plain-file persistence convention.
func OpenStore(dir string, opts ...StoreOption) (*Store, error) {
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, &InfraError{Op: "create store dir", Err: err}
	}
	s := &Store{dir: dir, turnLocks: map[string]*sync.Mutex{}}
	for _, o := range opts {
		o(s)
	}
	return s, nil
}

func (s *Store) lockFor(turnID string) *sync.Mutex {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.turnLocks[turnID]
	if !ok {
		l = &sync.Mutex{}
		s.turnLocks[turnID] = l
	}
	return l
}

func (s *Store) pathFor(turnID string) (string, error) {
	if !turnIDPattern.MatchString(turnID) {
		return "", fmt.Errorf("agentruntime: invalid turn_id %q", turnID)
	}
	return filepath.Join(s.dir, turnID+".jsonl"), nil
}

// Append is the sole write path. It assigns Seq and PrevHash to each
// candidate, folds existing+candidates through the reducer, and only then
// writes canonical lines with fsync. A reducer rejection writes nothing.
// An OS-level failure is returned as *InfraError; in that case the file
// may hold a partial batch and subsequent loads will fail loudly — the
// failure is infrastructure, not turn history.
func (s *Store) Append(turnID string, candidates ...Event) (*AppendResult, error) {
	if len(candidates) == 0 {
		return nil, fmt.Errorf("agentruntime: append requires at least one event")
	}
	path, err := s.pathFor(turnID)
	if err != nil {
		return nil, err
	}
	lock := s.lockFor(turnID)
	lock.Lock()
	defer lock.Unlock()

	existing, _, headHash, err := s.loadLocked(path, turnID)
	if err != nil {
		return nil, err
	}

	// Assign chain positions before gating so the reducer sees final seqs.
	// Events must name the turn they are appended to: a log file can never
	// hold another turn's history.
	prevHash := headHash
	hashes := make([]string, len(candidates))
	for i := range candidates {
		if candidates[i].TurnID != turnID {
			return nil, fmt.Errorf("agentruntime: candidate %d names turn %q, not %q", i, candidates[i].TurnID, turnID)
		}
		candidates[i].Seq = uint64(len(existing) + i)
		candidates[i].PrevHash = prevHash
		h, err := HashEvent(&candidates[i])
		if err != nil {
			return nil, err
		}
		hashes[i] = h
		prevHash = h
	}

	if _, err := ValidateAppend(existing, candidates...); err != nil {
		return nil, fmt.Errorf("agentruntime: append rejected by reducer gate: %w", err)
	}

	var buf bytes.Buffer
	for i := range candidates {
		line, err := CanonicalBytes(&candidates[i])
		if err != nil {
			return nil, err
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600) // #nosec G304 -- path is derived from the store dir and a validated turn ID
	if err != nil {
		return nil, &InfraError{Op: "open turn log", Err: err}
	}
	if _, err := f.Write(buf.Bytes()); err != nil {
		_ = f.Close()
		return nil, &InfraError{Op: "write turn log", Err: err}
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return nil, &InfraError{Op: "sync turn log", Err: err}
	}
	if err := f.Close(); err != nil {
		return nil, &InfraError{Op: "close turn log", Err: err}
	}

	res := &AppendResult{
		TurnID:   turnID,
		FromSeq:  uint64(len(existing)),
		ToSeq:    uint64(len(existing) + len(candidates) - 1),
		HeadHash: hashes[len(hashes)-1],
	}

	// Anchoring is additive and happens after the events are durable. An
	// anchor failure does not invalidate the durable events; it is
	// reported as infrastructure and can be repaired with AnchorRange.
	if s.anchor != nil {
		for _, h := range hashes {
			raw, decErr := hex.DecodeString(strings.TrimPrefix(h, sha256Prefix))
			if decErr != nil {
				return res, &InfraError{Op: "decode event hash for anchor", Err: decErr}
			}
			idx, ancErr := s.anchor.Append(raw)
			if ancErr != nil {
				return res, &InfraError{Op: "anchor event hash", Err: ancErr}
			}
			res.AnchorLeafIndices = append(res.AnchorLeafIndices, idx)
		}
	}
	return res, nil
}

// Load reads and fully verifies a turn log: canonical form per line,
// hash chain, and reducer legality. Any deviation fails loudly.
func (s *Store) Load(turnID string) ([]Event, *State, error) {
	path, err := s.pathFor(turnID)
	if err != nil {
		return nil, nil, err
	}
	lock := s.lockFor(turnID)
	lock.Lock()
	defer lock.Unlock()
	events, state, _, err := s.loadLocked(path, turnID)
	return events, state, err
}

// Verify checks a turn log without returning its contents.
func (s *Store) Verify(turnID string) error {
	_, _, err := s.Load(turnID)
	return err
}

// HeadHash returns the hash of the last event of a turn, or "" for an
// empty/nonexistent log.
func (s *Store) HeadHash(turnID string) (string, error) {
	path, err := s.pathFor(turnID)
	if err != nil {
		return "", err
	}
	lock := s.lockFor(turnID)
	lock.Lock()
	defer lock.Unlock()
	_, _, head, err := s.loadLocked(path, turnID)
	return head, err
}

// AnchorRange anchors the hashes of events [fromSeq, end) of a turn into
// the store's transparency log. It exists to repair anchoring after an
// InfraError during Append's anchor phase; callers track their own
// high-water mark. Anchoring the same seq twice appends duplicate leaves,
// so callers must treat fromSeq as authoritative.
func (s *Store) AnchorRange(turnID string, fromSeq uint64) ([]uint64, error) {
	if s.anchor == nil {
		return nil, fmt.Errorf("agentruntime: store has no anchor log")
	}
	events, _, err := s.Load(turnID)
	if err != nil {
		return nil, err
	}
	var indices []uint64
	for i := fromSeq; i < uint64(len(events)); i++ {
		h, err := HashEvent(&events[i])
		if err != nil {
			return nil, err
		}
		raw, err := hex.DecodeString(strings.TrimPrefix(h, sha256Prefix))
		if err != nil {
			return nil, &InfraError{Op: "decode event hash for anchor", Err: err}
		}
		idx, err := s.anchor.Append(raw)
		if err != nil {
			return indices, &InfraError{Op: "anchor event hash", Err: err}
		}
		indices = append(indices, idx)
	}
	return indices, nil
}

// loadLocked reads and verifies a turn log file. A missing file is an
// empty log. Any malformed line, non-canonical encoding, broken hash
// chain, turn-ID drift relative to the file name, or reducer-illegal
// sequence is a hard error.
func (s *Store) loadLocked(path, turnID string) ([]Event, *State, string, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is derived from the store dir and a validated turn ID
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, "", nil
		}
		return nil, nil, "", &InfraError{Op: "read turn log", Err: err}
	}
	if len(data) == 0 {
		return nil, nil, "", nil
	}
	if data[len(data)-1] != '\n' {
		return nil, nil, "", fmt.Errorf("agentruntime: corrupt turn log %s: final line is not newline-terminated (truncated write?)", path)
	}
	lines := strings.Split(string(data[:len(data)-1]), "\n")
	events := make([]Event, 0, len(lines))
	prevHash := ""
	for i, line := range lines {
		ev, err := decodeCanonicalLine(line)
		if err != nil {
			return nil, nil, "", fmt.Errorf("agentruntime: corrupt turn log %s at line %d: %w", path, i+1, err)
		}
		if ev.TurnID != turnID {
			return nil, nil, "", fmt.Errorf("agentruntime: corrupt turn log %s at line %d: event names turn %q, not %q", path, i+1, ev.TurnID, turnID)
		}
		if err := ev.Validate(); err != nil {
			return nil, nil, "", fmt.Errorf("agentruntime: corrupt turn log %s at line %d: %w", path, i+1, err)
		}
		if ev.PrevHash != prevHash {
			return nil, nil, "", fmt.Errorf("agentruntime: corrupt turn log %s at line %d: hash chain broken", path, i+1)
		}
		h, err := HashEvent(&ev)
		if err != nil {
			return nil, nil, "", err
		}
		prevHash = h
		events = append(events, ev)
	}
	state, err := ReduceEvents(events)
	if err != nil {
		return nil, nil, "", fmt.Errorf("agentruntime: corrupt turn log %s: %w", path, err)
	}
	return events, state, prevHash, nil
}

// decodeCanonicalLine decodes one JSONL line and requires that the line
// is exactly the canonical form of the decoded event: unknown fields,
// non-canonical key order, or cosmetic whitespace all fail loudly, so the
// stored bytes are always the hashed bytes.
func decodeCanonicalLine(line string) (Event, error) {
	var ev Event
	dec := json.NewDecoder(strings.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ev); err != nil {
		return Event{}, fmt.Errorf("invalid event JSON: %w", err)
	}
	canon, err := CanonicalBytes(&ev)
	if err != nil {
		return Event{}, err
	}
	if string(canon) != line {
		return Event{}, fmt.Errorf("line is not in canonical form")
	}
	return ev, nil
}
