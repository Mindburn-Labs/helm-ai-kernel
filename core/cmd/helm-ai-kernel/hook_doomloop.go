// quantum_posture: the advisory state uses classical SHA-256 hashes for
// session identifiers and tool-input signatures.

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/actioninbox"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

// hookDoomLoopFile is the on-disk circuit-breaker state for the pre-tool
// hook. The hook process is stateless between invocations, so the identical-
// denial run is persisted per session under the HELM data dir. The state is
// advisory evidence for the breaker only; losing it never weakens the base
// policy decision path, which remains fail-closed on its own.
type hookDoomLoopFile struct {
	Sessions map[string]*hookDoomLoopSession `json:"sessions"`
}

// hookDoomLoopSession tracks one session's consecutive-denial run. The trip
// latch is keyed per call signature (TrippedSignatures), never per session:
// a changed approach (different signature) is always evaluated fresh, while
// retrying an already-tripped identical call keeps the escalation steering.
type hookDoomLoopSession struct {
	LastSignature     string          `json:"last_signature"`
	RunLength         int             `json:"run_length"`
	TrippedSignatures map[string]bool `json:"tripped_signatures,omitempty"`
	TripCount         int             `json:"trip_count,omitempty"`
	LastTrippedAt     *time.Time      `json:"last_tripped_at,omitempty"`
	LastSeenAt        time.Time       `json:"last_seen_at"`
}

const (
	// hookDoomLoopStateTTL prunes idle sessions from the state file.
	hookDoomLoopStateTTL = 24 * time.Hour
	// hookDoomLoopMaxSessions bounds the state file (oldest LastSeenAt is
	// evicted first).
	hookDoomLoopMaxSessions = 128
	// hookDoomLoopMaxTrippedSignatures bounds the per-session latch map so
	// the persisted state cannot grow without bound. Eviction is
	// deterministic (lexicographically smallest signature); an evicted
	// signature simply re-trips after another threshold run of denials.
	hookDoomLoopMaxTrippedSignatures = 64
	// hookDoomLoopLockWait bounds how long a hook waits for the state lock
	// before giving up (the breaker is advisory; the policy path proceeds).
	hookDoomLoopLockWait = 2 * time.Second
	// hookDoomLoopMaxStateBytes bounds reads of locally tampered state.
	hookDoomLoopMaxStateBytes = 1 << 20
)

// hookSessionKey maps a client-supplied session ID to a fixed-size state
// key (sha256 hex). This bounds JSON map-key size regardless of ID length
// and keeps raw client identifiers out of the persisted state.
func hookSessionKey(sessionID string) string {
	sum := sha256.Sum256([]byte("helm-hook-doomloop-session\x00" + sessionID))
	return hex.EncodeToString(sum[:])
}

// recordDenied counts one final fail-closed denial for the signature and
// reports whether the breaker has latched for THIS signature, plus the current
// run length. A fully allowed hook outcome resets the run and never trips it.
func (s *hookDoomLoopSession) recordDenied(signature string, now time.Time) (bool, int) {
	if s.LastSignature == signature {
		s.RunLength++
	} else {
		s.LastSignature = signature
		s.RunLength = 1
	}
	if s.RunLength >= actioninbox.DefaultDoomLoopThreshold {
		if s.TrippedSignatures == nil {
			s.TrippedSignatures = map[string]bool{}
		}
		if !s.TrippedSignatures[signature] {
			if len(s.TrippedSignatures) >= hookDoomLoopMaxTrippedSignatures {
				// Bounded latch map: evict the deterministic victim
				// (smallest key). An evicted signature re-trips after
				// another threshold run of consecutive denials.
				victim := ""
				for k := range s.TrippedSignatures {
					if victim == "" || k < victim {
						victim = k
					}
				}
				delete(s.TrippedSignatures, victim)
			}
			s.TrippedSignatures[signature] = true
			s.TripCount++
			s.LastTrippedAt = &now
		}
	}
	return s.TrippedSignatures[signature], s.RunLength
}

// recordAllowed breaks the consecutive-denial run: a successful call means
// the agent is making progress, not looping. It never sets a latch.
func (s *hookDoomLoopSession) recordAllowed() {
	s.LastSignature = ""
	s.RunLength = 0
}

// recordHookDoomLoopOutcome records one final classified outcome (denied or
// allowed) for the session and reports whether the breaker has latched for
// this call signature. A signer/profile/receipt persistence failure is a final
// fail-closed denial and therefore counts. The read-modify-write is serialized
// with a lock file so concurrent hook processes cannot lose updates.
//
// Advisory note: the session ID is supplied by the agent client payload and
// is not authenticated — a client rotating session IDs could evade the
// breaker. The breaker is defense-in-depth UX steering on top of the
// authoritative fail-closed policy path, not a security boundary.
func recordHookDoomLoopOutcome(opts hookOptions, payload preToolPayload, classification hookClassification, denied bool, stderr io.Writer) (bool, int) {
	if strings.TrimSpace(opts.DataDir) == "" {
		// No local state dir (e.g. HOME-less environment): the breaker is
		// disabled rather than writing state into the caller's CWD.
		return false, 0
	}
	inputHash, err := canonicalize.CanonicalHash(payload.ToolInput)
	if err != nil {
		// Advisory state must never conflate an input it cannot identify.
		return false, 0
	}
	signature := actioninbox.SignatureFor(classification.ToolID, classification.Action, classification.Target+":"+inputHash)
	sessionID := strings.TrimSpace(payload.SessionID)
	if sessionID == "" {
		// No session identity: unrelated invocations must never share a
		// breaker bucket (a shared "_default" key would let one session's
		// denials falsely trip another's). Without a session ID the
		// breaker cannot attribute the run, so it stays out of the way —
		// same rule as DenyCascade: empty session never collides.
		return false, 0
	}
	// The session ID is client-supplied and unauthenticated; map it to a
	// fixed-size key so oversized IDs cannot bloat the persisted state
	// (keys are always 64 hex chars, preserving the bounded-state
	// guarantee) and raw client identifiers are never written to disk.
	sessionKey := hookSessionKey(sessionID)
	statePath := filepath.Join(opts.DataDir, "state", "hook-doomloop.json")
	unlock, ok := acquireHookDoomLoopLock(statePath+".lock", stderr)
	if !ok {
		return false, 0
	}
	defer unlock()

	now := hookNow()
	state := loadHookDoomLoopState(statePath, stderr)
	pruneHookDoomLoopSessions(state, now)
	sess, ok := state.Sessions[sessionKey]
	if !ok || sess == nil {
		if !denied {
			// No recorded run for this session and nothing to reset:
			// avoid creating breaker state for never-denied sessions.
			return false, 0
		}
		sess = &hookDoomLoopSession{}
		state.Sessions[sessionKey] = sess
	}
	sess.LastSeenAt = now
	var trippedB bool
	var runN int
	if denied {
		trippedB, runN = sess.recordDenied(signature, now)
	} else {
		sess.recordAllowed()
	}
	if err := saveHookDoomLoopState(statePath, state); err != nil {
		// Best-effort persistence: the base policy decision path is
		// unaffected and remains fail-closed; log and continue.
		fmt.Fprintf(stderr, "hook pre-tool: persist doom-loop state: %v\n", err)
	}
	return trippedB, runN
}

// pruneHookDoomLoopSessions drops sessions idle beyond the TTL and evicts
// the oldest sessions beyond the cap, keeping the state file bounded.
// Nil session entries (defensive: valid JSON can carry nulls) are dropped.
func pruneHookDoomLoopSessions(state *hookDoomLoopFile, now time.Time) {
	for id, sess := range state.Sessions {
		if sess == nil || sess.LastSeenAt.IsZero() || now.Sub(sess.LastSeenAt) > hookDoomLoopStateTTL {
			delete(state.Sessions, id)
		}
	}
	for len(state.Sessions) > hookDoomLoopMaxSessions {
		var oldestID string
		var oldest time.Time
		for id, sess := range state.Sessions {
			if sess == nil {
				oldestID = id
				break
			}
			if oldestID == "" || sess.LastSeenAt.Before(oldest) {
				oldestID, oldest = id, sess.LastSeenAt
			}
		}
		delete(state.Sessions, oldestID)
	}
}

// acquireHookDoomLoopLock takes the state lock as an OS-level advisory
// lock (flock / LockFileEx). The OS releases it on process exit, so a
// crashed holder can never leave a stale lock and no age-based reclaim can
// ever delete a live holder's lock. On contention past hookDoomLoopLockWait
// it reports ok=false; callers must treat the breaker update as skipped
// (advisory) and continue on the authoritative policy path.
func acquireHookDoomLoopLock(lockPath string, stderr io.Writer) (unlock func(), ok bool) {
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		fmt.Fprintf(stderr, "hook pre-tool: doom-loop lock dir: %v\n", err)
		return nil, false
	}
	unlock, held, err := hookDoomLoopFlock(lockPath, time.Now().Add(hookDoomLoopLockWait))
	if err != nil {
		fmt.Fprintf(stderr, "hook pre-tool: doom-loop lock: %v\n", err)
		return nil, false
	}
	if !held {
		fmt.Fprintf(stderr, "hook pre-tool: doom-loop state lock busy; skipping breaker update\n")
		return nil, false
	}
	return unlock, true
}

func loadHookDoomLoopState(path string, stderr io.Writer) *hookDoomLoopFile {
	state := &hookDoomLoopFile{Sessions: map[string]*hookDoomLoopSession{}}
	file, err := os.Open(path)
	if err != nil {
		if !os.IsNotExist(err) {
			fmt.Fprintf(stderr, "hook pre-tool: read doom-loop state: %v\n", err)
		}
		return state
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, hookDoomLoopMaxStateBytes+1))
	if err != nil {
		fmt.Fprintf(stderr, "hook pre-tool: read doom-loop state: %v\n", err)
		return state
	}
	if len(raw) > hookDoomLoopMaxStateBytes {
		fmt.Fprintf(stderr, "hook pre-tool: doom-loop state exceeds %d bytes, starting fresh\n", hookDoomLoopMaxStateBytes)
		return state
	}
	if err := json.Unmarshal(raw, state); err != nil {
		fmt.Fprintf(stderr, "hook pre-tool: doom-loop state unreadable, starting fresh: %v\n", err)
		return &hookDoomLoopFile{Sessions: map[string]*hookDoomLoopSession{}}
	}
	if state.Sessions == nil {
		fmt.Fprintln(stderr, "hook pre-tool: doom-loop state has no sessions map, starting fresh")
		return &hookDoomLoopFile{Sessions: map[string]*hookDoomLoopSession{}}
	}
	// Valid JSON can still carry null session values ("sessions":{"s":null});
	// drop them so no later traversal can dereference a nil session.
	for id, sess := range state.Sessions {
		if sess == nil {
			delete(state.Sessions, id)
		}
	}
	return state
}

func saveHookDoomLoopState(path string, state *hookDoomLoopFile) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".hook-doomloop-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err == nil {
		return nil
	} else if runtime.GOOS != "windows" {
		return err
	}
	// Windows rename does not replace an existing destination. The hook
	// state lock serializes writers; remove-and-rename is sufficient for
	// this advisory state file.
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.Rename(tmpName, path)
}
