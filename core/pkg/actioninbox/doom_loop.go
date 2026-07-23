package actioninbox

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
)

// DefaultDoomLoopThreshold matches the opencode DOOM_LOOP_THRESHOLD: three
// identical settled tool calls in a row is treated as a doom loop.
const DefaultDoomLoopThreshold = 3

// DoomLoopBreaker is a circuit breaker against agents retrying an identical
// call forever. After threshold consecutive identical signatures, it trips
// and stays tripped for that signature until a different signature is
// observed. Tripping only ever forces an ask/escalation; it never authorizes
// anything, so the breaker is fail-closed by construction.
//
// The zero value is unusable; construct via NewDoomLoopBreaker.
type DoomLoopBreaker struct {
	mu        sync.Mutex
	threshold int
	// tail holds the most recent consecutive identical-signature run.
	lastSignature string
	runLength     int
	tripped       map[string]bool
}

// NewDoomLoopBreaker creates a breaker that trips after threshold consecutive
// identical signatures. A threshold < 1 is clamped to DefaultDoomLoopThreshold
// (fail closed toward more protection, never less).
func NewDoomLoopBreaker(threshold int) *DoomLoopBreaker {
	if threshold < 1 {
		threshold = DefaultDoomLoopThreshold
	}
	return &DoomLoopBreaker{
		threshold: threshold,
		tripped:   make(map[string]bool),
	}
}

// SignatureFor builds a stable signature for a tool call. Callers should
// pass the normalized tool identity, action, and target; the signature binds
// all three so "identical call" means identical in everything that matters.
func SignatureFor(toolID, action, target string) string {
	sum := sha256.Sum256([]byte(toolID + "\x00" + action + "\x00" + target))
	return hex.EncodeToString(sum[:])
}

// Record observes one settled (or attempted, for pre-tool hooks) call with
// the given signature and reports whether the breaker is now tripped for it.
// Once tripped for a signature, Record keeps returning true for that
// signature until a different signature is recorded, which clears the
// consecutive run but leaves prior trips latched.
func (b *DoomLoopBreaker) Record(signature string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	if signature == b.lastSignature {
		b.runLength++
	} else {
		b.lastSignature = signature
		b.runLength = 1
	}
	if b.runLength >= b.threshold {
		b.tripped[signature] = true
	}
	return b.tripped[signature]
}

// Tripped reports whether the breaker has latched for the given signature,
// without recording a new observation.
func (b *DoomLoopBreaker) Tripped(signature string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.tripped[signature]
}

// Reset clears all latched trips and the consecutive-run state. Intended for
// explicit human/operator intervention (e.g. after an escalation is
// resolved), not for routine agent use.
func (b *DoomLoopBreaker) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.lastSignature = ""
	b.runLength = 0
	b.tripped = make(map[string]bool)
}
