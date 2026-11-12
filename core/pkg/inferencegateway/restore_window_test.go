package inferencegateway

import (
	"testing"
	"time"
)

// TestRestoredEnvelopeUseIsTheRecordedWindows (finding 2): a restart books a
// settlement's debit in the window its receipt names and closes exactly the
// windows it names, not the window of the time the line was written.
func TestRestoredEnvelopeUseIsTheRecordedWindows(t *testing.T) {
	h := newHarness(t, func(c *EngineConfig) { c.PlatformFeeBps = 0 })
	env := twoCentEnvelope()
	day := h.now                        // 2026-06-20
	written := day.Add(-24 * time.Hour) // a line recorded the day before
	h.ledger.RestoreEnvelopeUse(env, written, "2026-06-20", 2, nil)
	if consumed := h.ledger.envelopeConsumed(env, day); consumed != 2 {
		t.Fatalf("the restored debit is booked in another window: %d cents today", consumed)
	}
	h.ledger.RestoreEnvelopeUse(env, written, "", 0, []string{"2026-06-21"})
	if h.ledger.envelopeState(env, day).closed {
		t.Fatal("a window the receipt did not name was closed")
	}
	if !h.ledger.envelopeState(env, day.Add(24*time.Hour)).closed {
		t.Fatal("the named window was not closed")
	}
}
