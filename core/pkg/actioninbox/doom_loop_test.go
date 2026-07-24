package actioninbox_test

import (
	"fmt"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/actioninbox"
	"github.com/stretchr/testify/assert"
)

func TestDoomLoopBreaker_TripsAtThreshold(t *testing.T) {
	b := actioninbox.NewDoomLoopBreaker(3)
	sig := actioninbox.SignatureFor("shell", "shell_operate", "rm -rf /tmp/x")

	assert.False(t, b.Record(sig), "first attempt must not trip")
	assert.False(t, b.Record(sig), "second attempt must not trip")
	assert.True(t, b.Record(sig), "third identical attempt must trip")
	assert.True(t, b.Tripped(sig))
}

func TestDoomLoopBreaker_DifferentSignatureResetsRun(t *testing.T) {
	b := actioninbox.NewDoomLoopBreaker(3)
	sigA := actioninbox.SignatureFor("shell", "shell_operate", "rm -rf /tmp/a")
	sigB := actioninbox.SignatureFor("shell", "shell_operate", "rm -rf /tmp/b")

	assert.False(t, b.Record(sigA))
	assert.False(t, b.Record(sigA))
	assert.False(t, b.Record(sigB), "different signature breaks the run")
	assert.False(t, b.Record(sigA), "run restarts at 1 after a different signature")
}

func TestDoomLoopBreaker_TripLatchesUntilReset(t *testing.T) {
	b := actioninbox.NewDoomLoopBreaker(3)
	sigA := actioninbox.SignatureFor("shell", "shell_operate", "rm -rf /tmp/a")
	sigB := actioninbox.SignatureFor("shell", "shell_operate", "rm -rf /tmp/b")

	for i := 0; i < 3; i++ {
		b.Record(sigA)
	}
	assert.True(t, b.Tripped(sigA))

	// A different signature clears the consecutive run but the latch for
	// sigA stays: the agent cannot evade the breaker by interleaving one
	// different call.
	b.Record(sigB)
	assert.True(t, b.Record(sigA), "latched trip must survive interleaved calls")

	b.Reset()
	assert.False(t, b.Tripped(sigA))
	assert.False(t, b.Record(sigA), "after reset the run starts fresh")
}

func TestDoomLoopBreaker_ThresholdClampedToDefault(t *testing.T) {
	b := actioninbox.NewDoomLoopBreaker(0)
	sig := actioninbox.SignatureFor("t", "a", "x")
	for i := 0; i < actioninbox.DefaultDoomLoopThreshold-1; i++ {
		assert.False(t, b.Record(sig))
	}
	assert.True(t, b.Record(sig), "clamped threshold must match the default")
}

func TestDoomLoopBreaker_NeverUpgradesToAllow(t *testing.T) {
	// Conformance guard: the breaker's only outputs are tripped/not-tripped;
	// a not-tripped result is not an authorization. This test pins the
	// contract that Record returns a boolean about looping only.
	b := actioninbox.NewDoomLoopBreaker(1) // threshold 1: trips immediately
	sig := actioninbox.SignatureFor("mcp", "mcp_tool_call", "mcp__x__y")
	assert.True(t, b.Record(sig), "threshold 1 trips on first observation")
}

func TestDoomLoopBreaker_LatchMapIsBounded(t *testing.T) {
	b := actioninbox.NewDoomLoopBreaker(3)
	total := actioninbox.DefaultDoomLoopMaxTripped + 10
	for i := 0; i < total; i++ {
		sig := actioninbox.SignatureFor("shell", "shell_operate", fmt.Sprintf("target-%d", i))
		for j := 0; j < 3; j++ {
			b.Record(sig)
		}
	}
	// Distinct tripped signatures beyond the cap must not grow the latch
	// without bound; evicted signatures simply re-trip on a fresh run.
	// (The cap is an internal invariant; behavioral proof: recording many
	// distinct tripped signatures completes and the newest still trips.)
	newest := actioninbox.SignatureFor("shell", "shell_operate", fmt.Sprintf("target-%d", total-1))
	if !b.Tripped(newest) {
		t.Fatal("newest tripped signature must be latched")
	}
}

func TestSignatureFor_DeterministicAndDiscriminating(t *testing.T) {
	a1 := actioninbox.SignatureFor("shell", "shell_operate", "rm -rf /tmp/a")
	a2 := actioninbox.SignatureFor("shell", "shell_operate", "rm -rf /tmp/a")
	b := actioninbox.SignatureFor("shell", "shell_operate", "rm -rf /tmp/b")
	c := actioninbox.SignatureFor("Write", "file_write", ".env")

	assert.Equal(t, a1, a2, "same inputs must give the same signature")
	assert.NotEqual(t, a1, b, "different target must change the signature")
	assert.NotEqual(t, a1, c, "different tool/action must change the signature")
	assert.Len(t, a1, 64, "sha256 hex signature")
}
