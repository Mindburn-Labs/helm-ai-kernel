package runtime

import (
	"io"
	"testing"
)

// K7 is opt-in: selecting a worker address must not change the main listener.
func TestWorkerListenerCanBeSelectedExplicitly(t *testing.T) {
	if _, err := parseServeFlags([]string{"--worker-listen", "127.0.0.1:8444"}, io.Discard); err != nil {
		t.Fatalf("explicit worker listener rejected: %v", err)
	}
}
