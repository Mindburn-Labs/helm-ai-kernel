package replay_test

import (
	"context"
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/replay"
)

// MockReplayEngine implements replay.ReplayEngine for testing.
type MockReplayEngine struct{}

func (e *MockReplayEngine) Replay(ctx context.Context, script *contracts.ReplayScriptRef) ([]byte, error) {
	// Return a dummy output that hashes to "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" (empty string)
	return []byte{}, nil
}

func TestReplayIntegration(t *testing.T) {
	ctx := context.Background()

	// 2. Setup Replay Harness
	harness := replay.NewReplayHarness()
	harness.RegisterEngine("mock-engine", &MockReplayEngine{})

	// 4. Test Replay Verification
	// Create a dummy receipt with a replay script
	replayReceipt := &contracts.Receipt{
		ReceiptID: "rcpt-replay-test",
		ReplayScript: &contracts.ReplayScriptRef{
			Engine: "mock-engine",
		},
		// Empty string hash
		OutputHash: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	}

	err := harness.VerifyReceipt(ctx, replayReceipt)
	if err != nil {
		t.Fatalf("replay verification failed: %v", err)
	}
}
