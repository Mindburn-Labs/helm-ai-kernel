package replay

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

// ReplayHarness orchestrates the re-execution of a receipt.
type ReplayHarness struct {
	// Registry of available engines/adapters
	engines map[string]ReplayEngine
}

// ReplayEngine interface for components that can re-run an action.
type ReplayEngine interface {
	Replay(ctx context.Context, script *contracts.ReplayScriptRef) ([]byte, error)
}

func NewReplayHarness() *ReplayHarness {
	return &ReplayHarness{
		engines: make(map[string]ReplayEngine),
	}
}

func (h *ReplayHarness) RegisterEngine(name string, engine ReplayEngine) {
	h.engines[name] = engine
}

// VerifyReceipt attempts to reproduce the receipt's effect and verifies the output hash.
func (h *ReplayHarness) VerifyReceipt(ctx context.Context, receipt *contracts.Receipt) error {
	if receipt.ReplayScript == nil {
		return fmt.Errorf("receipt %s has no replay script", receipt.ReceiptID)
	}

	engine, ok := h.engines[receipt.ReplayScript.Engine]
	if !ok {
		return fmt.Errorf("unknown replay engine: %s", receipt.ReplayScript.Engine)
	}

	output, err := engine.Replay(ctx, receipt.ReplayScript)
	if err != nil {
		return fmt.Errorf("replay execution failed: %w", err)
	}

	// Verify Output Hash (Stub: In real impl, we'd hash the output and compare)
	hash := sha256.Sum256(output)
	computedHash := "sha256:" + hex.EncodeToString(hash[:])

	if receipt.OutputHash != "" && computedHash != receipt.OutputHash {
		return fmt.Errorf("replay mismatch: expected %s, got %s", receipt.OutputHash, computedHash)
	}

	return nil
}
