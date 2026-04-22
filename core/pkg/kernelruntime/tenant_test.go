package kernelruntime

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/interfaces"
)

type mockEventRepo struct{}

func (m *mockEventRepo) Append(ctx context.Context, eventType string, actorID string, payload interface{}) (*interfaces.Event, error) {
	return &interfaces.Event{
		SequenceID: 1,
		EventType:  eventType,
		ActorID:    actorID,
	}, nil
}

func (m *mockEventRepo) ReadFrom(ctx context.Context, startSequenceID int64, limit int) ([]interfaces.Event, error) {
	return nil, nil // Not used
}

func TestTenantSovereignty_I5(t *testing.T) {
	// Mock dependencies
	mockRepo := &mockEventRepo{}

	// Create runtime with mock
	// Note: We use the constructor or struct literal if allowed.
	// Since fields are unexported in Runtime, we should use NewRuntime or rely on same-package access.
	// We are in 'kernelruntime' package, so we can access unexported fields!
	// Setup KeyRing/Signer
	keyring := crypto.NewKeyRing()
	signer, _ := crypto.NewEd25519Signer("tester-key")
	keyring.AddKey(signer)

	// Create runtime with mock and keyring
	runtime := &Runtime{
		eventRepo: mockRepo,
		keyring:   keyring,
	}

	// Helper to sign intent
	sign := func(i *SignedIntent) *SignedIntent {
		i.ActorID = "tester-key" // Must match keyID in keyring for verification

		// Ensure Payload is non-nil if empty
		if i.Payload == nil {
			i.Payload = []byte("{}")
		}

		sigHex, _ := signer.Sign(i.Payload)
		sigBytes, _ := hex.DecodeString(sigHex)
		i.Signature = sigBytes
		return i
	}

	tests := []struct {
		name        string
		intent      *SignedIntent
		errContains string
	}{
		{
			name:        "MissingContext",
			intent:      sign(&SignedIntent{}),
			errContains: "missing actor context",
		},
		{
			name: "MissingTenantBinding",
			intent: sign(&SignedIntent{
				Context: &ActorContext{TenantID: "tenant-a"},
			}),
			errContains: "missing tenant_id binding",
		},
		{
			name: "TenantMismatch",
			intent: sign(&SignedIntent{
				TenantID: "tenant-b",
				Context:  &ActorContext{TenantID: "tenant-a"},
			}),
			errContains: "tenant_id mismatch",
		},
		{
			name: "ValidSovereignty",
			intent: sign(&SignedIntent{
				TenantID: "tenant-a",
				Context:  &ActorContext{TenantID: "tenant-a"},
			}),
			errContains: "", // Should succeed now!
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := runtime.SubmitIntent(context.Background(), tt.intent)
			if tt.errContains != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.errContains)
				}
				if !contains(err.Error(), tt.errContains) {
					t.Errorf("expected error containing %q, got %q", tt.errContains, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("expected success, got error: %v", err)
				}
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && search(s, substr)
}

func search(s, substr string) bool {
	// Simple containment check
	for i := 0; i < len(s)-len(substr)+1; i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			if s[i+j] != substr[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
