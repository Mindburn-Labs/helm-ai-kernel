package kernelruntime

import (
	"context"
	"fmt"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/interfaces"
)

// Runtime is the concrete implementation of the Kernel.
type Runtime struct {
	eventRepo interfaces.EventRepository
	projEng   interfaces.ProjectionEngine
	keyring   *crypto.KeyRing // Trusted keys for verification
}

func NewRuntime(
	eventRepo interfaces.EventRepository,
	projEng interfaces.ProjectionEngine,
	keyring *crypto.KeyRing,
) *Runtime {
	return &Runtime{
		eventRepo: eventRepo,
		projEng:   projEng,
		keyring:   keyring,
	}
}

func (r *Runtime) SubmitIntent(ctx context.Context, intent *SignedIntent) (*Receipt, error) {
	// 1. Verify Signature (Sovereign Barrier Enforced)
	// We verify that the payload was signed by the ActorID's registered public key.
	// NOTE: For MVP, we assume ActorID maps to a KeyID in the Keyring.
	// In production, this runs against a Tenant Identity Provider.
	if r.keyring != nil {
		valid, err := r.keyring.VerifyKey(intent.ActorID, intent.Payload, intent.Signature)
		if err != nil {
			return nil, fmt.Errorf("signature verification error: %w", err)
		}
		if !valid {
			return nil, fmt.Errorf("sovereign barrier denial: invalid signature for actor %s", intent.ActorID)
		}
	} else {
		// Fail closed if no keyring configured (except in specifically flagged dev modes, which we don't support here)
		return nil, fmt.Errorf("sovereign barrier error: runtime keyring not initialized")
	}

	// 2. Compile PRG (Stub for Node 8)
	// 2. Compile PRG (Stub for Node 8)
	// 3. Check Policy (Stub for Node 11)

	// I5 - Multi-tenant sovereignty Enforcement
	if intent.Context == nil {
		return nil, fmt.Errorf("kernel check failed: missing actor context (I5)")
	}
	if intent.TenantID == "" {
		return nil, fmt.Errorf("kernel check failed: missing tenant_id binding (I5)")
	}
	if intent.TenantID != intent.Context.TenantID {
		return nil, fmt.Errorf("kernel sovereignty violation: tenant_id mismatch (bound: %s, context: %s) (I5)", intent.TenantID, intent.Context.TenantID)
	}

	// Calculate ActorContext canonical hash for audit binding
	ctxHash, err := intent.Context.CanonicalHash()
	if err != nil {
		return nil, fmt.Errorf("kernel check failed: context canonicalization error: %w", err)
	}
	_ = ctxHash // Will be utilized in DecisionRecord binding in Node 9

	// 4. Persistence (Node 4)
	// For now, we simply log the "IntentSubmitted" event to prove integration.
	ev, err := r.eventRepo.Append(ctx, "IntentSubmitted", intent.ActorID, map[string]interface{}{
		"intent_blob_size": len(intent.Payload),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to persist intent: %w", err)
	}

	// Return Receipt
	return &Receipt{
		ID:        fmt.Sprintf("rcpt-intent-%d", ev.SequenceID),
		TenantID:  intent.TenantID,
		Status:    "ACCEPTED",
		Timestamp: ev.Timestamp.UnixNano(),
	}, nil
}

func (r *Runtime) Query(ctx context.Context, query *QueryRequest) (*QueryResult, error) {
	// In the future this routers to specific projections.
	// For Node 7, we just acknowledge wiring.
	if query.Projection == "health" {
		return &QueryResult{Data: "OK"}, nil
	}
	return nil, fmt.Errorf("unknown projection: %s", query.Projection)
}

func (r *Runtime) CheckHealth(ctx context.Context) error {
	// Verify connections to DB, etc.
	return nil
}
