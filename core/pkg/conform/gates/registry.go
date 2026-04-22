// Package gates provides the gate implementations and a default registry.
package gates

import "github.com/Mindburn-Labs/helm-oss/core/pkg/conform"

// DefaultEngine returns a conformance engine pre-loaded with all gates
// in canonical registration order (G0 → G12, G13–G15 L3, GX extensions).
// This is the standard way to create an engine for CLI or CI usage.
func DefaultEngine() *conform.Engine {
	e := conform.NewEngine()

	// L1/L2 core gates
	e.RegisterGate(&G0BuildIdentity{})
	e.RegisterGate(&G1ProofReceipts{})
	e.RegisterGate(&G2Replay{})
	e.RegisterGate(&G2ASchemaFirst{})
	e.RegisterGate(&G3Policy{})
	e.RegisterGate(&G3ABudget{})
	e.RegisterGate(&G4Secrets{})
	e.RegisterGate(&G5ToolTrust{})
	e.RegisterGate(&G6Taint{})
	e.RegisterGate(&G7Incident{})
	e.RegisterGate(&G8HITL{})
	e.RegisterGate(&G9Jurisdiction{})
	e.RegisterGate(&G11Operability{})
	e.RegisterGate(&G12SupplyChain{})

	// L3 gates (higher assurance)
	e.RegisterGate(&G13HSM{})
	e.RegisterGate(&G14BundleIntegrity{})
	e.RegisterGate(&G15Condensation{})

	// Extension gates
	e.RegisterGate(&GXTenantIsolation{})
	e.RegisterGate(&GXEnvelopeBound{})
	e.RegisterGate(&GXSDKDrift{})
	e.RegisterGate(&GXThreatScan{})
	e.RegisterGate(&GXDelegation{})

	return e
}
