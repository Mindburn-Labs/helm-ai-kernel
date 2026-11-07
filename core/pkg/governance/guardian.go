// quantum_posture: Guardian decision signatures use classical Ed25519 and do not provide post-quantum assurance.
package governance

import (
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

// Guardian is the governance-level authorization gateway. It combines a PolicyEngine
// (CEL-based policy evaluation) with an Ed25519 signer to produce signed DecisionRecords.
// Fail-closed: if policy evaluation errors or the expression is not satisfied, the
// verdict is DENY.
type Guardian struct {
	signer *crypto.Ed25519Signer
	engine *PolicyEngine
}
