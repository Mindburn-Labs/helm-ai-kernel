package adapters

import (
	"fmt"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence/externalhost"
)

// init registers this package's per-vendor binding checkers with the verifier so
// that externalhost.VerifyChain can bind an imported receipt's normalized fields
// (tool name, target, agent id, args hash) to the vendor's signed payload.
//
// A binary that verifies Signet/AGT receipts must import this package (a blank
// import is sufficient) for these registrations to take effect; without them the
// verifier fail-closes on foreign receipts carrying these source_profiles.
func init() {
	externalhost.RegisterBindingChecker("signet-v4", func(payload []byte, r *contracts.ExternalHostReceipt) error {
		if r.ActionEvent == nil {
			return fmt.Errorf("signet: receipt has no action_event to bind")
		}
		return signetBindingCheck(payload, r.ActionEvent)
	})
	externalhost.RegisterBindingChecker("agt-cedar-v1", func(payload []byte, r *contracts.ExternalHostReceipt) error {
		if r.ActionEvent == nil {
			return fmt.Errorf("agt: receipt has no action_event to bind")
		}
		argsHash := strings.TrimPrefix(r.ActionEvent.ParamsHash, "sha256:")
		return agtBindingCheck(payload, r.ActionEvent, r.AgentID, argsHash)
	})
}
