// Package gates provides the gate implementations and a default registry.
package gates

import "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/conform"

// DefaultEngine returns a conformance engine with the one gate that still runs:
// G0, build identity. The release pipeline signs a G0 report
// (`make conformance-release-report`). G1–G15 and the GX gates were retired in
// HELM-756: no EvidencePack could pass G1 and G7 together (audit 08-01), and
// several gates passed vacuously or by probing an in-process library.
func DefaultEngine() *conform.Engine {
	e := conform.NewEngine()
	e.RegisterGate(&G0BuildIdentity{})
	return e
}
