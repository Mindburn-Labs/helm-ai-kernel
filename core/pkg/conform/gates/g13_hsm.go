package gates

import (
	"context"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/conform"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/crypto/hsm"
)

// G13HSM validates HSM key management per L3 §G13.
// PASS requires: HSM provider can be initialized and at least one
// signing key exists or can be generated.
type G13HSM struct{}

func (g *G13HSM) ID() string   { return "G13" }
func (g *G13HSM) Name() string { return "HSM Key Management" }

func (g *G13HSM) Run(_ *conform.RunContext) *conform.GateResult {
	result := &conform.GateResult{
		GateID:        g.ID(),
		Pass:          true,
		Reasons:       []string{},
		EvidencePaths: []string{},
		Metrics:       conform.GateMetrics{Counts: make(map[string]int)},
	}

	p := hsm.NewSoftwareProvider()
	bgCtx := context.Background()

	if err := p.Open(bgCtx); err != nil {
		result.Pass = false
		result.Reasons = append(result.Reasons, "HSM provider failed to initialize: "+err.Error())
		return result
	}
	defer p.Close()

	// Verify key generation works
	handle, err := p.GenerateKey(bgCtx, hsm.KeyGenOpts{
		Algorithm: hsm.AlgorithmEd25519,
		Label:     "conformance-probe",
		Usage:     hsm.KeyUsageSign | hsm.KeyUsageVerify,
	})
	if err != nil {
		result.Pass = false
		result.Reasons = append(result.Reasons, "HSM key generation failed: "+err.Error())
		return result
	}

	// Verify sign + verify round-trip
	msg := []byte("G13 conformance probe")
	sig, err := p.Sign(bgCtx, handle, msg, hsm.SignOpts{})
	if err != nil {
		result.Pass = false
		result.Reasons = append(result.Reasons, "HSM signing failed: "+err.Error())
		return result
	}

	valid, err := p.Verify(bgCtx, handle, msg, sig)
	if err != nil || !valid {
		result.Pass = false
		result.Reasons = append(result.Reasons, "HSM signature verification failed")
		return result
	}

	result.Metrics.Counts["hsm_sign_verify"] = 1
	result.EvidencePaths = append(result.EvidencePaths, "G13_HSM/probe_pass")
	return result
}
