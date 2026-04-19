package titancapability

import (
	"errors"
	"testing"
)

func validEnvelope() CapabilityEnvelope {
	return CapabilityEnvelope{
		PolicyBundleSHA:  "sha256:active-bundle",
		OrganID:          "research.bull.v1",
		SessionID:        "sess-0001",
		SpendCapUSD:      12.5,
		RetentionDays:    2555,
		JurisdictionHint: "US-DE",
		Mode:             ModePaper,
	}
}

func validHeader() EvidencePackHeader {
	return EvidencePackHeader{
		ArtifactSHA:         "sha256:f00dface",
		ArtifactKind:        "model",
		LineageSHA:          "sha256:1ineage",
		ValidationReportSHA: "sha256:cafef00d",
		PolicyBundleSHA:     "sha256:active-bundle",
		Signature:           "ed25519:0xabc",
	}
}

func TestValidateEnvelope_Happy(t *testing.T) {
	if err := ValidateEnvelope(validEnvelope(), "sha256:active-bundle"); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestValidateEnvelope_Incomplete(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*CapabilityEnvelope)
	}{
		{"empty bundle", func(e *CapabilityEnvelope) { e.PolicyBundleSHA = "" }},
		{"empty organ", func(e *CapabilityEnvelope) { e.OrganID = "" }},
		{"empty session", func(e *CapabilityEnvelope) { e.SessionID = "" }},
		{"negative spend", func(e *CapabilityEnvelope) { e.SpendCapUSD = -1 }},
		{"negative retention", func(e *CapabilityEnvelope) { e.RetentionDays = -1 }},
		{"unknown mode", func(e *CapabilityEnvelope) { e.Mode = Mode("foo") }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env := validEnvelope()
			c.mut(&env)
			err := ValidateEnvelope(env, "sha256:active-bundle")
			if !errors.Is(err, ErrEnvelopeIncomplete) {
				t.Fatalf("expected ErrEnvelopeIncomplete, got %v", err)
			}
		})
	}
}

func TestValidateEnvelope_BundleMismatch(t *testing.T) {
	env := validEnvelope()
	env.PolicyBundleSHA = "sha256:OLD"
	err := ValidateEnvelope(env, "sha256:active-bundle")
	if !errors.Is(err, ErrPolicyBundleMismatch) {
		t.Fatalf("expected ErrPolicyBundleMismatch, got %v", err)
	}
}

func TestValidateEvidencePack_Happy(t *testing.T) {
	if err := ValidateEvidencePack(validHeader(), []string{"model", "factor"}); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestValidateEvidencePack_RejectsUnknownKind(t *testing.T) {
	h := validHeader()
	h.ArtifactKind = "totally-not-a-thing"
	err := ValidateEvidencePack(h, []string{"model", "factor"})
	if !errors.Is(err, ErrUnknownArtifactKind) {
		t.Fatalf("expected ErrUnknownArtifactKind, got %v", err)
	}
}

func TestValidateEvidencePack_RejectsBadSHA(t *testing.T) {
	h := validHeader()
	h.ArtifactSHA = "not-a-sha"
	err := ValidateEvidencePack(h, []string{"model"})
	if !errors.Is(err, ErrEvidencePackInvalid) {
		t.Fatalf("expected ErrEvidencePackInvalid, got %v", err)
	}
}

func TestValidateEvidencePack_RejectsBadSignature(t *testing.T) {
	h := validHeader()
	h.Signature = "rsa:nope"
	err := ValidateEvidencePack(h, []string{"model"})
	if !errors.Is(err, ErrEvidencePackInvalid) {
		t.Fatalf("expected ErrEvidencePackInvalid, got %v", err)
	}
}

func TestCapabilityClassConstants_StableNamespace(t *testing.T) {
	cases := map[CapabilityClass]string{
		ClassTradeExecute:       "titan.trade_execute",
		ClassModelChange:        "titan.model_change",
		ClassFactorPromote:      "titan.factor_promote",
		ClassDataSourceActivate: "titan.data_source_activate",
		ClassFeatureRead:        "titan.feature_read",
		ClassMarketDataStream:   "titan.market_data_stream",
		ClassKillSwitch:         "titan.kill_switch",
	}
	for got, want := range cases {
		if string(got) != want {
			t.Errorf("class drift: got %q want %q", string(got), want)
		}
	}
}
