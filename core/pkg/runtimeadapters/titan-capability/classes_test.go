package titancapability

import (
	"context"
	"errors"
	"testing"
)

func TestPhase1Adapters_StableOrderAndCount(t *testing.T) {
	got := Phase1Adapters()
	if len(got) != 5 {
		t.Fatalf("expected 5 Phase-1 adapters, got %d", len(got))
	}
	want := []CapabilityClass{
		ClassModelChange,
		ClassFactorPromote,
		ClassDataSourceActivate,
		ClassFeatureRead,
		ClassMarketDataStream,
	}
	for i, a := range got {
		if a.Class() != want[i] {
			t.Errorf("Phase1Adapters()[%d].Class() = %q, want %q", i, a.Class(), want[i])
		}
	}
}

func TestModelChangeAdapter_AllowedKindsAccepted(t *testing.T) {
	a := ModelChangeAdapter{}
	for _, kind := range ModelChangeArtifactKinds {
		t.Run(kind, func(t *testing.T) {
			h := validHeader()
			h.ArtifactKind = kind
			if err := a.Validate(context.Background(), validEnvelope(), h); err != nil {
				t.Fatalf("kind %q expected ALLOW, got %v", kind, err)
			}
		})
	}
}

func TestModelChangeAdapter_RejectsForbiddenKind(t *testing.T) {
	a := ModelChangeAdapter{}
	h := validHeader()
	h.ArtifactKind = "factor_neural" // wrong class
	err := a.Validate(context.Background(), validEnvelope(), h)
	if !errors.Is(err, ErrUnknownArtifactKind) {
		t.Fatalf("expected ErrUnknownArtifactKind, got %v", err)
	}
}

func TestFactorPromoteAdapter_RequiresValidationReport(t *testing.T) {
	a := FactorPromoteAdapter{}
	h := validHeader()
	h.ArtifactKind = "factor_canonical"
	h.ValidationReportSHA = "" // missing
	err := a.Validate(context.Background(), validEnvelope(), h)
	if !errors.Is(err, ErrEvidencePackInvalid) {
		t.Fatalf("expected ErrEvidencePackInvalid (missing validation report), got %v", err)
	}
}

func TestFactorPromoteAdapter_HappyPath(t *testing.T) {
	a := FactorPromoteAdapter{}
	h := validHeader()
	h.ArtifactKind = "factor_gp_mined"
	h.ValidationReportSHA = "sha256:cpcv-pbo-dsr-report"
	if err := a.Validate(context.Background(), validEnvelope(), h); err != nil {
		t.Fatalf("expected ALLOW, got %v", err)
	}
}

func TestDataSourceActivateAdapter_AllKindsCovered(t *testing.T) {
	a := DataSourceActivateAdapter{}
	for _, kind := range DataSourceActivateArtifactKinds {
		t.Run(kind, func(t *testing.T) {
			h := validHeader()
			h.ArtifactKind = kind
			if err := a.Validate(context.Background(), validEnvelope(), h); err != nil {
				t.Fatalf("kind %q expected ALLOW, got %v", kind, err)
			}
		})
	}
}

func TestFeatureReadAdapter_EnvelopeOnly(t *testing.T) {
	a := FeatureReadAdapter{}
	// Header completely empty — read-side adapter ignores it.
	if err := a.Validate(context.Background(), validEnvelope(), EvidencePackHeader{}); err != nil {
		t.Fatalf("expected ALLOW with empty header, got %v", err)
	}
}

func TestFeatureReadAdapter_RejectsBadEnvelope(t *testing.T) {
	a := FeatureReadAdapter{}
	env := validEnvelope()
	env.OrganID = ""
	err := a.Validate(context.Background(), env, EvidencePackHeader{})
	if !errors.Is(err, ErrEnvelopeIncomplete) {
		t.Fatalf("expected ErrEnvelopeIncomplete, got %v", err)
	}
}

func TestMarketDataStreamAdapter_EnvelopeOnly(t *testing.T) {
	a := MarketDataStreamAdapter{}
	if err := a.Validate(context.Background(), validEnvelope(), EvidencePackHeader{}); err != nil {
		t.Fatalf("expected ALLOW with empty header, got %v", err)
	}
}

func TestMarketDataStreamAdapter_RejectsBadEnvelope(t *testing.T) {
	a := MarketDataStreamAdapter{}
	env := validEnvelope()
	env.Mode = Mode("bogus")
	err := a.Validate(context.Background(), env, EvidencePackHeader{})
	if !errors.Is(err, ErrEnvelopeIncomplete) {
		t.Fatalf("expected ErrEnvelopeIncomplete, got %v", err)
	}
}
