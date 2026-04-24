package evidence

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

func TestFinal_BundleTypeConstants(t *testing.T) {
	types := []BundleType{BundleTypeSOC2, BundleTypeIncident}
	if len(types) != 2 {
		t.Fatal("expected 2 bundle types")
	}
}

func TestFinal_BundleJSONRoundTrip(t *testing.T) {
	b := Bundle{ID: "b1", Type: BundleTypeSOC2, TraceID: "t1"}
	data, _ := json.Marshal(b)
	var got Bundle
	json.Unmarshal(data, &got)
	if got.ID != "b1" || got.Type != BundleTypeSOC2 {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_ArtifactJSONRoundTrip(t *testing.T) {
	a := Artifact{Name: "envelope_0", Hash: "sha256:abc"}
	data, _ := json.Marshal(a)
	var got Artifact
	json.Unmarshal(data, &got)
	if got.Name != "envelope_0" || got.Hash != "sha256:abc" {
		t.Fatal("artifact round-trip")
	}
}

func TestFinal_NewExporterNilSigner(t *testing.T) {
	e := NewExporter(nil, "")
	if e == nil {
		t.Fatal("nil exporter")
	}
}

func TestFinal_ExportSOC2NilSignerFails(t *testing.T) {
	e := NewExporter(nil, "")
	_, err := e.ExportSOC2(context.Background(), "t1", nil)
	if err == nil {
		t.Fatal("should fail without signer")
	}
}

func TestFinal_ExportIncidentNilSignerFails(t *testing.T) {
	e := NewExporter(nil, "")
	_, err := e.ExportIncidentReport(context.Background(), "t1", nil)
	if err == nil {
		t.Fatal("should fail without signer")
	}
}

func TestFinal_ComputeHashDeterministic(t *testing.T) {
	h1 := computeHash([]byte("data"))
	h2 := computeHash([]byte("data"))
	if h1 != h2 {
		t.Fatal("not deterministic")
	}
}

func TestFinal_ComputeHashPrefix(t *testing.T) {
	h := computeHash([]byte("test"))
	if h[:7] != "sha256:" {
		t.Fatal("missing prefix")
	}
}

func TestFinal_NewRegistry(t *testing.T) {
	r := NewRegistry()
	if r == nil {
		t.Fatal("nil registry")
	}
}

func TestFinal_ManifestVersionUnloaded(t *testing.T) {
	r := NewRegistry()
	if r.ManifestVersion() != "unloaded" {
		t.Fatal("should be unloaded")
	}
}

func TestFinal_LoadManifestNil(t *testing.T) {
	r := NewRegistry()
	err := r.LoadManifest(nil)
	if err == nil {
		t.Fatal("should error on nil")
	}
}

func TestFinal_LoadManifestSuccess(t *testing.T) {
	r := NewRegistry()
	m := &contracts.EvidenceContractManifest{
		Version:   "1.0",
		Contracts: []contracts.EvidenceContract{{ContractID: "c1", ActionClass: "DATA_WRITE"}},
	}
	err := r.LoadManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	if r.ManifestVersion() != "1.0" {
		t.Fatal("version mismatch")
	}
}

func TestFinal_LoadManifestEmptyActionClass(t *testing.T) {
	r := NewRegistry()
	m := &contracts.EvidenceContractManifest{
		Version:   "1.0",
		Contracts: []contracts.EvidenceContract{{ContractID: "c1", ActionClass: ""}},
	}
	err := r.LoadManifest(m)
	if err == nil {
		t.Fatal("should error on empty action class")
	}
}

func TestFinal_GetContractExists(t *testing.T) {
	r := NewRegistry()
	r.LoadManifest(&contracts.EvidenceContractManifest{
		Version:   "1.0",
		Contracts: []contracts.EvidenceContract{{ContractID: "c1", ActionClass: "DATA_WRITE"}},
	})
	c := r.GetContract("DATA_WRITE")
	if c == nil || c.ContractID != "c1" {
		t.Fatal("get contract failed")
	}
}

func TestFinal_GetContractMissing(t *testing.T) {
	r := NewRegistry()
	c := r.GetContract("NOPE")
	if c != nil {
		t.Fatal("should be nil")
	}
}

func TestFinal_CheckBeforeNoContract(t *testing.T) {
	r := NewRegistry()
	v, err := r.CheckBefore(context.Background(), "NOPE", nil)
	if err != nil || !v.Satisfied {
		t.Fatal("no contract should satisfy")
	}
}

func TestFinal_CheckAfterNoContract(t *testing.T) {
	r := NewRegistry()
	v, err := r.CheckAfter(context.Background(), "NOPE", nil)
	if err != nil || !v.Satisfied {
		t.Fatal("no contract should satisfy")
	}
}

func TestFinal_CheckBeforeMissingRequired(t *testing.T) {
	r := NewRegistry()
	r.LoadManifest(&contracts.EvidenceContractManifest{
		Version: "1.0",
		Contracts: []contracts.EvidenceContract{{
			ContractID:  "c1",
			ActionClass: "DATA_WRITE",
			Requirements: []contracts.EvidenceSpec{{
				EvidenceType: "receipt",
				Required:     true,
				When:         "before",
			}},
		}},
	})
	v, _ := r.CheckBefore(context.Background(), "DATA_WRITE", nil)
	if v.Satisfied {
		t.Fatal("should not be satisfied without evidence")
	}
}

func TestFinal_CheckBeforeSatisfied(t *testing.T) {
	r := NewRegistry()
	r.LoadManifest(&contracts.EvidenceContractManifest{
		Version: "1.0",
		Contracts: []contracts.EvidenceContract{{
			ContractID:  "c1",
			ActionClass: "DATA_WRITE",
			Requirements: []contracts.EvidenceSpec{{
				EvidenceType: "receipt",
				Required:     true,
				When:         "before",
			}},
		}},
	})
	subs := []contracts.EvidenceSubmission{{EvidenceType: "receipt", Verified: true}}
	v, _ := r.CheckBefore(context.Background(), "DATA_WRITE", subs)
	if !v.Satisfied {
		t.Fatal("should be satisfied with evidence")
	}
}

func TestFinal_WithClock(t *testing.T) {
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r := NewRegistry().WithClock(func() time.Time { return fixed })
	if r == nil {
		t.Fatal("nil after WithClock")
	}
}

func TestFinal_ComputeManifestHash(t *testing.T) {
	m := &contracts.EvidenceContractManifest{Version: "1.0"}
	h, err := ComputeManifestHash(m)
	if err != nil || h == "" {
		t.Fatal("hash failed")
	}
}

func TestFinal_ComputeManifestHashDeterministic(t *testing.T) {
	m := &contracts.EvidenceContractManifest{Version: "1.0"}
	h1, _ := ComputeManifestHash(m)
	h2, _ := ComputeManifestHash(m)
	if h1 != h2 {
		t.Fatal("not deterministic")
	}
}

func TestFinal_CheckAfterPhase(t *testing.T) {
	r := NewRegistry()
	r.LoadManifest(&contracts.EvidenceContractManifest{
		Version: "1.0",
		Contracts: []contracts.EvidenceContract{{
			ContractID:  "c1",
			ActionClass: "DATA_WRITE",
			Requirements: []contracts.EvidenceSpec{{
				EvidenceType: "receipt",
				Required:     true,
				When:         "after",
			}},
		}},
	})
	v, _ := r.CheckBefore(context.Background(), "DATA_WRITE", nil)
	if !v.Satisfied {
		t.Fatal("before check should pass for after-only requirement")
	}
}

func TestFinal_CheckBothPhase(t *testing.T) {
	r := NewRegistry()
	r.LoadManifest(&contracts.EvidenceContractManifest{
		Version: "1.0",
		Contracts: []contracts.EvidenceContract{{
			ContractID:  "c1",
			ActionClass: "DATA_WRITE",
			Requirements: []contracts.EvidenceSpec{{
				EvidenceType: "receipt",
				Required:     true,
				When:         "both",
			}},
		}},
	})
	v, _ := r.CheckBefore(context.Background(), "DATA_WRITE", nil)
	if v.Satisfied {
		t.Fatal("both phase should require evidence before")
	}
}

func TestFinal_IssuerConstraint(t *testing.T) {
	r := NewRegistry()
	r.LoadManifest(&contracts.EvidenceContractManifest{
		Version: "1.0",
		Contracts: []contracts.EvidenceContract{{
			ContractID:  "c1",
			ActionClass: "FUNDS_TRANSFER",
			Requirements: []contracts.EvidenceSpec{{
				EvidenceType:     "receipt",
				Required:         true,
				When:             "before",
				IssuerConstraint: "trusted-issuer",
			}},
		}},
	})
	subs := []contracts.EvidenceSubmission{{EvidenceType: "receipt", Verified: true, IssuerID: "wrong"}}
	v, _ := r.CheckBefore(context.Background(), "FUNDS_TRANSFER", subs)
	if v.Satisfied {
		t.Fatal("wrong issuer should not satisfy")
	}
}

func TestFinal_EvidenceVerdictContractID(t *testing.T) {
	r := NewRegistry()
	r.LoadManifest(&contracts.EvidenceContractManifest{
		Version: "1.0",
		Contracts: []contracts.EvidenceContract{{
			ContractID:  "c1",
			ActionClass: "TEST",
		}},
	})
	v, _ := r.CheckBefore(context.Background(), "TEST", nil)
	if v.ContractID != "c1" {
		t.Fatal("contract ID should be set")
	}
}

func TestFinal_EvidenceVerdictVerifiedAt(t *testing.T) {
	r := NewRegistry()
	v, _ := r.CheckBefore(context.Background(), "NOPE", nil)
	if v.VerifiedAt.IsZero() {
		t.Fatal("verified_at should be set")
	}
}
