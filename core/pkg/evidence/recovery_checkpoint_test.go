package evidence

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

type checkpointEvidenceVector struct {
	Descriptor       contracts.RecoveryCheckpointDescriptor `json:"descriptor"`
	Seed             string                                 `json:"test_seed_hex"`
	PublicKey        string                                 `json:"public_key_hex"`
	KeyID            string                                 `json:"key_id"`
	Payload          string                                 `json:"payload_base64"`
	PAE              string                                 `json:"pae_base64"`
	Signature        string                                 `json:"signature_base64"`
	Envelope         string                                 `json:"envelope_base64"`
	DescriptorDigest string                                 `json:"descriptor_digest"`
	EnvelopeDigest   string                                 `json:"envelope_digest"`
}

func checkpointEvidenceGolden(t testing.TB) checkpointEvidenceVector {
	t.Helper()
	raw, err := os.ReadFile("testdata/recovery-checkpoint.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v checkpointEvidenceVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}
func checkpointEvidenceBytes(t testing.TB, value string) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func checkpointEvidencePolicy(t testing.TB) RecoveryCheckpointVerificationPolicy {
	t.Helper()
	v := checkpointEvidenceGolden(t)
	key, err := hex.DecodeString(v.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return RecoveryCheckpointVerificationPolicy{KeyID: v.KeyID, PublicKey: ed25519.PublicKey(key), Purpose: contracts.RecoveryCheckpointPurpose, PayloadType: contracts.RecoveryCheckpointPayloadType, Expected: v.Descriptor, ValidFromUnix: 1, ValidUntilUnix: 10, VerifyAtUnix: 5}
}

func TestRecoveryCheckpointIndependentDSSEVectorAndReplay(t *testing.T) {
	v := checkpointEvidenceGolden(t)
	payload := checkpointEvidenceBytes(t, v.Payload)
	pae, err := RecoveryCheckpointPAE(payload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pae, checkpointEvidenceBytes(t, v.PAE)) {
		t.Fatal("PAE differs from independently byte-counted vector")
	}
	if utf8.RuneCount(payload) == len(payload) {
		t.Fatal("vector must exercise UTF-8 byte/rune difference")
	}
	seed, err := hex.DecodeString(v.Seed)
	if err != nil {
		t.Fatal(err)
	}
	private := ed25519.NewKeyFromSeed(seed)
	signature := ed25519.Sign(private, pae)
	if !bytes.Equal(signature, checkpointEvidenceBytes(t, v.Signature)) {
		t.Fatal("signature differs from independent OpenSSL vector")
	}
	envelope, err := NewRecoveryCheckpointEnvelope(payload, v.KeyID, signature)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(envelope, checkpointEvidenceBytes(t, v.Envelope)) {
		t.Fatal("envelope differs from vector")
	}
	policy := checkpointEvidencePolicy(t)
	policy.FrozenEnvelopeDigest = v.EnvelopeDigest
	for range 3 {
		verified, err := VerifyRecoveryCheckpointEnvelope(envelope, policy)
		if err != nil {
			t.Fatal(err)
		}
		if verified.DescriptorDigest != v.DescriptorDigest || verified.EnvelopeDigest != v.EnvelopeDigest || verified.SnapshotDigest != v.Descriptor.Snapshot.Digest || !bytes.Equal(verified.PayloadBytes, payload) || !bytes.Equal(verified.EnvelopeBytes, envelope) {
			t.Fatal("verified bytes/digests changed")
		}
	}
	verified, err := VerifyRecoveryCheckpointEnvelope(envelope, policy)
	if err != nil {
		t.Fatal(err)
	}
	envelope[0] = ' '
	if verified.EnvelopeBytes[0] != '{' {
		t.Fatal("returned bytes alias caller memory")
	}
}

func TestRecoveryCheckpointSignsExactPayloadNotReserializedValue(t *testing.T) {
	v := checkpointEvidenceGolden(t)
	payload := checkpointEvidenceBytes(t, v.Payload)
	pretty := append([]byte(" \n"), payload...)
	pae, err := RecoveryCheckpointPAE(pretty)
	if err != nil {
		t.Fatal(err)
	}
	seed, _ := hex.DecodeString(v.Seed)
	signature := ed25519.Sign(ed25519.NewKeyFromSeed(seed), pae)
	envelope, err := NewRecoveryCheckpointEnvelope(pretty, v.KeyID, signature)
	if err != nil {
		t.Fatal(err)
	}
	policy := checkpointEvidencePolicy(t)
	verified, err := VerifyRecoveryCheckpointEnvelope(envelope, policy)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(verified.PayloadBytes, pretty) || verified.DescriptorDigest == v.DescriptorDigest {
		t.Fatal("verified a reserialized substitute")
	}
	var object contracts.RecoveryCheckpointEnvelope
	if err := json.Unmarshal(envelope, &object); err != nil {
		t.Fatal(err)
	}
	object.Payload = base64.StdEncoding.EncodeToString(payload)
	changed, _ := json.Marshal(object)
	if _, err := VerifyRecoveryCheckpointEnvelope(changed, policy); err == nil {
		t.Fatal("signature accepted canonical substitute for signed bytes")
	}
	// DSSE does not sign its outer JSON formatting. A retained envelope hash
	// freezes it, including otherwise valid equivalent outer serialization.
	frozen := checkpointEvidencePolicy(t)
	frozen.FrozenEnvelopeDigest = v.EnvelopeDigest
	original := checkpointEvidenceBytes(t, v.Envelope)
	rewrapped := append([]byte("\n"), original...)
	if _, err := VerifyRecoveryCheckpointEnvelope(rewrapped, policy); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRecoveryCheckpointEnvelope(rewrapped, frozen); err == nil {
		t.Fatal("replay replaced frozen envelope bytes")
	}
}

func TestRecoveryCheckpointRefusesLegacyAndUnframedSignatures(t *testing.T) {
	v := checkpointEvidenceGolden(t)
	payload := checkpointEvidenceBytes(t, v.Payload)
	seed, _ := hex.DecodeString(v.Seed)
	private := ed25519.NewKeyFromSeed(seed)
	for _, wrongPreimage := range [][]byte{
		payload,
		[]byte(`{"domain":"HELM/PackLifecycleEvidence/v1","schema_version":"pack-lifecycle-evidence.v1","evidence_hash":"legacy"}`),
		[]byte(`{"effect_mode":"no_effect","production_authority":false}`),
	} {
		envelope, err := NewRecoveryCheckpointEnvelope(payload, v.KeyID, ed25519.Sign(private, wrongPreimage))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyRecoveryCheckpointEnvelope(envelope, checkpointEvidencePolicy(t)); err == nil {
			t.Fatal("legacy or unframed preimage gained checkpoint authority")
		}
	}
}

func TestRecoveryCheckpointExternalTrustPolicyRefusals(t *testing.T) {
	cases := map[string]func(*RecoveryCheckpointVerificationPolicy){
		"no_key":          func(p *RecoveryCheckpointVerificationPolicy) { p.PublicKey = nil },
		"wrong_key":       func(p *RecoveryCheckpointVerificationPolicy) { p.PublicKey = bytes.Repeat([]byte{1}, 32) },
		"wrong_hint":      func(p *RecoveryCheckpointVerificationPolicy) { p.KeyID = "another-key" },
		"missing_purpose": func(p *RecoveryCheckpointVerificationPolicy) { p.Purpose = "" },
		"legacy_purpose":  func(p *RecoveryCheckpointVerificationPolicy) { p.Purpose = "pack-lifecycle-evidence.v1" },
		"wrong_type":      func(p *RecoveryCheckpointVerificationPolicy) { p.PayloadType = "application/vnd.helm.receipt.v5+json" },
		"revoked":         func(p *RecoveryCheckpointVerificationPolicy) { p.Revoked = true },
		"expired":         func(p *RecoveryCheckpointVerificationPolicy) { p.VerifyAtUnix = 10 },
		"not_yet_valid":   func(p *RecoveryCheckpointVerificationPolicy) { p.VerifyAtUnix = 0 },
		"inverted_window": func(p *RecoveryCheckpointVerificationPolicy) { p.ValidFromUnix = 11 },
		"unbounded_window": func(p *RecoveryCheckpointVerificationPolicy) {
			p.ValidUntilUnix = contracts.RecoveryCheckpointMaxInteger + 1
		},
		"wrong_issuer": func(p *RecoveryCheckpointVerificationPolicy) { p.Expected.Producer.Issuer = "https://another.example" },
		"wrong_qualified_source": func(p *RecoveryCheckpointVerificationPolicy) {
			p.Expected.Producer.SourceRevision = strings.Repeat("a", 40)
			p.Expected.Installed.RuntimeComponents[1].SourceRevision = p.Expected.Producer.SourceRevision
		},
		"wrong_qualified_cohort": func(p *RecoveryCheckpointVerificationPolicy) {
			p.Expected.Producer.CohortDigest = contracts.RecoveryCheckpointHash([]byte("another full cohort"))
			p.Expected.Installed.CohortDigest = p.Expected.Producer.CohortDigest
		},
		"wrong_bound_producer_pod": func(p *RecoveryCheckpointVerificationPolicy) {
			p.Expected.Producer.PodUID = p.Expected.Scope.OperationID
			p.Expected.Installed.RuntimeComponents[1].PodUIDs = []string{p.Expected.Producer.PodUID}
		},
		"wrong_tenant": func(p *RecoveryCheckpointVerificationPolicy) {
			p.Expected.Scope.TenantID = p.Expected.Scope.WorkspaceID
		},
		"wrong_workspace": func(p *RecoveryCheckpointVerificationPolicy) {
			p.Expected.Scope.WorkspaceID = p.Expected.Scope.TenantID
		},
		"wrong_org": func(p *RecoveryCheckpointVerificationPolicy) {
			p.Expected.Scope.OrganizationID = p.Expected.Scope.OperationID
		},
		"wrong_operation": func(p *RecoveryCheckpointVerificationPolicy) {
			p.Expected.Scope.OperationID = p.Expected.Scope.OrganizationID
		},
		"wrong_generation":   func(p *RecoveryCheckpointVerificationPolicy) { p.Expected.Scope.Generation++ },
		"wrong_installation": func(p *RecoveryCheckpointVerificationPolicy) { p.Expected.Scope.InstallationID = "other-installation" },
		"wrong_native_plan": func(p *RecoveryCheckpointVerificationPolicy) {
			p.Expected.Native.PlanDigest = contracts.RecoveryCheckpointHash([]byte("wrong"))
		},
		"wrong_cutoff": func(p *RecoveryCheckpointVerificationPolicy) {
			p.Expected.Native.CutoffWatermark = contracts.RecoveryCheckpointHash([]byte("wrong"))
		},
		"wrong_snapshot": func(p *RecoveryCheckpointVerificationPolicy) {
			p.Expected.Snapshot.Digest = contracts.RecoveryCheckpointHash([]byte("wrong"))
		},
		"wrong_custody": func(p *RecoveryCheckpointVerificationPolicy) {
			p.Expected.Snapshot.CustodyID = p.Expected.Scope.OperationID
		},
		"wrong_lifecycle": func(p *RecoveryCheckpointVerificationPolicy) { p.Expected.Capture.OrganizationRowVersion++ },
		"wrong_console_source": func(p *RecoveryCheckpointVerificationPolicy) {
			p.Expected.Installed.Console.SourceRevision = strings.Repeat("a", 40)
		},
		"wrong_participant": func(p *RecoveryCheckpointVerificationPolicy) {
			p.Expected.Participants[2].ContentDigest = contracts.RecoveryCheckpointHash([]byte("wrong"))
		},
		"wrong_prefix": func(p *RecoveryCheckpointVerificationPolicy) { p.Expected.EvidencePrefix.Sequence++ },
		"wrong_frozen_envelope": func(p *RecoveryCheckpointVerificationPolicy) {
			p.FrozenEnvelopeDigest = contracts.RecoveryCheckpointHash([]byte("wrong"))
		},
	}
	wire := checkpointEvidenceBytes(t, checkpointEvidenceGolden(t).Envelope)
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := checkpointEvidencePolicy(t)
			mutate(&p)
			if _, err := VerifyRecoveryCheckpointEnvelope(wire, p); err == nil {
				t.Fatal("untrusted evidence accepted")
			}
		})
	}
}

func TestRecoveryCheckpointEnvelopeWireRefusals(t *testing.T) {
	v := checkpointEvidenceGolden(t)
	wire := checkpointEvidenceBytes(t, v.Envelope)
	cases := map[string][]byte{
		"empty": nil, "trailing": append(bytes.Clone(wire), []byte(` {}`)...),
		"duplicate":            bytes.Replace(wire, []byte(`"payload":`), []byte(`"payload":"AA==","payload":`), 1),
		"unknown_key":          bytes.Replace(wire, []byte(`"payload":`), []byte(`"public_key":"self-trusted","payload":`), 1),
		"unknown_signature":    bytes.Replace(wire, []byte(`"keyid":`), []byte(`"issuer":"self-trusted","keyid":`), 1),
		"wrong_case":           bytes.Replace(wire, []byte(`"payloadType":`), []byte(`"PayloadType":`), 1),
		"unsigned":             bytes.Replace(wire, []byte(`"signatures":[`), []byte(`"signatures":[],"ignored":[`), 1),
		"signature_corruption": bytes.Replace(wire, []byte(v.Signature[:10]), []byte("AAAAAAAAAA"), 1),
		"bad_utf8":             append([]byte{0xff}, wire...),
		"oversize":             bytes.Repeat([]byte{' '}, contracts.RecoveryCheckpointMaxEnvelopeBytes+1),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyRecoveryCheckpointEnvelope(raw, checkpointEvidencePolicy(t)); err == nil {
				t.Fatal("invalid envelope accepted")
			}
		})
	}
	mutations := map[string]func(*contracts.RecoveryCheckpointEnvelope){
		"wrong_type": func(e *contracts.RecoveryCheckpointEnvelope) { e.PayloadType = "application/vnd.helm.receipt.v5+json" },
		"no_signatures": func(e *contracts.RecoveryCheckpointEnvelope) {
			e.Signatures = []contracts.RecoveryCheckpointSignature{}
		},
		"multiple_signatures": func(e *contracts.RecoveryCheckpointEnvelope) { e.Signatures = append(e.Signatures, e.Signatures[0]) },
		"base64_newline":      func(e *contracts.RecoveryCheckpointEnvelope) { e.Payload += "\n" },
		"base64_unpadded": func(e *contracts.RecoveryCheckpointEnvelope) {
			e.Payload = strings.TrimRight(e.Payload, "=")
			if !strings.HasSuffix(e.Payload, "=") {
				e.Payload += "="
			}
		},
		"signature_newline": func(e *contracts.RecoveryCheckpointEnvelope) { e.Signatures[0].Signature += "\n" },
		"signature_length": func(e *contracts.RecoveryCheckpointEnvelope) {
			e.Signatures[0].Signature = base64.StdEncoding.EncodeToString([]byte("short"))
		},
		"signature_noncanonical_bits": func(e *contracts.RecoveryCheckpointEnvelope) {
			e.Signatures[0].Signature = e.Signatures[0].Signature[:85] + "B=="
		},
		"legacy_payload": func(e *contracts.RecoveryCheckpointEnvelope) {
			e.Payload = base64.StdEncoding.EncodeToString([]byte(`{"schema_version":"pack-lifecycle-evidence.v1"}`))
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			var envelope contracts.RecoveryCheckpointEnvelope
			_ = json.Unmarshal(wire, &envelope)
			mutate(&envelope)
			raw, _ := json.Marshal(envelope)
			if _, err := VerifyRecoveryCheckpointEnvelope(raw, checkpointEvidencePolicy(t)); err == nil {
				t.Fatal("invalid DSSE accepted")
			}
		})
	}
	if _, err := NewRecoveryCheckpointEnvelope(checkpointEvidenceBytes(t, v.Payload), v.KeyID, nil); err == nil {
		t.Fatal("empty signature construction accepted")
	}
	if _, err := NewRecoveryCheckpointEnvelope(checkpointEvidenceBytes(t, v.Payload), "https://untrusted/key", checkpointEvidenceBytes(t, v.Signature)); err == nil {
		t.Fatal("locator used as key hint")
	}
	if _, err := RecoveryCheckpointPAE([]byte(`{}`)); err == nil {
		t.Fatal("untyped PAE construction accepted")
	}
}

func FuzzRecoveryCheckpointEnvelope(f *testing.F) {
	v := checkpointEvidenceGolden(f)
	f.Add(checkpointEvidenceBytes(f, v.Envelope))
	f.Add([]byte(`{"signatures":null}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		verified, err := VerifyRecoveryCheckpointEnvelope(raw, checkpointEvidencePolicy(t))
		if err != nil {
			return
		}
		envelope, payload, signature, err := contracts.DecodeRecoveryCheckpointEnvelope(raw)
		if err != nil {
			t.Fatal(err)
		}
		rebuilt, err := NewRecoveryCheckpointEnvelope(payload, envelope.Signatures[0].KeyID, signature)
		if err != nil {
			t.Fatal(err)
		}
		round, err := VerifyRecoveryCheckpointEnvelope(rebuilt, checkpointEvidencePolicy(t))
		if err != nil || !reflect.DeepEqual(round.Descriptor, verified.Descriptor) {
			t.Fatal("verified envelope is not reconstructible")
		}
	})
}
