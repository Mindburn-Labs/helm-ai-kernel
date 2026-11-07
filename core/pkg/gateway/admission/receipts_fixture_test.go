package admission

// quantum_posture: signs a fixed-seed classical Ed25519 receipt chain for the
// receiptverify frozen fixture; no post-quantum claim.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/receiptverify"
)

// frozenGatewayChainFile is the gateway receipt chain receiptverify keeps
// verifying (TestFrozenGatewayChainStillVerifies): it pins receipt.v5 gateway
// receipts and helm.gateway.receipt-binding.v1 for the move to the next
// envelope (helm-tracker#53).
var frozenGatewayChainFile = filepath.Join("..", "..", "receiptverify", "testdata", "frozen-gateway-chain.json")

// envRegenerateFrozenGatewayChain, set to 1, rewrites the fixture instead of
// comparing it. Regenerate only when the fixture is added; a change to what a
// gateway receipt signs is a new binding version (R12), not a new fixture.
const envRegenerateFrozenGatewayChain = "HELM_REGENERATE_FROZEN_GATEWAY_CHAIN"

// frozenGatewaySigner is the fixture's fixed key: the Ed25519 seed 0x40..0x5f.
func frozenGatewaySigner(t *testing.T) *crypto.Ed25519Signer {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(0x40 + i)
	}
	signer, err := crypto.NewEd25519SignerFromSeed(seed, "helm-gateway-frozen-fixture")
	must(t, err)
	return signer
}

// frozenGatewayDecisions are three decisions of one workspace, in chain
// order: an escalation, a denial of another attempt, and the re-admission of
// the escalated attempt after a step-up approval.
func frozenGatewayDecisions() []storedDecision {
	escalated := sampleDecision()
	escalated.Version, escalated.State, escalated.ReasonCode = 2, "ESCALATED", "APPROVAL_REQUIRED"
	escalated.PermitID, escalated.RiskClass = "", "high"
	escalated.ApprovalDigest = sum256("approval")
	expires := time.Date(2030, 1, 2, 4, 4, 5, 0, time.UTC)
	escalated.ApprovalExpiresAt = &expires

	denied := sampleDecision()
	denied.AttemptID, denied.Version = "0190a5b4-0000-7000-8000-000000000002", 2
	denied.State, denied.ReasonCode, denied.PermitID = "DENIED", "EFFECT_OUT_OF_SCOPE", ""
	denied.RequestDigest, denied.ArgumentDigest = sum256("request-2"), sum256(`{"text":"no"}`)
	denied.DecidedAt = escalated.DecidedAt.Add(time.Second)

	admitted := escalated
	admitted.Version, admitted.FromState, admitted.State, admitted.ReasonCode = 4, "ESCALATED", "ADMITTED", ""
	admitted.PermitID = samplePermit
	admitted.ApproverPrincipalID, admitted.ApproverActorID = "human-b", actor
	admitted.StepUpIssuer, admitted.StepUpJTI = "https://issuer.example", "step-up-jti-1"
	admitted.DecidedAt = escalated.DecidedAt.Add(2 * time.Second)
	return []storedDecision{escalated, denied, admitted}
}

// frozenGatewayChain signs the fixture decisions with the gateway's own
// builder and sealer and encodes them as an export bundle, plus the public
// key a test passes as its trust root (the bundle's own key is never trusted).
func frozenGatewayChain(t *testing.T) ([]byte, []SignedReceipt) {
	t.Helper()
	signer := frozenGatewaySigner(t)
	ids := []string{"0190a5b4-0000-7000-8000-0000000000f1", "0190a5b4-0000-7000-8000-0000000000f2", "0190a5b4-0000-7000-8000-0000000000f3"}
	var stored []SignedReceipt
	prev := ""
	for i, d := range frozenGatewayDecisions() {
		r, binding, err := buildDecisionReceipt(d, ids[i], uint64(i+1), prev)
		must(t, err)
		envelope, digest, err := sealReceipt(signer, r)
		must(t, err)
		stored = append(stored, SignedReceipt{Ref: ReceiptRef{ReceiptID: ids[i]}, Envelope: envelope, Binding: binding})
		prev = digest
	}
	bundle, err := encodeReceiptBundle(stored)
	must(t, err)
	var document map[string]json.RawMessage
	must(t, json.Unmarshal(bundle, &document))
	key, err := json.Marshal(signer.PublicKey())
	must(t, err)
	document["public_key_hex"] = key
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	must(t, encoder.Encode(document))
	return out.Bytes(), stored
}

// TestFrozenGatewayChainIsWhatTheBuilderSigns: the committed gateway chain is
// what this builder signs today, field for field and binding byte for byte.
// The fixture's own verification is receiptverify's
// TestFrozenGatewayChainStillVerifies, which never regenerates it.
func TestFrozenGatewayChainIsWhatTheBuilderSigns(t *testing.T) {
	document, stored := frozenGatewayChain(t)
	if os.Getenv(envRegenerateFrozenGatewayChain) == "1" {
		must(t, os.WriteFile(frozenGatewayChainFile, document, 0o600))
		t.Logf("wrote %s", frozenGatewayChainFile)
		return
	}
	raw, err := os.ReadFile(frozenGatewayChainFile)
	must(t, err)
	frozen, err := receiptverify.ParseBundle(raw)
	must(t, err)
	if len(frozen.Receipts) != len(stored) || len(frozen.GatewayBindings) != len(stored) {
		t.Fatalf("frozen chain holds %d receipts and %d bindings, want %d", len(frozen.Receipts), len(frozen.GatewayBindings), len(stored))
	}
	for i, s := range stored {
		fresh, err := receiptverify.ParseBundle(s.Envelope)
		must(t, err)
		got, want := frozen.Receipts[i], fresh.Receipts[0]
		if got.ReceiptID != want.ReceiptID || got.DecisionID != want.DecisionID || got.EffectID != want.EffectID ||
			got.Status != want.Status || got.OutputHash != want.OutputHash || got.PrevHash != want.PrevHash ||
			got.LamportClock != want.LamportClock || got.ArgsHash != want.ArgsHash || got.Verdict != want.Verdict ||
			got.ReasonCode != want.ReasonCode || got.PolicyHash != want.PolicyHash || got.SessionID != want.SessionID ||
			got.SignatureVersion != want.SignatureVersion || got.Signature != want.Signature || got.KeyID != want.KeyID {
			t.Errorf("receipt[%d]: the builder now signs %+v, the frozen chain holds %+v; a change to what a gateway receipt signs is a new binding version (R12)", i, want, got)
		}
		if !bytes.Equal(frozen.GatewayBindings[s.Ref.ReceiptID], s.Binding) {
			t.Errorf("receipt[%d]: the builder's binding differs from the frozen one:\n got %s\nwant %s", i, s.Binding, frozen.GatewayBindings[s.Ref.ReceiptID])
		}
	}
}
