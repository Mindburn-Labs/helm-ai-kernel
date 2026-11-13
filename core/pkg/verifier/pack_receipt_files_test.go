// quantum_posture: these tests exercise the pack verifier's classical Ed25519
// receipt and seal checks only; they add no signature scheme and claim no
// hybrid or post-quantum protection.
package verifier

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	evidencepkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence"
)

// TestTeamPackCannotHideADeletedReceipt is helm-tracker#305 round 2 finding
// 1. The chain checks of the pack verifier decoded every receipt file into
// contracts.Receipt with encoding/json, which binds "PREV_HASH" to prev_hash
// and "Lamport_Clock" to lamport_clock, while the signature check and every
// exact-name reader take the members as spelled.
//
// A team-profile pack is sealed by an operator key the trust config names; its
// receipt.v5 receipts are signed by a runtime key the caller trusts out of
// band. The operator, who holds the seal key and not the runtime key, deletes
// the DENY in the middle of ALLOW, DENY, ALLOW, appends a letter-case
// "PREV_HASH" pointing at the first receipt and a "Lamport_Clock" of 2 to the
// last one, and re-seals. Every signature still verifies, because the signed
// prev_hash and lamport_clock are untouched; the chain checks read the
// shadows, saw an unbroken chain, and the pack was verified. A receipt file
// that spells a receipt member in another letter case is now refused before
// the chain checks read it.
//
// This test covers letter-case shadows and a member written twice;
// TestTeamPackCannotHideADeletedReceiptBehindAnUnsignedStandIn covers a file
// put in the deleted receipt's place. Both are about a deleted receipt that a
// signed receipt.v5 receipt in the pack names as its prev_hash. The chain
// checks do not see the last receipt of a chain deleted: the receipts left
// still link genesis-to-head.
func TestTeamPackCannotHideADeletedReceipt(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keyHex := hex.EncodeToString(pub)
	t.Setenv("HELM_EVIDENCE_TRUSTED_PUBLIC_KEY_HEX", keyHex)
	t.Setenv("HELM_ALLOW_SELF_ATTESTED_EVIDENCE", "")

	r1 := teamPackReceipt(t, priv, keyHex, "r1", 1, "", "ALLOW")
	h1 := teamPackChainHash(t, r1)
	r2 := teamPackReceipt(t, priv, keyHex, "r2", 2, h1, "DENY")
	h2 := teamPackChainHash(t, r2)
	r3 := teamPackReceipt(t, priv, keyHex, "r3", 3, h2, "ALLOW")

	full := verifyTeamPack(t, map[string][]byte{"r1.json": r1, "r2.json": r2, "r3.json": r3})
	if !full.Verified {
		t.Fatalf("the genuine three-receipt team pack does not verify; the cases prove nothing: %+v", full.Checks)
	}
	if deleted := verifyTeamPack(t, map[string][]byte{"r1.json": r1, "r3.json": r3}); deleted.Verified || packCheck(t, deleted, "chain_integrity").Pass {
		t.Fatalf("a team pack with its middle receipt deleted verified; the cases prove nothing: %+v", deleted.Checks)
	}

	withMember := func(receipt []byte, member string) []byte {
		return append(append(append([]byte(nil), receipt[:len(receipt)-1]...), ","...), member+"}"...)
	}
	prevShadow := withMember(r3, `"PREV_HASH":"`+h1+`"`)
	bothShadows := withMember(prevShadow, `"Lamport_Clock":2`)
	var exact map[string]any
	if err := json.Unmarshal(bothShadows, &exact); err != nil || exact["prev_hash"] != h2 || exact["PREV_HASH"] != h1 {
		t.Fatalf("the planted receipt does not keep the signed prev_hash beside a different shadow; the case proves nothing (%v)", err)
	}

	for _, tc := range []struct {
		name     string
		shadowed []byte
	}{
		{"PREV_HASH and Lamport_Clock", bothShadows},
		{"PREV_HASH", prevShadow},
		{"Lamport_Clock", withMember(r3, `"Lamport_Clock":2`)},
	} {
		name := tc.name
		report := verifyTeamPack(t, map[string][]byte{"r1.json": r1, "r3.json": tc.shadowed})
		if report.Verified {
			t.Fatalf("%s: a team pack with its middle receipt deleted and the gap papered over by a letter-case shadow verified: %+v", name, report.Checks)
		}
		for _, check := range []string{"chain_integrity", "lamport_monotonicity"} {
			result := packCheck(t, report, check)
			if result.Pass || !strings.Contains(result.Reason, "r3.json") || !strings.Contains(result.Reason, "letter case") {
				t.Fatalf("%s: %s must refuse the receipt file and name the letter case: %+v", name, check, result)
			}
		}
	}

	// The same rule refuses one member written twice, which encoding/json
	// would otherwise resolve to the last one.
	twice := verifyTeamPack(t, map[string][]byte{"r1.json": r1, "r2.json": r2, "r3.json": withMember(r3, `"prev_hash":"`+h1+`"`)})
	if result := packCheck(t, twice, "chain_integrity"); twice.Verified || result.Pass || !strings.Contains(result.Reason, "duplicate object member") {
		t.Fatalf("a receipt file that writes prev_hash twice must be refused by the chain checks: %+v", result)
	}
}

// TestTeamPackCannotHideADeletedReceiptBehindAnUnsignedStandIn is
// helm-tracker#305 round 3 finding NF1. The chain checks accepted a "hash"
// member a receipt declares about itself as its identity, and a file with no
// signature_version joins a session through executor_id. The team-pack
// operator of TestTeamPackCannotHideADeletedReceipt replaces the deleted DENY
// with an unsigned stand-in that declares the deleted receipt's chain hash in
// "hash": no letter case is involved, embedded_signature_trust does not count
// a file that declares neither signature nor signature_version, and the
// re-sealed pack verified. A receipt.v5 successor now links only to an
// identity the verifier recomputed: contracts.ReceiptChainHash of its
// predecessor or the SHA-256 of the predecessor's file.
func TestTeamPackCannotHideADeletedReceiptBehindAnUnsignedStandIn(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keyHex := hex.EncodeToString(pub)
	t.Setenv("HELM_EVIDENCE_TRUSTED_PUBLIC_KEY_HEX", keyHex)
	t.Setenv("HELM_ALLOW_SELF_ATTESTED_EVIDENCE", "")

	r1 := teamPackReceipt(t, priv, keyHex, "r1", 1, "", "ALLOW")
	h1 := teamPackChainHash(t, r1)
	r2 := teamPackReceipt(t, priv, keyHex, "r2", 2, h1, "DENY")
	h2 := teamPackChainHash(t, r2)
	r3 := teamPackReceipt(t, priv, keyHex, "r3", 3, h2, "ALLOW")
	if full := verifyTeamPack(t, map[string][]byte{"r1.json": r1, "r2.json": r2, "r3.json": r3}); !full.Verified {
		t.Fatalf("the genuine three-receipt team pack does not verify; the case proves nothing: %+v", full.Checks)
	}

	standIn, err := json.Marshal(map[string]any{
		"receipt_id": "r2", "executor_id": "session", "prev_hash": h1, "lamport_clock": 2,
		"hash": h2, "verdict": "ALLOW", "status": "APPLIED",
	})
	if err != nil {
		t.Fatal(err)
	}
	report := verifyTeamPack(t, map[string][]byte{"r1.json": r1, "r2.json": standIn, "r3.json": r3})
	if trust := packCheck(t, report, "embedded_signature_trust"); !trust.Pass {
		t.Fatalf("embedded_signature_trust refuses the stand-in by itself; the case proves nothing about the chain checks: %+v", trust)
	}
	if report.Verified {
		t.Fatalf("a team pack whose deleted DENY is replaced by an unsigned stand-in declaring its hash verified: %+v", report.Checks)
	}
	for _, check := range []string{"chain_integrity", "lamport_monotonicity"} {
		result := packCheck(t, report, check)
		if result.Pass || !strings.Contains(result.Reason, "unreachable from genesis") || !strings.Contains(result.Reason, "r3 (prev_hash="+h2+")") {
			t.Fatalf("%s must leave the signed successor of the stand-in unreachable: %+v", check, result)
		}
	}

	// A successor with no signature_version still links through a declared
	// hash, as the demo producers chain (security ledger F-20).
	d1, _ := json.Marshal(map[string]any{"receipt_id": "d1", "executor_id": "demo", "prev_hash": "", "lamport_clock": 1, "hash": "sha256:d1"})
	d2, _ := json.Marshal(map[string]any{"receipt_id": "d2", "executor_id": "demo", "prev_hash": "sha256:d1", "lamport_clock": 2, "hash": "sha256:d2"})
	if result := packCheck(t, verifyTeamPack(t, map[string][]byte{"d1.json": d1, "d2.json": d2}), "chain_integrity"); !result.Pass {
		t.Fatalf("an unversioned chain linked through its declared hashes must still link: %+v", result)
	}
}

// TestDeeplyNestedReceiptIsNotSkippedBySignatureTrust: embedded_signature_trust
// reads each receipt file with receiptverify.ParseReceiptDocument, which since
// helm-tracker#305 refuses a document nested deeper than 64 levels before it is
// decoded. The check took the missing document for a file that is not a
// receipt and skipped it, so a team-pack receipt edited from DENY to ALLOW,
// with metadata nested 70 levels, was not counted and the pack verified with
// "no embedded receipt or witness signatures require verification". A file
// refused for its depth now fails the check, and the reason counts it as a
// file refused unread, not as a signature (helm-tracker#305 round 3 NF2).
func TestDeeplyNestedReceiptIsNotSkippedBySignatureTrust(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keyHex := hex.EncodeToString(pub)
	t.Setenv("HELM_EVIDENCE_TRUSTED_PUBLIC_KEY_HEX", keyHex)
	t.Setenv("HELM_ALLOW_SELF_ATTESTED_EVIDENCE", "")

	genuine := teamPackReceipt(t, priv, keyHex, "r1", 1, "", "DENY")
	if report := verifyTeamPack(t, map[string][]byte{"r1.json": genuine}); !report.Verified {
		t.Fatalf("the genuine one-receipt team pack does not verify; the case proves nothing: %+v", report.Checks)
	}
	forged := bytes.Replace(genuine, []byte(`"verdict":"DENY"`), []byte(`"verdict":"ALLOW"`), 1)
	if report := verifyTeamPack(t, map[string][]byte{"r1.json": forged}); report.Verified || packCheck(t, report, "embedded_signature_trust").Pass {
		t.Fatalf("a receipt edited from DENY to ALLOW verified; the case proves nothing: %+v", report.Checks)
	}
	deep := append(append([]byte(nil), forged[:len(forged)-1]...), `,"metadata":{"x":`+strings.Repeat("[", 70)+strings.Repeat("]", 70)+`}}`...)
	report := verifyTeamPack(t, map[string][]byte{"r1.json": deep})
	if check := packCheck(t, report, "embedded_signature_trust"); report.Verified || check.Pass {
		t.Fatalf("a forged receipt nested 70 levels deep was skipped by embedded_signature_trust and the pack verified: %+v", check)
	}

	const refusedUnread = "1 file(s) refused unread: JSON exceeds the 64-level nesting limit"
	deepArray := []byte(strings.Repeat("[", 65) + strings.Repeat("]", 65))
	for _, tc := range []struct {
		name         string
		receipts     map[string][]byte
		attestations map[string][]byte
		reason       string
	}{
		{"a deep receipt", map[string][]byte{"r1.json": deep}, nil, refusedUnread},
		{"a deep array beside a genuine receipt and a shallow array", map[string][]byte{"r1.json": genuine},
			map[string][]byte{"deep.json": deepArray, "shallow.json": []byte(`[[[]]]`)}, refusedUnread},
		{"a deep array beside a forged receipt", map[string][]byte{"r1.json": forged}, map[string][]byte{"deep.json": deepArray},
			"1/1 embedded receipt or witness signatures require a configured verifier; none are trusted by presence alone; " + refusedUnread},
	} {
		check := packCheck(t, verifyTeamPackWith(t, tc.receipts, tc.attestations), "embedded_signature_trust")
		if check.Pass || check.Reason != tc.reason {
			t.Errorf("%s: embedded_signature_trust must fail with %q, got %+v", tc.name, tc.reason, check)
		}
	}
}

// teamPackReceipt is a receipt.v5 receipt as the runtime signs it, signed by
// priv over its 13 signed members.
func teamPackReceipt(t *testing.T, priv ed25519.PrivateKey, keyHex, id string, lamport uint64, prev, verdict string) []byte {
	t.Helper()
	envelope := receiptV5DocumentEnvelope{
		SignatureVersion: contracts.ReceiptSignatureV5, ReceiptID: id, DecisionID: "dec-" + id, EffectID: "eff-evaluate",
		Status: "APPLIED", OutputHash: "sha256:out", PrevHash: prev, LamportClock: lamport, ArgsHash: "sha256:args",
		Verdict: verdict, ReasonCode: "R", PolicyHash: "sha256:policy", SessionID: "session",
	}
	signed, err := canonicalize.InteroperableJCS(envelope)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := json.Marshal(map[string]any{
		"signature_version": envelope.SignatureVersion, "receipt_id": id, "decision_id": envelope.DecisionID,
		"effect_id": envelope.EffectID, "status": envelope.Status, "output_hash": envelope.OutputHash,
		"prev_hash": prev, "lamport_clock": lamport, "args_hash": envelope.ArgsHash, "verdict": verdict,
		"reason_code": envelope.ReasonCode, "policy_hash": envelope.PolicyHash, "session_id": envelope.SessionID,
		"signature":         hex.EncodeToString(ed25519.Sign(priv, signed)),
		"signature_profile": "classical", "signature_algorithm": "ed25519",
		"public_key_set": map[string]any{"ed25519": keyHex}, "decision_hash": "sha256:decision-" + id,
	})
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

// teamPackChainHash is the identity a successor's prev_hash names.
func teamPackChainHash(t *testing.T, receipt []byte) string {
	t.Helper()
	var r contracts.Receipt
	if err := json.Unmarshal(receipt, &r); err != nil {
		t.Fatal(err)
	}
	hash, err := contracts.ReceiptChainHash(&r)
	if err != nil {
		t.Fatal(err)
	}
	return hash
}

// verifyTeamPack seals a pack holding receipts with a file-dev operator key and
// verifies it under the team profile, with that key named by the trust config
// and nothing self-attested.
func verifyTeamPack(t *testing.T, receipts map[string][]byte) *VerifyReport {
	t.Helper()
	return verifyTeamPackWith(t, receipts, nil)
}

// verifyTeamPackWith is verifyTeamPack with files under 07_ATTESTATIONS/ too.
func verifyTeamPackWith(t *testing.T, receipts, attestations map[string][]byte) *VerifyReport {
	t.Helper()
	dir := createValidBundleFixture(t)
	t.Setenv("HELM_ALLOW_SELF_ATTESTED_EVIDENCE", "")
	receiptsDir := filepath.Join(dir, "receipts")
	if err := os.RemoveAll(receiptsDir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(receiptsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, data := range receipts {
		if err := os.WriteFile(filepath.Join(receiptsDir, name), bytes.TrimSpace(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for name, data := range attestations {
		if err := os.MkdirAll(filepath.Join(dir, "07_ATTESTATIONS"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "07_ATTESTATIONS", name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Remove(filepath.Join(dir, evidencepkg.EvidencePackSealPath)); err != nil {
		t.Fatal(err)
	}
	writeSealFixtureIndex(t, dir)
	sealData := t.TempDir()
	if _, err := evidencepkg.SealEvidencePack(context.Background(), dir, evidencepkg.SealEvidencePackOptions{PackID: "team-pack", DataDir: sealData}); err != nil {
		t.Fatal(err)
	}
	operator, err := evidencepkg.NewFileDevEvidenceSigner(sealData)
	if err != nil {
		t.Fatal(err)
	}
	report, err := VerifyBundleWithOptions(dir, VerifyOptions{TrustConfig: &evidencepkg.EvidencePackTrustConfig{
		ActiveProfile: evidencepkg.EvidenceTrustProfileTeam,
		TrustedKeys:   map[string]string{operator.KeyID(): operator.PublicKeyHex()},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return report
}

func packCheck(t *testing.T, report *VerifyReport, name string) CheckResult {
	t.Helper()
	for _, check := range report.Checks {
		if check.Name == name {
			return check
		}
	}
	t.Fatalf("check %s missing from report: %+v", name, report.Checks)
	return CheckResult{}
}
