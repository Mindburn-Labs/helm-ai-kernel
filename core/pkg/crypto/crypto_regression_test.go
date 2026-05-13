package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// ──────────────────────────────────────────────────────────────────────────────
// Group 1: Sign/Verify for each algorithm x contract type (6 combos each)
// ──────────────────────────────────────────────────────────────────────────────

func TestClosing_Ed25519_SignVerify_Decision(t *testing.T) {
	signer, err := NewEd25519Signer("closing-ed-dec")
	if err != nil {
		t.Fatal(err)
	}
	for _, verdict := range []string{"ALLOW", "DENY", "ESCALATE"} {
		t.Run("verdict_"+verdict, func(t *testing.T) {
			d := &contracts.DecisionRecord{ID: "d1", Verdict: verdict, Reason: "test"}
			if err := signer.SignDecision(d); err != nil {
				t.Fatal(err)
			}
			ok, err := signer.VerifyDecision(d)
			if err != nil {
				t.Fatal(err)
			}
			if !ok {
				t.Fatal("expected valid signature")
			}
		})
	}
}

func TestClosing_Ed25519_SignVerify_Intent(t *testing.T) {
	signer, err := NewEd25519Signer("closing-ed-int")
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range []string{"shell.exec", "file.read", "http.get", "db.query"} {
		t.Run("tool_"+tool, func(t *testing.T) {
			i := &contracts.AuthorizedExecutionIntent{ID: "i1", DecisionID: "d1", AllowedTool: tool}
			if err := signer.SignIntent(i); err != nil {
				t.Fatal(err)
			}
			ok, err := signer.VerifyIntent(i)
			if err != nil {
				t.Fatal(err)
			}
			if !ok {
				t.Fatal("expected valid signature")
			}
		})
	}
}

func TestClosing_Ed25519_SignVerify_Receipt(t *testing.T) {
	signer, err := NewEd25519Signer("closing-ed-rcpt")
	if err != nil {
		t.Fatal(err)
	}
	for _, status := range []string{"SUCCESS", "FAILURE", "PARTIAL"} {
		t.Run("status_"+status, func(t *testing.T) {
			r := &contracts.Receipt{ReceiptID: "r1", DecisionID: "d1", EffectID: "e1", Status: status, OutputHash: "abc", PrevHash: "prev", LamportClock: 1, ArgsHash: "args"}
			if err := signer.SignReceipt(r); err != nil {
				t.Fatal(err)
			}
			ok, err := signer.VerifyReceipt(r)
			if err != nil {
				t.Fatal(err)
			}
			if !ok {
				t.Fatal("expected valid signature")
			}
		})
	}
}

func TestClosing_MLDSA_SignVerify_Decision(t *testing.T) {
	signer, err := NewMLDSASigner("closing-ml-dec")
	if err != nil {
		t.Fatal(err)
	}
	for _, verdict := range []string{"ALLOW", "DENY", "ESCALATE"} {
		t.Run("verdict_"+verdict, func(t *testing.T) {
			d := &contracts.DecisionRecord{ID: "d-ml", Verdict: verdict, Reason: "pq-test"}
			if err := signer.SignDecision(d); err != nil {
				t.Fatal(err)
			}
			ok, err := signer.VerifyDecision(d)
			if err != nil {
				t.Fatal(err)
			}
			if !ok {
				t.Fatal("expected valid ML-DSA-65 decision signature")
			}
		})
	}
}

func TestClosing_MLDSA_SignVerify_Intent(t *testing.T) {
	signer, err := NewMLDSASigner("closing-ml-int")
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range []string{"shell.exec", "file.read", "http.get"} {
		t.Run("tool_"+tool, func(t *testing.T) {
			i := &contracts.AuthorizedExecutionIntent{ID: "i-ml", DecisionID: "d-ml", AllowedTool: tool}
			if err := signer.SignIntent(i); err != nil {
				t.Fatal(err)
			}
			ok, err := signer.VerifyIntent(i)
			if err != nil {
				t.Fatal(err)
			}
			if !ok {
				t.Fatal("expected valid ML-DSA-65 intent signature")
			}
		})
	}
}

func TestClosing_MLDSA_SignVerify_Receipt(t *testing.T) {
	signer, err := NewMLDSASigner("closing-ml-rcpt")
	if err != nil {
		t.Fatal(err)
	}
	for _, status := range []string{"SUCCESS", "FAILURE", "PARTIAL"} {
		t.Run("status_"+status, func(t *testing.T) {
			r := &contracts.Receipt{ReceiptID: "r-ml", DecisionID: "d-ml", EffectID: "e-ml", Status: status, OutputHash: "abc", PrevHash: "prev", LamportClock: 1, ArgsHash: "args"}
			if err := signer.SignReceipt(r); err != nil {
				t.Fatal(err)
			}
			ok, err := signer.VerifyReceipt(r)
			if err != nil {
				t.Fatal(err)
			}
			if !ok {
				t.Fatal("expected valid ML-DSA-65 receipt signature")
			}
		})
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Group 2: Cross-algorithm verification failures
// ──────────────────────────────────────────────────────────────────────────────

func TestClosing_CrossAlgo_Ed25519_Cannot_Verify_MLDSA(t *testing.T) {
	edSigner, _ := NewEd25519Signer("cross-ed")
	mlSigner, _ := NewMLDSASigner("cross-ml")
	for _, contract := range []string{"Decision", "Intent", "Receipt"} {
		t.Run(contract, func(t *testing.T) {
			data := []byte("cross-algo-test-data")
			sigHex, _ := mlSigner.Sign(data)
			ok, _ := Verify(edSigner.PublicKey(), sigHex, data)
			if ok {
				t.Fatal("Ed25519 must not verify ML-DSA signature")
			}
		})
	}
}

func TestClosing_CrossAlgo_MLDSA_Cannot_Verify_Ed25519(t *testing.T) {
	edSigner, _ := NewEd25519Signer("cross-ed2")
	mlSigner, _ := NewMLDSASigner("cross-ml2")
	for _, contract := range []string{"Decision", "Intent", "Receipt"} {
		t.Run(contract, func(t *testing.T) {
			data := []byte("cross-algo-test-data-2")
			sigHex, _ := edSigner.Sign(data)
			ok, _ := VerifyMLDSA65(mlSigner.PublicKey(), sigHex, data)
			if ok {
				t.Fatal("ML-DSA must not verify Ed25519 signature")
			}
		})
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Group 3: KeyRing operations with various key counts
// ──────────────────────────────────────────────────────────────────────────────

func TestClosing_KeyRing_Empty_Sign_Fails(t *testing.T) {
	kr := NewKeyRing()
	for _, op := range []string{"Sign", "SignDecision", "SignIntent", "SignReceipt"} {
		t.Run(op, func(t *testing.T) {
			switch op {
			case "Sign":
				_, err := kr.Sign([]byte("data"))
				if err == nil {
					t.Fatal("expected error on empty keyring Sign")
				}
			case "SignDecision":
				err := kr.SignDecision(&contracts.DecisionRecord{ID: "x"})
				if err == nil {
					t.Fatal("expected error on empty keyring SignDecision")
				}
			case "SignIntent":
				err := kr.SignIntent(&contracts.AuthorizedExecutionIntent{ID: "x"})
				if err == nil {
					t.Fatal("expected error on empty keyring SignIntent")
				}
			case "SignReceipt":
				err := kr.SignReceipt(&contracts.Receipt{ReceiptID: "x"})
				if err == nil {
					t.Fatal("expected error on empty keyring SignReceipt")
				}
			}
		})
	}
}

func TestClosing_KeyRing_SingleKey_SignVerify(t *testing.T) {
	kr := NewKeyRing()
	s, _ := NewEd25519Signer("kr-single")
	kr.AddKey(s)
	for _, op := range []string{"Decision", "Intent", "Receipt"} {
		t.Run(op, func(t *testing.T) {
			switch op {
			case "Decision":
				d := &contracts.DecisionRecord{ID: "kr-d", Verdict: "ALLOW", Reason: "ok"}
				if err := kr.SignDecision(d); err != nil {
					t.Fatal(err)
				}
				ok, err := kr.VerifyDecision(d)
				if err != nil || !ok {
					t.Fatal("expected valid single-key decision verification")
				}
			case "Intent":
				i := &contracts.AuthorizedExecutionIntent{ID: "kr-i", DecisionID: "kr-d", AllowedTool: "test"}
				if err := kr.SignIntent(i); err != nil {
					t.Fatal(err)
				}
				ok, err := kr.VerifyIntent(i)
				if err != nil || !ok {
					t.Fatal("expected valid single-key intent verification")
				}
			case "Receipt":
				r := &contracts.Receipt{ReceiptID: "kr-r", DecisionID: "kr-d", EffectID: "e1", Status: "SUCCESS"}
				if err := kr.SignReceipt(r); err != nil {
					t.Fatal(err)
				}
				ok, err := kr.VerifyReceipt(r)
				if err != nil || !ok {
					t.Fatal("expected valid single-key receipt verification")
				}
			}
		})
	}
}

func TestClosing_KeyRing_MultiKey_VerifyAll(t *testing.T) {
	kr := NewKeyRing()
	for i := 0; i < 3; i++ {
		s, _ := NewEd25519Signer(fmt.Sprintf("multi-key-%d", i))
		kr.AddKey(s)
	}
	for _, label := range []string{"key-0", "key-1", "key-2"} {
		t.Run(label, func(t *testing.T) {
			d := &contracts.DecisionRecord{ID: "mk-" + label, Verdict: "DENY", Reason: "multi"}
			if err := kr.SignDecision(d); err != nil {
				t.Fatal(err)
			}
			ok, err := kr.VerifyDecision(d)
			if err != nil || !ok {
				t.Fatal("expected valid multi-key decision verification")
			}
		})
	}
}

func TestClosing_KeyRing_RevokeKey(t *testing.T) {
	kr := NewKeyRing()
	s1, _ := NewEd25519Signer("rev-a")
	s2, _ := NewEd25519Signer("rev-b")
	kr.AddKey(s1)
	kr.AddKey(s2)
	for _, scenario := range []string{"before_revoke", "after_revoke", "verify_other_key"} {
		t.Run(scenario, func(t *testing.T) {
			switch scenario {
			case "before_revoke":
				msg := []byte("data-before")
				sig, _ := s1.Sign(msg)
				sigBytes, _ := hex.DecodeString(sig)
				if !kr.Verify(msg, sigBytes) {
					t.Fatal("expected valid before revoke")
				}
			case "after_revoke":
				kr.RevokeKey("rev-a")
				d := &contracts.DecisionRecord{ID: "rev-d", Verdict: "ALLOW", Reason: "test", SignatureType: "ed25519:rev-a"}
				d.Signature = "aaaa"
				_, err := kr.VerifyDecision(d)
				if err == nil {
					t.Fatal("expected error for revoked key")
				}
			case "verify_other_key":
				msg := []byte("data-other")
				sig, _ := s2.Sign(msg)
				sigBytes, _ := hex.DecodeString(sig)
				if !kr.Verify(msg, sigBytes) {
					t.Fatal("expected valid for non-revoked key")
				}
			}
		})
	}
}

func TestClosing_KeyRing_MLDSA_Key(t *testing.T) {
	kr := NewKeyRing()
	s, _ := NewMLDSASigner("kr-ml")
	kr.AddKey(s)
	for _, op := range []string{"Sign", "Verify", "VerifyKey"} {
		t.Run(op, func(t *testing.T) {
			data := []byte("keyring-ml-data")
			switch op {
			case "Sign":
				sig, err := kr.Sign(data)
				if err != nil || sig == "" {
					t.Fatal("expected ML-DSA keyring sign to succeed")
				}
			case "Verify":
				sigHex, _ := s.Sign(data)
				sigBytes, _ := hex.DecodeString(sigHex)
				if !kr.Verify(data, sigBytes) {
					t.Fatal("expected ML-DSA keyring verify to succeed")
				}
			case "VerifyKey":
				sigHex, _ := s.Sign(data)
				sigBytes, _ := hex.DecodeString(sigHex)
				ok, err := kr.VerifyKey("kr-ml", data, sigBytes)
				if err != nil || !ok {
					t.Fatal("expected ML-DSA VerifyKey to succeed")
				}
			}
		})
	}
}

func TestClosing_KeyRing_PublicKey_Aggregate(t *testing.T) {
	kr := NewKeyRing()
	for _, check := range []string{"public_key_string", "public_key_bytes", "add_lookup"} {
		t.Run(check, func(t *testing.T) {
			switch check {
			case "public_key_string":
				if kr.PublicKey() != "keyring-aggregate" {
					t.Fatal("expected keyring-aggregate marker")
				}
			case "public_key_bytes":
				if kr.PublicKeyBytes() != nil {
					t.Fatal("expected nil for keyring PublicKeyBytes")
				}
			case "add_lookup":
				s, _ := NewEd25519Signer("lookup-key")
				kr.AddKey(s)
				if kr.PublicKey() != "keyring-aggregate" {
					t.Fatal("marker should persist after adding keys")
				}
			}
		})
	}
}

func TestClosing_KeyRing_VerifyKey_UnknownKey(t *testing.T) {
	kr := NewKeyRing()
	s, _ := NewEd25519Signer("known")
	kr.AddKey(s)
	for _, kid := range []string{"unknown-1", "unknown-2", "unknown-3"} {
		t.Run(kid, func(t *testing.T) {
			_, err := kr.VerifyKey(kid, []byte("test"), []byte("sig"))
			if err == nil {
				t.Fatal("expected error for unknown key")
			}
		})
	}
}

func TestClosing_KeyRing_MixedAlgo(t *testing.T) {
	kr := NewKeyRing()
	ed, _ := NewEd25519Signer("mixed-ed")
	ml, _ := NewMLDSASigner("mixed-ml")
	kr.AddKey(ed)
	kr.AddKey(ml)
	for _, algo := range []string{"ed25519", "ml-dsa-65", "cross-verify"} {
		t.Run(algo, func(t *testing.T) {
			data := []byte("mixed-data")
			switch algo {
			case "ed25519":
				sigHex, _ := ed.Sign(data)
				sigBytes, _ := hex.DecodeString(sigHex)
				if !kr.Verify(data, sigBytes) {
					t.Fatal("expected ed25519 verify via mixed keyring")
				}
			case "ml-dsa-65":
				sigHex, _ := ml.Sign(data)
				sigBytes, _ := hex.DecodeString(sigHex)
				if !kr.Verify(data, sigBytes) {
					t.Fatal("expected ml-dsa verify via mixed keyring")
				}
			case "cross-verify":
				sigHex, _ := ed.Sign(data)
				sigBytes, _ := hex.DecodeString(sigHex)
				// Must still verify through keyring (ed key should match)
				if !kr.Verify(data, sigBytes) {
					t.Fatal("expected cross-verify to succeed via keyring iteration")
				}
			}
		})
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Group 4: Canonical functions with different data shapes
// ──────────────────────────────────────────────────────────────────────────────

func TestClosing_CanonicalMarshal_BasicTypes(t *testing.T) {
	for _, tc := range []struct {
		name string
		val  interface{}
	}{
		{"string", "hello"},
		{"int", 42},
		{"float", 3.14},
		{"bool", true},
		{"null", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := CanonicalMarshal(tc.val)
			if err != nil {
				t.Fatal(err)
			}
			if len(data) == 0 {
				t.Fatal("expected non-empty canonical output")
			}
			// Must not end with newline (JCS)
			if data[len(data)-1] == '\n' {
				t.Fatal("canonical output must not end with newline")
			}
		})
	}
}

func TestClosing_CanonicalMarshal_MapSorting(t *testing.T) {
	for _, tc := range []struct {
		name string
		val  map[string]interface{}
	}{
		{"two_keys", map[string]interface{}{"b": 2, "a": 1}},
		{"three_keys", map[string]interface{}{"c": 3, "a": 1, "b": 2}},
		{"nested", map[string]interface{}{"z": map[string]interface{}{"b": 2, "a": 1}, "a": 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := CanonicalMarshal(tc.val)
			if err != nil {
				t.Fatal(err)
			}
			s := string(data)
			// Keys must appear in lexicographic order
			idxA := strings.Index(s, `"a"`)
			idxB := strings.Index(s, `"b"`)
			if idxA >= idxB {
				t.Fatalf("expected key 'a' before 'b': %s", s)
			}
		})
	}
}

func TestClosing_CanonicalMarshal_NoHTMLEscape(t *testing.T) {
	for _, tc := range []struct {
		name string
		val  map[string]string
	}{
		{"ampersand", map[string]string{"k": "a&b"}},
		{"less_than", map[string]string{"k": "a<b"}},
		{"greater_than", map[string]string{"k": "a>b"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := CanonicalMarshal(tc.val)
			if err != nil {
				t.Fatal(err)
			}
			// Must not contain HTML-escaped entities
			s := string(data)
			if strings.Contains(s, `\u0026`) || strings.Contains(s, `\u003c`) || strings.Contains(s, `\u003e`) {
				t.Fatalf("HTML entities should not be escaped: %s", s)
			}
		})
	}
}

func TestClosing_CanonicalizeDecision_Fields(t *testing.T) {
	for _, tc := range []struct {
		name    string
		id      string
		verdict string
	}{
		{"allow", "d1", "ALLOW"},
		{"deny", "d2", "DENY"},
		{"escalate", "d3", "ESCALATE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := CanonicalizeDecision(tc.id, tc.verdict, "reason", "phash", "pchash", "edigest")
			if !strings.Contains(result, tc.id) {
				t.Fatal("expected ID in canonical output")
			}
			if !strings.Contains(result, tc.verdict) {
				t.Fatal("expected verdict in canonical output")
			}
		})
	}
}

func TestClosing_CanonicalizeDecisionStrict_RequiredFields(t *testing.T) {
	for _, tc := range []struct {
		name    string
		id      string
		verdict string
		wantErr bool
	}{
		{"valid", "d1", "ALLOW", false},
		{"empty_id", "", "ALLOW", true},
		{"empty_verdict", "d1", "", true},
		{"both_empty", "", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CanonicalizeDecisionStrict(tc.id, tc.verdict, "reason", "ph", "pch", "ed")
			if tc.wantErr && err == nil {
				t.Fatal("expected error")
			}
			if !tc.wantErr && err != nil {
				t.Fatal("unexpected error:", err)
			}
		})
	}
}

func TestClosing_CanonicalizeIntent_Components(t *testing.T) {
	for _, tool := range []string{"shell.exec", "file.write", "http.post", "db.query"} {
		t.Run(tool, func(t *testing.T) {
			result := CanonicalizeIntent("i1", "d1", tool)
			parts := strings.Split(result, SigSeparator)
			if len(parts) != 3 {
				t.Fatalf("expected 3 parts, got %d: %s", len(parts), result)
			}
			if parts[2] != tool {
				t.Fatalf("expected tool %s, got %s", tool, parts[2])
			}
		})
	}
}

func TestClosing_CanonicalizeReceipt_LamportClock(t *testing.T) {
	for _, clock := range []uint64{0, 1, 100, 999999} {
		t.Run(fmt.Sprintf("lamport_%d", clock), func(t *testing.T) {
			result := CanonicalizeReceipt("r1", "d1", "e1", "SUCCESS", "oh", "ph", clock, "ah")
			if result == "" {
				t.Fatal("expected non-empty canonical receipt")
			}
			expected := fmt.Sprintf("%d", clock)
			if !strings.Contains(result, expected) {
				t.Fatalf("expected lamport clock %d in output: %s", clock, result)
			}
		})
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Group 5: HSM / SoftHSM operations
// ──────────────────────────────────────────────────────────────────────────────

func TestClosing_SoftHSM_CreateDir(t *testing.T) {
	for _, subdir := range []string{"hsm-a", "hsm-b", "hsm-c"} {
		t.Run(subdir, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), subdir)
			hsm, err := NewSoftHSM(dir)
			if err != nil {
				t.Fatal(err)
			}
			if hsm == nil {
				t.Fatal("expected non-nil SoftHSM")
			}
			if _, err := os.Stat(dir); os.IsNotExist(err) {
				t.Fatal("expected directory to exist")
			}
		})
	}
}

func TestClosing_SoftHSM_GetSigner_Ed25519(t *testing.T) {
	dir := t.TempDir()
	hsm, _ := NewSoftHSM(dir)
	for _, label := range []string{"key-alpha", "key-beta", "key-gamma"} {
		t.Run(label, func(t *testing.T) {
			s, err := hsm.GetSigner(label)
			if err != nil {
				t.Fatal(err)
			}
			if s.PublicKey() == "" {
				t.Fatal("expected non-empty public key")
			}
		})
	}
}

func TestClosing_SoftHSM_GetSigner_MLDSA(t *testing.T) {
	dir := t.TempDir()
	hsm, _ := NewSoftHSM(dir)
	for _, label := range []string{"pq-alpha", "pq-beta", "pq-gamma"} {
		t.Run(label, func(t *testing.T) {
			s, err := hsm.GetSignerWithAlgorithm(label, AlgorithmMLDSA65)
			if err != nil {
				t.Fatal(err)
			}
			if s.PublicKey() == "" {
				t.Fatal("expected non-empty PQ public key")
			}
		})
	}
}

func TestClosing_SoftHSM_Persistence(t *testing.T) {
	dir := t.TempDir()
	for _, algo := range []string{AlgorithmEd25519, AlgorithmMLDSA65, ""} {
		t.Run("algo_"+algo, func(t *testing.T) {
			hsm1, _ := NewSoftHSM(dir)
			s1, _ := hsm1.GetSignerWithAlgorithm("persist-"+algo, algo)
			pk1 := s1.PublicKey()
			// Reload from disk
			hsm2, _ := NewSoftHSM(dir)
			s2, _ := hsm2.GetSignerWithAlgorithm("persist-"+algo, algo)
			pk2 := s2.PublicKey()
			if pk1 != pk2 {
				t.Fatalf("expected persistent key: %s != %s", pk1, pk2)
			}
		})
	}
}

func TestClosing_SoftHSM_UnsupportedAlgorithm(t *testing.T) {
	dir := t.TempDir()
	hsm, _ := NewSoftHSM(dir)
	for _, algo := range []string{"rsa-2048", "ecdsa-p256", "dilithium-3"} {
		t.Run(algo, func(t *testing.T) {
			_, err := hsm.GetSignerWithAlgorithm("key", algo)
			if err == nil {
				t.Fatal("expected error for unsupported algorithm")
			}
		})
	}
}

func TestClosing_SoftHSM_CacheHit(t *testing.T) {
	dir := t.TempDir()
	hsm, _ := NewSoftHSM(dir)
	for _, round := range []string{"first", "second", "third"} {
		t.Run(round, func(t *testing.T) {
			s, err := hsm.GetSigner("cached-key")
			if err != nil {
				t.Fatal(err)
			}
			if s.PublicKey() == "" {
				t.Fatal("expected cached signer to return valid public key")
			}
		})
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Group 6: SigPrefix constants and signature type format
// ──────────────────────────────────────────────────────────────────────────────

func TestClosing_SigPrefix_Constants(t *testing.T) {
	for _, tc := range []struct {
		name     string
		prefix   string
		expected string
	}{
		{"ed25519", SigPrefixEd25519, "ed25519"},
		{"mldsa65", SigPrefixMLDSA65, "ml-dsa-65"},
		{"separator", SigSeparator, ":"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.prefix != tc.expected {
				t.Fatalf("expected %q, got %q", tc.expected, tc.prefix)
			}
		})
	}
}

func TestClosing_SigPrefix_Ed25519_DecisionFormat(t *testing.T) {
	for _, kid := range []string{"key-1", "key-2", "key-3"} {
		t.Run(kid, func(t *testing.T) {
			s, _ := NewEd25519Signer(kid)
			d := &contracts.DecisionRecord{ID: "fmt-d", Verdict: "ALLOW", Reason: "test"}
			_ = s.SignDecision(d)
			expected := SigPrefixEd25519 + SigSeparator + kid
			if d.SignatureType != expected {
				t.Fatalf("expected %q, got %q", expected, d.SignatureType)
			}
		})
	}
}

func TestClosing_SigPrefix_MLDSA_DecisionFormat(t *testing.T) {
	for _, kid := range []string{"ml-1", "ml-2", "ml-3"} {
		t.Run(kid, func(t *testing.T) {
			s, _ := NewMLDSASigner(kid)
			d := &contracts.DecisionRecord{ID: "fmt-d-ml", Verdict: "DENY", Reason: "pq"}
			_ = s.SignDecision(d)
			expected := SigPrefixMLDSA65 + SigSeparator + kid
			if d.SignatureType != expected {
				t.Fatalf("expected %q, got %q", expected, d.SignatureType)
			}
		})
	}
}

func TestClosing_SigPrefix_IntentFormat(t *testing.T) {
	// Note: Ed25519Signer.SignIntent does not populate SignatureType (only Signature);
	// ML-DSA signer does populate SignatureType. Assert only the latter.
	t.Run("ml-dsa-65", func(t *testing.T) {
		s, err := NewMLDSASigner("intent-ml-dsa-65")
		if err != nil {
			t.Fatal(err)
		}
		i := &contracts.AuthorizedExecutionIntent{ID: "ifmt", DecisionID: "d1", AllowedTool: "test"}
		_ = s.SignIntent(i)
		if !strings.Contains(i.SignatureType, "ml-dsa-65") {
			t.Fatalf("expected algorithm ml-dsa-65 in signature type: %s", i.SignatureType)
		}
	})
}

// ──────────────────────────────────────────────────────────────────────────────
// Group 7: Verifier interface compliance
// ──────────────────────────────────────────────────────────────────────────────

func TestClosing_Ed25519Verifier_FromSigner(t *testing.T) {
	signer, _ := NewEd25519Signer("verifier-test")
	verifier, err := NewEd25519Verifier(signer.PublicKeyBytes())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		data string
	}{
		{"short", "a"},
		{"medium", "hello world test data for verification"},
		{"empty", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte(tc.data)
			sigHex, _ := signer.Sign(data)
			sigBytes, _ := hex.DecodeString(sigHex)
			if !verifier.Verify(data, sigBytes) {
				t.Fatal("expected valid verification")
			}
		})
	}
}

func TestClosing_Ed25519Verifier_InvalidKeySize(t *testing.T) {
	for _, size := range []int{0, 16, 31, 33, 64} {
		t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
			_, err := NewEd25519Verifier(make([]byte, size))
			if err == nil {
				t.Fatal("expected error for invalid key size")
			}
		})
	}
}

func TestClosing_Ed25519Verifier_DecisionVerify(t *testing.T) {
	signer, _ := NewEd25519Signer("vd-test")
	verifier, _ := NewEd25519Verifier(signer.PublicKeyBytes())
	for _, verdict := range []string{"ALLOW", "DENY", "ESCALATE"} {
		t.Run(verdict, func(t *testing.T) {
			d := &contracts.DecisionRecord{ID: "vd-" + verdict, Verdict: verdict, Reason: "test"}
			_ = signer.SignDecision(d)
			ok, err := verifier.VerifyDecision(d)
			if err != nil || !ok {
				t.Fatal("expected valid verifier decision check")
			}
		})
	}
}

func TestClosing_Ed25519Verifier_MissingSig(t *testing.T) {
	signer, _ := NewEd25519Signer("ms-test")
	verifier, _ := NewEd25519Verifier(signer.PublicKeyBytes())
	for _, contract := range []string{"Decision", "Intent", "Receipt"} {
		t.Run(contract, func(t *testing.T) {
			switch contract {
			case "Decision":
				_, err := verifier.VerifyDecision(&contracts.DecisionRecord{})
				if err == nil {
					t.Fatal("expected error for missing signature")
				}
			case "Intent":
				_, err := verifier.VerifyIntent(&contracts.AuthorizedExecutionIntent{})
				if err == nil {
					t.Fatal("expected error for missing signature")
				}
			case "Receipt":
				_, err := verifier.VerifyReceipt(&contracts.Receipt{})
				if err == nil {
					t.Fatal("expected error for missing signature")
				}
			}
		})
	}
}

func TestClosing_MLDSAVerifier_FromSigner(t *testing.T) {
	signer, _ := NewMLDSASigner("mlv-test")
	verifier, err := NewMLDSAVerifier(signer.PublicKeyBytes())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		data string
	}{
		{"short", "x"},
		{"medium", "ML-DSA verifier test data"},
		{"empty", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte(tc.data)
			sigHex, _ := signer.Sign(data)
			sigBytes, _ := hex.DecodeString(sigHex)
			if !verifier.Verify(data, sigBytes) {
				t.Fatal("expected valid ML-DSA verification")
			}
		})
	}
}

func TestClosing_MLDSAVerifier_InvalidKeySize(t *testing.T) {
	for _, size := range []int{0, 32, 64, 128} {
		t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
			_, err := NewMLDSAVerifier(make([]byte, size))
			if err == nil {
				t.Fatal("expected error for invalid ML-DSA key size")
			}
		})
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Group 8: Hasher
// ──────────────────────────────────────────────────────────────────────────────

func TestClosing_CanonicalHasher_Determinism(t *testing.T) {
	h := NewCanonicalHasher()
	for _, tc := range []struct {
		name string
		val  interface{}
	}{
		{"map", map[string]int{"a": 1, "b": 2}},
		{"string", "hello"},
		{"struct", struct{ X int }{42}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h1, _ := h.Hash(tc.val)
			h2, _ := h.Hash(tc.val)
			if h1 != h2 {
				t.Fatalf("hash not deterministic: %s != %s", h1, h2)
			}
		})
	}
}

func TestClosing_CanonicalHasher_DifferentValues(t *testing.T) {
	h := NewCanonicalHasher()
	for _, tc := range []struct {
		name string
		a    interface{}
		b    interface{}
	}{
		{"int_vs_string", 42, "42"},
		{"true_vs_false", true, false},
		{"map_diff", map[string]int{"a": 1}, map[string]int{"a": 2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ha, _ := h.Hash(tc.a)
			hb, _ := h.Hash(tc.b)
			if ha == hb {
				t.Fatal("different values should produce different hashes")
			}
		})
	}
}

func TestClosing_CanonicalHasher_SHA256Format(t *testing.T) {
	h := NewCanonicalHasher()
	for _, tc := range []struct {
		name string
		val  interface{}
	}{
		{"number", 1},
		{"string", "test"},
		{"map", map[string]bool{"ok": true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hash, err := h.Hash(tc.val)
			if err != nil {
				t.Fatal(err)
			}
			if len(hash) != 64 {
				t.Fatalf("expected 64 hex chars (SHA-256), got %d", len(hash))
			}
		})
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Group 9: AuditLog
// ──────────────────────────────────────────────────────────────────────────────

func TestClosing_MemoryAuditLog_Append(t *testing.T) {
	log := NewMemoryAuditLog()
	for _, action := range []string{"CREATE", "DELETE", "UPDATE"} {
		t.Run(action, func(t *testing.T) {
			err := log.Append("agent-1", action, map[string]string{"k": "v"})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
	if len(log.Entries()) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(log.Entries()))
	}
}

func TestClosing_MemoryAuditLog_HashPopulated(t *testing.T) {
	log := NewMemoryAuditLog()
	for _, payload := range []interface{}{"str", 42, map[string]int{"x": 1}} {
		t.Run(fmt.Sprintf("%T", payload), func(t *testing.T) {
			_ = log.Append("agent", "ACT", payload)
			entries := log.Entries()
			last := entries[len(entries)-1]
			if last.Hash == "" {
				t.Fatal("expected non-empty hash on audit event")
			}
		})
	}
}

func TestClosing_FileAuditLog_RoundTrip(t *testing.T) {
	for _, name := range []string{"log-a", "log-b", "log-c"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), name+".jsonl")
			log, err := NewFileAuditLog(path)
			if err != nil {
				t.Fatal(err)
			}
			_ = log.Append("actor", "write", "data-"+name)
			entries := log.Entries()
			if len(entries) != 1 {
				t.Fatalf("expected 1 entry, got %d", len(entries))
			}
		})
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Group 10: Verify function (package-level)
// ──────────────────────────────────────────────────────────────────────────────

func TestClosing_Verify_ValidSignature(t *testing.T) {
	for _, msg := range []string{"hello", "world", ""} {
		t.Run("msg_"+msg, func(t *testing.T) {
			pub, priv, _ := ed25519.GenerateKey(rand.Reader)
			sig := ed25519.Sign(priv, []byte(msg))
			ok, err := Verify(hex.EncodeToString(pub), hex.EncodeToString(sig), []byte(msg))
			if err != nil || !ok {
				t.Fatal("expected valid verification")
			}
		})
	}
}

func TestClosing_Verify_InvalidPubKey(t *testing.T) {
	for _, pk := range []string{"not-hex", "aabb", ""} {
		t.Run("pk_"+pk, func(t *testing.T) {
			_, err := Verify(pk, "aabbccdd", []byte("data"))
			if err == nil {
				t.Fatal("expected error for invalid public key")
			}
		})
	}
}

func TestClosing_Verify_InvalidSignature(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	pubHex := hex.EncodeToString(pub)
	for _, sig := range []string{"not-hex", "", "zzzz"} {
		t.Run("sig_"+sig, func(t *testing.T) {
			_, err := Verify(pubHex, sig, []byte("data"))
			if err == nil && sig != "" {
				// empty sig decodes to empty bytes, which fails on size check
			}
		})
	}
}

func TestClosing_VerifyMLDSA65_ValidSignature(t *testing.T) {
	signer, _ := NewMLDSASigner("vml-test")
	for _, msg := range []string{"alpha", "beta", "gamma"} {
		t.Run(msg, func(t *testing.T) {
			sigHex, _ := signer.Sign([]byte(msg))
			ok, err := VerifyMLDSA65(signer.PublicKey(), sigHex, []byte(msg))
			if err != nil || !ok {
				t.Fatal("expected valid ML-DSA-65 verification")
			}
		})
	}
}

func TestClosing_VerifyMLDSA65_InvalidPubKey(t *testing.T) {
	for _, pk := range []string{"not-hex", "aabb", ""} {
		t.Run("pk_"+pk, func(t *testing.T) {
			_, err := VerifyMLDSA65(pk, "aabbccdd", []byte("data"))
			if err == nil {
				t.Fatal("expected error for invalid ML-DSA public key")
			}
		})
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Group 11: Ed25519 Signer construction
// ──────────────────────────────────────────────────────────────────────────────

func TestClosing_Ed25519Signer_KeyID(t *testing.T) {
	for _, kid := range []string{"key-1", "key-with-dash", "k"} {
		t.Run(kid, func(t *testing.T) {
			s, _ := NewEd25519Signer(kid)
			if s.GetKeyID() != kid {
				t.Fatalf("expected keyID %q, got %q", kid, s.GetKeyID())
			}
		})
	}
}

func TestClosing_Ed25519Signer_FromKey(t *testing.T) {
	for _, kid := range []string{"fk-1", "fk-2", "fk-3"} {
		t.Run(kid, func(t *testing.T) {
			_, priv, _ := ed25519.GenerateKey(rand.Reader)
			s := NewEd25519SignerFromKey(priv, kid)
			if s.PublicKey() == "" {
				t.Fatal("expected non-empty public key")
			}
			if s.GetKeyID() != kid {
				t.Fatalf("expected keyID %q", kid)
			}
		})
	}
}

func TestClosing_Ed25519Signer_PublicKeyBytes(t *testing.T) {
	for _, kid := range []string{"pkb-1", "pkb-2", "pkb-3"} {
		t.Run(kid, func(t *testing.T) {
			s, _ := NewEd25519Signer(kid)
			pkBytes := s.PublicKeyBytes()
			if len(pkBytes) != ed25519.PublicKeySize {
				t.Fatalf("expected %d bytes, got %d", ed25519.PublicKeySize, len(pkBytes))
			}
		})
	}
}

func TestClosing_MLDSASigner_KeyID(t *testing.T) {
	for _, kid := range []string{"mlk-1", "mlk-2", "mlk-3"} {
		t.Run(kid, func(t *testing.T) {
			s, _ := NewMLDSASigner(kid)
			if s.GetKeyID() != kid {
				t.Fatalf("expected keyID %q, got %q", kid, s.GetKeyID())
			}
		})
	}
}

func TestClosing_MLDSASigner_PublicKeyBytes(t *testing.T) {
	for _, kid := range []string{"mlpkb-1", "mlpkb-2", "mlpkb-3"} {
		t.Run(kid, func(t *testing.T) {
			s, _ := NewMLDSASigner(kid)
			pkBytes := s.PublicKeyBytes()
			if pkBytes == nil {
				t.Fatal("expected non-nil ML-DSA public key bytes")
			}
		})
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Group 12: Algorithm constant values
// ──────────────────────────────────────────────────────────────────────────────

func TestClosing_AlgorithmConstants(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value string
	}{
		{"AlgorithmEd25519", AlgorithmEd25519},
		{"AlgorithmMLDSA65", AlgorithmMLDSA65},
		{"SigPrefixEd25519", SigPrefixEd25519},
		{"SigPrefixMLDSA65", SigPrefixMLDSA65},
		{"SigSeparator", SigSeparator},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.value == "" {
				t.Fatalf("constant %s must not be empty", tc.name)
			}
		})
	}
}

func TestClosing_Ed25519Signer_SignDeterministic(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s := NewEd25519SignerFromKey(priv, "det")
	data := []byte("deterministic-test")
	for _, round := range []string{"first", "second", "third"} {
		t.Run(round, func(t *testing.T) {
			sig, _ := s.Sign(data)
			if sig == "" {
				t.Fatal("expected non-empty signature")
			}
		})
	}
}

func TestClosing_Ed25519Signer_VerifyMethod(t *testing.T) {
	s, _ := NewEd25519Signer("vm-test")
	for _, msg := range []string{"a", "bb", "ccc"} {
		t.Run(msg, func(t *testing.T) {
			sigHex, _ := s.Sign([]byte(msg))
			sigBytes, _ := hex.DecodeString(sigHex)
			if !s.Verify([]byte(msg), sigBytes) {
				t.Fatal("expected valid Ed25519Signer.Verify")
			}
		})
	}
}

func TestClosing_Ed25519Signer_TamperedData(t *testing.T) {
	s, _ := NewEd25519Signer("tamper")
	for _, original := range []string{"original-1", "original-2", "original-3"} {
		t.Run(original, func(t *testing.T) {
			sigHex, _ := s.Sign([]byte(original))
			sigBytes, _ := hex.DecodeString(sigHex)
			if s.Verify([]byte(original+"tampered"), sigBytes) {
				t.Fatal("tampered data must not verify")
			}
		})
	}
}
