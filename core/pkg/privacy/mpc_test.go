package privacy

import (
	"bytes"
	"testing"
	"time"
)

func TestSecretSharer_SplitReconstruct(t *testing.T) {
	sharer, err := NewSecretSharer(3, 5)
	if err != nil {
		t.Fatalf("NewSecretSharer(3, 5) failed: %v", err)
	}

	secret := []byte("helm-governance-secret-data")
	shares, err := sharer.Split(secret)
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}

	if len(shares) != 5 {
		t.Fatalf("expected 5 shares, got %d", len(shares))
	}

	// Verify each share has correct metadata.
	for i, sh := range shares {
		if sh.Index != i+1 {
			t.Errorf("share %d: expected index %d, got %d", i, i+1, sh.Index)
		}
		if sh.Threshold != 3 {
			t.Errorf("share %d: expected threshold 3, got %d", i, sh.Threshold)
		}
		if sh.Total != 5 {
			t.Errorf("share %d: expected total 5, got %d", i, sh.Total)
		}
		if len(sh.Value) != len(secret) {
			t.Errorf("share %d: expected value length %d, got %d", i, len(secret), len(sh.Value))
		}
		if sh.ShareID == "" {
			t.Errorf("share %d: expected non-empty ShareID", i)
		}
	}

	// Reconstruct from first 3 shares.
	recovered, err := sharer.Reconstruct(shares[:3])
	if err != nil {
		t.Fatalf("Reconstruct failed: %v", err)
	}
	if !bytes.Equal(recovered, secret) {
		t.Errorf("reconstructed secret mismatch:\n got: %q\nwant: %q", recovered, secret)
	}

	// Reconstruct from last 3 shares.
	recovered2, err := sharer.Reconstruct(shares[2:5])
	if err != nil {
		t.Fatalf("Reconstruct from last 3 failed: %v", err)
	}
	if !bytes.Equal(recovered2, secret) {
		t.Errorf("reconstructed secret (last 3) mismatch:\n got: %q\nwant: %q", recovered2, secret)
	}

	// Reconstruct from non-contiguous shares: [0, 2, 4].
	nonContiguous := []SecretShare{shares[0], shares[2], shares[4]}
	recovered3, err := sharer.Reconstruct(nonContiguous)
	if err != nil {
		t.Fatalf("Reconstruct from non-contiguous failed: %v", err)
	}
	if !bytes.Equal(recovered3, secret) {
		t.Errorf("reconstructed secret (non-contiguous) mismatch:\n got: %q\nwant: %q", recovered3, secret)
	}
}

func TestSecretSharer_ThresholdRequired(t *testing.T) {
	sharer, err := NewSecretSharer(3, 5)
	if err != nil {
		t.Fatalf("NewSecretSharer(3, 5) failed: %v", err)
	}

	secret := []byte("sensitive-input")
	shares, err := sharer.Split(secret)
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}

	// Only 2 shares — should fail (threshold is 3).
	_, err = sharer.Reconstruct(shares[:2])
	if err == nil {
		t.Fatal("expected error with fewer than threshold shares, got nil")
	}

	// Only 1 share — should fail.
	_, err = sharer.Reconstruct(shares[:1])
	if err == nil {
		t.Fatal("expected error with 1 share, got nil")
	}

	// Empty shares — should fail.
	_, err = sharer.Reconstruct(nil)
	if err == nil {
		t.Fatal("expected error with nil shares, got nil")
	}
}

func TestSecretSharer_InvalidConfig(t *testing.T) {
	tests := []struct {
		name      string
		threshold int
		total     int
	}{
		{"threshold > total", 5, 3},
		{"threshold < 2", 1, 3},
		{"total < 2", 2, 1},
		{"threshold zero", 0, 5},
		{"total zero", 2, 0},
		{"total exceeds 255", 3, 256},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewSecretSharer(tt.threshold, tt.total)
			if err == nil {
				t.Errorf("expected error for threshold=%d, total=%d", tt.threshold, tt.total)
			}
		})
	}
}

func TestSecretSharer_SplitEmptySecret(t *testing.T) {
	sharer, err := NewSecretSharer(2, 3)
	if err != nil {
		t.Fatalf("NewSecretSharer failed: %v", err)
	}

	_, err = sharer.Split([]byte{})
	if err == nil {
		t.Fatal("expected error for empty secret")
	}
}

func TestSecretSharer_LargeSecret(t *testing.T) {
	sharer, err := NewSecretSharer(3, 5)
	if err != nil {
		t.Fatalf("NewSecretSharer(3, 5) failed: %v", err)
	}

	// Generate a large secret (1 KB).
	secret := make([]byte, 1024)
	for i := range secret {
		secret[i] = byte(i % 256)
	}

	shares, err := sharer.Split(secret)
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}

	recovered, err := sharer.Reconstruct(shares[:3])
	if err != nil {
		t.Fatalf("Reconstruct failed: %v", err)
	}
	if !bytes.Equal(recovered, secret) {
		t.Error("reconstructed large secret does not match original")
	}
}

func TestSecretSharer_TwoOfTwo(t *testing.T) {
	sharer, err := NewSecretSharer(2, 2)
	if err != nil {
		t.Fatalf("NewSecretSharer(2, 2) failed: %v", err)
	}

	secret := []byte("minimal-sharing")
	shares, err := sharer.Split(secret)
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}

	recovered, err := sharer.Reconstruct(shares)
	if err != nil {
		t.Fatalf("Reconstruct failed: %v", err)
	}
	if !bytes.Equal(recovered, secret) {
		t.Errorf("reconstructed secret mismatch:\n got: %q\nwant: %q", recovered, secret)
	}
}

func TestSecretSharer_AllBytesSecret(t *testing.T) {
	// Ensure every byte value 0x00-0xFF round-trips correctly.
	sharer, err := NewSecretSharer(3, 5)
	if err != nil {
		t.Fatalf("NewSecretSharer failed: %v", err)
	}

	secret := make([]byte, 256)
	for i := range secret {
		secret[i] = byte(i)
	}

	shares, err := sharer.Split(secret)
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}

	recovered, err := sharer.Reconstruct(shares[:3])
	if err != nil {
		t.Fatalf("Reconstruct failed: %v", err)
	}
	if !bytes.Equal(recovered, secret) {
		t.Error("all-bytes secret round-trip failed")
	}
}

func TestPrivateEvaluator_EvaluatePrivately(t *testing.T) {
	fixedTime := time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)

	eval, err := NewPrivateEvaluator(3, 5)
	if err != nil {
		t.Fatalf("NewPrivateEvaluator failed: %v", err)
	}
	eval.WithClock(func() time.Time { return fixedTime })

	// Create secret-shared input.
	sharer, _ := NewSecretSharer(3, 5)
	input := []byte(`{"action":"read","resource":"patient_record"}`)
	shares, err := sharer.Split(input)
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}

	// Assign party IDs.
	partyIDs := []string{"hospital-a", "hospital-b", "hospital-c", "hospital-d", "hospital-e"}
	for i := range shares {
		shares[i].PartyID = partyIDs[i]
	}

	req := PrivateEvalRequest{
		RequestID:   "eval-001",
		PolicyHash:  "sha256:abc123",
		InputShares: shares[:3],
		PartyIDs:    partyIDs[:3],
		Threshold:   3,
		Timestamp:   fixedTime,
	}

	// Policy function: allow reads, deny writes.
	policyFn := func(data []byte) (string, error) {
		if bytes.Contains(data, []byte(`"read"`)) {
			return "ALLOW", nil
		}
		return "DENY", nil
	}

	result, err := eval.EvaluatePrivately(req, policyFn)
	if err != nil {
		t.Fatalf("EvaluatePrivately failed: %v", err)
	}

	if result.RequestID != "eval-001" {
		t.Errorf("expected RequestID eval-001, got %s", result.RequestID)
	}
	if result.Verdict != "ALLOW" {
		t.Errorf("expected verdict ALLOW, got %s", result.Verdict)
	}
	if result.ProofHash == "" {
		t.Error("expected non-empty ProofHash")
	}
	if result.ContentHash == "" {
		t.Error("expected non-empty ContentHash")
	}
	if len(result.Parties) != 3 {
		t.Errorf("expected 3 parties, got %d", len(result.Parties))
	}
	if result.Timestamp != fixedTime {
		t.Errorf("expected timestamp %v, got %v", fixedTime, result.Timestamp)
	}
}

func TestPrivateEvaluator_ThresholdShares(t *testing.T) {
	eval, err := NewPrivateEvaluator(2, 4)
	if err != nil {
		t.Fatalf("NewPrivateEvaluator failed: %v", err)
	}

	sharer, _ := NewSecretSharer(2, 4)
	input := []byte(`{"action":"write","resource":"financial_record"}`)
	shares, err := sharer.Split(input)
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}

	for i := range shares {
		shares[i].PartyID = "party-" + string(rune('A'+i))
	}

	req := PrivateEvalRequest{
		RequestID:   "eval-002",
		PolicyHash:  "sha256:def456",
		InputShares: shares[:2], // exactly threshold
		Threshold:   2,
	}

	policyFn := func(data []byte) (string, error) {
		return "DENY", nil
	}

	result, err := eval.EvaluatePrivately(req, policyFn)
	if err != nil {
		t.Fatalf("EvaluatePrivately with threshold shares failed: %v", err)
	}

	if result.Verdict != "DENY" {
		t.Errorf("expected verdict DENY, got %s", result.Verdict)
	}
}

func TestPrivateEvaluator_InsufficientShares(t *testing.T) {
	eval, err := NewPrivateEvaluator(3, 5)
	if err != nil {
		t.Fatalf("NewPrivateEvaluator failed: %v", err)
	}

	req := PrivateEvalRequest{
		RequestID:   "eval-003",
		PolicyHash:  "sha256:ghi789",
		InputShares: []SecretShare{{}, {}}, // only 2, need 3
		Threshold:   3,
	}

	_, err = eval.EvaluatePrivately(req, func([]byte) (string, error) { return "ALLOW", nil })
	if err == nil {
		t.Fatal("expected error with insufficient shares")
	}
}

func TestPrivateEvaluator_InputZeroed(t *testing.T) {
	eval, err := NewPrivateEvaluator(2, 3)
	if err != nil {
		t.Fatalf("NewPrivateEvaluator failed: %v", err)
	}

	sharer, _ := NewSecretSharer(2, 3)
	input := []byte("secret-data-must-be-zeroed")
	shares, err := sharer.Split(input)
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}

	// Track the reconstructed bytes pointer through the policy function.
	var capturedInput []byte
	policyFn := func(data []byte) (string, error) {
		capturedInput = data // captures the slice header (same backing array)
		return "ALLOW", nil
	}

	req := PrivateEvalRequest{
		RequestID:   "eval-zero",
		PolicyHash:  "sha256:test",
		InputShares: shares[:2],
		Threshold:   2,
	}

	_, err = eval.EvaluatePrivately(req, policyFn)
	if err != nil {
		t.Fatalf("EvaluatePrivately failed: %v", err)
	}

	// After evaluation, the captured slice should be zeroed.
	for i, b := range capturedInput {
		if b != 0 {
			t.Errorf("input byte %d not zeroed: got %d", i, b)
		}
	}
}

func TestGF256_Arithmetic(t *testing.T) {
	// Verify basic GF(256) properties.

	// Multiplicative identity: a * 1 = a
	for a := 1; a < 256; a++ {
		if gfMul(byte(a), 1) != byte(a) {
			t.Errorf("gfMul(%d, 1) = %d, want %d", a, gfMul(byte(a), 1), a)
		}
	}

	// Multiplicative inverse: a * a^-1 = 1
	for a := 1; a < 256; a++ {
		inv := gfInv(byte(a))
		if gfMul(byte(a), inv) != 1 {
			t.Errorf("gfMul(%d, gfInv(%d)) = %d, want 1", a, a, gfMul(byte(a), inv))
		}
	}

	// Zero absorbs multiplication: a * 0 = 0
	for a := 0; a < 256; a++ {
		if gfMul(byte(a), 0) != 0 {
			t.Errorf("gfMul(%d, 0) = %d, want 0", a, gfMul(byte(a), 0))
		}
	}
}
