package zk

import (
	"context"
	"encoding/json"
	"testing"
)

func TestSafetyGuestProgram_Execute(t *testing.T) {
	assertions := SafetyAssertion{
		BannedImports: []string{"os/exec", "net"},
		SandboxPaths:  []string{"/Users/ivan/Code/Mindburn-Labs/helm-ai-kernel"},
		AllowNetwork:  false,
		MaxFileSize:   1024,
	}

	program := NewSafetyGuestProgram([]byte("test_image_id"))

	tests := []struct {
		name       string
		proposal   string
		wantSafe   bool
		violations []string
	}{
		{
			name: "Standard safe proposal",
			proposal: `package main
import "fmt"
func main() {
	fmt.Println("Hello safe world")
}`,
			wantSafe: true,
		},
		{
			name: "Banned import - os/exec",
			proposal: `package main
import "os/exec"
func main() {
	cmd := exec.Command("ls")
	cmd.Run()
}`,
			wantSafe:   false,
			violations: []string{"contains banned import: os/exec"},
		},
		{
			name: "Network ban violation",
			proposal: `package main
import "fmt"
func main() {
	url := "https://malicious.api/leak"
	fmt.Println(url)
}`,
			wantSafe:   false,
			violations: []string{"violates network ban: found pattern https://"},
		},
		{
			name: "Sandbox path violation",
			proposal: `package main
import "os"
func main() {
	data, _ := os.ReadFile("/etc/passwd")
	_ = data
}`,
			wantSafe:   false,
			violations: []string{"attempts to reference path outside sandbox: /etc/passwd"},
		},
		{
			name: "Allowed sandbox path",
			proposal: `package main
import "os"
func main() {
	data, _ := os.ReadFile("/Users/ivan/Code/Mindburn-Labs/helm-ai-kernel/core/main.go")
	_ = data
}`,
			wantSafe: true,
		},
		{
			name:       "File size limit violation",
			proposal:   string(make([]byte, 2048)),
			wantSafe:   false,
			violations: []string{"proposal size 2048 exceeds limit of 1024"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			journal := program.Execute([]byte(tt.proposal), assertions)
			if journal.IsSafe != tt.wantSafe {
				t.Errorf("Execute() IsSafe = %v, want %v. Violations: %v", journal.IsSafe, tt.wantSafe, journal.Violations)
			}
			if !tt.wantSafe && len(journal.Violations) == 0 {
				t.Error("Execute() expected violations, got none")
			}
			for _, expectedViolation := range tt.violations {
				found := false
				for _, v := range journal.Violations {
					if v == expectedViolation {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Execute() missing expected violation: %q. Got: %v", expectedViolation, journal.Violations)
				}
			}
		})
	}
}

func TestZKVMGuestSafetyChecker_AttestAndVerify(t *testing.T) {
	imageID := "my_guest_safety_image"
	checker := NewZKVMGuestSafetyChecker(imageID)
	verifier := NewRISCZeroVerifier(imageID)

	ctx := context.Background()
	assertions := SafetyAssertion{
		BannedImports: []string{"unsafe"},
		SandboxPaths:  []string{"/Users/ivan"},
		AllowNetwork:  true,
		MaxFileSize:   500,
	}

	proposal := []byte(`package main
import "fmt"
func main() {
	fmt.Println("Sovereign stance holds")
}`)

	// 1. Success path
	receipt, err := checker.Attest(ctx, proposal, assertions, false)
	if err != nil {
		t.Fatalf("Attest failed: %v", err)
	}

	receiptBytes, err := json.Marshal(receipt)
	if err != nil {
		t.Fatalf("json.Marshal(receipt) failed: %v", err)
	}

	// Verify using the Verifier
	ok, err := verifier.VerifyReceipt(ctx, receiptBytes, receipt.Journal)
	if err != nil {
		t.Errorf("VerifyReceipt failed: %v", err)
	}
	if !ok {
		t.Error("VerifyReceipt returned false, expected true")
	}

	// Verify journal structure
	var journal SafetyJournal
	if err := json.Unmarshal(receipt.Journal, &journal); err != nil {
		t.Fatalf("Failed to unmarshal safety journal: %v", err)
	}
	if !journal.IsSafe {
		t.Errorf("Expected proposal to be certified safe, violations: %v", journal.Violations)
	}

	// 2. Failure path: Arbitrary non-empty seals must not verify.
	randomSealReceipt := *receipt
	randomSealReceipt.Seal = []byte("x")
	randomSealBytes, err := json.Marshal(&randomSealReceipt)
	if err != nil {
		t.Fatalf("json.Marshal(randomSealReceipt) failed: %v", err)
	}
	ok, err = verifier.VerifyReceipt(ctx, randomSealBytes, randomSealReceipt.Journal)
	if err == nil {
		t.Error("VerifyReceipt expected error on random seal, got nil")
	}
	if ok {
		t.Error("VerifyReceipt accepted arbitrary non-empty seal")
	}

	// 3. Failure path: Replaying the seal under another image ID must fail.
	wrongImageReceipt := *receipt
	wrongImageReceipt.ImageID = []byte("other_guest_image")
	wrongImageBytes, err := json.Marshal(&wrongImageReceipt)
	if err != nil {
		t.Fatalf("json.Marshal(wrongImageReceipt) failed: %v", err)
	}
	ok, err = verifier.VerifyReceipt(ctx, wrongImageBytes, wrongImageReceipt.Journal)
	if err == nil {
		t.Error("VerifyReceipt expected error on wrong image ID, got nil")
	}
	if ok {
		t.Error("VerifyReceipt accepted wrong image ID")
	}

	// 4. Failure path: Matching proof material cannot be reused for a different expected journal.
	ok, err = verifier.VerifyReceipt(ctx, receiptBytes, []byte("other journal"))
	if err == nil {
		t.Error("VerifyReceipt expected error on wrong expected journal, got nil")
	}
	if ok {
		t.Error("VerifyReceipt accepted wrong expected journal")
	}

	// 5. Failure path: Invalid Seal
	receiptFail, err := checker.Attest(ctx, proposal, assertions, true)
	if err != nil {
		t.Fatalf("Attest failed: %v", err)
	}

	receiptFailBytes, err := json.Marshal(receiptFail)
	if err != nil {
		t.Fatalf("json.Marshal(receiptFail) failed: %v", err)
	}

	ok, err = verifier.VerifyReceipt(ctx, receiptFailBytes, receiptFail.Journal)
	if err == nil {
		t.Error("VerifyReceipt expected error on invalid seal, got nil")
	}
	if ok {
		t.Error("VerifyReceipt expected false on invalid seal, got true")
	}

	// 6. Failure path: Empty proposal
	_, err = checker.Attest(ctx, nil, assertions, false)
	if err == nil {
		t.Error("Attest expected error on empty proposal, got nil")
	}
}
