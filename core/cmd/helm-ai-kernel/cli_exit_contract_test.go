package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	boundarypkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/store"
)

type surfaceCommand func([]string, io.Writer, io.Writer) int

func TestFailingSurfaceCommandsKeepJSONExitStatus(t *testing.T) {
	t.Setenv("HELM_DATA_DIR", t.TempDir())

	tests := []struct {
		name string
		args []string
		run  surfaceCommand
	}{
		{"boundary verify", []string{"--record-id", "missing"}, func(args []string, stdout, stderr io.Writer) int {
			return runBoundaryVerify(args, boundarypkg.NewSurfaceRegistry(time.Now), stdout, stderr)
		}},
		{"authz check", []string{"--stale"}, func(args []string, stdout, stderr io.Writer) int {
			return runAuthzCheck(args, boundarypkg.NewSurfaceRegistry(time.Now), stdout, stderr)
		}},
		{"mcp get", []string{"--server-id", "missing"}, runMCPGet},
		{"mcp auth-profile verify", []string{"--profile-id", "missing"}, func(args []string, stdout, stderr io.Writer) int {
			return runMCPAuthProfileVerify(args, boundarypkg.NewSurfaceRegistry(time.Now), stdout, stderr)
		}},
		{"sandbox get", []string{"--grant-id", "missing"}, runSandboxGet},
		{"sandbox verify", nil, runSandboxVerify},
		{"evidence envelope get", []string{"--manifest-id", "missing"}, runEvidenceEnvelopeGet},
		{"evidence envelope verify", nil, runEvidenceEnvelopeVerify},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var textOut, textErr bytes.Buffer
			textCode := test.run(test.args, &textOut, &textErr)

			var jsonOut, jsonErr bytes.Buffer
			jsonCode := test.run(append(append([]string{}, test.args...), "--json"), &jsonOut, &jsonErr)

			if textCode != 1 || jsonCode != textCode {
				t.Fatalf("failing exit drifted: text=%d json=%d\ntext=%s\njson=%s", textCode, jsonCode, textOut.String(), jsonOut.String())
			}
			var payload any
			if err := json.Unmarshal(jsonOut.Bytes(), &payload); err != nil {
				t.Fatalf("JSON failure output is not parseable: %v\n%s", err, jsonOut.String())
			}
		})
	}
}

type acceptingApprovalAssertionVerifier struct{}

func (acceptingApprovalAssertionVerifier) VerifyApprovalAssertion(contracts.ApprovalWebAuthnChallenge, contracts.ApprovalWebAuthnAssertion) error {
	return nil
}

func TestApprovalsAssertKeepsJSONExitStatusWhileQuorumIsPending(t *testing.T) {
	run := func(jsonOutput bool) (int, string) {
		registry := boundarypkg.NewSurfaceRegistry(time.Now)
		now := time.Now().UTC()
		_, err := registry.PutApproval(contracts.ApprovalCeremony{
			ApprovalID:    "approval-quorum",
			Subject:       "deploy",
			Action:        "approve",
			State:         contracts.ApprovalCeremonyPending,
			RequestedBy:   "agent:requester",
			Quorum:        2,
			TimelockUntil: now.Add(-time.Minute),
			ExpiresAt:     now.Add(time.Hour),
			CreatedAt:     now,
			UpdatedAt:     now,
		})
		if err != nil {
			t.Fatal(err)
		}
		registry.SetApprovalAssertionVerifier(acceptingApprovalAssertionVerifier{})
		challenge, err := registry.CreateApprovalChallenge("approval-quorum", "passkey", time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		args := []string{
			"--challenge-id", challenge.ChallengeID,
			"--actor", "user:reviewer",
			"--assertion", "verified-assertion",
			"--receipt-id", "receipt-review",
		}
		if jsonOutput {
			args = append(args, "--json")
		}
		var stdout, stderr bytes.Buffer
		return runApprovalsAssert(args, registry, &stdout, &stderr), stdout.String()
	}

	textCode, _ := run(false)
	jsonCode, jsonOut := run(true)
	if textCode != 1 || jsonCode != textCode {
		t.Fatalf("pending quorum exit drifted: text=%d json=%d\njson=%s", textCode, jsonCode, jsonOut)
	}
	var payload any
	if err := json.Unmarshal([]byte(jsonOut), &payload); err != nil {
		t.Fatalf("JSON approval output is not parseable: %v\n%s", err, jsonOut)
	}
}

func TestReportChainFailureReturnsNonzeroInEveryOutputMode(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "broken-chain.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	receipts, err := store.NewSQLiteReceiptStore(db)
	if err != nil {
		t.Fatal(err)
	}
	for i, id := range []string{"receipt-a", "receipt-b"} {
		if err := receipts.Store(context.Background(), &contracts.Receipt{
			ReceiptID:    id,
			DecisionID:   "decision-" + id,
			EffectID:     "effect-" + id,
			Status:       "ALLOW",
			LamportClock: 1,
			Timestamp:    time.Unix(int64(i+1), 0).UTC(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	outputPath := filepath.Join(t.TempDir(), "report.txt")
	tests := []struct {
		name string
		args []string
	}{
		{"text", []string{"--db", dbPath}},
		{"json", []string{"--db", dbPath, "--json"}},
		{"file", []string{"--db", dbPath, "--output", outputPath}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := runReportCmd(test.args, &stdout, &stderr); code != 1 {
				t.Fatalf("broken chain exit=%d, want 1\nstdout=%s\nstderr=%s", code, stdout.String(), stderr.String())
			}
		})
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte("FAILED")) {
		t.Fatalf("file report does not expose the chain failure: %s", data)
	}
}
