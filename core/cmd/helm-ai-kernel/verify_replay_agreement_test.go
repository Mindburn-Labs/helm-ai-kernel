package main

// quantum_posture: these tests use throwaway Ed25519 keys only to compare what
// `verify` and `evidence inspect` conclude; they make no post-quantum or
// classical signature assurance.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/conform"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/tape"
)

// g2TapeFiles is a recorded tape as pack files, with gate G2's other replay
// evidence. editRow may change manifest rows before they are written.
func g2TapeFiles(t *testing.T, editRow func(rows []map[string]any)) map[string][]byte {
	t.Helper()
	recorder := tape.NewRecorder("run-g2")
	recorder.RecordTime("kernel")
	recorder.RecordToolOutput("executor", "tool-search", []byte(`["a","b"]`))
	recorder.RecordNetwork("connector", "https://api.example.test/data", []byte(`{"ok":true}`))
	files := map[string][]byte{
		"02_PROOFGRAPH/determinism_manifest.json": []byte(`{"live_hash":"sha256:same","replay_hash":"sha256:same"}`),
	}
	for _, entry := range recorder.Entries() {
		data, err := json.Marshal(entry)
		if err != nil {
			t.Fatal(err)
		}
		files[fmt.Sprintf("08_TAPES/entry_%04d.json", entry.Seq)] = data
	}
	data, err := json.Marshal(recorder.BuildManifest())
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		RunID   string           `json:"run_id"`
		Entries []map[string]any `json:"entries"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if editRow != nil {
		editRow(manifest.Entries)
	}
	if data, err = json.Marshal(manifest); err != nil {
		t.Fatal(err)
	}
	files["08_TAPES/tape_manifest.json"] = data
	return files
}

// F4: `verify` and `replay` judge one tape alike. A sealed pack that declares
// G2 and whose manifest says NETWORK where the entry says TOOL_OUTPUT was
// VERIFIED by `verify` (the manifest was only parsed) and DIVERGED by `replay`.
func TestVerifyAndReplayAgreeOnTheTapeOfAG2Pack(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("HELM_DATA_DIR", dataDir)

	for _, tc := range []struct {
		name       string
		editRow    func(rows []map[string]any)
		wantVerify int
		wantReplay string
	}{
		{name: "intact tape", wantVerify: 0, wantReplay: "COMPLETE"},
		{name: "manifest disagrees with an entry", editRow: func(rows []map[string]any) { rows[1]["type"] = "NETWORK" }, wantVerify: 1, wantReplay: "DIVERGED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			packDir := writeCLIPack(t, dataDir, cliPack{
				files:       g2TapeFiles(t, tc.editRow),
				indexFields: map[string]any{"gates": []string{"G0", "G2"}},
			})
			verifyCode, report, raw := verifyJSONReport(t, "--allow-self-attested", packDir)
			if verifyCode != tc.wantVerify {
				t.Fatalf("verify exit=%d, want %d\n%s", verifyCode, tc.wantVerify, raw)
			}
			replayCode, result, replayRaw := runReplayJSON(t, packDir)
			if result["replay_status"] != tc.wantReplay {
				t.Fatalf("replay status=%v, want %s\n%s", result["replay_status"], tc.wantReplay, replayRaw)
			}
			if (verifyCode == 0) != (replayCode == 0) {
				t.Fatalf("verify exit=%d and replay exit=%d disagree on one tape\nverify: %s\nreplay: %s", verifyCode, replayCode, raw, replayRaw)
			}
			if tc.wantReplay == "DIVERGED" {
				statuses := reportCheckStatuses(t, report)
				if statuses["replay_determinism"] != "FAILED" {
					t.Fatalf("replay_determinism = %s, want FAILED\n%s", statuses["replay_determinism"], raw)
				}
				if !strings.Contains(raw, `seq=2 manifest field \"type\" is \"NETWORK\"`) {
					t.Fatalf("verify does not carry the replay issue:\n%s", raw)
				}
			}
		})
	}
}

// F8 V1: `evidence inspect` checks a conformance report signature against
// HELM_VERIFY_PUBLIC_KEY_HEX, as `verify` does. Passing no key there left the
// signature unchecked and failed the pack, and no test noticed.
func TestEvidenceInspectChecksTheConformanceSignatureWithTheEnvironmentKey(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("HELM_DATA_DIR", dataDir)
	packDir := writeCLIPack(t, dataDir, cliPack{})
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conform.SignReport(packDir, "sha256:policy", "sha256:schemas", "test-signer", func(data []byte) (string, error) {
		return hex.EncodeToString(ed25519.Sign(priv, data)), nil
	}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HELM_VERIFY_PUBLIC_KEY_HEX", hex.EncodeToString(pub))

	verifyCode, verifyReport, verifyRaw := verifyJSONReport(t, "--allow-self-attested", packDir)
	inspectCode, inspectReport, inspectRaw := inspectJSONReport(t, "--allow-self-attested", packDir)
	if verifyCode != 0 || verifyReport["outcome"] != "VERIFIED" {
		t.Fatalf("verify exit=%d outcome=%v, want 0/VERIFIED with the conformance key set\n%s", verifyCode, verifyReport["outcome"], verifyRaw)
	}
	if inspectCode != verifyCode || inspectReport["outcome"] != verifyReport["outcome"] {
		t.Fatalf("evidence inspect exit=%d outcome=%v, verify exit=%d outcome=%v\n%s", inspectCode, inspectReport["outcome"], verifyCode, verifyReport["outcome"], inspectRaw)
	}
	if _, present := reportCheckStatuses(t, inspectReport)["signature_verification"]; present {
		t.Fatalf("evidence inspect did not check the conformance signature with the environment key\n%s", inspectRaw)
	}
}

// F8 V2: `evidence inspect` checks a host receipt chain against
// HELM_EXTERNAL_HOST_PUBLIC_KEY_HEX, as `verify` does.
func TestEvidenceInspectChecksHostEvidenceWithTheEnvironmentKey(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("HELM_DATA_DIR", dataDir)
	chainPath, pubHex := writeCLIHostChain(t, t.TempDir(), "workload-a", "203.0.113.10")
	chain, err := os.ReadFile(chainPath)
	if err != nil {
		t.Fatal(err)
	}
	packDir := writeCLIPack(t, dataDir, cliPack{files: map[string][]byte{"11_HOST_EVIDENCE/host/chain.json": chain}})
	t.Setenv("HELM_EXTERNAL_HOST_PUBLIC_KEY_HEX", pubHex)

	const signature = "11_HOST_EVIDENCE/host/chain.json:external_host:signature"
	_, verifyReport, verifyRaw := verifyJSONReport(t, "--allow-self-attested", packDir)
	_, inspectReport, inspectRaw := inspectJSONReport(t, "--allow-self-attested", packDir)
	if got := reportCheckStatuses(t, verifyReport)[signature]; got != "VERIFIED" {
		t.Fatalf("verify: %s = %q, want VERIFIED with the host key set\n%s", signature, got, verifyRaw)
	}
	if got := reportCheckStatuses(t, inspectReport)[signature]; got != "VERIFIED" {
		t.Fatalf("evidence inspect: %s = %q, want VERIFIED: it did not use the environment key\n%s", signature, got, inspectRaw)
	}
}
