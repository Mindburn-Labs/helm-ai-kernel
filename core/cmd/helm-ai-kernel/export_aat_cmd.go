package main

// quantum_posture: AAT record signatures are optional classical Ed25519
// (operator-supplied seed); chain integrity is classical-only and no
// post-quantum assurance is claimed for this export/verify path.

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	cliui "github.com/Mindburn-Labs/helm-ai-kernel/core/internal/cli/ui"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/audit"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/store"
)

// runExportAATCmd implements `helm-ai-kernel export aat`.
//
// Converts exported audit store entries (the events.json produced by the
// audit evidence pack) into an IETF draft-sharif-agent-audit-trail
// conformant JSON Lines chain, or verifies an existing AAT chain.
//
// Exit codes:
//
//	0 = export/verify completed
//	1 = verification failed (chain broken or signature invalid)
//	2 = usage or runtime error
func runExportAATCmd(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("export aat", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		inPath     string
		outPath    string
		agentID    string
		signKeyHex string
		verifyPath string
	)

	cmd.StringVar(&inPath, "in", "", "Path to audit entries JSON array (events.json)")
	cmd.StringVar(&outPath, "out", "", "Output path for AAT JSONL (default: stdout)")
	cmd.StringVar(&agentID, "agent-id", "", "Agent identity recorded on every AAT record (REQUIRED for export)")
	cmd.StringVar(&signKeyHex, "sign-key", "", "Hex-encoded Ed25519 seed for optional record signatures")
	cmd.StringVar(&verifyPath, "verify", "", "Verify an existing AAT JSONL chain instead of exporting")

	if err := cmd.Parse(args); err != nil {
		return 2
	}

	if verifyPath != "" {
		return verifyAATFile(verifyPath, stdout, stderr)
	}

	if inPath == "" || agentID == "" {
		return cliui.WriteError(stderr, cliui.UsageErrorf("export aat", "--in and --agent-id are required (or use --verify)"))
	}

	data, err := os.ReadFile(inPath)
	if err != nil {
		return cliui.WriteError(stderr, cliui.Wrapf(err, cliui.ExitUsage, "export aat", "cannot read %s", inPath))
	}
	var entries []*store.AuditEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return cliui.WriteError(stderr, cliui.Wrapf(err, cliui.ExitUsage, "export aat", "%s is not a JSON array of audit entries", inPath))
	}

	var signer audit.AATSigner
	if signKeyHex != "" {
		seed, err := hex.DecodeString(signKeyHex)
		if err != nil || len(seed) != ed25519.SeedSize {
			return cliui.WriteError(stderr, cliui.UsageErrorf("export aat", "--sign-key must be a %d-byte hex Ed25519 seed", ed25519.SeedSize))
		}
		signer, err = audit.NewEd25519AATSigner(ed25519.NewKeyFromSeed(seed))
		if err != nil {
			return cliui.WriteError(stderr, cliui.Wrapf(err, cliui.ExitUsage, "export aat", ""))
		}
	}

	records, err := audit.ConvertEntriesToAAT(entries, agentID, signer)
	if err != nil {
		return cliui.WriteError(stderr, cliui.Wrapf(err, cliui.ExitUsage, "export aat", ""))
	}
	jsonl, err := audit.MarshalAATJSONL(records)
	if err != nil {
		return cliui.WriteError(stderr, cliui.Wrapf(err, cliui.ExitUsage, "export aat", ""))
	}

	if outPath == "" {
		_, _ = stdout.Write(jsonl)
		return 0
	}
	if err := os.WriteFile(outPath, jsonl, 0600); err != nil {
		return cliui.WriteError(stderr, cliui.Wrapf(err, cliui.ExitUsage, "export aat", "cannot write %s", outPath))
	}
	_, _ = fmt.Fprintf(stdout, "Exported %d AAT records to %s\n", len(records), outPath)
	return 0
}

func verifyAATFile(path string, stdout, stderr io.Writer) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return cliui.WriteError(stderr, cliui.Wrapf(err, cliui.ExitUsage, "export aat --verify", "cannot read %s", path))
	}
	var records []audit.AATRecord
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024)
	line := 0
	for scanner.Scan() {
		line++
		raw := bytes.TrimSpace(scanner.Bytes())
		if len(raw) == 0 {
			continue
		}
		var record audit.AATRecord
		if err := json.Unmarshal(raw, &record); err != nil {
			return cliui.WriteError(stderr, cliui.Wrapf(err, cliui.ExitUsage, "export aat --verify", "line %d is not a valid AAT record", line))
		}
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		return cliui.WriteError(stderr, cliui.Wrapf(err, cliui.ExitUsage, "export aat --verify", "reading %s", path))
	}
	if err := audit.VerifyAATChain(records); err != nil {
		return cliui.WriteError(stderr, cliui.Wrapf(err, cliui.ExitFailure, "", "AAT verification FAILED"))
	}
	_, _ = fmt.Fprintf(stdout, "AAT chain OK: %d records verified\n", len(records))
	return 0
}
