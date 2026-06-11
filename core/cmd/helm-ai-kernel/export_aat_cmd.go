package main

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
		_, _ = fmt.Fprintln(stderr, "Error: --in and --agent-id are required (or use --verify)")
		return 2
	}

	data, err := os.ReadFile(inPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: cannot read %s: %v\n", inPath, err)
		return 2
	}
	var entries []*store.AuditEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %s is not a JSON array of audit entries: %v\n", inPath, err)
		return 2
	}

	var signer audit.AATSigner
	if signKeyHex != "" {
		seed, err := hex.DecodeString(signKeyHex)
		if err != nil || len(seed) != ed25519.SeedSize {
			_, _ = fmt.Fprintf(stderr, "Error: --sign-key must be a %d-byte hex Ed25519 seed\n", ed25519.SeedSize)
			return 2
		}
		signer, err = audit.NewEd25519AATSigner(ed25519.NewKeyFromSeed(seed))
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
			return 2
		}
	}

	records, err := audit.ConvertEntriesToAAT(entries, agentID, signer)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	jsonl, err := audit.MarshalAATJSONL(records)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}

	if outPath == "" {
		_, _ = stdout.Write(jsonl)
		return 0
	}
	if err := os.WriteFile(outPath, jsonl, 0600); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: cannot write %s: %v\n", outPath, err)
		return 2
	}
	_, _ = fmt.Fprintf(stdout, "Exported %d AAT records to %s\n", len(records), outPath)
	return 0
}

func verifyAATFile(path string, stdout, stderr io.Writer) int {
	data, err := os.ReadFile(path)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: cannot read %s: %v\n", path, err)
		return 2
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
			_, _ = fmt.Fprintf(stderr, "Error: line %d is not a valid AAT record: %v\n", line, err)
			return 2
		}
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: reading %s: %v\n", path, err)
		return 2
	}
	if err := audit.VerifyAATChain(records); err != nil {
		_, _ = fmt.Fprintf(stderr, "AAT verification FAILED: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "AAT chain OK: %d records verified\n", len(records))
	return 0
}
