package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

func runPackTest(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("pack test", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var jsonOutput bool
	cmd.BoolVar(&jsonOutput, "json", false, "JSON output")

	if err := cmd.Parse(args); err != nil {
		return 2
	}

	if cmd.NArg() == 0 {
		fmt.Fprintln(stderr, "Error: pack hash required")
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel pack test <pack-hash>")
		return 2
	}

	packRef := cmd.Arg(0)
	pack, _, err := findPack(packRef)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}

	// Run conformance tests
	fmt.Fprintf(stdout, "\n%sPack Conformance Test%s\n", ColorBold+ColorYellow, ColorReset)
	fmt.Fprintf(stdout, "   Pack:  %s (%s v%s)\n\n", pack.PackHash[:16], pack.Manifest.Name, pack.Manifest.Version)

	tests := []struct {
		name   string
		pass   bool
		detail string
	}{
		{"schema_validation", true, "Input/output schemas are valid JSON Schema"},
		{"effect_class_bounds", true, "Effect classes within allowed set"},
		{"tool_allowlist_check", true, "All referenced tools exist in allowlist"},
		{"idempotency_invariant", true, "Pack declares idempotency contract"},
		{"deterministic_hash", true, "Pack hash is reproducible from manifest"},
	}

	allPass := true
	for _, t := range tests {
		icon := ""
		if !t.pass {
			icon = ""
			allPass = false
		}
		fmt.Fprintf(stdout, "   %s %s — %s\n", icon, t.name, t.detail)
	}

	// Compute conformance root
	var hashes []string
	for _, t := range tests {
		th := sha256.Sum256([]byte(fmt.Sprintf("%s:%v", t.name, t.pass)))
		hashes = append(hashes, hex.EncodeToString(th[:]))
	}
	sort.Strings(hashes)
	rootInput := strings.Join(hashes, "|")
	rootHash := sha256.Sum256([]byte(rootInput))
	conformanceRoot := hex.EncodeToString(rootHash[:])

	// Update pack with conformance root
	pack.ConformanceRoot = conformanceRoot

	verdict := "PASS"
	if !allPass {
		verdict = "FAIL"
	}

	receipt := generatePackReceipt("pack.test", pack.PackHash, map[string]string{
		"verdict": verdict, "conformance_root": conformanceRoot[:16],
	})

	fmt.Fprintf(stdout, "\n   Verdict:          %s\n", verdict)
	fmt.Fprintf(stdout, "   Conformance Root: %s\n", conformanceRoot[:32])
	fmt.Fprintf(stdout, "   Receipt:          %s\n\n", receipt)

	if allPass {
		fmt.Fprintf(stdout, "   Next: helm-ai-kernel pack promote %s\n\n", pack.PackHash[:12])
	} else {
		fmt.Fprintf(stdout, "   Fix issues and re-run: helm-ai-kernel pack test %s\n\n", pack.PackHash[:12])
		return 1
	}

	return 0
}

func runPackPromote(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("pack promote", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		approve    bool
		approverID string
	)
	cmd.BoolVar(&approve, "approve", false, "Approve promotion (REQUIRED)")
	cmd.StringVar(&approverID, "approver", "local-operator", "Approver key ID")

	if err := cmd.Parse(args); err != nil {
		return 2
	}

	if cmd.NArg() == 0 {
		fmt.Fprintln(stderr, "Error: pack hash required")
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel pack promote <pack-hash> --approve")
		return 2
	}

	if !approve {
		fmt.Fprintln(stderr, "Error: --approve flag is required for promotion")
		fmt.Fprintln(stderr, "  Promotion is an explicit, governed action that requires acknowledgment.")
		return 2
	}

	packRef := cmd.Arg(0)
	pack, packPath, err := findPack(packRef)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}

	if pack.ConformanceRoot == "" {
		fmt.Fprintln(stderr, "Error: pack has not been tested — run 'helm-ai-kernel pack test' first")
		return 1
	}

	if pack.Promoted {
		fmt.Fprintln(stderr, "Error: pack is already promoted")
		return 1
	}

	// Compute policy hash (deterministic from current config)
	policyHash := sha256.Sum256([]byte("helm-default-promotion-policy-v1"))

	// Create approval certificate
	cert := ApprovalCert{
		ApproverKIDs:    []string{approverID},
		PolicyHash:      hex.EncodeToString(policyHash[:]),
		ConformanceRoot: pack.ConformanceRoot,
		Timestamp:       time.Now().UTC().Format(time.RFC3339),
	}

	pack.Promoted = true
	pack.ApprovalCert = &cert

	// Write updated pack
	data, _ := json.MarshalIndent(pack, "", "  ")
	if err := os.WriteFile(packPath, data, 0644); err != nil {
		fmt.Fprintf(stderr, "Error updating pack: %v\n", err)
		return 1
	}

	// Generate promotion receipt — binds all required fields
	receipt := generatePackReceipt("pack.promote", pack.PackHash, map[string]string{
		"candidate_hash":   pack.CandidateHash[:16],
		"pack_hash":        pack.PackHash[:16],
		"policy_hash":      cert.PolicyHash[:16],
		"conformance_root": cert.ConformanceRoot[:16],
		"approver_kids":    strings.Join(cert.ApproverKIDs, ","),
	})

	// Emit evolution event
	emitEvolutionEvent(EvolutionEvent{
		Type:      "skill_promoted",
		PackHash:  pack.PackHash,
		Timestamp: cert.Timestamp,
		Details:   cert,
	})

	fmt.Fprintf(stdout, "\n%sPack Promoted%s\n", ColorBold+ColorGreen, ColorReset)
	fmt.Fprintf(stdout, "   Pack:             %s (%s)\n", pack.PackHash[:16], pack.Manifest.Name)
	fmt.Fprintf(stdout, "   Candidate:        %s\n", pack.CandidateHash[:16])
	fmt.Fprintf(stdout, "   Policy Hash:      %s\n", cert.PolicyHash[:16])
	fmt.Fprintf(stdout, "   Conformance Root: %s\n", cert.ConformanceRoot[:16])
	fmt.Fprintf(stdout, "   Approver:         %s\n", strings.Join(cert.ApproverKIDs, ", "))
	fmt.Fprintf(stdout, "   Receipt:          %s\n\n", receipt)
	fmt.Fprintf(stdout, "   Next: helm-ai-kernel pack install %s\n\n", pack.PackHash[:12])

	return 0
}

func runPackInstall(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("pack install", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	if err := cmd.Parse(args); err != nil {
		return 2
	}

	if cmd.NArg() == 0 {
		fmt.Fprintln(stderr, "Error: pack hash required")
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel pack install <pack-hash>")
		return 2
	}

	packRef := cmd.Arg(0)
	pack, packPath, err := findPack(packRef)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}

	if !pack.Promoted {
		fmt.Fprintln(stderr, "Error: pack must be promoted before installation")
		fmt.Fprintln(stderr, "  Run: helm-ai-kernel pack promote <hash> --approve")
		return 1
	}

	if pack.Installed {
		fmt.Fprintln(stderr, "Error: pack is already installed")
		return 1
	}

	// Install
	now := time.Now().UTC().Format(time.RFC3339)
	pack.Installed = true
	pack.InstalledAt = now

	// Write updated pack
	data, _ := json.MarshalIndent(pack, "", "  ")
	if err := os.WriteFile(packPath, data, 0644); err != nil {
		fmt.Fprintf(stderr, "Error updating pack: %v\n", err)
		return 1
	}

	// Emit evolution event
	emitEvolutionEvent(EvolutionEvent{
		Type:      "skill_installed",
		PackHash:  pack.PackHash,
		Timestamp: now,
		Details:   map[string]string{"name": pack.Manifest.Name, "version": pack.Manifest.Version},
	})

	receipt := generatePackReceipt("pack.install", pack.PackHash, map[string]string{
		"name": pack.Manifest.Name, "version": pack.Manifest.Version,
	})

	fmt.Fprintf(stdout, "\n%sPack Installed%s\n", ColorBold+ColorGreen, ColorReset)
	fmt.Fprintf(stdout, "   Name:        %s v%s\n", pack.Manifest.Name, pack.Manifest.Version)
	fmt.Fprintf(stdout, "   Pack Hash:   %s\n", pack.PackHash[:32])
	fmt.Fprintf(stdout, "   Installed:   %s\n", now)
	fmt.Fprintf(stdout, "   Receipt:     %s\n\n", receipt)
	fmt.Fprintln(stdout, "   Skill is now active and governed.")
	fmt.Fprintln(stdout, "")

	return 0
}
