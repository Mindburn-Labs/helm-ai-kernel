package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"
)

const reportSchemaVersion = "1"

// shortHash safely truncates a hash string.
func shortHash(h string, n int) string {
	if n <= 0 {
		return ""
	}
	if len(h) <= n {
		return h
	}
	return h[:n]
}

// lastReceipt safely returns the last receipt.
func lastReceipt(receipts []demoReceipt) (demoReceipt, bool) {
	if len(receipts) == 0 {
		return demoReceipt{}, false
	}
	return receipts[len(receipts)-1], true
}

// buildNarrative generates a human-readable summary from receipts.
func buildNarrative(receipts []demoReceipt) string {
	principals := map[string]bool{}
	hasDeny := false
	hasSkill := false
	hasMaint := false
	for _, r := range receipts {
		principals[r.Principal] = true
		if r.Verdict == "DENY" {
			hasDeny = true
		}
		if r.Action == "DETECT_SKILL_GAP" || r.Action == "AUTO_APPROVE_SKILL" {
			hasSkill = true
		}
		if r.Action == "INCIDENT_CREATED" || r.Action == "MAINTENANCE_RUN" {
			hasMaint = true
		}
	}
	parts := []string{fmt.Sprintf("%d principals executed %d actions across the governance lifecycle", len(principals), len(receipts))}
	if hasDeny {
		parts = append(parts, "one destructive action was blocked")
	}
	if hasSkill {
		parts = append(parts, "a skill gap was detected and resolved")
	}
	if hasMaint {
		parts = append(parts, "maintenance repaired an incident and verified conformance")
	}
	return strings.Join(parts, "; ") + "."
}

// getBuildInfo returns version control info if available.
func getBuildInfo() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" {
			if len(s.Value) > 12 {
				return s.Value[:12]
			}
			return s.Value
		}
	}
	return "unknown"
}

// verifyChain checks receipt chain integrity and returns derived checks.
func verifyChain(receipts []demoReceipt) (chainOK, lamportMonotonic, denyPresent, skillPresent, maintPresent, isDemoMode bool, denyTool, denyReason string) {
	chainOK = true
	lamportMonotonic = true
	for i, r := range receipts {
		if i > 0 {
			if r.PrevHash != receipts[i-1].Hash {
				chainOK = false
			}
			if r.Lamport <= receipts[i-1].Lamport {
				lamportMonotonic = false
			}
		}
		if r.Verdict == "DENY" {
			denyPresent = true
			denyTool = r.Tool
			denyReason = r.ReasonCode
		}
		if r.Action == "DETECT_SKILL_GAP" || r.Action == "AUTO_APPROVE_SKILL" {
			skillPresent = true
		}
		if r.Action == "INCIDENT_CREATED" || r.Action == "MAINTENANCE_RUN" {
			maintPresent = true
		}
		if r.Mode == "demo" {
			isDemoMode = true
		}
	}
	return
}

func generateProofReportJSON(receipts []demoReceipt, outDir, template, provider string) error {
	reportPath := filepath.Join(outDir, "run-report.json")

	if len(receipts) == 0 {
		return fmt.Errorf("no receipts to report")
	}

	last, _ := lastReceipt(receipts)
	chainOK, lamportOK, denyPresent, skillPresent, maintPresent, isDemoMode, denyTool, denyReason := verifyChain(receipts)

	report := map[string]any{
		"version":        "0.2.0",
		"schema_version": reportSchemaVersion,
		"generated_at":   time.Now().UTC().Format(time.RFC3339),
		"template":       template,
		"provider":       provider,
		"receipts":       receipts,
		"narrative":      buildNarrative(receipts),
		"summary": map[string]any{
			"total":             len(receipts),
			"lamport_final":     last.Lamport,
			"root_hash":         last.Hash,
			"chain_verified":    chainOK,
			"lamport_monotonic": lamportOK,
			"deny_path_tested":  denyPresent,
			"deny_tool":         denyTool,
			"deny_reason":       denyReason,
			"skill_lifecycle":   skillPresent,
			"maintenance":       maintPresent,
			"is_demo":           isDemoMode,
		},
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal report JSON: %w", err)
	}
	return os.WriteFile(reportPath, data, 0644)
}
