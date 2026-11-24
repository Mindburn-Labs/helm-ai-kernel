package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ── SkillCandidate ──────────────────────────────────────────────────────────

// SkillCandidate is a structured artifact describing a proposed capability
// extension. It is the input to the Pack build pipeline.
type SkillCandidate struct {
	Name              string            `json:"name"`
	Version           string            `json:"version"`
	Purpose           string            `json:"purpose"`
	Inputs            []FieldSpec       `json:"inputs"`
	Outputs           []FieldSpec       `json:"outputs"`
	AllowedTools      []string          `json:"allowed_tools"`
	EffectClasses     []string          `json:"effect_classes"`
	Invariants        []string          `json:"invariants"`
	Idempotent        bool              `json:"idempotent"`
	RequiredApprovals int               `json:"required_approvals"`
	Risk              string            `json:"risk"` // low | medium | high | critical
	Metadata          map[string]string `json:"metadata,omitempty"`
	Hash              string            `json:"hash"`
	CreatedAt         string            `json:"created_at"`
}

// FieldSpec describes a single input or output field.
type FieldSpec struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Required bool   `json:"required"`
}

// ── SkillPack ───────────────────────────────────────────────────────────────

// SkillPack is a built, testable, promotable unit of capability extension.
type SkillPack struct {
	CandidateHash   string            `json:"candidate_hash"`
	PackHash        string            `json:"pack_hash"`
	Manifest        PackManifest      `json:"manifest"`
	ConformanceRoot string            `json:"conformance_root,omitempty"`
	Promoted        bool              `json:"promoted"`
	ApprovalCert    *ApprovalCert     `json:"approval_cert,omitempty"`
	Installed       bool              `json:"installed"`
	InstalledAt     string            `json:"installed_at,omitempty"`
	Metadata        map[string]string `json:"metadata,omitempty"`
}

// PackManifest describes the contents of a SkillPack.
type PackManifest struct {
	Name          string   `json:"name"`
	Version       string   `json:"version"`
	Purpose       string   `json:"purpose"`
	AllowedTools  []string `json:"allowed_tools"`
	EffectClasses []string `json:"effect_classes"`
	Schemas       []string `json:"schemas"` // paths to JSON schemas
	Tests         []string `json:"tests"`   // paths to test files
	Docs          []string `json:"docs"`    // paths to documentation
}

// ApprovalCert records a promotion approval decision.
type ApprovalCert struct {
	ApproverKIDs    []string `json:"approver_kids"`
	PolicyHash      string   `json:"policy_hash"`
	ConformanceRoot string   `json:"conformance_root"`
	Timestamp       string   `json:"timestamp"`
	Signature       string   `json:"signature,omitempty"`
}

// ── Evolution Event ─────────────────────────────────────────────────────────

// EvolutionEvent records a system change event.
type EvolutionEvent struct {
	Type      string `json:"type"` // skill_installed | skill_promoted | maintenance_applied
	PackHash  string `json:"pack_hash,omitempty"`
	Timestamp string `json:"timestamp"`
	Details   any    `json:"details,omitempty"`
}

func runPackList(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("pack list", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var jsonOutput bool
	cmd.BoolVar(&jsonOutput, "json", false, "JSON output")

	if err := cmd.Parse(args); err != nil {
		return 2
	}

	fmt.Fprintf(stdout, "\n%sSkill Lifecycle Status%s\n\n", ColorBold+ColorBlue, ColorReset)

	// List candidates
	candidatesDir := filepath.Join("data", "candidates")
	candidates, _ := filepath.Glob(filepath.Join(candidatesDir, "*.json"))
	fmt.Fprintf(stdout, "  Candidates (%d):\n", len(candidates))
	for _, f := range candidates {
		data, _ := os.ReadFile(f)
		var c SkillCandidate
		_ = json.Unmarshal(data, &c)
		fmt.Fprintf(stdout, "    • %s (%s) risk=%s hash=%s\n", c.Name, c.Purpose, c.Risk, c.Hash[:12])
	}

	// List packs
	packsDir := filepath.Join("data", "packs")
	packs, _ := filepath.Glob(filepath.Join(packsDir, "*.json"))
	fmt.Fprintf(stdout, "\n  Packs (%d):\n", len(packs))
	for _, f := range packs {
		data, _ := os.ReadFile(f)
		var p SkillPack
		_ = json.Unmarshal(data, &p)
		status := "built"
		if p.Installed {
			status = "installed"
		} else if p.Promoted {
			status = "promoted"
		} else if p.ConformanceRoot != "" {
			status = "tested"
		}
		fmt.Fprintf(stdout, "    • %s v%s — %s (hash=%s)\n",
			p.Manifest.Name, p.Manifest.Version, status, p.PackHash[:12])
	}

	fmt.Fprintln(stdout, "")
	return 0
}

// ── Helpers ─────────────────────────────────────────────────────────────────

func findCandidate(ref string) (*SkillCandidate, string, error) {
	candidatesDir := filepath.Join("data", "candidates")
	files, err := filepath.Glob(filepath.Join(candidatesDir, "*.json"))
	if err != nil || len(files) == 0 {
		return nil, "", fmt.Errorf("no candidates found in %s", candidatesDir)
	}

	for _, f := range files {
		data, _ := os.ReadFile(f)
		var c SkillCandidate
		if err := json.Unmarshal(data, &c); err != nil {
			continue
		}
		if strings.HasPrefix(c.Hash, ref) || strings.Contains(filepath.Base(f), ref) {
			return &c, f, nil
		}
	}
	return nil, "", fmt.Errorf("candidate %q not found", ref)
}

func findPack(ref string) (*SkillPack, string, error) {
	packsDir := filepath.Join("data", "packs")
	files, err := filepath.Glob(filepath.Join(packsDir, "*.json"))
	if err != nil || len(files) == 0 {
		return nil, "", fmt.Errorf("no packs found in %s", packsDir)
	}

	for _, f := range files {
		data, _ := os.ReadFile(f)
		var p SkillPack
		if err := json.Unmarshal(data, &p); err != nil {
			continue
		}
		if strings.HasPrefix(p.PackHash, ref) || strings.Contains(filepath.Base(f), ref) {
			return &p, f, nil
		}
	}
	return nil, "", fmt.Errorf("pack %q not found", ref)
}

func generatePackReceipt(action, hash string, meta map[string]string) string {
	// Generate a receipt for a pack lifecycle event
	input := fmt.Sprintf("%s:%s:%v", action, hash, meta)
	h := sha256.Sum256([]byte(input))
	receiptID := fmt.Sprintf("pack-%s", hex.EncodeToString(h[:8]))

	// Append to receipts file
	receiptData := map[string]any{
		"receipt_id": receiptID,
		"action":     action,
		"hash":       hash,
		"metadata":   meta,
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
	}
	data, _ := json.Marshal(receiptData)

	receiptsDir := filepath.Join("data", "receipts")
	_ = os.MkdirAll(receiptsDir, 0750)
	f, err := os.OpenFile(filepath.Join(receiptsDir, "pack-receipts.jsonl"),
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		_, _ = f.Write(append(data, '\n'))
		_ = f.Close()
	}

	return receiptID
}

func emitEvolutionEvent(evt EvolutionEvent) {
	data, _ := json.Marshal(evt)
	eventsDir := filepath.Join("data", "events")
	_ = os.MkdirAll(eventsDir, 0750)
	f, err := os.OpenFile(filepath.Join(eventsDir, "evolution.jsonl"),
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		_, _ = f.Write(append(data, '\n'))
		_ = f.Close()
	}
}
