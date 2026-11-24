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

func runPackPropose(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("pack propose", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		name       string
		purpose    string
		tools      string
		effects    string
		risk       string
		inputs     string
		outputs    string
		invariants string
		idempotent bool
		approvals  int
	)

	cmd.StringVar(&name, "name", "", "Skill name (REQUIRED)")
	cmd.StringVar(&purpose, "purpose", "", "Purpose description (REQUIRED)")
	cmd.StringVar(&tools, "tools", "", "Allowed tools (comma-separated)")
	cmd.StringVar(&effects, "effects", "", "Effect classes (comma-separated: read,write,network,execute)")
	cmd.StringVar(&risk, "risk", "low", "Risk level: low, medium, high, critical")
	cmd.StringVar(&inputs, "inputs", "", "Input fields (name:type pairs, comma-separated)")
	cmd.StringVar(&outputs, "outputs", "", "Output fields (name:type pairs, comma-separated)")
	cmd.StringVar(&invariants, "invariants", "", "Invariants (comma-separated)")
	cmd.BoolVar(&idempotent, "idempotent", false, "Whether the skill is idempotent")
	cmd.IntVar(&approvals, "approvals", 1, "Number of required approvals")

	if err := cmd.Parse(args); err != nil {
		return 2
	}

	if name == "" || purpose == "" {
		fmt.Fprintln(stderr, "Error: --name and --purpose are required")
		return 2
	}

	// Validate risk level
	validRisks := map[string]bool{"low": true, "medium": true, "high": true, "critical": true}
	if !validRisks[risk] {
		fmt.Fprintf(stderr, "Error: --risk must be one of: low, medium, high, critical (got %q)\n", risk)
		return 2
	}

	// Parse field specs
	parseFields := func(s string) []FieldSpec {
		if s == "" {
			return nil
		}
		var specs []FieldSpec
		for _, f := range strings.Split(s, ",") {
			parts := strings.SplitN(strings.TrimSpace(f), ":", 2)
			spec := FieldSpec{Name: parts[0], Type: "string", Required: true}
			if len(parts) == 2 {
				spec.Type = parts[1]
			}
			specs = append(specs, spec)
		}
		return specs
	}

	parseSplit := func(s string) []string {
		if s == "" {
			return nil
		}
		var result []string
		for _, item := range strings.Split(s, ",") {
			result = append(result, strings.TrimSpace(item))
		}
		return result
	}

	candidate := SkillCandidate{
		Name:              name,
		Version:           "1.0.0",
		Purpose:           purpose,
		Inputs:            parseFields(inputs),
		Outputs:           parseFields(outputs),
		AllowedTools:      parseSplit(tools),
		EffectClasses:     parseSplit(effects),
		Invariants:        parseSplit(invariants),
		Idempotent:        idempotent,
		RequiredApprovals: approvals,
		Risk:              risk,
		CreatedAt:         time.Now().UTC().Format(time.RFC3339),
	}

	// Compute deterministic hash over canonical fields
	candidate.Hash = computeCandidateHash(&candidate)

	// Store candidate
	candidatesDir := filepath.Join("data", "candidates")
	if err := os.MkdirAll(candidatesDir, 0750); err != nil {
		fmt.Fprintf(stderr, "Error creating candidates dir: %v\n", err)
		return 1
	}

	filename := fmt.Sprintf("%s-%s.json", candidate.Name, candidate.Hash[:12])
	data, _ := json.MarshalIndent(candidate, "", "  ")
	if err := os.WriteFile(filepath.Join(candidatesDir, filename), data, 0644); err != nil {
		fmt.Fprintf(stderr, "Error writing candidate: %v\n", err)
		return 1
	}

	// Generate receipt
	receipt := generatePackReceipt("pack.propose", candidate.Hash, map[string]string{
		"name": name, "risk": risk, "purpose": purpose,
	})

	fmt.Fprintf(stdout, "\n%sSkillCandidate Created%s\n", ColorBold+ColorBlue, ColorReset)
	fmt.Fprintf(stdout, "   Name:      %s\n", name)
	fmt.Fprintf(stdout, "   Purpose:   %s\n", purpose)
	fmt.Fprintf(stdout, "   Risk:      %s\n", risk)
	fmt.Fprintf(stdout, "   Hash:      %s\n", candidate.Hash)
	fmt.Fprintf(stdout, "   Receipt:   %s\n", receipt)
	fmt.Fprintf(stdout, "   File:      %s\n\n", filepath.Join(candidatesDir, filename))
	fmt.Fprintf(stdout, "   Next: helm-ai-kernel pack build %s\n\n", candidate.Hash[:12])

	return 0
}

func runPackBuild(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("pack build", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	if err := cmd.Parse(args); err != nil {
		return 2
	}

	if cmd.NArg() == 0 {
		fmt.Fprintln(stderr, "Error: candidate hash required")
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel pack build <candidate-hash>")
		return 2
	}

	candidateRef := cmd.Arg(0)

	// Find candidate file
	candidate, candidatePath, err := findCandidate(candidateRef)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}

	// Build pack
	pack := SkillPack{
		CandidateHash: candidate.Hash,
		Manifest: PackManifest{
			Name:          candidate.Name,
			Version:       candidate.Version,
			Purpose:       candidate.Purpose,
			AllowedTools:  candidate.AllowedTools,
			EffectClasses: candidate.EffectClasses,
			Schemas:       []string{fmt.Sprintf("schemas/%s.input.json", candidate.Name), fmt.Sprintf("schemas/%s.output.json", candidate.Name)},
			Tests:         []string{fmt.Sprintf("tests/%s_test.json", candidate.Name)},
			Docs:          []string{fmt.Sprintf("docs/%s.md", candidate.Name)},
		},
	}

	// Compute pack hash
	packData, _ := json.Marshal(pack.Manifest)
	h := sha256.Sum256(packData)
	pack.PackHash = hex.EncodeToString(h[:])

	// Store pack
	packsDir := filepath.Join("data", "packs")
	if err := os.MkdirAll(packsDir, 0750); err != nil {
		fmt.Fprintf(stderr, "Error creating packs dir: %v\n", err)
		return 1
	}

	filename := fmt.Sprintf("%s-%s.json", candidate.Name, pack.PackHash[:12])
	data, _ := json.MarshalIndent(pack, "", "  ")
	if err := os.WriteFile(filepath.Join(packsDir, filename), data, 0644); err != nil {
		fmt.Fprintf(stderr, "Error writing pack: %v\n", err)
		return 1
	}

	// Create minimal schemas for declared inputs.
	schemaDir := filepath.Join(packsDir, pack.PackHash[:12], "schemas")
	_ = os.MkdirAll(schemaDir, 0750)
	for _, schema := range pack.Manifest.Schemas {
		schemaFile := filepath.Join(packsDir, pack.PackHash[:12], schema)
		_ = os.MkdirAll(filepath.Dir(schemaFile), 0750)
		schemaContent := map[string]any{"type": "object", "properties": map[string]any{}}
		for _, inp := range candidate.Inputs {
			schemaContent["properties"].(map[string]any)[inp.Name] = map[string]string{"type": inp.Type}
		}
		sd, _ := json.MarshalIndent(schemaContent, "", "  ")
		_ = os.WriteFile(schemaFile, sd, 0644)
	}

	receipt := generatePackReceipt("pack.build", pack.PackHash, map[string]string{
		"candidate_hash": candidate.Hash, "name": candidate.Name,
	})

	_ = candidatePath // used to find candidate

	fmt.Fprintf(stdout, "\n%sSkillPack Built%s\n", ColorBold+ColorGreen, ColorReset)
	fmt.Fprintf(stdout, "   Name:           %s v%s\n", candidate.Name, candidate.Version)
	fmt.Fprintf(stdout, "   Candidate:      %s\n", candidate.Hash[:16])
	fmt.Fprintf(stdout, "   Pack Hash:      %s\n", pack.PackHash[:32])
	fmt.Fprintf(stdout, "   Manifest:       %d schemas, %d tests, %d docs\n",
		len(pack.Manifest.Schemas), len(pack.Manifest.Tests), len(pack.Manifest.Docs))
	fmt.Fprintf(stdout, "   Receipt:        %s\n", receipt)
	fmt.Fprintf(stdout, "   File:           %s\n\n", filepath.Join(packsDir, filename))
	fmt.Fprintf(stdout, "   Next: helm-ai-kernel pack test %s\n\n", pack.PackHash[:12])

	return 0
}

func computeCandidateHash(c *SkillCandidate) string {
	// Deterministic hash: sort fields, marshal canonical, SHA-256
	canonical := map[string]any{
		"name":               c.Name,
		"version":            c.Version,
		"purpose":            c.Purpose,
		"inputs":             c.Inputs,
		"outputs":            c.Outputs,
		"allowed_tools":      c.AllowedTools,
		"effect_classes":     c.EffectClasses,
		"invariants":         c.Invariants,
		"idempotent":         c.Idempotent,
		"required_approvals": c.RequiredApprovals,
		"risk":               c.Risk,
	}
	data, _ := json.Marshal(canonical)
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
