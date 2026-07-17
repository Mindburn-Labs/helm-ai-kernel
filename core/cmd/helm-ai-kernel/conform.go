package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/conform"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/conform/gates"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/conformance"
)

// runConform implements `helm-ai-kernel conform` per §2.1.
//
// Exit codes:
//
//	0 = all gates pass
//	1 = any gate failed
//	2 = runtime error
func runConform(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "adversarial" {
		return runConformAdversarial(args[1:], stdout, stderr)
	}
	if len(args) > 0 && args[0] == "managed-agents" {
		return runConformManagedAgents(args[1:], stdout, stderr)
	}
	if len(args) > 0 && args[0] == "negative" {
		return runConformNegative(args[1:], stdout, stderr)
	}
	if len(args) > 0 && args[0] == "vectors" {
		return runConformVectors(args[1:], stdout, stderr)
	}

	cmd := flag.NewFlagSet("conform", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		profile      string
		jurisdiction string
		outputDir    string
		jsonOutput   bool
		signed       bool
		gateFilter   multiFlag
		level        string
		vectorPath   string
		manifestPath string
		evidencePack string
		kernelCommit string
	)

	cmd.StringVar(&profile, "profile", "", "Conformance profile (REQUIRED unless --level): SMB, CORE, ENTERPRISE, REGULATED_FINANCE, REGULATED_HEALTH, AGENTIC_WEB_ROUTER")
	cmd.StringVar(&jurisdiction, "jurisdiction", "", "Jurisdiction code (e.g. US, EU, APAC)")
	cmd.StringVar(&outputDir, "output", "", "Output directory for EvidencePack (default: artifacts/conformance)")
	cmd.BoolVar(&jsonOutput, "json", false, "Output report as JSON to stdout")
	cmd.BoolVar(&signed, "signed", false, "Emit signed report artifacts (conform_report.json + .sha256 + .sig)")
	cmd.Var(&gateFilter, "gate", "Run only specific gate(s) (repeatable)")
	cmd.StringVar(&level, "level", "", "Conformance level shortcut: L1 (deterministic bytes, ProofGraph, EvidencePack) or L2 (L1 + budget, HITL, replay, tenant, envelope)")
	cmd.StringVar(&vectorPath, "vector", "", "Run a single external failure conformance vector JSON")
	cmd.StringVar(&manifestPath, "validation-manifest", "", "Write signed external failure HCV validation manifest JSON")
	cmd.StringVar(&evidencePack, "evidencepack", "", "EvidencePack tar or directory bound into the validation manifest")
	cmd.StringVar(&kernelCommit, "kernel-commit", "", "Kernel commit SHA to include in the validation manifest")

	if err := cmd.Parse(args); err != nil {
		return 2
	}

	if vectorPath != "" {
		return runExternalFailureVector(vectorPath, externalFailureVectorOptions{
			JSONOutput:             jsonOutput,
			ValidationManifestPath: manifestPath,
			EvidencePackPath:       evidencePack,
			KernelCommit:           kernelCommit,
		}, stdout, stderr)
	}

	// Map --level to profile + gate filter
	if level != "" && profile == "" {
		switch level {
		case "L1":
			profile = "SMB"
			gateFilter = []string{"G0", "G1", "G2A"}
		case "L2":
			profile = "CORE"
			gateFilter = []string{"G0", "G1", "G2", "G2A", "G3A", "G5", "G8", "GX_ENVELOPE", "GX_TENANT"}
		default:
			_, _ = fmt.Fprintf(stderr, "Error: unknown level %q (valid: L1, L2)\n", level)
			return 2
		}
	}

	if profile == "" {
		_, _ = fmt.Fprintln(stderr, "Error: --profile or --level is required")
		_, _ = fmt.Fprintln(stderr, "Valid profiles: SMB, CORE, ENTERPRISE, REGULATED_FINANCE, REGULATED_HEALTH, AGENTIC_WEB_ROUTER")
		_, _ = fmt.Fprintln(stderr, "Valid levels:   L1, L2")
		return 2
	}

	// Validate profile
	profileID := conform.ProfileID(profile)
	if conform.GatesForProfile(profileID) == nil && len(gateFilter) == 0 {
		_, _ = fmt.Fprintf(stderr, "Error: unknown profile %q\n", profile)
		return 2
	}

	// Resolve project root
	projectRoot, err := os.Getwd()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: cannot determine working directory: %v\n", err)
		return 2
	}

	g1Verifier, err := conformG1ReceiptVerifierFromEnv()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: invalid G1 receipt verifier: %v\n", err)
		return 2
	}

	// Build engine with all gates
	engine := gates.DefaultEngineWithOptions(gates.RegistryOptions{G1ReceiptVerifier: g1Verifier})

	// Run conformance
	opts := &conform.RunOptions{
		Profile:      profileID,
		Jurisdiction: jurisdiction,
		GateFilter:   []string(gateFilter),
		ProjectRoot:  projectRoot,
		OutputDir:    outputDir,
		SeedBaseline: level != "",
	}

	report, err := engine.Run(opts)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: conformance run failed: %v\n", err)
		return 2
	}

	// Emit signed report artifacts if requested
	if signed {
		artDir := outputDir
		if artDir == "" {
			artDir = filepath.Join(projectRoot, "artifacts", "conformance")
		}
		if err := os.MkdirAll(artDir, 0750); err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: cannot create output dir: %v\n", err)
			return 2
		}

		// Write conform_report.json
		reportData, _ := json.MarshalIndent(report, "", "  ")
		reportPath := filepath.Join(artDir, "conform_report.json")
		if err := os.WriteFile(reportPath, reportData, 0644); err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: cannot write report: %v\n", err)
			return 2
		}

		// Write conform_report.sha256
		hash := sha256.Sum256(reportData)
		hashHex := hex.EncodeToString(hash[:])
		hashPath := filepath.Join(artDir, "conform_report.sha256")
		_ = os.WriteFile(hashPath, []byte(hashHex+"  conform_report.json\n"), 0644)

		// Sign with Ed25519 if key is available, otherwise hash-based fallback
		sigPath := filepath.Join(artDir, "conform_report.sig")
		keyHex := os.Getenv("HELM_SIGNING_KEY_HEX")
		if keyHex != "" && len(keyHex) == 128 {
			// Ed25519 private key as hex (64 bytes = 128 hex chars)
			keyBytes, err := hex.DecodeString(keyHex)
			if err != nil {
				_, _ = fmt.Fprintf(stderr, "Error: invalid HELM_SIGNING_KEY_HEX: %v\n", err)
				return 2
			}
			privKey := ed25519.NewKeyFromSeed(keyBytes[:32])
			sig := ed25519.Sign(privKey, hash[:])
			sigPayload := map[string]string{
				"algorithm":   "ed25519",
				"report_hash": hashHex,
				"signature":   hex.EncodeToString(sig),
				"profile":     string(report.Profile),
				"run_id":      report.RunID,
				"verdict":     fmt.Sprintf("%v", report.Pass),
			}
			sigData, _ := json.MarshalIndent(sigPayload, "", "  ")
			_ = os.WriteFile(sigPath, sigData, 0644)
			_, _ = fmt.Fprintf(stdout, "Ed25519 signed artifacts written to %s/\n", artDir)
		} else {
			// Unsigned fallback — clearly labeled as digest-only (NOT an HMAC)
			sigPayload := map[string]string{
				"algorithm":   "sha256-digest-only",
				"report_hash": hashHex,
				"profile":     string(report.Profile),
				"run_id":      report.RunID,
				"verdict":     fmt.Sprintf("%v", report.Pass),
				"warning":     "UNSIGNED: set HELM_SIGNING_KEY_HEX for cryptographic Ed25519 signatures",
			}
			sigData, _ := json.MarshalIndent(sigPayload, "", "  ")
			_ = os.WriteFile(sigPath, sigData, 0644)
			_, _ = fmt.Fprintf(stdout, "⚠️  Unsigned digest-only artifacts written to %s/ (set HELM_SIGNING_KEY_HEX for Ed25519)\n", artDir)
		}
		_, _ = fmt.Fprintf(stdout, "  conform_report.json\n")
		_, _ = fmt.Fprintf(stdout, "  conform_report.sha256\n")
		_, _ = fmt.Fprintf(stdout, "  conform_report.sig\n")
	}

	if jsonOutput {
		data, _ := json.MarshalIndent(report, "", "  ")
		_, _ = fmt.Fprintln(stdout, string(data))
	} else if !signed {
		printConformanceReport(stdout, report)
	}

	if !report.Pass {
		return 1
	}
	return 0
}

func conformG1ReceiptVerifierFromEnv() (func(data []byte, sig string) error, error) {
	keyHex := strings.TrimSpace(os.Getenv("HELM_CONFORM_RECEIPT_PUBLIC_KEY_HEX"))
	if keyHex == "" {
		return nil, nil
	}
	publicKey, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("HELM_CONFORM_RECEIPT_PUBLIC_KEY_HEX must be hex encoded: %w", err)
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("HELM_CONFORM_RECEIPT_PUBLIC_KEY_HEX must be a %d-byte Ed25519 public key encoded as hex", ed25519.PublicKeySize)
	}
	return func(data []byte, sig string) error {
		sigBytes, err := hex.DecodeString(strings.TrimPrefix(sig, "hex:"))
		if err != nil {
			return fmt.Errorf("receipt signature must be hex encoded: %w", err)
		}
		if !ed25519.Verify(ed25519.PublicKey(publicKey), data, sigBytes) {
			return fmt.Errorf("receipt signature verification failed")
		}
		return nil
	}, nil
}

type externalFailureVector struct {
	ID                 string `json:"id"`
	VectorID           string `json:"vector_id"`
	HPRID              string `json:"hpr_id"`
	FailureMode        string `json:"failure_mode"`
	ExpectedVerdict    string `json:"expected_verdict"`
	ExpectedReasonCode string `json:"expected_reason_code"`
	MustEmitReceipt    bool   `json:"must_emit_receipt"`
	MustNotDispatch    bool   `json:"must_not_dispatch"`
	MustBindEvidence   bool   `json:"must_bind_evidence"`
	Expected           struct {
		Verdict              string `json:"verdict"`
		ReasonCode           string `json:"reason_code"`
		ReceiptRequired      bool   `json:"receipt_required"`
		EvidencePackRequired bool   `json:"evidencepack_required"`
	} `json:"expected"`
	NegativeAssertions []string `json:"negative_assertions"`
}

type externalFailureVectorOptions struct {
	JSONOutput             bool
	ValidationManifestPath string
	EvidencePackPath       string
	KernelCommit           string
}

type externalFailureValidationManifest struct {
	ID                    string    `json:"id"`
	HPRID                 string    `json:"hpr_id"`
	HCVIDs                []string  `json:"hcv_ids"`
	ExpectedVerdicts      []string  `json:"expected_verdicts"`
	EvidencePackHash      string    `json:"evidencepack_hash"`
	ConformanceResultHash string    `json:"conformance_result_hash"`
	KernelCommit          string    `json:"kernel_commit"`
	IssuedAt              time.Time `json:"issued_at"`
	Signer                string    `json:"signer"`
	Signature             string    `json:"signature"`
}

func runExternalFailureVector(path string, opts externalFailureVectorOptions, stdout, stderr io.Writer) int {
	raw, err := os.ReadFile(path)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: read vector: %v\n", err)
		return 2
	}
	var vector externalFailureVector
	if err := json.Unmarshal(raw, &vector); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: parse vector: %v\n", err)
		return 2
	}
	issues := validateExternalFailureVector(vector)
	result := map[string]any{
		"vector_id": vector.ID,
		"hpr_id":    vector.HPRID,
		"status":    "PASS",
		"issues":    issues,
	}
	if len(issues) > 0 {
		result["status"] = "FAIL"
	}
	if opts.ValidationManifestPath != "" {
		if len(issues) > 0 {
			_, _ = fmt.Fprintln(stderr, "Error: validation manifest requires a passing external failure vector")
			return 1
		}
		if err := writeExternalFailureValidationManifest(opts.ValidationManifestPath, vector, result, opts); err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: write validation manifest: %v\n", err)
			return 2
		}
		result["validation_manifest"] = opts.ValidationManifestPath
	}
	if opts.JSONOutput {
		payload, _ := json.MarshalIndent(result, "", "  ")
		_, _ = fmt.Fprintln(stdout, string(payload))
	} else if len(issues) == 0 {
		_, _ = fmt.Fprintf(stdout, "External failure vector %s PASS (%s)\n", vector.ID, vector.ExpectedVerdict)
	} else {
		_, _ = fmt.Fprintf(stdout, "External failure vector %s FAIL\n", vector.ID)
		for _, issue := range issues {
			_, _ = fmt.Fprintf(stdout, "  - %s\n", issue)
		}
	}
	if len(issues) > 0 {
		return 1
	}
	return 0
}

func writeExternalFailureValidationManifest(path string, vector externalFailureVector, result map[string]any, opts externalFailureVectorOptions) error {
	if opts.EvidencePackPath == "" {
		return fmt.Errorf("--evidencepack is required when --validation-manifest is set")
	}
	evidenceBytes, err := os.ReadFile(opts.EvidencePackPath)
	if err != nil {
		return fmt.Errorf("read evidencepack: %w", err)
	}
	evidenceHash := sha256.Sum256(evidenceBytes)
	resultBytes, err := canonicalJSON(result)
	if err != nil {
		return fmt.Errorf("canonicalize vector result: %w", err)
	}
	resultHash := sha256.Sum256(resultBytes)
	kernelCommit := strings.TrimSpace(opts.KernelCommit)
	if kernelCommit == "" {
		kernelCommit = strings.TrimSpace(os.Getenv("HELM_KERNEL_COMMIT"))
	}
	if kernelCommit == "" {
		kernelCommit = "working-tree"
	}
	issuedAt := time.Now().UTC().Truncate(time.Second)
	if fixed := strings.TrimSpace(os.Getenv("HELM_FIXED_TIME_RFC3339")); fixed != "" {
		parsed, err := time.Parse(time.RFC3339, fixed)
		if err != nil {
			return fmt.Errorf("parse HELM_FIXED_TIME_RFC3339: %w", err)
		}
		issuedAt = parsed.UTC()
	}
	privateKey, signer, err := externalFailureSigningKey()
	if err != nil {
		return err
	}
	manifest := externalFailureValidationManifest{
		ID:                    "KVM-" + vector.HPRID,
		HPRID:                 vector.HPRID,
		HCVIDs:                []string{vector.ID},
		ExpectedVerdicts:      []string{vector.ExpectedVerdict},
		EvidencePackHash:      "sha256:" + hex.EncodeToString(evidenceHash[:]),
		ConformanceResultHash: "sha256:" + hex.EncodeToString(resultHash[:]),
		KernelCommit:          kernelCommit,
		IssuedAt:              issuedAt,
		Signer:                signer,
	}
	signingBytes, err := canonicalJSON(manifest)
	if err != nil {
		return fmt.Errorf("canonicalize manifest: %w", err)
	}
	manifest.Signature = hex.EncodeToString(ed25519.Sign(privateKey, signingBytes))
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

func externalFailureSigningKey() (ed25519.PrivateKey, string, error) {
	keyHex := strings.TrimSpace(os.Getenv("HELM_SIGNING_KEY_HEX"))
	if keyHex == "" {
		return nil, "", fmt.Errorf("HELM_SIGNING_KEY_HEX is required for signed Kernel validation manifests")
	}
	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, "", fmt.Errorf("invalid HELM_SIGNING_KEY_HEX: %w", err)
	}
	var privateKey ed25519.PrivateKey
	switch len(keyBytes) {
	case ed25519.SeedSize:
		privateKey = ed25519.NewKeyFromSeed(keyBytes)
	case ed25519.PrivateKeySize:
		privateKey = ed25519.PrivateKey(keyBytes)
	default:
		return nil, "", fmt.Errorf("HELM_SIGNING_KEY_HEX must be a 32-byte seed or 64-byte private key")
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return privateKey, hex.EncodeToString(publicKey), nil
}

func canonicalJSON(v any) ([]byte, error) {
	intermediate, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var generic any
	decoder := json.NewDecoder(bytes.NewReader(intermediate))
	decoder.UseNumber()
	if err := decoder.Decode(&generic); err != nil {
		return nil, err
	}
	return marshalCanonical(generic)
}

func marshalCanonical(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	switch value := v.(type) {
	case nil:
		return []byte("null"), nil
	case bool:
		if value {
			return []byte("true"), nil
		}
		return []byte("false"), nil
	case json.Number:
		return []byte(value.String()), nil
	case string:
		if err := enc.Encode(value); err != nil {
			return nil, err
		}
		return bytes.TrimSuffix(buf.Bytes(), []byte{'\n'}), nil
	case []any:
		buf.WriteByte('[')
		for i, item := range value {
			if i > 0 {
				buf.WriteByte(',')
			}
			data, err := marshalCanonical(item)
			if err != nil {
				return nil, err
			}
			buf.Write(data)
		}
		buf.WriteByte(']')
		return buf.Bytes(), nil
	case map[string]any:
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			keyBytes, err := marshalCanonical(key)
			if err != nil {
				return nil, err
			}
			valueBytes, err := marshalCanonical(value[key])
			if err != nil {
				return nil, err
			}
			buf.Write(keyBytes)
			buf.WriteByte(':')
			buf.Write(valueBytes)
		}
		buf.WriteByte('}')
		return buf.Bytes(), nil
	default:
		if err := enc.Encode(value); err != nil {
			return nil, err
		}
		return bytes.TrimSuffix(buf.Bytes(), []byte{'\n'}), nil
	}
}

func validateExternalFailureVector(vector externalFailureVector) []string {
	var issues []string
	if !strings.HasPrefix(vector.ID, "HCV-") {
		issues = append(issues, "vector id must use HCV prefix")
	}
	if vector.VectorID != "" && vector.VectorID != vector.ID {
		issues = append(issues, "vector_id must match id")
	}
	if !strings.HasPrefix(vector.HPRID, "HPR-") {
		issues = append(issues, "source replay id must use HPR prefix")
	}
	if vector.FailureMode == "" {
		issues = append(issues, "failure mode is required")
	}
	if vector.ExpectedVerdict != "ALLOW" && vector.ExpectedVerdict != "DENY" && vector.ExpectedVerdict != "ESCALATE" {
		issues = append(issues, "expected verdict must be ALLOW, DENY, or ESCALATE")
	}
	if vector.Expected.Verdict != "" && vector.Expected.Verdict != vector.ExpectedVerdict {
		issues = append(issues, "expected.verdict must match expected_verdict")
	}
	if vector.Expected.ReasonCode != "" && vector.ExpectedReasonCode != "" && vector.Expected.ReasonCode != vector.ExpectedReasonCode {
		issues = append(issues, "expected.reason_code must match expected_reason_code")
	}
	if !vector.MustEmitReceipt || !vector.Expected.ReceiptRequired {
		issues = append(issues, "receipt must be required")
	}
	if !vector.MustNotDispatch || !contains(vector.NegativeAssertions, "must_not_dispatch_connector") {
		issues = append(issues, "vector must assert no connector dispatch")
	}
	if !vector.MustBindEvidence || !vector.Expected.EvidencePackRequired {
		issues = append(issues, "EvidencePack binding must be required")
	}
	return issues
}

func contains(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func runConformNegative(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("conform negative", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var jsonOutput bool
	cmd.BoolVar(&jsonOutput, "json", false, "Output negative execution-boundary vectors as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}

	vectors := conformance.DefaultNegativeBoundaryVectors()
	if jsonOutput {
		data, _ := json.MarshalIndent(vectors, "", "  ")
		_, _ = fmt.Fprintln(stdout, string(data))
		return 0
	}

	_, _ = fmt.Fprintln(stdout, "HELM Negative Execution-Boundary Vectors")
	for _, vector := range vectors {
		_, _ = fmt.Fprintf(stdout, "  %s  verdict=%s reason=%s receipt=%t dispatch=%t\n",
			vector.ID,
			vector.ExpectedVerdict,
			vector.ExpectedReasonCode,
			vector.MustEmitReceipt,
			!vector.MustNotDispatch,
		)
	}
	return 0
}

func printConformanceReport(w io.Writer, report *conform.ConformanceReport) {
	_, _ = fmt.Fprintf(w, "HELM Conformance Report\n")
	_, _ = fmt.Fprintf(w, "───────────────────────\n")
	_, _ = fmt.Fprintf(w, "Run ID:    %s\n", report.RunID)
	_, _ = fmt.Fprintf(w, "Profile:   %s\n", report.Profile)
	_, _ = fmt.Fprintf(w, "Timestamp: %s\n", report.Timestamp.Format("2006-01-02T15:04:05Z"))
	_, _ = fmt.Fprintf(w, "Duration:  %s\n\n", report.Duration)

	for _, gr := range report.GateResults {
		status := "✅ PASS"
		if !gr.Pass {
			status = "❌ FAIL"
		}
		_, _ = fmt.Fprintf(w, "  %s  %s", status, gr.GateID)
		if len(gr.Reasons) > 0 {
			_, _ = fmt.Fprintf(w, "  [%s]", gr.Reasons[0])
			if len(gr.Reasons) > 1 {
				_, _ = fmt.Fprintf(w, " (+%d more)", len(gr.Reasons)-1)
			}
		}
		_, _ = fmt.Fprintln(w)
	}

	_, _ = fmt.Fprintln(w)
	if report.Pass {
		_, _ = fmt.Fprintf(w, "Result: ✅ PASS (%d gates)\n", len(report.GateResults))
	} else {
		failed := 0
		for _, gr := range report.GateResults {
			if !gr.Pass {
				failed++
			}
		}
		_, _ = fmt.Fprintf(w, "Result: ❌ FAIL (%d/%d gates failed)\n", failed, len(report.GateResults))
	}
}

// multiFlag allows repeatable flag values (e.g. --gate G0 --gate G1).
type multiFlag []string

func (f *multiFlag) String() string { return fmt.Sprintf("%v", *f) }
func (f *multiFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}

func init() {
	Register(Subcommand{Name: "conform", Aliases: []string{"conformance"}, Usage: "Run conformance gates (--level L1|L2 or --profile, --json)", RunFn: runConform})
}
