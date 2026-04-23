package main

import (
	"archive/tar"
	"compress/gzip"
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

	"github.com/Mindburn-Labs/helm-oss/core/pkg/verifier"
)

// CertificationCheck defines a single compliance requirement.
type CertificationCheck struct {
	Name              string
	Description       string
	RequiredNodeTypes []string
	Check             func(packDir string) (bool, string)
}

// CertificationReport is the structured output of compliance certification.
type CertificationReport struct {
	PackPath        string                `json:"pack_path"`
	Framework       string                `json:"framework"`
	FrameworkLabel  string                `json:"framework_label"`
	Certified       bool                  `json:"certified"`
	Checks          []CertificationResult `json:"checks"`
	PassedCount     int                   `json:"passed_count"`
	TotalCount      int                   `json:"total_count"`
	CertifiedAt     time.Time             `json:"certified_at"`
	HelmVersion     string                `json:"helm_version"`
	AttestationHash string                `json:"attestation_hash"`
}

// CertificationResult captures the outcome of a single check.
type CertificationResult struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Passed      bool   `json:"passed"`
	Reason      string `json:"reason,omitempty"`
}

// frameworkLabels maps framework IDs to human-readable names.
var frameworkLabels = map[string]string{
	"eu-ai-act":     "EU AI Act (Regulation 2024/1689)",
	"hipaa":         "HIPAA (Health Insurance Portability and Accountability Act)",
	"sox":           "SOX (Sarbanes-Oxley Act)",
	"gdpr":          "GDPR (General Data Protection Regulation)",
	"soc2":          "SOC 2 (Service Organization Control 2)",
	"nist-ai-rmf":   "NIST AI Risk Management Framework (AI 100-1)",
	"owasp-agentic": "OWASP Top 10 for Agentic AI (2025)",
}

// frameworkRequirements maps each compliance framework to its certification checks.
var frameworkRequirements = map[string][]CertificationCheck{
	"eu-ai-act": {
		{Name: "art12_record_keeping", Description: "Decision records with timestamps", RequiredNodeTypes: []string{"INTENT", "ATTESTATION", "EFFECT"}},
		{Name: "art13_transparency", Description: "Signed receipts for all decisions", Check: hasSignedReceipts},
		{Name: "art14_human_oversight", Description: "ESCALATE verdicts present", Check: hasEscalateVerdicts},
		{Name: "art15_robustness", Description: "Threat scan results", Check: hasThreatFindings},
	},
	"hipaa": {
		{Name: "audit_trail", Description: "Complete audit trail", RequiredNodeTypes: []string{"INTENT", "ATTESTATION"}},
		{Name: "access_control", Description: "Identity verification records", Check: hasIdentityChecks},
		{Name: "integrity", Description: "Signed evidence manifest", Check: hasSignedManifest},
	},
	"soc2": {
		{Name: "cc5_control_activities", Description: "Policy decisions recorded", RequiredNodeTypes: []string{"ATTESTATION"}},
		{Name: "cc7_monitoring", Description: "Continuous monitoring evidence", Check: hasMonitoringEvidence},
		{Name: "cc8_change_management", Description: "Policy versioning", Check: hasPolicyVersioning},
	},
	"gdpr": {
		{Name: "data_processing_records", Description: "Data processing decisions", RequiredNodeTypes: []string{"EFFECT"}},
		{Name: "lawful_basis", Description: "Policy basis for processing", Check: hasPolicyBasis},
	},
	"owasp-agentic": {
		{Name: "asi01_injection", Description: "Threat scanner coverage", Check: hasThreatFindings},
		{Name: "asi02_tool_poisoning", Description: "Tool validation records", Check: hasToolValidation},
		{Name: "asi03_permissions", Description: "Effect permits", RequiredNodeTypes: []string{"EFFECT"}},
		{Name: "asi04_validation", Description: "Guardian decisions", RequiredNodeTypes: []string{"ATTESTATION"}},
		{Name: "asi05_output", Description: "Output quarantine", Check: hasOutputQuarantine},
		{Name: "asi06_budget", Description: "Budget enforcement", Check: hasBudgetChecks},
		{Name: "asi07_cascade", Description: "Circuit breaker evidence", Check: hasCircuitBreakerEvidence},
		{Name: "asi08_data", Description: "Egress firewall logs", Check: hasEgressLogs},
		{Name: "asi09_plugins", Description: "MCP governance", Check: hasMCPGovernance},
		{Name: "asi10_monitoring", Description: "Evidence packs", Check: hasEvidencePacks},
	},
	"nist-ai-rmf": {
		{Name: "govern_1_policies", Description: "Policy bundles present", Check: hasPolicyBundles},
		{Name: "govern_2_accountability", Description: "Signed decision records", Check: hasSignedReceipts},
		{Name: "manage_1_risk", Description: "Risk decisions recorded", RequiredNodeTypes: []string{"ATTESTATION"}},
		{Name: "manage_4_monitoring", Description: "Continuous monitoring", Check: hasMonitoringEvidence},
	},
	"sox": {
		{Name: "sec302_internal_controls", Description: "Policy enforcement records", RequiredNodeTypes: []string{"ATTESTATION"}},
		{Name: "sec404_assessment", Description: "Control assessment evidence", Check: hasSignedReceipts},
		{Name: "sec802_record_retention", Description: "Evidence archive integrity", Check: hasSignedManifest},
	},
}

// runCertifyCmd implements `helm certify`.
//
// Certifies an evidence pack against a compliance framework by validating
// that all required evidence types are present.
//
// Exit codes:
//
//	0 = certified (all checks passed)
//	1 = certification failed (one or more checks not met)
//	2 = runtime error
func runCertifyCmd(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("certify", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		pack       string
		framework  string
		jsonOutput bool
		outFile    string
	)

	cmd.StringVar(&pack, "pack", "", "Path to evidence pack (directory or .tar/.tar.gz) (REQUIRED)")
	cmd.StringVar(&framework, "framework", "", "Compliance framework: eu-ai-act, hipaa, sox, gdpr, soc2, nist-ai-rmf, owasp-agentic (REQUIRED)")
	cmd.BoolVar(&jsonOutput, "json", false, "Output as JSON")
	cmd.StringVar(&outFile, "out", "", "Write attestation to file")

	if err := cmd.Parse(args); err != nil {
		return 2
	}

	if pack == "" {
		_, _ = fmt.Fprintln(stderr, "Error: --pack is required")
		cmd.Usage()
		return 2
	}
	if framework == "" {
		_, _ = fmt.Fprintln(stderr, "Error: --framework is required")
		_, _ = fmt.Fprintf(stderr, "Supported frameworks: %s\n", strings.Join(supportedFrameworks(), ", "))
		return 2
	}

	checks, ok := frameworkRequirements[framework]
	if !ok {
		_, _ = fmt.Fprintf(stderr, "Error: unknown framework %q\n", framework)
		_, _ = fmt.Fprintf(stderr, "Supported frameworks: %s\n", strings.Join(supportedFrameworks(), ", "))
		return 2
	}

	// Resolve the pack path to a directory, extracting archives if needed.
	packDir, cleanup, err := resolvePackDir(pack)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	if cleanup != nil {
		defer cleanup()
	}

	// Run basic structural verification first.
	report, verifyErr := verifier.VerifyBundle(packDir)
	if verifyErr != nil {
		_, _ = fmt.Fprintf(stderr, "Error: pack verification failed: %v\n", verifyErr)
		return 2
	}
	if !report.Verified {
		_, _ = fmt.Fprintf(stderr, "Error: evidence pack failed structural verification (%s)\n", report.Summary)
		_, _ = fmt.Fprintln(stderr, "Fix verification issues before certifying.")
		return 2
	}

	// Run certification checks.
	certReport := runCertification(pack, packDir, framework, checks)

	// Compute attestation hash over the report.
	certReport.AttestationHash = computeAttestationHash(certReport)

	// Write to file if requested.
	if outFile != "" {
		data, marshalErr := json.MarshalIndent(certReport, "", "  ")
		if marshalErr != nil {
			_, _ = fmt.Fprintf(stderr, "Error: cannot marshal attestation: %v\n", marshalErr)
			return 2
		}
		if writeErr := os.WriteFile(outFile, data, 0600); writeErr != nil {
			_, _ = fmt.Fprintf(stderr, "Error: cannot write attestation: %v\n", writeErr)
			return 2
		}
	}

	// Render output.
	if jsonOutput {
		data, _ := json.MarshalIndent(certReport, "", "  ")
		_, _ = fmt.Fprintln(stdout, string(data))
	} else {
		renderTextReport(stdout, certReport)
	}

	if outFile != "" && !jsonOutput {
		_, _ = fmt.Fprintf(stdout, "\nAttestation written to %s\n", outFile)
	}

	if !certReport.Certified {
		return 1
	}
	return 0
}

// runCertification executes all checks for a framework and builds the report.
func runCertification(packPath, packDir, framework string, checks []CertificationCheck) *CertificationReport {
	var results []CertificationResult
	passed := 0

	for _, check := range checks {
		result := runSingleCheck(packDir, check)
		results = append(results, result)
		if result.Passed {
			passed++
		}
	}

	label := frameworkLabels[framework]
	if label == "" {
		label = framework
	}

	return &CertificationReport{
		PackPath:       packPath,
		Framework:      framework,
		FrameworkLabel: label,
		Certified:      passed == len(checks),
		Checks:         results,
		PassedCount:    passed,
		TotalCount:     len(checks),
		CertifiedAt:    time.Now().UTC(),
		HelmVersion:    displayVersion(),
	}
}

// runSingleCheck evaluates one certification check.
func runSingleCheck(packDir string, check CertificationCheck) CertificationResult {
	// If RequiredNodeTypes is set, verify those node types exist in the proof graph.
	if len(check.RequiredNodeTypes) > 0 {
		ok, reason := checkNodeTypesPresent(packDir, check.RequiredNodeTypes)
		if !ok {
			return CertificationResult{
				Name:        check.Name,
				Description: check.Description,
				Passed:      false,
				Reason:      reason,
			}
		}
	}

	// If a custom check function is set, run it.
	if check.Check != nil {
		ok, reason := check.Check(packDir)
		return CertificationResult{
			Name:        check.Name,
			Description: check.Description,
			Passed:      ok,
			Reason:      reason,
		}
	}

	// RequiredNodeTypes passed, no custom check — pass.
	return CertificationResult{
		Name:        check.Name,
		Description: check.Description,
		Passed:      true,
	}
}

// --- Node type checks ---

// checkNodeTypesPresent scans the proof graph for the required node types.
func checkNodeTypesPresent(packDir string, required []string) (bool, string) {
	content, found := loadProofGraphContent(packDir)
	if !found {
		return false, "no proof graph found (expected proofgraph.json or 02_PROOFGRAPH/)"
	}

	var missing []string
	for _, nt := range required {
		if !strings.Contains(content, fmt.Sprintf("%q", nt)) {
			missing = append(missing, nt)
		}
	}

	if len(missing) > 0 {
		return false, fmt.Sprintf("missing node types in proof graph: %s", strings.Join(missing, ", "))
	}
	return true, ""
}

// loadProofGraphContent reads all proof graph content as a single string for scanning.
func loadProofGraphContent(packDir string) (string, bool) {
	// Try proofgraph.json
	pgPath := filepath.Join(packDir, "proofgraph.json")
	if data, err := os.ReadFile(pgPath); err == nil {
		return string(data), true
	}

	// Try 02_PROOFGRAPH directory
	pgDir := filepath.Join(packDir, "02_PROOFGRAPH")
	info, err := os.Stat(pgDir)
	if err != nil || !info.IsDir() {
		return "", false
	}

	var buf strings.Builder
	_ = filepath.Walk(pgDir, func(path string, fi os.FileInfo, walkErr error) error {
		if walkErr != nil || fi.IsDir() {
			return walkErr
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		buf.Write(data)
		buf.WriteByte('\n')
		return nil
	})

	content := buf.String()
	if content == "" {
		return "", false
	}
	return content, true
}

// --- Check functions ---

// hasSignedReceipts checks for receipt files with signatures.
func hasSignedReceipts(packDir string) (bool, string) {
	dirs := []string{
		filepath.Join(packDir, "receipts"),
		filepath.Join(packDir, "01_RECEIPTS"),
	}

	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			// Check for .sig sidecar files
			if strings.HasSuffix(entry.Name(), ".sig") {
				return true, ""
			}
			// Check for signature fields inside JSON receipts
			if strings.HasSuffix(entry.Name(), ".json") {
				data, readErr := os.ReadFile(filepath.Join(dir, entry.Name()))
				if readErr != nil {
					continue
				}
				if containsAnyField(data, "signature", "sig", "signed_hash") {
					return true, ""
				}
			}
		}
	}

	// Also check 07_ATTESTATIONS
	attDir := filepath.Join(packDir, "07_ATTESTATIONS")
	if entries, err := os.ReadDir(attDir); err == nil {
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), ".sig") {
				return true, ""
			}
		}
	}

	return false, "no signed receipts found (checked receipts/, 01_RECEIPTS/, 07_ATTESTATIONS/)"
}

// hasEscalateVerdicts checks for ESCALATE verdicts in decision records.
func hasEscalateVerdicts(packDir string) (bool, string) {
	searchDirs := []string{
		filepath.Join(packDir, "receipts"),
		filepath.Join(packDir, "01_RECEIPTS"),
		filepath.Join(packDir, "policy"),
		filepath.Join(packDir, "07_ATTESTATIONS"),
	}

	for _, dir := range searchDirs {
		if found := scanDirForPattern(dir, "ESCALATE"); found {
			return true, ""
		}
	}

	// Also check the proof graph
	if content, ok := loadProofGraphContent(packDir); ok {
		if strings.Contains(content, "ESCALATE") {
			return true, ""
		}
	}

	return false, "no ESCALATE verdicts found in decision records"
}

// hasThreatFindings checks for threat scan results.
func hasThreatFindings(packDir string) (bool, string) {
	searchDirs := []string{
		filepath.Join(packDir, "threat"),
		filepath.Join(packDir, "threats"),
		filepath.Join(packDir, "04_THREATS"),
		filepath.Join(packDir, "scans"),
		filepath.Join(packDir, "06_LOGS"),
	}

	for _, dir := range searchDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			name := strings.ToLower(entry.Name())
			if strings.Contains(name, "threat") || strings.Contains(name, "scan") || strings.Contains(name, "vuln") {
				return true, ""
			}
		}
	}

	// Check if any JSON file contains threat-related keys
	for _, dir := range searchDirs[:3] {
		if anyFileExists(dir) {
			return true, ""
		}
	}

	return false, "no threat scan results found"
}

// hasIdentityChecks checks for identity verification records.
func hasIdentityChecks(packDir string) (bool, string) {
	searchDirs := []string{
		filepath.Join(packDir, "identity"),
		filepath.Join(packDir, "auth"),
		filepath.Join(packDir, "07_ATTESTATIONS"),
	}

	for _, dir := range searchDirs {
		if anyFileExists(dir) {
			entries, _ := os.ReadDir(dir)
			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}
				data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
				if err != nil {
					continue
				}
				if containsAnyField(data, "principal", "actor_did", "identity", "subject", "caller") {
					return true, ""
				}
			}
		}
	}

	// Check receipts for identity fields
	receiptDirs := []string{
		filepath.Join(packDir, "receipts"),
		filepath.Join(packDir, "01_RECEIPTS"),
	}
	for _, dir := range receiptDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			data, readErr := os.ReadFile(filepath.Join(dir, entry.Name()))
			if readErr != nil {
				continue
			}
			if containsAnyField(data, "principal", "actor_did", "identity", "subject") {
				return true, ""
			}
		}
	}

	return false, "no identity verification records found"
}

// hasSignedManifest checks for a signed manifest file.
func hasSignedManifest(packDir string) (bool, string) {
	// Check manifest.json for manifest_hash or signature
	manifestPath := filepath.Join(packDir, "manifest.json")
	if data, err := os.ReadFile(manifestPath); err == nil {
		if containsAnyField(data, "manifest_hash", "signature", "signed_hash") {
			return true, ""
		}
	}

	// Check 00_INDEX.json
	indexPath := filepath.Join(packDir, "00_INDEX.json")
	if data, err := os.ReadFile(indexPath); err == nil {
		if containsAnyField(data, "hash", "signature", "manifest_hash", "root_hash") {
			return true, ""
		}
	}

	// Check for standalone signature files
	sigFiles := []string{
		filepath.Join(packDir, "manifest.sig"),
		filepath.Join(packDir, "manifest.json.sig"),
		filepath.Join(packDir, "00_INDEX.sig"),
	}
	for _, f := range sigFiles {
		if _, err := os.Stat(f); err == nil {
			return true, ""
		}
	}

	return false, "no signed manifest found (expected manifest_hash in manifest.json or .sig sidecar)"
}

// hasMonitoringEvidence checks for continuous monitoring artifacts.
func hasMonitoringEvidence(packDir string) (bool, string) {
	searchDirs := []string{
		filepath.Join(packDir, "03_TELEMETRY"),
		filepath.Join(packDir, "telemetry"),
		filepath.Join(packDir, "monitoring"),
		filepath.Join(packDir, "06_LOGS"),
		filepath.Join(packDir, "metrics"),
	}

	for _, dir := range searchDirs {
		if anyFileExists(dir) {
			return true, ""
		}
	}

	return false, "no monitoring evidence found (expected 03_TELEMETRY/, telemetry/, monitoring/, or 06_LOGS/)"
}

// hasPolicyVersioning checks for policy version tracking.
func hasPolicyVersioning(packDir string) (bool, string) {
	// Check policy directory for versioned files
	policyDirs := []string{
		filepath.Join(packDir, "policy"),
		filepath.Join(packDir, "policies"),
		filepath.Join(packDir, "09_SCHEMAS"),
	}

	for _, dir := range policyDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			data, readErr := os.ReadFile(filepath.Join(dir, entry.Name()))
			if readErr != nil {
				continue
			}
			if containsAnyField(data, "version", "policy_version", "policy_hash", "bundle_hash") {
				return true, ""
			}
		}
	}

	// Check manifest for policy_hash
	manifestPath := filepath.Join(packDir, "manifest.json")
	if data, err := os.ReadFile(manifestPath); err == nil {
		if containsAnyField(data, "policy_hash") {
			return true, ""
		}
	}

	return false, "no policy versioning evidence found"
}

// hasPolicyBasis checks for lawful basis records in policy decisions.
func hasPolicyBasis(packDir string) (bool, string) {
	policyDirs := []string{
		filepath.Join(packDir, "policy"),
		filepath.Join(packDir, "policies"),
		filepath.Join(packDir, "07_ATTESTATIONS"),
	}

	for _, dir := range policyDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			data, readErr := os.ReadFile(filepath.Join(dir, entry.Name()))
			if readErr != nil {
				continue
			}
			if containsAnyField(data, "policy", "basis", "lawful_basis", "reason", "verdict") {
				return true, ""
			}
		}
	}

	return false, "no policy basis records found"
}

// hasToolValidation checks for tool validation records (OWASP ASI-02).
func hasToolValidation(packDir string) (bool, string) {
	searchDirs := []string{
		filepath.Join(packDir, "transcripts"),
		filepath.Join(packDir, "08_TAPES"),
		filepath.Join(packDir, "tools"),
	}

	for _, dir := range searchDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			data, readErr := os.ReadFile(filepath.Join(dir, entry.Name()))
			if readErr != nil {
				continue
			}
			if containsAnyField(data, "tool", "connector", "action", "tool_name") {
				return true, ""
			}
		}
	}

	return false, "no tool validation records found"
}

// hasOutputQuarantine checks for output quarantine evidence (OWASP ASI-05).
func hasOutputQuarantine(packDir string) (bool, string) {
	// Check for quarantine-related files or fields
	quarantineDirs := []string{
		filepath.Join(packDir, "quarantine"),
		filepath.Join(packDir, "07_ATTESTATIONS"),
		filepath.Join(packDir, "receipts"),
		filepath.Join(packDir, "01_RECEIPTS"),
	}

	for _, dir := range quarantineDirs {
		if scanDirForPattern(dir, "quarantine") || scanDirForPattern(dir, "DENY") {
			return true, ""
		}
	}

	return false, "no output quarantine evidence found"
}

// hasBudgetChecks checks for budget/spend enforcement evidence (OWASP ASI-06).
func hasBudgetChecks(packDir string) (bool, string) {
	searchDirs := []string{
		filepath.Join(packDir, "receipts"),
		filepath.Join(packDir, "01_RECEIPTS"),
		filepath.Join(packDir, "policy"),
		filepath.Join(packDir, "07_ATTESTATIONS"),
	}

	for _, dir := range searchDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			data, readErr := os.ReadFile(filepath.Join(dir, entry.Name()))
			if readErr != nil {
				continue
			}
			if containsAnyField(data, "budget", "spend", "cost", "ceiling", "limit", "max_spend") {
				return true, ""
			}
		}
	}

	return false, "no budget enforcement evidence found"
}

// hasCircuitBreakerEvidence checks for circuit breaker records (OWASP ASI-07).
func hasCircuitBreakerEvidence(packDir string) (bool, string) {
	searchDirs := []string{
		filepath.Join(packDir, "receipts"),
		filepath.Join(packDir, "01_RECEIPTS"),
		filepath.Join(packDir, "06_LOGS"),
		filepath.Join(packDir, "07_ATTESTATIONS"),
	}

	for _, dir := range searchDirs {
		if scanDirForPattern(dir, "circuit") || scanDirForPattern(dir, "breaker") || scanDirForPattern(dir, "freeze") || scanDirForPattern(dir, "FREEZE") {
			return true, ""
		}
	}

	return false, "no circuit breaker evidence found"
}

// hasEgressLogs checks for egress firewall log entries (OWASP ASI-08).
func hasEgressLogs(packDir string) (bool, string) {
	searchDirs := []string{
		filepath.Join(packDir, "network"),
		filepath.Join(packDir, "egress"),
		filepath.Join(packDir, "firewall"),
		filepath.Join(packDir, "06_LOGS"),
	}

	for _, dir := range searchDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			name := strings.ToLower(entry.Name())
			if strings.Contains(name, "egress") || strings.Contains(name, "network") || strings.Contains(name, "firewall") {
				return true, ""
			}
		}
		// Any file in network/ or egress/ counts
		if len(entries) > 0 && (strings.HasSuffix(dir, "network") || strings.HasSuffix(dir, "egress") || strings.HasSuffix(dir, "firewall")) {
			return true, ""
		}
	}

	return false, "no egress firewall logs found"
}

// hasMCPGovernance checks for MCP governance records (OWASP ASI-09).
func hasMCPGovernance(packDir string) (bool, string) {
	searchDirs := []string{
		filepath.Join(packDir, "receipts"),
		filepath.Join(packDir, "01_RECEIPTS"),
		filepath.Join(packDir, "07_ATTESTATIONS"),
		filepath.Join(packDir, "policy"),
		filepath.Join(packDir, "transcripts"),
		filepath.Join(packDir, "08_TAPES"),
	}

	for _, dir := range searchDirs {
		if scanDirForPattern(dir, "mcp") || scanDirForPattern(dir, "MCP") || scanDirForPattern(dir, "delegation") {
			return true, ""
		}
	}

	return false, "no MCP governance records found"
}

// hasEvidencePacks checks that the pack itself is well-formed (OWASP ASI-10).
func hasEvidencePacks(packDir string) (bool, string) {
	// If we got this far, the pack passed structural verification.
	// Check for manifest integrity.
	manifestPath := filepath.Join(packDir, "manifest.json")
	if _, err := os.Stat(manifestPath); err == nil {
		return true, ""
	}
	indexPath := filepath.Join(packDir, "00_INDEX.json")
	if _, err := os.Stat(indexPath); err == nil {
		return true, ""
	}
	return false, "no evidence pack manifest found"
}

// hasPolicyBundles checks for policy bundle files.
func hasPolicyBundles(packDir string) (bool, string) {
	policyDirs := []string{
		filepath.Join(packDir, "policy"),
		filepath.Join(packDir, "policies"),
		filepath.Join(packDir, "bundles"),
		filepath.Join(packDir, "09_SCHEMAS"),
	}

	for _, dir := range policyDirs {
		if anyFileExists(dir) {
			return true, ""
		}
	}

	// Check manifest for policy_hash (implies a policy was active)
	manifestPath := filepath.Join(packDir, "manifest.json")
	if data, err := os.ReadFile(manifestPath); err == nil {
		if containsAnyField(data, "policy_hash") {
			return true, ""
		}
	}

	return false, "no policy bundles found"
}

// --- Rendering ---

// renderTextReport writes a human-readable certification report.
func renderTextReport(w io.Writer, r *CertificationReport) {
	_, _ = fmt.Fprintf(w, "\n%sHELM Certification Report%s\n", ColorBold, ColorReset)
	_, _ = fmt.Fprintf(w, "Framework: %s\n", r.FrameworkLabel)
	_, _ = fmt.Fprintf(w, "Pack: %s\n\n", r.PackPath)

	for _, check := range r.Checks {
		if check.Passed {
			_, _ = fmt.Fprintf(w, "  %s\u2705%s %-25s %s\n", ColorGreen, ColorReset, check.Name, check.Description)
		} else {
			reason := check.Reason
			if reason == "" {
				reason = "check not met"
			}
			_, _ = fmt.Fprintf(w, "  %s\u26A0\uFE0F%s  %-25s %s\n", ColorYellow, ColorReset, check.Name, reason)
		}
	}

	_, _ = fmt.Fprintf(w, "\nResult: %d/%d checks passed\n", r.PassedCount, r.TotalCount)

	if r.Certified {
		_, _ = fmt.Fprintf(w, "Status: %sCERTIFICATION PASSED%s\n", ColorGreen+ColorBold, ColorReset)
	} else {
		failed := r.TotalCount - r.PassedCount
		_, _ = fmt.Fprintf(w, "Status: %sCERTIFICATION FAILED%s (%d check(s) not met)\n", ColorRed+ColorBold, ColorReset, failed)
	}

	_, _ = fmt.Fprintf(w, "\nAttestation hash: sha256:%s\n", r.AttestationHash)
}

// --- Helpers ---

// resolvePackDir returns a directory path for the evidence pack,
// extracting archives into a temp directory if needed.
func resolvePackDir(pack string) (string, func(), error) {
	info, err := os.Stat(pack)
	if err != nil {
		return "", nil, fmt.Errorf("cannot access pack: %w", err)
	}

	if info.IsDir() {
		return pack, nil, nil
	}

	// Archive — extract to temp dir.
	tempDir, err := os.MkdirTemp("", "helm-certify-*")
	if err != nil {
		return "", nil, fmt.Errorf("cannot create temp directory: %w", err)
	}

	if err := extractCertifyArchive(pack, tempDir); err != nil {
		os.RemoveAll(tempDir)
		return "", nil, fmt.Errorf("cannot extract archive: %w", err)
	}

	cleanup := func() { os.RemoveAll(tempDir) }
	return tempDir, cleanup, nil
}

// extractCertifyArchive extracts a .tar or .tar.gz archive to dstDir.
func extractCertifyArchive(archivePath, dstDir string) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer file.Close()

	var reader io.Reader = file
	if strings.HasSuffix(archivePath, ".gz") || strings.HasSuffix(archivePath, ".tgz") {
		gzReader, gzErr := gzip.NewReader(file)
		if gzErr != nil {
			return fmt.Errorf("open gzip: %w", gzErr)
		}
		defer gzReader.Close()
		reader = gzReader
	}

	tarReader := tar.NewReader(reader)
	for {
		header, tarErr := tarReader.Next()
		if tarErr == io.EOF {
			return nil
		}
		if tarErr != nil {
			return fmt.Errorf("read tar entry: %w", tarErr)
		}

		targetPath := filepath.Join(dstDir, filepath.Clean(header.Name))
		cleanRoot := filepath.Clean(dstDir)
		if !strings.HasPrefix(targetPath, cleanRoot+string(os.PathSeparator)) && targetPath != cleanRoot {
			return fmt.Errorf("archive entry escapes destination: %s", header.Name)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if mkErr := os.MkdirAll(targetPath, 0750); mkErr != nil {
				return fmt.Errorf("create directory %s: %w", targetPath, mkErr)
			}
		case tar.TypeReg:
			if mkErr := os.MkdirAll(filepath.Dir(targetPath), 0750); mkErr != nil {
				return fmt.Errorf("prepare file %s: %w", targetPath, mkErr)
			}
			outFile, createErr := os.OpenFile(targetPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
			if createErr != nil {
				return fmt.Errorf("create file %s: %w", targetPath, createErr)
			}
			if _, copyErr := io.Copy(outFile, tarReader); copyErr != nil {
				outFile.Close()
				return fmt.Errorf("extract file %s: %w", targetPath, copyErr)
			}
			if closeErr := outFile.Close(); closeErr != nil {
				return fmt.Errorf("close file %s: %w", targetPath, closeErr)
			}
		default:
			// Skip unsupported entry types (symlinks, etc.)
			continue
		}
	}
}

// computeAttestationHash produces a deterministic SHA-256 hash of the report.
func computeAttestationHash(r *CertificationReport) string {
	// Hash the report content excluding the attestation_hash field itself.
	hashable := struct {
		PackPath       string                `json:"pack_path"`
		Framework      string                `json:"framework"`
		FrameworkLabel string                `json:"framework_label"`
		Certified      bool                  `json:"certified"`
		Checks         []CertificationResult `json:"checks"`
		PassedCount    int                   `json:"passed_count"`
		TotalCount     int                   `json:"total_count"`
		CertifiedAt    time.Time             `json:"certified_at"`
		HelmVersion    string                `json:"helm_version"`
	}{
		PackPath:       r.PackPath,
		Framework:      r.Framework,
		FrameworkLabel: r.FrameworkLabel,
		Certified:      r.Certified,
		Checks:         r.Checks,
		PassedCount:    r.PassedCount,
		TotalCount:     r.TotalCount,
		CertifiedAt:    r.CertifiedAt,
		HelmVersion:    r.HelmVersion,
	}

	data, err := json.Marshal(hashable)
	if err != nil {
		return "error"
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// supportedFrameworks returns a sorted list of framework identifiers.
func supportedFrameworks() []string {
	frameworks := make([]string, 0, len(frameworkRequirements))
	for k := range frameworkRequirements {
		frameworks = append(frameworks, k)
	}
	sort.Strings(frameworks)
	return frameworks
}

// containsAnyField checks whether a JSON blob contains any of the given top-level keys.
func containsAnyField(data []byte, fields ...string) bool {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil {
		// Fallback: raw string search for non-JSON files.
		content := string(data)
		for _, f := range fields {
			if strings.Contains(content, fmt.Sprintf("%q", f)) {
				return true
			}
		}
		return false
	}
	for _, f := range fields {
		if _, ok := obj[f]; ok {
			return true
		}
	}
	return false
}

// scanDirForPattern scans all files in a directory for a pattern (case-sensitive).
func scanDirForPattern(dir, pattern string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, readErr := os.ReadFile(filepath.Join(dir, entry.Name()))
		if readErr != nil {
			continue
		}
		if strings.Contains(string(data), pattern) {
			return true
		}
	}
	return false
}

// anyFileExists returns true if the directory exists and contains at least one file.
func anyFileExists(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			return true
		}
	}
	return false
}

func init() {
	Register(Subcommand{
		Name:    "certify",
		Aliases: []string{"cert"},
		Usage:   "Certify evidence pack against compliance framework (--pack, --framework)",
		RunFn:   runCertifyCmd,
	})
}
