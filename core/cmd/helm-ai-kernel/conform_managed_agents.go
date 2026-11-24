package main

// quantum_posture: classical Ed25519/SHA-256 only; no post-quantum assurance
// is claimed or provided by this file.

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/verifier"
)

func runConformManagedAgents(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "claude-self-hosted" {
		_, _ = fmt.Fprintln(stderr, "Usage: helm-ai-kernel conform managed-agents claude-self-hosted --provider daytona --live-config <file> --out <dir> --sign")
		return 2
	}
	return runConformClaudeSelfHosted(args[1:], stdout, stderr)
}

func runConformClaudeSelfHosted(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("conform managed-agents claude-self-hosted", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		provider        string
		configPath      string
		outDir          string
		signReport      bool
		promoteRegistry bool
		registryPath    string
		reportRefPath   string
		candidateCommit string
		candidateTree   string
	)
	cmd.StringVar(&provider, "provider", "daytona", "Live self-hosted worker provider fixture")
	cmd.StringVar(&configPath, "live-config", "", "Redacted live evidence config JSON")
	cmd.StringVar(&outDir, "out", filepath.Join("artifacts", "claude-managed-agents-live"), "Output directory for the evidence pack and report")
	cmd.BoolVar(&signReport, "sign", false, "Sign the live evidence report with HELM_SIGNING_KEY_HEX")
	cmd.BoolVar(&promoteRegistry, "promote-registry", false, "Promote compatibility registry entry when all live evidence guards pass")
	cmd.StringVar(&registryPath, "registry", filepath.Join("protocols", "conformance", "v1", "compatibility-registry.json"), "Compatibility registry path")
	cmd.StringVar(&reportRefPath, "report-ref", "", "Optional source-tree path for the sanitized report reference")
	cmd.StringVar(&candidateCommit, "candidate-commit", "", "Expected candidate commit; defaults to HELM_CANDIDATE_COMMIT or git HEAD")
	cmd.StringVar(&candidateTree, "candidate-tree", "", "Expected candidate tree hash; defaults to HELM_CANDIDATE_TREE or git rev-parse HEAD^{tree}")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if configPath == "" {
		_, _ = fmt.Fprintln(stderr, "Error: --live-config is required")
		return 2
	}
	if provider != "daytona" {
		_, _ = fmt.Fprintf(stderr, "Error: unsupported provider %q; only daytona is enabled for the first verified fixture\n", provider)
		return 2
	}
	cfg, err := readManagedAgentLiveConfig(configPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: live config invalid: %v\n", err)
		return 2
	}
	if candidateCommit == "" {
		candidateCommit = firstNonEmpty(os.Getenv("HELM_CANDIDATE_COMMIT"), gitValue("rev-parse", "HEAD"))
	}
	if candidateTree == "" {
		candidateTree = firstNonEmpty(os.Getenv("HELM_CANDIDATE_TREE"), gitValue("rev-parse", "HEAD^{tree}"))
	}

	blockers := validateManagedAgentLiveConfig(cfg, provider, candidateCommit, candidateTree, promoteRegistry)
	if !signReport {
		blockers = append(blockers, "live evidence report must be signed with --sign")
		sort.Strings(blockers)
	}
	report := buildManagedAgentLiveReport(cfg, blockers)
	report.Status = "blocked"
	report.OfflineVerification = "not-run"
	report.PromotionReady = len(blockers) == 0
	if report.PromotionReady {
		report.Status = "ready"
	}

	if err := os.MkdirAll(outDir, 0750); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: cannot create output dir: %v\n", err)
		return 2
	}
	reportPath := filepath.Join(outDir, "live-evidence-report.json")
	if err := writeManagedAgentJSON(reportPath, report); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: cannot write report: %v\n", err)
		return 2
	}

	var signer *managedAgentSigningMaterial
	if signReport {
		signer, err = loadManagedAgentSigningMaterial(cfg.Signer.KeyID)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: cannot load live evidence signing key: %v\n", err)
			return 2
		}
		sig, err := signManagedAgentLiveReport(reportPath, signer)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: cannot sign live evidence report: %v\n", err)
			return 2
		}
		if err := writeManagedAgentJSON(filepath.Join(outDir, "live-evidence-report.sig.json"), sig); err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: cannot write report signature: %v\n", err)
			return 2
		}
	}

	packDir := filepath.Join(outDir, "evidence-pack")
	if err := writeManagedAgentEvidenceDirectory(packDir, report, signer); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: cannot write evidence pack: %v\n", err)
		return 2
	}
	verifyReport, err := verifier.VerifyBundleWithOptions(packDir, verifier.VerifyOptions{
		// Pack produced by this process; self-attested seal is expected (F-02).
		AllowSelfAttested:               true,
		ManagedAgentReceiptPublicKeyHex: managedAgentSignerPublicKeyHex(signer),
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: cannot verify evidence pack: %v\n", err)
		return 2
	}
	if !verifyReport.Verified {
		report.OfflineVerification = "failed"
		report.Blockers = append(report.Blockers, "offline evidence pack verification failed: "+verifyReport.Summary)
		report.PromotionReady = false
		report.Status = "blocked"
	} else {
		report.OfflineVerification = "passed"
	}
	if err := writeManagedAgentJSON(reportPath, report); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: cannot refresh report: %v\n", err)
		return 2
	}
	if err := writeManagedAgentEvidenceDirectory(packDir, report, signer); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: cannot refresh evidence pack: %v\n", err)
		return 2
	}
	verifyReport, err = verifier.VerifyBundleWithOptions(packDir, verifier.VerifyOptions{
		// Pack produced by this process; self-attested seal is expected (F-02).
		AllowSelfAttested:               true,
		ManagedAgentReceiptPublicKeyHex: managedAgentSignerPublicKeyHex(signer),
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: cannot verify final evidence pack: %v\n", err)
		return 2
	}
	if !verifyReport.Verified {
		_, _ = fmt.Fprintf(stderr, "Error: final evidence pack verification failed: %s\n", verifyReport.Summary)
		return 2
	}

	archivePath := filepath.Join(outDir, "evidence-pack.tar")
	if err := archiveManagedAgentEvidence(packDir, archivePath); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: cannot archive evidence pack: %v\n", err)
		return 2
	}
	packHash, err := fileSHA256(archivePath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: cannot hash evidence pack: %v\n", err)
		return 2
	}
	report.EvidencePackSHA256 = "sha256:" + packHash
	if err := writeManagedAgentJSON(reportPath, report); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: cannot write final report: %v\n", err)
		return 2
	}

	if reportRefPath != "" || promoteRegistry {
		if reportRefPath == "" {
			reportRefPath = filepath.Join("protocols", "conformance", "managed-agents", "claude-self-hosted", "v1", "live-evidence-report.json")
		}
		if err := copyFile(reportPath, reportRefPath); err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: cannot write sanitized report reference: %v\n", err)
			return 2
		}
	}

	if promoteRegistry {
		if !report.PromotionReady {
			_, _ = fmt.Fprintln(stderr, "Error: live evidence is incomplete; refusing registry promotion")
			for _, blocker := range report.Blockers {
				_, _ = fmt.Fprintf(stderr, "- %s\n", blocker)
			}
			return 1
		}
		if err := promoteManagedAgentRegistry(registryPath, report); err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: cannot promote compatibility registry: %v\n", err)
			return 2
		}
	}

	if !report.PromotionReady {
		_, _ = fmt.Fprintf(stdout, "Claude Managed Agents live evidence blocked; report=%s\n", reportPath)
		for _, blocker := range report.Blockers {
			_, _ = fmt.Fprintf(stdout, "  - %s\n", blocker)
		}
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "Claude Managed Agents live evidence ready\n")
	_, _ = fmt.Fprintf(stdout, "  report: %s\n", reportPath)
	_, _ = fmt.Fprintf(stdout, "  pack:   %s\n", archivePath)
	_, _ = fmt.Fprintf(stdout, "  sha256: %s\n", report.EvidencePackSHA256)
	return 0
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func gitValue(args ...string) string {
	out, err := exec.Command("git", args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
