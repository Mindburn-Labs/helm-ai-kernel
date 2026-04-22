package gates

import (
	"os"
	"path/filepath"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/conform"
)

// G4Secrets validates secrets and key management per §G4.
type G4Secrets struct{}

func (g *G4Secrets) ID() string   { return "G4" }
func (g *G4Secrets) Name() string { return "Secrets and Key Management" }

func (g *G4Secrets) Run(ctx *conform.RunContext) *conform.GateResult {
	result := &conform.GateResult{
		GateID:        g.ID(),
		Pass:          true,
		Reasons:       []string{},
		EvidencePaths: []string{},
		Metrics:       conform.GateMetrics{Counts: make(map[string]int)},
	}

	// Scan all evidence artifacts for secret patterns
	scanDirs := []string{
		filepath.Join(ctx.EvidenceDir, "06_LOGS"),
		filepath.Join(ctx.EvidenceDir, "08_TAPES"),
		filepath.Join(ctx.EvidenceDir, "02_PROOFGRAPH"),
	}

	for _, dir := range scanDirs {
		if !dirExists(dir) {
			continue
		}
		_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			if containsSecretPattern(data) {
				result.Pass = false
				relPath, _ := filepath.Rel(ctx.EvidenceDir, path)
				result.Reasons = append(result.Reasons, "SECRET_LEAK_DETECTED:"+relPath)
			}
			result.Metrics.Counts["files_scanned"]++
			return nil
		})
	}

	return result
}

// containsSecretPattern checks for common secret patterns.
func containsSecretPattern(data []byte) bool {
	patterns := []string{
		"AKIA", // AWS access key
		"-----BEGIN RSA PRIVATE KEY-----",
		"-----BEGIN EC PRIVATE KEY-----",
		"-----BEGIN PRIVATE KEY-----",
		"sk_live_", // Stripe
		"ghp_",     // GitHub
		"password=",
	}
	s := string(data)
	for _, p := range patterns {
		for i := 0; i <= len(s)-len(p); i++ {
			if s[i:i+len(p)] == p {
				return true
			}
		}
	}
	return false
}
