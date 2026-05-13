package adversarial

import (
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/threatscan"
)

func TestThreatScannerSuitePasses(t *testing.T) {
	results := RunThreatScannerSuite(threatscan.New())

	for _, result := range results {
		if !result.Passed {
			t.Fatalf("%s failed: %s (%s)", result.Name, result.Reason, result.Summary)
		}
	}
}
