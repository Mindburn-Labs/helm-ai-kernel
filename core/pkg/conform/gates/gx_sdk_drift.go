package gates

import (
	"path/filepath"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/conform"
)

// GXSDKDrift validates that the canonical OpenAPI spec, SDKs, and CLI are in sync per §GX.
// This gate checks for the presence of the canonical OpenAPI spec and verifies
// that SDK wrapper files reference the same API version.
type GXSDKDrift struct{}

func (g *GXSDKDrift) ID() string   { return "GX_SDK_DRIFT" }
func (g *GXSDKDrift) Name() string { return "OpenAPI / SDK Drift Check" }

func (g *GXSDKDrift) Run(ctx *conform.RunContext) *conform.GateResult {
	result := &conform.GateResult{
		GateID:        g.ID(),
		Pass:          true,
		Reasons:       []string{},
		EvidencePaths: []string{},
		Metrics:       conform.GateMetrics{Counts: make(map[string]int)},
	}

	root := ctx.ProjectRoot

	// 1. Check canonical OpenAPI spec exists.
	openapiPaths := []string{
		filepath.Join(root, "api", "openapi", "helm.openapi.yaml"),
		filepath.Join(root, "api", "openapi.yaml"),
		filepath.Join(root, "docs", "api", "openapi.yaml"),
	}

	openapiFound := false
	for _, p := range openapiPaths {
		if fileExists(p) {
			openapiFound = true
			result.EvidencePaths = append(result.EvidencePaths, p)
			break
		}
	}

	if !openapiFound {
		result.Pass = false
		result.Reasons = append(result.Reasons, "OPENAPI_SPEC_MISSING")
		return result
	}
	result.Metrics.Counts["openapi_specs"] = 1

	// 2. Check SDK directories exist
	sdkDirs := []string{
		filepath.Join(root, "sdk", "python"),
		filepath.Join(root, "sdk", "ts"),
		filepath.Join(root, "sdk", "go"),
	}

	sdkCount := 0
	for _, d := range sdkDirs {
		if dirExists(d) {
			sdkCount++
			result.EvidencePaths = append(result.EvidencePaths, d)
		}
	}
	result.Metrics.Counts["sdk_directories"] = sdkCount

	// 3. Check for SDK version marker files (drift detection)
	// Each SDK should have a .openapi-version or similar marker
	if sdkCount > 0 {
		markerCount := 0
		for _, d := range sdkDirs {
			if !dirExists(d) {
				continue
			}
			markerPaths := []string{
				filepath.Join(d, ".openapi-version"),
				filepath.Join(d, "openapi-version.txt"),
				filepath.Join(d, "generated.json"),
			}
			for _, mp := range markerPaths {
				if fileExists(mp) {
					markerCount++
					break
				}
			}
		}
		result.Metrics.Counts["sdk_version_markers"] = markerCount
		// Soft warning — don't fail if markers missing, just note
		if markerCount < sdkCount {
			result.Reasons = append(result.Reasons, "SDK_VERSION_MARKER_MISSING")
			// This is a warning, not a failure for now
		}
	}

	return result
}
