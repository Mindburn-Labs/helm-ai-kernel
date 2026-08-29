// quantum_posture: this smoke fixture uses ephemeral classical Ed25519 only
// for the current Kernel policy-head compatibility contract; it makes no
// post-quantum assurance claim.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	policyreconcile "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/policy/reconcile"
)

const (
	runtimePolicyRef     = "/etc/helm-ai-kernel/serve-policy.toml"
	runtimeReferencePack = "reference_packs/eu_ai_act_high_risk.v2.json"
)

func main() {
	outDir := flag.String("out", "", "directory for generated fixture files")
	tenantID := flag.String("tenant", "", "policy tenant")
	workspaceID := flag.String("workspace", "", "policy workspace")
	referencePack := flag.String("reference-pack", "", "host path to the bundled reference pack")
	flag.Parse()

	if err := generate(*outDir, *tenantID, *workspaceID, *referencePack); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func generate(outDir, tenantID, workspaceID, referencePack string) error {
	if outDir == "" || tenantID == "" || workspaceID == "" || referencePack == "" {
		return fmt.Errorf("out, tenant, workspace, and reference-pack are required")
	}
	referencePackBytes, err := os.ReadFile(filepath.Clean(referencePack))
	if err != nil {
		return fmt.Errorf("read reference pack: %w", err)
	}
	bundle := []byte(fmt.Sprintf(`name = "kind-smoke"
profile = "high_risk"
reference_pack = %q

[server]
bind = "0.0.0.0"
port = 8080

[receipts]
store = "sqlite"
path = "/var/lib/helm-ai-kernel/helm.db"
`, runtimeReferencePack))
	head := policyreconcile.PolicyHead{
		Scope:       policyreconcile.PolicyScope{TenantID: tenantID, WorkspaceID: workspaceID}.Normalize(),
		PolicyEpoch: 1,
		PolicyHash:  policyreconcile.HashBytes(bundle),
		BundleRef:   runtimePolicyRef,
		SourceRefs: []string{fmt.Sprintf(
			"reference_pack:%s@%s",
			filepath.Join(filepath.Dir(runtimePolicyRef), runtimeReferencePack),
			policyreconcile.HashBytes(referencePackBytes),
		)},
	}
	material, err := policyreconcile.PolicyHeadSignatureMaterial(head)
	if err != nil {
		return fmt.Errorf("build policy signature material: %w", err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate fixture signing key: %w", err)
	}
	signature := ed25519.Sign(privateKey, material)
	if !ed25519.Verify(publicKey, material, signature) {
		return fmt.Errorf("fixture signature self-check failed")
	}
	head.Signature = hex.EncodeToString(signature)
	headJSON, err := json.MarshalIndent(head, "", "  ")
	if err != nil {
		return fmt.Errorf("encode policy head: %w", err)
	}

	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return fmt.Errorf("create fixture directory: %w", err)
	}
	files := map[string][]byte{
		"bundle.toml":    bundle,
		"head.json":      append(headJSON, '\n'),
		"public-key.hex": []byte(hex.EncodeToString(publicKey) + "\n"),
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(outDir, name), data, 0o600); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
	}
	return nil
}
