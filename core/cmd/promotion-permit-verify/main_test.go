// quantum_posture: these verifier tests exercise existing classical Ed25519
// trust inputs only; they add no post-quantum assurance claim.
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/promotionpermit"
)

func TestDecodeStrictPromotionInputRejectsAmbiguousJSON(t *testing.T) {
	encoded, err := json.Marshal(promotionpermit.Input{
		Schema: promotionpermit.InputSchemaV1, TargetEnvironment: "production",
		ReleaseManifestRef: "release:1", ReleaseManifestGeneration: 1,
		ReleaseManifestHash: "sha256:" + strings.Repeat("a", 64), ReleaseManifestStatus: promotionpermit.ReleaseManifestStatusProductionCandidate,
		PlatformOverlayRef: "platform:1", PlatformOverlayHash: "sha256:" + strings.Repeat("b", 64),
		AppsOverlayRef: "apps:1", AppsOverlayHash: "sha256:" + strings.Repeat("c", 64),
		ProtectedEnvironment: "production", AppsEmptyIntent: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	valid := string(encoded)
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{name: "duplicate", content: strings.Replace(valid, `"schema":`, `"schema":"forged","schema":`, 1), want: `duplicate JSON key "schema"`},
		{name: "unknown", content: strings.TrimSuffix(valid, "}") + `,"unexpected":true}`, want: "input keys must be exactly"},
		{name: "missing explicit bool", content: strings.Replace(valid, `,"apps_empty_intent":false`, "", 1), want: "input keys must be exactly"},
		{name: "null explicit bool", content: strings.Replace(valid, `"apps_empty_intent":false`, `"apps_empty_intent":null`, 1), want: "JSON null values are not accepted"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var input promotionpermit.Input
			_, err := decodeStrictFile(writeFixture(t, test.content), &input, promotionInputKeys)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("decodeStrictFile() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestRunRejectsDuplicateEnvelopeBeforeTrustResolution(t *testing.T) {
	path := writeFixture(t, `{"effect_id":"DEPLOY_PRODUCTION_ACTIVATE","effect_id":"PROVIDER_PROVISION"}`)
	err := run([]string{
		"--envelope", path, "--promotion-input", path, "--promotion-input-ref", "promotion:1",
		"--release-manifest", path, "--platform-overlay", path, "--apps-overlay", path,
		"--input-schema", path, "--verification-context", path,
	}, &strings.Builder{})
	if err == nil || !strings.Contains(err.Error(), `duplicate JSON key "effect_id"`) {
		t.Fatalf("run() error = %v, want duplicate envelope rejection", err)
	}
}

func TestReadRegularFileRejectsSymlink(t *testing.T) {
	target := writeFixture(t, "trusted")
	link := filepath.Join(t.TempDir(), "input")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("create symlink: %v", err)
	}
	if _, err := readRegularFile(link); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("readRegularFile() error = %v, want symlink rejection", err)
	}
}

func TestVerificationContextRejectsMalformedVerdictKey(t *testing.T) {
	inputs := verificationContextInput{
		Schema: verificationContextSchemaV1, ObservedAt: time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC),
		MaximumPermitTTL: "1m", ExpectedPolicyEpoch: "epoch-1", ApprovalConsumptionRef: "consumption:1",
		VerdictTrust: trustKey{PublicKey: "ed25519:" + strings.Repeat("0", 62) + "zz"},
	}
	_, err := inputs.launchContext(contracts.LaunchEffectAuthorizationEnvelope{}, []byte(`{"type":"object"}`))
	if err == nil || !strings.Contains(err.Error(), "verification context verdict key") {
		t.Fatalf("launchContext() error = %v, want malformed verdict key rejection", err)
	}
}

func TestTrustedPermitRejectsWrongEffect(t *testing.T) {
	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	permit := permitBinding{
		EffectID: contracts.EffectTypeProviderProvision, EffectOrdinal: 1, SingleUse: true,
		PermitIssuedAt: now, PermitExpiry: now.Add(time.Minute), KernelVerdictIssuedAt: now,
		KernelVerdictExpiry: now.Add(time.Minute), DispatchDeadline: now.Add(30 * time.Second),
	}
	if err := permit.validate(); err == nil || !strings.Contains(err.Error(), contracts.EffectTypeDeployProductionActivate) {
		t.Fatalf("validate() error = %v, want effect rejection", err)
	}
}

func writeFixture(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fixture")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
