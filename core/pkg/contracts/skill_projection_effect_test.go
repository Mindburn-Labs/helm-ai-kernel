package contracts

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSkillProjectionEffectSealsAndFailsClosed(t *testing.T) {
	now := time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)
	effect := validSkillProjectionEffect(t, now)
	sealed, err := effect.Seal()
	if err != nil {
		t.Fatal(err)
	}
	if err := sealed.ValidateAt(now); err != nil {
		t.Fatalf("ValidateAt: %v", err)
	}

	tampered := sealed
	tampered.WorkspaceID = "other"
	if err := tampered.ValidateAt(now); !errors.Is(err, ErrSkillProjectionEffectIntegrity) {
		t.Fatalf("tampered effect error = %v", err)
	}
	expired := sealed
	expired.ExpiresAt = now
	expired, err = expired.Seal()
	if err != nil {
		t.Fatal(err)
	}
	if err := expired.ValidateAt(now); !errors.Is(err, ErrSkillProjectionEffectInactive) {
		t.Fatalf("expired effect error = %v", err)
	}

	for name, mutate := range map[string]func(*SkillProjectionEffect){
		"schema":       func(e *SkillProjectionEffect) { e.SchemaVersion = "other" },
		"action":       func(e *SkillProjectionEffect) { e.Action = "execute" },
		"workspace":    func(e *SkillProjectionEffect) { e.WorkspaceID = "../escape" },
		"scope case":   func(e *SkillProjectionEffect) { e.TenantID = "Tenant-1" },
		"skill":        func(e *SkillProjectionEffect) { e.SkillID = "../escape" },
		"agent":        func(e *SkillProjectionEffect) { e.AgentTarget = "shell" },
		"agent alias":  func(e *SkillProjectionEffect) { e.AgentTarget = "generic" },
		"artifact":     func(e *SkillProjectionEffect) { e.ArtifactHash = hash64("f") },
		"policy":       func(e *SkillProjectionEffect) { e.PolicyHash = "sha256:BAD" },
		"certificates": func(e *SkillProjectionEffect) { e.CertificationRefs = []string{"z", "a"} },
		"permit":       func(e *SkillProjectionEffect) { e.ConsumedPermitRef = "sha256:BAD" },
		"generation":   func(e *SkillProjectionEffect) { e.Generation = 0 },
		"nonce":        func(e *SkillProjectionEffect) { e.Nonce = "short" },
		"sandbox":      func(e *SkillProjectionEffect) { e.SandboxProfile = "shell" },
		"invalid utf8": func(e *SkillProjectionEffect) { e.IdempotencyKey = string([]byte{0xff}) },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := effect
			mutate(&candidate)
			if _, err := candidate.Seal(); err == nil {
				t.Fatal("expected validation failure")
			}
		})
	}
}

func TestSkillProjectionEffectCanonicalHashVector(t *testing.T) {
	now := time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)
	effect := validSkillProjectionEffect(t, now)

	if effect.ArtifactHash != "sha256:7485bc0f65e565ec21749f4c7fd417deccd7713ea3bb9a1908633cb436501202" {
		t.Fatalf("artifact hash = %s", effect.ArtifactHash)
	}
	sealed, err := effect.Seal()
	if err != nil {
		t.Fatal(err)
	}
	if sealed.CanonicalRequestHash != "sha256:60b549ffc380a992c88f298f74afd32d7d252dda012db63588346fc5247e7c30" {
		t.Fatalf("canonical request hash = %s", sealed.CanonicalRequestHash)
	}
}

func TestSkillProjectionConsumedPermitRefIsCanonicalAndPreEffect(t *testing.T) {
	ref, err := ComputeSkillProjectionConsumedPermitRef("tenant-1", "workspace-1", "grant-1")
	if err != nil {
		t.Fatal(err)
	}
	if ref != "sha256:ac184e586819d187798f0149018e1329ec0eb68b982539d5a76211b670956259" {
		t.Fatalf("consumed permit reference = %s", ref)
	}

	now := time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)
	effect := validSkillProjectionEffect(t, now)
	effect.ConsumedPermitRef = ref
	effect, err = effect.Seal()
	if err != nil {
		t.Fatal(err)
	}
	grant := validApprovalGrant()
	grant.GrantID = "grant-1"
	grant.TenantID = effect.TenantID
	grant.WorkspaceID = effect.WorkspaceID
	grant.PackID = effect.SkillID
	grant.PackVersion = effect.SkillVersion
	grant.PackManifestHash = effect.ManifestHash
	grant.EffectHash = effect.CanonicalRequestHash
	grant.PolicyHash = effect.PolicyHash
	grant.ConnectorAuthority = approvalConnectorAuthorityFor(
		grant.TenantID, grant.WorkspaceID, grant.PackID, grant.PackVersion,
		grant.PackManifestHash, grant.Action, grant.EffectHash, grant.PolicyHash,
	)
	grant, err = grant.Seal()
	if err != nil {
		t.Fatal(err)
	}
	if ref == grant.GrantHash {
		t.Fatal("pre-effect permit reference must not alias the sealed grant hash")
	}
	recomputed, err := ComputeSkillProjectionConsumedPermitRef(grant.TenantID, grant.WorkspaceID, grant.GrantID)
	if err != nil || recomputed != ref {
		t.Fatalf("recomputed reference = %s, err = %v", recomputed, err)
	}

	for name, values := range map[string][3]string{
		"tenant":    {"tenant-2", "workspace-1", "grant-1"},
		"workspace": {"tenant-1", "workspace-2", "grant-1"},
		"grant":     {"tenant-1", "workspace-1", "grant-2"},
	} {
		t.Run(name, func(t *testing.T) {
			changed, err := ComputeSkillProjectionConsumedPermitRef(values[0], values[1], values[2])
			if err != nil {
				t.Fatal(err)
			}
			if changed == ref {
				t.Fatal("authority field mutation did not change the permit reference")
			}
		})
	}
}

func TestSkillProjectionConsumedPermitRefRejectsUnsafeScope(t *testing.T) {
	for name, values := range map[string][3]string{
		"tenant":             {"Tenant-1", "workspace-1", "grant-1"},
		"workspace":          {"tenant-1", "../workspace", "grant-1"},
		"grant":              {"tenant-1", "workspace-1", "grant id"},
		"unicode whitespace": {"tenant-1", "workspace-1", "grant\u00a0id"},
		"long grant":         {"tenant-1", "workspace-1", strings.Repeat("g", 513)},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ComputeSkillProjectionConsumedPermitRef(values[0], values[1], values[2]); err == nil {
				t.Fatal("expected unsafe consumed permit scope to fail")
			}
		})
	}
}

func TestSkillProjectionRollbackPermitIsSeparateAndActionBound(t *testing.T) {
	now := time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)
	effect := validSkillProjectionEffect(t, now)
	effect.Action = SkillProjectionActionRollback
	effect.Generation = 3
	permit := SkillProjectionRollbackPermit{
		SchemaVersion:      SkillProjectionRollbackPermitSchemaV1,
		ContractVersion:    SkillProjectionRollbackPermitContractV1,
		PermitRef:          hash64("8"),
		Action:             SkillProjectionActionRollback,
		TenantID:           effect.TenantID,
		WorkspaceID:        effect.WorkspaceID,
		SkillID:            effect.SkillID,
		AgentTarget:        effect.AgentTarget,
		FromGeneration:     2,
		TargetGeneration:   1,
		TargetSkillVersion: effect.SkillVersion,
		TargetArtifactHash: effect.ArtifactHash,
		TargetPolicyHash:   effect.PolicyHash,
		IssuedAt:           now.Add(-time.Minute),
		ExpiresAt:          now.Add(time.Minute),
		Nonce:              strings.Repeat("9", 64),
	}
	var err error
	permit, err = permit.Seal()
	if err != nil {
		t.Fatal(err)
	}
	effect.RollbackPermitHash = permit.PermitHash
	effect, err = effect.Seal()
	if err != nil {
		t.Fatal(err)
	}
	if err := effect.ValidateRollbackPermit(permit, now); err != nil {
		t.Fatalf("ValidateRollbackPermit: %v", err)
	}

	wrongTarget := permit
	wrongTarget.TargetGeneration = 2
	if err := effect.ValidateRollbackPermit(wrongTarget, now); err == nil {
		t.Fatal("expected tampered rollback permit to fail")
	}
	samePermit := permit
	samePermit.PermitRef = effect.ConsumedPermitRef
	samePermit, err = samePermit.Seal()
	if err != nil {
		t.Fatal(err)
	}
	effect.RollbackPermitHash = samePermit.PermitHash
	effect, err = effect.Seal()
	if err != nil {
		t.Fatal(err)
	}
	if err := effect.ValidateRollbackPermit(samePermit, now); err == nil {
		t.Fatal("expected general consumed permit reuse to fail")
	}
}

func validSkillProjectionEffect(t *testing.T, now time.Time) SkillProjectionEffect {
	t.Helper()
	manifestHash := hash64("1")
	contentHash := hash64("2")
	artifactHash, err := ComputeSkillProjectionArtifactHash(manifestHash, contentHash)
	if err != nil {
		t.Fatal(err)
	}
	return SkillProjectionEffect{
		SchemaVersion:     SkillProjectionEffectSchemaV1,
		ContractVersion:   SkillProjectionEffectContractV1,
		Action:            SkillProjectionActionInstall,
		TenantID:          "tenant-1",
		WorkspaceID:       "workspace-1",
		SkillID:           "helm/repo-auditor",
		SkillVersion:      "1.0.0",
		AgentTarget:       "codex",
		ArtifactHash:      artifactHash,
		ContentHash:       contentHash,
		ManifestHash:      manifestHash,
		PolicyHash:        hash64("3"),
		SchemaHash:        SkillProjectionArtifactSchemaHashV1,
		CertificationRefs: []string{"certification:one", "provenance:one"},
		ConsumedPermitRef: hash64("4"),
		IdempotencyKey:    "projection:tenant-1:workspace-1:helm/repo-auditor:1",
		AttemptID:         "attempt-1",
		Generation:        1,
		ExpiresAt:         now.Add(time.Minute),
		Nonce:             strings.Repeat("5", 64),
		SandboxProfile:    SkillProjectionSandboxProfileV1,
	}
}

func hash64(character string) string {
	return "sha256:" + strings.Repeat(character, 64)
}
