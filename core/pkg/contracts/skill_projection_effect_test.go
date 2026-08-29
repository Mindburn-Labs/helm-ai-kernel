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
		"skill":        func(e *SkillProjectionEffect) { e.SkillID = "../escape" },
		"agent":        func(e *SkillProjectionEffect) { e.AgentTarget = "shell" },
		"artifact":     func(e *SkillProjectionEffect) { e.ArtifactHash = hash64("f") },
		"policy":       func(e *SkillProjectionEffect) { e.PolicyHash = "sha256:BAD" },
		"certificates": func(e *SkillProjectionEffect) { e.CertificationRefs = []string{"z", "a"} },
		"permit":       func(e *SkillProjectionEffect) { e.ConsumedPermitRef = "sha256:BAD" },
		"generation":   func(e *SkillProjectionEffect) { e.Generation = 0 },
		"nonce":        func(e *SkillProjectionEffect) { e.Nonce = "short" },
		"sandbox":      func(e *SkillProjectionEffect) { e.SandboxProfile = "shell" },
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
