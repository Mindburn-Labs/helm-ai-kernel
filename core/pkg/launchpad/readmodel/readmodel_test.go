package readmodel

import (
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/plan"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/registry"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/secrets"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/session"
)

func TestRegistryAppsExpandsCatalogBackedBYOModelGateway(t *testing.T) {
	app := registry.AppSpec{
		ID:             "openclaw",
		Name:           "OpenClaw",
		Version:        "test",
		Availability:   registry.AvailabilityOSSSupported,
		Redistribution: "oss",
		Install:        registry.InstallSpec{Strategy: "signed_oci"},
		ModelGateway: registry.ModelGatewaySpec{
			LogicalSecret: "model_gateway",
			Provider:      "byo",
			ProviderIDs:   []string{"openai", "anthropic"},
			Mode:          "external_byo",
		},
		RequiredSecrets: []string{"model_gateway"},
		NetworkPolicy:   registry.NetworkPolicy{Default: "deny"},
		MCPPolicy:       registry.MCPPolicy{UnknownServerPolicy: "quarantine", UnknownToolPolicy: "ESCALATE", RequireSchemaPin: true},
		Conformance: registry.ConformanceSpec{
			LicenseVerified:      true,
			ArtifactVerified:     true,
			PolicyPackPresent:    true,
			SandboxVerified:      true,
			HealthcheckPassing:   true,
			E2EPassing:           true,
			TeardownVerified:     true,
			ReceiptVerified:      true,
			EvidencePackVerified: true,
		},
	}

	apps := RegistryApps(&registry.Catalog{Apps: []registry.AppSpec{app}}, []secrets.Status{{
		Name:      "model_gateway",
		Provider:  "openai",
		ValueEnv:  "OPENAI_API_KEY",
		Available: true,
	}}, nil)

	if len(apps) != 1 {
		t.Fatalf("RegistryApps returned %d apps", len(apps))
	}
	if !contains(apps[0].ModelGatewayEnv, "OPENAI_API_KEY") || !contains(apps[0].ModelGatewayEnv, "ANTHROPIC_API_KEY") {
		t.Fatalf("catalog-backed env not expanded: %#v", apps[0].ModelGatewayEnv)
	}
	if !contains(apps[0].NetworkNeeds, "https://api.openai.com/v1") || !contains(apps[0].NetworkNeeds, "https://api.anthropic.com/v1") {
		t.Fatalf("catalog-backed network needs not expanded: %#v", apps[0].NetworkNeeds)
	}
	if apps[0].Status.State != "ready" || len(apps[0].Status.MissingSecrets) != 0 {
		t.Fatalf("provider-specific model_gateway status did not satisfy BYO any-of secret: %#v", apps[0].Status)
	}
}

func TestRegistryAppsRequiresCompleteDynamicProviderEnvGroup(t *testing.T) {
	t.Setenv("AZURE_OPENAI_ENDPOINT", "")
	app := registry.AppSpec{
		ID:             "openclaw",
		Name:           "OpenClaw",
		Version:        "test",
		Availability:   registry.AvailabilityOSSSupported,
		Redistribution: "oss",
		Install:        registry.InstallSpec{Strategy: "signed_oci"},
		ModelGateway: registry.ModelGatewaySpec{
			LogicalSecret: "model_gateway",
			Provider:      "byo",
			ProviderIDs:   []string{"azure-openai"},
			Mode:          "external_byo",
		},
		RequiredSecrets: []string{"model_gateway"},
		NetworkPolicy:   registry.NetworkPolicy{Default: "deny"},
		MCPPolicy:       registry.MCPPolicy{UnknownServerPolicy: "quarantine", UnknownToolPolicy: "ESCALATE", RequireSchemaPin: true},
		Conformance: registry.ConformanceSpec{
			LicenseVerified:      true,
			ArtifactVerified:     true,
			PolicyPackPresent:    true,
			SandboxVerified:      true,
			HealthcheckPassing:   true,
			E2EPassing:           true,
			TeardownVerified:     true,
			ReceiptVerified:      true,
			EvidencePackVerified: true,
		},
	}
	statuses := []secrets.Status{{
		Name:      "model_gateway",
		Provider:  "azure-openai",
		ValueEnv:  "HELM_TEST_AZURE",
		Available: true,
	}}

	apps := RegistryApps(&registry.Catalog{Apps: []registry.AppSpec{app}}, statuses, nil)
	if apps[0].Status.State == "ready" || len(apps[0].Status.MissingSecrets) == 0 {
		t.Fatalf("Azure key without endpoint must remain missing: %#v", apps[0].Status)
	}

	t.Setenv("AZURE_OPENAI_ENDPOINT", "https://example.openai.azure.com/")
	apps = RegistryApps(&registry.Catalog{Apps: []registry.AppSpec{app}}, statuses, nil)
	if apps[0].Status.State != "ready" || len(apps[0].Status.MissingSecrets) != 0 {
		t.Fatalf("complete Azure group should satisfy BYO readiness: %#v", apps[0].Status)
	}
	if !contains(apps[0].NetworkNeeds, "https://example.openai.azure.com") {
		t.Fatalf("dynamic Azure endpoint not surfaced in readmodel: %#v", apps[0].NetworkNeeds)
	}
}

func TestRegistryAppsBuildsStatusAndMetadata(t *testing.T) {
	if got := RegistryApps(nil, nil, nil); len(got) != 0 {
		t.Fatalf("nil catalog returned %d apps, want 0", len(got))
	}

	t.Setenv("DIRECT_MODEL_KEY", "present")
	ready := testApp("ready")
	direct := testApp("direct")
	direct.ModelGatewayEnv = []string{"DIRECT_MODEL_KEY"}
	direct.RequiredSecrets = nil
	missing := testApp("missing")
	missing.ModelGatewayEnv = nil
	missing.RequiredSecrets = []string{"plain-secret"}
	unsupported := testApp("unsupported")
	unsupported.Availability = registry.AvailabilityOSSCandidate
	unsupported.Conformance = registry.ConformanceSpec{}

	got := RegistryApps(&registry.Catalog{Apps: []registry.AppSpec{ready, direct, missing, unsupported}}, []secrets.Status{{
		Name:      "model-key",
		Provider:  "env",
		ValueEnv:  "SOURCE_MODEL_KEY",
		Available: true,
	}}, []session.LaunchRun{
		{AppID: "ready"},
		{AppID: "ready", EvidencePackRefs: []string{"evidence-old", "evidence-new"}},
	})
	if len(got) != 4 {
		t.Fatalf("RegistryApps returned %d apps, want 4", len(got))
	}

	readyView := got[0]
	if readyView.Status.State != "ready" || readyView.Status.Verdict != "ALLOW" {
		t.Fatalf("ready status = %+v, want ready allow", readyView.Status)
	}
	if readyView.Status.LastEvidencePack != "evidence-new" || !readyView.Status.OfflineVerifiable {
		t.Fatalf("ready evidence status = %+v, want latest evidence and offline verification", readyView.Status)
	}
	if !readyView.OSSSupported || readyView.BlockedReason != "" {
		t.Fatalf("ready app oss/block fields = oss:%v blocked:%q", readyView.OSSSupported, readyView.BlockedReason)
	}
	if !contains(readyView.DeclaredCapabilities, "scoped-network-egress") || !contains(readyView.DeclaredCapabilities, "mcp-firewall") {
		t.Fatalf("declared capabilities = %#v, want network and mcp capabilities", readyView.DeclaredCapabilities)
	}
	if len(readyView.MCPServers) != 1 || readyView.MCPServers[0].ID != "ready-mcp" || !readyView.MCPServers[0].SchemaPinRequired {
		t.Fatalf("mcp servers = %#v, want one schema-pinned server", readyView.MCPServers)
	}
	if len(readyView.TeardownRecipe) == 0 || readyView.PolicyRef != "policy://ready" {
		t.Fatalf("registry metadata not projected: teardown=%#v policy=%q", readyView.TeardownRecipe, readyView.PolicyRef)
	}

	if got[1].Status.State != "ready" || len(got[1].Status.MissingSecrets) != 0 {
		t.Fatalf("direct env status = %+v, want ready without missing secrets", got[1].Status)
	}
	if got[2].Status.State != "needs_secret" || got[2].BlockedReason != "ERR_LAUNCHPAD_REQUIRED_SECRET_MISSING" || !contains(got[2].Status.MissingSecrets, "plain-secret") {
		t.Fatalf("missing secret status = %+v blocked=%q, want needs_secret", got[2].Status, got[2].BlockedReason)
	}
	if got[3].Status.State != "verification_failed" || got[3].Status.ReasonCode != "ERR_LAUNCHPAD_APP_CONFORMANCE_REQUIRED" {
		t.Fatalf("unsupported status = %+v, want conformance failure", got[3].Status)
	}
}

func TestGatesFromPlanCoversDenyRepairAndReceipts(t *testing.T) {
	app := testApp("launchpad")
	substrate := registry.SubstrateSpec{ID: "local-docker", Kind: "container"}

	artifactDenied := GatesFromPlan(app, substrate, plan.LaunchPlan{
		KernelVerdict: "DENY",
		ReasonCode:    "ERR_ARTIFACT_DIGEST_MISMATCH",
		Status:        string(session.StateValidated),
		MCPPolicy:     registry.MCPPolicy{UnknownServerPolicy: "quarantine"},
	}, nil)
	if gateByID(t, artifactDenied, "artifact.digest").Verdict != "DENY" {
		t.Fatalf("artifact.digest gate = %+v, want DENY", gateByID(t, artifactDenied, "artifact.digest"))
	}
	if gateByID(t, artifactDenied, "mcp.quarantine").ReasonCode != "ERR_MCP_QUARANTINE_UNPROVEN" {
		t.Fatalf("mcp gate = %+v, want quarantine reason", gateByID(t, artifactDenied, "mcp.quarantine"))
	}
	if gateByID(t, artifactDenied, "runtime.start").ProofStatus != "unproven" {
		t.Fatalf("runtime.start gate = %+v, want unproven without run", gateByID(t, artifactDenied, "runtime.start"))
	}

	secretDenied := GatesFromPlan(app, substrate, plan.LaunchPlan{
		KernelVerdict: "DENY",
		ReasonCode:    "ERR_LAUNCHPAD_REQUIRED_SECRET_MISSING",
		Status:        string(session.StateEscalated),
	}, nil)
	secretGate := gateByID(t, secretDenied, "secrets.required")
	if secretGate.Verdict != "ESCALATE" || len(secretGate.FixActions) != 1 || !strings.Contains(secretGate.FixActions[0].CLI, "model-key") {
		t.Fatalf("secret gate = %+v, want escalation with app-specific fix action", secretGate)
	}

	unverified := app
	unverified.Conformance = registry.ConformanceSpec{}
	ossGate := gateByID(t, GatesFromPlan(unverified, substrate, plan.LaunchPlan{KernelVerdict: "ALLOW", Status: string(session.StateValidated)}, nil), "app.oss_supported")
	if ossGate.Verdict != "ESCALATE" || ossGate.ReasonCode != "ERR_LAUNCHPAD_APP_CONFORMANCE_REQUIRED" {
		t.Fatalf("oss gate = %+v, want conformance escalation", ossGate)
	}

	// verify_only is a documented allowed support state: the support gate
	// must not escalate what the verify-only contract preflight proves.
	verifyOnly := unverified
	verifyOnly.SupportLevel = registry.SupportLevelVerifyOnly
	verifyOnlyGate := gateByID(t, GatesFromPlan(verifyOnly, substrate, plan.LaunchPlan{KernelVerdict: "ALLOW", Status: string(session.StateValidated)}, nil), "app.oss_supported")
	if verifyOnlyGate.Verdict != "ALLOW" || verifyOnlyGate.ReasonCode != "LAUNCHPAD_APP_VERIFY_ONLY" {
		t.Fatalf("verify-only oss gate = %+v, want ALLOW with verify-only reason", verifyOnlyGate)
	}

	run := fullRun()
	receipted := GatesFromPlan(app, substrate, plan.LaunchPlan{KernelVerdict: "ALLOW", Status: string(session.StateRunning)}, &run)
	for _, id := range []string{"mcp.quarantine", "runtime.start", "healthcheck", "receipts.emit", "evidence.export", "offline.verify", "teardown.cascade"} {
		if got := gateByID(t, receipted, id); got.Verdict != "ALLOW" || got.ProofStatus != "proven" {
			t.Fatalf("%s gate = %+v, want ALLOW proven", id, got)
		}
	}
	if sandbox := gateByID(t, receipted, "sandbox.grant"); sandbox.ProofStatus != "proven" || len(sandbox.ReceiptRefs) != 1 {
		t.Fatalf("sandbox gate = %+v, want sandbox receipt proof", sandbox)
	}

	repair := run
	repair.State = session.StateRepairRequired
	repairGate := gateByID(t, GatesFromPlan(app, substrate, plan.LaunchPlan{KernelVerdict: "ALLOW", Status: string(session.StateRepairRequired)}, &repair), "runtime.start")
	if repairGate.Verdict != "ESCALATE" || !strings.Contains(repairGate.Summary, "requires repair") {
		t.Fatalf("repair runtime gate = %+v, want repair escalation", repairGate)
	}
}

func TestEventsFromRunMarksQuarantineAndEscalatedGaps(t *testing.T) {
	escalated := session.LaunchRun{
		LaunchID:      "run-escalated",
		KernelVerdict: "DENY",
		State:         session.StateEscalated,
		EvidencePackRefs: []string{
			"evidence-pack",
		},
	}
	events := EventsFromRun(escalated)
	mcp := eventByStage(t, events, "mcp_quarantine_enforced")
	if mcp.Verdict != "ESCALATE" || mcp.ReasonCode != "ERR_MCP_QUARANTINE_UNPROVEN" {
		t.Fatalf("mcp event = %+v, want unproven quarantine escalation", mcp)
	}
	if got := eventByStage(t, events, "healthcheck_passed"); got.ActionableError == "" {
		t.Fatalf("healthcheck event = %+v, want actionable error for escalated unproven stage", got)
	}

	proven := fullRun()
	provenEvents := EventsFromRun(proven)
	if got := eventByStage(t, provenEvents, "mcp_quarantine_enforced"); got.Verdict != "ALLOW" || got.ReasonCode != "" || got.ProofStatus != "proven" {
		t.Fatalf("proven mcp event = %+v, want allow/proven", got)
	}
	if got := eventByStage(t, provenEvents, "launch_receipt_emitted"); got.CLIEquivalent != "helm-ai-kernel run receipts run-1" {
		t.Fatalf("launch receipt cli = %q, want run receipts command", got.CLIEquivalent)
	}
}

func TestRuntimeDetailAndSandboxGrantViews(t *testing.T) {
	run := fullRun()
	instance := RuntimeFromRun(run)
	if instance.Runtime != "local-docker" || instance.EvidencePackRef != "evidence-new" || !instance.OfflineVerificationReady {
		t.Fatalf("runtime instance = %+v, want substrate runtime, latest evidence, offline ready", instance)
	}
	if instance.LocalVerificationStatus != "available" || instance.RuntimeHandles["container_id"] != "container-1" || instance.RuntimeHandles["bucket"] != "bucket-1" {
		t.Fatalf("runtime verification/handles = status:%q handles:%#v", instance.LocalVerificationStatus, instance.RuntimeHandles)
	}
	if !contains(instance.ActiveGrants, "sandbox-ref") || !contains(instance.Receipts, "launch-ref") {
		t.Fatalf("runtime grants/receipts = grants:%#v receipts:%#v", instance.ActiveGrants, instance.Receipts)
	}
	if instance.SandboxGrant.ProofStatus != "proven" || instance.SandboxGrant.FilesystemPreopens[0] != "unproven" {
		t.Fatalf("runtime sandbox from run = %+v, want proven unproven-policy placeholder", instance.SandboxGrant)
	}

	empty := RuntimeFromRun(session.LaunchRun{LaunchID: "empty"})
	if empty.Runtime != "local-container" || empty.LocalVerificationStatus != "unavailable" || len(empty.EvidencePackRefs) != 0 {
		t.Fatalf("empty runtime instance = %+v, want defaults", empty)
	}

	app := testApp("sandbox")
	substrate := registry.SubstrateSpec{ID: "wasmtime", Kind: "wasm"}
	grant := SandboxGrant(app, substrate, run)
	if grant.BackendProfile != "wasmtime" || grant.Runtime != "wasm" || grant.ImageDigest != "sha256:sandbox" {
		t.Fatalf("sandbox grant = %+v, want app/substrate overrides", grant)
	}
	if !contains(grant.FilesystemPreopens, "/workspace/sandbox") || !contains(grant.NetworkPolicy, "api.sandbox.example") || !contains(grant.Env, "MODEL_API_KEY") {
		t.Fatalf("sandbox policy projection = %+v", grant)
	}

	fallback := SandboxGrant(registry.AppSpec{}, registry.SubstrateSpec{}, session.LaunchRun{LaunchID: "run-empty", PlanHash: "plan-empty", ArtifactDigest: "sha256:run"})
	if fallback.BackendProfile != "local-container" || fallback.Runtime != "local-container" || fallback.FilesystemPreopens[0] != "deny-by-default" {
		t.Fatalf("fallback sandbox = %+v, want deny-by-default local container", fallback)
	}
	if fallback.NetworkPolicy[0] != "default-deny" || fallback.Env[0] != "none" || !strings.HasPrefix(fallback.GrantHash, "sha256:") || fallback.ProofStatus != "unproven" {
		t.Fatalf("fallback sandbox policy/hash = %+v", fallback)
	}

	detail := Detail(app, substrate, plan.LaunchPlan{KernelVerdict: "ALLOW", Status: string(session.StateRunning)}, run)
	if detail.Run.LaunchID != run.LaunchID || len(detail.Gates) == 0 || len(detail.Events) == 0 || detail.Instance.SandboxGrant.Runtime != "wasm" {
		t.Fatalf("detail = %+v, want run, gates, events, substrate sandbox runtime", detail)
	}
}

func TestMCPThreatReviews(t *testing.T) {
	if got := MCPThreatReviews(nil, nil); len(got) != 0 {
		t.Fatalf("nil catalog returned %d reviews, want 0", len(got))
	}

	noPolicy := testApp("plain")
	noPolicy.MCPPolicy = registry.MCPPolicy{}
	mcpApp := testApp("mcp")
	reviews := MCPThreatReviews(&registry.Catalog{Apps: []registry.AppSpec{noPolicy, mcpApp}}, []session.LaunchRun{
		{AppID: "mcp", MCPRefs: []string{"mcp-ref"}},
		{AppID: "mcp", MCPRefs: []string{"ignored-later-ref"}},
	})
	if len(reviews) != 2 {
		t.Fatalf("reviews length = %d, want 2", len(reviews))
	}
	if reviews[0].State != "unproven" || reviews[0].ProofStatus != "unproven" {
		t.Fatalf("no-policy review = %+v, want unproven", reviews[0])
	}
	if reviews[1].State != "quarantined" || reviews[1].ProofStatus != "proven" || reviews[1].Publisher != "https://example.test/mcp" {
		t.Fatalf("mcp review = %+v, want proven quarantined review with metadata", reviews[1])
	}
	if len(reviews[1].FixActions) != 1 || !strings.Contains(reviews[1].CLIEquivalent, "mcp-mcp") {
		t.Fatalf("mcp review actions = %+v cli=%q", reviews[1].FixActions, reviews[1].CLIEquivalent)
	}
}

func TestPolicySimulationForApp(t *testing.T) {
	app := testApp("policy")
	allow := PolicySimulationForApp(app, plan.LaunchPlan{
		KernelVerdict: "ALLOW",
		PlanHash:      "plan-hash",
		PolicyHash:    "policy-hash",
	})
	if allow.Verdict != "ALLOW" || allow.ProofStatus != "proven" || !strings.Contains(allow.PlainEnglish, "deny-by-default") {
		t.Fatalf("allow simulation = %+v, want proven allow summary", allow)
	}
	if allow.Structured["mcp"] != app.MCPPolicy || allow.Raw["policy_hash"] != "policy-hash" {
		t.Fatalf("allow simulation structured/raw = structured:%#v raw:%#v", allow.Structured, allow.Raw)
	}

	blocked := PolicySimulationForApp(app, plan.LaunchPlan{
		KernelVerdict: "DENY",
		ReasonCode:    "ERR_LAUNCHPAD_REQUIRED_SECRET_MISSING",
	})
	if blocked.ProofStatus != "unproven" || !strings.Contains(blocked.PlainEnglish, "blocked until required secret") {
		t.Fatalf("blocked simulation = %+v, want missing-secret explanation and unproven proof", blocked)
	}
}

func TestSecretGrantStatuses(t *testing.T) {
	statuses := SecretGrantStatuses([]secrets.Status{
		{Name: "present", Provider: "env", ValueEnv: "PRESENT", Available: true},
		{Name: "missing", Provider: "env", ValueEnv: "MISSING", Available: false},
	})
	if len(statuses) != 2 {
		t.Fatalf("SecretGrantStatuses returned %d statuses, want 2", len(statuses))
	}
	if statuses[0].LaunchImpact != "allows launch after preflight" || !strings.HasPrefix(statuses[0].GrantHash, "sha256:") {
		t.Fatalf("present status = %+v, want allow impact and hash", statuses[0])
	}
	if statuses[1].LaunchImpact != "blocks launch" {
		t.Fatalf("missing status = %+v, want block impact", statuses[1])
	}
}

func TestReadmodelHelpers(t *testing.T) {
	app := testApp("helpers")
	if got := appStatus(app, nil, "evidence"); got.State != "ready" || !got.OfflineVerifiable {
		t.Fatalf("ready app status = %+v", got)
	}
	if got := appStatus(app, []string{"MODEL_API_KEY"}, ""); got.State != "needs_secret" {
		t.Fatalf("missing secret app status = %+v, want needs_secret", got)
	}
	unverified := app
	unverified.Availability = registry.AvailabilityBlockedConformance
	if got := appStatus(unverified, nil, ""); got.State != "verification_failed" {
		t.Fatalf("unverified app status = %+v, want verification_failed", got)
	}

	noExtras := app
	noExtras.NetworkPolicy.Allowlist = nil
	noExtras.MCPPolicy.UnknownServerPolicy = ""
	if got := declaredCapabilities(noExtras); len(got) != 3 || contains(got, "scoped-network-egress") || contains(got, "mcp-firewall") {
		t.Fatalf("base capabilities = %#v, want base-only capabilities", got)
	}
	if server := mcpServers(app)[0]; server.ID != "helpers-mcp" || server.UnknownToolPolicy != "deny" {
		t.Fatalf("mcp server helper = %+v", server)
	}
	envMissingApp := app
	envMissingApp.ModelGatewayEnv = []string{"UNBOUND_MODEL_KEY"}
	envMissingApp.RequiredSecrets = []string{"unbound-logical"}
	if got := missingSecrets(envMissingApp, nil); len(got) != 1 || got[0] != "UNBOUND_MODEL_KEY" {
		t.Fatalf("missingSecrets with unbound model env = %#v, want UNBOUND_MODEL_KEY", got)
	}

	policyGate := gate("policy.evaluate", "Policy", "Apply", "ALLOW", "", "proven", "summary", []string{" receipt ", "receipt", ""}, []string{" evidence "})
	if policyGate.RawDetailRef != "policy_evaluate.json" || len(policyGate.FixActions) != 1 || len(policyGate.ReceiptRefs) != 1 || len(policyGate.EvidenceRefs) != 1 {
		t.Fatalf("policy gate = %+v, want normalized refs and policy fix action", policyGate)
	}
	secretEvent := event(session.LaunchRun{LaunchID: "run-helper", EvidencePackRefs: []string{"evidence"}}, "secret_stage", "Secret", "ESCALATE", "ERR_REQUIRED_SECRET_MISSING", "unproven", "summary", "", "")
	if secretEvent.CLIEquivalent != "helm-ai-kernel secret set <name>" || len(secretEvent.FixActions) != 1 {
		t.Fatalf("secret event = %+v, want secret CLI and fix action", secretEvent)
	}

	if verdictFor(true) != "ALLOW" || verdictFor(false) != "ESCALATE" {
		t.Fatalf("verdictFor returned unexpected values")
	}
	if verdictFromRefs([]string{"", " ref "}) != "ALLOW" || verdictFromRefs(nil) != "ESCALATE" {
		t.Fatalf("verdictFromRefs returned unexpected values")
	}
	if proofFromRefs([]string{"ref"}) != "proven" || proofFromRefs([]string{" "}) != "unproven" || proofFromBool(true) != "proven" || proofFromBool(false) != "unproven" {
		t.Fatalf("proof helpers returned unexpected values")
	}
	if first(nil) != "" || first([]string{"a", "b"}) != "a" {
		t.Fatalf("first helper returned unexpected values")
	}
	if got := refsWithPrefix([]string{"secret-1", "sandbox-1", "my-secret-2"}, "secret"); len(got) != 2 {
		t.Fatalf("refsWithPrefix = %#v, want 2 secret refs", got)
	}

	if verdict, reason, _ := mcpQuarantineState(plan.LaunchPlan{}, nil); verdict != "ALLOW" || reason != "" {
		t.Fatalf("mcp state without policy = verdict:%q reason:%q, want allow", verdict, reason)
	}
	if actions := fixActionsFor("ERR_MCP_SERVER_QUARANTINED", "mcp"); len(actions) != 1 || !strings.Contains(actions[0].CLI, "mcp quarantine") {
		t.Fatalf("mcp fix actions = %#v", actions)
	}
	if actions := fixActionsFor("", "noop"); actions != nil {
		t.Fatalf("noop fix actions = %#v, want nil", actions)
	}
	if got := cliForGate("teardown.cascade"); got != "helm-ai-kernel teardown <run_id> --cascade" {
		t.Fatalf("cliForGate teardown = %q", got)
	}

	run := session.LaunchRun{LaunchID: "run-cli", SubstrateID: "runtime"}
	for stage, want := range map[string]string{
		"secret_grant":    "helm-ai-kernel secret set <name>",
		"sandbox_grant":   "helm-ai-kernel sandbox inspect run-cli",
		"mcp_quarantine":  "helm-ai-kernel mcp quarantine",
		"evidence_export": "helm-ai-kernel evidence export run-cli",
		"teardown_done":   "helm-ai-kernel teardown run-cli --cascade",
		"receipt_written": "helm-ai-kernel run receipts run-cli",
		"other":           "helm-ai-kernel run open run-cli",
	} {
		if got := cliForEvent(run, stage); got != want {
			t.Fatalf("cliForEvent(%q) = %q, want %q", stage, got, want)
		}
	}
	if cliForEvent(session.LaunchRun{}, "other") != "helm-ai-kernel run open <run_id>" {
		t.Fatalf("cliForEvent without launch id did not use placeholder")
	}
	if runRefs(nil, "sandbox") != nil || runRefs(&session.LaunchRun{}, "unknown") != nil {
		t.Fatalf("runRefs nil/unknown returned non-nil")
	}
	if got := rawRefForGate("a.b.c"); got != "a_b_c.json" {
		t.Fatalf("rawRefForGate = %q, want a_b_c.json", got)
	}
	if stableHash("a", "b") == stableHash("a", "c") || !strings.HasPrefix(stableHash("a"), "sha256:") {
		t.Fatalf("stableHash returned unexpected values")
	}
	if firstNonEmptyString("", "fallback") != "fallback" || firstNonEmptyString("", "") != "" {
		t.Fatalf("firstNonEmptyString returned unexpected values")
	}
	if runtimeName(session.LaunchRun{}) != "local-container" || runtimeName(run) != "runtime" {
		t.Fatalf("runtimeName returned unexpected values")
	}
	if verificationStatus(session.LaunchRun{}) != "unavailable" || verificationStatus(session.LaunchRun{VerificationCommand: "verify"}) != "available" {
		t.Fatalf("verificationStatus returned unexpected values")
	}
	if impactForSecret(true) != "allows launch after preflight" || impactForSecret(false) != "blocks launch" {
		t.Fatalf("impactForSecret returned unexpected values")
	}
	if len(cloneStrings(nil)) != 0 {
		t.Fatalf("cloneStrings(nil) returned non-empty slice")
	}
	original := []string{"one"}
	cloned := cloneStrings(original)
	cloned[0] = "two"
	if original[0] != "one" {
		t.Fatalf("cloneStrings aliased input slice")
	}
	if got := compactStrings([]string{" one ", "", "one", "two"}); len(got) != 2 || got[0] != "one" || got[1] != "two" {
		t.Fatalf("compactStrings = %#v, want normalized unique values", got)
	}
}

func testApp(id string) registry.AppSpec {
	return registry.AppSpec{
		ID:             id,
		Name:           "App " + id,
		Version:        "1.0.0",
		Redistribution: "allowed",
		Availability:   registry.AvailabilityOSSSupported,
		Install: registry.InstallSpec{
			Strategy: "oci",
			Image:    "ghcr.io/example/" + id + ":1.0.0",
			Digest:   "sha256:" + id,
			Source:   "https://example.test/" + id,
		},
		ModelGatewayEnv: []string{"MODEL_API_KEY"},
		RequiredSecrets: []string{"model-key"},
		FilesystemPolicy: registry.PolicyRef{
			Mounts:    []string{"/workspace/" + id},
			PolicyRef: "policy://" + id,
		},
		NetworkPolicy: registry.NetworkPolicy{
			Default:   "deny",
			Allowlist: []string{"api." + id + ".example"},
		},
		MCPPolicy: registry.MCPPolicy{
			UnknownServerPolicy: "quarantine",
			UnknownToolPolicy:   "deny",
			RequireSchemaPin:    true,
		},
		Healthchecks:         []registry.HealthcheckSpec{{Type: "http", URL: "http://localhost:8080/healthz"}},
		RiskClass:            "medium",
		EvidenceRequirements: []string{"signature", "sbom", "vuln-scan"},
		SupplyChainEvidence: registry.SupplyChainEvidenceSpec{
			SignatureRef: "signature://" + id,
		},
		Conformance: verifiedConformance(),
		Metadata:    map[string]string{"upstream_repo": "https://example.test/" + id},
	}
}

func verifiedConformance() registry.ConformanceSpec {
	return registry.ConformanceSpec{
		LicenseVerified:      true,
		ArtifactVerified:     true,
		PolicyPackPresent:    true,
		SandboxVerified:      true,
		HealthcheckPassing:   true,
		E2EPassing:           true,
		TeardownVerified:     true,
		ReceiptVerified:      true,
		EvidencePackVerified: true,
	}
}

func fullRun() session.LaunchRun {
	return session.LaunchRun{
		LaunchID:            "run-1",
		AppID:               "launchpad",
		SubstrateID:         "local-docker",
		PlanHash:            "plan-hash",
		ArtifactDigest:      "sha256:artifact",
		State:               session.StateRunning,
		KernelVerdict:       "ALLOW",
		BoundaryRecordRefs:  []string{"boundary-ref"},
		CPIRefs:             []string{"cpi-ref"},
		SandboxGrantRefs:    []string{"sandbox-ref", "sandbox-ref"},
		EgressReceiptRefs:   []string{"egress-ref"},
		MCPRefs:             []string{"mcp-ref"},
		SecretGrantRefs:     []string{"secret-ref", " secret-ref ", ""},
		InstallReceiptRefs:  []string{"install-ref"},
		LaunchReceiptRefs:   []string{"launch-ref"},
		StartReceiptRefs:    []string{"start-ref"},
		HealthcheckRefs:     []string{"health-ref"},
		TeardownReceiptRefs: []string{"teardown-ref"},
		EvidencePackRefs:    []string{"evidence-old", "evidence-new"},
		RuntimeHandles: session.RuntimeHandles{
			ContainerID:       "container-1",
			EgressNetworkName: "egress-net",
			EgressProxyID:     "proxy-1",
			CloudResourceIDs:  map[string]string{"bucket": "bucket-1"},
		},
		VerificationCommand: "helm-ai-kernel verify evidence-new",
		TeardownCommand:     "helm-ai-kernel teardown run-1 --cascade",
	}
}

func gateByID(t *testing.T, gates []GateResult, id string) GateResult {
	t.Helper()
	for _, gate := range gates {
		if gate.ID == id {
			return gate
		}
	}
	t.Fatalf("gate %q not found in %#v", id, gates)
	return GateResult{}
}

func eventByStage(t *testing.T, events []RunEvent, stage string) RunEvent {
	t.Helper()
	for _, event := range events {
		if event.Stage == stage {
			return event
		}
	}
	t.Fatalf("event stage %q not found in %#v", stage, events)
	return RunEvent{}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
