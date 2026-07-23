package contracts_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

type launchInputFixture struct {
	effectID  string
	schema    string
	input     map[string]any
	goldenKey string
}

func TestLaunchMissionEffectCatalogPreviewIsExplicitlyNonExecutable(t *testing.T) {
	catalog := contracts.LaunchMissionEffectCatalogPreview()
	if catalog.CatalogVersion != contracts.LaunchEffectCatalogVersion {
		t.Fatalf("catalog version = %q, want %q", catalog.CatalogVersion, contracts.LaunchEffectCatalogVersion)
	}
	if len(catalog.EffectTypes) != 6 {
		t.Fatalf("preview effect count = %d, want 6", len(catalog.EffectTypes))
	}

	seen := make(map[string]bool, len(catalog.EffectTypes))
	for _, effect := range catalog.EffectTypes {
		if seen[effect.TypeID] {
			t.Fatalf("duplicate preview effect %s", effect.TypeID)
		}
		seen[effect.TypeID] = true
		if effect.Status != contracts.LaunchEffectStatusPreview {
			t.Errorf("%s status = %q, want preview", effect.TypeID, effect.Status)
		}
		if effect.Taxon != contracts.EffectRiskClass(effect.TypeID) {
			t.Errorf("%s taxon = %q, risk class = %q", effect.TypeID, effect.Taxon, contracts.EffectRiskClass(effect.TypeID))
		}
		if len(effect.BaseEffectTypes) == 0 {
			t.Errorf("%s has no mandatory base-effect expansion", effect.TypeID)
		}
		if !effect.PreflightRequired || !effect.TwoPhaseCommitRequired {
			t.Errorf("%s must require preflight and two-phase commit", effect.TypeID)
		}
		if effect.InputSchema == "" || effect.AuthorizationEnvelopeSchema == "" || effect.ReceiptSchema == "" || effect.ConnectorID == "" || effect.ActionURN == "" {
			t.Errorf("%s is missing input, authorization, receipt, connector, or action binding", effect.TypeID)
		}
		if effect.CompensationRequired && effect.CompensationEffectType == "" {
			t.Errorf("%s requires compensation but has no executable mapping", effect.TypeID)
		}
		if contracts.LookupEffectType(effect.TypeID) != nil {
			t.Errorf("preview effect %s leaked into executable DefaultEffectCatalog", effect.TypeID)
		}
	}

	defaultCatalog := contracts.DefaultEffectCatalog()
	if len(defaultCatalog.EffectTypes) != 21 || defaultCatalog.CatalogVersion != "1.0.0" {
		t.Fatalf("default runtime catalog changed during preview: version=%s count=%d", defaultCatalog.CatalogVersion, len(defaultCatalog.EffectTypes))
	}
	provision := contracts.LookupLaunchMissionEffectPreview(contracts.EffectTypeProviderProvision)
	if provision.CompensationRequired || provision.CompensationAuthorization != "fresh_dual_control_only_no_preauthorization" {
		t.Fatal("provider failure cleanup must freeze for fresh dual-control teardown, never carry deletion preauthorization")
	}
}

func TestEffectCatalogWireSchemaAcceptsRuntimeAndPreviewCatalogs(t *testing.T) {
	schema := compileSchema(t, "effects/effect_type_catalog.schema.json")
	for name, catalog := range map[string]*contracts.EffectTypeCatalog{
		"runtime": contracts.DefaultEffectCatalog(),
		"preview": contracts.LaunchMissionEffectCatalogPreview(),
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateAgainstSchema(t, schema, catalog); err != nil {
				t.Fatalf("%s catalog does not match wire schema: %v", name, err)
			}
		})
	}
}

func TestLaunchEffectPreviewIsRejectedByEveryProductionConsumerSchema(t *testing.T) {
	h := launchHash("a")
	tests := []struct {
		name       string
		schemaPath string
		valid      map[string]any
		setEffect  func(map[string]any, string)
	}{
		{
			name:       "pdp request",
			schemaPath: "policy/pdp_request.schema.json",
			valid: map[string]any{
				"request_id": "550e8400-e29b-41d4-a716-446655440000",
				"effect": map[string]any{
					"effect_id": "effect-1", "effect_type": "DATA_WRITE", "effect_payload_hash": h, "idempotency_key": "idempotency-1",
				},
				"subject": map[string]any{
					"actor_id": "actor-1", "actor_type": "agent", "auth_context": map[string]any{},
				},
				"context": map[string]any{
					"mode_id": "mode-1", "jurisdiction": "EU", "environment_snapshot_hash": h, "phenotype_hash": h,
					"time": map[string]any{"decision_time_source": "observed_at", "timestamp": "2026-07-18T12:00:00Z"},
				},
				"obligations_context": map[string]any{},
			},
			setEffect: func(value map[string]any, effect string) {
				value["effect"].(map[string]any)["effect_type"] = effect
			},
		},
		{
			name:       "policy input bundle",
			schemaPath: "policy/policy_input_bundle.v1.schema.json",
			valid: map[string]any{
				"request_id": "request-1", "effect_type": "DATA_WRITE", "principal": "agent-1", "target": "resource-1", "payload": map[string]any{},
			},
			setEffect: func(value map[string]any, effect string) { value["effect_type"] = effect },
		},
		{
			name:       "kernel effect boundary",
			schemaPath: "kernel/effect_boundary.schema.json",
			valid: map[string]any{
				"effect_id": "550e8400-e29b-41d4-a716-446655440000", "effect_type": "DATA_WRITE", "submitted_at": "2026-07-18T12:00:00Z",
				"subject": map[string]any{"subject_id": "agent-1", "subject_type": "module"},
				"payload": map[string]any{"payload_hash": h},
			},
			setEffect: func(value map[string]any, effect string) { value["effect_type"] = effect },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			schema := compileSchema(t, test.schemaPath)
			if err := schema.Validate(test.valid); err != nil {
				t.Fatalf("control fixture is invalid: %v", err)
			}
			for _, effect := range contracts.LaunchMissionEffectCatalogPreview().EffectTypes {
				candidate := cloneLaunchInput(t, test.valid)
				test.setEffect(candidate, effect.TypeID)
				if err := schema.Validate(candidate); err == nil {
					t.Errorf("preview effect %s passed %s", effect.TypeID, test.schemaPath)
				}
			}
		})
	}
}

func TestLaunchEffectBaseEffectsExistInRegisteredVocabulary(t *testing.T) {
	root := repoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "protocols", "json-schemas", "effects", "effect_type_catalog.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, effect := range contracts.LaunchMissionEffectCatalogPreview().EffectTypes {
		for _, baseEffect := range effect.BaseEffectTypes {
			if !strings.Contains(string(data), `"`+baseEffect+`"`) {
				t.Errorf("preview effect %s expands to unregistered base effect %s", effect.TypeID, baseEffect)
			}
		}
	}
}

func TestLaunchEffectPreviewInputsAndDerivedIdempotencyVectors(t *testing.T) {
	for _, fixture := range launchInputFixtures() {
		fixture := fixture
		t.Run(fixture.effectID, func(t *testing.T) {
			schema := compileSchema(t, fixture.schema)
			if err := schema.Validate(fixture.input); err != nil {
				t.Fatalf("valid fixture rejected: %v", err)
			}
			if err := contracts.ValidateLaunchEffectInputSemantics(fixture.effectID, fixture.input); err != nil {
				t.Fatalf("semantic validation rejected fixture: %v", err)
			}

			key, err := contracts.DeriveLaunchEffectIdempotencyKey(fixture.effectID, fixture.input)
			if err != nil {
				t.Fatalf("derive key: %v", err)
			}
			if fixture.goldenKey == "" {
				t.Fatal("fixture is missing a committed golden idempotency vector")
			}
			if key != fixture.goldenKey {
				t.Fatalf("key = %s, want golden %s", key, fixture.goldenKey)
			}
			if err := contracts.ValidateLaunchEffectIdempotencyKey(fixture.effectID, fixture.input, key); err != nil {
				t.Fatalf("derived key rejected: %v", err)
			}
			if err := contracts.ValidateLaunchEffectIdempotencyKey(fixture.effectID, fixture.input, "sha256:"+strings.Repeat("0", 64)); err == nil {
				t.Fatal("arbitrary caller-provided idempotency key was accepted")
			}

			missingPlan := cloneLaunchInput(t, fixture.input)
			delete(missingPlan, "plan_hash")
			if err := schema.Validate(missingPlan); err == nil {
				t.Fatal("fixture without plan_hash unexpectedly validated")
			}

			mutated := cloneLaunchInput(t, fixture.input)
			mutated["effect_ordinal"] = mutated["effect_ordinal"].(int) + 1
			mutatedKey, err := contracts.DeriveLaunchEffectIdempotencyKey(fixture.effectID, mutated)
			if err != nil {
				t.Fatalf("derive mutated key: %v", err)
			}
			if mutatedKey == key {
				t.Fatal("authority-relevant mutation did not change idempotency key")
			}
		})
	}
}

func TestLaunchEffectIdempotencyNormalizesCrossLanguageIntegerSpellings(t *testing.T) {
	fixture := launchInputFixtures()[0]
	baseline, err := contracts.DeriveLaunchEffectIdempotencyKey(fixture.effectID, fixture.input)
	if err != nil {
		t.Fatal(err)
	}
	equivalent := cloneLaunchInput(t, fixture.input)
	equivalent["effect_ordinal"] = json.Number("1.0")
	got, err := contracts.DeriveLaunchEffectIdempotencyKey(fixture.effectID, equivalent)
	if err != nil {
		t.Fatalf("equivalent JSON integer spelling was rejected: %v", err)
	}
	if got != baseline {
		t.Fatalf("equivalent integer spellings produced different keys: %s != %s", got, baseline)
	}
	if err := contracts.ValidateLaunchEffectInputSemantics(fixture.effectID, equivalent); err != nil {
		t.Fatalf("equivalent JSON integer spelling failed semantic validation: %v", err)
	}

	fractional := cloneLaunchInput(t, fixture.input)
	fractional["effect_ordinal"] = json.Number("1.5")
	if _, err := contracts.DeriveLaunchEffectIdempotencyKey(fixture.effectID, fractional); err == nil {
		t.Fatal("fractional launch input number was hashed as an integer contract")
	}
	unsafe := cloneLaunchInput(t, fixture.input)
	unsafe["effect_ordinal"] = json.Number("9007199254740992")
	if _, err := contracts.DeriveLaunchEffectIdempotencyKey(fixture.effectID, unsafe); err == nil {
		t.Fatal("cross-language unsafe integer was accepted into an authority hash")
	}
	precisionLoss := cloneLaunchInput(t, fixture.input)
	precisionLoss["effect_ordinal"] = json.Number("9007199254740991.1")
	if _, err := contracts.DeriveLaunchEffectIdempotencyKey(fixture.effectID, precisionLoss); err == nil {
		t.Fatal("fractional JSON number was rounded into a safe authority integer")
	}
}

func TestLaunchEffectPreviewRejectsStandingAuthorityAndUnverifiedCredit(t *testing.T) {
	fixtures := launchInputFixtures()
	activation := cloneLaunchInput(t, fixtures[1].input)
	activation["enable_autodeploy"] = true
	if err := compileSchema(t, fixtures[1].schema).Validate(activation); err == nil {
		t.Fatal("production activation accepted deployment-on-push standing authority")
	}
	if err := contracts.ValidateLaunchEffectInputSemantics(contracts.EffectTypeDeployProductionActivate, activation); err == nil {
		t.Fatal("semantic validator accepted deployment-on-push standing authority")
	}

	customDomain := cloneLaunchInput(t, fixtures[1].input)
	customDomain["primary_endpoint"] = "https://launch.example.com"
	if err := contracts.ValidateLaunchEffectInputSemantics(contracts.EffectTypeDeployProductionActivate, customDomain); err != nil {
		t.Fatalf("provider-neutral semantic validator rejected a valid HTTPS endpoint: %v", err)
	}
	nonEUActivation := cloneLaunchInput(t, fixtures[1].input)
	nonEUActivation["region"] = "nyc"
	nonEUActivation["jurisdiction"] = "US"
	if err := contracts.ValidateLaunchEffectInputSemantics(contracts.EffectTypeDeployProductionActivate, nonEUActivation); err != nil {
		t.Fatalf("provider-neutral semantic validator hard-coded an EU region: %v", err)
	}

	provision := cloneLaunchInput(t, fixtures[0].input)
	provision["preauthorized_teardown_permit_ref"] = "forbidden-delete-permit"
	if err := compileSchema(t, fixtures[0].schema).Validate(provision); err == nil {
		t.Fatal("provider provision accepted preauthorized deletion authority")
	}
	if err := contracts.ValidateLaunchEffectInputSemantics(contracts.EffectTypeProviderProvision, provision); err == nil {
		t.Fatal("semantic validator accepted preauthorized deletion authority")
	}

	for _, fixture := range []launchInputFixture{fixtures[0], fixtures[3], fixtures[4]} {
		nonEU := cloneLaunchInput(t, fixture.input)
		nonEU["region"], nonEU["jurisdiction"] = "nyc", "US"
		if err := contracts.ValidateLaunchEffectInputSemantics(fixture.effectID, nonEU); err != nil {
			t.Errorf("%s hard-coded an EU route: %v", fixture.effectID, err)
		}
	}

	provisionOverCap := cloneLaunchInput(t, fixtures[0].input)
	provisionOverCap["gross_exposure_minor"] = 1201
	if err := contracts.ValidateLaunchEffectInputSemantics(contracts.EffectTypeProviderProvision, provisionOverCap); err == nil {
		t.Fatal("provider provision exposure above its gross cap was accepted")
	}

	spend := cloneLaunchInput(t, fixtures[2].input)
	spend["credit_status"] = "UNKNOWN"
	if err := compileSchema(t, fixtures[2].schema).Validate(spend); err != nil {
		t.Fatalf("schema should leave cross-field credit proof to semantic validator: %v", err)
	}
	if err := contracts.ValidateLaunchEffectInputSemantics(contracts.EffectTypeSpendAuthorize, spend); err == nil {
		t.Fatal("unverified credit was allowed to reduce expected cash cost")
	}

	overCap := cloneLaunchInput(t, fixtures[2].input)
	overCap["gross_cap_minor"] = 6000
	overCap["gross_exposure_minor"] = 6000
	overCap["base_provider_cost_minor"] = 5850
	overCap["expected_cash_minor"] = 5750
	if err := compileSchema(t, fixtures[2].schema).Validate(overCap); err != nil {
		t.Fatalf("provider-neutral spend schema hard-coded the original EUR 50 mission cap: %v", err)
	}
	if err := contracts.ValidateLaunchEffectInputSemantics(contracts.EffectTypeSpendAuthorize, overCap); err != nil {
		t.Fatalf("provider-neutral spend semantics rejected internally consistent mission values: %v", err)
	}
	for name, mutation := range map[string]map[string]any{
		"cash above gross":   {"expected_cash_minor": 1201},
		"credit above cost":  {"verified_credit_minor": 1051},
		"bad gross equation": {"gross_exposure_minor": 1199},
		"bad cash equation":  {"expected_cash_minor": 949},
		"overlong authority": {"expires_at": "2026-08-19T01:00:01Z"},
	} {
		candidate := cloneLaunchInput(t, fixtures[2].input)
		for key, value := range mutation {
			candidate[key] = value
		}
		if err := contracts.ValidateLaunchEffectInputSemantics(contracts.EffectTypeSpendAuthorize, candidate); err == nil {
			t.Errorf("accepted invalid spend case %q", name)
		}
	}
}

func TestLaunchActivationAndCompensationRepresentStatefulResourcesWithoutDeploymentFields(t *testing.T) {
	fixtures := launchInputFixtures()
	activation := cloneLaunchInput(t, fixtures[1].input)
	activation["activation_class"] = contracts.LaunchTransitionResourceState
	activation["exposure_kind"] = "DATA"
	activation["compensation_class"] = contracts.LaunchCompensationResourceRestore
	for _, field := range []string{"primary_endpoint", "tls_evidence_hash", "deployment_id", "source_commit_sha", "immutable_artifact_digest", "release_manifest_ref", "release_manifest_hash", "provenance_ref", "provenance_hash"} {
		delete(activation, field)
	}
	if err := compileSchema(t, fixtures[1].schema).Validate(activation); err != nil {
		t.Fatalf("stateful resource activation still requires deployment artifacts: %v", err)
	}
	if err := contracts.ValidateLaunchEffectInputSemantics(contracts.EffectTypeDeployProductionActivate, activation); err != nil {
		t.Fatalf("stateful resource activation failed semantic validation: %v", err)
	}
	activation["deployment_id"] = "forbidden-release-field"
	if err := compileSchema(t, fixtures[1].schema).Validate(activation); err == nil {
		t.Fatal("stateful resource activation accepted a release-only deployment field")
	}

	rollback := cloneLaunchInput(t, fixtures[3].input)
	rollback["compensation_class"] = contracts.LaunchCompensationDataRestore
	rollback["reason"] = "data_integrity_failure"
	for _, field := range []string{"source_deployment_id", "source_artifact_digest", "target_deployment_id", "target_commit_sha", "target_artifact_digest"} {
		delete(rollback, field)
	}
	if err := compileSchema(t, fixtures[3].schema).Validate(rollback); err != nil {
		t.Fatalf("data restore still requires deployment rollback fields: %v", err)
	}
	if err := contracts.ValidateLaunchEffectInputSemantics(contracts.EffectTypeProviderRollback, rollback); err != nil {
		t.Fatalf("data restore failed semantic validation: %v", err)
	}
}

func TestLaunchEffectSchemasAdvertisePreviewOnly(t *testing.T) {
	root := repoRoot(t)
	for _, fixture := range launchInputFixtures() {
		path := filepath.Join(root, "protocols", "json-schemas", filepath.FromSlash(fixture.schema))
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var raw map[string]any
		if err := json.Unmarshal(data, &raw); err != nil {
			t.Fatal(err)
		}
		meta, ok := raw["x-helm"].(map[string]any)
		if !ok || meta["status"] != "preview" || meta["execution_enabled"] != false {
			t.Fatalf("%s does not advertise preview/non-executable status", fixture.schema)
		}
	}
}

func launchInput(effectID string, ordinal int, fields map[string]any) map[string]any {
	input := map[string]any{
		"schema_version": "launch_effect_input.v1",
		"effect_id":      effectID,
		"tenant_id":      "tenant-1",
		"workspace_id":   "workspace-1",
		"mission_id":     "mission-1",
		"effect_ordinal": ordinal,
	}
	for key, value := range fields {
		input[key] = value
	}
	return input
}

func providerLaunchInput(effectID string, ordinal int, fields map[string]any) map[string]any {
	input := launchInput(effectID, ordinal, map[string]any{
		"provider":              "digitalocean",
		"provider_account_ref":  "provider-account-1",
		"provider_account_hash": launchHash("1"),
		"region":                "fra",
		"jurisdiction":          "EU",
	})
	for key, value := range fields {
		input[key] = value
	}
	return input
}

func providerActionLaunchInput(effectID string, ordinal int, actionURN string, fields map[string]any) map[string]any {
	input := providerLaunchInput(effectID, ordinal, map[string]any{
		"workload_graph_ref": "workload-graph-1", "workload_graph_hash": launchHash("2"),
		"route_binding_ref": "route-1", "route_binding_hash": launchHash("3"), "route_placement_id": "placement-1",
		"provider_offering_id":            "app-platform",
		"provider_capability_profile_ref": "do-profile-1", "provider_capability_profile_hash": launchHash("4"),
		"provider_certification_ref": "do-certification-1", "provider_certification_hash": launchHash("5"),
		"provider_connector_id": contracts.LaunchConnectorDigitalOcean, "provider_connector_contract_hash": launchHash("5"),
		"provider_action_urn": actionURN, "provider_destination_hash": launchHash("d"), "provider_payload_hash": launchHash("6"),
		"provision_receipt_ref": "provision-receipt-1", "provision_receipt_hash": launchHash("0"),
		"resource_graph_ref": "resource-graph-1", "resource_graph_hash": launchHash("7"),
	})
	for key, value := range fields {
		input[key] = value
	}
	return input
}

func launchInputFixtures() []launchInputFixture {
	h := launchHash
	return []launchInputFixture{
		{
			effectID:  contracts.EffectTypeProviderProvision,
			schema:    "effects/launch/provider_provision.v1.json",
			goldenKey: "sha256:4d0f9f802ce906ec6cf444457b19aa2afcbb45ff028c3c4bd20930c266be6b2c",
			input: providerLaunchInput(contracts.EffectTypeProviderProvision, 1, map[string]any{
				"repository_analysis_ref": "analysis-1", "repository_analysis_hash": h("0"), "workload_graph_ref": "workload-graph-1", "workload_graph_hash": h("1"),
				"route_binding_ref": "route-1", "route_binding_hash": h("2"), "route_placement_id": "placement-1", "provider_offering_id": "app-platform", "provider_capability_profile_ref": "do-profile-1", "provider_capability_profile_hash": h("3"),
				"provider_certification_ref": "do-certification-1", "provider_certification_hash": h("4"),
				"provider_connector_id": contracts.LaunchConnectorDigitalOcean, "provider_connector_contract_hash": h("4"), "provider_action_urn": contracts.LaunchProviderActionDigitalOceanProvision, "provider_destination_hash": h("d"), "provider_payload_hash": h("5"),
				"resource_graph_hash": h("6"),
				"billing_cadence":     "MONTHLY", "commitment_term": "MONTH_TO_MONTH", "gross_cap_currency": "EUR", "gross_cap_minor": 1200, "gross_exposure_minor": 1200,
				"generated_spec_hash": h("7"), "route_quote_ref": "route-quote-1", "route_quote_hash": h("8"), "constraint_set_hash": h("9"),
				"spend_intent_hash": h("a"), "spend_envelope_hash": h("b"), "budget_verdict_receipt_hash": h("c"),
				"budget_reservation_ref": "budget-reservation-1", "budget_reservation_hash": h("8"), "provider_terms_profile_hash": h("9"),
				"compensation_graph_hash": h("a"), "failure_teardown_policy_hash": h("b"), "teardown_authority_mode": "FRESH_DUAL_CONTROL_REQUIRED",
				"plan_hash": h("c"), "connector_contract_hash": h("d"),
			}),
		},
		{
			effectID:  contracts.EffectTypeDeployProductionActivate,
			schema:    "effects/launch/deploy_production_activate.v1.json",
			goldenKey: "sha256:503807511de64e5e0584d5d42b534b1b540eb48033e1f9f56fb41ecd21b49a1d",
			input: providerActionLaunchInput(contracts.EffectTypeDeployProductionActivate, 2, contracts.LaunchProviderActionDigitalOceanActivate, map[string]any{
				"activation_class": contracts.LaunchTransitionReleaseCutover, "exposure_kind": "ENDPOINT",
				"source_state_ref": "deployment-state-1", "source_state_hash": h("3"), "target_state_ref": "deployment-state-2", "target_state_hash": h("4"),
				"transition_plan_ref": "transition-plan-1", "transition_plan_hash": h("5"), "verification_plan_hash": h("6"), "activation_evidence_hash": h("b"),
				"compensation_class": contracts.LaunchCompensationReleaseRollback, "compensation_target_ref": "deployment-state-1", "compensation_target_hash": h("d"), "compensation_plan_hash": h("c"),
				"promotion_permit_ref": "promotion-permit-1", "promotion_permit_hash": h("8"),
				"endpoint_set_hash": h("8"), "primary_endpoint": "https://mission-1.ondigitalocean.app", "health_evidence_hash": h("9"), "tls_evidence_hash": h("a"),
				"deployment_id": "deployment-2", "source_commit_sha": strings.Repeat("a", 40), "immutable_artifact_digest": h("2"),
				"release_manifest_ref": "release-manifest-1", "release_manifest_hash": h("6"), "provenance_ref": "provenance-1", "provenance_hash": h("7"),
				"rollback_authorization_mode": "PREAUTHORIZED_EXACT_TARGET", "rollback_permit_ref": "rollback-permit-1", "rollback_permit_hash": h("e"),
				"rollback_permit_expiry": "2026-07-19T01:05:00Z",
				"plan_hash":              h("f"), "connector_contract_hash": h("1"),
			}),
		},
		{
			effectID:  contracts.EffectTypeSpendAuthorize,
			schema:    "effects/launch/spend_authorize.v1.json",
			goldenKey: "sha256:47472ae4fc905eb20b1fbb3858b6fef6d189aee269bc43d8cfaf66d0d4113553",
			input: launchInput(contracts.EffectTypeSpendAuthorize, 0, map[string]any{
				"provider": "digitalocean", "provider_account_ref": "provider-account-1", "provider_account_hash": h("1"),
				"workload_graph_ref": "workload-graph-1", "workload_graph_hash": h("0"), "route_binding_ref": "route-1", "route_binding_hash": h("1"), "route_placement_id": "placement-1",
				"provider_capability_profile_ref": "do-profile-1", "provider_capability_profile_hash": h("2"), "provider_certification_ref": "do-certification-1", "provider_certification_hash": h("3"),
				"currency": "EUR", "gross_cap_minor": 1200, "base_provider_cost_minor": 1050, "gross_exposure_minor": 1200,
				"expected_cash_minor": 950, "verified_credit_minor": 250,
				"credit_status": "ACTIVE_CREDIT_VERIFIED", "tax_fx_reserve_minor": 150, "billing_cadence": "MONTHLY", "commitment_term": "MONTH_TO_MONTH",
				"recurring_exposure": true, "authorization_horizon_months": 1, "provider_service_renews": true, "helm_auto_renews_authority": false,
				"quote_hash": h("2"), "price_snapshot_hash": h("3"), "credit_snapshot_hash": h("4"), "fx_snapshot_hash": h("5"), "tax_snapshot_hash": h("6"),
				"spend_intent_hash": h("7"), "spend_envelope_hash": h("8"), "budget_verdict_receipt_hash": h("9"),
				"budget_reservation_ref": "budget-reservation-1", "budget_reservation_hash": h("a"), "provider_terms_profile_hash": h("b"),
				"constraint_set_hash": h("c"), "plan_hash": h("d"), "connector_contract_hash": h("e"), "authorized_at": "2026-07-19T01:00:00Z", "expires_at": "2026-07-19T01:05:00Z",
			}),
		},
		{
			effectID:  contracts.EffectTypeProviderRollback,
			schema:    "effects/launch/provider_rollback.v1.json",
			goldenKey: "sha256:316a4cd6253bacbb3a61bb29dd8d283a0f743f9ecd10260e0e435db9b0036701",
			input: providerActionLaunchInput(contracts.EffectTypeProviderRollback, 3, contracts.LaunchProviderActionDigitalOceanRollback, map[string]any{
				"origin_activation_receipt_ref": "activation-receipt-1", "origin_activation_receipt_hash": h("f"), "resource_ownership_hash": h("2"),
				"compensation_class": contracts.LaunchCompensationReleaseRollback, "source_state_ref": "deployment-state-2", "source_state_hash": h("4"), "target_state_ref": "deployment-state-1", "target_state_hash": h("6"),
				"compensation_plan_ref": "compensation-plan-1", "compensation_plan_hash": h("8"), "verification_plan_hash": h("9"), "target_health_evidence_hash": h("7"),
				"source_deployment_id": "deployment-2", "source_artifact_digest": h("3"), "target_deployment_id": "deployment-1", "target_commit_sha": strings.Repeat("b", 40), "target_artifact_digest": h("5"),
				"rollback_authorization_mode": "PREAUTHORIZED_EXACT_TARGET", "rollback_permit_ref": "rollback-permit-1", "rollback_permit_hash": h("e"), "rollback_permit_expiry": "2026-07-19T01:05:00Z",
				"plan_hash": h("a"), "connector_contract_hash": h("b"), "reason": "health_check_failure",
			}),
		},
		{
			effectID:  contracts.EffectTypeProviderTeardown,
			schema:    "effects/launch/provider_teardown.v1.json",
			goldenKey: "sha256:262e39c8119b6930f4b5f68cab9c9fa06876367c0d577b5724434c375ebb8bcd",
			input: providerActionLaunchInput(contracts.EffectTypeProviderTeardown, 4, contracts.LaunchProviderActionDigitalOceanTeardown, map[string]any{
				"resource_ownership_hash": h("2"), "observed_state_hash": h("3"), "dependency_snapshot_hash": h("4"),
				"resource_empty_evidence_hash": h("5"), "retention_clearance_hash": h("6"), "backup_clearance_hash": h("7"), "billing_exposure_snapshot_hash": h("8"),
				"fresh_teardown_approval_ref": "teardown-approval-1", "fresh_teardown_approval_hash": h("9"), "teardown_plan_hash": h("a"), "expected_deleted_state_hash": h("b"),
				"plan_hash": h("c"), "connector_contract_hash": h("d"),
			}),
		},
		{
			effectID:  contracts.EffectTypeCompanyArtifactUpdate,
			schema:    "effects/launch/company_artifact_update.v1.json",
			goldenKey: "sha256:96a29180140e798be4adb5d6f219fa4a466ee0aca01a12135afc601ea375d591",
			input: launchInput(contracts.EffectTypeCompanyArtifactUpdate, 5, map[string]any{
				"artifact_id": "company-artifact-1", "company_state_version": 7, "previous_hash": h("1"), "new_hash": h("2"),
				"generated_spec_hash": h("3"), "launch_result_hash": h("4"), "reconciliation_receipt_hash": h("5"),
				"source_receipt_ref": "receipt-1", "source_receipt_hash": h("6"), "evidence_pack_ref": "evidencepack-1", "evidence_pack_hash": h("7"), "plan_hash": h("8"),
				"connector_contract_hash": h("9"),
			}),
		},
	}
}

func launchHash(char string) string {
	return "sha256:" + strings.Repeat(char, 64)
}

func cloneLaunchInput(t *testing.T, input map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	var cloned map[string]any
	if err := json.Unmarshal(raw, &cloned); err != nil {
		t.Fatal(err)
	}
	// Preserve integer fixture types for direct mutation checks.
	for key, value := range cloned {
		if number, ok := value.(float64); ok && number == float64(int(number)) {
			cloned[key] = int(number)
		}
	}
	return cloned
}
