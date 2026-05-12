package acton

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/evidencepack"
)

const EvidenceSchemaVersion = "ton.acton.evidence.v1"

type EvidencePackInput struct {
	PackID              string                  `json:"pack_id"`
	ActorDID            string                  `json:"actor_did"`
	IntentID            string                  `json:"intent_id"`
	PolicyHash          string                  `json:"policy_hash"`
	Envelope            *ActonCommandEnvelope   `json:"envelope"`
	Receipt             *ActonReceipt           `json:"receipt"`
	ContractBundle      ConnectorContractBundle `json:"connector_contract_bundle"`
	PolicyBundle        any                     `json:"orggenome_policy_bundle,omitempty"`
	P0Ceilings          P0Ceilings              `json:"p0_ceilings"`
	PlanIR              any                     `json:"plan_ir,omitempty"`
	CPIInputs           any                     `json:"cpi_inputs,omitempty"`
	CPIOutput           any                     `json:"cpi_output,omitempty"`
	KernelVerdict       any                     `json:"kernel_verdict,omitempty"`
	ApprovalCeremony    any                     `json:"approval_ceremony,omitempty"`
	SandboxGrant        any                     `json:"sandbox_grant,omitempty"`
	AdditionalArtifacts map[string][]byte       `json:"-"`
	CreatedAt           time.Time               `json:"created_at,omitempty"`
}

type EvidencePackBuildResult struct {
	Manifest *evidencepack.Manifest `json:"manifest"`
	Contents map[string][]byte      `json:"contents"`
}

func BuildEvidencePack(input EvidencePackInput) (*EvidencePackBuildResult, error) {
	if input.Envelope == nil || input.Receipt == nil {
		return nil, fmt.Errorf("ton.acton evidence: envelope and receipt are required")
	}
	if input.PackID == "" {
		input.PackID = "ton-acton-" + input.Envelope.CommandID
	}
	if input.ActorDID == "" {
		input.ActorDID = input.Envelope.Principal
	}
	if input.IntentID == "" {
		input.IntentID = input.Envelope.CommandID
	}
	if input.PolicyHash == "" {
		input.PolicyHash = input.Envelope.PolicyHash
	}
	builder := evidencepack.NewBuilder(input.PackID, input.ActorDID, input.IntentID, input.PolicyHash)
	if !input.CreatedAt.IsZero() {
		builder.WithCreatedAt(input.CreatedAt)
	}
	if err := builder.AddReceipt("tool_receipt", input.Receipt); err != nil {
		return nil, err
	}
	builder.AddRawEntry("acton_command_envelope.json", "application/json", mustJSON(input.Envelope))
	builder.AddRawEntry("connector_contract_bundle.json", "application/json", mustJSON(ContractBundle()))
	builder.AddRawEntry("p0_ceilings.json", "application/json", mustJSON(input.P0Ceilings))
	builder.AddRawEntry("acton_version.txt", "text/plain", []byte(input.Envelope.ActonVersion))
	builder.AddRawEntry("tolk_compiler_version.txt", "text/plain", []byte(input.Envelope.TolkCompilerVersion))
	builder.AddRawEntry("source_tree_hash.txt", "text/plain", []byte(input.Envelope.SourceTreeHash))
	builder.AddRawEntry("Acton.toml.hash", "text/plain", []byte(input.Envelope.ManifestHash))
	builder.AddRawEntry("replay_instructions.txt", "text/plain", []byte(ReplayInstructions(input.Envelope)))
	builder.AddRawEntry("redaction_map.json", "application/json", mustJSON(map[string]any{"redactions": input.Receipt.Redactions}))
	builder.AddRawEntry("proofgraph.json", "application/json", mustJSON(map[string]any{
		"nodes": []map[string]any{
			{"type": "INTENT", "connector_id": ConnectorID, "seq": 1, "command_id": input.Envelope.CommandID},
			{"type": "EFFECT", "connector_id": ConnectorID, "seq": 2, "command_id": input.Envelope.CommandID},
		},
	}))
	builder.AddRawEntry("08_TAPES/tape_manifest.json", "application/json", mustJSON(map[string]any{
		"run_id":  input.Envelope.CommandID,
		"entries": []any{},
	}))
	if input.PlanIR != nil {
		builder.AddRawEntry("plan_ir.json", "application/json", mustJSON(input.PlanIR))
	}
	if input.CPIInputs != nil {
		builder.AddRawEntry("cpi_inputs.json", "application/json", mustJSON(input.CPIInputs))
	}
	if input.CPIOutput != nil {
		builder.AddRawEntry("cpi_output.json", "application/json", mustJSON(input.CPIOutput))
	}
	if input.KernelVerdict != nil {
		builder.AddRawEntry("kernel_verdict.json", "application/json", mustJSON(input.KernelVerdict))
	}
	if input.ApprovalCeremony != nil {
		builder.AddRawEntry("approval_ceremony.json", "application/json", mustJSON(input.ApprovalCeremony))
	}
	if input.SandboxGrant != nil {
		builder.AddRawEntry("sandbox_grant.json", "application/json", mustJSON(input.SandboxGrant))
	}
	for path, data := range input.AdditionalArtifacts {
		builder.AddRawEntry(path, contentTypeFor(path), data)
	}
	manifest, contents, err := builder.Build()
	if err != nil {
		return nil, err
	}
	return &EvidencePackBuildResult{Manifest: manifest, Contents: contents}, nil
}

func WriteEvidencePackDir(dir string, result *EvidencePackBuildResult) error {
	if result == nil {
		return fmt.Errorf("evidence result is nil")
	}
	for path, data := range result.Contents {
		full := filepath.Join(dir, path)
		if err := os.MkdirAll(filepath.Dir(full), 0750); err != nil {
			return err
		}
		if err := os.WriteFile(full, data, 0644); err != nil {
			return err
		}
	}
	return nil
}

func ReplayInstructions(env *ActonCommandEnvelope) string {
	return fmt.Sprintf("Verify hashes, policy, sandbox grant, and receipt, then replay typed action %s with argv array %q. Do not use shell interpolation.\n", env.ActionURN, env.Argv)
}

func mustJSON(v any) []byte {
	data, _ := json.MarshalIndent(v, "", "  ")
	return data
}

func contentTypeFor(path string) string {
	switch filepath.Ext(path) {
	case ".json":
		return "application/json"
	case ".txt":
		return "text/plain"
	default:
		return "application/octet-stream"
	}
}
