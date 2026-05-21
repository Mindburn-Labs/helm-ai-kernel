package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

type State string

const (
	StatePlanned        State = "PLANNED"
	StateValidated      State = "VALIDATED"
	StateEscalated      State = "ESCALATED"
	StateDenied         State = "DENIED"
	StateProvisioning   State = "PROVISIONING"
	StateInstalling     State = "INSTALLING"
	StateStarting       State = "STARTING"
	StateHealthchecking State = "HEALTHCHECKING"
	StateRunning        State = "RUNNING"
	StateRepairRequired State = "REPAIR_REQUIRED"
	StateRepairing      State = "REPAIRING"
	StateTearingDown    State = "TEARING_DOWN"
	StateDeleted        State = "DELETED"
	StateFailed         State = "FAILED"
)

type LaunchRun struct {
	LaunchID              string            `json:"launch_id"`
	AppID                 string            `json:"app_id"`
	AppVersion            string            `json:"app_version"`
	SubstrateID           string            `json:"substrate_id"`
	Principal             string            `json:"principal"`
	PlanHash              string            `json:"plan_hash"`
	ArtifactImage         string            `json:"artifact_image,omitempty"`
	ArtifactDigest        string            `json:"artifact_digest,omitempty"`
	State                 State             `json:"state"`
	KernelVerdict         string            `json:"kernel_verdict"`
	ReasonCode            string            `json:"reason_code,omitempty"`
	Reason                string            `json:"reason,omitempty"`
	CreatedAt             time.Time         `json:"created_at"`
	UpdatedAt             time.Time         `json:"updated_at"`
	BoundaryRecordRefs    []string          `json:"boundary_record_refs"`
	CPIRefs               []string          `json:"cpi_refs"`
	SandboxGrantRefs      []string          `json:"sandbox_grant_refs"`
	EgressReceiptRefs     []string          `json:"egress_receipt_refs,omitempty"`
	MCPRefs               []string          `json:"mcp_refs"`
	SecretGrantRefs       []string          `json:"secret_grant_refs,omitempty"`
	ModelGatewayGrantRefs []string          `json:"model_gateway_grant_refs,omitempty"`
	InstallReceiptRefs    []string          `json:"install_receipt_refs"`
	LaunchReceiptRefs     []string          `json:"launch_receipt_refs"`
	StartReceiptRefs      []string          `json:"start_receipt_refs,omitempty"`
	HealthcheckRefs       []string          `json:"healthcheck_receipt_refs"`
	TeardownReceiptRefs   []string          `json:"teardown_receipt_refs"`
	EvidencePackRefs      []string          `json:"evidence_pack_refs"`
	EvidenceGraphRefs     []string          `json:"evidence_graph_refs,omitempty"`
	RuntimeHandles        RuntimeHandles    `json:"runtime_handles"`
	IdempotencyKeys       map[string]string `json:"idempotency_keys"`
	VerificationCommand   string            `json:"verification_command,omitempty"`
	TeardownCommand       string            `json:"teardown_command,omitempty"`
	LogPath               string            `json:"log_path,omitempty"`
}

type RuntimeHandles struct {
	ContainerID       string            `json:"container_id,omitempty"`
	EgressNetworkName string            `json:"egress_network_name,omitempty"`
	EgressProxyID     string            `json:"egress_proxy_id,omitempty"`
	EgressProxyName   string            `json:"egress_proxy_name,omitempty"`
	CloudResourceIDs  map[string]string `json:"cloud_resource_ids,omitempty"`
}

type Store struct {
	root string
}

func DefaultRoot() string {
	if override := os.Getenv("HELM_LAUNCHPAD_HOME"); override != "" {
		return override
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".helm", "launchpad")
	}
	return filepath.Join(home, ".helm", "launchpad")
}

func NewStore(root string) *Store {
	if root == "" {
		root = DefaultRoot()
	}
	return &Store{root: root}
}

func (s *Store) Root() string {
	return s.root
}

func (s *Store) Save(run LaunchRun) error {
	if err := validateTerminalState(run); err != nil {
		return err
	}
	now := time.Now().UTC()
	if run.CreatedAt.IsZero() {
		run.CreatedAt = now
	}
	run.UpdatedAt = now
	if run.IdempotencyKeys == nil {
		run.IdempotencyKeys = map[string]string{}
	}
	if run.RuntimeHandles.CloudResourceIDs == nil {
		run.RuntimeHandles.CloudResourceIDs = map[string]string{}
	}
	if err := os.MkdirAll(s.runsDir(), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(run, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.runPath(run.LaunchID), append(data, '\n'), 0o600)
}

func (s *Store) Get(launchID string) (LaunchRun, error) {
	if launchID == "" {
		return LaunchRun{}, errors.New("launch id is required")
	}
	data, err := os.ReadFile(s.runPath(launchID))
	if err != nil {
		return LaunchRun{}, err
	}
	var run LaunchRun
	if err := json.Unmarshal(data, &run); err != nil {
		return LaunchRun{}, err
	}
	return run, nil
}

func (s *Store) List() ([]LaunchRun, error) {
	entries, err := os.ReadDir(s.runsDir())
	if errors.Is(err, os.ErrNotExist) {
		return []LaunchRun{}, nil
	}
	if err != nil {
		return nil, err
	}
	runs := make([]LaunchRun, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.runsDir(), entry.Name()))
		if err != nil {
			return nil, err
		}
		var run LaunchRun
		if err := json.Unmarshal(data, &run); err != nil {
			return nil, err
		}
		runs = append(runs, run)
	}
	sort.SliceStable(runs, func(i, j int) bool {
		return runs[i].UpdatedAt.After(runs[j].UpdatedAt)
	})
	return runs, nil
}

func (s *Store) AppendLog(launchID, line string) (string, error) {
	if launchID == "" {
		return "", errors.New("launch id is required")
	}
	logDir := filepath.Join(s.root, "logs")
	if err := os.MkdirAll(logDir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(logDir, launchID+".log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := fmt.Fprintln(f, line); err != nil {
		return "", err
	}
	return path, nil
}

func (s *Store) ReadLog(launchID string) ([]byte, error) {
	return os.ReadFile(filepath.Join(s.root, "logs", launchID+".log"))
}

func (s *Store) runsDir() string {
	return filepath.Join(s.root, "runs")
}

func (s *Store) runPath(launchID string) string {
	return filepath.Join(s.runsDir(), launchID+".json")
}

func validateTerminalState(run LaunchRun) error {
	switch run.State {
	case StatePlanned, StateValidated, StateEscalated, StateDenied, StateProvisioning, StateInstalling, StateStarting, StateHealthchecking, StateRunning, StateRepairRequired, StateTearingDown, StateDeleted, StateFailed:
	default:
		return fmt.Errorf("unknown launch state %q", run.State)
	}
	switch run.KernelVerdict {
	case "", "ALLOW", "DENY", "ESCALATE":
	default:
		return fmt.Errorf("unknown kernel verdict %q", run.KernelVerdict)
	}
	if isSideEffectState(run.State) && run.KernelVerdict != "ALLOW" {
		return fmt.Errorf("%s requires ALLOW verdict before side effects", run.State)
	}
	if run.State == StateRunning && (len(run.LaunchReceiptRefs) == 0 || len(run.HealthcheckRefs) == 0 || len(run.SandboxGrantRefs) == 0) {
		return errors.New("RUNNING requires launch receipt, healthcheck receipt, and sandbox grant refs")
	}
	if run.State == StateDeleted && len(run.TeardownReceiptRefs) == 0 {
		return errors.New("DELETED requires teardown receipt refs")
	}
	return nil
}

func isSideEffectState(state State) bool {
	switch state {
	case StateProvisioning, StateInstalling, StateStarting, StateHealthchecking, StateRunning, StateTearingDown, StateDeleted:
		return true
	default:
		return false
	}
}
