package acton

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts/actuators"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/effects"
)

type realActonExecutor struct {
	actonBin string
	homeDir  string
}

func (e realActonExecutor) Exec(ctx context.Context, _ string, req *actuators.ExecRequest) (*actuators.ExecResult, error) {
	if len(req.Command) == 0 || req.Command[0] != "acton" {
		return nil, exec.ErrNotFound
	}
	argv := append([]string{e.actonBin}, req.Command[1:]...)
	start := time.Now().UTC()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Dir = req.WorkDir
	cmd.Env = append(os.Environ(),
		"ACTON_LOG_DIR="+filepath.Join(e.homeDir, "logs"),
		"HOME="+e.homeDir,
		"NO_COLOR=1",
	)
	stdout, stderr := strings.Builder{}, strings.Builder{}
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	exitCode := 0
	if err != nil {
		exitCode = 1
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		}
	}
	outBytes := []byte(stdout.String())
	errBytes := []byte(stderr.String())
	spec := &actuators.SandboxSpec{
		Runtime: "local-acton-smoke",
		Egress:  actuators.EgressPolicy{Disabled: true},
		WorkDir: req.WorkDir,
	}
	return &actuators.ExecResult{
		ExitCode: exitCode,
		Stdout:   outBytes,
		Stderr:   errBytes,
		Duration: time.Since(start),
		Receipt:  actuators.ComputeReceiptFragment(req, outBytes, errBytes, e.Provider(), start, spec, actuators.EffectExecShell),
	}, nil
}

func (e realActonExecutor) Provider() string { return "local-acton-smoke" }

func TestRealActonSmokeTypedConnector(t *testing.T) {
	actonBin := os.Getenv("ACTON_BIN")
	if actonBin == "" {
		t.Skip("set ACTON_BIN to run real Acton smoke validation")
	}
	actonBin, err := filepath.Abs(actonBin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(actonBin); err != nil {
		t.Fatalf("ACTON_BIN is not executable: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	root := t.TempDir()
	homeDir := filepath.Join(root, "home")
	if err := os.MkdirAll(homeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	projectRoot := filepath.Join(root, "sample")
	runActonNew(ctx, t, actonBin, homeDir, projectRoot)

	manifestHash := fileSHA256(t, filepath.Join(projectRoot, "Acton.toml"))
	sourceHash := sourceTreeSHA256(t, projectRoot)
	scriptHash := fileSHA256(t, filepath.Join(projectRoot, "scripts", "deploy.tolk"))
	grant := sealedGrant(t, false, true)
	permit := &effects.EffectPermit{
		PermitID:    "permit-real-acton-smoke",
		IntentHash:  "sha256:real-acton-smoke",
		VerdictHash: "sha256:real-acton-smoke-verdict",
		PolicyHash:  "sha256:real-acton-smoke-policy",
		EffectType:  effects.EffectTypeExecute,
		ConnectorID: ConnectorID,
		IssuerID:    "principal:real-acton-smoke",
		IssuedAt:    time.Now().UTC(),
		ExpiresAt:   time.Now().UTC().Add(time.Hour),
	}
	connector := NewConnector(Config{
		Runner:       Runner{Executor: realActonExecutor{actonBin: actonBin, homeDir: homeDir}, SandboxID: "real-acton-smoke"},
		SandboxGrant: grant,
	})

	baseParams := map[string]any{
		"acton_version":         "1.0.0",
		"tolk_compiler_version": "1.4.0",
		"project_root":          projectRoot,
		"manifest_hash":         manifestHash,
		"source_tree_hash":      sourceHash,
		"sandbox_grant_hash":    grant.GrantHash,
		"policy_hash":           permit.PolicyHash,
		"p0_ceilings_hash":      DefaultP0Ceilings().Hash(),
		"created_at_lamport":    uint64(1),
	}
	buildParams := cloneParams(baseParams)
	buildReceipt := executeRealSmokeAction(ctx, t, connector, permit, ActionBuild, buildParams)

	for _, action := range []ActionURN{ActionCheck, ActionFormatCheck, ActionTest} {
		executeRealSmokeAction(ctx, t, connector, permit, action, cloneParams(baseParams))
	}
	scriptParams := cloneParams(baseParams)
	scriptParams["script_path"] = "scripts/deploy.tolk"
	scriptParams["script_hash"] = scriptHash
	executeRealSmokeAction(ctx, t, connector, permit, ActionScriptLocal, scriptParams)

	if evidenceDir := os.Getenv("TON_ACTON_SMOKE_EVIDENCE_DIR"); evidenceDir != "" {
		env, err := NewEnvelope(buildParams, ActionBuild, permit.IntentHash, 0)
		if err != nil {
			t.Fatal(err)
		}
		env.PolicyHash = permit.PolicyHash
		env.P0CeilingsHash = DefaultP0Ceilings().Hash()
		env.SandboxGrantHash = grant.GrantHash
		result, err := BuildEvidencePack(EvidencePackInput{
			PackID:       "ton-acton-real-smoke",
			ActorDID:     permit.IssuerID,
			IntentID:     "intent-real-acton-smoke",
			PolicyHash:   permit.PolicyHash,
			Envelope:     env,
			Receipt:      buildReceipt,
			P0Ceilings:   DefaultP0Ceilings(),
			SandboxGrant: grant,
			CreatedAt:    time.Unix(1700000000, 0).UTC(),
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.RemoveAll(evidenceDir); err != nil {
			t.Fatal(err)
		}
		if err := WriteEvidencePackDir(evidenceDir, result); err != nil {
			t.Fatal(err)
		}
	}
}

func runActonNew(ctx context.Context, t *testing.T, actonBin, homeDir, projectRoot string) {
	t.Helper()
	cmd := exec.CommandContext(ctx, actonBin, "--color", "never", "new", projectRoot, "--template", "empty")
	cmd.Env = append(os.Environ(), "ACTON_LOG_DIR="+filepath.Join(homeDir, "logs"), "HOME="+homeDir, "NO_COLOR=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("acton new failed: %v\n%s", err, out)
	}
}

func executeRealSmokeAction(ctx context.Context, t *testing.T, connector *Connector, permit *effects.EffectPermit, action ActionURN, params map[string]any) *ActonReceipt {
	t.Helper()
	out, err := connector.Execute(ctx, permit, string(action), params)
	if err != nil {
		t.Fatal(err)
	}
	receipt, ok := out.(*ActonReceipt)
	if !ok {
		t.Fatalf("expected ActonReceipt, got %T", out)
	}
	if receipt.Verdict != contracts.VerdictAllow || receipt.Status != "ok" || receipt.ExitCode != 0 {
		t.Fatalf("action %s failed: verdict=%s status=%s reason=%s exit=%d tool_error=%q", action, receipt.Verdict, receipt.Status, receipt.ReasonCode, receipt.ExitCode, receipt.ToolError)
	}
	if receipt.RequestHash == "" || receipt.DecisionHash == "" || receipt.StdoutHash == "" || receipt.StderrHash == "" {
		t.Fatalf("action %s missing receipt hashes: %#v", action, receipt)
	}
	return receipt
}

func cloneParams(params map[string]any) map[string]any {
	out := make(map[string]any, len(params))
	for key, value := range params {
		out[key] = value
	}
	return out
}

func fileSHA256(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func sourceTreeSHA256(t *testing.T, root string) string {
	t.Helper()
	var parts []string
	for _, dir := range []string{"contracts", "scripts", "tests", "wrappers"} {
		base := filepath.Join(root, dir)
		if _, err := os.Stat(base); err != nil {
			continue
		}
		if err := filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			sum := sha256.Sum256(data)
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				return relErr
			}
			parts = append(parts, filepath.ToSlash(rel)+"="+hex.EncodeToString(sum[:]))
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	sort.Strings(parts)
	sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return "sha256:" + hex.EncodeToString(sum[:])
}
