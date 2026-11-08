package admission

// quantum_posture: compares SHA-256 content addresses and scans stored rows for
// a canary string; no signing claim.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/actuators"
	sandboxadapter "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters/sandbox"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/authorityrows"
)

// sandboxProvider is an in-memory sandbox provider. Its sandboxes run commands
// in the local shell, so the adapter's real wrapper scripts run.
type sandboxProvider struct {
	mu           sync.Mutex
	boxes        map[string]*actuators.Info
	next         int
	creates      int
	execs        int
	tokens       []string
	landThenFail bool
}

var _ actuators.Provider = (*sandboxProvider)(nil)

func (p *sandboxProvider) Provider() string { return "fake" }
func (p *sandboxProvider) Preflight(context.Context) (*actuators.PreflightReport, error) {
	return &actuators.PreflightReport{StrictPassed: true}, nil
}
func (p *sandboxProvider) Create(_ context.Context, spec *actuators.SandboxSpec) (*actuators.SandboxHandle, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.creates++
	p.next++
	id := fmt.Sprintf("sbx-%d", p.next)
	p.boxes[id] = &actuators.Info{ID: id, Status: actuators.StatusRunning, Labels: spec.Labels, Runtime: spec.Runtime}
	if p.landThenFail {
		return nil, &actuators.CallError{Provider: "fake", Status: 502, Detail: "POST /sandboxes: status 502"}
	}
	return &actuators.SandboxHandle{ID: id, Provider: "fake", Status: actuators.StatusRunning}, nil
}
func (p *sandboxProvider) Resume(context.Context, string) (*actuators.SandboxHandle, error) {
	return nil, actuators.ErrNotSupported
}
func (p *sandboxProvider) Pause(context.Context, string) error { return actuators.ErrNotSupported }
func (p *sandboxProvider) Terminate(_ context.Context, id string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if b, ok := p.boxes[id]; ok {
		b.Status = actuators.StatusTerminated
	}
	return nil
}
func (p *sandboxProvider) Exec(ctx context.Context, _ string, req *actuators.ExecRequest) (*actuators.ExecResult, error) {
	p.mu.Lock()
	p.execs++
	p.mu.Unlock()
	cmd := exec.CommandContext(ctx, req.Command[0], req.Command[1:]...) // #nosec G204 -- the test shell standing in for a sandbox
	out, err := cmd.Output()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return nil, err
		}
		code = ee.ExitCode()
	}
	return &actuators.ExecResult{ExitCode: code, Stdout: out}, nil
}
func (p *sandboxProvider) ReadFile(context.Context, string, string) ([]byte, error) {
	return nil, actuators.ErrNotSupported
}
func (p *sandboxProvider) WriteFile(context.Context, string, string, []byte) error {
	return actuators.ErrNotSupported
}
func (p *sandboxProvider) ListFiles(context.Context, string, string) ([]actuators.FileEntry, error) {
	return nil, actuators.ErrNotSupported
}
func (p *sandboxProvider) AllowEgress(context.Context, string, []actuators.EgressRule) error {
	return actuators.ErrNotSupported
}
func (p *sandboxProvider) Logs(context.Context, string, *actuators.LogOptions) ([]actuators.LogEntry, error) {
	return nil, actuators.ErrNotSupported
}
func (p *sandboxProvider) Lookup(_ context.Context, id string) (*actuators.Info, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	b, ok := p.boxes[id]
	if !ok {
		return nil, actuators.ErrSandboxNotFound
	}
	c := *b
	return &c, nil
}
func (p *sandboxProvider) Find(_ context.Context, labels map[string]string) ([]actuators.Info, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []actuators.Info
	for _, b := range p.boxes {
		match := true
		for k, v := range labels {
			match = match && b.Labels[k] == v
		}
		if match {
			out = append(out, *b)
		}
	}
	return out, nil
}

const (
	sbxCreateArgs = `{"schema":"helm.sandbox.create.v1","runtime":"base","cpu_millis":500,"memory_mb":256,"disk_mb":0,"timeout_seconds":600,"max_processes":64,"egress_disabled":true}`
	sbxExecArgs   = `{"schema":"helm.sandbox.exec.v1","command":["sh","-c","printf '%s' \"$0\"","from the sandbox"],"workdir":"","timeout_seconds":60}`
)

var tenantBHuman = Caller{TenantID: tenantB, WorkspaceID: workspace, PrincipalID: "human-a", ActorID: actor}
var tenantBWorkload = Caller{TenantID: tenantB, WorkspaceID: workspace, PrincipalID: actor}

func (f *fixture) sandboxProposal(key, mandateID, effectType, target, args string) ProposeInput {
	in := proposal(key, effectType, target, []byte(args))
	in.MandateID = mandateID
	if effectType != effectargs.SandboxTerminate {
		// The adapter's fixed quote: one count per create and per exec.
		in.Quote = []Amount{{Unit: "count", Amount: 1}}
	}
	return in
}

func (f *fixture) sandboxMandate(tenant string) string {
	f.t.Helper()
	types := []string{effectargs.SandboxCreate, effectargs.SandboxExec, effectargs.SandboxTerminate}
	for _, et := range types {
		// The tenant registers exec as it declares it, high, in production;
		// the proof registers it medium to avoid a human step-up ceremony,
		// which is not what is under test.
		must(f.t, f.rows.CreateEffectType(context.Background(), tenant, et, authorityrows.RiskMedium))
	}
	m := f.rootMandate(tenant, "human-a", authorityrows.Terms{EffectTypes: types,
		ValidFrom: f.now.Add(-time.Hour), ValidUntil: f.now.Add(24 * time.Hour)})
	return m.ID.String()
}

func TestPostgresSandboxEffectsAdmitDispatchReconcileAndStayInTheirTenant(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	mandateA, mandateB := f.sandboxMandate(tenantA), f.sandboxMandate(tenantB)
	provider := &sandboxProvider{boxes: map[string]*actuators.Info{}}
	adapter, err := sandboxadapter.New([]sandboxadapter.Backend{{
		Name: "e2b", NeedsKey: true, CompareRuntime: true,
		ValidateRuntime: func(string) error { return nil },
		Open: func(ctx context.Context, token string) (actuators.Provider, context.Context, error) {
			provider.mu.Lock()
			provider.tokens = append(provider.tokens, token)
			provider.mu.Unlock()
			return provider, ctx, nil
		},
	}})
	must(t, err)
	svc := f.withAdapter(adapter)
	var attempts []string
	t.Cleanup(func() {
		for _, id := range attempts {
			_ = os.RemoveAll("/tmp/.helm/" + id)
		}
	})
	run := func(caller, runner Caller, key, mandate, effectType, target, args string) Attempt {
		t.Helper()
		a, _, err := svc.Propose(ctx, caller, f.sandboxProposal(key, mandate, effectType, target, args))
		must(t, err)
		attempts = append(attempts, a.ID)
		got, _, err := svc.Dispatch(ctx, runner, a.ID)
		must(t, err)
		return got
	}

	// create: admitted, dispatched once, read back as a schema-checked artifact.
	created := run(human, workload, "sbx-create", mandateA, effectargs.SandboxCreate, "sandbox/e2b", sbxCreateArgs)
	wantOutcome(t, "create", created, "OBSERVED", "SUCCEEDED", "")
	art := created.LatestObservation.Artifact
	if art == nil || art.SchemaID != "helm.sandbox.create.result.v1" || created.LatestObservation.ResultRef != art.Digest {
		t.Fatalf("create result = %+v", created.LatestObservation)
	}
	var result map[string]any
	must(t, json.Unmarshal(art.CanonicalBytes, &result))
	sandboxID, _ := result["sandbox_id"].(string)
	if result["state"] != "running" || sandboxID == "" || created.LatestObservation.TrustClass != "provider_readback" {
		t.Fatalf("create result = %v (%s)", result, created.LatestObservation.TrustClass)
	}
	// A propose of the same request does not create a second sandbox.
	if again, existing, err := svc.Dispatch(ctx, workload, created.ID); err != nil || !existing || again.Version != created.Version {
		t.Fatalf("a repeated dispatch = %+v %v %v", again, existing, err)
	}
	if provider.creates != 1 {
		t.Fatalf("%d creates", provider.creates)
	}

	// exec: the command ran in the sandbox and the sandbox's record is the result.
	ran := run(human, workload, "sbx-exec", mandateA, effectargs.SandboxExec, "sandbox/e2b/"+sandboxID, sbxExecArgs)
	wantOutcome(t, "exec", ran, "OBSERVED", "SUCCEEDED", "")
	var execResult map[string]any
	must(t, json.Unmarshal(ran.LatestObservation.Artifact.CanonicalBytes, &execResult))
	if execResult["stdout_excerpt"] != "from the sandbox" || execResult["exit_code"] != float64(0) || ran.LatestObservation.TrustClass != "sandbox_reported" {
		t.Fatalf("exec result = %v (%s)", execResult, ran.LatestObservation.TrustClass)
	}

	// Another tenant, holding the same provider account, cannot exec in or
	// terminate it: the adapter answers NOT_SENT and no command reaches the provider.
	execsBefore := provider.execs
	foreignExec := run(tenantBHuman, tenantBWorkload, "sbx-foreign-exec", mandateB, effectargs.SandboxExec, "sandbox/e2b/"+sandboxID, sbxExecArgs)
	wantOutcome(t, "another tenant's exec", foreignExec, "OBSERVED", "FAILED", contracts.ReasonPreconditionFailed)
	foreignStop := run(tenantBHuman, tenantBWorkload, "sbx-foreign-stop", mandateB, effectargs.SandboxTerminate, "sandbox/e2b/"+sandboxID, `{"schema":"helm.sandbox.terminate.v1"}`)
	wantOutcome(t, "another tenant's terminate", foreignStop, "OBSERVED", "FAILED", contracts.ReasonPreconditionFailed)
	if provider.execs != execsBefore {
		t.Fatal("another tenant's command reached the provider")
	}
	if b := provider.boxes[sandboxID]; b.Status != actuators.StatusRunning {
		t.Fatal("another tenant terminated the sandbox")
	}

	// A create whose answer is lost after the sandbox exists is UNKNOWN, and
	// Observe reconciles it by reading the provider back; it is never created twice.
	provider.mu.Lock()
	provider.landThenFail = true
	provider.mu.Unlock()
	a, _, err := svc.Propose(ctx, human, f.sandboxProposal("sbx-lost", mandateA, effectargs.SandboxCreate, "sandbox/e2b", sbxCreateArgs))
	must(t, err)
	lost, _, err := svc.Dispatch(ctx, workload, a.ID)
	must(t, err)
	if lost.State != "UNKNOWN" {
		t.Fatalf("a lost create answer: %s(%s)", lost.State, lost.Outcome)
	}
	provider.mu.Lock()
	provider.landThenFail = false
	provider.mu.Unlock()
	reconciled, _, err := svc.Observe(ctx, workload, a.ID)
	must(t, err)
	wantOutcome(t, "reconciled create", reconciled, "RECONCILED", "SUCCEEDED", "")
	if provider.creates != 2 {
		t.Fatalf("%d creates after the reconciliation, want 2", provider.creates)
	}

	// terminate.
	stopped := run(human, workload, "sbx-stop", mandateA, effectargs.SandboxTerminate, "sandbox/e2b/"+sandboxID, `{"schema":"helm.sandbox.terminate.v1"}`)
	wantOutcome(t, "terminate", stopped, "OBSERVED", "SUCCEEDED", "")

	// An argument the closed schema refuses never becomes an attempt.
	_, _, err = svc.Propose(ctx, human, f.sandboxProposal("sbx-env", mandateA, effectargs.SandboxExec, "sandbox/e2b/"+sandboxID,
		`{"schema":"helm.sandbox.exec.v1","command":["env"],"workdir":"","timeout_seconds":5,"env":{"TOKEN":"x"}}`))
	wantRefusal(t, "an exec that carries an environment", err, CodeInvalidArgument, contracts.ReasonSchemaViolation)
	_, _, err = svc.Propose(ctx, human, f.sandboxProposal("sbx-badtarget", mandateA, effectargs.SandboxExec, "sandbox/e2b/../daytona", sbxExecArgs))
	if err == nil {
		t.Fatal("a target that climbs out of its provider was admitted")
	}

	// R8: the provider key reached the provider client and nowhere else. It
	// is in no stored attempt, argument, observation or receipt.
	var key string
	for _, token := range provider.tokens {
		key = token
		if token == "" {
			t.Fatal("the provider was opened without the custody's key")
		}
	}
	if key != "token-for-tenant-a-sandbox.create" && key != "token-for-tenant-a-sandbox.exec" && key != "token-for-tenant-a-sandbox.terminate" &&
		key != "token-for-tenant-b-sandbox.exec" && key != "token-for-tenant-b-sandbox.terminate" {
		t.Fatalf("the provider was opened with %q", key)
	}
	for _, tenant := range []string{tenantA, tenantB} {
		if n := f.count(tenant, `SELECT count(*) FROM (
			SELECT row_to_json(t)::text AS j FROM authority_observations t
			UNION ALL SELECT row_to_json(t)::text FROM authority_effect_attempts t
			UNION ALL SELECT row_to_json(t)::text FROM authority_attempt_contents t
			UNION ALL SELECT row_to_json(t)::text FROM authority_receipts t) x
			WHERE j LIKE '%token-for-%' OR j LIKE '%' || encode('token-for-'::bytea, 'hex') || '%'`); n != 0 {
			t.Fatalf("%d stored rows of %s carry the provider key", n, tenant)
		}
	}
	f.ledgerBalances()
}
