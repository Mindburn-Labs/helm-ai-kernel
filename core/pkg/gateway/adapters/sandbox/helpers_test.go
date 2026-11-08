package sandbox

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/actuators"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
)

const testKey = "sk-test-very-secret-provider-key"

type staticToken struct {
	token string
	err   error
	calls int
}

func (s *staticToken) Token(context.Context) (string, error) {
	s.calls++
	return s.token, s.err
}

var attemptCounter struct {
	sync.Mutex
	n int
}

// attemptID is a fresh attempt id. The exec record lives under /tmp/.helm/<id>
// in the (local) sandbox, so the test removes it.
func attemptID(t *testing.T) string {
	t.Helper()
	attemptCounter.Lock()
	attemptCounter.n++
	n := attemptCounter.n
	attemptCounter.Unlock()
	id := fmt.Sprintf("t%d-%d-%d", os.Getpid(), time.Now().UnixNano()%1_000_000, n)
	t.Cleanup(func() { _ = os.RemoveAll(recordDir(id)) })
	return id
}

func digest(args string) []byte {
	sum := sha256.Sum256([]byte(args))
	return sum[:]
}

func effectFor(effectType, target, args, tenant, attempt string) adapters.Effect {
	return adapters.Effect{EffectType: effectType, Target: target, Arguments: []byte(args),
		Invocation: &adapters.Invocation{TenantID: tenant, WorkspaceID: "ws", AttemptID: attempt}}
}

const createArgsJSON = `{"schema":"helm.sandbox.create.v1","runtime":"base","cpu_millis":500,"memory_mb":256,"disk_mb":0,"timeout_seconds":600,"max_processes":64,"egress_disabled":true}`

func execArgsJSON(timeout int, workdir string, command ...string) string {
	quoted := make([]string, len(command))
	for i, c := range command {
		quoted[i] = fmt.Sprintf("%q", c)
	}
	return fmt.Sprintf(`{"schema":"helm.sandbox.exec.v1","command":[%s],"workdir":%q,"timeout_seconds":%d}`, strings.Join(quoted, ","), workdir, timeout)
}

const terminateArgsJSON = `{"schema":"helm.sandbox.terminate.v1"}`

// memProvider is an in-memory provider whose sandbox runs commands in the local
// shell, so the real wrapper scripts are exercised.
type memProvider struct {
	mu        sync.Mutex
	sandboxes map[string]*actuators.Info
	next      int

	createCalls, execCalls, terminateCalls int
	argv                                   [][]string
	specs                                  []*actuators.SandboxSpec

	// fault injection
	createErr, findErr, lookupErr, execErr, terminateErr error
	landThenFail                                         bool // Create stores the sandbox and still returns createErr
	createID                                             string
	execResult                                           func(argv []string) (*actuators.ExecResult, bool)
}

func newMem() *memProvider { return &memProvider{sandboxes: map[string]*actuators.Info{}} }

var _ actuators.Provider = (*memProvider)(nil)

func (m *memProvider) Provider() string { return "mem" }
func (m *memProvider) Preflight(context.Context) (*actuators.PreflightReport, error) {
	return &actuators.PreflightReport{StrictPassed: true}, nil
}
func (m *memProvider) Create(_ context.Context, spec *actuators.SandboxSpec) (*actuators.SandboxHandle, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.createCalls++
	m.specs = append(m.specs, spec)
	if m.createErr != nil && !m.landThenFail {
		return nil, m.createErr
	}
	m.next++
	id := fmt.Sprintf("sbx-%d", m.next)
	labels := map[string]string{}
	for k, v := range spec.Labels {
		labels[k] = v
	}
	m.sandboxes[id] = &actuators.Info{ID: id, Status: actuators.StatusRunning, Labels: labels, Runtime: spec.Runtime}
	if m.createErr != nil {
		return nil, m.createErr
	}
	if m.createID != "" {
		id = m.createID
	}
	return &actuators.SandboxHandle{ID: id, Provider: "mem", Status: actuators.StatusRunning}, nil
}
func (m *memProvider) Resume(context.Context, string) (*actuators.SandboxHandle, error) {
	return nil, actuators.ErrNotSupported
}
func (m *memProvider) Pause(context.Context, string) error { return actuators.ErrNotSupported }
func (m *memProvider) Terminate(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.terminateCalls++
	if m.terminateErr != nil {
		return m.terminateErr
	}
	if s, ok := m.sandboxes[id]; ok {
		s.Status = actuators.StatusTerminated
	}
	return nil
}
func (m *memProvider) Exec(ctx context.Context, id string, req *actuators.ExecRequest) (*actuators.ExecResult, error) {
	m.mu.Lock()
	m.execCalls++
	m.argv = append(m.argv, append([]string(nil), req.Command...))
	hook, execErr := m.execResult, m.execErr
	m.mu.Unlock()
	if execErr != nil {
		return nil, execErr
	}
	if hook != nil {
		if res, ok := hook(req.Command); ok {
			return res, nil
		}
	}
	cmd := exec.CommandContext(ctx, req.Command[0], req.Command[1:]...) // #nosec G204 -- test shell
	out, err := cmd.Output()
	code := 0
	var stderr []byte
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return nil, err
		}
		code, stderr = ee.ExitCode(), ee.Stderr
	}
	return &actuators.ExecResult{ExitCode: code, Stdout: out, Stderr: stderr}, nil
}
func (m *memProvider) ReadFile(context.Context, string, string) ([]byte, error) {
	return nil, actuators.ErrNotSupported
}
func (m *memProvider) WriteFile(context.Context, string, string, []byte) error {
	return actuators.ErrNotSupported
}
func (m *memProvider) ListFiles(context.Context, string, string) ([]actuators.FileEntry, error) {
	return nil, actuators.ErrNotSupported
}
func (m *memProvider) AllowEgress(context.Context, string, []actuators.EgressRule) error {
	return actuators.ErrNotSupported
}
func (m *memProvider) Logs(context.Context, string, *actuators.LogOptions) ([]actuators.LogEntry, error) {
	return nil, actuators.ErrNotSupported
}
func (m *memProvider) Lookup(_ context.Context, id string) (*actuators.Info, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lookupErr != nil {
		return nil, m.lookupErr
	}
	s, ok := m.sandboxes[id]
	if !ok {
		return nil, actuators.ErrSandboxNotFound
	}
	c := *s
	return &c, nil
}
func (m *memProvider) Find(_ context.Context, labels map[string]string) ([]actuators.Info, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.findErr != nil {
		return nil, m.findErr
	}
	var out []actuators.Info
	for _, s := range m.sandboxes {
		match := true
		for k, v := range labels {
			match = match && s.Labels[k] == v
		}
		if match {
			out = append(out, *s)
		}
	}
	return out, nil
}

// adopt stores a sandbox the gateway did not create (or another tenant did).
func (m *memProvider) adopt(id string, labels map[string]string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sandboxes[id] = &actuators.Info{ID: id, Status: actuators.StatusRunning, Labels: labels}
}

// testAdapter is an adapter over the in-memory provider under the name "e2b".
type testAdapter struct {
	*Adapter
	mem    *memProvider
	opens  int
	opened []string
}

func newTestAdapter(t *testing.T, mem *memProvider) *testAdapter {
	t.Helper()
	ta := &testAdapter{mem: mem}
	a, err := New([]Backend{{
		Name: "e2b", NeedsKey: true, ValidateRuntime: testValidate, CompareRuntime: true,
		Open: func(ctx context.Context, token string) (actuators.Provider, context.Context, error) {
			ta.opens++
			ta.opened = append(ta.opened, token)
			return mem, ctx, nil
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	a.now = func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }
	ta.Adapter = a
	return ta
}

var idInDetail = regexp.MustCompile(`sbx-\d+`)

func mustContain(t *testing.T, what, haystack, needle string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Fatalf("%s %q does not contain %q", what, haystack, needle)
	}
}

// testValidate accepts what a cloud provider's template id may be.
func testValidate(runtime string) error {
	if !runtimePattern.MatchString(runtime) {
		return fmt.Errorf("not a template id")
	}
	return nil
}
