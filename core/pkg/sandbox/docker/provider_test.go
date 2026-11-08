package docker

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/actuators"
)

const pinned = "busybox@sha256:0000000000000000000000000000000000000000000000000000000000000000"

// fakeDocker writes a docker stand-in that records argv (one line per call)
// and runs body, a shell snippet that sees "$@".
func fakeDocker(t *testing.T, body string) (*Provider, string) {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "argv")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '" + log + "'\n" + body + "\n"
	bin := filepath.Join(dir, "docker")
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return NewProvider(SandboxesConfig{DockerBin: bin}), log
}

func argv(t *testing.T, log string) []string {
	t.Helper()
	b, _ := os.ReadFile(log)
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

func goodSpec() *actuators.SandboxSpec {
	return &actuators.SandboxSpec{Runtime: pinned, Egress: actuators.EgressPolicy{Disabled: true},
		Resources: actuators.ResourceSpec{MemoryMB: 128, CPUMillis: 500, MaxProcesses: 64, Timeout: time.Minute},
		Labels:    map[string]string{"helm.tenant": "abc", "helm.attempt": "a1"}}
}

func TestCreateArgsAreHardenedAndPinned(t *testing.T) {
	p, log := fakeDocker(t, "echo cid")
	h, err := p.Create(context.Background(), goodSpec())
	if err != nil || !strings.HasPrefix(h.ID, "helm-sbx-") || h.Provider != "docker" {
		t.Fatalf("Create = %+v, %v", h, err)
	}
	line := argv(t, log)[0]
	for _, want := range []string{"run -d --name helm-sbx-", "--read-only", "--cap-drop ALL", "--security-opt no-new-privileges",
		"--network none", "--memory 128m", "--pids-limit 64", "--label helm.attempt=a1 --label helm.tenant=abc",
		pinned + " sleep 60", "--tmpfs /tmp:rw,nosuid,size=64m"} {
		if !strings.Contains(line, want) {
			t.Errorf("argv %q lacks %q", line, want)
		}
	}
}

func TestCreateRefusesWhatItCannotHold(t *testing.T) {
	p, log := fakeDocker(t, "echo cid")
	for name, mut := range map[string]func(*actuators.SandboxSpec){
		"tag":      func(s *actuators.SandboxSpec) { s.Runtime = "busybox:latest" },
		"env":      func(s *actuators.SandboxSpec) { s.Env = map[string]string{"A": "b"} },
		"mount":    func(s *actuators.SandboxSpec) { s.Mounts = []actuators.MountSpec{{Source: "/", Target: "/x"}} },
		"allow":    func(s *actuators.SandboxSpec) { s.Egress.DefaultAllowlist = []actuators.EgressRule{{Host: "x"}} },
		"memory":   func(s *actuators.SandboxSpec) { s.Resources.MemoryMB = 0 },
		"timeout":  func(s *actuators.SandboxSpec) { s.Resources.Timeout = 0 },
		"badlabel": func(s *actuators.SandboxSpec) { s.Labels = map[string]string{"k": "a b"} },
	} {
		s := goodSpec()
		mut(s)
		if _, err := p.Create(context.Background(), s); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if _, err := os.Stat(log); err == nil {
		t.Fatal("docker ran for a refused spec")
	}
}

func TestCreateFailureSaysNothingAboutTheDaemonMessage(t *testing.T) {
	p, _ := fakeDocker(t, "echo 'SECRET-IN-MESSAGE' >&2; exit 125")
	_, err := p.Create(context.Background(), goodSpec())
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("err = %v", err)
	}
}

const inspectJSON = `{"Name":"/helm-sbx-1","State":{"Status":"running"},"Config":{"Image":"img@sha256:x","Labels":{"helm.attempt":"a1","helm.tenant":"abc"}}}`

func TestLookupAndFind(t *testing.T) {
	p, log := fakeDocker(t, `case "$1" in inspect) echo '`+inspectJSON+`';; ps) echo helm-sbx-1;; esac`)
	info, err := p.Lookup(context.Background(), "helm-sbx-1")
	if err != nil || info.Status != actuators.StatusRunning || info.Labels["helm.tenant"] != "abc" {
		t.Fatalf("Lookup = %+v, %v", info, err)
	}
	found, err := p.Find(context.Background(), map[string]string{"helm.attempt": "a1"})
	if err != nil || len(found) != 1 {
		t.Fatalf("Find = %+v, %v", found, err)
	}
	if none, _ := p.Find(context.Background(), map[string]string{"helm.attempt": "other"}); len(none) != 0 {
		t.Fatal("client-side label filter did not drop a mismatch")
	}
	if !strings.Contains(strings.Join(argv(t, log), "\n"), "--filter label=helm.attempt=a1") {
		t.Fatal("ps filter missing")
	}
	if _, err := p.Lookup(context.Background(), "../x"); err == nil {
		t.Fatal("bad id accepted")
	}
}

func TestLookupMissingAndUnknownState(t *testing.T) {
	p, _ := fakeDocker(t, "echo 'Error: No such container: x' >&2; exit 1")
	if _, err := p.Lookup(context.Background(), "x"); !errors.Is(err, actuators.ErrSandboxNotFound) {
		t.Fatalf("err = %v", err)
	}
	q, _ := fakeDocker(t, `echo '{"State":{"Status":"weird"},"Config":{}}'`)
	if _, err := q.Lookup(context.Background(), "x"); err == nil {
		t.Fatal("unknown state accepted")
	}
}

func TestExecClassification(t *testing.T) {
	p, log := fakeDocker(t, `echo out; echo err >&2; exit 3`)
	res, err := p.Exec(context.Background(), "helm-sbx-1", &actuators.ExecRequest{Command: []string{"ls", "-l"}, WorkDir: "/tmp", Timeout: time.Minute})
	if err != nil || res.ExitCode != 3 || string(res.Stdout) != "out\n" {
		t.Fatalf("Exec = %+v, %v", res, err)
	}
	if got := argv(t, log)[0]; got != "exec -w /tmp helm-sbx-1 ls -l" {
		t.Fatalf("argv = %q", got)
	}
	if _, err := p.Exec(context.Background(), "helm-sbx-1", &actuators.ExecRequest{Command: []string{"x"}, Env: map[string]string{"A": "b"}}); err == nil {
		t.Fatal("env accepted")
	}
	m, _ := fakeDocker(t, "echo 'Error response from daemon: No such container: x' >&2; exit 1")
	if _, err := m.Exec(context.Background(), "x", &actuators.ExecRequest{Command: []string{"x"}}); !errors.Is(err, actuators.ErrSandboxNotFound) {
		t.Fatalf("err = %v", err)
	}
	d, _ := fakeDocker(t, "echo daemon down >&2; exit 125")
	if _, err := d.Exec(context.Background(), "x", &actuators.ExecRequest{Command: []string{"x"}}); err == nil || errors.Is(err, actuators.ErrSandboxNotFound) {
		t.Fatalf("daemon failure looked like %v", err)
	}
	s, _ := fakeDocker(t, "sleep 5")
	r, err := s.Exec(context.Background(), "x", &actuators.ExecRequest{Command: []string{"x"}, Timeout: 200 * time.Millisecond})
	if err != nil || !r.TimedOut {
		t.Fatalf("timeout = %+v, %v", r, err)
	}
}

func TestTerminateIsIdempotent(t *testing.T) {
	p, log := fakeDocker(t, "echo 'Error: No such container: x' >&2; exit 1")
	if err := p.Terminate(context.Background(), "x"); err != nil {
		t.Fatal(err)
	}
	if argv(t, log)[0] != "rm -f x" {
		t.Fatal(argv(t, log))
	}
	q, _ := fakeDocker(t, "echo boom >&2; exit 1")
	if err := q.Terminate(context.Background(), "x"); err == nil {
		t.Fatal("real failure hidden")
	}
}

func TestSocketAndUnsupported(t *testing.T) {
	p, log := fakeDocker(t, "echo ok")
	p.runner.config.DockerSocket = "/run/x.sock"
	_ = p.Terminate(context.Background(), "x")
	if !strings.HasPrefix(argv(t, log)[0], "-H unix:///run/x.sock rm") {
		t.Fatal(argv(t, log))
	}
	if _, err := p.Resume(context.Background(), "x"); !errors.Is(err, actuators.ErrNotSupported) {
		t.Fatal("resume")
	}
	rep, _ := p.Preflight(context.Background())
	if !rep.StrictPassed {
		t.Fatal("preflight")
	}
}

func TestLiveDockerProvider(t *testing.T) {
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skip("docker is not available")
	}
	out, err := exec.Command("docker", "images", "--no-trunc", "--digests", "--format", "{{.Repository}}@{{.Digest}}").Output()
	if err != nil {
		t.Skip("cannot list images")
	}
	var image string
	for _, l := range strings.Fields(string(out)) {
		if strings.Contains(l, "@sha256:") && (strings.HasPrefix(l, "busybox@") || strings.HasPrefix(l, "alpine@") || strings.Contains(l, "/busybox@") || strings.Contains(l, "/alpine@")) {
			image = l
			break
		}
	}
	if image == "" {
		t.Skip("no local busybox or alpine image with a repo digest; the test never pulls")
	}
	p := NewProvider(DefaultSandboxesConfig())
	ctx := context.Background()
	spec := goodSpec()
	spec.Runtime = image
	spec.Labels = map[string]string{"helm.attempt": "live-" + time.Now().Format("150405.000000")}
	h, err := p.Create(ctx, spec)
	if err != nil {
		t.Skipf("create failed (image may not run here): %v", err)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", h.ID).Run() })
	found, err := p.Find(ctx, spec.Labels)
	if err != nil || len(found) != 1 || found[0].ID != h.ID {
		t.Fatalf("Find = %+v, %v", found, err)
	}
	if info, err := p.Lookup(ctx, h.ID); err != nil || info.Status != actuators.StatusRunning {
		t.Fatalf("Lookup = %+v, %v", info, err)
	}
	if r, err := p.Exec(ctx, h.ID, &actuators.ExecRequest{Command: []string{"echo", "hi"}}); err != nil || r.ExitCode != 0 || string(r.Stdout) != "hi\n" {
		t.Fatalf("echo = %+v, %v", r, err)
	}
	if r, err := p.Exec(ctx, h.ID, &actuators.ExecRequest{Command: []string{"false"}}); err != nil || r.ExitCode != 1 {
		t.Fatalf("false = %+v, %v", r, err)
	}
	if err := p.Terminate(ctx, h.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Lookup(ctx, h.ID); !errors.Is(err, actuators.ErrSandboxNotFound) {
		t.Fatalf("after terminate: %v", err)
	}
}
