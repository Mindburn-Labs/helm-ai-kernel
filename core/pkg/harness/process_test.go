package harness

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// jsonParser is a stand-in adapter parser: every well-formed object becomes one
// message event, and anything else is unparseable.
func jsonParser(line []byte) ([]Event, error) {
	var frame struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(line, &frame); err != nil {
		return nil, err
	}
	return []Event{{Kind: EventMessage, Text: frame.Text}}, nil
}

// drain collects a run to completion. It fails the test if the channel closes
// without exactly one EventCompleted, which is the guarantee an observer relies
// on to know a run is over.
func drain(t *testing.T, events <-chan Event) ([]Event, Event) {
	t.Helper()
	var collected []Event
	var completed []Event

	deadline := time.After(30 * time.Second)
	for {
		select {
		case event, ok := <-events:
			if !ok {
				if len(completed) != 1 {
					t.Fatalf("expected exactly one EventCompleted, got %d", len(completed))
				}
				return collected, completed[0]
			}
			collected = append(collected, event)
			if event.Kind == EventCompleted {
				completed = append(completed, event)
			}
		case <-deadline:
			t.Fatal("run did not complete; an observer would have waited forever")
		}
	}
}

func shellSpec(script string) processSpec {
	return processSpec{
		binary:          "/bin/sh",
		args:            []string{"-c", script},
		credentialRoute: "route-under-test",
		parse:           jsonParser,
	}
}

func TestExactlyOneCompletedOnCleanExit(t *testing.T) {
	events := runProcess(context.Background(), shellSpec(`printf '{"text":"one"}\n{"text":"two"}\n'; exit 0`))
	all, completed := drain(t, events)

	if completed.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", completed.ExitCode)
	}
	if completed.Err != nil {
		t.Errorf("Err = %v, want nil", completed.Err)
	}
	if completed.DroppedLines != 0 {
		t.Errorf("DroppedLines = %d, want 0", completed.DroppedLines)
	}

	var messages int
	for _, event := range all {
		if event.Kind == EventMessage {
			messages++
		}
	}
	if messages != 2 {
		t.Errorf("parsed %d message events, want 2", messages)
	}
}

func TestExactlyOneCompletedOnNonZeroExit(t *testing.T) {
	events := runProcess(context.Background(), shellSpec(`echo "boom" 1>&2; exit 7`))
	_, completed := drain(t, events)

	if completed.ExitCode != 7 {
		t.Errorf("ExitCode = %d, want 7", completed.ExitCode)
	}
	// A non-zero exit is a result the run produced, not a supervision failure.
	if completed.Err != nil {
		t.Errorf("Err = %v, want nil for an ordinary non-zero exit", completed.Err)
	}
	if len(completed.Stderr) == 0 || !strings.Contains(strings.Join(completed.Stderr, "\n"), "boom") {
		t.Errorf("stderr tail = %q, want the child's diagnostic", completed.Stderr)
	}
}

func TestExactlyOneCompletedOnSpawnFailure(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-vendor-cli")
	spec := shellSpec("true")
	spec.binary = missing

	all, completed := drain(t, events(t, spec))

	if completed.ExitCode != -1 {
		t.Errorf("ExitCode = %d, want -1 for a child that never started", completed.ExitCode)
	}
	if completed.Err == nil {
		t.Error("Err = nil, want the spawn failure")
	}
	var sawError bool
	for _, event := range all {
		if event.Kind == EventError {
			sawError = true
		}
	}
	if !sawError {
		t.Error("no EventError emitted for a spawn failure")
	}
}

func TestExactlyOneCompletedOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	evs := runProcess(ctx, shellSpec(`while :; do sleep 0.05; done`))

	time.Sleep(150 * time.Millisecond)
	cancel()

	_, completed := drain(t, evs)
	if completed.Err == nil || !errors.Is(completed.Err, context.Canceled) {
		t.Errorf("Err = %v, want context.Canceled", completed.Err)
	}
}

// TestKillTreeReapsGrandchildren is the reason killTree signals the negative
// pid. The direct child backgrounds a shell that backgrounds a sleep; signalling
// only the direct child would leave both survivors running against the tree.
func TestKillTreeReapsGrandchildren(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "grandchild.pid")
	inner := fmt.Sprintf("sleep 300 & echo $! > %s; wait", pidFile)
	script := fmt.Sprintf("sh -c '%s' & wait", inner)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	evs := runProcess(ctx, shellSpec(script))

	descendant := waitForPIDFile(t, pidFile)
	if !processAlive(descendant) {
		t.Fatalf("descendant %d was not running before cancellation", descendant)
	}

	cancel()
	drain(t, evs)

	if !waitForProcessGone(descendant, 10*time.Second) {
		t.Errorf("descendant %d survived the run; killTree did not reach the process group", descendant)
	}
}

// TestKillTreeEscalatesToSIGKILL: the child traps SIGTERM, so only the timed
// escalation can end the run. Skipping the escalation would hold the tree
// indefinitely.
func TestKillTreeEscalatesToSIGKILL(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	evs := runProcess(ctx, shellSpec(`trap '' TERM; while :; do sleep 0.05; done`))

	time.Sleep(200 * time.Millisecond)

	start := time.Now()
	cancel()
	_, completed := drain(t, evs)
	elapsed := time.Since(start)

	if elapsed > killGrace+15*time.Second {
		t.Errorf("run took %s to end; escalation did not fire", elapsed)
	}
	if completed.ExitCode != -1 {
		t.Errorf("ExitCode = %d, want -1 for a signalled child", completed.ExitCode)
	}
}

// TestDroppedLinesAreCountedNotDiscarded: output HELM could not read is a gap in
// the run's evidence and has to be reported as one.
func TestDroppedLinesAreCountedNotDiscarded(t *testing.T) {
	script := `printf '{"text":"ok"}\nthis is not json\n{"text":"also ok"}\nneither is this\n'`
	_, completed := drain(t, events(t, shellSpec(script)))

	if completed.DroppedLines != 2 {
		t.Errorf("DroppedLines = %d, want 2", completed.DroppedLines)
	}
}

// TestOversizeLineIsDroppedNotBuffered proves the reader is bounded: a line
// larger than maxLineBytes is reported, not accumulated.
func TestOversizeLineIsDroppedNotBuffered(t *testing.T) {
	script := fmt.Sprintf(`head -c %d /dev/zero | tr '\0' 'x'; printf '\n{"text":"after"}\n'`, maxLineBytes+1024)
	all, completed := drain(t, events(t, shellSpec(script)))

	if completed.DroppedLines < 1 {
		t.Errorf("DroppedLines = %d, want at least 1 for the oversize line", completed.DroppedLines)
	}
	var recovered bool
	for _, event := range all {
		if event.Kind == EventMessage && event.Text == "after" {
			recovered = true
		}
	}
	if !recovered {
		t.Error("the reader did not recover after the oversize line")
	}
}

// TestCredentialRouteIsStampedOnEveryEvent: the route is decided once before
// spawn, so every event of the run stays attributable to it.
func TestCredentialRouteIsStampedOnEveryEvent(t *testing.T) {
	all, _ := drain(t, events(t, shellSpec(`printf '{"text":"a"}\n{"text":"b"}\n'; exit 3`)))

	if len(all) < 3 {
		t.Fatalf("expected at least three events, got %d", len(all))
	}
	for _, event := range all {
		if event.CredentialRoute != "route-under-test" {
			t.Errorf("%s event carries route %q, want %q", event.Kind, event.CredentialRoute, "route-under-test")
		}
	}
}

func TestStderrTailIsBounded(t *testing.T) {
	script := fmt.Sprintf(`i=0; while [ $i -lt %d ]; do echo "line-$i" 1>&2; i=$((i+1)); done`, stderrTailLines*3)
	_, completed := drain(t, events(t, shellSpec(script)))

	if len(completed.Stderr) != stderrTailLines {
		t.Fatalf("stderr tail has %d lines, want %d", len(completed.Stderr), stderrTailLines)
	}
	// The tail keeps the end, which is the diagnostically useful part.
	last := completed.Stderr[len(completed.Stderr)-1]
	if want := fmt.Sprintf("line-%d", stderrTailLines*3-1); last != want {
		t.Errorf("last stderr line = %q, want %q", last, want)
	}
}

func TestRingSnapshotOrdering(t *testing.T) {
	r := newRing(3)
	if got := r.snapshot(); got != nil {
		t.Errorf("empty ring snapshot = %v, want nil", got)
	}
	r.add("a")
	r.add("b")
	if got := strings.Join(r.snapshot(), ","); got != "a,b" {
		t.Errorf("partial ring = %q, want \"a,b\"", got)
	}
	r.add("c")
	r.add("d")
	if got := strings.Join(r.snapshot(), ","); got != "b,c,d" {
		t.Errorf("wrapped ring = %q, want \"b,c,d\"", got)
	}
}

func events(t *testing.T, spec processSpec) <-chan Event {
	t.Helper()
	return runProcess(context.Background(), spec)
}

func waitForPIDFile(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil {
			if pid, convErr := strconv.Atoi(strings.TrimSpace(string(data))); convErr == nil && pid > 0 {
				return pid
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("descendant never wrote its pid to %s", path)
	return 0
}

// processAlive reports whether a pid can still be signalled. Signal 0 performs
// the permission and existence checks without delivering anything.
func processAlive(pid int) bool {
	return syscall.Kill(pid, 0) == nil
}

func waitForProcessGone(pid int, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if !processAlive(pid) {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return !processAlive(pid)
}
