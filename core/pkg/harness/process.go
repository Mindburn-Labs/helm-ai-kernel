package harness

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

const (
	// killGrace is how long a signalled process tree has to exit cooperatively
	// before it is killed outright.
	killGrace = 5 * time.Second

	// drainGrace is how long the harness waits for the output pipes to reach EOF
	// after the direct child has already exited.
	drainGrace = 2 * time.Second

	// stderrTailLines bounds the stderr kept for the completion event. Vendor
	// CLIs emit progress spinners and dependency warnings by the megabyte; the
	// diagnostically useful part of a failure is the end.
	stderrTailLines = 40

	// maxLineBytes bounds one stdout line. A vendor stream that exceeds it is
	// reported as dropped rather than buffered without limit.
	maxLineBytes = 1 << 20

	// eventBuffer lets a fast child run ahead of a slow observer.
	eventBuffer = 64
)

// lineParser turns one stdout line into zero or more events. Returning an error
// marks the line unparseable; it is counted, never silently discarded.
type lineParser func(line []byte) ([]Event, error)

// processSpec is everything the supervisor needs to own one child.
type processSpec struct {
	binary          string
	args            []string
	dir             string
	env             []string
	credentialRoute string
	parse           lineParser
}

// runProcess spawns the child and streams its events.
//
// The returned channel always terminates in exactly one EventCompleted followed
// by close — on clean exit, on non-zero exit, on spawn failure, and on context
// cancellation. That is the contract an observer relies on to know a run is
// over; without it, a supervisor waiting for completion would hang on precisely
// the failures it was built to react to.
func runProcess(ctx context.Context, spec processSpec) <-chan Event {
	out := make(chan Event, eventBuffer)
	go supervise(ctx, spec, out)
	return out
}

func supervise(ctx context.Context, spec processSpec, out chan<- Event) {
	defer close(out)

	tail := newRing(stderrTailLines)

	fail := func(err error) {
		out <- Event{Kind: EventError, CredentialRoute: spec.credentialRoute, Text: err.Error(), Err: err}
		out <- Event{
			Kind:            EventCompleted,
			CredentialRoute: spec.credentialRoute,
			ExitCode:        -1,
			Stderr:          tail.snapshot(),
			Err:             err,
		}
	}

	// Explicit pipes rather than cmd.StdoutPipe: StdoutPipe requires that all
	// reads finish before Wait, which deadlocks when a grandchild inherits the
	// write end and outlives the direct child. Owning the pipes lets the
	// supervisor wait and read concurrently and reap the group when the pipe
	// stays open past the child's exit.
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		fail(fmt.Errorf("harness: stdout pipe: %w", err))
		return
	}
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		_ = stdoutR.Close()
		_ = stdoutW.Close()
		fail(fmt.Errorf("harness: stderr pipe: %w", err))
		return
	}

	cmd := exec.Command(spec.binary, spec.args...)
	cmd.Dir = spec.dir
	cmd.Env = spec.env
	cmd.Stdout = stdoutW
	cmd.Stderr = stderrW
	// Stdin is left nil, which exec wires to /dev/null. A vendor CLI that
	// decides to prompt then reads EOF and exits instead of blocking forever on
	// a terminal that is not there.
	cmd.Stdin = nil
	// Setpgid puts the child in its own process group whose id equals its pid,
	// which is what makes killTree able to address the whole tree.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		_ = stdoutR.Close()
		_ = stdoutW.Close()
		_ = stderrR.Close()
		_ = stderrW.Close()
		fail(fmt.Errorf("harness: spawn %s: %w", spec.binary, err))
		return
	}

	// The parent's copies of the write ends must go, or the read ends never see
	// EOF: the parent would be holding the pipe open against itself.
	_ = stdoutW.Close()
	_ = stderrW.Close()

	pid := cmd.Process.Pid

	var dropped int
	stdoutDone := make(chan struct{})
	go func() {
		defer close(stdoutDone)
		dropped = pumpStdout(stdoutR, spec, out)
	}()

	stderrDone := make(chan struct{})
	go func() {
		defer close(stderrDone)
		scanLines(stderrR, func(line []byte, oversize bool) {
			if oversize {
				return
			}
			if text := strings.TrimRight(string(line), "\r\n"); text != "" {
				tail.add(text)
			}
		})
	}()

	procDone := make(chan struct{})
	var waitErr error
	go func() {
		defer close(procDone)
		waitErr = cmd.Wait()
	}()

	// Cancellation watchdog.
	cancelDone := make(chan struct{})
	go func() {
		defer close(cancelDone)
		select {
		case <-ctx.Done():
			killTree(pid, killGrace, procDone)
		case <-procDone:
		}
	}()

	// Drain watchdog. If the child has exited but a pipe is still open, a
	// grandchild inherited it — an MCP server or a backgrounded shell tool. It
	// is still running, still able to write to the tree, and still keeping the
	// reader from reaching EOF. A held-open pipe is also positive evidence that
	// the process group still has a live member, which is what makes a
	// group-wide kill safe to issue after the direct child was already reaped.
	drained := readersDone(stdoutDone, stderrDone)
	go func() {
		select {
		case <-procDone:
		case <-drained:
			return
		}
		select {
		case <-drained:
		case <-time.After(drainGrace):
			signalGroup(pid, syscall.SIGKILL)
		}
	}()

	<-procDone
	<-stdoutDone
	<-stderrDone
	<-cancelDone
	_ = stdoutR.Close()
	_ = stderrR.Close()

	exitCode, runErr := exitStatus(waitErr)
	if ctxErr := ctx.Err(); ctxErr != nil {
		runErr = errors.Join(runErr, ctxErr)
	}

	out <- Event{
		Kind:            EventCompleted,
		CredentialRoute: spec.credentialRoute,
		ExitCode:        exitCode,
		DroppedLines:    dropped,
		Stderr:          tail.snapshot(),
		Err:             runErr,
	}
}

// readersDone returns a channel closed once both readers have hit EOF.
func readersDone(a, b <-chan struct{}) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-a
		<-b
	}()
	return done
}

// killTree terminates the child and everything it spawned.
//
// The negative pid is the point. A vendor CLI is a supervisor in its own right:
// it forks shells for bash tools and long-lived MCP server processes. Signalling
// the direct child alone leaves those grandchildren running — still holding the
// run's stdout pipe, still able to write to the tree after HELM believes the
// run has ended, and outside every subsequent accounting of it. Setpgid at spawn
// gives the child its own group, so -pid addresses the whole tree at once.
//
// SIGTERM first, because a CLI given the chance flushes its stream and releases
// its session lock. The escalation is not optional: a process wedged in an
// uninterruptible call would otherwise hold the tree indefinitely, so SIGKILL
// follows on a timer whether or not the group cooperated.
func killTree(pid int, grace time.Duration, exited <-chan struct{}) {
	if pid <= 0 {
		return
	}
	signalGroup(pid, syscall.SIGTERM)
	select {
	case <-exited:
		// Reaped while still cooperating. Escalating now would mean signalling a
		// group id whose leader has already been reaped and whose pid the kernel
		// is free to recycle, so the group-wide kill is left to the drain
		// watchdog, which fires only on positive evidence that a member is
		// still alive.
		return
	case <-time.After(grace):
	}
	signalGroup(pid, syscall.SIGKILL)
}

// signalGroup signals the whole process group led by pid. Errors are discarded:
// the only expected one is ESRCH, meaning the group is already gone.
func signalGroup(pid int, sig syscall.Signal) {
	if pid <= 0 {
		return
	}
	_ = syscall.Kill(-pid, sig)
}

// exitStatus separates an ordinary non-zero exit from a supervision failure. A
// non-zero exit is a result the run produced; a Wait error that is not an
// ExitError means the harness lost track of the child, which is a different
// class of problem and is reported as one.
func exitStatus(waitErr error) (int, error) {
	if waitErr == nil {
		return 0, nil
	}
	var exitErr *exec.ExitError
	if errors.As(waitErr, &exitErr) {
		return exitErr.ExitCode(), nil
	}
	return -1, waitErr
}

// pumpStdout parses the child's stdout into events and returns the number of
// lines it could not parse.
func pumpStdout(r io.Reader, spec processSpec, out chan<- Event) int {
	dropped := 0
	scanLines(r, func(line []byte, oversize bool) {
		if oversize {
			dropped++
			return
		}
		if len(bytes.TrimSpace(line)) == 0 {
			return
		}
		events, err := spec.parse(line)
		if err != nil {
			dropped++
			return
		}
		for _, event := range events {
			// Stamped here, from the route decided before spawn, so every event
			// of the run carries it — including any the vendor emits after an
			// internal retry, which would otherwise be the events whose
			// attribution is least obvious.
			event.CredentialRoute = spec.credentialRoute
			out <- event
		}
	})
	return dropped
}

// scanLines reads newline-delimited records with bounded memory.
//
// A line longer than maxLineBytes is reported oversize and discarded rather than
// accumulated, so a runaway vendor stream cannot exhaust the host. Reading is
// done by ReadSlice rather than bufio.Scanner for the same reason worktree
// capture avoids Scanner: Scanner's line splitting rewrites lone carriage
// returns, and a record HELM rewrote on the way in is not the record the vendor
// emitted.
func scanLines(r io.Reader, fn func(line []byte, oversize bool)) {
	br := bufio.NewReaderSize(r, maxLineBytes)
	for {
		slice, err := br.ReadSlice('\n')
		switch {
		case err == nil:
			fn(slice, false)
		case errors.Is(err, bufio.ErrBufferFull):
			// Discard the remainder of the oversize line, then report it once.
			for {
				_, derr := br.ReadSlice('\n')
				if errors.Is(derr, bufio.ErrBufferFull) {
					continue
				}
				fn(nil, true)
				if derr != nil {
					return
				}
				break
			}
		default:
			if len(slice) > 0 {
				fn(slice, false)
			}
			return
		}
	}
}

// ring is a fixed-size tail buffer.
type ring struct {
	lines []string
	next  int
	full  bool
}

func newRing(size int) *ring {
	return &ring{lines: make([]string, size)}
}

func (r *ring) add(line string) {
	r.lines[r.next] = line
	r.next = (r.next + 1) % len(r.lines)
	if r.next == 0 {
		r.full = true
	}
}

func (r *ring) snapshot() []string {
	if !r.full {
		if r.next == 0 {
			return nil
		}
		out := make([]string, r.next)
		copy(out, r.lines[:r.next])
		return out
	}
	out := make([]string, 0, len(r.lines))
	out = append(out, r.lines[r.next:]...)
	return append(out, r.lines[:r.next]...)
}
