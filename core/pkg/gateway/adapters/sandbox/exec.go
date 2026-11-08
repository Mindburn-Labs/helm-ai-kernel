package sandbox

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// The exec record protocol. A sandbox keeps no durable record of a command it
// ran, and the gateway keeps none in memory (R5), so the effect leaves its own
// record inside the sandbox, and Observe reads it back with fixed read-only
// scripts. For attempt A the record is /tmp/.helm/A/:
//
//	started  written before the command starts: the epoch second of the start
//	out, err the command's stdout and stderr
//	rc       the command's exit status, written last and atomically (mv)
//
// started without rc is a command that has not finished (or was killed with
// its wrapper): the read-back is inconclusive until the exec's own timeout has
// passed, and then it is a timed-out command. Neither file is a command that
// never started. The record is the sandbox's own account of what it ran: the
// read-back's trust class says so.

const (
	recordRoot = "/tmp/.helm/"
	// excerptBytes bounds the stdout and stderr excerpts a result carries.
	excerptBytes = 8192
	// readTimeout bounds each read-back exec.
	readTimeout = 30 * time.Second
	// timeoutGrace is how long past its timeout a started, unfinished command
	// is waited for before it is called timed out.
	timeoutGrace = 30
)

// wrapper statuses the dispatch maps: the command did not start.
const (
	wrapperNoRecord = 125
	wrapperNoShell  = 126
	wrapperNotFound = 127
)

func recordDir(attemptID string) string { return recordRoot + attemptID }

// execArgv is the argument vector that runs the command and records it.
// workdir "" runs in the sandbox's default directory. The command is passed as
// positional parameters of a fixed script, so it is never parsed by a shell
// here, and providers that take one command string receive it ShellJoin-quoted.
func execArgv(attemptID, workdir string, command []string) []string {
	script := `umask 077
d=` + recordDir(attemptID) + `
[ -e "$d/started" ] && exit 0
mkdir -p "$d" && date +%s >"$d/started" || exit 125
w=$1; shift
if cd "$w" 2>/dev/null; then
  "$@" >"$d/out" 2>"$d/err" </dev/null
  echo $? >"$d/rc.tmp"
else
  : >"$d/out"; echo 'workdir not found' >"$d/err"; echo 126 >"$d/rc.tmp"
fi
mv "$d/rc.tmp" "$d/rc"
exit 0`
	if workdir == "" {
		workdir = "."
	}
	argv := []string{"sh", "-c", script, "helm-exec", workdir}
	return append(argv, command...)
}

// statusArgv reads the record's state: "none", "running S N" or "done RC OUT ERR".
func statusArgv(attemptID string) []string {
	script := `d=` + recordDir(attemptID) + `
if [ ! -e "$d/started" ]; then echo none; exit 0; fi
s=$(cat "$d/started" 2>/dev/null); n=$(date +%s)
if [ ! -e "$d/rc" ]; then echo "running $s $n"; exit 0; fi
echo "done $(cat "$d/rc") $(wc -c <"$d/out") $(wc -c <"$d/err")"`
	return []string{"sh", "-c", script, "helm-status"}
}

// excerptArgv reads the first excerptBytes of the record's out or err.
func excerptArgv(attemptID, stream string) []string {
	return []string{"head", "-c", strconv.Itoa(excerptBytes), recordDir(attemptID) + "/" + stream}
}

// recordState is a parsed status line.
type recordState struct {
	kind               string // none, running, done
	started, now       int64
	rc                 int64
	outBytes, errBytes int64
}

func parseStatus(stdout []byte) (recordState, error) {
	f := strings.Fields(string(stdout))
	bad := func() (recordState, error) {
		return recordState{}, fmt.Errorf("the sandbox's record status is not one of the known forms")
	}
	if len(f) == 0 {
		return bad()
	}
	num := func(i int) (int64, bool) {
		if i >= len(f) {
			return 0, false
		}
		v, err := strconv.ParseInt(f[i], 10, 64)
		return v, err == nil && v >= 0
	}
	switch {
	case f[0] == "none" && len(f) == 1:
		return recordState{kind: "none"}, nil
	case f[0] == "running" && len(f) == 3:
		s, ok1 := num(1)
		n, ok2 := num(2)
		if !ok1 || !ok2 {
			return bad()
		}
		return recordState{kind: "running", started: s, now: n}, nil
	case f[0] == "done" && len(f) == 4:
		rc, ok1 := num(1)
		o, ok2 := num(2)
		e, ok3 := num(3)
		if !ok1 || !ok2 || !ok3 || rc > 255 {
			return bad()
		}
		return recordState{kind: "done", rc: rc, outBytes: o, errBytes: e}, nil
	}
	return bad()
}

// timedOut is whether a started, unfinished record is past its exec timeout.
func (s recordState) timedOut(timeoutSeconds int64) bool {
	return s.kind == "running" && s.now-s.started > timeoutSeconds+timeoutGrace
}
