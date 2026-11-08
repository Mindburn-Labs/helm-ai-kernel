package sandboxproviders

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
)

const (
	testKey           = "sk-test-very-secret-provider-key"
	tenantA, tenantB  = "tenant-a", "tenant-b"
	createArgsJSON    = `{"schema":"helm.sandbox.create.v1","runtime":"base","cpu_millis":500,"memory_mb":256,"disk_mb":0,"timeout_seconds":600,"max_processes":64,"egress_disabled":true}`
	terminateArgsJSON = `{"schema":"helm.sandbox.terminate.v1"}`
)

type staticToken struct {
	token string
	calls int
}

func (s *staticToken) Token(context.Context) (string, error) {
	s.calls++
	return s.token, nil
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
	id := fmt.Sprintf("p%d-%d-%d", os.Getpid(), time.Now().UnixNano()%1_000_000, n)
	t.Cleanup(func() { _ = os.RemoveAll("/tmp/.helm/" + id) })
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

func execArgsJSON(timeout int, workdir string, command ...string) string {
	quoted := make([]string, len(command))
	for i, c := range command {
		quoted[i] = fmt.Sprintf("%q", c)
	}
	return fmt.Sprintf(`{"schema":"helm.sandbox.exec.v1","command":[%s],"workdir":%q,"timeout_seconds":%d}`, strings.Join(quoted, ","), workdir, timeout)
}

func artifactOf(t *testing.T, obs *adapters.Observation) map[string]any {
	t.Helper()
	require.NotNil(t, obs)
	require.NotNil(t, obs.Artifact)
	var out map[string]any
	require.NoError(t, json.Unmarshal(obs.Artifact.CanonicalBytes, &out))
	return out
}
