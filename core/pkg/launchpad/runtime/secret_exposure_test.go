package runtime

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/internal/secrettest"
)

// 17-04 end to end: a Launchpad launch hands provider secrets to the
// container without putting them in the docker CLI's argv (world-readable
// through /proc/<pid>/cmdline), the logs, or the returned handle.
func TestLaunchKeepsSecretsOutOfArgvLogsAndHandle(t *testing.T) {
	const canary = "sk-or-CANARY-launch-5e1b77"
	docker := secrettest.FakeExecutable(t, "docker", "")
	t.Setenv("PATH", docker.Dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	logs := secrettest.CaptureLogs(t)

	req := baseContainerRequest(t)
	req.DryRun = false
	req.Secrets = map[string]string{"OPENROUTER_API_KEY": canary}
	handle, err := NewLocalContainerRuntime().Start(req)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(handle)

	secrettest.AssertAbsent(t, canary, map[string]string{
		"docker argv": docker.Argv(t),
		"logs":        logs.String(),
		"handle":      string(out),
	})
	if !strings.Contains(docker.Env(t), "OPENROUTER_API_KEY="+canary) {
		t.Fatal("the secret no longer reaches the container environment")
	}
}
