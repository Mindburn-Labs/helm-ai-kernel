package claudemanaged

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWorkerWorkDirNeverSendsAPathOnTheGatewayHost(t *testing.T) {
	ctx := ExecutionContext{SandboxID: "sbx", WorkspaceRoot: "/var/helm/ws/sbx/workspace"}
	for host, want := range map[string]string{
		"":                                  "",
		"/var/helm/ws/sbx/workspace":        "",
		"/var/helm/ws/sbx/workspace/a/b":    "a/b",
		"/var/helm/ws/sbx/workspace/a/../b": "b",
	} {
		got, err := workerWorkDir(ctx, host)
		require.NoError(t, err, host)
		assert.Equal(t, want, got, host)
	}
	for _, escape := range []string{"/etc", "/var/helm/ws/sbx/workspace/../other", "/var/helm/ws/sbx"} {
		_, err := workerWorkDir(ctx, escape)
		assert.Error(t, err, escape)
	}
}
