package codeexec

import (
	"context"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPythonExecutor_RunScript(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not in PATH")
	}
	e := NewPythonExecutor(10)
	res, err := e.Run(context.Background(), `print("hello world")`, nil)
	require.NoError(t, err)
	assert.Equal(t, "hello world\n", res.Stdout)
	assert.Equal(t, 0, res.ExitCode)
}

func TestPythonExecutor_CapturesStderr(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not in PATH")
	}
	e := NewPythonExecutor(10)
	res, err := e.Run(context.Background(), `import sys; sys.stderr.write("oops\n"); sys.exit(1)`, nil)
	require.NoError(t, err)
	assert.Equal(t, "oops\n", res.Stderr)
	assert.Equal(t, 1, res.ExitCode)
}

func TestPythonExecutor_PassesEnv(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not in PATH")
	}
	e := NewPythonExecutor(10)
	res, err := e.Run(context.Background(), `import os; print(os.environ.get("HELM_TEST",""))`, map[string]string{"HELM_TEST": "works"})
	require.NoError(t, err)
	assert.Equal(t, "works\n", res.Stdout)
}
