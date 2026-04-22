package codeexec

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"time"
)

type Result struct {
	Stdout     string
	Stderr     string
	ExitCode   int
	DurationMs int64
}

type PythonExecutor struct {
	timeoutSec int
}

func NewPythonExecutor(timeoutSec int) *PythonExecutor {
	return &PythonExecutor{timeoutSec: timeoutSec}
}

func (e *PythonExecutor) Run(ctx context.Context, script string, env map[string]string) (*Result, error) {
	f, err := os.CreateTemp("", "helm-research-*.py")
	if err != nil {
		return nil, err
	}
	tmpPath := f.Name()
	defer os.Remove(tmpPath)

	if _, err := f.WriteString(script); err != nil {
		f.Close()
		return nil, err
	}
	f.Close()

	tctx, cancel := context.WithTimeout(ctx, time.Duration(e.timeoutSec)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(tctx, "python3", tmpPath)
	if len(env) > 0 {
		cmd.Env = os.Environ()
		for k, v := range env {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	start := time.Now()
	err = cmd.Run()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			return nil, err
		}
	}

	return &Result{
		Stdout:     stdout.String(),
		Stderr:     stderr.String(),
		ExitCode:   exitCode,
		DurationMs: time.Since(start).Milliseconds(),
	}, nil
}
