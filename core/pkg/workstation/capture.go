package workstation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

type CaptureStartOptions struct {
	Surface       string
	WorkspacePath string
	Goal          string
	ActorID       string
	WorkspaceID   string
	Repository    string
	PolicyProfile string
	StartedAt     time.Time
}

type CaptureFinishOptions struct {
	ValidationCommand string
	ToolEventsPath    string
	SigningSeed       []byte
	CompletedAt       time.Time
}

func StartCapture(outDir string, opts CaptureStartOptions) (*RunManifest, error) {
	if strings.TrimSpace(outDir) == "" {
		return nil, errors.New("capture output directory is required")
	}
	if strings.TrimSpace(opts.Goal) == "" {
		return nil, errors.New("capture goal is required")
	}
	if strings.TrimSpace(opts.WorkspacePath) == "" {
		opts.WorkspacePath = "."
	}
	workspacePath, err := filepath.Abs(opts.WorkspacePath)
	if err == nil {
		opts.WorkspacePath = workspacePath
	}
	if opts.StartedAt.IsZero() {
		opts.StartedAt = time.Now().UTC()
	}
	manifest := &RunManifest{
		RunID:         deterministicID("run", opts.Goal, opts.WorkspacePath, firstNonEmpty(opts.Surface, defaultSurface), opts.StartedAt.UTC().Format(time.RFC3339Nano)),
		Goal:          opts.Goal,
		ActorID:       firstNonEmpty(opts.ActorID, "agent.local"),
		ActorType:     defaultActorType,
		WorkspaceID:   firstNonEmpty(opts.WorkspaceID, defaultWorkspaceID),
		WorkspacePath: opts.WorkspacePath,
		Repository:    firstNonEmpty(opts.Repository, repositoryName(opts.WorkspacePath)),
		AgentSurface:  firstNonEmpty(opts.Surface, defaultSurface),
		PolicyProfile: firstNonEmpty(opts.PolicyProfile, contracts.PolicyProfileWorkstationObserveDraftV1),
		StartedAt:     opts.StartedAt.UTC(),
		Metadata: map[string]string{
			"capture_contract": "manifest-first",
		},
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, fmt.Errorf("create capture dir: %w", err)
	}
	if err := writeCanonicalJSON(filepath.Join(outDir, ManifestFile), manifest, 0o600); err != nil {
		return nil, err
	}
	return manifest, nil
}

func FinishCapture(artifactDir string, opts CaptureFinishOptions) (*ImportResult, error) {
	if strings.TrimSpace(artifactDir) == "" {
		return nil, errors.New("artifact directory is required")
	}
	manifestPath := filepath.Join(artifactDir, ManifestFile)
	manifest, err := readRequiredJSON[RunManifest](manifestPath)
	if err != nil {
		return nil, err
	}
	if opts.CompletedAt.IsZero() {
		opts.CompletedAt = time.Now().UTC()
	}
	completedAt := opts.CompletedAt.UTC()
	manifest.CompletedAt = &completedAt
	if err := writeCanonicalJSON(manifestPath, manifest, 0o600); err != nil {
		return nil, err
	}
	diff := DiffSummary{
		Repository:   firstNonEmpty(manifest.Repository, repositoryName(manifest.WorkspacePath)),
		ChangedFiles: gitDiffSummary(context.Background(), manifest.WorkspacePath),
	}
	sortChangedFiles(diff.ChangedFiles)
	if err := writeCanonicalJSON(filepath.Join(artifactDir, DiffSummaryFile), diff, 0o600); err != nil {
		return nil, err
	}
	validation := ValidationArtifact{}
	if strings.TrimSpace(opts.ValidationCommand) != "" {
		result := runValidationCommand(context.Background(), manifest.WorkspacePath, opts.ValidationCommand)
		validation.Commands = append(validation.Commands, result)
	}
	if err := writeCanonicalJSON(filepath.Join(artifactDir, ValidationFile), validation, 0o600); err != nil {
		return nil, err
	}
	if strings.TrimSpace(opts.ToolEventsPath) != "" {
		if err := copyToolEvents(opts.ToolEventsPath, filepath.Join(artifactDir, ToolEventsFile)); err != nil {
			return nil, err
		}
	}
	return ImportArtifactDir(artifactDir, ImportOptions{SigningSeed: opts.SigningSeed})
}

func writeCanonicalJSON(path string, value any, perm os.FileMode) error {
	data, err := canonicalize.JCS(value)
	if err != nil {
		return fmt.Errorf("canonicalize %s: %w", filepath.Base(path), err)
	}
	if err := os.WriteFile(path, append(data, '\n'), perm); err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	return nil
}

func gitDiffSummary(ctx context.Context, workspace string) []contracts.AgentChangedFile {
	cmd := exec.CommandContext(ctx, "git", "-C", workspace, "diff", "--numstat", "--")
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	var files []contracts.AgentChangedFile
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 3 {
			continue
		}
		additions, _ := strconv.Atoi(fields[0])
		deletions, _ := strconv.Atoi(fields[1])
		files = append(files, contracts.AgentChangedFile{
			Path:      fields[2],
			Status:    "modified",
			Additions: additions,
			Deletions: deletions,
		})
	}
	return files
}

func runValidationCommand(ctx context.Context, workspace, command string) contracts.AgentValidationResult {
	startedAt := time.Now().UTC()
	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	cmd.Dir = workspace
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	completedAt := time.Now().UTC()
	exitCode := 0
	status := "passed"
	if err != nil {
		status = "failed"
		exitCode = 1
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		}
	}
	return contracts.AgentValidationResult{
		Command:     command,
		ExitCode:    exitCode,
		Status:      status,
		StdoutHash:  hashBytes(stdout.Bytes()),
		StderrHash:  hashBytes(stderr.Bytes()),
		StartedAt:   &startedAt,
		CompletedAt: &completedAt,
	}
}

func copyToolEvents(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open tool events: %w", err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create tool events: %w", err)
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return fmt.Errorf("copy tool events: %w", err)
	}
	return nil
}

func repositoryName(workspace string) string {
	workspace = strings.TrimSpace(workspace)
	if workspace == "" {
		return ""
	}
	cmd := exec.Command("git", "-C", workspace, "rev-parse", "--show-toplevel")
	out, err := cmd.Output()
	if err == nil {
		return filepath.Base(strings.TrimSpace(string(out)))
	}
	return filepath.Base(filepath.Clean(workspace))
}

func DecodeManifest(path string) (*RunManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var manifest RunManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, err
	}
	return &manifest, nil
}
