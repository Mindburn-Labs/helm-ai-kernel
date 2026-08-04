package harness

import (
	"errors"
	"slices"
	"testing"
)

func TestClaudeArgsGolden(t *testing.T) {
	tests := []struct {
		name string
		spec RunSpec
		want []string
	}{
		{
			name: "readonly",
			spec: RunSpec{Prompt: "audit the tree", Access: AccessReadonly},
			want: []string{
				"-p", "audit the tree",
				"--output-format", "stream-json",
				"--verbose",
				"--permission-mode", "plan",
				"--setting-sources", "",
				"--strict-mcp-config",
				"--disable-slash-commands",
			},
		},
		{
			name: "workspace write with model",
			spec: RunSpec{Prompt: "fix the failing test", Access: AccessWorkspaceWrite, Model: "claude-opus-4-8"},
			want: []string{
				"-p", "fix the failing test",
				"--output-format", "stream-json",
				"--verbose",
				"--permission-mode", "acceptEdits",
				"--model", "claude-opus-4-8",
			},
		},
		{
			name: "full access",
			spec: RunSpec{Prompt: "run the migration", Access: AccessFull},
			want: []string{
				"-p", "run the migration",
				"--output-format", "stream-json",
				"--verbose",
				"--permission-mode", "bypassPermissions",
			},
		},
		{
			name: "resume",
			spec: RunSpec{Prompt: "continue", Access: AccessWorkspaceWrite, ResumeSessionID: "sess-42"},
			want: []string{
				"-p", "continue",
				"--output-format", "stream-json",
				"--verbose",
				"--permission-mode", "acceptEdits",
				"--resume", "sess-42",
			},
		},
		{
			name: "instructions fold into the prompt",
			spec: RunSpec{Instructions: "Stay inside the tree.", Prompt: "audit", Access: AccessReadonly},
			want: []string{
				"-p", "Stay inside the tree.\n\naudit",
				"--output-format", "stream-json",
				"--verbose",
				"--permission-mode", "plan",
				"--setting-sources", "",
				"--strict-mcp-config",
				"--disable-slash-commands",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := claudeArgs(tt.spec)
			if err != nil {
				t.Fatalf("claudeArgs: %v", err)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("argv mismatch\n got: %q\nwant: %q", got, tt.want)
			}
		})
	}
}

// TestClaudeReadonlyPassesEmptySettingSources pins the empty-string argument.
// Omitting the flag lets the CLI load the operator's own settings, which can
// re-grant the write tools plan mode just denied.
func TestClaudeReadonlyPassesEmptySettingSources(t *testing.T) {
	args, err := claudeArgs(RunSpec{Prompt: "audit", Access: AccessReadonly})
	if err != nil {
		t.Fatalf("claudeArgs: %v", err)
	}
	index := slices.Index(args, "--setting-sources")
	if index < 0 {
		t.Fatal("--setting-sources missing from readonly argv")
	}
	if index+1 >= len(args) {
		t.Fatal("--setting-sources has no value")
	}
	if args[index+1] != "" {
		t.Errorf("--setting-sources = %q, want an empty argument", args[index+1])
	}
}

func TestCodexExecArgsGolden(t *testing.T) {
	tests := []struct {
		name string
		spec RunSpec
		want []string
	}{
		{
			name: "readonly",
			spec: RunSpec{Prompt: "audit the tree", Access: AccessReadonly},
			want: []string{
				"exec", "--json", "--sandbox", "read-only", "--skip-git-repo-check",
				"--", "audit the tree",
			},
		},
		{
			name: "workspace write with model",
			spec: RunSpec{Prompt: "fix the failing test", Access: AccessWorkspaceWrite, Model: "gpt-5-codex"},
			want: []string{
				"exec", "--json", "--sandbox", "workspace-write", "--skip-git-repo-check",
				"-m", "gpt-5-codex",
				"--", "fix the failing test",
			},
		},
		{
			name: "full access",
			spec: RunSpec{Prompt: "run the migration", Access: AccessFull},
			want: []string{
				"exec", "--json", "--sandbox", "danger-full-access", "--skip-git-repo-check",
				"--", "run the migration",
			},
		},
		{
			name: "config overrides and images",
			spec: RunSpec{
				Prompt:          "look at this",
				Access:          AccessWorkspaceWrite,
				ConfigOverrides: []string{`model_reasoning_effort="high"`},
				Images:          []string{"/tmp/a.png", "/tmp/b.png"},
			},
			want: []string{
				"exec", "--json", "--sandbox", "workspace-write", "--skip-git-repo-check",
				"-c", `model_reasoning_effort="high"`,
				"-i", "/tmp/a.png",
				"-i", "/tmp/b.png",
				"--", "look at this",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := codexExecArgs(tt.spec)
			if err != nil {
				t.Fatalf("codexExecArgs: %v", err)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("argv mismatch\n got: %q\nwant: %q", got, tt.want)
			}
		})
	}
}

func TestCodexResumeArgsGolden(t *testing.T) {
	got, err := codexResumeArgs(RunSpec{
		Prompt:          "continue",
		Access:          AccessWorkspaceWrite,
		Model:           "gpt-5-codex",
		ResumeSessionID: "sess-42",
	})
	if err != nil {
		t.Fatalf("codexResumeArgs: %v", err)
	}
	want := []string{
		"exec", "resume", "sess-42", "--json", "--skip-git-repo-check",
		"-m", "gpt-5-codex",
		"-c", `sandbox_mode="workspace-write"`,
		"--", "continue",
	}
	if !slices.Equal(got, want) {
		t.Errorf("argv mismatch\n got: %q\nwant: %q", got, want)
	}
}

// TestCodexResumeNeverPassesSandboxFlag is ordering rule (b). The resume
// subcommand does not accept --sandbox; passing it either aborts the run or, on
// tolerant builds, drops the sandbox back to the default. The mode has to ride
// as a config override instead.
func TestCodexResumeNeverPassesSandboxFlag(t *testing.T) {
	for _, access := range []AccessProfile{AccessReadonly, AccessWorkspaceWrite, AccessFull} {
		args, err := codexResumeArgs(RunSpec{Prompt: "continue", Access: access, ResumeSessionID: "sess-1"})
		if err != nil {
			t.Fatalf("codexResumeArgs(%s): %v", access, err)
		}
		if slices.Contains(args, "--sandbox") {
			t.Errorf("resume argv for %s contains --sandbox, which the subcommand rejects: %q", access, args)
		}

		mode, err := codexSandboxMode(access)
		if err != nil {
			t.Fatalf("codexSandboxMode(%s): %v", access, err)
		}
		want := `sandbox_mode="` + mode + `"`
		if !slices.Contains(args, want) {
			t.Errorf("resume argv for %s is missing the config override %q: %q", access, want, args)
		}
	}
}

// TestCodexConfigOverridesPrecedeImages is ordering rule (a). -i is variadic, so
// a -c emitted after it is swallowed as an image path and silently never
// applied — including, on the resume path, the sandbox_mode override that bounds
// the run.
func TestCodexConfigOverridesPrecedeImages(t *testing.T) {
	build := map[string]func(RunSpec) ([]string, error){
		"exec":   codexExecArgs,
		"resume": codexResumeArgs,
	}

	for name, fn := range build {
		t.Run(name, func(t *testing.T) {
			spec := RunSpec{
				Prompt:          "look",
				Access:          AccessWorkspaceWrite,
				ResumeSessionID: "sess-1",
				ConfigOverrides: []string{`a="1"`, `b="2"`},
				Images:          []string{"/tmp/a.png"},
			}
			args, err := fn(spec)
			if err != nil {
				t.Fatalf("build argv: %v", err)
			}

			lastConfig := -1
			firstImage := -1
			for i, arg := range args {
				switch arg {
				case "-c":
					lastConfig = i
				case "-i":
					if firstImage < 0 {
						firstImage = i
					}
				}
			}
			if lastConfig < 0 {
				t.Fatalf("no -c override in argv: %q", args)
			}
			if firstImage < 0 {
				t.Fatalf("no -i image in argv: %q", args)
			}
			if lastConfig > firstImage {
				t.Errorf("-c at %d comes after -i at %d; the override would be consumed as an image path: %q",
					lastConfig, firstImage, args)
			}
		})
	}
}

// TestCodexSandboxOverrideKeepsTOMLQuotes pins the literal quotes: -c parses
// values as TOML, where a bare word is not a string, so an unquoted value is
// discarded and the run reverts to the default sandbox.
func TestCodexSandboxOverrideKeepsTOMLQuotes(t *testing.T) {
	if got := codexSandboxOverride("read-only"); got != `sandbox_mode="read-only"` {
		t.Errorf("codexSandboxOverride = %q, want the TOML-quoted form", got)
	}
}

// TestCodexHELMOverridesWinOverCallerOverrides: repeated -c keys resolve
// last-wins, so HELM's sandbox decision is emitted after the caller's.
func TestCodexHELMOverridesWinOverCallerOverrides(t *testing.T) {
	args, err := codexResumeArgs(RunSpec{
		Prompt:          "continue",
		Access:          AccessReadonly,
		ResumeSessionID: "sess-1",
		ConfigOverrides: []string{`sandbox_mode="danger-full-access"`},
	})
	if err != nil {
		t.Fatalf("codexResumeArgs: %v", err)
	}
	callerIndex := slices.Index(args, `sandbox_mode="danger-full-access"`)
	helmIndex := slices.Index(args, `sandbox_mode="read-only"`)
	if helmIndex < 0 {
		t.Fatalf("HELM sandbox override missing: %q", args)
	}
	if callerIndex >= 0 && callerIndex > helmIndex {
		t.Errorf("caller override at %d wins over HELM's at %d: %q", callerIndex, helmIndex, args)
	}
}

func TestArgsRejectUnknownAccessProfile(t *testing.T) {
	spec := RunSpec{Prompt: "hi", Access: AccessProfile("wide-open")}
	if _, err := claudeArgs(spec); !errors.Is(err, ErrAccessUnsupported) {
		t.Errorf("claudeArgs err = %v, want ErrAccessUnsupported", err)
	}
	if _, err := codexExecArgs(spec); !errors.Is(err, ErrAccessUnsupported) {
		t.Errorf("codexExecArgs err = %v, want ErrAccessUnsupported", err)
	}
}

func TestValidateRunSpecRejectsMissingTreeAndPrompt(t *testing.T) {
	caps := claudeCapabilities()
	if err := validateRunSpec(RunSpec{Prompt: "hi", Access: AccessReadonly}, caps); !errors.Is(err, ErrTreeRequired) {
		t.Errorf("err = %v, want ErrTreeRequired", err)
	}
	if err := validateRunSpec(RunSpec{Tree: "/t", Access: AccessReadonly}, caps); !errors.Is(err, ErrPromptRequired) {
		t.Errorf("err = %v, want ErrPromptRequired", err)
	}
	if err := validateRunSpec(RunSpec{Tree: "/t", Prompt: "hi", Access: "nope"}, caps); !errors.Is(err, ErrAccessUnsupported) {
		t.Errorf("err = %v, want ErrAccessUnsupported", err)
	}
}
