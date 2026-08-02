package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/session"
)

func TestDispatchHelpSkipsHandler(t *testing.T) {
	original := subcommands
	subcommands = make(map[string]Subcommand)
	t.Cleanup(func() { subcommands = original })

	calls := 0
	Register(Subcommand{
		Name:  "mutating-test-command",
		Usage: "would write state",
		RunFn: func(_ []string, _, _ io.Writer) int {
			calls++
			return 1
		},
	})

	for _, args := range [][]string{{"--help"}, {"-h"}, {"help"}} {
		var stdout, stderr bytes.Buffer
		code, ok := Dispatch("mutating-test-command", args, &stdout, &stderr)
		if !ok || code != 0 {
			t.Fatalf("args=%v code=%d handled=%t", args, code, ok)
		}
		if calls != 0 {
			t.Fatalf("args=%v invoked handler %d times", args, calls)
		}
		if !strings.Contains(stdout.String(), "mutating-test-command") || stderr.Len() != 0 {
			t.Fatalf("args=%v stdout=%q stderr=%q", args, stdout.String(), stderr.String())
		}
	}
}

func TestRegisterRejectsDuplicateNamesAndAliases(t *testing.T) {
	original := subcommands
	subcommands = make(map[string]Subcommand)
	t.Cleanup(func() { subcommands = original })

	Register(Subcommand{Name: "first", Aliases: []string{"first-alias"}})
	for _, duplicate := range []Subcommand{
		{Name: "first"},
		{Name: "second", Aliases: []string{"first-alias"}},
		{Name: "third", Aliases: []string{"third"}},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatalf("Register(%+v) did not reject duplicate", duplicate)
				}
			}()
			Register(duplicate)
		}()
	}
}

func TestHelpMatrix(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	if err := os.Mkdir(home, 0750); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "xdg-config"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(root, "xdg-data"))
	t.Setenv("HELM_LAUNCHPAD_HOME", filepath.Join(root, "launchpad"))

	before, err := snapshotHelpTestTree(root)
	if err != nil {
		t.Fatal(err)
	}
	originalStartServer := startServer
	startCalls := 0
	startServer = func() error {
		startCalls++
		return nil
	}
	t.Cleanup(func() { startServer = originalStartServer })

	originalDeleteCloudResources := deleteCloudResources
	providerCalls := 0
	deleteCloudResources = func(session.LaunchRun) (map[string][]byte, []string, error) {
		providerCalls++
		return nil, nil, nil
	}
	t.Cleanup(func() { deleteCloudResources = originalDeleteCloudResources })

	canonicalNames := make([]string, 0, len(subcommands))
	for name, cmd := range subcommands {
		if name == cmd.Name {
			canonicalNames = append(canonicalNames, name)
		}
	}
	sort.Strings(canonicalNames)
	if len(canonicalNames) == 0 {
		t.Fatal("no registered commands")
	}

	for _, name := range canonicalNames {
		for _, helpArg := range []string{"--help", "-h", "help"} {
			assertSafeHelp(t, []string{name, helpArg})
		}
	}
	for _, name := range []string{
		"init", "health", "launch", "teardown", "up", "coverage", "approvals", "authz", "budget", "boundary", "traces",
		"server", "serve", "threat", "version",
	} {
		assertSafeHelp(t, []string{name, "--help"})
	}
	assertSafeHelp(t, []string{"help", "quickstart"})
	assertSafeHelp(t, []string{"help", "--all"})
	assertSafeHelp(t, []string{"--help"})
	assertSafeHelp(t, []string{"-h"})

	if startCalls != 0 {
		t.Fatalf("help started the server %d times", startCalls)
	}
	if providerCalls != 0 {
		t.Fatalf("help invoked provider deletion %d times", providerCalls)
	}
	after, err := snapshotHelpTestTree(root)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("help changed isolated filesystem\\nbefore=%v\\nafter=%v", before, after)
	}
	t.Logf("verified --help, -h, and help for %d canonical commands", len(canonicalNames))
}

func assertSafeHelp(t *testing.T, args []string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Run(append([]string{"helm-ai-kernel"}, args...), &stdout, &stderr)
	if code != 0 || stdout.Len() == 0 || stderr.Len() != 0 {
		t.Fatalf("args=%v code=%d stdout=%q stderr=%q", args, code, stdout.String(), stderr.String())
	}
}

func snapshotHelpTestTree(root string) (map[string]string, error) {
	snapshot := make(map[string]string)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if path == root {
			snapshot["."] = fmt.Sprintf("dir:%#o:%d", info.Mode().Perm(), info.ModTime().UnixNano())
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			snapshot[rel+string(filepath.Separator)] = fmt.Sprintf("dir:%#o:%d", info.Mode().Perm(), info.ModTime().UnixNano())
			return nil
		}
		contents, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(contents)
		snapshot[rel] = fmt.Sprintf("file:%#o:%d:%x", info.Mode().Perm(), info.ModTime().UnixNano(), digest)
		return nil
	})
	return snapshot, err
}
