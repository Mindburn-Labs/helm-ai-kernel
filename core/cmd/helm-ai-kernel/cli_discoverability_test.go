package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/session"
)

func TestHelpJSONCatalogIsStableAndSideEffectFree(t *testing.T) {
	isolateDiscoverabilityTest(t)

	first := runDiscoverabilityCommand(t, "help", "--json")
	second := runDiscoverabilityCommand(t, "help", "--json")
	if first != second {
		t.Fatalf("help --json is not deterministic\nfirst=%s\nsecond=%s", first, second)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(first), &raw); err != nil {
		t.Fatalf("help --json is not valid JSON: %v\n%s", err, first)
	}
	if raw["schema_version"] == nil || raw["commands"] == nil {
		t.Fatalf("unexpected catalog schema: %s", first)
	}

	var catalog commandCatalogDocument
	if err := json.Unmarshal([]byte(first), &catalog); err != nil {
		t.Fatalf("decode catalog: %v", err)
	}
	if catalog.SchemaVersion != commandCatalogSchemaVersion {
		t.Fatalf("schema_version=%q", catalog.SchemaVersion)
	}

	expected := make(map[string]struct{})
	for name, cmd := range subcommands {
		if name == cmd.Name {
			expected[name] = struct{}{}
		}
	}
	for _, name := range []string{"completion", "help", "server", "serve", "threat", "version"} {
		expected[name] = struct{}{}
	}
	if len(catalog.Commands) != len(expected) {
		t.Fatalf("catalog command count=%d, want %d", len(catalog.Commands), len(expected))
	}

	for index, command := range catalog.Commands {
		if index > 0 && catalog.Commands[index-1].Name >= command.Name {
			t.Fatalf("catalog order is not stable: %q before %q", catalog.Commands[index-1].Name, command.Name)
		}
		if command.Aliases == nil || !sort.StringsAreSorted(command.Aliases) {
			t.Fatalf("command %q aliases=%v", command.Name, command.Aliases)
		}
		if command.Usage == "" {
			t.Fatalf("command %q has no usage", command.Name)
		}
		if _, ok := expected[command.Name]; !ok {
			t.Fatalf("catalog included non-canonical command %q", command.Name)
		}
		delete(expected, command.Name)
	}
	if len(expected) != 0 {
		t.Fatalf("catalog omitted commands: %v", sortedDiscoverabilityNames(expected))
	}
	if catalogContainsName(catalog, "launchpad") {
		t.Fatal("catalog listed alias launchpad as a canonical command")
	}
	if !catalogContainsName(catalog, "watch") {
		t.Fatal("catalog omitted the integrated watch command")
	}

	wantSections := []struct {
		id    string
		title string
	}{
		{id: "get-started", title: "Get started"},
		{id: "use-helm", title: "Use HELM"},
		{id: "evidence", title: "Evidence"},
		{id: "operate", title: "Operate"},
	}
	if len(catalog.Sections) != len(wantSections) {
		t.Fatalf("catalog section count=%d, want %d", len(catalog.Sections), len(wantSections))
	}
	seenSections := make(map[string]struct{}, len(catalog.Sections))
	for index, section := range catalog.Sections {
		if section.ID != wantSections[index].id || section.Title != wantSections[index].title {
			t.Fatalf("catalog section[%d]=%+v, want id=%q title=%q", index, section, wantSections[index].id, wantSections[index].title)
		}
		if len(section.Commands) == 0 {
			t.Fatalf("catalog section %q is empty", section.ID)
		}
		seenSections[section.Title] = struct{}{}
		for _, command := range section.Commands {
			if command.Group != section.Title {
				t.Fatalf("command %q group=%q, want %q", command.Name, command.Group, section.Title)
			}
		}
	}
	if !sectionContainsCommand(catalog, "get-started", "quickstart") {
		t.Fatal("get-started section omitted quickstart")
	}
	if !sectionContainsCommand(catalog, "use-helm", "watch") {
		t.Fatal("use-helm section omitted watch")
	}
	if !sectionContainsCommand(catalog, "evidence", "verify") {
		t.Fatal("evidence section omitted verify")
	}
	if !sectionContainsCommand(catalog, "operate", "workstation") {
		t.Fatal("operate section omitted workstation")
	}
	for _, title := range []string{"Get started", "Use HELM", "Evidence", "Operate"} {
		if _, ok := seenSections[title]; !ok {
			t.Fatalf("missing catalog section %q", title)
		}
	}
}

func TestCompletionScriptsAreDeterministicAndSideEffectFree(t *testing.T) {
	isolateDiscoverabilityTest(t)

	markers := map[string]string{
		"bash":       "complete -F _helm_ai_kernel_completion helm-ai-kernel",
		"zsh":        "compdef _helm_ai_kernel_completion helm-ai-kernel",
		"fish":       "complete -c helm-ai-kernel -f",
		"powershell": "Register-ArgumentCompleter -Native -CommandName helm-ai-kernel",
	}
	for _, shell := range []string{"bash", "zsh", "fish", "powershell"} {
		t.Run(shell, func(t *testing.T) {
			first := runDiscoverabilityCommand(t, "completion", shell)
			second := runDiscoverabilityCommand(t, "completion", shell)
			if first != second {
				t.Fatalf("completion output is not deterministic\nfirst=%s\nsecond=%s", first, second)
			}
			if !strings.Contains(first, markers[shell]) {
				t.Fatalf("%s completion did not contain its registration marker", shell)
			}
			for _, command := range commandCatalog().Commands {
				if !strings.Contains(first, command.Name) {
					t.Fatalf("%s completion omitted %q", shell, command.Name)
				}
			}
			for _, token := range []string{
				"launch",
				"delete",
				"evidence",
				"setup",
				"codex",
				"status",
				"quickstart",
				"--console",
				"receipts",
				"tail",
				"--agent",
				"scan",
				"--risk-envelope",
				"watch",
				"--api-key-file",
			} {
				if !strings.Contains(first, token) {
					t.Fatalf("%s completion omitted nested token %q", shell, token)
				}
			}
		})
	}
}

func TestCompletionRejectsMissingInvalidAndExtraArguments(t *testing.T) {
	isolateDiscoverabilityTest(t)

	for _, args := range [][]string{{}, {"unknown"}, {"bash", "extra"}} {
		var stdout, stderr bytes.Buffer
		code := Run(append([]string{"helm-ai-kernel", "completion"}, args...), &stdout, &stderr)
		if code != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "Usage: helm-ai-kernel completion") {
			t.Fatalf("args=%v code=%d stdout=%q stderr=%q", args, code, stdout.String(), stderr.String())
		}
	}
}

func TestVersionJSONIsStableForVersionAliases(t *testing.T) {
	var first string
	for _, command := range []string{"version", "--version"} {
		var stdout, stderr bytes.Buffer
		code := Run([]string{"helm-ai-kernel", command, "--json"}, &stdout, &stderr)
		if code != 0 || stderr.Len() != 0 {
			t.Fatalf("command=%q code=%d stdout=%q stderr=%q", command, code, stdout.String(), stderr.String())
		}
		if strings.Contains(stdout.String(), "\x1b[") {
			t.Fatalf("command=%q wrote ANSI output: %q", command, stdout.String())
		}
		if first == "" {
			first = stdout.String()
		} else if stdout.String() != first {
			t.Fatalf("version aliases differ\nfirst=%s\nsecond=%s", first, stdout.String())
		}
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(first), &raw); err != nil {
		t.Fatalf("version --json is not valid JSON: %v\n%s", err, first)
	}
	if len(raw) != 3 || raw["version"] == nil || raw["commit"] == nil || raw["build_time"] == nil {
		t.Fatalf("unexpected version schema: %s", first)
	}
	var version cliVersionInfo
	if err := json.Unmarshal([]byte(first), &version); err != nil {
		t.Fatalf("decode version JSON: %v", err)
	}
	if version.Version != displayVersion() || version.Commit != displayCommit() || version.BuildTime != displayBuildTime() {
		t.Fatalf("version JSON=%+v", version)
	}
}

func TestGlobalHumanOutputIsPlainForNonTerminalWriters(t *testing.T) {
	for _, args := range [][]string{{}, {"version"}, {"help", "--all"}} {
		var stdout, stderr bytes.Buffer
		code := Run(append([]string{"helm-ai-kernel"}, args...), &stdout, &stderr)
		if code != 0 || stderr.Len() != 0 {
			t.Fatalf("args=%v code=%d stdout=%q stderr=%q", args, code, stdout.String(), stderr.String())
		}
		if strings.Contains(stdout.String(), "\x1b[") {
			t.Fatalf("args=%v wrote ANSI to non-terminal output: %q", args, stdout.String())
		}
	}
}

func TestLiteralHelpArgumentDoesNotTriggerGlobalHelp(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "help")
	canonicalParent, err := filepath.EvalSymlinks(filepath.Dir(dataDir))
	if err != nil {
		t.Fatalf("resolve data directory parent: %v", err)
	}
	wantDataDir := filepath.Join(canonicalParent, filepath.Base(dataDir))
	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "quickstart", "--data-dir", dataDir, "--dry-run"}, &stdout, &stderr)
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}

	var preview struct {
		Operation string `json:"operation"`
		DataDir   string `json:"data_dir"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &preview); err != nil {
		t.Fatalf("decode quickstart preview: %v\n%s", err, stdout.String())
	}
	if preview.Operation != "preview" || preview.DataDir != wantDataDir {
		t.Fatalf("preview=%+v, want operation=preview data_dir=%q", preview, wantDataDir)
	}
}

func TestNestedHelpReachesLeafFlagSets(t *testing.T) {
	isolateDiscoverabilityTest(t)

	for _, tc := range []struct {
		name     string
		args     []string
		wantCode int
		wantFlag string
		parent   string
	}{
		{"receipts tail", []string{"receipts", "tail", "--help"}, 2, "-agent string", "Usage: helm-ai-kernel receipts [options]"},
		{"mcp authorize-call", []string{"mcp", "authorize-call", "--help"}, 2, "-server-id string", "Usage: helm-ai-kernel mcp [options]"},
		{"workstation verify-decision", []string{"workstation", "verify-decision", "--help"}, 0, "-receipt string", "Usage: helm-ai-kernel workstation [options]"},
		{"setup install", []string{"setup", "codex", "--help"}, 0, "--scope user|project", "Choose a local agent profile"},
		{"setup status", []string{"setup", "status", "codex", "--help"}, 0, "Usage: helm-ai-kernel setup status", "Choose a local agent profile"},
		{"setup remove", []string{"setup", "remove", "codex", "--help"}, 0, "--yes", "Choose a local agent profile"},
		{"setup quickstart", []string{"setup", "--quickstart", "--help"}, 0, "--console", "Choose a local agent profile"},
		{"setup support matrix", []string{"setup", "--json", "--help"}, 0, "--json", "Choose a local agent profile"},
		{"setup print config", []string{"setup", "--client", "cursor", "--print-config", "--help"}, 0, "--print-config", "Choose a local agent profile"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Run(append([]string{"helm-ai-kernel"}, tc.args...), &stdout, &stderr)
			if code != tc.wantCode {
				t.Fatalf("code=%d want %d stdout=%q stderr=%q", code, tc.wantCode, stdout.String(), stderr.String())
			}
			output := stdout.String() + stderr.String()
			if !strings.Contains(output, tc.wantFlag) || strings.Contains(output, tc.parent) {
				t.Fatalf("leaf help not reached: %q", output)
			}
		})
	}
}

func TestFrontDoorCommandsExposeSpecificHelp(t *testing.T) {
	isolateDiscoverabilityTest(t)

	for _, tc := range []struct {
		name   string
		args   []string
		want   string
		unwant string
	}{
		{"scan", []string{"scan", "--help"}, "--risk-envelope FILE", "Run `helm-ai-kernel help --all` to list commands."},
		{"receipts", []string{"receipts", "--help"}, "--agent <id>", "Run `helm-ai-kernel help --all` to list commands."},
		{"watch", []string{"watch", "--help"}, "--api-key-file FILE", "Run `helm-ai-kernel help --all` to list commands."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Run(append([]string{"helm-ai-kernel"}, tc.args...), &stdout, &stderr)
			if code != 0 || stderr.Len() != 0 {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			if !strings.Contains(stdout.String(), tc.want) || strings.Contains(stdout.String(), tc.unwant) {
				t.Fatalf("help output = %q", stdout.String())
			}
		})
	}
}

func TestHelpAllGroupsCommandsByUserJourney(t *testing.T) {
	isolateDiscoverabilityTest(t)

	output := runDiscoverabilityCommand(t, "help", "--all")
	sections := []string{"Get started:", "Use HELM:", "Evidence:", "Operate:"}
	last := -1
	for _, section := range sections {
		index := strings.Index(output, section)
		if index < 0 {
			t.Fatalf("help --all omitted section %q\n%s", section, output)
		}
		if index <= last {
			t.Fatalf("help --all section order is unstable\n%s", output)
		}
		last = index
	}
	for _, expected := range []string{"quickstart", "watch", "verify", "workstation"} {
		if !strings.Contains(output, expected) {
			t.Fatalf("help --all omitted %q\n%s", expected, output)
		}
	}
}

func isolateDiscoverabilityTest(t *testing.T) {
	t.Helper()
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
	originalDeleteCloudResources := deleteCloudResources
	providerCalls := 0
	deleteCloudResources = func(session.LaunchRun) (map[string][]byte, []string, error) {
		providerCalls++
		return nil, nil, nil
	}
	t.Cleanup(func() {
		defer func() { startServer = originalStartServer }()
		defer func() { deleteCloudResources = originalDeleteCloudResources }()
		if startCalls != 0 {
			t.Fatalf("discoverability command started the server %d times", startCalls)
		}
		if providerCalls != 0 {
			t.Fatalf("discoverability command invoked provider deletion %d times", providerCalls)
		}
		after, err := snapshotHelpTestTree(root)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(before, after) {
			t.Fatalf("discoverability command changed isolated filesystem\nbefore=%v\nafter=%v", before, after)
		}
	})
}

func runDiscoverabilityCommand(t *testing.T, args ...string) string {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Run(append([]string{"helm-ai-kernel"}, args...), &stdout, &stderr)
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("args=%v code=%d stdout=%q stderr=%q", args, code, stdout.String(), stderr.String())
	}
	return stdout.String()
}

func catalogContainsName(catalog commandCatalogDocument, name string) bool {
	for _, command := range catalog.Commands {
		if command.Name == name {
			return true
		}
	}
	return false
}

func sectionContainsCommand(catalog commandCatalogDocument, sectionID, commandName string) bool {
	for _, section := range catalog.Sections {
		if section.ID != sectionID {
			continue
		}
		for _, command := range section.Commands {
			if command.Name == commandName {
				return true
			}
		}
	}
	return false
}

func sortedDiscoverabilityNames(values map[string]struct{}) []string {
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
