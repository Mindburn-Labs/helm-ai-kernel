package adapters

import (
	"crypto/sha256"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func TestCheckPermitDigest(t *testing.T) {
	args := []byte(`{"a":1}`)
	sum := sha256.Sum256(args)
	if r := CheckPermitDigest(args, sum[:]); r != nil {
		t.Fatalf("the matching digest was refused: %v", r)
	}
	other := sha256.Sum256([]byte(`{"a":2}`))
	for name, digest := range map[string][]byte{
		"other bytes": other[:],
		"nil":         nil,
		"truncated":   sum[:31],
		"hex text":    []byte("6a2da20943931e9834fc12cfe5bb47bbd9ae43489a30726962b576f4e3993e50"),
	} {
		if r := CheckPermitDigest(args, digest); r == nil || r.Reason != contracts.ReasonPermitArgumentMismatch {
			t.Errorf("%s: %v", name, r)
		}
	}
}

func TestRecordsNeverCountASkipAsAPass(t *testing.T) {
	suite := Suite{Adapter: "x", AdapterVersion: "1", SuiteVersion: "1", Cases: []SuiteCase{
		{ID: "a/1", Operation: "a"}, {ID: "a/2", Operation: "a"}, {ID: "b/1", Operation: "b"},
	}}
	records := suite.Records("env", map[string]CheckStatus{"a/1": CheckPass, "a/2": CheckSkipped, "b/1": CheckPass}, nil)
	if len(records) != 2 || records[0].Qualified || !records[1].Qualified {
		t.Fatalf("records %+v", records)
	}
	missing := suite.Records("env", map[string]CheckStatus{"a/1": CheckPass}, nil)
	if missing[0].Qualified || missing[1].Qualified || missing[1].Checks[0].Status != CheckSkipped {
		t.Fatalf("a case with no result counted: %+v", missing)
	}
	if records[0].SuiteDigest != suite.Digest() || len(suite.Digest()) != 64 {
		t.Fatal("the record does not carry the suite digest")
	}
	changed := suite
	changed.Cases = append([]SuiteCase{{ID: "a/1", Operation: "a", Description: "changed"}}, suite.Cases[1:]...)
	if changed.Digest() == suite.Digest() {
		t.Fatal("the digest does not cover the cases")
	}
}

// The typed results mirror the proto messages field for field, in field
// order, so the gateway can convert them without a mapping table.
func TestResultTypesMirrorTheProto(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "..", "..", "protocols", "proto", "helm", "gateway", "v1", "gateway.proto"))
	if err != nil {
		t.Fatal(err)
	}
	proto := string(raw)
	fieldRE := regexp.MustCompile(`(?m)^\s+\w+ (\w+) = (\d+);`)
	for message, typ := range map[string]reflect.Type{
		"GitHubPullRequestResult": reflect.TypeOf(GitHubPullRequestResult{}),
		"GitHubBranchResult":      reflect.TypeOf(GitHubBranchResult{}),
		"GitHubRepositoryResult":  reflect.TypeOf(GitHubRepositoryResult{}),
	} {
		start := strings.Index(proto, "message "+message+" {")
		if start < 0 {
			t.Fatalf("gateway.proto has no message %s", message)
		}
		body := proto[start : start+strings.Index(proto[start:], "\n}")]
		var protoFields []string
		for _, m := range fieldRE.FindAllStringSubmatch(body, -1) {
			protoFields = append(protoFields, m[1])
		}
		var goFields []string
		for i := 0; i < typ.NumField(); i++ {
			goFields = append(goFields, typ.Field(i).Tag.Get("json"))
		}
		if !reflect.DeepEqual(protoFields, goFields) || len(goFields) == 0 {
			t.Errorf("%s: proto fields %v, Go fields %v", message, protoFields, goFields)
		}
	}
}

// The effect gateway must stay movable to its own repository: the adapters
// depend, even transitively, on none of the legacy runtime.
func TestAdaptersDoNotImportTheLegacyRuntime(t *testing.T) {
	forbidden := []string{"guardian", "proxy", "mcp", "executor", "connectors"}
	isForbidden := func(dep string) bool {
		for _, f := range forbidden {
			p := "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/" + f
			if dep == p || strings.HasPrefix(dep, p+"/") {
				return true
			}
		}
		return false
	}
	if !isForbidden("github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/guardian/firewall") ||
		isForbidden("github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/mcpx") {
		t.Fatal("the boundary check does not recognise what it should")
	}
	_, file, _, _ := runtime.Caller(0)
	cmd := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}", "./pkg/gateway/adapters/...")
	cmd.Dir = filepath.Join(filepath.Dir(file), "..", "..", "..")
	cmd.Env = append(os.Environ(), "GOWORK=off")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	deps := strings.Fields(string(out))
	if !contains(deps, "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters/github") {
		t.Fatal("go list did not report the GitHub adapter; the check would see nothing")
	}
	for _, dep := range deps {
		if isForbidden(dep) {
			t.Errorf("the adapters depend on %s", dep)
		}
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
