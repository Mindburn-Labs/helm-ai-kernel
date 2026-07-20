package profile

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

func testSigner(t *testing.T) *crypto.Ed25519Signer {
	t.Helper()
	seed := bytes.Repeat([]byte{7}, ed25519.SeedSize)
	return crypto.NewEd25519SignerFromKey(ed25519.NewKeyFromSeed(seed), "boundary-test-key")
}

func testCompileOptions() CompileOptions {
	return CompileOptions{
		KernelVersion: "0.7.4-test",
		CompiledAt:    time.Date(2026, 7, 21, 0, 0, 0, 0, time.UTC),
	}
}

const goldenGatewayDropin = `# Boundary Enforcement Profile harsh-mdc-01 (tier enforce).
# Compiled by ` + "`helm-ai-kernel boundary profile compile`" + `. Do not edit: posture drift fails closed.
[Service]
NoNewPrivileges=yes
ProtectSystem=strict
PrivateTmp=yes
CapabilityBoundingSet=
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CPUQuota=50%
MemoryMax=536870912
TasksMax=128
DevicePolicy=closed
DeviceAllow=/dev/null rw
`

const goldenWorkloadDropin = `# Boundary Enforcement Profile harsh-mdc-01 (tier enforce).
# Compiled by ` + "`helm-ai-kernel boundary profile compile`" + `. Do not edit: posture drift fails closed.
# Sealed topology: orchestrator.service may reach only the HELM gateway.
[Service]
IPAddressDeny=any
IPAddressAllow=127.0.0.1
`

const goldenNftRuleset = `# Boundary Enforcement Profile harsh-mdc-01 (tier enforce).
# Compiled by ` + "`helm-ai-kernel boundary profile compile`" + `. Do not edit: posture drift fails closed.

table inet helm_boundary
delete table inet helm_boundary
table inet helm_boundary {
	chain output {
		type filter hook output priority filter; policy drop;
		oifname "lo" accept
		ct state established,related accept
		ip daddr 203.0.113.0/24 tcp dport 443 accept
	}
}
`

func TestCompileGoldenArtifacts(t *testing.T) {
	compiled, err := Compile(fixtureInput(), testSigner(t), testCompileOptions())
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{
		"systemd/helm-gateway.service.d/50-helm-boundary.conf": goldenGatewayDropin,
		"systemd/orchestrator.service.d/50-helm-boundary.conf": goldenWorkloadDropin,
		"nftables/helm-boundary.nft":                           goldenNftRuleset,
	} {
		got, ok := compiled.Files[path]
		if !ok {
			t.Fatalf("missing artifact %s", path)
		}
		if string(got) != want {
			t.Fatalf("artifact %s mismatch:\n--- got ---\n%s\n--- want ---\n%s", path, got, want)
		}
	}

	var posture ExpectedPosture
	if err := json.Unmarshal(compiled.Files["posture/expected_posture.json"], &posture); err != nil {
		t.Fatalf("expected posture must be valid JSON: %v", err)
	}
	if posture.SchemaVersion != ExpectedPostureSchemaVersion {
		t.Fatalf("posture schema version = %q", posture.SchemaVersion)
	}
	wantRulesetHash := canonicalize.ComputeArtifactHash([]byte(NormalizeNftRuleset(goldenNftRuleset)))
	if posture.Nftables.RulesetSHA256 != wantRulesetHash {
		t.Fatalf("posture ruleset hash = %s want %s", posture.Nftables.RulesetSHA256, wantRulesetHash)
	}
	gw := posture.Systemd["helm-gateway.service"]
	if gw["NoNewPrivileges"] != "yes" || gw["ProtectSystem"] != "strict" || gw["MemoryMax"] != "536870912" {
		t.Fatalf("gateway systemd expectations wrong: %v", gw)
	}
	wl := posture.Systemd["orchestrator.service"]
	if wl["IPAddressDeny"] != "any" || wl["IPAddressAllow"] != "127.0.0.1" {
		t.Fatalf("workload systemd expectations wrong: %v", wl)
	}
	cg := posture.Cgroup["helm-gateway.service"]
	if cg["cpu.max"] != "50000 100000" || cg["memory.max"] != "536870912" || cg["pids.max"] != "128" {
		t.Fatalf("cgroup expectations wrong: %v", cg)
	}
	if posture.GatewayScope.AllowedDomains[0] != "api.openai.com" || posture.GatewayScope.MaxPayloadBytes != 1048576 {
		t.Fatalf("gateway scope wrong: %+v", posture.GatewayScope)
	}
}

func TestCompileDeterministic(t *testing.T) {
	first, err := Compile(fixtureInput(), testSigner(t), testCompileOptions())
	if err != nil {
		t.Fatal(err)
	}
	second, err := Compile(fixtureInput(), testSigner(t), testCompileOptions())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first.Receipt, second.Receipt) {
		t.Fatalf("receipts differ across identical compiles:\n%+v\n%+v", first.Receipt, second.Receipt)
	}
	if len(first.Files) != len(second.Files) {
		t.Fatalf("file counts differ")
	}
	for path, content := range first.Files {
		if !bytes.Equal(content, second.Files[path]) {
			t.Fatalf("artifact %s differs across identical compiles", path)
		}
	}
	if first.Receipt.ReceiptID == "" || !strings.HasPrefix(first.Receipt.ReceiptID, "bp-") {
		t.Fatalf("deterministic receipt id expected, got %q", first.Receipt.ReceiptID)
	}
}

func TestCompileEmptyEgressIsPureDefaultDrop(t *testing.T) {
	in := fixtureInput()
	in.Egress.AllowedCIDRs = nil
	in.Egress.AllowedProtocols = nil
	in.Egress.AllowedDomains = nil
	compiled, err := Compile(in, testSigner(t), testCompileOptions())
	if err != nil {
		t.Fatal(err)
	}
	nft := string(compiled.Files[nftFilePath])
	if strings.Contains(nft, "daddr") {
		t.Fatalf("empty allowlist must compile to pure default-drop, got:\n%s", nft)
	}
	if !strings.Contains(nft, "policy drop;") {
		t.Fatalf("ruleset must default-drop, got:\n%s", nft)
	}
}

func TestCompileUnixTopology(t *testing.T) {
	in := fixtureInput()
	in.Topology.Gateway = GatewayEndpoint{Kind: "unix", Path: "/run/helm/gateway.sock"}
	compiled, err := Compile(in, testSigner(t), testCompileOptions())
	if err != nil {
		t.Fatal(err)
	}
	wl := string(compiled.Files["systemd/orchestrator.service.d/50-helm-boundary.conf"])
	for _, want := range []string{"PrivateNetwork=yes", "IPAddressDeny=any", "ReadWritePaths=/run/helm/gateway.sock"} {
		if !strings.Contains(wl, want) {
			t.Fatalf("unix workload drop-in missing %q:\n%s", want, wl)
		}
	}
}

func TestArtifactSetHashOrderIndependentAndValidated(t *testing.T) {
	a := map[string][]byte{"a/one": []byte("1"), "b/two": []byte("2"), "c/three": []byte("3")}
	b := map[string][]byte{"c/three": []byte("3"), "a/one": []byte("1"), "b/two": []byte("2")}
	refsA, hashA, err := ArtifactSetHash(a)
	if err != nil {
		t.Fatal(err)
	}
	_, hashB, err := ArtifactSetHash(b)
	if err != nil {
		t.Fatal(err)
	}
	if hashA != hashB {
		t.Fatalf("artifact set hash must not depend on map order")
	}
	if refsA[0].Path != "a/one" || refsA[2].Path != "c/three" {
		t.Fatalf("artifact refs must be path-sorted: %+v", refsA)
	}
	for _, bad := range []string{"/abs/path", "up/../down", "", "dot/./dot"} {
		if _, _, err := ArtifactSetHash(map[string][]byte{bad: []byte("x")}); err == nil {
			t.Fatalf("path %q must be rejected", bad)
		}
	}
}

func TestCompilePreconditions(t *testing.T) {
	if _, err := Compile(fixtureInput(), nil, testCompileOptions()); err == nil {
		t.Fatal("nil signer must be rejected")
	}
	opts := testCompileOptions()
	opts.KernelVersion = ""
	if _, err := Compile(fixtureInput(), testSigner(t), opts); err == nil {
		t.Fatal("missing kernel version must be rejected")
	}
	opts = testCompileOptions()
	opts.CompiledAt = time.Time{}
	if _, err := Compile(fixtureInput(), testSigner(t), opts); err == nil {
		t.Fatal("zero compiled-at must be rejected")
	}
}

// nftListRendering simulates `nft list table inet helm_boundary` output for
// the golden ruleset: no shebang/comments/declare/delete preamble, nft's own
// indentation. Normalization must converge both forms to the same body.
const nftListRendering = `table inet helm_boundary {
	chain output {
		type filter hook output priority filter; policy drop;
		oifname "lo" accept
		ct state established,related accept
		ip daddr 203.0.113.0/24 tcp dport 443 accept
	}
}
`

func TestNormalizeNftRulesetConvergesFileAndListForms(t *testing.T) {
	fromFile := NormalizeNftRuleset(goldenNftRuleset)
	fromList := NormalizeNftRuleset(nftListRendering)
	if fromFile != fromList {
		t.Fatalf("normalized forms diverge:\n--- file ---\n%s\n--- list ---\n%s", fromFile, fromList)
	}
	if !strings.Contains(fromFile, "chain output") || !strings.Contains(fromFile, "policy drop;") {
		t.Fatalf("normalized body lost structure:\n%s", fromFile)
	}
}
