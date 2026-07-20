package profile

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

const (
	// NftTableName is the nftables table the profile owns end to end.
	NftTableName = "inet helm_boundary"

	dropinFileName = "50-helm-boundary.conf"
	nftFilePath    = "nftables/helm-boundary.nft"
	posturePath    = "posture/expected_posture.json"

	// ExpectedPostureSchemaVersion identifies the machine-readable posture
	// expectations artifact emitted alongside the OS artifacts.
	ExpectedPostureSchemaVersion = "boundary_expected_posture.v1"
)

// CompileOptions carries the non-policy inputs of a compile. CompiledAt is
// injected so canonical bytes never depend on wall clock inside this package.
type CompileOptions struct {
	KernelVersion string
	CompiledAt    time.Time
	// ReceiptID overrides the deterministic default
	// "bp-" + first 12 hex chars of the policy input hash.
	ReceiptID string
}

// Compiled is the result of one profile compile: the artifact files (relative
// path → content) and the sealed compile receipt binding them to the input.
type Compiled struct {
	Files   map[string][]byte
	Receipt CompileReceipt
}

// NftExpectation pins the live ruleset: the attestor compares the sha256 of
// the normalized `nft list table` output against RulesetSHA256.
type NftExpectation struct {
	Table         string `json:"table"`
	RulesetSHA256 string `json:"ruleset_sha256"`
}

// GatewayScope records the egress dimensions that CANNOT be OS rules
// (domain names and payload caps are L7 — enforced by the gateway's egress
// checker, not nftables). Recording them here keeps the artifact honest about
// where each control lives.
type GatewayScope struct {
	AllowedDomains  []string `json:"allowed_domains"`
	DeniedDomains   []string `json:"denied_domains"`
	MaxPayloadBytes int64    `json:"max_payload_bytes"`
}

// ExpectedPosture is the machine-readable expectation set the attestor
// compares live OS state against. Systemd values are stored in the forms
// `systemctl show` reports; resource limits are attested through the
// cgroup-v2 filesystem (raw integers) to avoid systemd's humanized rendering.
type ExpectedPosture struct {
	SchemaVersion string                       `json:"schema_version"`
	ProfileID     string                       `json:"profile_id"`
	ModeTier      string                       `json:"mode_tier"`
	Systemd       map[string]map[string]string `json:"systemd"`
	Nftables      NftExpectation               `json:"nftables"`
	Cgroup        map[string]map[string]string `json:"cgroup"`
	GatewayScope  GatewayScope                 `json:"gateway_scope"`
}

// Compile deterministically emits the OS enforcement artifacts for the input
// and seals a compile receipt over them. Compiling the same input with the
// same options twice yields byte-identical files and an identical receipt.
func Compile(in ProfileInput, signer crypto.Signer, opts CompileOptions) (Compiled, error) {
	if err := in.Validate(); err != nil {
		return Compiled{}, err
	}
	if signer == nil {
		return Compiled{}, fmt.Errorf("compile requires a signer: compile receipts are never emitted unsigned")
	}
	if opts.KernelVersion == "" {
		return Compiled{}, fmt.Errorf("compile requires the kernel version for the receipt")
	}
	if opts.CompiledAt.IsZero() {
		return Compiled{}, fmt.Errorf("compile requires an explicit compiled-at time")
	}
	inputHash, err := in.Hash()
	if err != nil {
		return Compiled{}, err
	}

	files := map[string][]byte{
		gatewayDropinPath(in): emitGatewayDropin(in),
		nftFilePath:           emitNftRuleset(in),
	}
	for _, unit := range in.Topology.WorkloadUnits {
		files[workloadDropinPath(unit)] = emitWorkloadDropin(in, unit)
	}
	posture, err := emitExpectedPosture(in, string(files[nftFilePath]))
	if err != nil {
		return Compiled{}, err
	}
	files[posturePath] = posture

	refs, setHash, err := ArtifactSetHash(files)
	if err != nil {
		return Compiled{}, err
	}

	receiptID := opts.ReceiptID
	if receiptID == "" {
		receiptID = "bp-" + strings.TrimPrefix(inputHash, "sha256:")[:12]
	}
	receipt := CompileReceipt{
		SchemaVersion:   CompileReceiptSchemaVersion,
		ReceiptID:       receiptID,
		ProfileID:       in.ProfileID,
		ModeTier:        in.ModeTier,
		PolicyInputHash: inputHash,
		Artifacts:       refs,
		ArtifactSetHash: setHash,
		KernelVersion:   opts.KernelVersion,
		CompiledAt:      opts.CompiledAt.UTC().Format(time.RFC3339Nano),
		SignerKeyID:     signerKeyID(signer),
	}
	sealed, err := SealCompileReceipt(receipt, signer)
	if err != nil {
		return Compiled{}, err
	}
	return Compiled{Files: files, Receipt: sealed}, nil
}

// ArtifactSetHash derives the artifact references (sorted by path) and the
// set hash binding them: sha256 of the JCS-canonical reference list. The
// result is independent of map iteration order.
func ArtifactSetHash(files map[string][]byte) ([]ArtifactRef, string, error) {
	if len(files) == 0 {
		return nil, "", fmt.Errorf("artifact set must not be empty")
	}
	paths := make([]string, 0, len(files))
	for path := range files {
		if err := validateArtifactPath(path); err != nil {
			return nil, "", err
		}
		paths = append(paths, path)
	}
	sort.Strings(paths)
	refs := make([]ArtifactRef, 0, len(paths))
	for _, path := range paths {
		refs = append(refs, ArtifactRef{Path: path, SHA256: canonicalize.ComputeArtifactHash(files[path])})
	}
	payload, err := canonicalize.JCS(refs)
	if err != nil {
		return nil, "", fmt.Errorf("canonicalize artifact refs: %w", err)
	}
	return refs, canonicalize.ComputeArtifactHash(payload), nil
}

func gatewayDropinPath(in ProfileInput) string {
	return "systemd/" + in.Topology.GatewayUnit + ".d/" + dropinFileName
}

func workloadDropinPath(unit string) string {
	return "systemd/" + unit + ".d/" + dropinFileName
}

func artifactHeader(in ProfileInput) []string {
	return []string{
		fmt.Sprintf("# Boundary Enforcement Profile %s (tier %s).", in.ProfileID, in.ModeTier),
		"# Compiled by `helm-ai-kernel boundary profile compile`. Do not edit: posture drift fails closed.",
	}
}

func emitGatewayDropin(in ProfileInput) []byte {
	h := in.Hardening
	lines := append(artifactHeader(in), "[Service]")
	lines = append(lines, "NoNewPrivileges="+yesNo(h.NoNewPrivileges))
	if h.ProtectSystem != "" {
		lines = append(lines, "ProtectSystem="+h.ProtectSystem)
	}
	lines = append(lines, "PrivateTmp="+yesNo(h.PrivateTmp))
	lines = append(lines, "CapabilityBoundingSet="+h.CapabilityBoundingSet)
	if len(h.RestrictAddressFamilies) > 0 {
		lines = append(lines, "RestrictAddressFamilies="+joinSorted(h.RestrictAddressFamilies))
	}
	if len(h.ReadOnlyPaths) > 0 {
		lines = append(lines, "ReadOnlyPaths="+joinSorted(h.ReadOnlyPaths))
	}
	if in.Resources.CPUMillis > 0 {
		lines = append(lines, fmt.Sprintf("CPUQuota=%d%%", in.Resources.CPUMillis/10))
	}
	if in.Resources.MemoryMB > 0 {
		lines = append(lines, fmt.Sprintf("MemoryMax=%d", in.Resources.MemoryMB<<20))
	}
	if in.Resources.MaxProcesses > 0 {
		lines = append(lines, fmt.Sprintf("TasksMax=%d", in.Resources.MaxProcesses))
	}
	if len(in.DevicePermits) > 0 {
		lines = append(lines, "DevicePolicy=closed")
		for _, permit := range sortedCopy(in.DevicePermits) {
			lines = append(lines, "DeviceAllow="+permit)
		}
	}
	return []byte(strings.Join(lines, "\n") + "\n")
}

// emitWorkloadDropin compiles the sealed topology: the workload unit can
// reach ONLY the HELM gateway endpoint. systemd enforces it (IPAddressDeny/
// IPAddressAllow are cgroup-scoped socket filters; PrivateNetwork is a
// network namespace) — HELM only emits and later attests.
func emitWorkloadDropin(in ProfileInput, unit string) []byte {
	lines := append(artifactHeader(in),
		fmt.Sprintf("# Sealed topology: %s may reach only the HELM gateway.", unit),
		"[Service]",
	)
	switch in.Topology.Gateway.Kind {
	case "tcp":
		host, _, _ := net.SplitHostPort(in.Topology.Gateway.Address)
		lines = append(lines, "IPAddressDeny=any", "IPAddressAllow="+host)
	case "unix":
		lines = append(lines, "PrivateNetwork=yes", "IPAddressDeny=any", "ReadWritePaths="+in.Topology.Gateway.Path)
	}
	return []byte(strings.Join(lines, "\n") + "\n")
}

// emitNftRuleset compiles the egress allowlist into a default-drop nftables
// ruleset. An empty allowlist compiles to pure default-drop (loopback and
// established flows only) — the same fail-closed semantics the gateway's
// EgressChecker already enforces at L7, expressed as OS rules.
//
// The chain priority is written as the named "filter" priority so the file
// form and the `nft list` rendering normalize identically.
func emitNftRuleset(in ProfileInput) []byte {
	lines := append(artifactHeader(in), "")
	lines = append(lines,
		"table "+NftTableName,
		"delete table "+NftTableName,
		"table "+NftTableName+" {",
		"\tchain output {",
		"\t\ttype filter hook output priority filter; policy drop;",
		"\t\toifname \"lo\" accept",
		"\t\tct state established,related accept",
	)
	for _, rule := range buildNftRules(in.Egress.AllowedCIDRs, in.Egress.AllowedProtocols) {
		lines = append(lines, "\t\t"+rule)
	}
	lines = append(lines, "\t}", "}")
	return []byte(strings.Join(lines, "\n") + "\n")
}

// buildNftRules expands CIDR × protocol into deterministic accept rules.
// With no protocols, CIDRs are allowed on any port; with protocols, only the
// mapped L4 ports are allowed (validated to a known mapping at input time).
func buildNftRules(cidrs, protocols []string) []string {
	var rules []string
	for _, cidr := range sortedCopy(cidrs) {
		family := "ip"
		if ip, _, err := net.ParseCIDR(cidr); err == nil && ip.To4() == nil {
			family = "ip6"
		}
		if len(protocols) == 0 {
			rules = append(rules, fmt.Sprintf("%s daddr %s accept", family, cidr))
			continue
		}
		seen := map[string]bool{}
		for _, proto := range sortedCopy(protocols) {
			for _, port := range protocolPorts[proto] {
				rule := fmt.Sprintf("%s daddr %s %s dport %d accept", family, cidr, port.l4, port.port)
				if !seen[rule] {
					seen[rule] = true
					rules = append(rules, rule)
				}
			}
		}
	}
	return rules
}

// NormalizeNftRuleset reduces both the compiled .nft file and live
// `nft list table` output to a comparable canonical body: comments, blank
// lines, brace-only lines, and the table declare/delete preamble drop out;
// each remaining line is whitespace-trimmed with any trailing "{" removed.
func NormalizeNftRuleset(ruleset string) string {
	var keep []string
	for _, line := range strings.Split(ruleset, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		t = strings.TrimSpace(strings.TrimSuffix(t, "{"))
		if t == "" || t == "}" || t == "table "+NftTableName || t == "delete table "+NftTableName {
			continue
		}
		keep = append(keep, t)
	}
	return strings.Join(keep, "\n")
}

func emitExpectedPosture(in ProfileInput, nftRuleset string) ([]byte, error) {
	posture := ExpectedPosture{
		SchemaVersion: ExpectedPostureSchemaVersion,
		ProfileID:     in.ProfileID,
		ModeTier:      in.ModeTier,
		Systemd:       map[string]map[string]string{},
		Nftables: NftExpectation{
			Table:         NftTableName,
			RulesetSHA256: canonicalize.ComputeArtifactHash([]byte(NormalizeNftRuleset(nftRuleset))),
		},
		Cgroup: map[string]map[string]string{},
		GatewayScope: GatewayScope{
			AllowedDomains:  sortedCopy(in.Egress.AllowedDomains),
			DeniedDomains:   sortedCopy(in.Egress.DeniedDomains),
			MaxPayloadBytes: in.Egress.MaxPayloadBytes,
		},
	}
	posture.Systemd[in.Topology.GatewayUnit] = expectedGatewayProps(in)
	for _, unit := range in.Topology.WorkloadUnits {
		posture.Systemd[unit] = expectedWorkloadProps(in)
	}
	if cgroup := expectedCgroupLimits(in); len(cgroup) > 0 {
		posture.Cgroup[in.Topology.GatewayUnit] = cgroup
	}
	payload, err := canonicalize.JCS(posture)
	if err != nil {
		return nil, fmt.Errorf("canonicalize expected posture: %w", err)
	}
	return append(payload, '\n'), nil
}

// expectedGatewayProps stores expectations in the exact string forms
// `systemctl show -p <prop> --value` reports. Humanized durations
// (CPUQuotaPerSecUSec) are deliberately NOT attested through systemd —
// CPU/memory/pids limits are attested via the cgroup filesystem instead.
func expectedGatewayProps(in ProfileInput) map[string]string {
	h := in.Hardening
	props := map[string]string{
		"NoNewPrivileges":       yesNo(h.NoNewPrivileges),
		"PrivateTmp":            yesNo(h.PrivateTmp),
		"CapabilityBoundingSet": h.CapabilityBoundingSet,
	}
	if h.ProtectSystem != "" {
		props["ProtectSystem"] = h.ProtectSystem
	}
	if len(h.RestrictAddressFamilies) > 0 {
		props["RestrictAddressFamilies"] = joinSorted(h.RestrictAddressFamilies)
	}
	if len(h.ReadOnlyPaths) > 0 {
		props["ReadOnlyPaths"] = joinSorted(h.ReadOnlyPaths)
	}
	if len(in.DevicePermits) > 0 {
		props["DevicePolicy"] = "closed"
	}
	if in.Resources.MaxProcesses > 0 {
		props["TasksMax"] = fmt.Sprintf("%d", in.Resources.MaxProcesses)
	}
	if in.Resources.MemoryMB > 0 {
		props["MemoryMax"] = fmt.Sprintf("%d", in.Resources.MemoryMB<<20)
	}
	return props
}

func expectedWorkloadProps(in ProfileInput) map[string]string {
	switch in.Topology.Gateway.Kind {
	case "unix":
		return map[string]string{
			"PrivateNetwork": "yes",
			"IPAddressDeny":  "any",
			"ReadWritePaths": in.Topology.Gateway.Path,
		}
	default:
		host, _, _ := net.SplitHostPort(in.Topology.Gateway.Address)
		return map[string]string{
			"IPAddressDeny":  "any",
			"IPAddressAllow": host,
		}
	}
}

// expectedCgroupLimits pins resource limits at the cgroup-v2 filesystem,
// where values are raw integers ("536870912", "128", "50000 100000") and
// immune to systemd's humanized property rendering.
func expectedCgroupLimits(in ProfileInput) map[string]string {
	limits := map[string]string{}
	if in.Resources.MemoryMB > 0 {
		limits["memory.max"] = fmt.Sprintf("%d", in.Resources.MemoryMB<<20)
	}
	if in.Resources.MaxProcesses > 0 {
		limits["pids.max"] = fmt.Sprintf("%d", in.Resources.MaxProcesses)
	}
	if in.Resources.CPUMillis > 0 {
		limits["cpu.max"] = fmt.Sprintf("%d 100000", in.Resources.CPUMillis*100)
	}
	return limits
}

func signerKeyID(signer crypto.Signer) string {
	if ider, ok := signer.(interface{ GetKeyID() string }); ok {
		return ider.GetKeyID()
	}
	return ""
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func sortedCopy(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}

func joinSorted(values []string) string {
	return strings.Join(sortedCopy(values), " ")
}

func validateArtifactPath(path string) error {
	if path == "" || strings.HasPrefix(path, "/") || strings.Contains(path, "\\") {
		return fmt.Errorf("artifact path %q must be relative with forward slashes", path)
	}
	for _, part := range strings.Split(path, "/") {
		if part == "" || part == "." || part == ".." {
			return fmt.Errorf("artifact path %q must be clean (no empty, . or .. segments)", path)
		}
	}
	return nil
}
