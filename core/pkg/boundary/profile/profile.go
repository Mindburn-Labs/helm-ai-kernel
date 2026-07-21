// Package profile compiles Boundary Enforcement Profiles: OS-enforcement
// artifacts (systemd hardening drop-ins, an nftables egress ruleset, cgroup
// resource limits, device permits) derived from governed policy inputs, plus
// signed compile receipts and live posture attestation.
//
// Doctrine invariant: HELM never executes isolation. This package COMPILES
// enforcement artifacts from policy, the appliance OS (systemd/nftables)
// applies and enforces them, and the posture attestor proves the live OS
// state matches the compiled artifacts — failing closed on drift. Nothing in
// this package runs in the kernel verdict path.
//
// "Quarantine" (core/pkg/mcp — a governance state over tool/server approval)
// is deliberately distinct from the OS containment compiled here, which is
// always called the Boundary Enforcement Profile.
//
// Record types live in this package rather than core/pkg/contracts because
// contracts is a protected path; the signing pattern deliberately mirrors
// contracts.LaunchProviderCertificationRecord (RFC 8785 JCS payload,
// sha256:-prefixed record hash, ed25519:-prefixed signature, offline verify).
//
// The profile input is hash-bound into the compile receipt. No canonical
// signed policy-bundle record contract exists yet as a compiler input (the
// closest signature precedent is policy/reconcile.Ed25519PolicyVerifier,
// which verifies reconciler bundle signatures); when such a contract lands,
// signed-input verification slots in ahead of Compile — binding to that
// verifier pattern — without changing the receipt format.
//
// quantum_posture: boundary profile records use classical Ed25519 signatures;
// this preview contract makes no hybrid or post-quantum claim.
package profile

import (
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/firewall"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/sandbox"
)

const (
	// ProfileInputSchemaVersion identifies the profile input document format.
	ProfileInputSchemaVersion = "boundary_profile_input.v1"

	// Mode tiers are validated locally: the repo has no unified mode-ladder
	// enum, and this package must not invent one in a protected surface.
	// TierObserve compiles the same artifacts but marks the profile as
	// non-gating; TierEnforce is the sealed-appliance posture.
	TierObserve = "observe"
	TierEnforce = "enforce"
)

// GatewayEndpoint describes how workloads reach the HELM gateway — the only
// egress path the sealed topology leaves open to them.
type GatewayEndpoint struct {
	Kind    string `json:"kind"`              // "tcp" | "unix"
	Address string `json:"address,omitempty"` // "ip:port" when kind=tcp
	Path    string `json:"path,omitempty"`    // absolute socket path when kind=unix
}

// Topology names the systemd units the profile governs.
type Topology struct {
	GatewayUnit   string          `json:"gateway_unit"`
	WorkloadUnits []string        `json:"workload_units"`
	Gateway       GatewayEndpoint `json:"gateway"`
}

// HardeningOptions mirrors the sandbox Docker runner posture (cap-drop ALL,
// no-new-privileges, read-only, private tmp — core/pkg/sandbox/docker) in
// systemd terms. The zero value of CapabilityBoundingSet means drop all
// capabilities (fail-closed direction).
type HardeningOptions struct {
	NoNewPrivileges         bool     `json:"no_new_privileges"`
	ProtectSystem           string   `json:"protect_system"` // "" (omit) | "yes" | "full" | "strict"
	PrivateTmp              bool     `json:"private_tmp"`
	CapabilityBoundingSet   string   `json:"capability_bounding_set"`
	RestrictAddressFamilies []string `json:"restrict_address_families"`
	ReadOnlyPaths           []string `json:"read_only_paths"`
}

// ProfileInput is the policy input document a Boundary Enforcement Profile is
// compiled from. It is hash-bound into the compile receipt via Hash.
type ProfileInput struct {
	SchemaVersion string                 `json:"schema_version"`
	ProfileID     string                 `json:"profile_id"`
	ModeTier      string                 `json:"mode_tier"`
	Topology      Topology               `json:"topology"`
	Egress        firewall.EgressPolicy  `json:"egress"`
	Resources     sandbox.ResourceLimits `json:"resources"`
	Hardening     HardeningOptions       `json:"hardening"`
	DevicePermits []string               `json:"device_permits"` // systemd DeviceAllow= values, e.g. "/dev/nvidia0 rw"

	// EgressDomainsGatewayOnly acknowledges that AllowedDomains are enforced
	// only by the gateway's L7 egress checker: domain names cannot become
	// nftables (L3/L4) rules. Without this acknowledgment, a policy that
	// allows domains but no CIDRs is a contradiction — the compiled OS
	// ruleset would deny-all traffic the L7 policy intends to allow — and
	// compilation fails closed.
	EgressDomainsGatewayOnly bool `json:"egress_domains_gateway_only,omitempty"`
}

// DefaultHardening is the sealed-appliance baseline: the systemd equivalent
// of the Docker runner's unconditional security block.
func DefaultHardening() HardeningOptions {
	return HardeningOptions{
		NoNewPrivileges:         true,
		ProtectSystem:           "strict",
		PrivateTmp:              true,
		CapabilityBoundingSet:   "",
		RestrictAddressFamilies: []string{"AF_INET", "AF_INET6", "AF_UNIX"},
	}
}

var (
	validProfileID    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	validUnitName     = regexp.MustCompile(`^[A-Za-z0-9@:._\-]+\.service$`)
	validDevicePermit = regexp.MustCompile(`^/dev/[A-Za-z0-9/._\-*]+ [rwm]{1,3}$`)
)

// nftPort maps a gateway-level protocol name onto the L4 rule the nftables
// emitter can honestly enforce. Unknown protocol names are a compile error
// (fail closed) — the OS layer never silently widens.
type nftPort struct {
	l4   string
	port int
}

var protocolPorts = map[string][]nftPort{
	"https": {{l4: "tcp", port: 443}},
	"http":  {{l4: "tcp", port: 80}},
	"grpc":  {{l4: "tcp", port: 443}},
	"dns":   {{l4: "tcp", port: 53}, {l4: "udp", port: 53}},
	"ntp":   {{l4: "udp", port: 123}},
	"ssh":   {{l4: "tcp", port: 22}},
}

// Validate fail-closed checks the input document. Anything ambiguous or
// unknown is an error, never a silently-widened profile.
func (in ProfileInput) Validate() error {
	if in.SchemaVersion != ProfileInputSchemaVersion {
		return fmt.Errorf("profile input schema_version must be %q", ProfileInputSchemaVersion)
	}
	if !validProfileID.MatchString(in.ProfileID) {
		return fmt.Errorf("profile_id must match %s", validProfileID.String())
	}
	switch in.ModeTier {
	case TierObserve, TierEnforce:
	default:
		return fmt.Errorf("mode_tier must be %q or %q", TierObserve, TierEnforce)
	}
	if err := in.Topology.validate(); err != nil {
		return err
	}
	if err := validateEgress(in.Egress); err != nil {
		return err
	}
	if len(in.Egress.AllowedDomains) > 0 && len(in.Egress.AllowedCIDRs) == 0 && !in.EgressDomainsGatewayOnly {
		return fmt.Errorf("egress allows domains but no CIDRs: the OS ruleset would deny what the gateway policy allows; supply allowed_cidrs or set egress_domains_gateway_only to acknowledge gateway-only domain enforcement")
	}
	if err := validateResources(in.Resources); err != nil {
		return err
	}
	if err := in.Hardening.validate(); err != nil {
		return err
	}
	if in.ModeTier == TierEnforce {
		// A zero-value or omitted hardening block would otherwise compile
		// NoNewPrivileges=no / no ProtectSystem with no operator intent —
		// the exact silent weakening this profile exists to prevent.
		if !in.Hardening.NoNewPrivileges {
			return fmt.Errorf("mode_tier %q requires hardening.no_new_privileges = true", TierEnforce)
		}
		switch in.Hardening.ProtectSystem {
		case "full", "strict":
		default:
			return fmt.Errorf("mode_tier %q requires hardening.protect_system to be \"full\" or \"strict\"", TierEnforce)
		}
	}
	for _, permit := range in.DevicePermits {
		if !validDevicePermit.MatchString(permit) {
			return fmt.Errorf("device permit %q must match %s", permit, validDevicePermit.String())
		}
		// The regex alone would accept "/dev/../proc/kcore rw"; permits must
		// stay under /dev, so reject traversal and empty segments outright.
		node, _, _ := strings.Cut(permit, " ")
		for _, part := range strings.Split(strings.TrimPrefix(node, "/"), "/") {
			if part == "" || part == "." || part == ".." {
				return fmt.Errorf("device permit %q must be a clean path under /dev", permit)
			}
		}
	}
	return nil
}

func (t Topology) validate() error {
	if !validUnitName.MatchString(t.GatewayUnit) {
		return fmt.Errorf("gateway_unit %q must be a .service unit name", t.GatewayUnit)
	}
	seen := map[string]bool{t.GatewayUnit: true}
	for _, unit := range t.WorkloadUnits {
		if !validUnitName.MatchString(unit) {
			return fmt.Errorf("workload unit %q must be a .service unit name", unit)
		}
		if seen[unit] {
			return fmt.Errorf("unit %q appears more than once in topology", unit)
		}
		seen[unit] = true
	}
	switch t.Gateway.Kind {
	case "tcp":
		if t.Gateway.Path != "" {
			return fmt.Errorf("tcp gateway endpoint must not set path")
		}
		host, port, err := net.SplitHostPort(t.Gateway.Address)
		if err != nil {
			return fmt.Errorf("tcp gateway address %q must be ip:port: %w", t.Gateway.Address, err)
		}
		if _, err := netip.ParseAddr(host); err != nil {
			return fmt.Errorf("tcp gateway address host %q must be a literal IP (needed for IPAddressAllow=)", host)
		}
		portNum, err := strconv.Atoi(port)
		if err != nil || portNum < 1 || portNum > 65535 {
			return fmt.Errorf("tcp gateway address %q must carry a port in 1-65535", t.Gateway.Address)
		}
	case "unix":
		if t.Gateway.Address != "" {
			return fmt.Errorf("unix gateway endpoint must not set address")
		}
		if !strings.HasPrefix(t.Gateway.Path, "/") {
			return fmt.Errorf("unix gateway socket path %q must be absolute", t.Gateway.Path)
		}
	default:
		return fmt.Errorf("gateway endpoint kind must be \"tcp\" or \"unix\"")
	}
	return nil
}

func validateEgress(p firewall.EgressPolicy) error {
	for _, cidr := range p.AllowedCIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("egress allowed CIDR %q is invalid: %w", cidr, err)
		}
	}
	for _, proto := range p.AllowedProtocols {
		if _, ok := protocolPorts[proto]; !ok {
			return fmt.Errorf("egress protocol %q has no OS-level port mapping; supported: %s", proto, strings.Join(knownProtocols(), ", "))
		}
	}
	if p.MaxPayloadBytes < 0 {
		return fmt.Errorf("egress max_payload_bytes must not be negative")
	}
	return nil
}

// Upper bounds keep the compiler's arithmetic (MemoryMB<<20, CPUMillis*100)
// far below an int64 overflow, which would otherwise emit negative or
// wrapped systemd/cgroup limits. The ceilings are orders of magnitude above
// any real appliance.
const (
	maxCPUMillis    = 1_000_000 // 1000 CPUs
	maxMemoryMB     = 1 << 26   // 64 TiB
	maxDiskMB       = 1 << 26   // 64 TiB
	maxMaxProcesses = 1 << 22   // ~4M PIDs
)

func validateResources(r sandbox.ResourceLimits) error {
	if r.CPUMillis < 0 || r.MemoryMB < 0 || r.DiskMB < 0 || r.MaxProcesses < 0 || r.Timeout < 0 {
		return fmt.Errorf("resource limits must not be negative")
	}
	if r.CPUMillis%10 != 0 {
		return fmt.Errorf("cpu_millis must be a multiple of 10 (compiles to an integer CPUQuota percent)")
	}
	for _, limit := range []struct {
		field string
		value int64
		max   int64
	}{
		{"cpu_millis", r.CPUMillis, maxCPUMillis},
		{"memory_mb", r.MemoryMB, maxMemoryMB},
		{"disk_mb", r.DiskMB, maxDiskMB},
		{"max_processes", int64(r.MaxProcesses), maxMaxProcesses},
	} {
		if limit.value > limit.max {
			return fmt.Errorf("%s must not exceed %d", limit.field, limit.max)
		}
	}
	return nil
}

func (h HardeningOptions) validate() error {
	switch h.ProtectSystem {
	case "", "yes", "full", "strict":
	default:
		return fmt.Errorf("protect_system must be one of \"\", \"yes\", \"full\", \"strict\"")
	}
	for _, family := range h.RestrictAddressFamilies {
		if !strings.HasPrefix(family, "AF_") {
			return fmt.Errorf("restrict_address_families entry %q must be an AF_* name", family)
		}
	}
	for _, path := range h.ReadOnlyPaths {
		if !strings.HasPrefix(path, "/") {
			return fmt.Errorf("read_only_paths entry %q must be absolute", path)
		}
	}
	return nil
}

// Hash returns the sha256:-prefixed hash of the JCS-canonical input document.
// This is the policy_input_hash bound into the compile receipt.
func (in ProfileInput) Hash() (string, error) {
	if err := in.Validate(); err != nil {
		return "", err
	}
	payload, err := canonicalize.JCS(in)
	if err != nil {
		return "", fmt.Errorf("canonicalize profile input: %w", err)
	}
	return canonicalize.ComputeArtifactHash(payload), nil
}

func knownProtocols() []string {
	names := make([]string, 0, len(protocolPorts))
	for name := range protocolPorts {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
