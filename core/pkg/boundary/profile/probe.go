package profile

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// The provider seam mirrors launchpad/runtime's DockerInfoProvider pattern:
// plain function types, injectable for deterministic tests, with the live
// implementations doing the actual OS reads. Probe failures are errors, never
// fabricated MATCH values — the attestor fails closed on an unreadable OS.
type (
	// SystemdPropsProvider returns the requested unit properties in the
	// exact string forms `systemctl show` reports.
	SystemdPropsProvider func(unit string, props []string) (map[string]string, error)
	// NftRulesetProvider returns the live rendering of the given nftables
	// table (the `nft list table <table>` output).
	NftRulesetProvider func(table string) (string, error)
	// CgroupLimitsProvider reads the requested cgroup-v2 interface files for
	// a unit's cgroup (raw values, trailing whitespace trimmed).
	CgroupLimitsProvider func(unit string, files []string) (map[string]string, error)
)

// Prober bundles the three live-posture read seams.
type Prober struct {
	SystemdProps SystemdPropsProvider
	NftRuleset   NftRulesetProvider
	CgroupLimits CgroupLimitsProvider
}

// Absolute binary paths: probes exec argv directly (no shell, no PATH
// lookup). If a binary is missing the probe errors and attestation fails
// closed. ponytail: fixed paths; make them configurable when a real target
// needs it.
const (
	systemctlBin = "/usr/bin/systemctl"
	nftBin       = "/usr/sbin/nft"
	cgroupRoot   = "/sys/fs/cgroup/system.slice"
)

// LiveProber reads the real OS. It compiles everywhere but only functions on
// a systemd/nftables Linux host; anywhere else the probes error, which the
// attestor treats as fail-closed. Reading the live nftables ruleset requires
// CAP_NET_ADMIN — the reference deployment runs attestation in a dedicated
// short-lived privileged oneshot unit, never in the gateway process.
func LiveProber() Prober {
	return Prober{
		SystemdProps: liveSystemdProps,
		NftRuleset:   liveNftRuleset,
		CgroupLimits: liveCgroupLimits,
	}
}

func liveSystemdProps(unit string, props []string) (map[string]string, error) {
	if !validUnitName.MatchString(unit) {
		return nil, fmt.Errorf("refusing to probe invalid unit name %q", unit)
	}
	args := []string{"show", unit}
	for _, prop := range props {
		args = append(args, "--property="+prop)
	}
	out, err := exec.Command(systemctlBin, args...).Output()
	if err != nil {
		return nil, fmt.Errorf("systemctl show %s: %w", unit, err)
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		if key, value, ok := strings.Cut(line, "="); ok {
			values[key] = value
		}
	}
	return values, nil
}

func liveNftRuleset(table string) (string, error) {
	parts := strings.Fields(table)
	if len(parts) != 2 {
		return "", fmt.Errorf("nftables table %q must be \"<family> <name>\"", table)
	}
	out, err := exec.Command(nftBin, "list", "table", parts[0], parts[1]).Output()
	if err != nil {
		return "", fmt.Errorf("nft list table %s: %w", table, err)
	}
	return string(out), nil
}

func liveCgroupLimits(unit string, files []string) (map[string]string, error) {
	if !validUnitName.MatchString(unit) {
		return nil, fmt.Errorf("refusing to probe invalid unit name %q", unit)
	}
	values := map[string]string{}
	for _, file := range files {
		if file == "" || strings.ContainsAny(file, "/\\") {
			return nil, fmt.Errorf("refusing to read invalid cgroup file %q", file)
		}
		raw, err := os.ReadFile(filepath.Join(cgroupRoot, unit, file))
		if err != nil {
			return nil, fmt.Errorf("read cgroup %s for %s: %w", file, unit, err)
		}
		values[file] = strings.TrimSpace(string(raw))
	}
	return values, nil
}
