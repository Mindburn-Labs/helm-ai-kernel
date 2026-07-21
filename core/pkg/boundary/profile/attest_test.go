package profile

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func compiledFixture(t *testing.T) (Compiled, ExpectedPosture) {
	t.Helper()
	compiled, err := Compile(fixtureInput(), testSigner(t), testCompileOptions())
	if err != nil {
		t.Fatal(err)
	}
	var posture ExpectedPosture
	if err := json.Unmarshal(compiled.Files[posturePath], &posture); err != nil {
		t.Fatal(err)
	}
	return compiled, posture
}

// proberFromExpected mirrors the compiled expectations perfectly — the
// "healthy sealed box" prober.
func proberFromExpected(posture ExpectedPosture, nftBody string) Prober {
	return Prober{
		SystemdProps: func(unit string, props []string) (map[string]string, error) {
			values := map[string]string{}
			for _, prop := range props {
				values[prop] = posture.Systemd[unit][prop]
			}
			return values, nil
		},
		NftRuleset: func(table string) (string, error) { return nftBody, nil },
		CgroupLimits: func(unit string, files []string) (map[string]string, error) {
			values := map[string]string{}
			for _, file := range files {
				values[file] = posture.Cgroup[unit][file]
			}
			return values, nil
		},
	}
}

func testAttestOptions() AttestOptions {
	return AttestOptions{ObservedAt: time.Date(2026, 7, 21, 0, 5, 0, 0, time.UTC)}
}

func TestAttestMatchOnHealthyBox(t *testing.T) {
	compiled, posture := compiledFixture(t)
	prober := proberFromExpected(posture, string(compiled.Files[nftFilePath]))
	attestation, err := Attest(compiled.Receipt, compiled.Files, prober, testSigner(t), testAttestOptions())
	if err != nil {
		t.Fatal(err)
	}
	if attestation.Verdict != VerdictMatch {
		t.Fatalf("healthy box must attest MATCH, got %s: %+v", attestation.Verdict, attestation.Checks)
	}
	if !GateDispatch(attestation) {
		t.Fatal("MATCH attestation must gate open")
	}
	if attestation.ReceiptHash != compiled.Receipt.RecordHash {
		t.Fatal("attestation must bind the receipt record hash")
	}
	if err := VerifyPostureAttestation(attestation, testSigner(t).PublicKeyBytes()); err != nil {
		t.Fatalf("sealed attestation must verify: %v", err)
	}
}

// TestLoosenedRuleFailsClosed is the payload assertion of the whole
// subsystem: a single loosened OS rule must produce DRIFT with the diff
// recorded, and the gate must close.
func TestLoosenedRuleFailsClosed(t *testing.T) {
	compiled, posture := compiledFixture(t)
	prober := proberFromExpected(posture, string(compiled.Files[nftFilePath]))
	prober.SystemdProps = func(unit string, props []string) (map[string]string, error) {
		values := map[string]string{}
		for _, prop := range props {
			values[prop] = posture.Systemd[unit][prop]
		}
		if unit == "helm-gateway.service" {
			values["NoNewPrivileges"] = "no" // the loosened rule
		}
		return values, nil
	}
	attestation, err := Attest(compiled.Receipt, compiled.Files, prober, testSigner(t), testAttestOptions())
	if err != nil {
		t.Fatalf("a clean probe of a drifted box is not a probe error: %v", err)
	}
	if attestation.Verdict != VerdictDrift {
		t.Fatalf("loosened rule must attest DRIFT, got %s", attestation.Verdict)
	}
	var diff *PostureCheck
	for i := range attestation.Checks {
		if attestation.Checks[i].Property == "NoNewPrivileges" && attestation.Checks[i].Result == CheckFail {
			diff = &attestation.Checks[i]
		}
	}
	if diff == nil {
		t.Fatalf("DRIFT must record the failing check, got %+v", attestation.Checks)
	}
	if diff.Expected != "yes" || diff.Observed != "no" {
		t.Fatalf("drift diff must carry both sides, got %+v", diff)
	}
	if GateDispatch(attestation) {
		t.Fatal("DRIFT attestation must gate closed")
	}
	if err := VerifyPostureAttestation(attestation, testSigner(t).PublicKeyBytes()); err != nil {
		t.Fatalf("DRIFT evidence must still seal and verify: %v", err)
	}
}

// TestGateDispatchRejectsForgedShapes pins that the gate validates the whole
// record, not just two fields: a hand-built MATCH carrying failed checks, or
// an otherwise malformed record, must gate closed.
func TestGateDispatchRejectsForgedShapes(t *testing.T) {
	compiled, posture := compiledFixture(t)
	good, err := Attest(compiled.Receipt, compiled.Files, proberFromExpected(posture, string(compiled.Files[nftFilePath])), testSigner(t), testAttestOptions())
	if err != nil {
		t.Fatal(err)
	}
	if !GateDispatch(good) {
		t.Fatal("a sealed MATCH must gate open")
	}
	for name, mutate := range map[string]func(*PostureAttestation){
		"match with failed check": func(a *PostureAttestation) {
			a.Checks = append(a.Checks, PostureCheck{Target: "systemd:x", Property: "NoNewPrivileges", Expected: "yes", Observed: "no", Result: CheckFail})
		},
		"no checks at all":     func(a *PostureAttestation) { a.Checks = nil },
		"unknown verdict":      func(a *PostureAttestation) { a.Verdict = "PROBABLY" },
		"receipt hash cleared": func(a *PostureAttestation) { a.ReceiptHash = "" },
		"record hash cleared":  func(a *PostureAttestation) { a.RecordHash = "" },
	} {
		forged := good
		forged.Checks = append([]PostureCheck(nil), good.Checks...)
		mutate(&forged)
		if GateDispatch(forged) {
			t.Fatalf("%s must gate closed", name)
		}
	}
}

func TestLoosenedNftRulesetDrifts(t *testing.T) {
	compiled, posture := compiledFixture(t)
	loosened := strings.Replace(string(compiled.Files[nftFilePath]),
		"ct state established,related accept",
		"ct state established,related accept\n\t\tip daddr 0.0.0.0/0 accept", 1)
	attestation, err := Attest(compiled.Receipt, compiled.Files, proberFromExpected(posture, loosened), testSigner(t), testAttestOptions())
	if err != nil {
		t.Fatal(err)
	}
	if attestation.Verdict != VerdictDrift || GateDispatch(attestation) {
		t.Fatalf("widened ruleset must attest DRIFT and gate closed, got %s", attestation.Verdict)
	}
}

func TestAttestNormalizesIPAddressPrefixes(t *testing.T) {
	compiled, posture := compiledFixture(t)
	prober := proberFromExpected(posture, string(compiled.Files[nftFilePath]))
	base := prober.SystemdProps
	prober.SystemdProps = func(unit string, props []string) (map[string]string, error) {
		values, err := base(unit, props)
		if err != nil {
			return nil, err
		}
		if unit == "orchestrator.service" {
			values["IPAddressAllow"] = "127.0.0.1/32" // systemd's rendered form
		}
		return values, nil
	}
	attestation, err := Attest(compiled.Receipt, compiled.Files, prober, testSigner(t), testAttestOptions())
	if err != nil {
		t.Fatal(err)
	}
	if attestation.Verdict != VerdictMatch {
		t.Fatalf("prefix-normalized address must MATCH, got %+v", attestation.Checks)
	}
}

func TestAttestNftListRenderingMatches(t *testing.T) {
	compiled, posture := compiledFixture(t)
	attestation, err := Attest(compiled.Receipt, compiled.Files, proberFromExpected(posture, nftListRendering), testSigner(t), testAttestOptions())
	if err != nil {
		t.Fatal(err)
	}
	if attestation.Verdict != VerdictMatch {
		t.Fatalf("nft list rendering must normalize to MATCH, got %+v", attestation.Checks)
	}
}

func TestProbeErrorNeverAttestsMatch(t *testing.T) {
	compiled, posture := compiledFixture(t)
	prober := proberFromExpected(posture, string(compiled.Files[nftFilePath]))
	prober.NftRuleset = func(string) (string, error) { return "", errors.New("nft: command not found") }
	attestation, err := Attest(compiled.Receipt, compiled.Files, prober, testSigner(t), testAttestOptions())
	if err == nil {
		t.Fatal("probe error must surface as an error")
	}
	if attestation.Verdict == VerdictMatch || GateDispatch(attestation) {
		t.Fatal("probe error must never attest MATCH or gate open")
	}
	found := false
	for _, check := range attestation.Checks {
		if check.Target == "nftables" && check.Property == "probe" && check.Result == CheckFail {
			found = true
		}
	}
	if !found {
		t.Fatalf("probe failure must be recorded as a failing check: %+v", attestation.Checks)
	}
}

func TestArtifactTamperIsHardErrorNotDrift(t *testing.T) {
	compiled, posture := compiledFixture(t)
	tampered := map[string][]byte{}
	for path, content := range compiled.Files {
		tampered[path] = append([]byte(nil), content...)
	}
	tampered[nftFilePath] = append(tampered[nftFilePath], []byte("# loosened\n")...)
	_, err := Attest(compiled.Receipt, tampered, proberFromExpected(posture, string(tampered[nftFilePath])), testSigner(t), testAttestOptions())
	if err == nil || !strings.Contains(err.Error(), "modified after compile") {
		t.Fatalf("tampered artifacts must be a hard error, got %v", err)
	}
}

func TestAttestDeterministicAndUnsignedSealing(t *testing.T) {
	compiled, posture := compiledFixture(t)
	prober := proberFromExpected(posture, string(compiled.Files[nftFilePath]))
	first, err := Attest(compiled.Receipt, compiled.Files, prober, testSigner(t), testAttestOptions())
	if err != nil {
		t.Fatal(err)
	}
	second, err := Attest(compiled.Receipt, compiled.Files, prober, testSigner(t), testAttestOptions())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("identical attest runs must produce identical records")
	}

	unsigned, err := Attest(compiled.Receipt, compiled.Files, prober, nil, testAttestOptions())
	if err != nil {
		t.Fatal(err)
	}
	if unsigned.RecordHash == "" || unsigned.Signature != "" {
		t.Fatalf("unsigned attestation must be hash-sealed without a signature: %+v", unsigned)
	}
	if err := VerifyPostureAttestation(unsigned, nil); err != nil {
		t.Fatalf("hash-sealed attestation must verify without a key: %v", err)
	}
	unsigned.Verdict = VerdictDrift
	if err := VerifyPostureAttestation(unsigned, nil); err == nil {
		t.Fatal("tampered verdict must fail hash verification")
	}
}
