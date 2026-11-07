package pack

import (
	"testing"
)

func TestCoverageCompatibilityMatrix(t *testing.T) {
	matrix := &CompatibilityMatrix{
		Entries: []CompatibilityEntry{{
			ComponentA: "kernel",
			VersionA:   ">=1.0.0 <2.0.0",
			ComponentB: "sdk-go",
			VersionB:   "^1.4.0",
			Status:     CompatFull,
		}},
	}

	if got := matrix.IsCompatible("kernel", "1.5.0", "sdk-go", "1.4.3"); got != CompatFull {
		t.Fatalf("forward compatibility = %s, want %s", got, CompatFull)
	}
	if got := matrix.IsCompatible("sdk-go", "1.4.3", "kernel", "1.5.0"); got != CompatFull {
		t.Fatalf("reverse compatibility = %s, want %s", got, CompatFull)
	}
	if got := matrix.IsCompatible("kernel", "2.0.0", "sdk-go", "1.4.3"); got != CompatUntested {
		t.Fatalf("version mismatch compatibility = %s, want %s", got, CompatUntested)
	}
	if got := matrix.IsCompatible("kernel", "1.5.0", "sdk-ts", "1.4.3"); got != CompatUntested {
		t.Fatalf("component mismatch compatibility = %s, want %s", got, CompatUntested)
	}

	if matchesConstraint("not a constraint", "1.0.0") {
		t.Fatal("invalid constraint should not match")
	}
	if matchesConstraint(">=1.0.0", "not-semver") {
		t.Fatal("invalid version should not match")
	}
}
