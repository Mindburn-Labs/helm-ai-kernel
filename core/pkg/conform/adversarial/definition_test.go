package adversarial

import "testing"

func TestDefinitionBindsEveryMandatorySuiteToItsMutationAndDetectorTest(t *testing.T) {
	definition, err := Definition()
	if err != nil {
		t.Fatalf("Definition: %v", err)
	}
	if definition.Revision != DetectorRevision {
		t.Fatalf("revision = %q, want %q", definition.Revision, DetectorRevision)
	}
	if len(definition.Suites) != 10 {
		t.Fatalf("suite count = %d, want 10", len(definition.Suites))
	}
	for index, suite := range definition.Suites {
		if suite.SuiteID == "" || suite.Name == "" || suite.MutationID == "" || suite.ExpectedTestID == "" {
			t.Fatalf("suite %d has an incomplete definition: %+v", index, suite)
		}
	}

	// Definition must not expose shared mutable state to callers.
	definition.Suites[0].MutationID = "caller-mutated"
	fresh, err := Definition()
	if err != nil {
		t.Fatalf("second Definition: %v", err)
	}
	if fresh.Suites[0].MutationID == "caller-mutated" {
		t.Fatal("Definition returned shared mutable state")
	}
}

func TestDefinitionDigestIsSourceOwnedCompatibilityKey(t *testing.T) {
	digest, err := DefinitionDigest()
	if err != nil {
		t.Fatalf("DefinitionDigest: %v", err)
	}
	const want = "sha256:224cef33fe624f734f168d0974366ffed325815024204135f168516b179a6138"
	if digest != want {
		t.Fatalf("definition digest = %q, want %q; bump DetectorRevision and update this compatibility fixture for intentional detector changes", digest, want)
	}
}
