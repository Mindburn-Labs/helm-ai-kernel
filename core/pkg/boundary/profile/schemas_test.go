package profile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v5"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/profile/updatebundle"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

func schemasDir(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		candidate := filepath.Join(dir, "protocols", "json-schemas", "boundary")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate protocols/json-schemas/boundary above the working directory")
		}
		dir = parent
	}
}

func compileBoundarySchema(t *testing.T, name string) *jsonschema.Schema {
	t.Helper()
	path := filepath.Join(schemasDir(t), name)
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	url := "https://schemas.helm.ai/boundary/" + name
	if err := compiler.AddResource(url, strings.NewReader(string(payload))); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile(url)
	if err != nil {
		t.Fatalf("compile schema %s: %v", name, err)
	}
	return schema
}

func validateAgainst(t *testing.T, schema *jsonschema.Schema, record any) error {
	t.Helper()
	payload, err := canonicalize.JCS(record)
	if err != nil {
		t.Fatal(err)
	}
	var decoded any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatal(err)
	}
	return schema.Validate(decoded)
}

// TestBoundaryProfileSchemas binds the Go record shapes — including the
// operator-authored input, whose embedded firewall/sandbox structs live in
// unprotected packages — to the protocols/ schemas. Upstream struct drift
// breaks this test loudly instead of silently changing the wire contract.
func TestBoundaryProfileSchemas(t *testing.T) {
	compiled, _ := compiledFixture(t)
	prober := proberFromExpected(mustExpectedPosture(t, compiled), string(compiled.Files[nftFilePath]))
	match, err := Attest(compiled.Receipt, compiled.Files, prober, testSigner(t), testAttestOptions())
	if err != nil {
		t.Fatal(err)
	}
	drifted := proberFromExpected(mustExpectedPosture(t, compiled), string(compiled.Files[nftFilePath]))
	base := drifted.SystemdProps
	drifted.SystemdProps = func(unit string, props []string) (map[string]string, error) {
		values, err := base(unit, props)
		if err != nil {
			return nil, err
		}
		if unit == "helm-gateway.service" {
			values["NoNewPrivileges"] = "no"
		}
		return values, nil
	}
	drift, err := Attest(compiled.Receipt, compiled.Files, drifted, nil, testAttestOptions())
	if err != nil {
		t.Fatal(err)
	}

	inputSchema := compileBoundarySchema(t, "boundary_profile_input.v1.schema.json")
	receiptSchema := compileBoundarySchema(t, "profile_compile_receipt.v1.schema.json")
	attestationSchema := compileBoundarySchema(t, "posture_attestation.v1.schema.json")

	if err := validateAgainst(t, inputSchema, fixtureInput()); err != nil {
		t.Fatalf("profile input must validate against its schema: %v", err)
	}
	if err := validateAgainst(t, receiptSchema, compiled.Receipt); err != nil {
		t.Fatalf("compile receipt must validate against its schema: %v", err)
	}
	if err := validateAgainst(t, attestationSchema, match); err != nil {
		t.Fatalf("MATCH attestation must validate against its schema: %v", err)
	}
	if err := validateAgainst(t, attestationSchema, drift); err != nil {
		t.Fatalf("unsigned DRIFT attestation must validate against its schema: %v", err)
	}

	var extra map[string]any
	payload, _ := canonicalize.JCS(compiled.Receipt)
	if err := json.Unmarshal(payload, &extra); err != nil {
		t.Fatal(err)
	}
	extra["unknown_field"] = "x"
	if err := receiptSchema.Validate(extra); err == nil {
		t.Fatal("schema must reject unknown fields")
	}
}

// TestSchemasRejectWhatGoRejects keeps schema strictness aligned with the Go
// validators: tooling that only checks the schema must not accept documents
// the kernel fails closed on.
func TestSchemasRejectWhatGoRejects(t *testing.T) {
	inputSchema := compileBoundarySchema(t, "boundary_profile_input.v1.schema.json")
	receiptSchema := compileBoundarySchema(t, "profile_compile_receipt.v1.schema.json")

	decode := func(v any) map[string]any {
		payload, err := canonicalize.JCS(v)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(payload, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}

	t.Run("gateway endpoint kind conditionals", func(t *testing.T) {
		for name, mutate := range map[string]func(map[string]any){
			"tcp without address": func(m map[string]any) {
				m["topology"].(map[string]any)["gateway"] = map[string]any{"kind": "tcp"}
			},
			"tcp carrying path": func(m map[string]any) {
				m["topology"].(map[string]any)["gateway"] = map[string]any{"kind": "tcp", "address": "127.0.0.1:7714", "path": "/run/helm.sock"}
			},
			"unix without path": func(m map[string]any) {
				m["topology"].(map[string]any)["gateway"] = map[string]any{"kind": "unix"}
			},
			"unix carrying address": func(m map[string]any) {
				m["topology"].(map[string]any)["gateway"] = map[string]any{"kind": "unix", "path": "/run/helm.sock", "address": "127.0.0.1:7714"}
			},
		} {
			doc := decode(fixtureInput())
			mutate(doc)
			if err := inputSchema.Validate(doc); err == nil {
				t.Fatalf("%s must be rejected by the schema", name)
			}
		}
	})

	t.Run("tcp address must be a literal ip:port", func(t *testing.T) {
		for _, bad := range []string{"gateway.local:7714", "127.0.0.1", "not-an-address"} {
			doc := decode(fixtureInput())
			doc["topology"].(map[string]any)["gateway"] = map[string]any{"kind": "tcp", "address": bad}
			if err := inputSchema.Validate(doc); err == nil {
				t.Fatalf("gateway address %q must be rejected by the schema", bad)
			}
		}
	})

	t.Run("domains without cidrs need the acknowledgment", func(t *testing.T) {
		in := fixtureInput()
		in.Egress.AllowedCIDRs = nil
		doc := decode(in) // unacknowledged: Go rejects it, so the schema must too
		if err := inputSchema.Validate(doc); err == nil {
			t.Fatal("domains with no CIDRs must be rejected without the acknowledgment")
		}
		in.EgressDomainsGatewayOnly = true
		if err := inputSchema.Validate(decode(in)); err != nil {
			t.Fatalf("acknowledged gateway-only domains must validate: %v", err)
		}
	})

	t.Run("malformed cidrs", func(t *testing.T) {
		for _, bad := range []string{"203.0.113.0", "not-a-cidr", "203.0.113.0/", "/24"} {
			in := fixtureInput()
			in.Egress.AllowedCIDRs = []string{bad}
			if err := inputSchema.Validate(decode(in)); err == nil {
				t.Fatalf("CIDR %q must be rejected by the schema", bad)
			}
		}
	})

	t.Run("signed attestation needs a signer key id", func(t *testing.T) {
		attestationSchema := compileBoundarySchema(t, "posture_attestation.v1.schema.json")
		compiled, posture := compiledFixture(t)
		signed, err := Attest(compiled.Receipt, compiled.Files, proberFromExpected(posture, string(compiled.Files[nftFilePath])), testSigner(t), testAttestOptions())
		if err != nil {
			t.Fatal(err)
		}
		doc := decode(signed)
		delete(doc, "signer_key_id")
		if err := attestationSchema.Validate(doc); err == nil {
			t.Fatal("a signature without signer_key_id must be rejected by the schema")
		}
	})

	t.Run("artifact path traversal", func(t *testing.T) {
		compiled, _ := compiledFixture(t)
		for _, bad := range []string{"../escape.conf", "systemd/../../etc/shadow", "a//b.conf", "/etc/shadow", "a/./b.conf", "back\\slash.conf"} {
			doc := decode(compiled.Receipt)
			doc["artifacts"].([]any)[0].(map[string]any)["path"] = bad
			if err := receiptSchema.Validate(doc); err == nil {
				t.Fatalf("artifact path %q must be rejected by the schema", bad)
			}
		}
		// A clean nested path with dots in the filename still validates.
		doc := decode(compiled.Receipt)
		doc["artifacts"].([]any)[0].(map[string]any)["path"] = "systemd/helm-gateway.service.d/50-helm-boundary.conf"
		if err := receiptSchema.Validate(doc); err != nil {
			t.Fatalf("clean path must validate: %v", err)
		}
	})
}

func TestUpdateBundleManifestSchema(t *testing.T) {
	schema := compileBoundarySchema(t, "update_bundle_manifest.v1.schema.json")
	manifest := sealedUpdateBundleManifest(t)
	if err := validateAgainst(t, schema, manifest); err != nil {
		t.Fatalf("update bundle manifest must validate against its schema: %v", err)
	}
}

func mustExpectedPosture(t *testing.T, compiled Compiled) ExpectedPosture {
	t.Helper()
	var posture ExpectedPosture
	if err := json.Unmarshal(compiled.Files[posturePath], &posture); err != nil {
		t.Fatal(err)
	}
	return posture
}

func sealedUpdateBundleManifest(t *testing.T) updatebundle.UpdateBundleManifest {
	t.Helper()
	entries := []updatebundle.BundleEntry{{
		Path:   "policy_packs/soc2_type2.v1.json",
		SHA256: "sha256:" + strings.Repeat("ab", 32),
		Size:   42,
	}}
	setHash, err := updatebundle.EntrySetHash(entries)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := updatebundle.SealManifest(updatebundle.UpdateBundleManifest{
		SchemaVersion:   updatebundle.UpdateBundleManifestSchemaVersion,
		BundleID:        "bundle-schema-test",
		KernelVersion:   "0.7.4-test",
		CreatedAt:       "2026-07-21T00:00:00Z",
		Entries:         entries,
		ArtifactSetHash: setHash,
		SignerKeyID:     "bundle-test-key",
	}, testSigner(t))
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}
