package contracts

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

type checkpointContractVector struct {
	Descriptor RecoveryCheckpointDescriptor `json:"descriptor"`
	Payload    string                       `json:"payload_base64"`
	Snapshot   string                       `json:"snapshot_bytes_base64"`
	Envelope   string                       `json:"envelope_base64"`
}

func checkpointContractGolden(t *testing.T) checkpointContractVector {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "evidence", "testdata", "recovery-checkpoint.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector checkpointContractVector
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	return vector
}

func checkpointContractPayload(t *testing.T) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(checkpointContractGolden(t).Payload)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestRecoveryCheckpointGoldenConstructionAndPrivateContent(t *testing.T) {
	vector := checkpointContractGolden(t)
	raw, err := EncodeRecoveryCheckpoint(vector.Descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, checkpointContractPayload(t)) {
		t.Fatal("canonical bytes differ from independent vector")
	}
	decoded, err := DecodeRecoveryCheckpoint(raw)
	if err != nil || !reflect.DeepEqual(decoded, vector.Descriptor) {
		t.Fatalf("decode: %v", err)
	}
	content, _ := base64.StdEncoding.DecodeString(vector.Snapshot)
	if err := VerifyRecoveryCheckpointContent(decoded, content); err != nil {
		t.Fatal(err)
	}
	for _, changed := range [][]byte{nil, append(bytes.Clone(content), '!'), append([]byte{'X'}, content[1:]...)} {
		if VerifyRecoveryCheckpointContent(decoded, changed) == nil {
			t.Fatal("changed private content accepted")
		}
	}
	for range 3 {
		again, err := EncodeRecoveryCheckpoint(decoded)
		if err != nil || !bytes.Equal(raw, again) {
			t.Fatal("construction is nondeterministic")
		}
	}
}

func TestRecoveryCheckpointUUIDWireForm(t *testing.T) {
	// Nonzero lowercase canonical bytes are the whole contract; UUID version
	// and variant bits are deliberately unconstrained, as in the schema.
	for _, value := range []string{
		"00000000-0000-0000-0000-000000000001",
		"ffffffff-ffff-ffff-ffff-ffffffffffff",
		"12345678-9abc-4def-8123-456789abcdef",
	} {
		if !checkpointUUID(value) {
			t.Fatalf("valid canonical ID refused: %q", value)
		}
	}
	canonical := "12345678-9abc-4def-8123-456789abcdef"
	invalid := []string{
		"", "00000000-0000-0000-0000-000000000000", canonical[:35], canonical + "0",
		strings.ReplaceAll(canonical, "-", ""), "{" + canonical + "}", "urn:uuid:" + canonical,
		strings.ToUpper(canonical), " " + canonical, canonical + "\n",
	}
	for i := range len(canonical) {
		value := []byte(canonical)
		if value[i] == '-' {
			value[i] = '0'
		} else {
			value[i] = 'g'
		}
		invalid = append(invalid, string(value))
	}
	for _, value := range invalid {
		if checkpointUUID(value) {
			t.Fatalf("noncanonical ID accepted: %q", value)
		}
	}
}

func TestRecoveryCheckpointStrictWireRefusals(t *testing.T) {
	raw := checkpointContractPayload(t)
	cases := map[string][]byte{
		"empty": nil, "malformed": raw[:len(raw)-1], "trailing": append(bytes.Clone(raw), []byte(` {}`)...),
		"top_duplicate":     bytes.Replace(raw, []byte(`"purpose":`), []byte(`"purpose":"provider-recovery-checkpoint","purpose":`), 1),
		"nested_duplicate":  bytes.Replace(raw, []byte(`"generation":2`), []byte(`"generation":2,"generation":2`), 1),
		"escaped_duplicate": bytes.Replace(raw, []byte(`"generation":2`), []byte(`"generation":2,"generat\u0069on":2`), 1),
		"case_alias":        bytes.Replace(raw, []byte(`"generation":2`), []byte(`"Generation":2`), 1),
		"null":              bytes.Replace(raw, []byte(`"generation":2`), []byte(`"generation":null`), 1),
		"fraction":          bytes.Replace(raw, []byte(`"generation":2`), []byte(`"generation":2.0`), 1),
		"exponent":          bytes.Replace(raw, []byte(`"generation":2`), []byte(`"generation":2e0`), 1),
		"negative":          bytes.Replace(raw, []byte(`"generation":2`), []byte(`"generation":-1`), 1),
		"integer_overflow":  bytes.Replace(raw, []byte(`"generation":2`), []byte(`"generation":18446744073709551616`), 1),
		"unsafe_integer":    bytes.Replace(raw, []byte(`"generation":2`), []byte(`"generation":9007199254740992`), 1),
		"string_integer":    bytes.Replace(raw, []byte(`"generation":2`), []byte(`"generation":"2"`), 1),
		"bad_utf8":          bytes.Replace(raw, []byte("信頼"), []byte{0xff}, 1),
		"lone_high":         bytes.Replace(raw, []byte("信頼"), []byte(`\ud800`), 1),
		"lone_low":          bytes.Replace(raw, []byte("信頼"), []byte(`\udfff`), 1),
		"bad_pair":          bytes.Replace(raw, []byte("信頼"), []byte(`\ud800\u0041`), 1),
		"depth":             []byte(`{"x":` + strings.Repeat("[", 26) + "0" + strings.Repeat("]", 26) + "}"),
		"nodes":             []byte("[" + strings.Repeat(`"",`, 65536) + `""]`),
		"size":              bytes.Repeat([]byte{' '}, RecoveryCheckpointMaxPayloadBytes+1),
	}
	for name, altered := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeRecoveryCheckpoint(altered); err == nil {
				t.Fatal("invalid wire accepted")
			}
		})
	}
	paired := bytes.Replace(raw, []byte("信頼"), []byte(`\ud83d\ude00`), 1)
	if _, err := DecodeRecoveryCheckpoint(paired); err != nil {
		t.Fatalf("valid UTF-16 pair refused: %v", err)
	}
}

func TestRecoveryCheckpointEveryFieldRequiredAndClosed(t *testing.T) {
	raw := checkpointContractPayload(t)
	var root any
	if err := json.Unmarshal(raw, &root); err != nil {
		t.Fatal(err)
	}
	var visit func(any, string)
	visit = func(value any, path string) {
		switch object := value.(type) {
		case map[string]any:
			for key, original := range object {
				delete(object, key)
				wire, _ := json.Marshal(root)
				if _, err := DecodeRecoveryCheckpoint(wire); err == nil {
					t.Fatalf("missing field accepted: %s.%s", path, key)
				}
				object[key] = original
				visit(original, path+"."+key)
			}
			object["unbound_authority"] = true
			wire, _ := json.Marshal(root)
			if _, err := DecodeRecoveryCheckpoint(wire); err == nil {
				t.Fatalf("unknown field accepted at %s", path)
			}
			delete(object, "unbound_authority")
		case []any:
			for _, item := range object {
				visit(item, path+"[]")
			}
		}
	}
	visit(root, "descriptor")
	for _, field := range []string{"private_key", "access_token", "credential", "storage_locator", "resume_authorized", "provider_backup_supported", "restore_authorized"} {
		wire := bytes.Replace(raw, []byte(`{"capture":`), []byte(`{"`+field+`":"forbidden","capture":`), 1)
		if _, err := DecodeRecoveryCheckpoint(wire); err == nil {
			t.Fatalf("privacy/authority extension accepted: %s", field)
		}
	}
}

func TestRecoveryCheckpointSemanticRefusals(t *testing.T) {
	cases := map[string]func(*RecoveryCheckpointDescriptor){
		"legacy_schema":         func(d *RecoveryCheckpointDescriptor) { d.SchemaVersion = "receipt.v5" },
		"noeffect_purpose":      func(d *RecoveryCheckpointDescriptor) { d.Purpose = "no_effect" },
		"wrong_uuid":            func(d *RecoveryCheckpointDescriptor) { d.Scope.TenantID = "tenant" },
		"nil_uuid":              func(d *RecoveryCheckpointDescriptor) { d.Scope.OperationID = "00000000-0000-0000-0000-000000000000" },
		"locator":               func(d *RecoveryCheckpointDescriptor) { d.Scope.InstallationID = "https://private/bucket" },
		"zero_generation":       func(d *RecoveryCheckpointDescriptor) { d.Scope.Generation = 0 },
		"unsafe_generation":     func(d *RecoveryCheckpointDescriptor) { d.Scope.Generation = RecoveryCheckpointMaxInteger + 1 },
		"bad_issuer":            func(d *RecoveryCheckpointDescriptor) { d.Producer.Issuer = "http://issuer.example" },
		"issuer_credentials":    func(d *RecoveryCheckpointDescriptor) { d.Producer.Issuer = "https://user:password@issuer.example" },
		"issuer_path":           func(d *RecoveryCheckpointDescriptor) { d.Producer.Issuer = "https://issuer.example/free-metadata" },
		"issuer_empty_query":    func(d *RecoveryCheckpointDescriptor) { d.Producer.Issuer = "https://issuer.example?" },
		"issuer_empty_fragment": func(d *RecoveryCheckpointDescriptor) { d.Producer.Issuer = "https://issuer.example#" },
		"issuer_empty_port":     func(d *RecoveryCheckpointDescriptor) { d.Producer.Issuer = "https://issuer.example:" },
		"issuer_port_range":     func(d *RecoveryCheckpointDescriptor) { d.Producer.Issuer = "https://issuer.example:65536" },
		"wrong_subject":         func(d *RecoveryCheckpointDescriptor) { d.Producer.Subject = "spiffe://helm/data-plane" },
		"invalid_utf8_construction": func(d *RecoveryCheckpointDescriptor) {
			d.Producer.Issuer = "https://" + string([]byte{0xff}) + ".example"
		},
		"revision":         func(d *RecoveryCheckpointDescriptor) { d.Producer.SourceRevision = "main" },
		"missing_ancestor": func(d *RecoveryCheckpointDescriptor) { d.Native.CoveredVersionIDs = d.Native.CoveredVersionIDs[:1] },
		"cohort_duplicate": func(d *RecoveryCheckpointDescriptor) { d.Native.CoveredVersionIDs[1] = d.Native.CoveredVersionIDs[0] },
		"cohort_order": func(d *RecoveryCheckpointDescriptor) {
			d.Native.CoveredVersionIDs[0], d.Native.CoveredVersionIDs[1] = d.Native.CoveredVersionIDs[1], d.Native.CoveredVersionIDs[0]
		},
		"unresolved": func(d *RecoveryCheckpointDescriptor) { d.Native.UnresolvedCount = 1 },
		"inventory_changed": func(d *RecoveryCheckpointDescriptor) {
			d.Native.AfterInventoryWatermark = RecoveryCheckpointHash([]byte("changed"))
		},
		"zero_revision":    func(d *RecoveryCheckpointDescriptor) { d.Native.AuthorityRevision = 0 },
		"unsafe_count":     func(d *RecoveryCheckpointDescriptor) { d.Native.InventoryCount = RecoveryCheckpointMaxInteger + 1 },
		"zero_bytes":       func(d *RecoveryCheckpointDescriptor) { d.Snapshot.ByteLength = 0 },
		"oversized_bytes":  func(d *RecoveryCheckpointDescriptor) { d.Snapshot.ByteLength = RecoveryCheckpointMaxContentBytes + 1 },
		"custody_locator":  func(d *RecoveryCheckpointDescriptor) { d.Snapshot.CustodyID = "s3://private/key" },
		"missing_digest":   func(d *RecoveryCheckpointDescriptor) { d.Snapshot.SchemaDigest = "" },
		"zero_row_version": func(d *RecoveryCheckpointDescriptor) { d.Capture.OrganizationRowVersion = 0 },
		"missing_sections": func(d *RecoveryCheckpointDescriptor) { d.Capture.Sections = nil },
		"unordered_sections": func(d *RecoveryCheckpointDescriptor) {
			d.Capture.Sections[0], d.Capture.Sections[1] = d.Capture.Sections[1], d.Capture.Sections[0]
		},
		"unsafe_rows": func(d *RecoveryCheckpointDescriptor) {
			d.Capture.Sections[0].RowCount = RecoveryCheckpointMaxInteger + 1
		},
		"invalid_section": func(d *RecoveryCheckpointDescriptor) { d.Capture.Sections[0].Name = "secret/key" },
		"cursor": func(d *RecoveryCheckpointDescriptor) {
			d.Capture.RealtimeContext.Floor = d.Capture.RealtimeContext.Head + 1
		},
		"seven_of_eight": func(d *RecoveryCheckpointDescriptor) { d.Installed.Console.Name = "" },
		"six_runtime": func(d *RecoveryCheckpointDescriptor) {
			d.Installed.RuntimeComponents = d.Installed.RuntimeComponents[:6]
		},
		"runtime_order": func(d *RecoveryCheckpointDescriptor) {
			d.Installed.RuntimeComponents[0], d.Installed.RuntimeComponents[1] = d.Installed.RuntimeComponents[1], d.Installed.RuntimeComponents[0]
		},
		"cohort_identity": func(d *RecoveryCheckpointDescriptor) {
			d.Installed.CohortDigest = RecoveryCheckpointHash([]byte("different cohort"))
		},
		"observation_changed": func(d *RecoveryCheckpointDescriptor) {
			d.Installed.AfterObservationDigest = RecoveryCheckpointHash([]byte("different pods"))
		},
		"producer_pod": func(d *RecoveryCheckpointDescriptor) { d.Producer.PodUID = d.Scope.TenantID },
		"producer_image": func(d *RecoveryCheckpointDescriptor) {
			d.Producer.ImageDigest = RecoveryCheckpointHash([]byte("wrong image"))
		},
		"platform":              func(d *RecoveryCheckpointDescriptor) { d.Installed.Console.Platform = "unknown" },
		"no_pods":               func(d *RecoveryCheckpointDescriptor) { d.Installed.Console.PodUIDs = []string{} },
		"trust_role":            func(d *RecoveryCheckpointDescriptor) { d.Installed.Console.TrustRole = "unfence" },
		"missing_participant":   func(d *RecoveryCheckpointDescriptor) { d.Participants = d.Participants[:2] },
		"participant_duplicate": func(d *RecoveryCheckpointDescriptor) { d.Participants[1].StoreID = d.Participants[0].StoreID },
		"participant_kind":      func(d *RecoveryCheckpointDescriptor) { d.Participants[2].Kind = "s3_etag" },
		"participant_drift": func(d *RecoveryCheckpointDescriptor) {
			d.Participants[2].AfterWatermark = RecoveryCheckpointHash([]byte("changed"))
		},
		"native_participant": func(d *RecoveryCheckpointDescriptor) { d.Participants[1].EntryCount++ },
		"prefix":             func(d *RecoveryCheckpointDescriptor) { d.EvidencePrefix.Sequence = RecoveryCheckpointMaxInteger + 1 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			d := checkpointContractGolden(t).Descriptor
			mutate(&d)
			if _, err := EncodeRecoveryCheckpoint(d); err == nil {
				t.Fatal("invalid construction accepted")
			}
			// encoding/json replaces invalid Go-string UTF-8 on Marshal. That
			// resulting wire value is different input; raw invalid UTF-8 is
			// covered separately by TestRecoveryCheckpointStrictWireRefusals.
			if name == "invalid_utf8_construction" {
				return
			}
			raw, _ := json.Marshal(d)
			if _, err := DecodeRecoveryCheckpoint(raw); err == nil {
				t.Fatal("invalid descriptor accepted")
			}
		})
	}
	d := checkpointContractGolden(t).Descriptor
	d.Scope.Generation = RecoveryCheckpointMaxInteger
	d.Capture.RealtimeContext.Head = RecoveryCheckpointMaxInteger
	if _, err := EncodeRecoveryCheckpoint(d); err != nil {
		t.Fatalf("safe integer boundary refused: %v", err)
	}
	d.Producer.Issuer = "https://issuer.example:8443"
	if _, err := EncodeRecoveryCheckpoint(d); err != nil {
		t.Fatalf("explicit HTTPS origin port refused: %v", err)
	}
}

func TestRecoveryCheckpointSchemaParity(t *testing.T) {
	filename := filepath.Join(evidencePackSuccessorRepoRoot(t), "protocols", "json-schemas", "evidence", "provider_recovery_checkpoint.v1.schema.json")
	raw, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	const schemaURL = "https://helm.mindburn.org/schemas/provider-recovery-checkpoint.v1"
	if err := compiler.AddResource(schemaURL, bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile(schemaURL)
	if err != nil {
		t.Fatal(err)
	}
	var descriptor any
	if err := json.Unmarshal(checkpointContractPayload(t), &descriptor); err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(descriptor); err != nil {
		t.Fatal(err)
	}
	var visit func(any, string)
	visit = func(value any, path string) {
		switch object := value.(type) {
		case map[string]any:
			for key, original := range object {
				delete(object, key)
				if schema.Validate(descriptor) == nil {
					t.Fatalf("schema accepted missing %s.%s", path, key)
				}
				object[key] = original
				visit(original, path+"."+key)
			}
			object["unknown_extension"] = true
			if schema.Validate(descriptor) == nil {
				t.Fatalf("schema open at %s", path)
			}
			delete(object, "unknown_extension")
		case []any:
			for _, item := range object {
				visit(item, path+"[]")
			}
		}
	}
	visit(descriptor, "descriptor")
	envelopeSchema, err := compiler.Compile(schemaURL + "#/$defs/envelope")
	if err != nil {
		t.Fatal(err)
	}
	envelopeBytes, err := base64.StdEncoding.DecodeString(checkpointContractGolden(t).Envelope)
	if err != nil {
		t.Fatal(err)
	}
	var envelope any
	if err := json.Unmarshal(envelopeBytes, &envelope); err != nil {
		t.Fatal(err)
	}
	if err := envelopeSchema.Validate(envelope); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryCheckpointEnvelopeTransportIsClosed(t *testing.T) {
	golden := checkpointContractGolden(t)
	raw, err := base64.StdEncoding.DecodeString(golden.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	envelope, payload, signature, err := DecodeRecoveryCheckpointEnvelope(raw)
	if err != nil || !bytes.Equal(payload, checkpointContractPayload(t)) || len(signature) != 64 || envelope.PayloadType != RecoveryCheckpointPayloadType {
		t.Fatalf("exact transport decode: %v", err)
	}
	for _, field := range []string{"payloadType", "payload", "signatures"} {
		var object map[string]any
		_ = json.Unmarshal(raw, &object)
		delete(object, field)
		altered, _ := json.Marshal(object)
		if _, _, _, err := DecodeRecoveryCheckpointEnvelope(altered); err == nil {
			t.Fatalf("missing envelope field accepted: %s", field)
		}
	}
	for _, field := range []string{"keyid", "sig"} {
		var object map[string]any
		_ = json.Unmarshal(raw, &object)
		delete(object["signatures"].([]any)[0].(map[string]any), field)
		altered, _ := json.Marshal(object)
		if _, _, _, err := DecodeRecoveryCheckpointEnvelope(altered); err == nil {
			t.Fatalf("missing signature field accepted: %s", field)
		}
	}
	for _, mutate := range []func(*RecoveryCheckpointEnvelope){
		func(e *RecoveryCheckpointEnvelope) { e.PayloadType = "legacy" },
		func(e *RecoveryCheckpointEnvelope) { e.Signatures = nil },
		func(e *RecoveryCheckpointEnvelope) { e.Signatures[0].KeyID = "secret://locator" },
		func(e *RecoveryCheckpointEnvelope) { e.Payload += "\n" },
		func(e *RecoveryCheckpointEnvelope) { e.Payload = "" },
		func(e *RecoveryCheckpointEnvelope) { e.Signatures[0].Signature = "AA==" },
		func(e *RecoveryCheckpointEnvelope) { e.Signatures[0].Signature += "\n" },
	} {
		var changed RecoveryCheckpointEnvelope
		_ = json.Unmarshal(raw, &changed)
		mutate(&changed)
		altered, _ := json.Marshal(changed)
		if _, _, _, err := DecodeRecoveryCheckpointEnvelope(altered); err == nil {
			t.Fatal("invalid transport accepted")
		}
	}
}

func FuzzRecoveryCheckpointDecode(f *testing.F) {
	raw, err := os.ReadFile(filepath.Join("..", "evidence", "testdata", "recovery-checkpoint.v1.json"))
	if err != nil {
		f.Fatal(err)
	}
	var vector checkpointContractVector
	if err := json.Unmarshal(raw, &vector); err != nil {
		f.Fatal(err)
	}
	payload, _ := base64.StdEncoding.DecodeString(vector.Payload)
	f.Add(payload)
	f.Add([]byte(`{"scope":{"generation":null}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		descriptor, err := DecodeRecoveryCheckpoint(data)
		if err != nil {
			return
		}
		canonical, err := EncodeRecoveryCheckpoint(descriptor)
		if err != nil {
			t.Fatal(err)
		}
		round, err := DecodeRecoveryCheckpoint(canonical)
		if err != nil || !reflect.DeepEqual(round, descriptor) {
			t.Fatal("successful decode is not stable")
		}
	})
}
