package kernelv1

import (
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestDecisionRecordV4AuthorityFieldsRoundTrip(t *testing.T) {
	want := &DecisionRecord{
		SubjectId:      "agent:alice",
		Action:         "EXECUTE_TOOL",
		Resource:       "github.create_issue",
		SignatureType:  "ed25519:release-key",
		ReasonCodeText: "SEMANTIC_THREAT_ESCALATE",
	}

	payload, err := proto.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var got DecisionRecord
	if err := proto.Unmarshal(payload, &got); err != nil {
		t.Fatal(err)
	}
	if got.GetSubjectId() != want.GetSubjectId() ||
		got.GetAction() != want.GetAction() ||
		got.GetResource() != want.GetResource() ||
		got.GetSignatureType() != want.GetSignatureType() ||
		got.GetReasonCodeText() != want.GetReasonCodeText() {
		t.Fatalf("generated DecisionRecord lost V4 authority fields: got=%+v", got)
	}

	for _, wantField := range []struct {
		name   string
		number int32
	}{
		{name: "subject_id", number: 18},
		{name: "action", number: 19},
		{name: "resource", number: 20},
		{name: "signature_type", number: 21},
		{name: "reason_code_text", number: 22},
	} {
		field := got.ProtoReflect().Descriptor().Fields().ByName(protoreflect.Name(wantField.name))
		if field == nil {
			t.Fatalf("generated descriptor is missing field %q", wantField.name)
		}
		if int32(field.Number()) != wantField.number {
			t.Fatalf("field %q has number %d, want %d", wantField.name, field.Number(), wantField.number)
		}
	}
}
