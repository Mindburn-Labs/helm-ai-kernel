// Contract tests for the gateway's authority administration API
// (AuthorityAdminService, docs/architecture/gateway-provisioning-api.md). They
// pin the wire shape the Control Plane builds against: the RPCs, the absence of
// any tenant on the wire, the token scope of each RPC, the reason codes the
// proto names, and the closed vocabularies. Every checker also runs on a
// planted violation first, so a checker that cannot fail fails the test.
//
// quantum_posture: contract test only; it reads descriptors and the proto
// source, and signs or verifies nothing.
package gatewayv1

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"unicode/utf16"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/known/structpb"
)

const adminProtoRel = "protocols/proto/helm/gateway/v1/authority_admin.proto"

func adminService(t *testing.T) protoreflect.ServiceDescriptor {
	t.Helper()
	svc := File_helm_gateway_v1_authority_admin_proto.Services().ByName("AuthorityAdminService")
	if svc == nil {
		t.Fatal("AuthorityAdminService is missing from the compiled descriptor")
	}
	return svc
}

// The three RPCs, unary, each with its own request and response. Only the
// reads may be marked NO_SIDE_EFFECTS, which lets Connect serve them over GET.
func TestAuthorityAdminServiceHasItsRPCs(t *testing.T) {
	want := []string{"EnsurePrincipals", "GetProvisioning", "ListEffectTypes"}
	reads := map[string]bool{"GetProvisioning": true, "ListEffectTypes": true}
	methods := adminService(t).Methods()
	var got []string
	for i := 0; i < methods.Len(); i++ {
		m := methods.Get(i)
		name := string(m.Name())
		got = append(got, name)
		if m.IsStreamingClient() || m.IsStreamingServer() {
			t.Errorf("%s streams; every RPC is unary", name)
		}
		if in := string(m.Input().Name()); in != name+"Request" {
			t.Errorf("%s takes %s, want %sRequest", name, in, name)
		}
		if out := string(m.Output().Name()); out != name+"Response" {
			t.Errorf("%s returns %s, want %sResponse", name, out, name)
		}
		wantLevel := descriptorpb.MethodOptions_IDEMPOTENCY_UNKNOWN
		if reads[name] {
			wantLevel = descriptorpb.MethodOptions_NO_SIDE_EFFECTS
		}
		if level := m.Options().(*descriptorpb.MethodOptions).GetIdempotencyLevel(); level != wantLevel {
			t.Errorf("%s idempotency_level = %v, want %v", name, level, wantLevel)
		}
	}
	if !slices.Equal(got, want) {
		t.Fatalf("RPCs = %v, want %v", got, want)
	}

	procedures := map[string]string{
		AuthorityAdminServiceEnsurePrincipalsProcedure: "EnsurePrincipals",
		AuthorityAdminServiceGetProvisioningProcedure:  "GetProvisioning",
		AuthorityAdminServiceListEffectTypesProcedure:  "ListEffectTypes",
	}
	if len(procedures) != len(want) {
		t.Errorf("%d procedure constants checked, want %d", len(procedures), len(want))
	}
	for procedure, method := range procedures {
		if want := "/helm.gateway.v1.AuthorityAdminService/" + method; procedure != want {
			t.Errorf("procedure %q, want %q", procedure, want)
		}
	}
}

// The file imports the well-known timestamp and its sibling gateway.proto,
// which it takes RiskClass from. An import of another HELM package would
// generate uncompilable Go under the helm.mindburn.run vanity go_package.
func TestAuthorityAdminImportsOnlyItsSiblings(t *testing.T) {
	imports := File_helm_gateway_v1_authority_admin_proto.Imports()
	var got []string
	for i := 0; i < imports.Len(); i++ {
		got = append(got, imports.Get(i).Path())
	}
	slices.Sort(got)
	if want := []string{"google/protobuf/timestamp.proto", "helm/gateway/v1/gateway.proto"}; !slices.Equal(got, want) {
		t.Fatalf("authority_admin.proto imports %v, want %v", got, want)
	}
}

// adminIdentityFieldAllowed names the request fields the identity rule of
// gateway.proto would flag but that this API needs: they name the principal
// being registered, and the gateway checks them against its own rows. No
// request may name a tenant or a workspace.
var adminIdentityFieldAllowed = map[string]string{
	"helm.gateway.v1.PrincipalSpec.principal_id": "the principal being registered",
	"helm.gateway.v1.ExternalSubject.id":         "the external subject's id in the system that vouches for it",
}

func TestNoAdminRequestNamesATenantOrWorkspace(t *testing.T) {
	// Planted violation: a field that names a principal is flagged.
	if got := identityFields((&EffectAttempt{}).ProtoReflect().Descriptor(), map[protoreflect.FullName]bool{}); len(got) == 0 {
		t.Fatal("the identity checker cannot fail")
	}
	methods := adminService(t).Methods()
	for i := 0; i < methods.Len(); i++ {
		in := methods.Get(i).Input()
		for _, field := range identityFields(in, map[protoreflect.FullName]bool{}) {
			if _, ok := adminIdentityFieldAllowed[field]; !ok {
				t.Errorf("%s: %s asserts an identity; the tenant and the caller come only from the token", in.FullName(), field)
			}
			if strings.Contains(field, "tenant") || strings.Contains(field, "workspace") {
				t.Errorf("%s names a tenant or workspace", field)
			}
		}
	}
}

// No float anywhere in the file.
func TestAdminMessagesHaveNoFloatingPoint(t *testing.T) {
	if got := floatFields((&structpb.Value{}).ProtoReflect().Descriptor(), map[protoreflect.FullName]bool{}); len(got) == 0 {
		t.Fatal("checker missed the planted double field")
	}
	messages := File_helm_gateway_v1_authority_admin_proto.Messages()
	for i := 0; i < messages.Len(); i++ {
		if found := floatFields(messages.Get(i), map[protoreflect.FullName]bool{}); len(found) > 0 {
			t.Errorf("floating-point fields %v", found)
		}
	}
}

// Each RPC names its one token scope: the provision scope for the write, the
// read scope for the reads.
func TestAuthorityAdminTokenScopes(t *testing.T) {
	want := map[string][]string{
		"EnsurePrincipals": {"helm.gateway.provision"},
		"GetProvisioning":  {"helm.gateway.read"},
		"ListEffectTypes":  {"helm.gateway.read"},
	}
	got, err := rpcScopes(readRepoFile(t, adminProtoRel))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Errorf("found scopes for %d RPCs, want %d: %v", len(got), len(want), got)
	}
	for rpc, scopes := range want {
		if s := got[rpc]; !slices.Equal(s, scopes) {
			t.Errorf("rpc %s names token scopes %v, want %v", rpc, s, scopes)
		}
	}
}

// Every reason code the proto names is registered today (ADR-0001 §6): this
// API emits only codes the registry already has.
func TestAuthorityAdminReasonCodesAreRegistered(t *testing.T) {
	registry := registeredCodes(t)
	registered, pending, problems := checkReasonCodes(readRepoFile(t, adminProtoRel), registry)
	for _, p := range problems {
		t.Error(p)
	}
	if len(pending) != 0 {
		t.Errorf("reason_code_pending markers %v: this API registers no new code", pending)
	}
	for _, code := range []string{"SCHEMA_VIOLATION", "INSUFFICIENT_PRIVILEGE", "IDENTITY_ISOLATION_VIOLATION", "PRINCIPAL_INACTIVE"} {
		if !slices.Contains(registered, code) {
			t.Errorf("the proto no longer names %s", code)
		}
	}
}

// The enums, names and numbers frozen.
func TestAuthorityAdminEnums(t *testing.T) {
	cases := []struct {
		enum protoreflect.EnumDescriptor
		want []string
	}{
		{PrincipalKind(0).Descriptor(), []string{"0:PRINCIPAL_KIND_UNSPECIFIED", "1:PRINCIPAL_KIND_HUMAN", "2:PRINCIPAL_KIND_AGENT", "3:PRINCIPAL_KIND_SERVICE"}},
		{PrincipalStatus(0).Descriptor(), []string{"0:PRINCIPAL_STATUS_UNSPECIFIED", "1:PRINCIPAL_STATUS_ACTIVE", "2:PRINCIPAL_STATUS_DISABLED"}},
	}
	for _, c := range cases {
		if got := enumValues(c.enum); !slices.Equal(got, c.want) {
			t.Errorf("%s = %v, want %v", c.enum.FullName(), got, c.want)
		}
	}
}

// The step-up proof is ApproveRequest field 4, the number the effect API held
// for it, and a string: a compact token.
func TestApproveRequestCarriesTheStepUpProof(t *testing.T) {
	f := (&ApproveRequest{}).ProtoReflect().Descriptor().Fields().ByNumber(4)
	if f == nil || f.Name() != "step_up_proof" || f.Kind() != protoreflect.StringKind {
		t.Fatalf("ApproveRequest field 4 is %v, want the string step_up_proof", f)
	}
	if (&RejectRequest{}).ProtoReflect().Descriptor().Fields().ByName("step_up_proof") != nil {
		t.Error("RejectRequest carries a step-up proof; a rejection narrows and needs none")
	}
}

// ListAttempts filters and pages: the shape the design note gives, on the
// field numbers it took.
func TestListAttemptsShape(t *testing.T) {
	req := (&ListAttemptsRequest{}).ProtoReflect().Descriptor()
	want := map[protoreflect.Name]protoreflect.FieldNumber{
		"states": 1, "commitment_id": 2, "case_id": 3, "requester_principal_id": 4, "effect_type": 5,
		"updated_after": 6, "page_size": 7, "page_token": 8,
	}
	if req.Fields().Len() != len(want) {
		t.Errorf("ListAttemptsRequest has %d fields, want %d", req.Fields().Len(), len(want))
	}
	for name, number := range want {
		if f := req.Fields().ByName(name); f == nil || f.Number() != number {
			t.Errorf("ListAttemptsRequest.%s: got %v, want field %d", name, f, number)
		}
	}
	if oneof := req.Oneofs().ByName("work_ref"); oneof == nil || oneof.Fields().Len() != 2 {
		t.Error("ListAttemptsRequest names at most one work_ref")
	}
	resp := (&ListAttemptsResponse{}).ProtoReflect().Descriptor()
	if f := resp.Fields().ByName("attempts"); f == nil || f.Number() != 1 || !f.IsList() {
		t.Error("ListAttemptsResponse.attempts is not repeated field 1")
	}
	if f := resp.Fields().ByName("next_page_token"); f == nil || f.Number() != 2 {
		t.Error("ListAttemptsResponse.next_page_token is not field 2")
	}
	if f := resp.Fields().ByName("settled_before"); f == nil || f.Number() != 3 || f.Message() == nil ||
		f.Message().FullName() != "google.protobuf.Timestamp" {
		t.Error("ListAttemptsResponse.settled_before is not the Timestamp field 3")
	}
	if resp.Fields().Len() != 3 {
		t.Errorf("ListAttemptsResponse has %d fields, want 3", resp.Fields().Len())
	}
}

// jcs writes v as RFC 8785 (JCS) does, for the values encoding/json produces
// when it decodes with UseNumber: objects with their members sorted by UTF-16
// code units, strings as ES6 JSON.stringify writes them (only the quote, the
// backslash and the control characters are escaped: "&", "<", ">", non-ASCII
// text and U+2028 stay as they are, which encoding/json does not do), and
// numbers with their digits as written.
func jcs(t *testing.T, buf *bytes.Buffer, v any) {
	t.Helper()
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case json.Number:
		buf.WriteString(x.String())
	case string:
		jcsString(buf, x)
	case []any:
		buf.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			jcs(t, buf, e)
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		slices.SortFunc(keys, func(a, b string) int {
			return slices.Compare(utf16.Encode([]rune(a)), utf16.Encode([]rune(b)))
		})
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			jcsString(buf, k)
			buf.WriteByte(':')
			jcs(t, buf, x[k])
		}
		buf.WriteByte('}')
	default:
		t.Fatalf("jcs: %T", v)
	}
}

func jcsString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			buf.WriteString(`\"`)
		case r == '\\':
			buf.WriteString(`\\`)
		case r == '\b':
			buf.WriteString(`\b`)
		case r == '\f':
			buf.WriteString(`\f`)
		case r == '\n':
			buf.WriteString(`\n`)
		case r == '\r':
			buf.WriteString(`\r`)
		case r == '\t':
			buf.WriteString(`\t`)
		case r < 0x20:
			buf.WriteString(fmt.Sprintf(`\u%04x`, r))
		default:
			buf.WriteRune(r)
		}
	}
	buf.WriteByte('"')
}

func decodePlan(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var plan map[string]any
	if err := dec.Decode(&plan); err != nil {
		t.Fatal(err)
	}
	return plan
}

// planDigest is the reference plan digest: SHA-256 of the RFC 8785 form of the
// plan without base_plan_digest.
func planDigest(t *testing.T, raw []byte) string {
	t.Helper()
	plan := decodePlan(t, raw)
	delete(plan, "base_plan_digest")
	var canonical bytes.Buffer
	jcs(t, &canonical, plan)
	sum := sha256.Sum256(canonical.Bytes())
	return hex.EncodeToString(sum[:])
}

// The plan digest test vectors. testdata/plan_digest.py is a separate Python
// implementation; the Go reference, the Python one and the design note must
// carry the same values, so the Control Plane can check its own encoder before
// it sends a plan, and the gateway's implementation (core/pkg/gateway/effectargs,
// over core/pkg/canonicalize) is held to the same values by its own test. The
// second plan carries what a naive encoder gets wrong: "&&", "<" and ">" in a
// condition (encoding/json writes them as \u0026, \u003c and \u003e), and
// non-ASCII text, a character beyond the BMP and U+2028 in a target.
func TestPlanDigestVector(t *testing.T) {
	const want = "70d6c47ca51186780504038bdadb939319455ee16c14f59d4829fd1a8bdee5af"
	const wantEscapes = "81bbed39150fdb7cc7988f955bcdb6be75b150b07b8ca8cd0fe425ffb386b4ef"
	plan := []byte(readRepoFile(t, "protocols/json-schemas/effects/authority/examples/provision.v1.valid.json"))
	escapes := []byte(readRepoFile(t, "protocols/json-schemas/effects/authority/examples/provision.v1.valid-escapes.json"))
	if got := planDigest(t, plan); got != want {
		t.Fatalf("plan digest = %s, want %s", got, want)
	}
	if got := planDigest(t, escapes); got != wantEscapes {
		t.Fatalf("escapes plan digest = %s, want %s", got, wantEscapes)
	}
	// Planted: the vector discriminates. encoding/json's compact form of the
	// second plan is a different byte string, so a digest over it differs.
	naive, err := json.Marshal(decodePlan(t, escapes))
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(naive); hex.EncodeToString(sum[:]) == wantEscapes {
		t.Error("the escapes plan does not tell RFC 8785 from encoding/json")
	}
	// Planted: base_plan_digest is not part of the digest; any other byte is.
	doc := decodePlan(t, plan)
	doc["base_plan_digest"] = strings.Repeat("f", 64)
	other, _ := json.Marshal(doc)
	if got := planDigest(t, other); got != want {
		t.Errorf("base_plan_digest changed the digest to %s", got)
	}
	doc["version_ref"] = "another"
	changed, _ := json.Marshal(doc)
	if planDigest(t, changed) == want {
		t.Error("the digest ignores version_ref")
	}

	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatalf("python3 is required for the cross-implementation check: %v", err)
	}
	out, err := exec.Command(python, filepath.Join("testdata", "plan_digest.py"), repoRoot(t)).Output()
	if err != nil {
		t.Fatalf("testdata/plan_digest.py: %v", err)
	}
	var py struct {
		Digest        string `json:"digest"`
		WithOtherBase string `json:"with_other_base"`
		Escapes       string `json:"escapes"`
	}
	if err := json.Unmarshal(out, &py); err != nil {
		t.Fatalf("testdata/plan_digest.py output: %v", err)
	}
	if py.Digest != want || py.WithOtherBase != want || py.Escapes != wantEscapes {
		t.Errorf("the Python reference disagrees with Go: %+v, want %s and %s", py, want, wantEscapes)
	}
	doc2 := readRepoFile(t, "docs/architecture/gateway-provisioning-api.md")
	for _, v := range []string{want, wantEscapes} {
		if !strings.Contains(doc2, v) {
			t.Errorf("docs/architecture/gateway-provisioning-api.md does not carry %s", v)
		}
	}
}
