// Contract tests for the gateway effect API (HELM-751 s1,
// docs/architecture/gateway-effect-api.md). They pin the wire shape WS-B
// builds against: the operations, the state machine, the identity rule, the
// token scopes and the reason codes the proto names. Every checker also runs
// on a planted violation first, so a checker that cannot fail fails the test.
//
// quantum_posture: contract test only; it reads descriptors and the proto
// source, computes SHA-256 approval-digest vectors, and signs or verifies
// nothing.
package gatewayv1

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const protoRel = "protocols/proto/helm/gateway/v1/gateway.proto"
const registryRel = "protocols/json-schemas/reason-codes/reason-codes-v1.json"

func service(t *testing.T) protoreflect.ServiceDescriptor {
	t.Helper()
	svc := File_helm_gateway_v1_gateway_proto.Services().ByName("EffectGatewayService")
	if svc == nil {
		t.Fatal("EffectGatewayService is missing from the compiled descriptor")
	}
	return svc
}

// The six operations of rev 3.4 §4.2 as eight unary RPCs, plus Cancel and
// GetAttemptContent from WS-B's review.
func TestServiceHasTheSixOperations(t *testing.T) {
	want := []string{"Propose", "Approve", "Reject", "Cancel", "Dispatch", "Observe", "GetAttempt", "GetAttemptContent", "Stop", "Lift"}
	methods := service(t).Methods()
	var got []string
	for i := 0; i < methods.Len(); i++ {
		m := methods.Get(i)
		name := string(m.Name())
		got = append(got, name)
		if m.IsStreamingClient() || m.IsStreamingServer() {
			t.Errorf("%s streams; every gateway RPC is unary", name)
		}
		if in := string(m.Input().Name()); in != name+"Request" {
			t.Errorf("%s takes %s, want %sRequest", name, in, name)
		}
		if out := string(m.Output().Name()); out != name+"Response" {
			t.Errorf("%s returns %s, want %sResponse", name, out, name)
		}
		level := m.Options().(*descriptorpb.MethodOptions).GetIdempotencyLevel()
		wantLevel := descriptorpb.MethodOptions_IDEMPOTENCY_UNKNOWN
		if name == "GetAttempt" || name == "GetAttemptContent" {
			wantLevel = descriptorpb.MethodOptions_NO_SIDE_EFFECTS
		}
		if level != wantLevel {
			t.Errorf("%s idempotency_level = %v, want %v", name, level, wantLevel)
		}
	}
	if !slices.Equal(got, want) {
		t.Fatalf("RPCs = %v, want %v", got, want)
	}

	// The Connect routes WS-B's adapter calls.
	procedures := map[string]string{
		EffectGatewayServiceProposeProcedure:           "Propose",
		EffectGatewayServiceApproveProcedure:           "Approve",
		EffectGatewayServiceRejectProcedure:            "Reject",
		EffectGatewayServiceCancelProcedure:            "Cancel",
		EffectGatewayServiceDispatchProcedure:          "Dispatch",
		EffectGatewayServiceObserveProcedure:           "Observe",
		EffectGatewayServiceGetAttemptProcedure:        "GetAttempt",
		EffectGatewayServiceGetAttemptContentProcedure: "GetAttemptContent",
		EffectGatewayServiceStopProcedure:              "Stop",
		EffectGatewayServiceLiftProcedure:              "Lift",
	}
	if len(procedures) != len(want) {
		t.Errorf("%d procedure constants checked, want %d", len(procedures), len(want))
	}
	for procedure, method := range procedures {
		if want := "/helm.gateway.v1.EffectGatewayService/" + method; procedure != want {
			t.Errorf("procedure %q, want %q", procedure, want)
		}
	}
}

// The package imports only well-known types. go_package uses the
// helm.mindburn.run vanity prefix, which does not resolve as a Go import, so an
// import of another HELM proto package would generate uncompilable Go.
// ErrorDetail travels in Connect error details, not in these messages.
func TestImportsOnlyWellKnownTypes(t *testing.T) {
	imports := File_helm_gateway_v1_gateway_proto.Imports()
	for i := 0; i < imports.Len(); i++ {
		if path := imports.Get(i).Path(); !strings.HasPrefix(path, "google/protobuf/") {
			t.Errorf("gateway.proto imports %s", path)
		}
	}
}

func enumValues(e protoreflect.EnumDescriptor) []string {
	var out []string
	for i := 0; i < e.Values().Len(); i++ {
		v := e.Values().Get(i)
		out = append(out, fmt.Sprintf("%d:%s", v.Number(), v.Name()))
	}
	return out
}

// The §4.3 state machine and the ADR-0003 settlement states, names and
// numbers frozen.
func TestStateMachineEnums(t *testing.T) {
	cases := []struct {
		enum protoreflect.EnumDescriptor
		want []string
	}{
		{EffectAttemptState(0).Descriptor(), []string{
			"0:EFFECT_ATTEMPT_STATE_UNSPECIFIED",
			"1:EFFECT_ATTEMPT_STATE_PROPOSED",
			"2:EFFECT_ATTEMPT_STATE_DENIED",
			"3:EFFECT_ATTEMPT_STATE_ESCALATED",
			"4:EFFECT_ATTEMPT_STATE_APPROVED",
			"5:EFFECT_ATTEMPT_STATE_REJECTED",
			"6:EFFECT_ATTEMPT_STATE_EXPIRED",
			"7:EFFECT_ATTEMPT_STATE_ADMITTED",
			"8:EFFECT_ATTEMPT_STATE_CANCELLED",
			"9:EFFECT_ATTEMPT_STATE_DISPATCHING",
			"10:EFFECT_ATTEMPT_STATE_DISPATCHED",
			"11:EFFECT_ATTEMPT_STATE_UNKNOWN",
			"12:EFFECT_ATTEMPT_STATE_OBSERVED",
			"13:EFFECT_ATTEMPT_STATE_RECONCILED",
			"14:EFFECT_ATTEMPT_STATE_ESCALATED_TO_HUMAN",
			"15:EFFECT_ATTEMPT_STATE_SETTLED",
			"16:EFFECT_ATTEMPT_STATE_COMPENSATED",
		}},
		{EffectOutcome(0).Descriptor(), []string{
			"0:EFFECT_OUTCOME_UNSPECIFIED", "1:EFFECT_OUTCOME_SUCCEEDED", "2:EFFECT_OUTCOME_FAILED",
		}},
		{OutcomeBasis(0).Descriptor(), []string{
			"0:OUTCOME_BASIS_UNSPECIFIED", "1:OUTCOME_BASIS_OBSERVED", "2:OUTCOME_BASIS_RECONCILED",
		}},
		{SettlementState(0).Descriptor(), []string{
			"0:SETTLEMENT_STATE_UNSPECIFIED",
			"1:SETTLEMENT_STATE_HELD",
			"2:SETTLEMENT_STATE_ESTIMATED",
			"3:SETTLEMENT_STATE_UNRESOLVED_FINAL",
			"4:SETTLEMENT_STATE_CONFIRMED",
			"5:SETTLEMENT_STATE_RELEASED",
		}},
		{ExposureKind(0).Descriptor(), []string{
			"0:EXPOSURE_KIND_UNSPECIFIED", "1:EXPOSURE_KIND_HELD", "2:EXPOSURE_KIND_ESTIMATED",
			"3:EXPOSURE_KIND_CONFIRMED", "4:EXPOSURE_KIND_RELEASED",
		}},
		{AuthorityRowKind(0).Descriptor(), []string{
			"0:AUTHORITY_ROW_KIND_UNSPECIFIED", "1:AUTHORITY_ROW_KIND_TENANT", "2:AUTHORITY_ROW_KIND_PRINCIPAL",
			"3:AUTHORITY_ROW_KIND_MANDATE", "4:AUTHORITY_ROW_KIND_EFFECT_TYPE", "5:AUTHORITY_ROW_KIND_LIMIT",
		}},
		{StopScopeKind(0).Descriptor(), []string{
			"0:STOP_SCOPE_KIND_UNSPECIFIED", "1:STOP_SCOPE_KIND_TENANT", "2:STOP_SCOPE_KIND_PRINCIPAL",
			"3:STOP_SCOPE_KIND_MANDATE", "4:STOP_SCOPE_KIND_EFFECT_TYPE",
		}},
	}
	for _, c := range cases {
		if got := enumValues(c.enum); !slices.Equal(got, c.want) {
			t.Errorf("%s = %v, want %v", c.enum.FullName(), got, c.want)
		}
	}
}

// identityFieldRE matches field names that would assert who the caller is or
// which tenant or workspace it acts in. Rule R9 and ADR-0005: those come only
// from the token.
var identityFieldRE = regexp.MustCompile(`^(tenant|tenant_id|workspace|workspace_id|principal|principal_id|subject|user_id|actor_id|approver_id|.*_principal_id)$`)

// identityFields walks a message and every message it contains.
func identityFields(msg protoreflect.MessageDescriptor, seen map[protoreflect.FullName]bool) []string {
	if seen[msg.FullName()] {
		return nil
	}
	seen[msg.FullName()] = true
	var out []string
	for i := 0; i < msg.Fields().Len(); i++ {
		f := msg.Fields().Get(i)
		if identityFieldRE.MatchString(string(f.Name())) {
			out = append(out, string(f.FullName()))
		}
		if f.Message() != nil {
			out = append(out, identityFields(f.Message(), seen)...)
		}
	}
	return out
}

func TestNoRequestCarriesCallerIdentity(t *testing.T) {
	// Planted violation: EffectAttempt carries requester_principal_id, which
	// is output only. The checker must see it.
	planted := (&EffectAttempt{}).ProtoReflect().Descriptor()
	if got := identityFields(planted, map[protoreflect.FullName]bool{}); !slices.Contains(got, "helm.gateway.v1.EffectAttempt.requester_principal_id") {
		t.Fatalf("checker missed the planted identity field; got %v", got)
	}

	methods := service(t).Methods()
	for i := 0; i < methods.Len(); i++ {
		in := methods.Get(i).Input()
		if found := identityFields(in, map[protoreflect.FullName]bool{}); len(found) > 0 {
			t.Errorf("%s carries identity fields %v; tenant and principal come only from the token", in.FullName(), found)
		}
	}
}

// floatFields lists float and double fields in a message and the messages it
// contains.
func floatFields(msg protoreflect.MessageDescriptor, seen map[protoreflect.FullName]bool) []string {
	if seen[msg.FullName()] {
		return nil
	}
	seen[msg.FullName()] = true
	var out []string
	for i := 0; i < msg.Fields().Len(); i++ {
		f := msg.Fields().Get(i)
		if f.Kind() == protoreflect.FloatKind || f.Kind() == protoreflect.DoubleKind {
			out = append(out, string(f.FullName()))
		}
		if f.Message() != nil {
			out = append(out, floatFields(f.Message(), seen)...)
		}
	}
	return out
}

// Money and quantities are integers (rev 3.4 §3): no float anywhere.
func TestNoFloatingPointAndIntegerAmounts(t *testing.T) {
	// Planted violation: google.protobuf.Value.number_value is a double.
	if got := floatFields((&structpb.Value{}).ProtoReflect().Descriptor(), map[protoreflect.FullName]bool{}); len(got) == 0 {
		t.Fatal("checker missed the planted double field")
	}

	messages := File_helm_gateway_v1_gateway_proto.Messages()
	for i := 0; i < messages.Len(); i++ {
		msg := messages.Get(i)
		if found := floatFields(msg, map[protoreflect.FullName]bool{}); len(found) > 0 {
			t.Errorf("floating-point fields %v", found)
		}
		for j := 0; j < msg.Fields().Len(); j++ {
			f := msg.Fields().Get(j)
			name := string(f.Name())
			if (name == "amount" || strings.HasSuffix(name, "_micros")) && f.Kind() != protoreflect.Int64Kind {
				t.Errorf("%s is %v, want int64", f.FullName(), f.Kind())
			}
		}
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, protoRel)); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("no %s above the test directory; this test needs the repository checkout", protoRel)
		}
		dir = parent
	}
}

func readRepoFile(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func registeredCodes(t *testing.T) map[string]bool {
	t.Helper()
	var reg struct {
		Codes []struct {
			Code string `json:"code"`
		} `json:"codes"`
	}
	if err := json.Unmarshal([]byte(readRepoFile(t, registryRel)), &reg); err != nil {
		t.Fatal(err)
	}
	codes := map[string]bool{}
	for _, c := range reg.Codes {
		codes[c.Code] = true
	}
	if len(codes) == 0 {
		t.Fatal("the reason-code registry lists no codes")
	}
	return codes
}

var (
	markerRE      = regexp.MustCompile(`\[reason_code(_pending)?: ([A-Z][A-Z0-9_]*)\]`)
	markerStartRE = regexp.MustCompile(`\[reason_code`)
)

// checkReasonCodes returns the violations in src: a malformed or wrapped
// marker, a reason_code marker naming an unregistered code, a
// reason_code_pending marker naming a code that is now registered, and a
// registered code mentioned outside a marker.
func checkReasonCodes(src string, registry map[string]bool) (registered, pending []string, problems []string) {
	matches := markerRE.FindAllStringSubmatch(src, -1)
	if n := len(markerStartRE.FindAllString(src, -1)); n != len(matches) {
		problems = append(problems, fmt.Sprintf("%d reason-code markers, %d well formed: write each as [reason_code: X] or [reason_code_pending: X] on one line", n, len(matches)))
	}
	for _, m := range matches {
		code := m[2]
		if m[1] == "" {
			registered = append(registered, code)
			if !registry[code] {
				problems = append(problems, fmt.Sprintf("[reason_code: %s] is not in reason-codes-v1.json", code))
			}
		} else {
			pending = append(pending, code)
			if registry[code] {
				problems = append(problems, fmt.Sprintf("[reason_code_pending: %s] is registered now; mark it [reason_code: %s]", code, code))
			}
		}
	}
	outside := markerRE.ReplaceAllString(src, "")
	for code := range registry {
		if regexp.MustCompile(`\b` + code + `\b`).MatchString(outside) {
			problems = append(problems, fmt.Sprintf("registered code %s is named outside a marker", code))
		}
	}
	sort.Strings(problems)
	return registered, pending, problems
}

// Every reason code the proto names exists in the one registry, or is marked
// pending and does not exist yet (ADR-0001 §6).
func TestReasonCodesExistInRegistry(t *testing.T) {
	registry := registeredCodes(t)

	planted := "// [reason_code: NOT_A_REGISTERED_CODE] [reason_code_pending: BUDGET_EXCEEDED]\n" +
		"// APPROVAL_REQUIRED [reason_code_pending:\n// WRAPPED]"
	if _, _, problems := checkReasonCodes(planted, registry); len(problems) != 4 {
		t.Fatalf("checker found %d of the 4 planted problems: %v", len(problems), problems)
	}

	registered, pending, problems := checkReasonCodes(readRepoFile(t, protoRel), registry)
	for _, p := range problems {
		t.Error(p)
	}
	if len(registered) == 0 || len(pending) == 0 {
		t.Fatalf("expected both registered and pending markers, got %d and %d", len(registered), len(pending))
	}
	for _, code := range []string{"EMERGENCY_STOP_FENCED", "BUDGET_EXCEEDED", "APPROVAL_REQUIRED", "APPROVAL_TIMEOUT", "SCHEMA_VIOLATION"} {
		if !slices.Contains(registered, code) {
			t.Errorf("the proto no longer names %s", code)
		}
	}
	// ADR-0001 §6's codes to register, plus IDEMPOTENCY_CONFLICT and
	// STEP_UP_REQUIRED, which this contract adds. When one is
	// registered, this test fails until its marker changes.
	for _, code := range []string{
		"PRINCIPAL_INACTIVE", "MANDATE_INACTIVE", "MANDATE_OUTSIDE_VALIDITY", "EFFECT_OUT_OF_SCOPE",
		"PER_CALL_LIMIT", "ARITHMETIC_OVERFLOW", "APPROVER_NOT_DISTINCT", "APPROVAL_REJECTED",
		"INSUFFICIENT_CREDIT", "ROUTE_UNPRICED", "AUTHORITY_CHANGED", "PERMIT_EXPIRED", "IDEMPOTENCY_CONFLICT",
		"STEP_UP_REQUIRED",
	} {
		if !slices.Contains(pending, code) && !slices.Contains(registered, code) {
			t.Errorf("the proto no longer names %s", code)
		}
	}
}

var (
	rpcRE   = regexp.MustCompile(`^\s*rpc (\w+)\(`)
	scopeRE = regexp.MustCompile(`Token scope: ([a-z][a-z.]*[a-z])`)
)

// rpcScopes reads the "Token scope:" line from each RPC's leading comment.
func rpcScopes(src string) (map[string][]string, error) {
	scopes := map[string][]string{}
	var comment []string
	for _, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "//"):
			comment = append(comment, trimmed)
		case rpcRE.MatchString(line):
			name := rpcRE.FindStringSubmatch(line)[1]
			if _, dup := scopes[name]; dup {
				return nil, fmt.Errorf("rpc %s declared twice", name)
			}
			scopes[name] = nil
			for _, m := range scopeRE.FindAllStringSubmatch(strings.Join(comment, "\n"), -1) {
				scopes[name] = append(scopes[name], m[1])
			}
			comment = nil
		default:
			comment = nil
		}
	}
	return scopes, nil
}

// Each RPC names exactly the token scopes WS-B proposed and the coordinator
// resolved (docs/architecture/gateway-effect-api.md, "Resolved").
func TestRPCTokenScopes(t *testing.T) {
	want := map[string][]string{
		"Propose":           {"helm.gateway.propose"},
		"Approve":           {"helm.gateway.decide"},
		"Reject":            {"helm.gateway.decide"},
		"Cancel":            {"helm.gateway.propose", "helm.gateway.stop"},
		"Dispatch":          {"helm.gateway.execute"},
		"Observe":           {"helm.gateway.execute"},
		"GetAttempt":        {"helm.gateway.read"},
		"GetAttemptContent": {"helm.gateway.read"},
		"Stop":              {"helm.gateway.stop"},
		"Lift":              {"helm.gateway.stop"},
	}

	planted := "  // Token scope: helm.gateway.read.\n  // Token scope: helm.gateway.stop.\n  rpc Planted(PlantedRequest) returns (PlantedResponse);\n" +
		"  rpc Bare(BareRequest) returns (BareResponse);\n"
	got, err := rpcScopes(planted)
	if err != nil || len(got["Planted"]) != 2 || len(got["Bare"]) != 0 {
		t.Fatalf("scope parser misread the planted RPCs: %v, %v", got, err)
	}

	got, err = rpcScopes(readRepoFile(t, protoRel))
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

// Field numbers held for fields a later slice shapes (the step-up assertion,
// typed result payloads). They are not `reserved`, since buf breaking would
// then reject the field that takes the number, so this test keeps them free.
// The slice that adds such a field updates this list.
func TestHeldFieldNumbersStayFree(t *testing.T) {
	held := []struct {
		msg     protoreflect.MessageDescriptor
		numbers []protoreflect.FieldNumber
	}{
		{(&ApproveRequest{}).ProtoReflect().Descriptor(), []protoreflect.FieldNumber{4}},
		{(&Observation{}).ProtoReflect().Descriptor(), []protoreflect.FieldNumber{7, 8, 9, 10, 11, 12, 13, 14, 15}},
	}
	for _, h := range held {
		for _, n := range h.numbers {
			if f := h.msg.Fields().ByNumber(n); f != nil {
				t.Errorf("%s field %d is held, but %s uses it", h.msg.FullName(), n, f.Name())
			}
		}
	}
	// Planted: ApproveRequest field 1 is taken, and ByNumber must see it.
	if (&ApproveRequest{}).ProtoReflect().Descriptor().Fields().ByNumber(1) == nil {
		t.Fatal("ByNumber missed a field that exists")
	}
}

// approvalDigestV1 is the reference construction of
// PendingApproval.approval_digest, as the design note specifies it.
func approvalDigestV1(attemptID string, targetDigest, argumentDigest []byte, quote []*ResourceAmount, expiresAt *timestamppb.Timestamp) []byte {
	h := sha256.New()
	u64 := func(v uint64) {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], v)
		h.Write(b[:])
	}
	field := func(b []byte) {
		u64(uint64(len(b)))
		h.Write(b)
	}
	field([]byte("helm.gateway.v1.approval-digest.v1"))
	field([]byte(attemptID))
	field(targetDigest)
	field(argumentDigest)
	sorted := slices.Clone(quote)
	slices.SortFunc(sorted, func(a, b *ResourceAmount) int { return strings.Compare(a.GetUnit(), b.GetUnit()) })
	u64(uint64(len(sorted)))
	for _, q := range sorted {
		field([]byte(q.GetUnit()))
		u64(uint64(q.GetAmount()))
	}
	u64(uint64(expiresAt.GetSeconds()))
	var nanos [4]byte
	binary.BigEndian.PutUint32(nanos[:], uint32(expiresAt.GetNanos()))
	h.Write(nanos[:])
	return h.Sum(nil)
}

// The approval-digest test vector. The expected value was computed by a
// separate Python implementation of the design note's construction; the
// note carries the same value, so a client can check its own encoder.
func TestApprovalDigestVector(t *testing.T) {
	const want = "cb2cd8caa08ee2544750dd59644a0d2f3bb16a729be108520055c2f72c5f53d7"
	target := sha256.Sum256([]byte("github.com/Mindburn-Labs/example/pull/42"))
	args := sha256.Sum256([]byte(`{"merge_method":"squash"}`))
	quote := []*ResourceAmount{{Unit: "count", Amount: 1}, {Unit: "USD", Amount: 2500}}
	expires := timestamppb.New(time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC))

	got := hex.EncodeToString(approvalDigestV1("0192f0c4-7a1e-7c3b-9d2a-5b8e4f1a2c3d", target[:], args[:], quote, expires))
	if got != want {
		t.Fatalf("approval digest = %s, want %s", got, want)
	}
	// Planted: reordering the quote input must not change the digest, and
	// changing an amount must.
	reordered := approvalDigestV1("0192f0c4-7a1e-7c3b-9d2a-5b8e4f1a2c3d", target[:], args[:], []*ResourceAmount{quote[1], quote[0]}, expires)
	if hex.EncodeToString(reordered) != want {
		t.Error("the digest depends on quote order; entries must be sorted by unit")
	}
	changed := approvalDigestV1("0192f0c4-7a1e-7c3b-9d2a-5b8e4f1a2c3d", target[:], args[:], []*ResourceAmount{{Unit: "count", Amount: 1}, {Unit: "USD", Amount: 2501}}, expires)
	if hex.EncodeToString(changed) == want {
		t.Error("the digest ignores the quote amount")
	}
	if !strings.Contains(readRepoFile(t, "docs/architecture/gateway-effect-api.md"), want) {
		t.Error("docs/architecture/gateway-effect-api.md does not carry the test vector")
	}
}
