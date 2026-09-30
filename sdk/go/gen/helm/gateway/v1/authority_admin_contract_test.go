// Contract tests for the gateway provisioning API (AuthorityAdminService,
// docs/architecture/gateway-provisioning-api.md). They pin the wire shape the
// Control Plane builds against: the RPCs, the idempotency key on every request,
// the absence of any tenant on the wire, the one token scope, the reason codes
// the proto names, and activation digest v1. Every checker also runs on a
// planted violation first, so a checker that cannot fail fails the test.
//
// quantum_posture: contract test only; it reads descriptors and the proto
// source, computes SHA-256 activation-digest vectors, and signs or verifies
// nothing.
package gatewayv1

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
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

// The eight provisioning RPCs, unary, each with its own request and response.
func TestAuthorityAdminServiceHasItsRPCs(t *testing.T) {
	want := []string{"UpsertTenant", "UpsertPrincipal", "DeactivatePrincipal", "RegisterEffectTypes", "ActivateRootMandate",
		"DelegateMandate", "RevokeMandate", "SetLimit"}
	methods := adminService(t).Methods()
	var got []string
	for i := 0; i < methods.Len(); i++ {
		m := methods.Get(i)
		name := string(m.Name())
		got = append(got, name)
		if m.IsStreamingClient() || m.IsStreamingServer() {
			t.Errorf("%s streams; every provisioning RPC is unary", name)
		}
		if in := string(m.Input().Name()); in != name+"Request" {
			t.Errorf("%s takes %s, want %sRequest", name, in, name)
		}
		if out := string(m.Output().Name()); out != name+"Response" {
			t.Errorf("%s returns %s, want %sResponse", name, out, name)
		}
		// Writes: none is a read, so none may be marked NO_SIDE_EFFECTS, which
		// would let Connect serve it over GET.
		if level := m.Options().(*descriptorpb.MethodOptions).GetIdempotencyLevel(); level != descriptorpb.MethodOptions_IDEMPOTENCY_UNKNOWN {
			t.Errorf("%s idempotency_level = %v, want unset", name, level)
		}
	}
	if !slices.Equal(got, want) {
		t.Fatalf("RPCs = %v, want %v", got, want)
	}

	procedures := map[string]string{
		AuthorityAdminServiceUpsertTenantProcedure:        "UpsertTenant",
		AuthorityAdminServiceUpsertPrincipalProcedure:     "UpsertPrincipal",
		AuthorityAdminServiceDeactivatePrincipalProcedure: "DeactivatePrincipal",
		AuthorityAdminServiceRegisterEffectTypesProcedure: "RegisterEffectTypes",
		AuthorityAdminServiceActivateRootMandateProcedure: "ActivateRootMandate",
		AuthorityAdminServiceDelegateMandateProcedure:     "DelegateMandate",
		AuthorityAdminServiceRevokeMandateProcedure:       "RevokeMandate",
		AuthorityAdminServiceSetLimitProcedure:            "SetLimit",
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

// Every request opens with the tenant-scoped idempotency key (R6).
func TestEveryAdminRequestCarriesAnIdempotencyKey(t *testing.T) {
	// Planted violation: ApproveRequest's first field is not a key.
	planted := (&ApproveRequest{}).ProtoReflect().Descriptor().Fields().ByNumber(1)
	if planted.Name() == "idempotency_key" {
		t.Fatal("the planted message already has a key; the check below could not fail")
	}
	methods := adminService(t).Methods()
	for i := 0; i < methods.Len(); i++ {
		in := methods.Get(i).Input()
		f := in.Fields().ByNumber(1)
		if f == nil || f.Name() != "idempotency_key" || f.Kind() != protoreflect.StringKind {
			t.Errorf("%s field 1 is %v, want the string idempotency_key", in.FullName(), f)
		}
	}
}

// adminIdentityFieldAllowed names the request fields the identity rule of
// gateway.proto would flag but that provisioning needs: they name the object
// being provisioned, and the gateway checks them against its own rows. No
// request may name a tenant or a workspace.
var adminIdentityFieldAllowed = map[string]string{
	"helm.gateway.v1.UpsertPrincipalRequest.principal_id":     "the principal being registered",
	"helm.gateway.v1.DeactivatePrincipalRequest.principal_id": "the principal being disabled",
}

func TestNoAdminRequestNamesATenantOrWorkspace(t *testing.T) {
	// Planted violation: a field that names a tenant is flagged.
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

// Amounts and limits are integers: no float anywhere in the file.
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

// Every RPC takes the one provisioning scope.
func TestAuthorityAdminTokenScope(t *testing.T) {
	got, err := rpcScopes(readRepoFile(t, adminProtoRel))
	if err != nil {
		t.Fatal(err)
	}
	methods := adminService(t).Methods()
	if len(got) != methods.Len() {
		t.Errorf("found scopes for %d RPCs, want %d: %v", len(got), methods.Len(), got)
	}
	for i := 0; i < methods.Len(); i++ {
		name := string(methods.Get(i).Name())
		if s := got[name]; !slices.Equal(s, []string{"helm.gateway.provision"}) {
			t.Errorf("rpc %s names token scopes %v, want [helm.gateway.provision]", name, s)
		}
	}
}

// Every reason code the proto names is registered today (ADR-0001 §6): the
// provisioning API emits only codes the registry already has.
func TestAuthorityAdminReasonCodesAreRegistered(t *testing.T) {
	registry := registeredCodes(t)
	registered, pending, problems := checkReasonCodes(readRepoFile(t, adminProtoRel), registry)
	for _, p := range problems {
		t.Error(p)
	}
	if len(pending) != 0 {
		t.Errorf("reason_code_pending markers %v: the provisioning API registers no new code", pending)
	}
	for _, code := range []string{"SCHEMA_VIOLATION", "IDEMPOTENCY_CONFLICT", "INSUFFICIENT_PRIVILEGE", "TENANT_ISOLATION",
		"IDENTITY_ISOLATION_VIOLATION", "DELEGATION_SCOPE_VIOLATION", "PRINCIPAL_INACTIVE", "MANDATE_INACTIVE",
		"EMERGENCY_STOP_FENCED", "APPROVER_NOT_DISTINCT", "APPROVAL_REQUIRED", "AUTHORITY_CHANGED"} {
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
		{MandateStatus(0).Descriptor(), []string{"0:MANDATE_STATUS_UNSPECIFIED", "1:MANDATE_STATUS_ACTIVE", "2:MANDATE_STATUS_REVOKED"}},
		{LimitMeasure(0).Descriptor(), []string{"0:LIMIT_MEASURE_UNSPECIFIED", "1:LIMIT_MEASURE_SUM", "2:LIMIT_MEASURE_COUNT", "3:LIMIT_MEASURE_DISTINCT"}},
		{LimitWindow(0).Descriptor(), []string{"0:LIMIT_WINDOW_UNSPECIFIED", "1:LIMIT_WINDOW_NONE", "2:LIMIT_WINDOW_HOUR", "3:LIMIT_WINDOW_DAY", "4:LIMIT_WINDOW_MONTH"}},
	}
	for _, c := range cases {
		if got := enumValues(c.enum); !slices.Equal(got, c.want) {
			t.Errorf("%s = %v, want %v", c.enum.FullName(), got, c.want)
		}
	}
}

// activationDigestV1 is the reference construction of activation digest v1, as
// the design note specifies it, over the wire messages. It is independent of
// the gateway's implementation and of testdata/activation_digest.py.
func activationDigestV1(holder, requestedBy string, terms *MandateTerms, limits []*LimitTerms) []byte {
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
	sortedSet := func(values []string) {
		set := slices.Clone(values)
		slices.Sort(set)
		set = slices.Compact(set)
		u64(uint64(len(set)))
		for _, v := range set {
			field([]byte(v))
		}
	}
	optional := func(v *int64) {
		if v == nil {
			h.Write([]byte{0})
			return
		}
		h.Write([]byte{1})
		u64(uint64(*v))
	}
	field([]byte("helm.gateway.v1.mandate-activation-digest.v1"))
	field([]byte(holder))
	field([]byte(requestedBy))
	sortedSet(terms.GetEffectTypes())
	optional(terms.PerCallLimit)
	optional(terms.ApprovalThreshold)
	field([]byte(microsText(terms.GetValidFrom())))
	field([]byte(microsText(terms.GetValidUntil())))
	sortedSet(terms.GetTargets())
	field([]byte(terms.GetCondition()))
	sortedSet(terms.GetApprovalRequired())
	types := make([]string, 0, len(terms.GetRiskClasses()))
	for effectType := range terms.GetRiskClasses() {
		types = append(types, effectType)
	}
	slices.Sort(types)
	u64(uint64(len(types)))
	for _, effectType := range types {
		field([]byte(effectType))
		field([]byte(strings.ToLower(strings.TrimPrefix(terms.GetRiskClasses()[effectType].String(), "RISK_CLASS_"))))
	}
	ordered := slices.Clone(limits)
	slices.SortFunc(ordered, func(a, b *LimitTerms) int {
		for _, c := range []int{
			strings.Compare(a.GetUnit(), b.GetUnit()),
			strings.Compare(measureName(a.GetMeasure()), measureName(b.GetMeasure())),
			strings.Compare(windowName(a.GetWindow()), windowName(b.GetWindow())),
			int(a.GetSpan()) - int(b.GetSpan()),
		} {
			if c != 0 {
				return c
			}
		}
		switch {
		case a.GetValue() < b.GetValue():
			return -1
		case a.GetValue() > b.GetValue():
			return 1
		}
		return 0
	})
	u64(uint64(len(ordered)))
	for _, l := range ordered {
		field([]byte(l.GetUnit()))
		field([]byte(measureName(l.GetMeasure())))
		field([]byte(windowName(l.GetWindow())))
		u64(uint64(l.GetSpan()))
		u64(uint64(l.GetValue()))
	}
	return h.Sum(nil)
}

func measureName(m LimitMeasure) string {
	return strings.ToLower(strings.TrimPrefix(m.String(), "LIMIT_MEASURE_"))
}

func windowName(w LimitWindow) string {
	return strings.ToLower(strings.TrimPrefix(w.String(), "LIMIT_WINDOW_"))
}

// microsText is a timestamp as the digest encodes it: RFC 3339, UTC, exactly
// six fractional digits, truncated to microseconds, never rounded.
func microsText(ts *timestamppb.Timestamp) string {
	return ts.AsTime().UTC().Truncate(time.Microsecond).Format("2006-01-02T15:04:05.000000Z")
}

func activationVector() (string, string, *MandateTerms, []*LimitTerms) {
	threshold := int64(0)
	terms := &MandateTerms{
		EffectTypes:       []string{"github.repository.get", "github.branch.create_from_changes", "github.repository.get"},
		ApprovalThreshold: &threshold,
		ValidFrom:         timestamppb.New(time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)),
		ValidUntil:        timestamppb.New(time.Date(2026, 10, 30, 12, 30, 45, 123456789, time.UTC)),
		Targets:           []string{"github.com/Mindburn-Labs/example", "github.com/Mindburn-Labs/other"},
		Condition:         `input.args.head.startsWith("helm/")`,
		ApprovalRequired:  []string{"github.branch.create_from_changes"},
		RiskClasses: map[string]RiskClass{
			"github.repository.get":             RiskClass_RISK_CLASS_LOW,
			"github.branch.create_from_changes": RiskClass_RISK_CLASS_MEDIUM,
		},
	}
	limits := []*LimitTerms{
		{Unit: "usd_cents", Measure: LimitMeasure_LIMIT_MEASURE_SUM, Window: LimitWindow_LIMIT_WINDOW_MONTH, Span: 1, Value: 50000},
		{Unit: "count", Measure: LimitMeasure_LIMIT_MEASURE_COUNT, Window: LimitWindow_LIMIT_WINDOW_DAY, Span: 1, Value: 20},
	}
	return "agent-a", "human-a", terms, limits
}

// The activation digest test vector. testdata/activation_digest.py is a
// separate Python implementation of the design note's construction; the Go
// reference, the Python one and the note must carry the same value, so the
// Control Plane can check its own encoder before it mints an approval token.
func TestActivationDigestVector(t *testing.T) {
	const want = "fe6393c4a564545f1e6b835f0e06eddc7d555120272158e578f8ca6a1908c527"
	holder, requestedBy, terms, limits := activationVector()
	got := hex.EncodeToString(activationDigestV1(holder, requestedBy, terms, limits))
	if got != want {
		t.Fatalf("activation digest = %s, want %s", got, want)
	}
	// Planted: the digest ignores the order of set-like fields and the
	// nanoseconds below a microsecond; it must follow every other field.
	reordered := &MandateTerms{}
	reordered.EffectTypes = slices.Clone(terms.EffectTypes)
	slices.Reverse(reordered.EffectTypes)
	reordered.ApprovalThreshold, reordered.ValidFrom, reordered.ValidUntil = terms.ApprovalThreshold, terms.ValidFrom, terms.ValidUntil
	reordered.Targets = []string{terms.Targets[1], terms.Targets[0]}
	reordered.Condition, reordered.ApprovalRequired, reordered.RiskClasses = terms.Condition, terms.ApprovalRequired, terms.RiskClasses
	if hex.EncodeToString(activationDigestV1(holder, requestedBy, reordered, []*LimitTerms{limits[1], limits[0]})) != want {
		t.Error("the digest depends on the order of effect types, targets or limits; they are sorted before encoding")
	}
	trimmed := &MandateTerms{
		EffectTypes: terms.EffectTypes, ApprovalThreshold: terms.ApprovalThreshold, ValidFrom: terms.ValidFrom,
		ValidUntil: timestamppb.New(time.Date(2026, 10, 30, 12, 30, 45, 123456000, time.UTC)), Targets: terms.Targets,
		Condition: terms.Condition, ApprovalRequired: terms.ApprovalRequired, RiskClasses: terms.RiskClasses,
	}
	if hex.EncodeToString(activationDigestV1(holder, requestedBy, trimmed, limits)) != want {
		t.Error("nanoseconds below a microsecond change the digest; they are truncated")
	}
	for name, digest := range map[string][]byte{
		"holder":       activationDigestV1("agent-b", requestedBy, terms, limits),
		"requested_by": activationDigestV1(holder, "human-b", terms, limits),
		"limit value":  activationDigestV1(holder, requestedBy, terms, []*LimitTerms{limits[0], {Unit: "count", Measure: LimitMeasure_LIMIT_MEASURE_COUNT, Window: LimitWindow_LIMIT_WINDOW_DAY, Span: 1, Value: 21}}),
		"no limits":    activationDigestV1(holder, requestedBy, terms, nil),
	} {
		if hex.EncodeToString(digest) == want {
			t.Errorf("the digest ignores the %s", name)
		}
	}

	// The independent Python implementation. A missing interpreter fails the
	// test: a vector nobody recomputed proves nothing.
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatalf("python3 is required for the cross-implementation check: %v", err)
	}
	out, err := exec.Command(python, filepath.Join("testdata", "activation_digest.py")).Output()
	if err != nil {
		t.Fatalf("testdata/activation_digest.py: %v", err)
	}
	var py struct {
		Digest         string `json:"digest"`
		Truncated      string `json:"truncated"`
		Reordered      string `json:"reordered"`
		ValidUntilText string `json:"valid_until_text"`
	}
	if err := json.Unmarshal(out, &py); err != nil {
		t.Fatalf("testdata/activation_digest.py output: %v", err)
	}
	if py.Digest != want || py.Truncated != want || py.Reordered != want || py.ValidUntilText != "2026-10-30T12:30:45.123456Z" {
		t.Errorf("the Python reference disagrees with Go: %+v, want %s", py, want)
	}

	doc := readRepoFile(t, "docs/architecture/gateway-provisioning-api.md")
	for _, v := range []string{want, "2026-10-30T12:30:45.123456Z"} {
		if !strings.Contains(doc, v) {
			t.Errorf("docs/architecture/gateway-provisioning-api.md does not carry %s", v)
		}
	}
}
