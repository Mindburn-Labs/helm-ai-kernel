package tonacton

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/connectors/ton/acton"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
)

const (
	testSecret = "testnet-wallet-secret-do-not-leak"
	txHash     = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	address    = "EQDtestnetaddress"
)

// fakeActon is a stand-in Acton binary. MODE selects its behaviour; it logs
// each run's argv and whether the wallet variable was set, never the value.
type fakeActon struct {
	bin, log, mode string
}

func newFakeActon(t *testing.T) *fakeActon {
	t.Helper()
	dir := t.TempDir()
	f := &fakeActon{bin: filepath.Join(dir, "acton"), log: filepath.Join(dir, "log"), mode: filepath.Join(dir, "mode")}
	script := fmt.Sprintf(`#!/bin/sh
mode=$(cat %[3]s 2>/dev/null)
if [ -n "$ACTON_WALLET_SECRET" ]; then w=wallet; else w=nowallet; fi
echo "$w $PWD $@" >> %[2]s
env | sort | cut -d= -f1 | tr '\n' ' ' >> %[2]s; echo >> %[2]s
case "$mode" in
  sleep) exec sleep 30;;
  fail) echo "boom" >&2; exit 3;;
  badshape) echo "not json at all"; exit 0;;
  leak) echo "{\"address\":\"%[4]s\",\"tx_hash\":\"%[5]s\",\"note\":\"$ACTON_WALLET_SECRET\"}"; exit 0;;
esac
case "$1" in
  script|verify|library)
    if [ -n "$ACTON_WALLET_SECRET" ]; then echo '{"address":"%[4]s","tx_hash":"%[5]s","amount_ton":"0.05"}'; else echo '{"fork":"ok"}'; fi;;
  --version) echo "acton 1.0.0 (tolk 1.4.0)";;
  *) echo '{"ok":true}';;
esac
`, "", f.log, f.mode, address, txHash)
	if err := os.WriteFile(f.bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fakeActon) setMode(t *testing.T, m string) {
	t.Helper()
	if err := os.WriteFile(f.mode, []byte(m), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (f *fakeActon) runs(t *testing.T) []string {
	t.Helper()
	b, _ := os.ReadFile(f.log)
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

type fakeChain struct {
	found bool
	err   error
	calls int
}

func (c *fakeChain) FindTransaction(_ context.Context, a, h string) (ChainTx, error) {
	c.calls++
	if c.err != nil {
		return ChainTx{}, c.err
	}
	if a != address || h != txHash {
		return ChainTx{}, nil
	}
	return ChainTx{Found: c.found, Evidence: []byte("chain-evidence")}, nil
}

type creds struct {
	secret string
	err    error
}

func (c creds) Token(context.Context) (string, error) { return c.secret, c.err }

type rig struct {
	t         *testing.T
	a         *Adapter
	fake      *fakeActon
	chain     *fakeChain
	workspace string
}

func newRig(t *testing.T, withChain bool) *rig {
	t.Helper()
	r := &rig{t: t, fake: newFakeActon(t), chain: &fakeChain{found: true}, workspace: t.TempDir()}
	cfg := Config{Binary: r.fake.bin, WorkspaceRoot: r.workspace, Timeout: 3 * time.Second, Isolation: []string{"/usr/bin/env"}}
	if withChain {
		cfg.Chain = r.chain
	}
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r.a = a
	return r
}

func (r *rig) project(name string) {
	if err := os.MkdirAll(filepath.Join(r.workspace, "t1", name), 0o750); err != nil {
		r.t.Fatal(err)
	}
}

func effectOf(t *testing.T, action acton.ActionURN, project string, args map[string]any) (adapters.Effect, []byte) {
	t.Helper()
	o, ok := lookup(effectargs.TONActonPrefix + strings.TrimPrefix(string(action), actionPrefix))
	if !ok {
		t.Fatalf("no op for %s", action)
	}
	args["schema"] = o.schemaConst()
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	return adapters.Effect{EffectType: o.effectType(), Target: "ton-acton:" + project, Arguments: raw,
		Invocation: &adapters.Invocation{TenantID: "t1", WorkspaceID: "w1", AttemptID: "att-1", PermitID: "p1", RequesterPrincipalID: "agent"}}, sum[:]
}

func scriptArgs() map[string]any {
	eff := map[string]any{"effect_kind": "TON_LIBRARY_PUBLISH", "effect_class": "IRREVERSIBLE", "network": "testnet",
		"wallet_ref": "wallet:tenant-test-1", "max_ton_spend": "0.05"}
	return map[string]any{
		"library_path": "libs/lib.boc", "wallet_ref": "wallet:tenant-test-1", "max_ton_spend": "0.05",
		"expected_effects": []any{eff},
	}
}

func TestDeclarationsAreTheOwnersScopeAndNeverMainnet(t *testing.T) {
	local := newRig(t, false)
	for _, d := range local.a.Declarations() {
		if strings.Contains(d.EffectType, "testnet") && !strings.Contains(d.EffectType, "fork") {
			t.Fatalf("%s is declared without a chain reader", d.EffectType)
		}
	}
	full := newRig(t, true)
	declared := map[string]bool{}
	for _, d := range full.a.Declarations() {
		declared[d.EffectType] = true
		if effectargs.IsTONActonMainnet(d.EffectType) {
			t.Fatalf("%s is a mainnet effect and must not be declared", d.EffectType)
		}
		if _, err := adapters.CompileArgumentSchema(d); err != nil {
			t.Fatalf("%s argument schema: %v", d.EffectType, err)
		}
		if _, err := adapters.CompileResultSchema(d); err != nil {
			t.Fatalf("%s result schema: %v", d.EffectType, err)
		}
	}
	if declared["ton.acton.script.testnet"] {
		t.Fatal("script.testnet runs tenant code next to a signing key and must not be declared")
	}
	bare, _ := New(Config{Binary: full.fake.bin, WorkspaceRoot: full.workspace, Chain: full.chain})
	for _, d := range bare.Declarations() {
		o, _ := lookup(d.EffectType)
		if o.needsIsolation() {
			t.Fatalf("%s runs over tenant files and is declared without an isolation command", d.EffectType)
		}
	}
	if len(bare.Declarations()) != 6 {
		t.Fatalf("without isolation only the six operations that do not run over tenant files remain: %d", len(bare.Declarations()))
	}
	for _, want := range []string{"ton.acton.contract.build", "ton.acton.script.fork_mainnet",
		"ton.acton.library.publish_testnet", "ton.acton.library.topup_testnet", "ton.acton.source.verify_testnet", "ton.acton.library.fetch"} {
		if !declared[want] {
			t.Errorf("%s is not declared", want)
		}
	}
}

// Every connector command is admitted, left out on purpose, or a refused
// mainnet command: a new command is never admitted by default.
func TestEveryConnectorCommandIsDecided(t *testing.T) {
	admitted := map[acton.ActionURN]bool{}
	for _, o := range ops {
		admitted[o.action] = true
	}
	skipped := map[acton.ActionURN]bool{}
	for _, a := range notAdmitted {
		skipped[a] = true
	}
	for _, urn := range acton.AllActionURNs() {
		spec, _ := acton.ClassifyAction(urn)
		mainnet := spec.Network == acton.NetworkMainnet && spec.Broadcast
		effectType := effectargs.TONActonPrefix + strings.TrimPrefix(string(urn), actionPrefix)
		switch {
		case urn == acton.ActionScriptTestnet:
			if admitted[urn] || !effectargs.IsTONActonKeyWithTenantCode(effectType) {
				t.Errorf("%s runs a script with a signing key and must be refused, not admitted", urn)
			}
		case mainnet:
			if admitted[urn] || !effectargs.IsTONActonMainnet(effectType) {
				t.Errorf("%s is a mainnet broadcast and must be refused, not admitted", urn)
			}
		case admitted[urn] == skipped[urn]:
			t.Errorf("%s must be exactly one of admitted and not admitted", urn)
		}
		if admitted[urn] && effectargs.IsTONActonMainnet(effectType) {
			t.Errorf("%s is admitted and refused", urn)
		}
	}
}

func TestMainnetEffectsAreRefusedByTheAdapterToo(t *testing.T) {
	r := newRig(t, true)
	for _, et := range []string{"ton.acton.script.mainnet", "ton.acton.library.publish_mainnet", "ton.acton.library.topup_mainnet", "ton.acton.source.verify_mainnet", "ton.acton.script.testnet"} {
		e := adapters.Effect{EffectType: et, Target: "ton-acton:p", Arguments: []byte(`{}`)}
		sum := sha256.Sum256(e.Arguments)
		got := r.a.Dispatch(context.Background(), creds{secret: testSecret}, e, sum[:])
		want := contracts.ReasonTONMainnetRefused
		if et == "ton.acton.script.testnet" {
			want = contracts.ReasonTONTenantCodeWithKeyRefused
		}
		if got.Status != adapters.DispatchNotSent || got.Reason != want {
			t.Fatalf("%s: %+v", et, got)
		}
		if _, err := r.a.Prepare(context.Background(), nil, e); err == nil {
			t.Fatalf("%s: Prepare accepted a mainnet effect", et)
		}
	}
	if _, err := os.Stat(r.fake.log); err == nil {
		t.Fatal("acton ran for a mainnet effect")
	}
}

func TestLocalBuildRunsWithoutTheWalletAndReadsBack(t *testing.T) {
	r := newRig(t, true)
	r.project("demo")
	e, digest := effectOf(t, acton.ActionBuild, "demo", map[string]any{})
	if got := r.a.Dispatch(context.Background(), creds{secret: testSecret}, e, digest); got.Status != adapters.DispatchSent {
		t.Fatalf("dispatch: %+v", got)
	}
	runs := r.fake.runs(t)
	if !strings.HasPrefix(runs[0], "nowallet ") || !strings.Contains(runs[0], "/t1/demo build") {
		t.Fatalf("unexpected run: %v", runs)
	}
	if strings.Contains(runs[1], "ACTON_WALLET_SECRET") {
		t.Fatal("a local operation received the wallet variable")
	}
	obs := r.a.Observe(context.Background(), nil, e)
	if obs.Outcome != adapters.OutcomeSucceeded || obs.Observation == nil || obs.Observation.Artifact == nil {
		t.Fatalf("observe: %+v", obs)
	}
	d := declarationOf(t, r.a, e.EffectType)
	schema, _ := adapters.CompileResultSchema(d)
	if err := schema.Validate(obs.Observation.Artifact); err != nil {
		t.Fatalf("the artifact breaks the declared result schema: %v", err)
	}
	if again := r.a.Observe(context.Background(), nil, e); again.Outcome != adapters.OutcomeSucceeded {
		t.Fatalf("Observe is not repeatable: %+v", again)
	}
}

func declarationOf(t *testing.T, a *Adapter, effectType string) adapters.Declaration {
	t.Helper()
	for _, d := range a.Declarations() {
		if d.EffectType == effectType {
			return d
		}
	}
	t.Fatalf("%s not declared", effectType)
	return adapters.Declaration{}
}

func TestTestnetBroadcastKeepsTheSecretInTheEnvironmentOnly(t *testing.T) {
	r := newRig(t, true)
	r.project("demo")
	e, digest := effectOf(t, acton.ActionLibraryPublishTN, "demo", scriptArgs())
	if got := r.a.Dispatch(context.Background(), creds{secret: testSecret}, e, digest); got.Status != adapters.DispatchSent {
		t.Fatalf("dispatch: %+v", got)
	}
	runs := r.fake.runs(t)
	if !strings.HasPrefix(runs[0], "wallet ") || !strings.Contains(runs[1], "ACTON_WALLET_SECRET") || strings.Contains(runs[0], testSecret) {
		t.Fatalf("the secret must be in the environment and not in argv: %v", runs)
	}
	if strings.Contains(runs[0], "--tonconnect") {
		t.Fatal("the gateway must not ask for an interactive wallet")
	}
	obs := r.a.Observe(context.Background(), nil, e)
	if obs.Outcome != adapters.OutcomeSucceeded || r.chain.calls != 1 {
		t.Fatalf("observe: %+v chain calls %d", obs, r.chain.calls)
	}
	var res Result
	if err := json.Unmarshal(obs.Observation.Artifact.CanonicalBytes, &res); err != nil || res.ChainConfirmed == nil || !*res.ChainConfirmed || res.TxHash != txHash {
		t.Fatalf("result: %+v %v", res, err)
	}
	filepath.WalkDir(r.workspace, func(p string, d os.DirEntry, _ error) error {
		if !d.IsDir() {
			if b, _ := os.ReadFile(p); strings.Contains(string(b), testSecret) {
				t.Errorf("the wallet secret reached %s", p)
			}
		}
		return nil
	})
	if strings.Contains(string(obs.Observation.Artifact.CanonicalBytes), testSecret) {
		t.Fatal("the secret is in the result")
	}
}

func TestSecretEchoedByActonIsRedacted(t *testing.T) {
	r := newRig(t, true)
	r.project("demo")
	r.fake.setMode(t, "leak")
	e, digest := effectOf(t, acton.ActionLibraryPublishTN, "demo", scriptArgs())
	r.a.Dispatch(context.Background(), creds{secret: testSecret}, e, digest)
	obs := r.a.Observe(context.Background(), nil, e)
	if obs.Observation == nil || strings.Contains(string(obs.Observation.Artifact.CanonicalBytes), testSecret) ||
		!strings.Contains(string(obs.Observation.Artifact.CanonicalBytes), "REDACTED") {
		t.Fatalf("the echoed secret must be redacted: %+v", obs)
	}
}

func TestTestnetFailureModes(t *testing.T) {
	cases := []struct {
		name     string
		mode     string
		wantSent adapters.DispatchStatus
		reason   contracts.ReasonCode
		observe  adapters.Outcome
	}{
		{"wrong shape is drift, indefinite", "badshape", adapters.DispatchIndefinite, contracts.ReasonConnectorContractDrift, adapters.OutcomeUnknown},
		{"nonzero exit after broadcast is indefinite", "fail", adapters.DispatchIndefinite, contracts.ReasonProviderError, adapters.OutcomeUnknown},
		{"cut short is indefinite", "sleep", adapters.DispatchIndefinite, contracts.ReasonComputeTimeExhausted, adapters.OutcomeUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t, true)
			r.a.cfg.Timeout = 2 * time.Second
			r.project("demo")
			r.fake.setMode(t, c.mode)
			e, digest := effectOf(t, acton.ActionLibraryPublishTN, "demo", scriptArgs())
			got := r.a.Dispatch(context.Background(), creds{secret: testSecret}, e, digest)
			if got.Status != c.wantSent || got.Reason != c.reason {
				t.Fatalf("dispatch: %+v", got)
			}
			if obs := r.a.Observe(context.Background(), nil, e); obs.Outcome != c.observe {
				t.Fatalf("observe: %+v", obs)
			}
		})
	}
}

func TestChainReadBack(t *testing.T) {
	r := newRig(t, true)
	r.project("demo")
	e, digest := effectOf(t, acton.ActionLibraryPublishTN, "demo", scriptArgs())
	r.a.Dispatch(context.Background(), creds{secret: testSecret}, e, digest)

	r.chain.found = false
	if obs := r.a.Observe(context.Background(), nil, e); obs.Outcome != adapters.OutcomeFailed || !obs.Absent || obs.Observation == nil {
		t.Fatalf("a transaction testnet does not show is FAILED by absence: %+v", obs)
	}
	r.chain.err = errors.New("rpc down")
	if obs := r.a.Observe(context.Background(), nil, e); obs.Outcome != adapters.OutcomeUnknown {
		t.Fatalf("an unreadable chain is UNKNOWN: %+v", obs)
	}
}

func TestDispatchRefusals(t *testing.T) {
	r := newRig(t, true)
	r.project("demo")
	ctx := context.Background()

	e, digest := effectOf(t, acton.ActionBuild, "demo", map[string]any{})
	bad := sha256.Sum256([]byte("other"))
	if got := r.a.Dispatch(ctx, nil, e, bad[:]); got.Reason != contracts.ReasonPermitArgumentMismatch || got.Status != adapters.DispatchNotSent {
		t.Fatalf("digest: %+v", got)
	}

	ts, tsDigest := effectOf(t, acton.ActionLibraryPublishTN, "demo", scriptArgs())
	if got := r.a.Dispatch(ctx, creds{err: errors.New("none")}, ts, tsDigest); got.Reason != contracts.ReasonProviderCredentialRejected || got.Status != adapters.DispatchNotSent {
		t.Fatalf("no wallet: %+v", got)
	}
	over := scriptArgs()
	over["max_ton_spend"] = "5"
	oe, od := effectOf(t, acton.ActionLibraryPublishTN, "demo", over)
	if got := r.a.Dispatch(ctx, creds{secret: testSecret}, oe, od); got.Reason != contracts.ReasonTONSpendCeilingExceeded || got.Status != adapters.DispatchNotSent {
		t.Fatalf("spend: %+v", got)
	}
	if _, err := os.Stat(r.fake.log); err == nil {
		t.Fatal("acton ran for a refused effect")
	}

	missing, md2 := effectOf(t, acton.ActionBuild, "nope", map[string]any{})
	if got := r.a.Dispatch(ctx, nil, missing, md2); got.Status != adapters.DispatchNotSent || got.Reason != contracts.ReasonPreconditionFailed {
		t.Fatalf("missing project: %+v", got)
	}
	extra, ed := effectOf(t, acton.ActionBuild, "demo", map[string]any{"extra_flags": "--net mainnet"})
	if got := r.a.Dispatch(ctx, nil, extra, ed); got.Reason != contracts.ReasonSchemaViolation {
		t.Fatalf("unknown argument: %+v", got)
	}
	badTarget := e
	badTarget.Target = "ton-acton:../etc"
	if got := r.a.Dispatch(ctx, nil, badTarget, digest); got.Reason != contracts.ReasonSchemaViolation {
		t.Fatalf("target: %+v", got)
	}
	noInv := e
	noInv.Invocation = nil
	if got := r.a.Dispatch(ctx, nil, noInv, digest); got.Status != adapters.DispatchNotSent {
		t.Fatalf("invocation: %+v", got)
	}
}

func TestProjectCannotResolveOutsideTheTenantWorkspace(t *testing.T) {
	r := newRig(t, false)
	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(r.workspace, "t1"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(r.workspace, "t1", "evil")); err != nil {
		t.Fatal(err)
	}
	e, digest := effectOf(t, acton.ActionBuild, "evil", map[string]any{})
	if got := r.a.Dispatch(context.Background(), nil, e, digest); got.Status != adapters.DispatchNotSent || got.Reason != contracts.ReasonPreconditionFailed {
		t.Fatalf("symlink escape: %+v", got)
	}
}

func TestLocalFailureAndMissingBinary(t *testing.T) {
	r := newRig(t, false)
	r.project("demo")
	r.fake.setMode(t, "fail")
	// A write that failed may have written something: SENT, and Observe says FAILED.
	e, digest := effectOf(t, acton.ActionBuild, "demo", map[string]any{})
	if got := r.a.Dispatch(context.Background(), nil, e, digest); got.Status != adapters.DispatchSent {
		t.Fatalf("failed write: %+v", got)
	}
	if obs := r.a.Observe(context.Background(), nil, e); obs.Outcome != adapters.OutcomeFailed || obs.Absent || obs.Reason != contracts.ReasonProviderError {
		t.Fatalf("observe: %+v", obs)
	}
	// A pure operation that failed changed nothing: NOT_SENT.
	c, cd := effectOf(t, acton.ActionCheck, "demo", map[string]any{})
	c.Invocation.AttemptID = "att-check"
	if got := r.a.Dispatch(context.Background(), nil, c, cd); got.Status != adapters.DispatchNotSent {
		t.Fatalf("failed read: %+v", got)
	}

	gone, _ := New(Config{Binary: filepath.Join(t.TempDir(), "missing"), WorkspaceRoot: r.workspace})
	g, gd := effectOf(t, acton.ActionVersion, "demo", map[string]any{})
	g.Invocation.AttemptID = "att-gone"
	if got := gone.Dispatch(context.Background(), nil, g, gd); got.Status != adapters.DispatchNotSent || got.Reason != contracts.ReasonProviderError {
		t.Fatalf("missing binary: %+v", got)
	}
}

func TestObserveWithoutOrWithAnotherEffectsRecord(t *testing.T) {
	r := newRig(t, false)
	r.project("demo")
	e, digest := effectOf(t, acton.ActionBuild, "demo", map[string]any{})
	if obs := r.a.Observe(context.Background(), nil, e); obs.Outcome != adapters.OutcomeFailed || !obs.Absent || obs.Observation == nil {
		t.Fatalf("no record is FAILED by absence: %+v", obs)
	}
	r.a.Dispatch(context.Background(), nil, e, digest)
	other, _ := effectOf(t, acton.ActionBuild, "demo", map[string]any{"tolk_compiler_version": "1.4.0"})
	if obs := r.a.Observe(context.Background(), nil, other); obs.Outcome != adapters.OutcomeFailed || obs.Absent || obs.Reason != contracts.ReasonReadbackMismatch {
		t.Fatalf("another effect's record must not confirm this one: %+v", obs)
	}
	path := recordPath(filepath.Join(r.workspace, "t1"), "att-1")
	if err := os.WriteFile(path, []byte(`{"version":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if obs := r.a.Observe(context.Background(), nil, e); obs.Outcome != adapters.OutcomeUnknown {
		t.Fatalf("a record of the wrong shape is UNKNOWN: %+v", obs)
	}
}

func TestProjectNewAndInit(t *testing.T) {
	r := newRig(t, false)
	e, d := effectOf(t, acton.ActionProjectNew, "fresh", map[string]any{"project_name": "other"})
	if got := r.a.Dispatch(context.Background(), nil, e, d); got.Reason != contracts.ReasonSchemaViolation {
		t.Fatalf("project_name must equal the target: %+v", got)
	}
	e, d = effectOf(t, acton.ActionProjectNew, "fresh", map[string]any{"project_name": "fresh"})
	if got := r.a.Dispatch(context.Background(), nil, e, d); got.Status != adapters.DispatchSent {
		t.Fatalf("new: %+v", got)
	}
	if run := r.fake.runs(t)[0]; !strings.HasSuffix(run, "/t1 new fresh") {
		t.Fatalf("new runs in the tenant root: %q", run)
	}
	i, id := effectOf(t, acton.ActionProjectInit, "inited", map[string]any{})
	i.Invocation.AttemptID = "att-2"
	if got := r.a.Dispatch(context.Background(), nil, i, id); got.Status != adapters.DispatchSent {
		t.Fatalf("init: %+v", got)
	}
	if _, err := os.Stat(filepath.Join(r.workspace, "t1", "inited")); err != nil {
		t.Fatal(err)
	}
}

func TestToncenterReadsATransaction(t *testing.T) {
	b64 := "ASNFZ4mrze8BI0VniavN7wEjRWeJq83vASNFZ4mrze8="
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/getTransactions" || req.URL.Query().Get("address") != address {
			http.Error(w, "no", http.StatusNotFound)
			return
		}
		fmt.Fprintf(w, `{"ok":true,"result":[{"transaction_id":{"hash":%q}}]}`, b64)
	}))
	defer srv.Close()
	c, err := NewToncenter(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if tx, err := c.FindTransaction(context.Background(), address, txHash); err != nil || !tx.Found {
		t.Fatalf("found: %+v %v", tx, err)
	}
	if tx, err := c.FindTransaction(context.Background(), address, strings.Repeat("0", 64)); err != nil || tx.Found {
		t.Fatalf("not found: %+v %v", tx, err)
	}
	if _, err := c.FindTransaction(context.Background(), "other", txHash); err == nil {
		t.Fatal("an HTTP error must be an error")
	}
	if _, err := NewToncenter("http://example.com"); err == nil {
		t.Fatal("plain http to a remote host must be refused")
	}
}

func TestNewRefusesRelativePaths(t *testing.T) {
	if _, err := New(Config{Binary: "acton", WorkspaceRoot: "/x"}); err == nil {
		t.Fatal("relative binary")
	}
	if _, err := New(Config{Binary: "/x/acton", WorkspaceRoot: "x"}); err == nil {
		t.Fatal("relative workspace")
	}
}

func TestAdapterRevalidatesArgumentsWithoutTheSchema(t *testing.T) {
	r := newRig(t, true)
	r.project("demo")
	ctx := context.Background()
	for name, c := range map[string]struct {
		action acton.ActionURN
		args   map[string]any
	}{
		"mainnet network":    {acton.ActionLibraryInfo, map[string]any{"library_ref": "lib1", "network": "mainnet"}},
		"no network":         {acton.ActionLibraryInfo, map[string]any{"library_ref": "lib1"}},
		"dash path":          {acton.ActionCompile, map[string]any{"source_path": "-rf"}},
		"dash nested path":   {acton.ActionCompile, map[string]any{"source_path": "src/--out"}},
		"traversal":          {acton.ActionCompile, map[string]any{"source_path": "../x"}},
		"dash library ref":   {acton.ActionLibraryInfo, map[string]any{"library_ref": "--net", "network": "testnet"}},
		"dash doc query":     {acton.ActionDoc, map[string]any{"query": "--help"}},
		"mainnet effect net": {acton.ActionLibraryPublishTN, withEffectNet(scriptArgs(), "mainnet")},
	} {
		e, d := effectOf(t, c.action, "demo", c.args)
		got := r.a.Dispatch(ctx, creds{secret: testSecret}, e, d)
		if got.Status != adapters.DispatchNotSent || got.Reason != contracts.ReasonSchemaViolation {
			t.Errorf("%s: %+v", name, got)
		}
	}
	if _, err := os.Stat(r.fake.log); err == nil {
		t.Fatal("acton ran for an invalid argument")
	}
}

func withEffectNet(a map[string]any, net string) map[string]any {
	a["expected_effects"].([]any)[0].(map[string]any)["network"] = net
	return a
}

func TestWorkspaceConfigActonLoadsIsRefused(t *testing.T) {
	r := newRig(t, true)
	r.project("demo")
	for _, name := range []string{".env", ".env.local", "wallets.toml"} {
		path := filepath.Join(r.workspace, "t1", "demo", name)
		if err := os.WriteFile(path, []byte("X=1"), 0o600); err != nil {
			t.Fatal(err)
		}
		e, d := effectOf(t, acton.ActionBuild, "demo", map[string]any{})
		if got := r.a.Dispatch(context.Background(), nil, e, d); got.Status != adapters.DispatchNotSent || got.Reason != contracts.ReasonPreconditionFailed {
			t.Errorf("%s: %+v", name, got)
		}
		_ = os.Remove(path)
	}
	// One level up, in the tenant root, applies to every project below it.
	if err := os.WriteFile(filepath.Join(r.workspace, "t1", ".env"), []byte("X=1"), 0o600); err != nil {
		t.Fatal(err)
	}
	e, d := effectOf(t, acton.ActionBuild, "demo", map[string]any{})
	if got := r.a.Dispatch(context.Background(), nil, e, d); got.Status != adapters.DispatchNotSent {
		t.Fatalf("tenant root .env: %+v", got)
	}
	if _, err := os.Stat(r.fake.log); err == nil {
		t.Fatal("acton ran in a workspace with an auto-loaded file")
	}
}

func TestVersionPinsAreMeasuredAgainstTheBinary(t *testing.T) {
	r := newRig(t, true)
	r.project("demo")
	ctx := context.Background()
	ok, d := effectOf(t, acton.ActionBuild, "demo", map[string]any{"acton_version": "1.0.0", "tolk_compiler_version": "1.4.0"})
	if got := r.a.Dispatch(ctx, nil, ok, d); got.Status != adapters.DispatchSent {
		t.Fatalf("matching pins: %+v", got)
	}
	r2 := newRig(t, true)
	r2.project("demo")
	bad, bd := effectOf(t, acton.ActionBuild, "demo", map[string]any{"acton_version": "0.5.0"})
	if got := r2.a.Dispatch(ctx, nil, bad, bd); got.Status != adapters.DispatchNotSent || got.Reason != contracts.ReasonTONActonUnsupportedVersion {
		t.Fatalf("acton pin: %+v", got)
	}
	tolk, td := effectOf(t, acton.ActionBuild, "demo", map[string]any{"tolk_compiler_version": "0.13.0"})
	if got := r2.a.Dispatch(ctx, nil, tolk, td); got.Status != adapters.DispatchNotSent || got.Reason != contracts.ReasonTONTolkCompilerMismatch {
		t.Fatalf("tolk pin: %+v", got)
	}
	for _, line := range r2.fake.runs(t) {
		if strings.Contains(line, " build") {
			t.Fatalf("a build ran despite a pin mismatch: %s", line)
		}
	}
}

func TestPlaintextWalletMaterialIsRefusedByPolicy(t *testing.T) {
	r := newRig(t, true)
	r.project("demo")
	a := scriptArgs()
	a["wallet_ref"] = "wallet:mnemonic"
	e, d := effectOf(t, acton.ActionLibraryPublishTN, "demo", a)
	if got := r.a.Dispatch(context.Background(), creds{secret: testSecret}, e, d); got.Reason != contracts.ReasonTONPlaintextMnemonicForbidden || got.Status != adapters.DispatchNotSent {
		t.Fatalf("%+v", got)
	}
}

// A run that started must always be accounted for: with no record, Observe is
// UNKNOWN and never FAILED by absence, which would release the reservation.
func TestAttemptMarkerKeepsAnUnrecordedBroadcastUnknown(t *testing.T) {
	r := newRig(t, true)
	r.project("demo")
	runs := filepath.Join(r.workspace, "t1", ".runs")
	if err := os.MkdirAll(runs, 0o700); err != nil {
		t.Fatal(err)
	}
	e, d := effectOf(t, acton.ActionLibraryPublishTN, "demo", scriptArgs())

	// The marker cannot be written: nothing is launched.
	if err := os.Chmod(runs, 0o500); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 {
		if got := r.a.Dispatch(context.Background(), creds{secret: testSecret}, e, d); got.Status != adapters.DispatchNotSent {
			t.Fatalf("unwritable marker: %+v", got)
		}
		if _, err := os.Stat(r.fake.log); err == nil {
			t.Fatal("acton launched without a marker")
		}
	}
	if err := os.Chmod(runs, 0o700); err != nil {
		t.Fatal(err)
	}

	// Acton ran but its record is lost.
	if got := r.a.Dispatch(context.Background(), creds{secret: testSecret}, e, d); got.Status != adapters.DispatchSent {
		t.Fatalf("dispatch: %+v", got)
	}
	if err := os.Remove(recordPath(filepath.Join(r.workspace, "t1"), "att-1")); err != nil {
		t.Fatal(err)
	}
	if obs := r.a.Observe(context.Background(), nil, e); obs.Outcome != adapters.OutcomeUnknown {
		t.Fatalf("a marker without a record must be UNKNOWN: %+v", obs)
	}
	// The same attempt is never launched twice.
	before := len(r.fake.runs(t))
	if got := r.a.Dispatch(context.Background(), creds{secret: testSecret}, e, d); got.Status != adapters.DispatchIndefinite {
		t.Fatalf("second dispatch: %+v", got)
	}
	if len(r.fake.runs(t)) != before {
		t.Fatal("the attempt was launched again")
	}
}

func TestRecordWriteFailureAfterABroadcastIsIndefiniteAndStaysUnknown(t *testing.T) {
	r := newRig(t, true)
	r.project("demo")
	e, d := effectOf(t, acton.ActionLibraryPublishTN, "demo", scriptArgs())
	// A directory where the record goes makes the atomic rename fail after Acton ran.
	if err := os.MkdirAll(recordPath(filepath.Join(r.workspace, "t1"), "att-1"), 0o700); err != nil {
		t.Fatal(err)
	}
	got := r.a.Dispatch(context.Background(), creds{secret: testSecret}, e, d)
	if got.Status != adapters.DispatchIndefinite {
		t.Fatalf("dispatch: %+v", got)
	}
	if obs := r.a.Observe(context.Background(), nil, e); obs.Outcome == adapters.OutcomeFailed {
		t.Fatalf("an unaccounted broadcast must not read FAILED: %+v", obs)
	}
}

func TestOperationsOverTenantFilesNeedIsolation(t *testing.T) {
	r := newRig(t, false)
	r.project("demo")
	bare, _ := New(Config{Binary: r.fake.bin, WorkspaceRoot: r.workspace})
	e, d := effectOf(t, acton.ActionTest, "demo", map[string]any{})
	if got := bare.Dispatch(context.Background(), nil, e, d); got.Status != adapters.DispatchNotSent || got.Reason != contracts.ReasonSchemaViolation {
		t.Fatalf("test without isolation: %+v", got)
	}
	if _, err := New(Config{Binary: r.fake.bin, WorkspaceRoot: r.workspace, Isolation: []string{"env"}}); err == nil {
		t.Fatal("a relative isolation program must be refused")
	}
}
