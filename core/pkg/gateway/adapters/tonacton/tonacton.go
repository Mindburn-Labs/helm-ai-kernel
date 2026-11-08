// Package tonacton is the gateway effect adapter of the TON Acton connector
// (helm-tracker#266). It performs a closed set of Acton operations: local
// project work, forks, and testnet broadcasts. Every mainnet operation is
// refused at admission (effectargs.IsTONActonMainnet) and has no adapter.
//
// Dispatch runs the operator-configured Acton binary with typed argv built by
// the connector (core/pkg/connectors/ton/acton), inside the tenant's workspace
// directory, with an environment built from nothing. The testnet wallet secret
// comes from the gateway's connection custody and is put into that
// environment for a testnet operation only (R8); it is never in the arguments,
// the argv, the run record or the result.
//
// Observe reads back the run record Dispatch wrote for the attempt and checks it
// against the arguments. A testnet broadcast is SUCCEEDED only when the
// configured testnet RPC also shows the transaction.
package tonacton

// quantum_posture: SHA-256 binds arguments, run records and results; nothing
// here signs or verifies, and no post-quantum claim is made.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/connectors/ton/acton"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/effects"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/interfaces"
)

const (
	// ResultSchemaID is the typed result of every Acton effect.
	ResultSchemaID = "ton.acton.result.v1"
	// WalletSecretEnv is the one environment variable that carries the testnet
	// wallet secret to the Acton process, for a testnet operation only.
	WalletSecretEnv = "ACTON_WALLET_SECRET" // #nosec G101 -- a variable name, not a credential

	observationSource = "gateway.ton-acton.readback"
	trustClass        = "gateway_workspace"
	maxStdoutText     = 32 * 1024
	recordVersion     = "helm.gateway.ton-acton-run.v1"
)

// Config configures the adapter.
type Config struct {
	// Binary is the absolute path of the Acton executable.
	Binary string
	// WorkspaceRoot is the absolute directory that holds one directory per tenant.
	WorkspaceRoot string
	// Chain reads TON testnet. Without it the testnet operations are not
	// declared: the gateway will not broadcast what it cannot read back.
	Chain ChainReader
	// Timeout bounds one run; default two minutes.
	Timeout time.Duration
	// MaxTestnetSpend is the per-action TON ceiling for a testnet operation;
	// default "1".
	MaxTestnetSpend string
	// NetworkDestinations are the hosts the sandbox grant records for network
	// operations; default testnet.toncenter.com.
	NetworkDestinations []string
	Now                 func() time.Time
}

// Result is the typed result of an Acton effect (ResultSchemaID).
type Result struct {
	Action          string `json:"action"`
	Network         string `json:"network"`
	Status          string `json:"status"`
	ExitCode        int    `json:"exit_code"`
	RequestHash     string `json:"request_hash"`
	StdoutHash      string `json:"stdout_hash"`
	StderrHash      string `json:"stderr_hash"`
	Stdout          string `json:"stdout"`
	StdoutTruncated bool   `json:"stdout_truncated"`
	Address         string `json:"address,omitempty"`
	TxHash          string `json:"tx_hash,omitempty"`
	AmountTON       string `json:"amount_ton,omitempty"`
	ChainConfirmed  *bool  `json:"chain_confirmed,omitempty"`
}

// runRecord is what Dispatch leaves in the tenant's workspace for Observe.
type runRecord struct {
	Version        string `json:"version"`
	EffectType     string `json:"effect_type"`
	Target         string `json:"target"`
	ArgumentDigest string `json:"argument_digest"`
	Result         Result `json:"result"`
}

// Adapter performs the Acton effect types.
type Adapter struct {
	cfg Config
}

var _ adapters.Adapter = (*Adapter)(nil)

// New returns the adapter.
func New(cfg Config) (*Adapter, error) {
	if !filepath.IsAbs(cfg.Binary) {
		return nil, errors.New("the Acton binary path must be absolute")
	}
	if !filepath.IsAbs(cfg.WorkspaceRoot) {
		return nil, errors.New("the Acton workspace root must be absolute")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 2 * time.Minute
	}
	if cfg.MaxTestnetSpend == "" {
		cfg.MaxTestnetSpend = "1"
	}
	if len(cfg.NetworkDestinations) == 0 {
		cfg.NetworkDestinations = []string{"testnet.toncenter.com"}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Adapter{cfg: cfg}, nil
}

func (a *Adapter) enabled(o op) bool { return o.group != groupTestnet || a.cfg.Chain != nil }

// Declarations implements adapters.Adapter.
func (a *Adapter) Declarations() []adapters.Declaration {
	var out []adapters.Declaration
	for _, o := range ops {
		if a.enabled(o) {
			out = append(out, o.declaration())
		}
	}
	return out
}

func (a *Adapter) resolveOp(effectType string) (op, *adapters.Refusal) {
	if effectargsMainnet(effectType) {
		return op{}, adapters.Refuse(contracts.ReasonTONMainnetRefused, "%s operates on TON mainnet", effectType)
	}
	o, ok := lookup(effectType)
	if !ok || !a.enabled(o) {
		return op{}, schemaViolation("effect type %q is not an Acton effect this gateway performs", effectType)
	}
	return o, nil
}

// Prepare implements adapters.Adapter. It checks the target and arguments and
// reads nothing else.
func (a *Adapter) Prepare(_ context.Context, _ adapters.TokenSource, effect adapters.Effect) (*adapters.Preparation, error) {
	o, r := a.resolveOp(effect.EffectType)
	if r != nil {
		return nil, r
	}
	if _, r := parseTarget(effect.Target); r != nil {
		return nil, r
	}
	if _, r := parseArgs(o, effect.Arguments); r != nil {
		return nil, r
	}
	return &adapters.Preparation{Declaration: o.declaration(), Target: effect.Target}, nil
}

func notSent(r *adapters.Refusal) adapters.DispatchResult {
	return adapters.DispatchResult{Status: adapters.DispatchNotSent, Reason: r.Reason, Detail: r.Detail}
}

func indefinite(reason contracts.ReasonCode, format string, args ...any) adapters.DispatchResult {
	return adapters.DispatchResult{Status: adapters.DispatchIndefinite, Reason: reason, Detail: fmt.Sprintf(format, args...)}
}

// tenantRoot is the tenant's workspace directory, created if absent.
func (a *Adapter) tenantRoot(tenantID string) (string, *adapters.Refusal) {
	if !tenantPattern.MatchString(tenantID) {
		return "", adapters.Refuse(contracts.ReasonPreconditionFailed, "the tenant id is not usable as a workspace name")
	}
	root := filepath.Join(a.cfg.WorkspaceRoot, tenantID)
	if err := os.MkdirAll(filepath.Join(root, ".home"), 0o750); err != nil {
		return "", adapters.Refuse(contracts.ReasonProviderError, "the tenant workspace is not available")
	}
	return root, nil
}

// workDir is the directory the process runs in, inside the tenant root.
func workDir(o op, root, project string, a args) (string, *adapters.Refusal) {
	switch o.action {
	case acton.ActionProjectNew:
		if a.ProjectName != project {
			return "", schemaViolation("project_name must equal the target's project")
		}
		return root, nil
	case acton.ActionDoctor, acton.ActionEnv, acton.ActionVersion:
		return root, nil
	case acton.ActionProjectInit:
		if err := os.MkdirAll(filepath.Join(root, project), 0o750); err != nil {
			return "", adapters.Refuse(contracts.ReasonProviderError, "the project directory cannot be created")
		}
	}
	dir := filepath.Join(root, project)
	realRoot, err1 := filepath.EvalSymlinks(root)
	realDir, err2 := filepath.EvalSymlinks(dir)
	if err2 != nil {
		return "", adapters.Refuse(contracts.ReasonPreconditionFailed, "the project does not exist in the tenant's workspace")
	}
	if err1 != nil || !strings.HasPrefix(realDir, realRoot+string(filepath.Separator)) {
		return "", adapters.Refuse(contracts.ReasonPreconditionFailed, "the project resolves outside the tenant's workspace")
	}
	return realDir, nil
}

func (a *Adapter) ceilings(o op) acton.P0Ceilings {
	p := acton.DefaultP0Ceilings()
	p.AllowTestnetDeploy = true
	// The compiler pin is demanded by the commands that need it (the
	// connector's own classification), not by default.
	p.RequireCompilerPin = false
	p.MaxTONSpendPerAction = a.cfg.MaxTestnetSpend
	p.MaxTONSpendPerDay = a.cfg.MaxTestnetSpend
	return p
}

// grant is the sandbox grant the connector's policy checks; the gateway
// composes it from the operation, never from the request.
func (a *Adapter) grant(o op) (contracts.SandboxGrant, error) {
	req := acton.RequirementsForAction(&acton.ActonCommandEnvelope{ActionURN: o.action, ProjectRoot: "."})
	mode := "ro"
	if req.Writable {
		mode = "rw"
	}
	g := contracts.SandboxGrant{
		GrantID:            "helm-gateway-" + o.effectType(),
		Runtime:            "process",
		Profile:            "ton-acton",
		FilesystemPreopens: []contracts.FilesystemPreopen{{Path: ".", Mode: mode}},
		Env:                contracts.EnvExposurePolicy{Mode: "deny-all"},
		Network:            contracts.NetworkGrant{Mode: "deny-all"},
		DeclaredAt:         a.cfg.Now().UTC(),
	}
	if req.RequireNetwork {
		g.Network = contracts.NetworkGrant{Mode: "allowlist", Destinations: a.cfg.NetworkDestinations}
	}
	if o.usesWallet() {
		g.Env = contracts.EnvExposurePolicy{Mode: "allowlist", Names: []string{WalletSecretEnv}}
	}
	return g.Seal()
}

// Dispatch implements adapters.Adapter.
func (a *Adapter) Dispatch(ctx context.Context, creds adapters.TokenSource, effect adapters.Effect, permitArgumentDigest []byte) adapters.DispatchResult {
	if r := adapters.CheckPermitDigest(effect.Arguments, permitArgumentDigest); r != nil {
		return notSent(r)
	}
	o, r := a.resolveOp(effect.EffectType)
	if r != nil {
		return notSent(r)
	}
	inv := effect.Invocation
	if inv == nil || inv.TenantID == "" || !attemptRe.MatchString(inv.AttemptID) {
		return notSent(adapters.Refuse(contracts.ReasonPreconditionFailed, "the dispatch carries no invocation"))
	}
	project, r := parseTarget(effect.Target)
	if r != nil {
		return notSent(r)
	}
	ar, r := parseArgs(o, effect.Arguments)
	if r != nil {
		return notSent(r)
	}
	root, r := a.tenantRoot(inv.TenantID)
	if r != nil {
		return notSent(r)
	}
	dir, r := workDir(o, root, project, ar)
	if r != nil {
		return notSent(r)
	}
	env := []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + filepath.Join(root, ".home"), "LANG=C"}
	secret := ""
	if o.usesWallet() {
		if creds == nil {
			return notSent(adapters.Refuse(contracts.ReasonProviderCredentialRejected, "the gateway holds no testnet wallet"))
		}
		var err error
		if secret, err = creds.Token(ctx); err != nil || secret == "" || strings.ContainsAny(secret, "\x00\r\n") {
			return notSent(adapters.Refuse(contracts.ReasonProviderCredentialRejected, "the gateway holds no testnet wallet for this tenant and wallet_ref"))
		}
		env = append(env, WalletSecretEnv+"="+secret)
	}
	grant, err := a.grant(o)
	if err != nil {
		return notSent(adapters.Refuse(contracts.ReasonPreconditionFailed, "the sandbox grant is invalid"))
	}
	ceilings := a.ceilings(o)
	exec := &processExecutor{binary: a.cfg.Binary, dir: dir, env: env, secret: secret}
	conn := acton.NewConnector(acton.Config{
		Runner:       acton.Runner{Executor: exec, SandboxID: "helm-gateway", Timeout: a.cfg.Timeout},
		DefaultP0:    ceilings,
		SandboxGrant: &grant,
	})
	digest := hex.EncodeToString(permitArgumentDigest)
	permit := &effects.EffectPermit{
		PermitID: inv.PermitID, IntentHash: "sha256:" + digest, ConnectorID: acton.ConnectorID,
		IssuerID:         "helm-gateway",
		EvidenceBindings: map[string]string{"sandbox_grant_hash": grant.GrantHash},
	}
	out, err := conn.Execute(ctx, permit, string(o.action), ar.params(o, inv, ceilings.Hash()))
	receipt, _ := out.(*acton.ActonReceipt)
	side := o.spec().SideEffect
	switch {
	case exec.startErr != nil:
		return notSent(adapters.Refuse(contracts.ReasonProviderError, "the Acton binary could not be started"))
	case err != nil || receipt == nil:
		if exec.started && side {
			return indefinite(contracts.ReasonProviderError, "the connector failed after Acton started")
		}
		return notSent(adapters.Refuse(contracts.ReasonProviderError, "the connector refused the call: %v", err))
	case !exec.started:
		// Policy refused before any process ran.
		detail, _ := receipt.Metadata["policy_reason"].(string)
		return notSent(adapters.Refuse(contracts.ReasonCode(receipt.ReasonCode), "%s", detail))
	}

	text, truncated := textOf(exec.stdout)
	result := Result{
		Action: string(o.action), Network: string(o.spec().Network), Status: receipt.Status, ExitCode: receipt.ExitCode,
		RequestHash: receipt.RequestHash, StdoutHash: receipt.StdoutHash, StderrHash: receipt.StderrHash,
		Stdout: text, StdoutTruncated: truncated,
	}
	shapeOK := true
	if o.broadcast() {
		if out, perr := parseOutput(exec.stdout); perr == nil {
			result.Address, result.TxHash = out.Address, out.TxHash
			if spendRe.MatchString(out.AmountTON) {
				result.AmountTON = out.AmountTON
			}
		} else {
			shapeOK = false
		}
	}
	if werr := a.writeRecord(root, inv.AttemptID, runRecord{Version: recordVersion, EffectType: effect.EffectType,
		Target: effect.Target, ArgumentDigest: digest, Result: result}); werr != nil {
		if side {
			return indefinite(contracts.ReasonProviderError, "Acton ran but its run record could not be written")
		}
		return notSent(adapters.Refuse(contracts.ReasonProviderError, "the run record could not be written"))
	}
	switch {
	case receipt.Status == "timeout" || receipt.Status == "resource_exhausted":
		if side {
			return indefinite(contracts.ReasonCode(receipt.ReasonCode), "Acton was cut short")
		}
		return notSent(adapters.Refuse(contracts.ReasonCode(receipt.ReasonCode), "Acton was cut short"))
	case receipt.ExitCode != 0 && o.broadcast():
		return indefinite(contracts.ReasonProviderError, "Acton exited %d after a broadcast operation", receipt.ExitCode)
	case o.broadcast() && !shapeOK:
		return indefinite(contracts.ReasonConnectorContractDrift, "Acton's answer is not the output contract of %s", effect.EffectType)
	case receipt.ExitCode != 0 && !side:
		return notSent(adapters.Refuse(contracts.ReasonProviderError, "Acton exited %d", receipt.ExitCode))
	}
	return adapters.DispatchResult{Status: adapters.DispatchSent}
}

// Observe implements adapters.Adapter.
func (a *Adapter) Observe(ctx context.Context, _ adapters.TokenSource, effect adapters.Effect) adapters.ObserveResult {
	unknown := func(reason contracts.ReasonCode, format string, args ...any) adapters.ObserveResult {
		return adapters.ObserveResult{Outcome: adapters.OutcomeUnknown, Reason: reason, Detail: fmt.Sprintf(format, args...)}
	}
	o, r := a.resolveOp(effect.EffectType)
	if r != nil {
		return unknown(r.Reason, "%s", r.Detail)
	}
	inv := effect.Invocation
	if inv == nil || inv.TenantID == "" || !attemptRe.MatchString(inv.AttemptID) || !tenantPattern.MatchString(inv.TenantID) {
		return unknown(contracts.ReasonPreconditionFailed, "the read-back carries no invocation")
	}
	sum := sha256.Sum256(effect.Arguments)
	digest := hex.EncodeToString(sum[:])
	path := recordPath(filepath.Join(a.cfg.WorkspaceRoot, inv.TenantID), inv.AttemptID)
	raw, err := os.ReadFile(path) // #nosec G304 -- built from a validated tenant id and attempt id under the operator's workspace root
	base := &adapters.Observation{Source: observationSource, TrustClass: trustClass, ObservedAt: a.cfg.Now().UTC()}
	failed := func(absent bool, reason contracts.ReasonCode, res Result, evidence []byte, format string, args ...any) adapters.ObserveResult {
		art, aerr := resultArtifact(res)
		if aerr != nil {
			return unknown(contracts.ReasonPreconditionFailed, "the result cannot be built")
		}
		obs := *base
		obs.Artifact, obs.EvidenceDigest = art, evidence
		return adapters.ObserveResult{Outcome: adapters.OutcomeFailed, Reason: reason, Detail: fmt.Sprintf(format, args...), Observation: &obs, Absent: absent}
	}
	empty := sha256.Sum256(nil)
	emptyHash := "sha256:" + hex.EncodeToString(empty[:])
	synthetic := Result{Action: string(o.action), Network: string(o.spec().Network), Status: "error", ExitCode: -1,
		RequestHash: "sha256:" + digest, StdoutHash: emptyHash, StderrHash: emptyHash}
	if errors.Is(err, os.ErrNotExist) {
		return failed(true, contracts.ReasonReadbackMismatch, synthetic, sum[:], "no run record exists for this attempt")
	}
	if err != nil {
		return unknown(contracts.ReasonProviderError, "the run record could not be read")
	}
	rec, rerr := decodeRecord(raw)
	evidence := sha256.Sum256(raw)
	if rerr != nil {
		return unknown(contracts.ReasonConnectorContractDrift, "the run record is not the expected document")
	}
	if rec.EffectType != effect.EffectType || rec.Target != effect.Target || rec.ArgumentDigest != digest {
		return failed(false, contracts.ReasonReadbackMismatch, synthetic, evidence[:], "the run record is not this effect's")
	}
	res := rec.Result
	if o.broadcast() {
		if res.TxHash == "" || res.Address == "" {
			return unknown(contracts.ReasonConnectorContractDrift, "the run names no transaction to look for")
		}
		tx, cerr := a.cfg.Chain.FindTransaction(ctx, res.Address, res.TxHash)
		if cerr != nil {
			return unknown(contracts.ReasonProviderError, "the testnet RPC could not be read")
		}
		confirmed := tx.Found
		res.ChainConfirmed = &confirmed
		both := sha256.Sum256(append(append([]byte{}, raw...), tx.Evidence...))
		switch {
		case !tx.Found:
			return failed(true, contracts.ReasonReadbackMismatch, res, both[:], "testnet shows no such transaction")
		case res.ExitCode != 0:
			return failed(false, contracts.ReasonReadbackMismatch, res, both[:], "testnet shows a transaction but Acton reported exit %d", res.ExitCode)
		}
		evidence = both
	} else if res.ExitCode != 0 || res.Status != "ok" {
		return failed(false, contracts.ReasonProviderError, res, evidence[:], "Acton exited %d (%s)", res.ExitCode, res.Status)
	}
	art, aerr := resultArtifact(res)
	if aerr != nil {
		return unknown(contracts.ReasonPreconditionFailed, "the result cannot be built")
	}
	obs := *base
	obs.Artifact, obs.EvidenceDigest = art, evidence[:]
	return adapters.ObserveResult{Outcome: adapters.OutcomeSucceeded, Observation: &obs}
}

func resultArtifact(r Result) (*interfaces.Artifact, error) {
	canonical, err := canonicalize.JCS(r)
	if err != nil {
		return nil, err
	}
	return adapters.NewJSONResult(ResultSchemaID, canonical)
}
