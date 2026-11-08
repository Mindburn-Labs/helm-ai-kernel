package tonacton

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/connectors/ton/acton"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
)

// targetForm is the form of every Acton effect's target: the project directory
// under the tenant's workspace. The target, never an argument, names where the
// process runs (09-02).
const targetForm = "ton-acton:{project}"

var (
	targetPattern = regexp.MustCompile(`^ton-acton:([A-Za-z0-9][A-Za-z0-9._-]{0,63})$`)
	tenantPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	attemptRe     = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
	addressRe     = regexp.MustCompile(addressPattern)
	txHashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// args is the union of every operation's arguments.
type args struct {
	Schema              string                 `json:"schema"`
	ProjectName         string                 `json:"project_name"`
	SourcePath          string                 `json:"source_path"`
	ArtifactPath        string                 `json:"artifact_path"`
	ScriptPath          string                 `json:"script_path"`
	LibraryPath         string                 `json:"library_path"`
	OutputPath          string                 `json:"output_path"`
	Query               string                 `json:"query"`
	LibraryRef          string                 `json:"library_ref"`
	Network             string                 `json:"network"`
	Address             string                 `json:"address"`
	WalletRef           string                 `json:"wallet_ref"`
	MaxTONSpend         string                 `json:"max_ton_spend"`
	ActonVersion        string                 `json:"acton_version"`
	TolkCompilerVersion string                 `json:"tolk_compiler_version"`
	ExpectedEffects     []acton.ExpectedEffect `json:"expected_effects"`
}

func schemaViolation(format string, a ...any) *adapters.Refusal {
	return adapters.Refuse(contracts.ReasonSchemaViolation, format, a...)
}

// parseTarget returns the project name of a target.
func parseTarget(target string) (string, *adapters.Refusal) {
	m := targetPattern.FindStringSubmatch(target)
	if m == nil {
		return "", schemaViolation("the target must be %s", targetForm)
	}
	return m[1], nil
}

// parseArgs decodes the operation's arguments strictly: exactly the properties
// the operation declares, the required ones present.
func parseArgs(o op, raw []byte) (args, *adapters.Refusal) {
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(raw, &keys); err != nil || keys == nil {
		return args{}, schemaViolation("the arguments are not one JSON object")
	}
	allowed := append([]string{"schema"}, o.properties...)
	for k := range keys {
		if !slices.Contains(allowed, k) {
			return args{}, schemaViolation("%q is not an argument of %s", k, o.effectType())
		}
	}
	for _, k := range append([]string{"schema"}, o.required...) {
		if _, ok := keys[k]; !ok {
			return args{}, schemaViolation("%q is required", k)
		}
	}
	var a args
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil {
		return args{}, schemaViolation("the arguments do not decode: %v", err)
	}
	if a.Schema != o.schemaConst() {
		return args{}, schemaViolation("schema must be %q", o.schemaConst())
	}
	if r := a.checkValues(); r != nil {
		return args{}, r
	}
	return a, nil
}

var (
	pathRe       = regexp.MustCompile(pathPattern)
	projectRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	queryRe      = regexp.MustCompile(`^([A-Za-z0-9_][A-Za-z0-9 _.:-]{0,199})?$`)
	libraryRefRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:_.-]{0,127}$`)
	walletRefRe  = regexp.MustCompile(walletRefPattern)
	versionRe    = regexp.MustCompile(versionPattern)
)

// checkValues re-checks every value against the patterns the published schema
// states. The gateway validates the schema at admission, but the adapter does
// not rely on it: nothing that starts with a dash (an Acton flag), reaches
// outside the project, or names mainnet gets as far as argv.
func (a args) checkValues() *adapters.Refusal {
	check := func(name, v string, re *regexp.Regexp) *adapters.Refusal {
		if v != "" && !re.MatchString(v) {
			return schemaViolation("%s is not a valid %s", name, name)
		}
		return nil
	}
	for _, c := range []struct {
		name, v string
		re      *regexp.Regexp
	}{
		{"project_name", a.ProjectName, projectRe}, {"source_path", a.SourcePath, pathRe}, {"artifact_path", a.ArtifactPath, pathRe},
		{"script_path", a.ScriptPath, pathRe}, {"library_path", a.LibraryPath, pathRe}, {"output_path", a.OutputPath, pathRe},
		{"query", a.Query, queryRe}, {"library_ref", a.LibraryRef, libraryRefRe}, {"address", a.Address, addressRe},
		{"wallet_ref", a.WalletRef, walletRefRe}, {"max_ton_spend", a.MaxTONSpend, spendRe},
		{"acton_version", a.ActonVersion, versionRe}, {"tolk_compiler_version", a.TolkCompilerVersion, versionRe},
	} {
		if r := check(c.name, c.v, c.re); r != nil {
			return r
		}
	}
	// The only network an Acton operation here may name is testnet; an
	// operation that takes no network has none.
	if a.Network != "" && a.Network != "testnet" {
		return schemaViolation("network must be testnet")
	}
	for _, e := range a.ExpectedEffects {
		if e.Network != "" && e.Network != "testnet" {
			return schemaViolation("expected_effects network must be testnet")
		}
	}
	return nil
}

// params turns checked arguments into the connector's parameter map. Only
// fields the schema admitted are copied; the gateway supplies the rest, and the
// connector's trust-bearing parameters (sandbox_grant, p0_ceilings and raw
// command fields) are never set from a request.
func (a args) params(o op, inv *adapters.Invocation, ceilingsHash string) map[string]any {
	p := map[string]any{
		"tenant_id":        inv.TenantID,
		"workspace_id":     inv.WorkspaceID,
		"principal":        inv.RequesterPrincipalID,
		"p0_ceilings_hash": ceilingsHash,
		// The wallet reaches Acton through the environment, never --tonconnect.
		"wallet_mode": "secret_manager",
	}
	set := func(k, v string) {
		if v != "" {
			p[k] = v
		}
	}
	set("project_name", a.ProjectName)
	set("source_path", a.SourcePath)
	set("artifact_path", a.ArtifactPath)
	set("script_path", a.ScriptPath)
	set("library_path", a.LibraryPath)
	set("output_path", a.OutputPath)
	set("query", a.Query)
	set("library_ref", a.LibraryRef)
	set("network", a.Network)
	set("address", a.Address)
	set("wallet_ref", a.WalletRef)
	set("max_ton_spend", a.MaxTONSpend)
	set("acton_version", a.ActonVersion)
	set("tolk_compiler_version", a.TolkCompilerVersion)
	if len(a.ExpectedEffects) > 0 {
		p["expected_effects"] = a.ExpectedEffects
	}
	return p
}

// output is the answer a broadcast operation must print: one JSON object naming
// the account and the transaction. Anything else is drift from the contract.
type output struct {
	Address   string `json:"address"`
	TxHash    string `json:"tx_hash"`
	AmountTON string `json:"amount_ton"`
}

func parseOutput(stdout []byte) (output, error) {
	var out output
	if err := json.Unmarshal(bytes.TrimSpace(stdout), &out); err != nil {
		return out, fmt.Errorf("the answer is not one JSON object")
	}
	if !addressRe.MatchString(out.Address) || !txHashPattern.MatchString(out.TxHash) {
		return out, fmt.Errorf("the answer names no valid address and transaction hash")
	}
	return out, nil
}
