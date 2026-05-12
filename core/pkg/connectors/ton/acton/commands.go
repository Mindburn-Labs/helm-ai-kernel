package acton

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

const ConnectorID = "ton.acton"

type ActionURN string

const (
	ActionProjectNew        ActionURN = "connector.ton.acton.project.new"
	ActionProjectInit       ActionURN = "connector.ton.acton.project.init"
	ActionDoctor            ActionURN = "connector.ton.acton.doctor"
	ActionEnv               ActionURN = "connector.ton.acton.env"
	ActionVersion           ActionURN = "connector.ton.acton.version"
	ActionBuild             ActionURN = "connector.ton.acton.contract.build"
	ActionCheck             ActionURN = "connector.ton.acton.contract.check"
	ActionFormat            ActionURN = "connector.ton.acton.contract.format"
	ActionFormatCheck       ActionURN = "connector.ton.acton.contract.format_check"
	ActionTest              ActionURN = "connector.ton.acton.contract.test"
	ActionCoverage          ActionURN = "connector.ton.acton.contract.test_coverage"
	ActionMutation          ActionURN = "connector.ton.acton.contract.test_mutation"
	ActionWrapperGenerate   ActionURN = "connector.ton.acton.contract.wrapper_generate"
	ActionWrapperGenerateTS ActionURN = "connector.ton.acton.contract.wrapper_generate_ts"
	ActionCompile           ActionURN = "connector.ton.acton.contract.compile"
	ActionDisasm            ActionURN = "connector.ton.acton.contract.disasm"
	ActionDoc               ActionURN = "connector.ton.acton.contract.doc"
	ActionRetrace           ActionURN = "connector.ton.acton.contract.retrace"
	ActionFunc2Tolk         ActionURN = "connector.ton.acton.contract.func2tolk"
	ActionScriptLocal       ActionURN = "connector.ton.acton.script.local"
	ActionScriptForkTestnet ActionURN = "connector.ton.acton.script.fork_testnet"
	ActionScriptForkMainnet ActionURN = "connector.ton.acton.script.fork_mainnet"
	ActionScriptTestnet     ActionURN = "connector.ton.acton.script.testnet"
	ActionScriptMainnet     ActionURN = "connector.ton.acton.script.mainnet"
	ActionVerifyDryRun      ActionURN = "connector.ton.acton.source.verify_dry_run"
	ActionVerifyTestnet     ActionURN = "connector.ton.acton.source.verify_testnet"
	ActionVerifyMainnet     ActionURN = "connector.ton.acton.source.verify_mainnet"
	ActionLibraryInfo       ActionURN = "connector.ton.acton.library.info"
	ActionLibraryFetch      ActionURN = "connector.ton.acton.library.fetch"
	ActionLibraryPublishTN  ActionURN = "connector.ton.acton.library.publish_testnet"
	ActionLibraryPublishMN  ActionURN = "connector.ton.acton.library.publish_mainnet"
	ActionLibraryTopupTN    ActionURN = "connector.ton.acton.library.topup_testnet"
	ActionLibraryTopupMN    ActionURN = "connector.ton.acton.library.topup_mainnet"
	ActionWalletList        ActionURN = "connector.ton.acton.wallet.list"
	ActionRPCQuery          ActionURN = "connector.ton.acton.rpc.query"
)

type CommandSpec struct {
	URN                     ActionURN      `json:"urn"`
	ActonSubcommand         string         `json:"acton_subcommand"`
	RiskClass               RiskClass      `json:"risk_class"`
	EffectClass             EffectClass    `json:"effect_class,omitempty"`
	ExecutorKind            ExecutorKind   `json:"executor_kind"`
	Network                 NetworkProfile `json:"network,omitempty"`
	SideEffect              bool           `json:"side_effect"`
	Broadcast               bool           `json:"broadcast"`
	RequiresManifest        bool           `json:"requires_manifest,omitempty"`
	RequiresWallet          bool           `json:"requires_wallet,omitempty"`
	RequiresSpendCap        bool           `json:"requires_spend_cap,omitempty"`
	RequiresApproval        bool           `json:"requires_approval,omitempty"`
	RequiresFullEvidence    bool           `json:"requires_full_evidence,omitempty"`
	RequiresNetworkGrant    bool           `json:"requires_network_grant,omitempty"`
	RequiresCompilerPin     bool           `json:"requires_compiler_pin,omitempty"`
	RequiresWritablePreopen bool           `json:"requires_writable_preopen,omitempty"`
	RequiresComputeBudget   bool           `json:"requires_compute_budget,omitempty"`
	RequiresExpectedEffects bool           `json:"requires_expected_effects,omitempty"`
	GenericDenied           bool           `json:"generic_denied,omitempty"`
}

var commandSpecs = map[ActionURN]CommandSpec{
	ActionProjectNew:        spec(ActionProjectNew, "new", RiskT1, EffectReversible, NetworkLocal, true),
	ActionProjectInit:       spec(ActionProjectInit, "init", RiskT1, EffectReversible, NetworkLocal, true),
	ActionDoctor:            spec(ActionDoctor, "doctor", RiskT0, EffectNone, NetworkLocal, false),
	ActionEnv:               spec(ActionEnv, "doctor", RiskT0, EffectNone, NetworkLocal, false),
	ActionVersion:           spec(ActionVersion, "--version", RiskT0, EffectNone, NetworkLocal, false),
	ActionBuild:             spec(ActionBuild, "build", RiskT1, EffectReversible, NetworkLocal, true),
	ActionCheck:             spec(ActionCheck, "check", RiskT1, EffectNone, NetworkLocal, false),
	ActionFormat:            spec(ActionFormat, "fmt", RiskT1, EffectReversible, NetworkLocal, true).withWritable(),
	ActionFormatCheck:       spec(ActionFormatCheck, "fmt", RiskT1, EffectNone, NetworkLocal, false),
	ActionTest:              spec(ActionTest, "test", RiskT1, EffectNone, NetworkLocal, false).withCompute(),
	ActionCoverage:          spec(ActionCoverage, "test", RiskT2, EffectNone, NetworkLocal, false).withCompute(),
	ActionMutation:          spec(ActionMutation, "test", RiskT2, EffectNone, NetworkLocal, false).withCompute(),
	ActionWrapperGenerate:   spec(ActionWrapperGenerate, "wrapper", RiskT1, EffectReversible, NetworkLocal, true).withWritable(),
	ActionWrapperGenerateTS: spec(ActionWrapperGenerateTS, "wrapper", RiskT1, EffectReversible, NetworkLocal, true).withWritable(),
	ActionCompile:           spec(ActionCompile, "compile", RiskT1, EffectReversible, NetworkLocal, true),
	ActionDisasm:            spec(ActionDisasm, "disasm", RiskT1, EffectNone, NetworkLocal, false),
	ActionDoc:               spec(ActionDoc, "doc", RiskT1, EffectNone, NetworkLocal, false),
	ActionRetrace:           spec(ActionRetrace, "retrace", RiskT2, EffectNone, NetworkLocal, false).withCompute(),
	ActionFunc2Tolk:         spec(ActionFunc2Tolk, "func2tolk", RiskT2, EffectReversible, NetworkLocal, true).withWritable(),
	ActionScriptLocal:       spec(ActionScriptLocal, "script", RiskT2, EffectNone, NetworkLocal, false),
	ActionScriptForkTestnet: spec(ActionScriptForkTestnet, "script", RiskT2, EffectNone, NetworkForkTestnet, false).withNetwork(),
	ActionScriptForkMainnet: spec(ActionScriptForkMainnet, "script", RiskT2, EffectNone, NetworkForkMainnet, false).withNetwork(),
	ActionScriptTestnet:     spec(ActionScriptTestnet, "script", RiskT2, EffectIrreversible, NetworkTestnet, true).withNetwork().withManifest().withWallet().withSpend().withExpected(),
	ActionScriptMainnet:     spec(ActionScriptMainnet, "script", RiskT3, EffectIrreversible, NetworkMainnet, true).withNetwork().withManifest().withWallet().withSpend().withApproval().withEvidence().withCompiler().withExpected().withGenericDenied(),
	ActionVerifyDryRun:      spec(ActionVerifyDryRun, "verify", RiskT2, EffectNone, NetworkTestnet, false).withNetwork().withCompiler(),
	ActionVerifyTestnet:     spec(ActionVerifyTestnet, "verify", RiskT2, EffectIrreversible, NetworkTestnet, true).withNetwork().withWallet().withSpend().withCompiler(),
	ActionVerifyMainnet:     spec(ActionVerifyMainnet, "verify", RiskT3, EffectIrreversible, NetworkMainnet, true).withNetwork().withWallet().withSpend().withApproval().withEvidence().withCompiler(),
	ActionLibraryInfo:       spec(ActionLibraryInfo, "library", RiskT2, EffectNone, NetworkTestnet, false).withNetwork(),
	ActionLibraryFetch:      spec(ActionLibraryFetch, "library", RiskT2, EffectReversible, NetworkTestnet, true).withNetwork(),
	ActionLibraryPublishTN:  spec(ActionLibraryPublishTN, "library", RiskT2, EffectIrreversible, NetworkTestnet, true).withNetwork().withWallet().withSpend().withExpected(),
	ActionLibraryPublishMN:  spec(ActionLibraryPublishMN, "library", RiskT3, EffectIrreversible, NetworkMainnet, true).withNetwork().withWallet().withSpend().withApproval().withEvidence().withExpected().withGenericDenied(),
	ActionLibraryTopupTN:    spec(ActionLibraryTopupTN, "library", RiskT2, EffectIrreversible, NetworkTestnet, true).withNetwork().withWallet().withSpend().withExpected(),
	ActionLibraryTopupMN:    spec(ActionLibraryTopupMN, "library", RiskT3, EffectIrreversible, NetworkMainnet, true).withNetwork().withWallet().withSpend().withApproval().withEvidence().withExpected().withGenericDenied(),
	ActionWalletList:        spec(ActionWalletList, "wallet", RiskT2, EffectNone, NetworkLocal, false),
	ActionRPCQuery:          spec(ActionRPCQuery, "rpc", RiskT2, EffectNone, NetworkTestnet, false).withNetwork(),
}

func spec(urn ActionURN, sub string, risk RiskClass, effect EffectClass, network NetworkProfile, sideEffect bool) CommandSpec {
	return CommandSpec{URN: urn, ActonSubcommand: sub, RiskClass: risk, EffectClass: effect, ExecutorKind: ExecutorDigital, Network: network, SideEffect: sideEffect}
}

func (s CommandSpec) withNetwork() CommandSpec  { s.RequiresNetworkGrant = true; return s }
func (s CommandSpec) withManifest() CommandSpec { s.RequiresManifest = true; return s }
func (s CommandSpec) withWallet() CommandSpec   { s.RequiresWallet = true; return s }
func (s CommandSpec) withSpend() CommandSpec    { s.RequiresSpendCap = true; return s }
func (s CommandSpec) withApproval() CommandSpec { s.RequiresApproval = true; return s }
func (s CommandSpec) withEvidence() CommandSpec { s.RequiresFullEvidence = true; return s }
func (s CommandSpec) withCompiler() CommandSpec { s.RequiresCompilerPin = true; return s }
func (s CommandSpec) withWritable() CommandSpec { s.RequiresWritablePreopen = true; return s }
func (s CommandSpec) withCompute() CommandSpec  { s.RequiresComputeBudget = true; return s }
func (s CommandSpec) withExpected() CommandSpec { s.RequiresExpectedEffects = true; return s }
func (s CommandSpec) withGenericDenied() CommandSpec {
	s.GenericDenied = true
	return s
}

func AllActionURNs() []ActionURN {
	out := make([]ActionURN, 0, len(commandSpecs))
	for urn := range commandSpecs {
		out = append(out, urn)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func ResolveAction(toolName string, params map[string]any) (ActionURN, bool) {
	if v, ok := stringParam(params, "action_urn"); ok && v != "" {
		action := ActionURN(v)
		_, exists := commandSpecs[action]
		return action, exists
	}
	action := ActionURN(toolName)
	_, exists := commandSpecs[action]
	return action, exists
}

func RejectRawCommandFields(params map[string]any) error {
	for _, key := range []string{"cmd", "command", "shell", "raw_command", "argv", "args", "extra_flags"} {
		if _, ok := params[key]; ok {
			return fmt.Errorf("%s: %s", ReasonRawShellForbidden, key)
		}
	}
	return nil
}

func BuildArgv(action ActionURN, params map[string]any) ([]string, error) {
	if err := RejectRawCommandFields(params); err != nil {
		return nil, err
	}
	spec, ok := commandSpecs[action]
	if !ok {
		return nil, fmt.Errorf("%s: %s", ReasonUnknownCommand, action)
	}
	argv := []string{"acton", spec.ActonSubcommand}
	switch action {
	case ActionProjectNew:
		name := requiredString(params, "project_name")
		argv = append(argv, cleanRel(name))
	case ActionFormatCheck:
		argv = append(argv, "--check")
	case ActionCoverage:
		argv = append(argv, "--coverage")
	case ActionMutation:
		argv = append(argv, "--mutate")
		if seed, ok := stringParam(params, "mutation_seed"); ok && seed != "" {
			argv = append(argv, "--seed", seed)
		}
	case ActionWrapperGenerate:
		argv = append(argv, "generate")
	case ActionWrapperGenerateTS:
		argv = append(argv, "generate", "--ts")
	case ActionCompile:
		argv = append(argv, requiredCleanPath(params, "source_path"))
	case ActionDisasm:
		argv = append(argv, requiredCleanPath(params, "artifact_path"))
	case ActionDoc:
		if query, ok := stringParam(params, "query"); ok && query != "" {
			argv = append(argv, query)
		}
	case ActionRetrace:
		argv = append(argv, requiredCleanPath(params, "trace_path"))
	case ActionFunc2Tolk:
		argv = append(argv, requiredCleanPath(params, "source_path"))
	case ActionScriptLocal, ActionScriptForkTestnet, ActionScriptForkMainnet, ActionScriptTestnet, ActionScriptMainnet:
		argv = append(argv, requiredCleanPath(params, "script_path"))
		switch action {
		case ActionScriptForkTestnet:
			argv = append(argv, "--fork-net", "testnet")
		case ActionScriptForkMainnet:
			argv = append(argv, "--fork-net", "mainnet")
		case ActionScriptTestnet:
			argv = append(argv, "--net", "testnet")
			argv = appendSignerFlag(argv, params)
		case ActionScriptMainnet:
			argv = append(argv, "--net", "mainnet")
			argv = appendSignerFlag(argv, params)
		}
	case ActionVerifyDryRun, ActionVerifyTestnet, ActionVerifyMainnet:
		argv = append(argv, requiredString(params, "address"), requiredCleanPath(params, "source_path"))
		if action == ActionVerifyDryRun {
			argv = append(argv, "--dry-run")
		}
		if action == ActionVerifyTestnet {
			argv = append(argv, "--net", "testnet")
			argv = appendSignerFlag(argv, params)
		}
		if action == ActionVerifyMainnet {
			argv = append(argv, "--net", "mainnet")
			argv = appendSignerFlag(argv, params)
		}
	case ActionLibraryInfo:
		argv = append(argv, "info", requiredString(params, "library_ref"))
		argv = appendNetworkIfPresent(argv, params)
	case ActionLibraryFetch:
		argv = append(argv, "fetch", requiredString(params, "library_ref"))
		argv = appendNetworkIfPresent(argv, params)
		if out, ok := stringParam(params, "output_path"); ok && out != "" {
			argv = append(argv, "--out", cleanRel(out))
		}
	case ActionLibraryPublishTN:
		argv = append(argv, "publish", requiredCleanPath(params, "library_path"), "--net", "testnet")
		argv = appendSignerFlag(argv, params)
	case ActionLibraryPublishMN:
		argv = append(argv, "publish", requiredCleanPath(params, "library_path"), "--net", "mainnet")
		argv = appendSignerFlag(argv, params)
	case ActionLibraryTopupTN:
		argv = append(argv, "topup", requiredString(params, "library_ref"), "--net", "testnet")
		argv = appendSignerFlag(argv, params)
	case ActionLibraryTopupMN:
		argv = append(argv, "topup", requiredString(params, "library_ref"), "--net", "mainnet")
		argv = appendSignerFlag(argv, params)
	case ActionWalletList:
		argv = append(argv, "list")
	case ActionRPCQuery:
		argv = append(argv, "query", requiredString(params, "method"))
		argv = appendNetworkIfPresent(argv, params)
	}
	return validateArgvForAction(action, argv)
}

func appendNetworkIfPresent(argv []string, params map[string]any) []string {
	network, _ := stringParam(params, "network")
	switch network {
	case "testnet", "mainnet":
		return append(argv, "--net", network)
	default:
		return argv
	}
}

func appendSignerFlag(argv []string, params map[string]any) []string {
	if mode, ok := stringParam(params, "wallet_mode"); ok && mode == "secret_manager" {
		return argv
	}
	return append(argv, "--tonconnect")
}

func validateArgvForAction(action ActionURN, argv []string) ([]string, error) {
	if len(argv) < 2 || argv[0] != "acton" {
		return nil, fmt.Errorf("%s: argv[0] must be acton", ReasonArgvRejected)
	}
	joined := strings.Join(argv, "\x00")
	if strings.Contains(joined, "\n") || strings.Contains(joined, "\r") {
		return nil, fmt.Errorf("%s: newline in argv", ReasonArgvRejected)
	}
	hasNetMainnet := containsFlagValue(argv, "--net", "mainnet")
	hasNetTestnet := containsFlagValue(argv, "--net", "testnet")
	hasForkNet := containsFlag(argv, "--fork-net")
	switch {
	case hasNetMainnet && action != ActionScriptMainnet && action != ActionVerifyMainnet && action != ActionLibraryPublishMN && action != ActionLibraryTopupMN:
		return nil, fmt.Errorf("%s", ReasonGenericMainnetScriptDenied)
	case hasNetTestnet && action != ActionScriptTestnet && action != ActionVerifyTestnet && action != ActionLibraryPublishTN && action != ActionLibraryTopupTN && action != ActionLibraryInfo && action != ActionLibraryFetch && action != ActionRPCQuery:
		return nil, fmt.Errorf("%s", ReasonArgvRejected)
	case hasForkNet && action != ActionScriptForkTestnet && action != ActionScriptForkMainnet:
		return nil, fmt.Errorf("%s", ReasonArgvRejected)
	}
	if action == ActionScriptLocal && containsFlag(argv, "--net") {
		return nil, fmt.Errorf("%s", ReasonArgvRejected)
	}
	return argv, nil
}

func containsFlag(argv []string, flag string) bool {
	for _, arg := range argv {
		if arg == flag {
			return true
		}
	}
	return false
}

func containsFlagValue(argv []string, flag, value string) bool {
	for i := 0; i < len(argv)-1; i++ {
		if argv[i] == flag && argv[i+1] == value {
			return true
		}
	}
	return false
}

func requiredString(params map[string]any, key string) string {
	v, _ := stringParam(params, key)
	return v
}

func requiredCleanPath(params map[string]any, key string) string {
	return cleanRel(requiredString(params, key))
}

func cleanRel(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return path
	}
	clean := filepath.Clean(path)
	if strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
		return path
	}
	return clean
}

func stringParam(params map[string]any, key string) (string, bool) {
	v, ok := params[key]
	if !ok || v == nil {
		return "", false
	}
	s, ok := v.(string)
	if ok {
		return strings.TrimSpace(s), true
	}
	return fmt.Sprint(v), true
}
