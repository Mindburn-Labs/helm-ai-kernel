package tonacton

import (
	"encoding/json"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/connectors/ton/acton"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
)

// group is how far an operation reaches.
type group int

const (
	// groupLocal runs on the project's files and the machine only.
	groupLocal group = iota
	// groupFork reads a forked copy of testnet or mainnet state and broadcasts
	// nothing.
	groupFork
	// groupTestnet broadcasts to TON testnet with the gateway's testnet wallet.
	groupTestnet
)

// op is one admitted Acton operation: the connector's command, the effect type
// it is exposed as and the closed set of arguments it takes.
type op struct {
	action acton.ActionURN
	group  group
	// properties names the argument properties beyond "schema"; required is the
	// subset the effect cannot run without.
	properties  []string
	required    []string
	description string
}

// actionPrefix is stripped from a connector action URN to form the effect type.
const actionPrefix = "connector.ton.acton."

// effectType is the effect type of the operation: ton.acton.<command>.
func (o op) effectType() string {
	return effectargs.TONActonPrefix + strings.TrimPrefix(string(o.action), actionPrefix)
}

// spec is the connector's classification of the command.
func (o op) spec() acton.CommandSpec {
	s, _ := acton.ClassifyAction(o.action)
	return s
}

func (o op) broadcast() bool { return o.spec().Broadcast }

func (o op) usesWallet() bool { return o.spec().RequiresWallet }

// schemaConst is the value of the "schema" argument.
func (o op) schemaConst() string { return "helm." + o.effectType() + ".v1" }

var spend = []string{"wallet_ref", "max_ton_spend", "expected_effects"}

// ops is every operation the gateway performs, in effect-type order. The
// operations the owner left out are listed in notAdmitted, and the mainnet
// ones in effectargs: a connector command in neither is a test failure, so a
// new command is never admitted by default.
var ops = []op{
	{action: acton.ActionProjectNew, properties: []string{"project_name"}, required: []string{"project_name"},
		description: "Creates a new Acton project directory in the tenant's workspace."},
	{action: acton.ActionProjectInit, description: "Initializes an Acton project in the target's workspace directory."},
	{action: acton.ActionDoctor, properties: []string{"acton_version"}, description: "Runs Acton's environment diagnostics."},
	{action: acton.ActionEnv, properties: []string{"acton_version"}, description: "Reports Acton's environment."},
	{action: acton.ActionVersion, description: "Reports the Acton version."},
	{action: acton.ActionBuild, properties: []string{"acton_version", "tolk_compiler_version"}, description: "Builds the project's contracts."},
	{action: acton.ActionCheck, properties: []string{"acton_version", "tolk_compiler_version"}, description: "Statically checks the project's contracts."},
	{action: acton.ActionFormat, description: "Formats the project's sources in place."},
	{action: acton.ActionFormatCheck, description: "Checks the project's formatting and changes nothing."},
	{action: acton.ActionTest, properties: []string{"acton_version", "tolk_compiler_version"}, description: "Runs the project's contract tests locally."},
	{action: acton.ActionWrapperGenerate, description: "Generates the project's contract wrappers."},
	{action: acton.ActionWrapperGenerateTS, description: "Generates the project's TypeScript contract wrappers."},
	{action: acton.ActionCompile, properties: []string{"source_path", "tolk_compiler_version"}, required: []string{"source_path"},
		description: "Compiles one source file."},
	{action: acton.ActionDisasm, properties: []string{"artifact_path"}, required: []string{"artifact_path"},
		description: "Disassembles one compiled artifact."},
	{action: acton.ActionDoc, properties: []string{"query"}, description: "Looks up Acton documentation."},
	{action: acton.ActionLibraryInfo, properties: []string{"library_ref", "network"}, required: []string{"library_ref", "network"},
		description: "Reads one library's published information from TON testnet."},
	{action: acton.ActionLibraryFetch, properties: []string{"library_ref", "network", "output_path"}, required: []string{"library_ref", "network"},
		description: "Fetches one library from TON testnet into the project."},
	{action: acton.ActionScriptForkTestnet, group: groupFork, properties: []string{"script_path"}, required: []string{"script_path"},
		description: "Runs a script against a fork of TON testnet state; nothing is broadcast."},
	{action: acton.ActionScriptForkMainnet, group: groupFork, properties: []string{"script_path"}, required: []string{"script_path"},
		description: "Runs a script against a fork of TON mainnet state; nothing is broadcast and no mainnet wallet is used."},
	{action: acton.ActionScriptTestnet, group: groupTestnet,
		properties:  append([]string{"script_path", "script_hash", "script_manifest"}, spend...),
		required:    []string{"script_path", "script_hash", "script_manifest", "wallet_ref", "max_ton_spend", "expected_effects"},
		description: "Runs a script on TON testnet, broadcasting with the gateway's testnet wallet."},
	{action: acton.ActionVerifyTestnet, group: groupTestnet,
		properties:  []string{"address", "source_path", "tolk_compiler_version", "wallet_ref", "max_ton_spend"},
		required:    []string{"address", "source_path", "tolk_compiler_version", "wallet_ref", "max_ton_spend"},
		description: "Verifies a contract's source on TON testnet, paying with the gateway's testnet wallet."},
	{action: acton.ActionLibraryPublishTN, group: groupTestnet,
		properties:  append([]string{"library_path"}, spend...),
		required:    []string{"library_path", "wallet_ref", "max_ton_spend", "expected_effects"},
		description: "Publishes a library to TON testnet with the gateway's testnet wallet."},
	{action: acton.ActionLibraryTopupTN, group: groupTestnet,
		properties:  append([]string{"library_ref"}, spend...),
		required:    []string{"library_ref", "wallet_ref", "max_ton_spend", "expected_effects"},
		description: "Tops up a library on TON testnet with the gateway's testnet wallet."},
}

// notAdmitted are the connector commands this gateway does not perform and does
// not refuse by name: the owner's scope is the list in ops plus the mainnet
// refusals.
var notAdmitted = []acton.ActionURN{
	acton.ActionCoverage, acton.ActionMutation, acton.ActionRetrace, acton.ActionFunc2Tolk,
	acton.ActionScriptLocal, acton.ActionVerifyDryRun, acton.ActionWalletList, acton.ActionRPCQuery,
}

func lookup(effectType string) (op, bool) {
	for _, o := range ops {
		if o.effectType() == effectType {
			return o, true
		}
	}
	return op{}, false
}

// Property schemas. The patterns are RE2: the gateway compiles the schema with
// Go, which has no look-around, so a path pattern forbids ".." by allowing no
// segment to start with a dot.
const (
	pathPattern = `^[A-Za-z0-9_-][A-Za-z0-9._-]{0,63}(/[A-Za-z0-9_-][A-Za-z0-9._-]{0,63}){0,7}$`
	// versionPattern admits a pinned tool version such as 1.0.0.
	versionPattern = `^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$`
)

func str(pattern string, max int) map[string]any {
	return map[string]any{"type": "string", "pattern": pattern, "maxLength": max}
}

var effectSchema = map[string]any{
	"type": "object", "additionalProperties": false,
	"required": []string{"effect_kind", "effect_class"},
	"properties": map[string]any{
		"effect_kind":                  str(`^[A-Z][A-Z0-9_]{0,63}$`, 64),
		"effect_class":                 map[string]any{"enum": []string{"REVERSIBLE", "COMPENSABLE", "IRREVERSIBLE"}},
		"network":                      map[string]any{"enum": []string{"testnet"}},
		"wallet_ref":                   str(walletRefPattern, 128),
		"max_ton_spend":                str(spendPattern, 20),
		"contract_address":             str(addressPattern, 100),
		"contract_code_hash":           str(`^sha256:[0-9a-f]{64}$`, 71),
		"requires_source_verification": map[string]any{"type": "boolean"},
		"irreversible_reason":          map[string]any{"type": "string", "maxLength": 200},
	},
}

const (
	walletRefPattern = `^wallet:[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,120}$`
	spendPattern     = `^[0-9]{1,6}(\.[0-9]{1,9})?$`
	addressPattern   = `^[A-Za-z0-9_:-]{1,100}$`
)

var manifestSchema = map[string]any{
	"type": "object", "additionalProperties": false,
	"required": []string{"schema_version", "script_path", "script_hash", "allowed_networks", "expected_effects", "required_preflight"},
	"properties": map[string]any{
		"schema_version":   map[string]any{"const": acton.ScriptManifestSchemaVersion},
		"script_path":      str(pathPattern, 600),
		"script_hash":      str(`^sha256:[0-9a-f]{64}$`, 71),
		"allowed_networks": map[string]any{"type": "array", "minItems": 1, "maxItems": 1, "items": map[string]any{"enum": []string{"testnet"}}},
		"expected_effects": map[string]any{"type": "array", "minItems": 1, "maxItems": 8, "items": effectSchema},
		"required_preflight": map[string]any{
			"type": "object", "additionalProperties": false,
			"required": []string{"build", "test", "check", "fmt_check", "verify_dry_run"},
			"properties": map[string]any{
				"build": map[string]any{"type": "boolean"}, "test": map[string]any{"type": "boolean"},
				"check": map[string]any{"type": "boolean"}, "fmt_check": map[string]any{"type": "boolean"},
				"verify_dry_run": map[string]any{"type": "boolean"},
			},
		},
	},
}

// propertySchemas is the schema of every argument property any operation takes.
var propertySchemas = map[string]map[string]any{
	"project_name":          str(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`, 64),
	"source_path":           str(pathPattern, 600),
	"artifact_path":         str(pathPattern, 600),
	"script_path":           str(pathPattern, 600),
	"library_path":          str(pathPattern, 600),
	"output_path":           str(pathPattern, 600),
	"query":                 str(`^[A-Za-z0-9 _.:-]{0,200}$`, 200),
	"library_ref":           str(`^[A-Za-z0-9][A-Za-z0-9:_.-]{0,127}$`, 128),
	"network":               {"enum": []string{"testnet"}},
	"address":               str(addressPattern, 100),
	"wallet_ref":            str(walletRefPattern, 128),
	"max_ton_spend":         str(spendPattern, 20),
	"acton_version":         str(versionPattern, 40),
	"tolk_compiler_version": str(versionPattern, 40),
	"script_hash":           str(`^sha256:[0-9a-f]{64}$`, 71),
	"script_manifest":       manifestSchema,
	"expected_effects":      {"type": "array", "minItems": 1, "maxItems": 8, "items": effectSchema},
}

// argumentSchema is the closed JSON Schema (draft 2020-12) of the operation's
// arguments.
func (o op) argumentSchema() []byte {
	props := map[string]any{"schema": map[string]any{"const": o.schemaConst()}}
	for _, name := range o.properties {
		props[name] = propertySchemas[name]
	}
	required := append([]string{"schema"}, o.required...)
	doc := map[string]any{
		"$schema":              "https://json-schema.org/draft/2020-12/schema",
		"type":                 "object",
		"additionalProperties": false,
		"required":             required,
		"properties":           props,
	}
	body, err := json.Marshal(doc)
	if err != nil {
		// The document is built from constants; a failure is a programming error.
		panic("tonacton: argument schema: " + err.Error())
	}
	return body
}

// resultSchema is the closed schema of every operation's typed result.
func resultSchema() []byte {
	hash := str(`^sha256:[0-9a-f]{64}$`, 71)
	doc := map[string]any{
		"$schema":              "https://json-schema.org/draft/2020-12/schema",
		"$id":                  ResultSchemaID,
		"type":                 "object",
		"additionalProperties": false,
		"required":             []string{"action", "network", "status", "exit_code", "request_hash", "stdout_hash", "stderr_hash", "stdout", "stdout_truncated"},
		"properties": map[string]any{
			"action":           map[string]any{"type": "string", "maxLength": 100},
			"network":          map[string]any{"enum": []string{"local", "fork_testnet", "fork_mainnet", "testnet"}},
			"status":           map[string]any{"enum": []string{"ok", "tool_error", "timeout", "resource_exhausted", "error"}},
			"exit_code":        map[string]any{"type": "integer", "minimum": -1, "maximum": 255},
			"request_hash":     hash,
			"stdout_hash":      hash,
			"stderr_hash":      hash,
			"stdout":           map[string]any{"type": "string", "maxLength": maxStdoutText},
			"stdout_truncated": map[string]any{"type": "boolean"},
			"address":          str(addressPattern, 100),
			"tx_hash":          str(`^[0-9a-f]{64}$`, 64),
			"amount_ton":       str(spendPattern, 20),
			"chain_confirmed":  map[string]any{"type": "boolean"},
		},
	}
	body, err := json.Marshal(doc)
	if err != nil {
		panic("tonacton: result schema: " + err.Error())
	}
	return body
}

func riskOf(o op) adapters.RiskClass {
	switch {
	case o.group == groupTestnet:
		return adapters.RiskHigh
	case o.group == groupFork:
		return adapters.RiskMedium
	case o.spec().SideEffect:
		return adapters.RiskMedium
	default:
		return adapters.RiskLow
	}
}

func idempotencyOf(o op) adapters.Idempotency {
	switch {
	case o.broadcast():
		return adapters.IdempotentNo
	case o.spec().SideEffect:
		return adapters.IdempotentConditional
	default:
		return adapters.IdempotentYes
	}
}

func reversibilityOf(o op) adapters.Reversibility {
	switch o.spec().EffectClass {
	case acton.EffectIrreversible:
		return adapters.ReversibleNo
	case acton.EffectReversible, acton.EffectCompensable:
		return adapters.ReversibleYes
	default:
		return adapters.ReversibleNotApplicable
	}
}

// declaration is the operation's §9.1 declaration. Only the testnet operations
// are mediation-enforced: the testnet wallet exists nowhere but the gateway. The
// others run on workspace files that the gateway's operator can also reach.
func (o op) declaration() adapters.Declaration {
	mediation := adapters.MediationObservedOnly
	notes := "Runs the Acton binary the operator configured, with typed arguments only, in the tenant's workspace. " +
		"Observe reads back the run record the gateway wrote for this attempt and checks it against the arguments."
	if o.group == groupTestnet {
		mediation = adapters.MediationEnforced
		notes = "Broadcasts to TON testnet with the gateway's testnet wallet, which reaches the Acton process only for this call. " +
			"A run whose answer breaks the output contract, or that is cut short, is INDEFINITE; Observe confirms the transaction on testnet " +
			"through the configured RPC before it reports SUCCEEDED."
	}
	return adapters.Declaration{
		EffectType:     o.effectType(),
		RiskClass:      riskOf(o),
		Idempotent:     idempotencyOf(o),
		Observable:     adapters.ObservableYes,
		Reversible:     reversibilityOf(o),
		Mediation:      mediation,
		Notes:          notes,
		TargetForm:     targetForm,
		Description:    o.description,
		ArgumentSchema: o.argumentSchema(),
		ResultSchemaID: ResultSchemaID,
		ResultSchema:   resultSchema(),
		Grantable:      true,
		Quote:          []adapters.Amount{{Unit: "count", Amount: 1}},
	}
}
