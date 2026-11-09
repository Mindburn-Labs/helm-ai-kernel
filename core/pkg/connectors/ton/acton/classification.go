package acton

type RiskClass string

const (
	RiskT0 RiskClass = "T0"
	RiskT1 RiskClass = "T1"
	RiskT2 RiskClass = "T2"
	RiskT3 RiskClass = "T3"
)

type EffectClass string

const (
	EffectNone         EffectClass = ""
	EffectReversible   EffectClass = "REVERSIBLE"
	EffectCompensable  EffectClass = "COMPENSABLE"
	EffectIrreversible EffectClass = "IRREVERSIBLE"
)

type ExecutorKind string

const (
	ExecutorDigital ExecutorKind = "DIGITAL"
)

type NetworkProfile string

const (
	NetworkNone        NetworkProfile = ""
	NetworkLocal       NetworkProfile = "local"
	NetworkForkTestnet NetworkProfile = "fork_testnet"
	NetworkForkMainnet NetworkProfile = "fork_mainnet"
	NetworkTestnet     NetworkProfile = "testnet"
	NetworkMainnet     NetworkProfile = "mainnet"
)

func ClassifyAction(action ActionURN) (CommandSpec, bool) {
	spec, ok := commandSpecs[action]
	return spec, ok
}
