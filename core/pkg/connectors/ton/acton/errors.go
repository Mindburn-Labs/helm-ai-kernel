package acton

// ReasonCode is the connector-local stable reason code carried by ActonReceipt.
// DENY/ESCALATE codes that cross the generic execution-boundary record are also
// registered in contracts/verdict.go.
type ReasonCode string

const (
	ReasonOK                             ReasonCode = "OK"
	ReasonUnknownCommand                 ReasonCode = "ERR_TON_ACTON_UNKNOWN_COMMAND"
	ReasonUnsupportedVersion             ReasonCode = "ERR_TON_ACTON_UNSUPPORTED_VERSION"
	ReasonCompilerUnpinned               ReasonCode = "ERR_TON_TOLK_COMPILER_UNPINNED"
	ReasonCompilerMismatch               ReasonCode = "ERR_TON_TOLK_COMPILER_MISMATCH"
	ReasonArgvRejected                   ReasonCode = "ERR_TON_ACTON_ARGV_REJECTED"
	ReasonRawShellForbidden              ReasonCode = "ERR_TON_ACTON_RAW_SHELL_FORBIDDEN"
	ReasonGenericMainnetScriptDenied     ReasonCode = "ERR_TON_ACTON_GENERIC_MAINNET_SCRIPT_DENIED"
	ReasonScriptManifestRequired         ReasonCode = "ERR_TON_SCRIPT_MANIFEST_REQUIRED"
	ReasonScriptManifestHashMismatch     ReasonCode = "ERR_TON_SCRIPT_MANIFEST_HASH_MISMATCH"
	ReasonExpectedEffectMismatch         ReasonCode = "ERR_TON_EXPECTED_EFFECT_MISMATCH"
	ReasonSpendCeilingExceeded           ReasonCode = "ERR_TON_SPEND_CEILING_EXCEEDED"
	ReasonMainnetRequiresApproval        ReasonCode = "ERR_TON_MAINNET_REQUIRES_APPROVAL"
	ReasonApprovalCeremonyRequired       ReasonCode = "ERR_TON_APPROVAL_CEREMONY_REQUIRED"
	ReasonWalletRefRequired              ReasonCode = "ERR_TON_WALLET_REF_REQUIRED"
	ReasonPlaintextMnemonicForbidden     ReasonCode = "ERR_TON_PLAINTEXT_MNEMONIC_FORBIDDEN"
	ReasonNetworkGrantRequired           ReasonCode = "ERR_TON_NETWORK_GRANT_REQUIRED"
	ReasonSandboxGrantRequired           ReasonCode = "ERR_TON_SANDBOX_GRANT_REQUIRED"
	ReasonSourceVerificationRequired     ReasonCode = "ERR_TON_SOURCE_VERIFICATION_REQUIRED"
	ReasonVerifyDryRunRequired           ReasonCode = "ERR_TON_VERIFY_DRY_RUN_REQUIRED"
	ReasonVerifyBytecodeMismatch         ReasonCode = "ERR_TON_VERIFY_BYTECODE_MISMATCH"
	ReasonCoverageThresholdFailed        ReasonCode = "ERR_TON_COVERAGE_THRESHOLD_FAILED"
	ReasonMutationThresholdFailed        ReasonCode = "ERR_TON_MUTATION_THRESHOLD_FAILED"
	ReasonLibraryMainnetRequiresApproval ReasonCode = "ERR_TON_LIBRARY_MAINNET_REQUIRES_APPROVAL"
	ReasonLibrarySpendCeilingExceeded    ReasonCode = "ERR_TON_LIBRARY_SPEND_CEILING_EXCEEDED"
	ReasonConnectorContractDrift         ReasonCode = "ERR_CONNECTOR_CONTRACT_DRIFT"
	ReasonComputeGasExhausted            ReasonCode = "ERR_COMPUTE_GAS_EXHAUSTED"
	ReasonComputeTimeExhausted           ReasonCode = "ERR_COMPUTE_TIME_EXHAUSTED"
)

func (r ReasonCode) String() string {
	return string(r)
}

func allReasonCodes() []ReasonCode {
	return []ReasonCode{
		ReasonOK,
		ReasonUnknownCommand,
		ReasonUnsupportedVersion,
		ReasonCompilerUnpinned,
		ReasonCompilerMismatch,
		ReasonArgvRejected,
		ReasonRawShellForbidden,
		ReasonGenericMainnetScriptDenied,
		ReasonScriptManifestRequired,
		ReasonScriptManifestHashMismatch,
		ReasonExpectedEffectMismatch,
		ReasonSpendCeilingExceeded,
		ReasonMainnetRequiresApproval,
		ReasonApprovalCeremonyRequired,
		ReasonWalletRefRequired,
		ReasonPlaintextMnemonicForbidden,
		ReasonNetworkGrantRequired,
		ReasonSandboxGrantRequired,
		ReasonSourceVerificationRequired,
		ReasonVerifyDryRunRequired,
		ReasonVerifyBytecodeMismatch,
		ReasonCoverageThresholdFailed,
		ReasonMutationThresholdFailed,
		ReasonLibraryMainnetRequiresApproval,
		ReasonLibrarySpendCeilingExceeded,
		ReasonConnectorContractDrift,
		ReasonComputeGasExhausted,
		ReasonComputeTimeExhausted,
	}
}
