package acton

import "fmt"

func ValidateSourceVerification(env *ActonCommandEnvelope) error {
	switch env.ActionURN {
	case ActionVerifyDryRun, ActionVerifyTestnet, ActionVerifyMainnet:
	default:
		return nil
	}
	if env.TolkCompilerVersion == "" {
		return fmt.Errorf("%s", ReasonCompilerUnpinned)
	}
	if env.ActionURN == ActionVerifyDryRun && containsFlag(env.Argv, "--net") && !containsFlag(env.Argv, "--dry-run") {
		return fmt.Errorf("%s", ReasonVerifyDryRunRequired)
	}
	return nil
}

func VerifyDryRunRequiredForDeploy(env *ActonCommandEnvelope) bool {
	return env.ActionURN == ActionScriptMainnet && env.EvidenceRequirements.RequireVerifierDryRun
}
