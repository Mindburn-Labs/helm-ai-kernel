package executor

import ()

func failureCheckIDs(result *VerificationResult) []string {
	ids := make([]string, 0, len(result.ChecksFailed))
	for _, failure := range result.ChecksFailed {
		ids = append(ids, failure.CheckID)
	}
	return ids
}
