package verification

import "github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime"

// checkSourceCount returns ERR_PRIMARY_SOURCE_COUNT_LOW when the number of
// primary sources falls below Config.MinPrimarySourceCount.
func (s *Service) checkSourceCount(sources []researchruntime.SourceSnapshot) []string {
	primary := 0
	for _, src := range sources {
		if src.Primary {
			primary++
		}
	}
	if primary < s.config.MinPrimarySourceCount {
		return []string{"ERR_PRIMARY_SOURCE_COUNT_LOW"}
	}
	return nil
}

// checkSourcesVerified returns ERR_SOURCE_SNAPSHOT_MISSING when any source
// has a provenance status other than "verified" or "captured".
// The check is skipped when Config.RequireAllSourcesVerified is false.
func (s *Service) checkSourcesVerified(sources []researchruntime.SourceSnapshot) []string {
	if !s.config.RequireAllSourcesVerified {
		return nil
	}
	for _, src := range sources {
		switch src.ProvenanceStatus {
		case researchruntime.ProvenanceVerified, researchruntime.ProvenanceCaptured:
			// acceptable
		default:
			return []string{"ERR_SOURCE_SNAPSHOT_MISSING"}
		}
	}
	return nil
}
