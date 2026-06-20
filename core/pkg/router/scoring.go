package router

// scoreCandidates assigns each candidate a 0..1 score according to the policy
// mode and mutates cand.Score in place. Higher is better.
//
// Single-dimension modes optimize one axis; RouteModeBalanced and
// RouteModeComplianceFirst blend axes so that region match and data retention
// genuinely participate in selection — not just cost and latency. A degraded
// candidate keeps its score (so it can still be surfaced) but the caller maps a
// degraded winner to ESCALATE.
func (r *Router) scoreCandidates(cands []scoredCandidate, policy *RoutePolicy) {
	minCost, maxCost := costRange(cands)
	minLat, maxLat := latencyRange(cands)
	minRet, maxRet := retentionRange(cands)

	for i := range cands {
		c := &cands[i]
		costScore := invNorm(c.costPerMTok, minCost, maxCost)     // cheaper -> higher
		latScore := invNorm(float64(c.latencyMS), minLat, maxLat) // faster -> higher
		retScore := invNorm(float64(c.retention), minRet, maxRet) // less retention -> higher
		regionScore := 0.0
		if c.regionMatch {
			regionScore = 1.0
		}
		// Quality is modeled from cost when no explicit quality signal exists: a
		// costlier frontier model is treated as higher quality. This keeps
		// quality_first meaningfully different from cost_first.
		qualScore := norm(c.costPerMTok, minCost, maxCost)

		switch policy.Mode {
		case RouteModeCostFirst:
			c.cand.Score = costScore
		case RouteModeLatencyFirst:
			c.cand.Score = latScore
		case RouteModeQualityFirst:
			c.cand.Score = qualScore
		case RouteModeComplianceFirst:
			// Compliance posture: retention (lower is better) and region match
			// dominate; cost breaks ties.
			c.cand.Score = 0.5*retScore + 0.4*regionScore + 0.1*costScore
		case RouteModeRegionPinned:
			// Region already gated; prefer cheaper within region.
			c.cand.Score = 0.7*regionScore + 0.3*costScore
		case RouteModePinned, RouteModeProviderPinned, RouteModeModelPinned:
			// Candidate set is already pinned; pick cheapest deterministically.
			c.cand.Score = costScore
		case RouteModeBalanced:
			w := policy.effectiveWeights()
			total := w.Cost + w.Latency + w.Quality + w.Region + w.Retention
			if total <= 0 {
				total = 1
			}
			c.cand.Score = (w.Cost*costScore +
				w.Latency*latScore +
				w.Quality*qualScore +
				w.Region*regionScore +
				w.Retention*retScore) / total
		default:
			c.cand.Score = costScore
		}
	}
}

// norm maps v into 0..1 within [min,max]; higher v -> higher score.
func norm(v, min, max float64) float64 {
	if max <= min {
		return 1.0
	}
	s := (v - min) / (max - min)
	return clamp01(s)
}

// invNorm maps v into 0..1 within [min,max]; lower v -> higher score.
func invNorm(v, min, max float64) float64 {
	return 1.0 - norm(v, min, max)
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func costRange(cands []scoredCandidate) (float64, float64) {
	if len(cands) == 0 {
		return 0, 0
	}
	min, max := cands[0].costPerMTok, cands[0].costPerMTok
	for _, c := range cands[1:] {
		if c.costPerMTok < min {
			min = c.costPerMTok
		}
		if c.costPerMTok > max {
			max = c.costPerMTok
		}
	}
	return min, max
}

func latencyRange(cands []scoredCandidate) (float64, float64) {
	if len(cands) == 0 {
		return 0, 0
	}
	min, max := float64(cands[0].latencyMS), float64(cands[0].latencyMS)
	for _, c := range cands[1:] {
		v := float64(c.latencyMS)
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
	}
	return min, max
}

func retentionRange(cands []scoredCandidate) (float64, float64) {
	if len(cands) == 0 {
		return 0, 0
	}
	min, max := float64(cands[0].retention), float64(cands[0].retention)
	for _, c := range cands[1:] {
		v := float64(c.retention)
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
	}
	return min, max
}
