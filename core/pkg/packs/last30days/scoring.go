package last30days

import "sort"

// ConvergenceSignal describes an entity that has been mentioned by multiple
// independent sources during the collection window.
type ConvergenceSignal struct {
	Entity   string   `json:"entity"`
	Sources  []string `json:"sources"`
	Strength float64  `json:"strength"` // 0.0–1.0
}

// DetectConvergence finds entities mentioned across multiple sources and
// returns a convergence signal for each, sorted by descending Strength.
//
// Strength is computed as min(sourceCount/totalSources, 1.0).  An entity
// mentioned in every source therefore has Strength 1.0.
func DetectConvergence(items []Item) []ConvergenceSignal {
	// entity → set of source names
	entitySources := make(map[string]map[string]struct{})
	// track unique source names present in the dataset
	allSources := make(map[string]struct{})

	for _, item := range items {
		allSources[item.Source] = struct{}{}
		for _, entity := range item.Entities {
			if entity == "" {
				continue
			}
			if entitySources[entity] == nil {
				entitySources[entity] = make(map[string]struct{})
			}
			entitySources[entity][item.Source] = struct{}{}
		}
	}

	totalSources := len(allSources)
	if totalSources == 0 {
		return nil
	}

	var signals []ConvergenceSignal
	for entity, srcSet := range entitySources {
		if len(srcSet) < 2 {
			// Single-source mentions are not convergence signals.
			continue
		}

		srcs := make([]string, 0, len(srcSet))
		for s := range srcSet {
			srcs = append(srcs, s)
		}
		sort.Strings(srcs) // deterministic order

		strength := float64(len(srcSet)) / float64(totalSources)
		if strength > 1.0 {
			strength = 1.0
		}

		signals = append(signals, ConvergenceSignal{
			Entity:   entity,
			Sources:  srcs,
			Strength: strength,
		})
	}

	// Sort deterministically: descending strength, then entity name.
	sort.Slice(signals, func(i, j int) bool {
		if signals[i].Strength != signals[j].Strength {
			return signals[i].Strength > signals[j].Strength
		}
		return signals[i].Entity < signals[j].Entity
	})

	return signals
}

// ScoreNovelty assigns each item a novelty score in [0.0, 1.0].
// Uniqueness is the inverse of duplication: items that share a ContentHash
// with many others receive a lower score.  The returned map is keyed by
// ContentHash.
func ScoreNovelty(items []Item) map[string]float64 {
	// Count how many items share each hash.
	counts := make(map[string]int, len(items))
	for _, item := range items {
		counts[item.ContentHash]++
	}

	scores := make(map[string]float64, len(counts))
	for hash, count := range counts {
		// score = 1 / count  →  unique item scores 1.0, duplicate of 2 scores 0.5, etc.
		scores[hash] = 1.0 / float64(count)
	}
	return scores
}

// FindContradictions returns the entity names where both bullish and bearish
// stances have been observed within the collected items.
func FindContradictions(items []Item) []string {
	type stances struct {
		bullish bool
		bearish bool
	}
	entityStances := make(map[string]*stances)

	for _, item := range items {
		for _, entity := range item.Entities {
			if entity == "" {
				continue
			}
			if entityStances[entity] == nil {
				entityStances[entity] = &stances{}
			}
			switch item.Stance {
			case "bullish":
				entityStances[entity].bullish = true
			case "bearish":
				entityStances[entity].bearish = true
			}
		}
	}

	var contradictions []string
	for entity, s := range entityStances {
		if s.bullish && s.bearish {
			contradictions = append(contradictions, entity)
		}
	}

	sort.Strings(contradictions) // deterministic
	return contradictions
}
