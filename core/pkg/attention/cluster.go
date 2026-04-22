package attention

import (
	"fmt"
	"time"
)

// SignalCluster groups related signals by entity and topic.
// Clusters are used to batch-route signals and reduce notification fatigue.
type SignalCluster struct {
	// ClusterID is the unique identifier for this cluster.
	ClusterID string `json:"cluster_id"`

	// EntityID is the entity that this cluster is about.
	EntityID string `json:"entity_id"`

	// Topic is the topic grouping key.
	Topic string `json:"topic"`

	// SignalIDs are the signals in this cluster.
	SignalIDs []string `json:"signal_ids"`

	// AggScore is the aggregate attention score for the cluster.
	AggScore float64 `json:"agg_score"`

	// FirstSeen is when the first signal in the cluster arrived.
	FirstSeen time.Time `json:"first_seen"`

	// LastSeen is when the most recent signal in the cluster arrived.
	LastSeen time.Time `json:"last_seen"`

	// Count is the number of signals in this cluster.
	Count int `json:"count"`
}

// clusterKey is the internal grouping key for cluster building.
type clusterKey struct {
	EntityID string
	Topic    string
}

// pendingSignal holds signal data before clusters are finalized.
type pendingSignal struct {
	SignalID string
	Score    float64
}

// ClusterBuilder accumulates signals and groups them into clusters by (entityID, topic).
type ClusterBuilder struct {
	signals map[clusterKey][]pendingSignal
	seq     int
}

// NewClusterBuilder creates a new ClusterBuilder.
func NewClusterBuilder() *ClusterBuilder {
	return &ClusterBuilder{
		signals: make(map[clusterKey][]pendingSignal),
	}
}

// AddSignal adds a signal to the builder. Signals are grouped by (entityID, topic).
func (cb *ClusterBuilder) AddSignal(signalID, entityID, topic string, score float64) {
	key := clusterKey{EntityID: entityID, Topic: topic}
	cb.signals[key] = append(cb.signals[key], pendingSignal{
		SignalID: signalID,
		Score:    score,
	})
}

// Build finalizes the builder and returns all clusters.
// Each cluster groups signals by (entityID, topic) and computes an aggregate score
// as the maximum score across all signals in the cluster.
func (cb *ClusterBuilder) Build() []SignalCluster {
	now := time.Now()
	var clusters []SignalCluster

	for key, signals := range cb.signals {
		cb.seq++

		var ids []string
		var maxScore float64
		for _, s := range signals {
			ids = append(ids, s.SignalID)
			if s.Score > maxScore {
				maxScore = s.Score
			}
		}

		clusters = append(clusters, SignalCluster{
			ClusterID: fmt.Sprintf("cluster-%d", cb.seq),
			EntityID:  key.EntityID,
			Topic:     key.Topic,
			SignalIDs: ids,
			AggScore:  maxScore,
			FirstSeen: now,
			LastSeen:  now,
			Count:     len(signals),
		})
	}

	return clusters
}
