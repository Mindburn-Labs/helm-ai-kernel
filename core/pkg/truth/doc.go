// Package truth defines the public contracts for HELM's Versioned Truth Registry.
//
// The Truth Registry provides the canonical types and interfaces for managing
// versioned governance truth: policy versions, schema versions, regulatory
// snapshots, and annotation lineage. It serves as the single source of truth
// for what governance rules were active at any point in time.
//
// Key invariant: Truth objects are immutable once registered. New versions
// create new objects; they never modify existing ones.
//
// The commercial HELM Platform extends this with enterprise-grade persistence,
// federated truth synchronization, and compliance audit trails.
package truth
