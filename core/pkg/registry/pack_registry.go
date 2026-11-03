// Package registry - pack_registry.go
// Provides pack publishing and marketplace registry for HELM.
// Per Section 5 - enables publishing, searching, and retrieving verified packs.

package registry

import (
	"sync"
	"time"
)

// PackState represents the lifecycle state of a pack in the registry.
type PackState string

const (
	PackStatePublished  PackState = "published"
	PackStateVerified   PackState = "verified"
	PackStateSigned     PackState = "signed"
	PackStateActive     PackState = "active"
	PackStateDeprecated PackState = "deprecated"
)

// PackEntry is a registered pack in the registry.
type PackEntry struct {
	PackID       string                 `json:"pack_id"`
	Name         string                 `json:"name"`
	Version      string                 `json:"version"`
	Description  string                 `json:"description"`
	Capabilities []string               `json:"capabilities"`
	State        PackState              `json:"state"`
	ContentHash  string                 `json:"content_hash"`
	Signatures   []PackSignature        `json:"signatures"`
	PublishedAt  time.Time              `json:"published_at"`
	PublishedBy  string                 `json:"published_by"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// PackSignature represents a cryptographic signature on a pack.
type PackSignature struct {
	SignerID  string    `json:"signer_id"`
	Algorithm string    `json:"algorithm"`
	Signature string    `json:"signature"`
	KeyID     string    `json:"key_id"`
	SignedAt  time.Time `json:"signed_at"`
}

// PackRegistry manages pack entries with staged activation.
type PackRegistry struct {
	entries  map[string]*PackEntry // packID -> entry
	byName   map[string][]string   // name -> list of packIDs (all versions)
	byCap    map[string][]string   // capability -> list of packIDs
	verifier PackSignatureVerifier
	mu       sync.RWMutex
}

// PackSignatureVerifier verifies pack signatures.
type PackSignatureVerifier interface {
	VerifyPackSignature(contentHash string, signature *PackSignature) (bool, error)
}

// PackSearchQuery defines search criteria.
type PackSearchQuery struct {
	Name       string      `json:"name,omitempty"`
	Capability string      `json:"capability,omitempty"`
	States     []PackState `json:"states,omitempty"`
	Limit      int         `json:"limit,omitempty"`
}

// PackSearchResult is the result of a search.
type PackSearchResult struct {
	Entries    []*PackEntry    `json:"entries"`
	TotalCount int             `json:"total_count"`
	Query      PackSearchQuery `json:"query"`
}
