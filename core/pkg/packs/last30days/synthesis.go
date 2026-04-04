package last30days

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Synthesis is the human-readable summary produced from the collected items.
type Synthesis struct {
	Summary        string   `json:"summary"`
	Contradictions []string `json:"contradictions"`
	WatchItems     []string `json:"watch_items"`
}

// Digest is the top-level output of the Pack.Run pipeline.
type Digest struct {
	DigestID           string              `json:"digest_id"`
	Topic              string              `json:"topic"`
	WindowDays         int                 `json:"window_days"`
	Items              []Item              `json:"items"`
	ConvergenceSignals []ConvergenceSignal `json:"convergence_signals"`
	Synthesis          Synthesis           `json:"synthesis"`
	GeneratedAt        time.Time           `json:"generated_at"`
	ContentHash        string              `json:"content_hash"`
}

// Synthesize creates a Digest from collected items and pre-computed signals.
// It derives the Synthesis inline (no external LLM call) and computes a
// deterministic ContentHash over the canonical payload.
func Synthesize(
	topic string,
	windowDays int,
	items []Item,
	signals []ConvergenceSignal,
	contradictions []string,
) *Digest {
	summary := buildSummary(topic, windowDays, items, signals, contradictions)
	watchItems := buildWatchItems(signals)

	syn := Synthesis{
		Summary:        summary,
		Contradictions: contradictions,
		WatchItems:     watchItems,
	}

	d := &Digest{
		DigestID:           uuid.NewString(),
		Topic:              topic,
		WindowDays:         windowDays,
		Items:              items,
		ConvergenceSignals: signals,
		Synthesis:          syn,
		GeneratedAt:        time.Now().UTC(),
	}

	d.ContentHash = computeDigestHash(d)
	return d
}

// buildSummary produces a deterministic, template-driven summary string.
// This is intentionally rule-based so the pack is self-contained and does
// not depend on an LLM at construction time.
func buildSummary(topic string, windowDays int, items []Item, signals []ConvergenceSignal, contradictions []string) string {
	sourceSet := make(map[string]struct{})
	for _, item := range items {
		sourceSet[item.Source] = struct{}{}
	}
	sources := make([]string, 0, len(sourceSet))
	for s := range sourceSet {
		sources = append(sources, s)
	}
	sort.Strings(sources)

	var sb strings.Builder
	fmt.Fprintf(&sb, "30-day alternative data digest for topic %q covering %d day(s).", topic, windowDays)
	fmt.Fprintf(&sb, " Collected %d item(s) from %d source(s) (%s).", len(items), len(sources), strings.Join(sources, ", "))

	if len(signals) > 0 {
		top := signals[0]
		fmt.Fprintf(&sb, " Strongest convergence signal: %q (%.0f%% of sources).", top.Entity, top.Strength*100)
	}

	if len(contradictions) > 0 {
		fmt.Fprintf(&sb, " Contradicting stances detected on: %s.", strings.Join(contradictions, ", "))
	}

	return sb.String()
}

// buildWatchItems returns entities from the top convergence signals.
func buildWatchItems(signals []ConvergenceSignal) []string {
	var watch []string
	for _, sig := range signals {
		if sig.Strength >= 0.5 {
			watch = append(watch, sig.Entity)
		}
	}
	return watch
}

// computeDigestHash computes a deterministic SHA-256 hash of the digest
// payload (excluding the hash field itself and the non-deterministic DigestID
// and GeneratedAt fields).
func computeDigestHash(d *Digest) string {
	// Build a canonical representation that is stable across re-runs.
	type canonicalItem struct {
		Source      string `json:"source"`
		ContentHash string `json:"content_hash"`
	}

	canonItems := make([]canonicalItem, len(d.Items))
	for i, item := range d.Items {
		canonItems[i] = canonicalItem{Source: item.Source, ContentHash: item.ContentHash}
	}
	// Already sorted by ContentHash in Pack.Run, but sort here too for safety.
	sort.Slice(canonItems, func(i, j int) bool {
		return canonItems[i].ContentHash < canonItems[j].ContentHash
	})

	signalEntities := make([]string, len(d.ConvergenceSignals))
	for i, sig := range d.ConvergenceSignals {
		signalEntities[i] = sig.Entity
	}

	payload := struct {
		Topic          string          `json:"topic"`
		WindowDays     int             `json:"window_days"`
		Items          []canonicalItem `json:"items"`
		SignalEntities []string        `json:"signal_entities"`
		Contradictions []string        `json:"contradictions"`
	}{
		Topic:          d.Topic,
		WindowDays:     d.WindowDays,
		Items:          canonItems,
		SignalEntities: signalEntities,
		Contradictions: d.Synthesis.Contradictions,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return ""
	}

	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h)
}
