package threatscan

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

const (
	semanticFailureUnavailable  = "MODEL_UNAVAILABLE"
	semanticFailureHashMismatch = "MODEL_HASH_MISMATCH"
	semanticFailureInvalid      = "MODEL_INVALID"
	semanticMaxInputWindows     = 16
)

//go:generate go run ../../cmd/semantic-model-gen -out semantic_model.json -hash-out semantic_model_hash_generated.go

//go:embed semantic_model.json
var embeddedSemanticModel []byte

type semanticModel struct {
	Version     string                  `json:"version"`
	Dimensions  int                     `json:"dimensions"`
	ThresholdBP int                     `json:"threshold_bp"`
	MaxTokens   int                     `json:"max_tokens"`
	Embeddings  map[string][]int8       `json:"embeddings"`
	Centroids   []semanticClassCentroid `json:"centroids"`
}

type semanticClassCentroid struct {
	Class  string `json:"class"`
	Vector []int8 `json:"vector"`
}

// SemanticDetector performs deterministic, integer-only similarity scoring
// against a content-addressed quantized subword model.
type SemanticDetector struct {
	model     semanticModel
	modelHash string
}

func (s *Scanner) setSemanticModel(model []byte, expectedHash string) {
	detector, unavailable := loadSemanticDetector(model, expectedHash)
	s.semantic = detector
	s.semanticUnavailable = unavailable
	if detector != nil {
		s.semanticThresholdBP = detector.model.ThresholdBP
	} else {
		s.semanticThresholdBP = 0
	}
}

func (s *Scanner) semanticAssessment(normalized string) *contracts.SemanticThreatAssessment {
	if s.semantic == nil {
		if s.semanticUnavailable == nil {
			return nil
		}
		assessment := *s.semanticUnavailable
		return &assessment
	}
	return s.semantic.Assess(normalized, s.semanticThresholdBP)
}

func loadSemanticDetector(model []byte, expectedHash string) (*SemanticDetector, *contracts.SemanticThreatAssessment) {
	actualHash := semanticArtifactHash(model)
	base := &contracts.SemanticThreatAssessment{
		Available:         false,
		ModelHash:         actualHash,
		ExpectedModelHash: expectedHash,
	}
	if len(model) == 0 {
		base.FailureReason = semanticFailureUnavailable
		return nil, base
	}
	if expectedHash == "" || actualHash != expectedHash {
		base.FailureReason = semanticFailureHashMismatch
		return nil, base
	}

	var parsed semanticModel
	if err := json.Unmarshal(model, &parsed); err != nil {
		base.FailureReason = semanticFailureInvalid
		return nil, base
	}
	if err := validateSemanticModel(parsed); err != nil {
		base.FailureReason = semanticFailureInvalid
		return nil, base
	}
	base.ModelVersion = parsed.Version
	base.ThresholdBP = parsed.ThresholdBP
	return &SemanticDetector{model: parsed, modelHash: actualHash}, nil
}

func validateSemanticModel(model semanticModel) error {
	if model.Version == "" || model.Dimensions < 2 || model.Dimensions > 64 {
		return errors.New("invalid model header")
	}
	if model.ThresholdBP < 1 || model.ThresholdBP > 10000 || model.MaxTokens < 1 || model.MaxTokens > 4096 {
		return errors.New("invalid model limits")
	}
	if len(model.Embeddings) == 0 || len(model.Centroids) == 0 {
		return errors.New("empty semantic model")
	}
	for subword, vector := range model.Embeddings {
		if subword == "" || len(vector) != model.Dimensions {
			return fmt.Errorf("invalid embedding %q", subword)
		}
	}
	for _, centroid := range model.Centroids {
		if centroid.Class == "" || len(centroid.Vector) != model.Dimensions {
			return fmt.Errorf("invalid centroid %q", centroid.Class)
		}
	}
	return nil
}

// Assess returns fixed-point cosine similarity in basis points. No float or
// runtime randomness participates in the score.
func (d *SemanticDetector) Assess(input string, thresholdBP int) *contracts.SemanticThreatAssessment {
	if thresholdBP < 1 || thresholdBP > 10000 {
		thresholdBP = d.model.ThresholdBP
	}
	tokens, truncated := d.boundedTokens(input)
	maxBP := 0
	nearestClass := ""
	scoreWindow := func(window []string) {
		vector := d.embedTokens(window)
		for _, centroid := range d.model.Centroids {
			score := cosineBP(vector, centroid.Vector)
			if semanticIntentCoverage(vector) < 3 {
				score = 0
			}
			if score > maxBP || (score == maxBP && (nearestClass == "" || centroid.Class < nearestClass)) {
				maxBP = score
				nearestClass = centroid.Class
			}
		}
	}

	if len(tokens) == 0 {
		scoreWindow(nil)
	} else {
		windowSize := d.model.MaxTokens
		stride := max(windowSize/2, 1)
		for start := 0; start < len(tokens); start += stride {
			end := min(start+windowSize, len(tokens))
			scoreWindow(tokens[start:end])
			if end == len(tokens) {
				break
			}
		}
	}
	return &contracts.SemanticThreatAssessment{
		Available:         true,
		ModelVersion:      d.model.Version,
		ModelHash:         d.modelHash,
		ExpectedModelHash: d.modelHash,
		ThresholdBP:       thresholdBP,
		MaxBP:             maxBP,
		NearestClass:      nearestClass,
		Flagged:           maxBP >= thresholdBP,
		InputTruncated:    truncated,
	}
}

func semanticIntentCoverage(vector []int64) int {
	coverage := 0
	for i := 0; i < 4 && i < len(vector); i++ {
		if vector[i] >= 60 {
			coverage++
		}
	}
	return coverage
}

func (d *SemanticDetector) embed(input string) ([]int64, bool) {
	tokens, truncated := d.boundedTokens(input)
	if len(tokens) > d.model.MaxTokens {
		tokens = tokens[:d.model.MaxTokens]
	}
	return d.embedTokens(tokens), truncated
}

func (d *SemanticDetector) boundedTokens(input string) ([]string, bool) {
	maxInputTokens := d.model.MaxTokens * semanticMaxInputWindows
	tokens := semanticTokens(input, maxInputTokens+1)
	truncated := len(tokens) > maxInputTokens
	if truncated {
		tokens = tokens[:maxInputTokens]
	}
	return tokens, truncated
}

func (d *SemanticDetector) embedTokens(tokens []string) []int64 {
	vector := make([]int64, d.model.Dimensions)
	for _, token := range tokens {
		tokenVector := make([]int64, d.model.Dimensions)
		matches := int64(0)
		accumulate := func(subword string) {
			embedding, ok := d.model.Embeddings[subword]
			if !ok {
				return
			}
			matches++
			for i, value := range embedding {
				tokenVector[i] += int64(value)
			}
		}
		forEachPrefixSubword(token, accumulate)
		if matches == 0 {
			if len([]rune(token)) < 6 {
				continue
			}
			trigramCount := int64(0)
			forEachCharTrigram(token, func(subword string) {
				trigramCount++
				accumulate(subword)
			})
			// Require both multiple matches and 60% trigram coverage. Incidental
			// shared trigrams in ordinary vocabulary must not become a vector.
			if matches < 2 || matches*5 < trigramCount*3 {
				continue
			}
		}
		if matches == 0 {
			continue
		}
		for i := range vector {
			vector[i] += tokenVector[i] / matches
		}
	}
	return vector
}

func semanticTokens(input string, limit int) []string {
	if limit <= 0 {
		return nil
	}
	tokens := make([]string, 0, min(limit, 32))
	var token strings.Builder
	flush := func() bool {
		if token.Len() == 0 {
			return false
		}
		tokens = append(tokens, token.String())
		token.Reset()
		return len(tokens) >= limit
	}
	for _, r := range strings.ToLower(input) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			token.WriteRune(r)
			continue
		}
		if flush() {
			return tokens
		}
	}
	flush()
	return tokens
}

func forEachPrefixSubword(token string, yield func(string)) {
	bounded := []rune("^" + token + "$")
	for size := 5; size <= 8 && size <= len(bounded); size++ {
		yield("p:" + string(bounded[:size]))
	}
}

func forEachCharTrigram(token string, yield func(string)) {
	bounded := []rune("^" + token + "$")
	for start := 0; start+3 <= len(bounded); start++ {
		yield("g:" + string(bounded[start:start+3]))
	}
}

func cosineBP(left []int64, right []int8) int {
	if len(left) == 0 || len(left) != len(right) {
		return 0
	}
	// validateSemanticModel caps dimensions at 64 and each scoring window at
	// 4096 tokens. With int8 embeddings, each accumulated component is at most
	// 4096*127, so products and sums remain well inside int64/uint64 bounds.
	var dot, leftSquared, rightSquared uint64
	var signedDot int64
	for i, leftValue := range left {
		rightValue := int64(right[i])
		signedDot += leftValue * rightValue
		leftSquared += uint64(leftValue * leftValue)
		rightSquared += uint64(rightValue * rightValue)
	}
	if signedDot <= 0 || leftSquared == 0 || rightSquared == 0 {
		return 0
	}
	leftNorm := integerSqrt(leftSquared)
	rightNorm := integerSqrt(rightSquared)
	if leftNorm == 0 || rightNorm == 0 {
		return 0
	}
	dot = uint64(signedDot)
	score := dot * 10000 / (leftNorm * rightNorm)
	if score > 10000 {
		return 10000
	}
	return int(score)
}

func integerSqrt(value uint64) uint64 {
	if value < 2 {
		return value
	}
	x := value
	y := (x + 1) / 2
	for y < x {
		x = y
		y = (x + value/x) / 2
	}
	return x
}

func semanticArtifactHash(model []byte) string {
	sum := sha256.Sum256(model)
	return "sha256:" + hex.EncodeToString(sum[:])
}
