// Package vibevoice provides the HELM connector for the VibeVoice ASR (Automatic Speech
// Recognition) API.
//
// Architecture:
//   - types.go:     Request/response types for transcription operations
//   - client.go:    HTTP client for the VibeVoice API (stub implementation)
//   - receipts.go:  Receipt generation for transcription operations
//   - connector.go: Self-contained connector with Transcribe tool
package vibevoice

// TranscriptionRequest is the input for a transcription operation.
type TranscriptionRequest struct {
	AudioURL     string `json:"audio_url"`
	LanguageCode string `json:"language_code"`
	SampleRate   int    `json:"sample_rate"`
	Encoding     string `json:"encoding"` // wav, mp3, ogg
}

// TranscriptionResult is the output of a completed transcription.
type TranscriptionResult struct {
	TranscriptID string              `json:"transcript_id"`
	Text         string              `json:"text"`
	Segments     []TranscriptSegment `json:"segments"`
	Language     string              `json:"language"`
	DurationMs   int64               `json:"duration_ms"`
	Confidence   float64             `json:"confidence"`
	ContentHash  string              `json:"content_hash"`
}

// TranscriptSegment is a timed text segment within a transcription.
type TranscriptSegment struct {
	StartMs    int64   `json:"start_ms"`
	EndMs      int64   `json:"end_ms"`
	Text       string  `json:"text"`
	Speaker    string  `json:"speaker,omitempty"`
	Confidence float64 `json:"confidence"`
}

// intentPayload is the graph INTENT node payload for a vibevoice action.
type intentPayload struct {
	Type     string         `json:"type"`
	ToolName string         `json:"tool_name"`
	Params   map[string]any `json:"params,omitempty"`
}

// effectPayload is the graph EFFECT node payload after a vibevoice action.
type effectPayload struct {
	Type           string `json:"type"`
	ToolName       string `json:"tool_name"`
	ContentHash    string `json:"content_hash"`
	ProvenanceHash string `json:"provenance_hash,omitempty"`
}
