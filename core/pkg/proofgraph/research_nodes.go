package proofgraph

const (
	NodeTypeResearchPromotion   NodeType = "RESEARCH_PROMOTION"
	NodeTypeResearchPublication NodeType = "RESEARCH_PUBLICATION"
)

// ResearchPromotionPayload is the payload for a research promotion ProofGraph node.
type ResearchPromotionPayload struct {
	MissionID    string `json:"mission_id"`
	ReceiptHash  string `json:"receipt_hash"`
	ArtifactHash string `json:"artifact_hash"`
}

// ResearchPublicationPayload is the payload for a research publication ProofGraph node.
type ResearchPublicationPayload struct {
	MissionID     string `json:"mission_id"`
	PublicationID string `json:"publication_id"`
	Slug          string `json:"slug"`
}

// NewResearchPromotionPayload creates an encoded payload for a research promotion node.
func NewResearchPromotionPayload(missionID, receiptHash, artifactHash string) ([]byte, error) {
	return EncodePayload(ResearchPromotionPayload{
		MissionID:    missionID,
		ReceiptHash:  receiptHash,
		ArtifactHash: artifactHash,
	})
}

// NewResearchPublicationPayload creates an encoded payload for a research publication node.
func NewResearchPublicationPayload(missionID, publicationID, slug string) ([]byte, error) {
	return EncodePayload(ResearchPublicationPayload{
		MissionID:     missionID,
		PublicationID: publicationID,
		Slug:          slug,
	})
}
