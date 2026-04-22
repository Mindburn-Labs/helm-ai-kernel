package verification

// checkEditorScore returns ERR_EDITOR_SCORE_TOO_LOW when the editor score
// falls below Config.MinEditorScore.
func (s *Service) checkEditorScore(score float64) []string {
	if score < s.config.MinEditorScore {
		return []string{"ERR_EDITOR_SCORE_TOO_LOW"}
	}
	return nil
}
