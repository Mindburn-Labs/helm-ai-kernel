package api

import (
	"fmt"
	"strings"
)

// NormalizePublicSessionID trims caller input and enforces the public session
// contract used by evaluate and receipt lookup routes.
func NormalizePublicSessionID(sessionID string) (string, error) {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" || strings.ContainsRune(sessionID, 0) || strings.ContainsAny(sessionID, `/\`) {
		return "", fmt.Errorf("invalid session_id")
	}
	return sessionID, nil
}
