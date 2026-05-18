package skillpacks

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

func HashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func hashCanonical(v any) string {
	data, _ := json.Marshal(v)
	return HashBytes(data)
}
