package acton

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

func hashString(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func joinSorted(values []string) string {
	sort.Strings(values)
	return strings.Join(values, ",")
}
