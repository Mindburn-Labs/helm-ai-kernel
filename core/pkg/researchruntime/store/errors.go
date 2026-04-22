package store

import (
	"errors"
	"strconv"
)

// ErrNotFound is returned when a requested record does not exist.
var ErrNotFound = errors.New("store: record not found")

// itoa converts an int to its decimal string representation.
// Used for building parameterised SQL query strings.
func itoa(n int) string {
	return strconv.Itoa(n)
}
