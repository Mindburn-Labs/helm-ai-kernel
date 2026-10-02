//go:build race

package store

import "time"

const receiptThroughputTimeout = 3 * time.Minute
