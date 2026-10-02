//go:build !race

package store

import "time"

const receiptThroughputTimeout = 45 * time.Second
