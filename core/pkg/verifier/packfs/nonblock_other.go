//go:build !unix

package packfs

// openNonBlocking is zero where named pipes are not files a pack can hold.
const openNonBlocking = 0
