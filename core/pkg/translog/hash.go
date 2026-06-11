// Package translog implements an RFC 6962-style append-only Merkle
// transparency log over receipt hashes: deterministic tree heads,
// inclusion proofs, and consistency proofs.
//
// Hashing follows RFC 6962 section 2.1 exactly:
//
//	leaf hash = SHA-256(0x00 || leaf input)
//	node hash = SHA-256(0x01 || left || right)
//
// All proof generation and verification functions are pure and
// deterministic so independent verifiers reproduce identical results.
package translog

import "crypto/sha256"

const (
	leafHashPrefix = 0x00
	nodeHashPrefix = 0x01

	// HashSize is the size in bytes of all hashes in the log (SHA-256).
	HashSize = sha256.Size
)

// LeafHash computes the RFC 6962 leaf hash: SHA-256(0x00 || leafInput).
// For the receipt transparency log the leaf input is the raw receipt
// hash bytes (the content address of the canonical receipt).
func LeafHash(leafInput []byte) [HashSize]byte {
	h := sha256.New()
	h.Write([]byte{leafHashPrefix})
	h.Write(leafInput)
	var out [HashSize]byte
	h.Sum(out[:0])
	return out
}

// NodeHash computes the RFC 6962 interior node hash: SHA-256(0x01 || left || right).
func NodeHash(left, right [HashSize]byte) [HashSize]byte {
	h := sha256.New()
	h.Write([]byte{nodeHashPrefix})
	h.Write(left[:])
	h.Write(right[:])
	var out [HashSize]byte
	h.Sum(out[:0])
	return out
}

// EmptyRoot returns the Merkle tree hash of an empty log: SHA-256 of the
// empty string (RFC 6962 section 2.1).
func EmptyRoot() [HashSize]byte {
	return sha256.Sum256(nil)
}

// RootFromLeafHashes computes the Merkle tree hash MTH(D[n]) over the
// given ordered leaf hashes (RFC 6962 section 2.1).
func RootFromLeafHashes(leafHashes [][HashSize]byte) [HashSize]byte {
	n := uint64(len(leafHashes))
	if n == 0 {
		return EmptyRoot()
	}
	return subtreeRoot(leafHashes, 0, n)
}

// subtreeRoot computes MTH(D[lo:hi]) where hi > lo.
func subtreeRoot(leafHashes [][HashSize]byte, lo, hi uint64) [HashSize]byte {
	n := hi - lo
	if n == 1 {
		return leafHashes[lo]
	}
	k := largestPowerOfTwoBelow(n)
	return NodeHash(subtreeRoot(leafHashes, lo, lo+k), subtreeRoot(leafHashes, lo+k, hi))
}

// largestPowerOfTwoBelow returns the largest power of two strictly less
// than n. Requires n > 1.
func largestPowerOfTwoBelow(n uint64) uint64 {
	k := uint64(1)
	for k<<1 < n {
		k <<= 1
	}
	return k
}
