//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly || windows)

package spendproxy

// lockFile has no OS file lock on this platform (solaris, aix, plan9,
// js/wasm), so the receipts directory is not locked: run one proxy, and
// reconcile only while it is stopped. A marker file is no substitute, because
// a crash would leave it behind.
func lockFile(string) (func(), error) { return func() {}, nil }
