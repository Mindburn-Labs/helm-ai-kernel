//go:build !unix

package packfs

// openNonBlocking is zero where named pipes are not files a pack can hold.
const openNonBlocking = 0

// The trailing separator passed to Root.OpenFile requires a directory;
// these platforms do not need Unix named-pipe open flags.
const openDirectoryFlags = 0
