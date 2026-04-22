package interfaces

// ProjectionEngine defines the interface for the projection system
// required by the Kernel Runtime.
type ProjectionEngine interface {
	// Marker interface for now, as Runtime doesn't strictly call methods on it yet
	// but holds a reference. In the future this might include Rebuild/Reset.
}
