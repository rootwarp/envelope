//go:build !envelope_signaltest

package pipeline

// defaultDeps is the production seam set. The zero value opens /dev/tty on
// demand and captures nothing.
func defaultDeps() deps { return deps{} }
