//go:build !envelope_signaltest

package pipeline

// defaultDeps is the production seam set. The zero value opens /dev/tty on
// demand, captures nothing, writes straight to the destination, and uses the
// real rename, remove and directory sync.
func defaultDeps() deps { return deps{} }
