package decoy

import "net"

// listenAddr is a thin wrapper around net.Listen that returns the
// concrete listener so callers can interrogate its bound address.
func listenAddr(addr string) (net.Listener, error) {
	return net.Listen("tcp", addr)
}
